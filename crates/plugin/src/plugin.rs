//! Our implementation of `IVpnPlugIn` which is the bulk of the VPN plugin.

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use windows::{
    core::*,
    Networking::Sockets::*,
    Networking::Vpn::*,
    Networking::*,
    Win32::Foundation::{E_BOUNDS, E_INVALIDARG, E_UNEXPECTED},
};
use windows_collections::IVectorView;
use wireguard_config::{IpNetwork, WireGuardConfig};

use crate::logging::WireGuardEvents;
use crate::utils::{debug_log, IBufferExt, Vector};

/// The tunnel is considered stale (and timers are polled) after this long.
const STALE_SESSION: Duration = Duration::from_millis(250);

/// Size of a WireGuard handshake initiation message.
const HANDSHAKE_INIT_SZ: usize = 148;

/// Scratch buffer size for packets produced by `boringtun`.
const SCRATCH_SZ: usize = 1500;

/// The VPN plugin object which provides the hooks that the UWP VPN platform will call into.
#[implement(IVpnPlugIn)]
pub struct VpnPlugin {
    /// The WireGuard state machine; `None` until `Connect` succeeded.
    tunn: Mutex<Option<Tunn>>,
    etw_logger: WireGuardEvents,
}

impl IVpnPlugIn_Impl for VpnPlugin_Impl {
    /// Called by the platform so that we may connect and setup the VPN tunnel.
    fn Connect(&self, channel: Ref<VpnChannel>) -> Result<()> {
        self.connect_inner(channel).inspect_err(|err| {
            self.etw_logger
                .connect_fail(None, err.code().0 as u32, &err.to_string());
        })
    }

    /// Called by the platform to indicate we should disconnect and cleanup the VPN tunnel.
    fn Disconnect(&self, channel: Ref<VpnChannel>) -> Result<()> {
        match self.disconnect_inner(channel) {
            Ok(()) => {
                self.etw_logger.disconnect(None, 0, "Operation successful.");
                Ok(())
            }
            Err(err) => {
                self.etw_logger
                    .disconnect(None, err.code().0 as u32, &err.to_string());
                Err(err)
            }
        }
    }

    /// Called by the platform from time to time so that we may send some keepalive payload.
    ///
    /// If we decide we want to send any keepalive payload, we place it in `keepAlivePacket`.
    fn GetKeepAlivePayload(
        &self,
        channel: Ref<VpnChannel>,
        keepAlivePacket: OutRef<VpnPacketBuffer>,
    ) -> Result<()> {
        let channel = channel.as_ref().ok_or(Error::from(E_UNEXPECTED))?;

        let mut guard = self.lock_tunn();
        let Some(tunn) = guard.as_mut() else {
            return Ok(());
        };

        let mut dst = [0u8; SCRATCH_SZ];
        match tunn.update_timers(&mut dst) {
            TunnResult::Done => keepAlivePacket.write(None),
            TunnResult::Err(err) => Err(tunn_error("update_timers", err)),
            TunnResult::WriteToNetwork(packet) => {
                self.etw_logger.keepalive(None, packet.len() as u32);
                keepAlivePacket.write(Some(send_buffer(channel, packet)?))
            }
            TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => {
                unreachable!("update_timers never yields tunnel data")
            }
        }
    }

    /// Called by the platform to indicate there are outgoing packets ready to be encapsulated.
    ///
    /// `packets` contains outgoing L3 IP packets that we should encapsulate in whatever protocol
    /// dependant manner before placing them in `encapsulatedPackets` so that they may be sent to
    /// the remote endpoint.
    fn Encapsulate(
        &self,
        channel: Ref<VpnChannel>,
        packets: Ref<VpnPacketBufferList>,
        encapsulatedPackets: Ref<VpnPacketBufferList>,
    ) -> Result<()> {
        self.encapsulate_inner(channel, packets, encapsulatedPackets)
            .inspect_err(|err| {
                self.etw_logger
                    .encapsulate_fail(None, err.code().0 as u32, &err.to_string());
            })
    }

    /// Called by the platform to indicate we've received a frame from the remote endpoint.
    ///
    /// `buffer` will contain whatever data we received from the remote endpoint which may
    /// either contain control or data payloads. For data payloads, we will decapsulate into
    /// 1 (or more) L3 IP packet(s) before returning them to the platform by placing them in
    /// `decapsulatedPackets`, making them ready to be injected into the virtual tunnel. If
    /// we need to send back control payloads or otherwise back to the remote endpoint, we
    /// may place such frames into `controlPackets`.
    fn Decapsulate(
        &self,
        channel: Ref<VpnChannel>,
        buffer: Ref<VpnPacketBuffer>,
        decapsulatedPackets: Ref<VpnPacketBufferList>,
        controlPackets: Ref<VpnPacketBufferList>,
    ) -> Result<()> {
        self.decapsulate_inner(channel, buffer, decapsulatedPackets, controlPackets)
            .inspect_err(|err| {
                self.etw_logger
                    .decapsulate_fail(None, err.code().0 as u32, &err.to_string());
            })
    }
}

impl VpnPlugin {
    pub fn new() -> Self {
        Self {
            tunn: Mutex::new(None),
            etw_logger: WireGuardEvents::new(),
        }
    }

    /// Lock the tunnel state. A panic in another callback must not wedge the VPN.
    fn lock_tunn(&self) -> MutexGuard<'_, Option<Tunn>> {
        self.tunn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Internal `Connect` implementation.
    fn connect_inner(&self, channel: Ref<VpnChannel>) -> Result<()> {
        let channel = channel.as_ref().ok_or(Error::from(E_UNEXPECTED))?;
        let config = channel.Configuration()?;

        let wg_config =
            WireGuardConfig::from_xml(&config.CustomField()?.to_string()).map_err(|err| {
                let _ = channel
                    .SetErrorMessage(&HSTRING::from(format!("failed to parse config: {err}")));
                Error::from(E_INVALIDARG)
            })?;

        let (ipv4, ipv6): (Vec<&IpNetwork>, Vec<&IpNetwork>) = wg_config
            .interface
            .address
            .iter()
            .partition(|net| net.is_ipv4());
        let ipv4_addrs = address_view(host_names(ipv4.iter().map(|net| net.ip()))?)?;
        let ipv6_addrs = address_view(host_names(ipv6.iter().map(|net| net.ip()))?)?;

        // Routes over (AllowedIPs) and around (ExcludedIPs) the tunnel.
        let routes = VpnRouteAssignment::new()?;
        let (allowed_v4, allowed_v6) = build_routes(&wg_config.peer.allowed_ips)?;
        let (excluded_v4, excluded_v6) = build_routes(&wg_config.peer.excluded_ips)?;

        if !allowed_v4.is_empty() {
            routes.SetIpv4InclusionRoutes(&Vector::new(allowed_v4))?;
        }
        if !allowed_v6.is_empty() {
            routes.SetIpv6InclusionRoutes(&Vector::new(allowed_v6))?;
        }
        if !excluded_v4.is_empty() {
            routes.SetIpv4ExclusionRoutes(&Vector::new(excluded_v4))?;
        }
        if !excluded_v6.is_empty() {
            routes.SetIpv6ExclusionRoutes(&Vector::new(excluded_v6))?;
        }

        let namespace_assignment = build_dns(
            host_names(&wg_config.interface.dns_servers)?,
            &wg_config.interface.search_domains,
        )?;

        let tunn = Tunn::new(
            StaticSecret::from(wg_config.interface.private_key.to_bytes()),
            PublicKey::from(wg_config.peer.public_key.to_bytes()),
            wg_config
                .peer
                .preshared_key
                .as_ref()
                .map(|key| key.to_bytes()),
            wg_config.peer.persistent_keepalive,
            rand::random(), // Our sender index. Needs to be a pseudorandom number.
            None,           // No rate limiter
        );
        if self.lock_tunn().replace(tunn).is_some() {
            debug_log!("Replacing leftover tunn state.");
        }

        let sock = DatagramSocket::new()?;
        channel.AddAndAssociateTransport(&sock, None)?;

        let server = config.ServerHostNameList()?.GetAt(0)?;
        let port = wg_config.peer.port;
        debug_log!("Server: {} Port: {}", server.ToString()?, port);

        // We "block" here with the call to `.join()` but given this is a UDP socket
        // connect isn't actually something that will hang (DNS aside perhaps?).
        sock.ConnectAsync(&server, &HSTRING::from(port.to_string()))?
            .join()?;

        channel.Start(
            ipv4_addrs.as_ref(),
            ipv6_addrs.as_ref(),
            None, // Interface ID portion of IPv6 address for VPN tunnel
            &routes,
            &namespace_assignment,
            u32::from(wg_config.interface.effective_mtu()), // MTU of the tunnel interface
            1600,  // Max frame size of incoming buffers from remote endpoint
            false, // Disable low cost network monitoring
            &sock, // Pass in the socket to the remote endpoint
            None,  // No secondary socket used.
        )?;

        self.etw_logger
            .connected(None, &server.ToString()?.to_string(), port);
        Ok(())
    }

    /// Internal `Disconnect` implementation.
    fn disconnect_inner(&self, channel: Ref<VpnChannel>) -> Result<()> {
        let channel = channel.as_ref().ok_or(Error::from(E_UNEXPECTED))?;
        *self.lock_tunn() = None;
        channel.Stop()
    }

    fn encapsulate_inner(
        &self,
        channel: Ref<VpnChannel>,
        packets: Ref<VpnPacketBufferList>,
        encapsulatedPackets: Ref<VpnPacketBufferList>,
    ) -> Result<()> {
        let channel = channel.as_ref().ok_or(Error::from(E_UNEXPECTED))?;
        let packets = packets.as_ref().ok_or(Error::from(E_UNEXPECTED))?;
        let encapsulatedPackets = encapsulatedPackets
            .as_ref()
            .ok_or(Error::from(E_UNEXPECTED))?;

        let mut guard = self.lock_tunn();
        let Some(tunn) = guard.as_mut() else {
            return Ok(());
        };

        // Usually this would be called in the background by some periodic timer
        // but a UWP VPN plugin will get suspended if there's no traffic and that
        // includes any background threads or such we could create.
        // So we may find ourselves with a stale session and need to do a new
        // handshake. Thus, we just call this opportunistically here before
        // trying to encapsulate.
        if tunn.time_since_last_handshake() >= Some(STALE_SESSION) {
            let mut handshake_buf = [0u8; HANDSHAKE_INIT_SZ];
            match tunn.update_timers(&mut handshake_buf) {
                TunnResult::Done => {}
                TunnResult::Err(err) => return Err(tunn_error("update_timers", err)),
                TunnResult::WriteToNetwork(packet) => {
                    encapsulatedPackets.Append(&send_buffer(channel, packet)?)?;
                }
                TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => {
                    unreachable!("update_timers never yields tunnel data")
                }
            }
        }

        let packets_sz = packets.Size()?;
        self.etw_logger.encapsulate_begin(None, packets_sz);

        // Buffers we requested but did not fill; they must still go back to the platform.
        let mut unused_buffers = vec![];
        let mut encap_err = None;

        // Not using the simpler `for packet in packets` because
        // `packets.First()?` fails with E_NOINTERFACE for some reason.
        for _ in 0..packets_sz {
            let packet = packets.RemoveAtBegin()?;
            let src = packet.get_buf()?;

            let mut encapPacket = channel.GetVpnSendPacketBuffer()?;
            encapPacket
                .Buffer()?
                .SetLength(encapPacket.Buffer()?.Capacity()?)?;
            let dst = encapPacket.get_buf_mut()?;

            match tunn.encapsulate(src, dst) {
                TunnResult::WriteToNetwork(out) => {
                    let new_len = u32::try_from(out.len()).map_err(|_| Error::from(E_BOUNDS))?;
                    encapPacket.Buffer()?.SetLength(new_len)?;
                    encapsulatedPackets.Append(&encapPacket)?;
                }
                // Packet was queued while we complete the handshake
                TunnResult::Done => unused_buffers.push(encapPacket),
                TunnResult::Err(err) => {
                    encap_err.get_or_insert_with(|| tunn_error("encap", err));
                    unused_buffers.push(encapPacket);
                }
                TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => {
                    unreachable!("encapsulate never yields tunnel data")
                }
            }

            // Every `VpnPacketBuffer` the platform hands us must be returned to it. Since we
            // don't encapsulate in place, leave the input in `packets` for the platform to
            // clean up.
            packets.Append(&packet)?;
        }

        self.etw_logger
            .encapsulate_end(None, encapsulatedPackets.Size()?);

        for buffer in unused_buffers {
            packets.Append(&buffer)?;
        }

        encap_err.map_or(Ok(()), Err)
    }

    fn decapsulate_inner(
        &self,
        channel: Ref<VpnChannel>,
        buffer: Ref<VpnPacketBuffer>,
        decapsulatedPackets: Ref<VpnPacketBufferList>,
        controlPackets: Ref<VpnPacketBufferList>,
    ) -> Result<()> {
        let channel = channel.as_ref().ok_or(Error::from(E_UNEXPECTED))?;
        let buffer = buffer.as_ref().ok_or(Error::from(E_UNEXPECTED))?;
        let decapsulatedPackets = decapsulatedPackets
            .as_ref()
            .ok_or(Error::from(E_UNEXPECTED))?;
        let controlPackets = controlPackets.as_ref().ok_or(Error::from(E_UNEXPECTED))?;

        let mut guard = self.lock_tunn();
        let Some(tunn) = guard.as_mut() else {
            return Ok(());
        };

        self.etw_logger
            .decapsulate_begin(None, buffer.Buffer()?.Length()?);

        let mut dst = [0u8; SCRATCH_SZ];
        let datagram = buffer.get_buf()?;

        match tunn.decapsulate(None, datagram, &mut dst) {
            TunnResult::Done => {}

            // DD-WRT sometimes sends us packets that are destined for someone else?
            // Either way, just ignore the packet.
            TunnResult::Err(WireGuardError::WrongIndex) => {}

            TunnResult::Err(err) => return Err(tunn_error("decap", err)),

            // We need to send at least one response back to remote endpoint
            TunnResult::WriteToNetwork(packet) => {
                controlPackets.Append(&send_buffer(channel, packet)?)?;

                while let TunnResult::WriteToNetwork(packet) = tunn.decapsulate(None, &[], &mut dst)
                {
                    controlPackets.Append(&send_buffer(channel, packet)?)?;
                }
            }

            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                let mut decapPacket = channel.GetVpnReceivePacketBuffer()?;
                let new_len = u32::try_from(packet.len()).map_err(|_| Error::from(E_BOUNDS))?;
                decapPacket.Buffer()?.SetLength(new_len)?;
                decapPacket.get_buf_mut()?.copy_from_slice(packet);

                // Tack onto `decapsulatedPackets` to inject into VPN interface
                decapsulatedPackets.Append(&decapPacket)?;
            }
        }

        self.etw_logger
            .decapsulate_end(None, decapsulatedPackets.Size()?, controlPackets.Size()?);

        Ok(())
    }
}

/// Wrap a `boringtun` failure in a WinRT error.
fn tunn_error(context: &str, err: WireGuardError) -> Error {
    Error::new(E_UNEXPECTED, format!("{context} error: {err:?}"))
}

/// Copy `data` into a fresh send buffer obtained from the platform.
fn send_buffer(channel: &VpnChannel, data: &[u8]) -> Result<VpnPacketBuffer> {
    let mut buffer = channel.GetVpnSendPacketBuffer()?;
    buffer
        .Buffer()?
        .SetLength(u32::try_from(data.len()).map_err(|_| Error::from(E_BOUNDS))?)?;
    buffer.get_buf_mut()?.copy_from_slice(data);
    Ok(buffer)
}

/// Turn anything printable into a list of WinRT `HostName`s.
fn host_names<I>(items: I) -> Result<Vec<Option<HostName>>>
where
    I: IntoIterator,
    I::Item: ToString,
{
    items
        .into_iter()
        .map(|item| HostName::CreateHostName(&HSTRING::from(item.to_string())).map(Some))
        .collect()
}

/// `VpnChannel::Start` wants `None` rather than an empty list.
fn address_view(addrs: Vec<Option<HostName>>) -> Result<Option<IVectorView<HostName>>> {
    if addrs.is_empty() {
        Ok(None)
    } else {
        Vector::<HostName>::new(addrs).GetView().map(Some)
    }
}

/// A list of WinRT routes as expected by `Vector::new`.
type RouteList = Vec<Option<VpnRoute>>;

/// Build the IPv4 and IPv6 route lists for `networks`.
fn build_routes(networks: &[IpNetwork]) -> Result<(RouteList, RouteList)> {
    let (mut ipv4, mut ipv6) = (vec![], vec![]);

    for net in networks {
        let route = VpnRoute::CreateVpnRoute(
            &HostName::CreateHostName(&HSTRING::from(net.network().to_string()))?,
            net.prefix(),
        )?;
        let routes = if net.is_ipv4() { &mut ipv4 } else { &mut ipv6 };
        routes.push(Some(route));
    }

    Ok((ipv4, ipv6))
}

/// Plumb DNS through NRPT rules: one wildcard rule for the servers plus one
/// suffix rule per search domain.
fn build_dns(
    dns_servers: Vec<Option<HostName>>,
    search_domains: &[String],
) -> Result<VpnNamespaceAssignment> {
    let mut namespaces = Vec::with_capacity(search_domains.len() + 1);

    // Search domains become suffix rules (prefixed with '.') so they get added to the
    // virtual interface's Connection-Specific DNS Suffix Search List.
    for domain in search_domains {
        let servers = Vector::new(dns_servers.clone());
        let name = HSTRING::from(format!(".{domain}"));
        namespaces.push(Some(VpnNamespaceInfo::CreateVpnNamespaceInfo(
            &name, &servers, None,
        )?));
    }

    if !dns_servers.is_empty() {
        // The namespace '.' applies to everything instead of a specific set of domains.
        let servers = Vector::new(dns_servers);
        namespaces.push(Some(VpnNamespaceInfo::CreateVpnNamespaceInfo(
            &HSTRING::from("."),
            &servers,
            None,
        )?));
    }

    let assignment = VpnNamespaceAssignment::new()?;
    assignment.SetNamespaceList(&Vector::new(namespaces))?;
    Ok(assignment)
}
