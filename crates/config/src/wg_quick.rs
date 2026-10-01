//! Import of the standard `wg-quick` INI format (`.conf` files).

use std::net::IpAddr;

use crate::{ConfigError, InterfaceConfig, IpNetwork, Key, PeerConfig, WireGuardConfig};

/// Result of importing a `.conf` file.
#[derive(Debug, Clone, PartialEq)]
pub struct Imported {
    /// Host part of `Endpoint`, to be used as the VPN profile's server name.
    pub server: Option<String>,
    /// The converted profile.
    pub config: WireGuardConfig,
}

#[derive(PartialEq)]
enum Section {
    None,
    Interface,
    Peer,
}

/// Parse a `wg-quick` style configuration.
///
/// Only a single `[Peer]` is supported, matching what the plugin can run.
/// Options that have no meaning for a Windows VPN plugin (`ListenPort`,
/// `Table`, `PostUp`, ...) are ignored.
pub fn parse_wg_quick(text: &str) -> Result<Imported, ConfigError> {
    let mut section = Section::None;
    let mut seen_peer = false;

    let mut private_key = None;
    let mut address = Vec::new();
    let mut dns_servers = Vec::new();
    let mut search_domains = Vec::new();
    let mut mtu = None;

    let mut public_key = None;
    let mut preshared_key = None;
    let mut allowed_ips = Vec::new();
    let mut endpoint = None;
    let mut keepalive = None;

    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let err = |message: String| ConfigError::WgQuick {
            line: line_no,
            message,
        };

        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = match name.trim().to_ascii_lowercase().as_str() {
                "interface" => Section::Interface,
                "peer" => {
                    if std::mem::replace(&mut seen_peer, true) {
                        return Err(err("only one [Peer] section is supported".into()));
                    }
                    Section::Peer
                }
                other => return Err(err(format!("unknown section [{other}]"))),
            };
            continue;
        }

        // Split on the first '=' only: base64 keys contain '=' padding.
        let (key, value) = line
            .split_once('=')
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim()))
            .ok_or_else(|| err("expected `Key = Value`".into()))?;

        let key_of = |v: &str| Key::from_base64(v).map_err(|e| err(format!("{key}: {e}")));

        match (&section, key.as_str()) {
            (Section::None, _) => return Err(err("option outside of a section".into())),

            (Section::Interface, "privatekey") => private_key = Some(key_of(value)?),
            (Section::Interface, "address") => {
                for item in list(value) {
                    address.push(network(item).map_err(|m| err(format!("Address: {m}")))?);
                }
            }
            (Section::Interface, "dns") => {
                for item in list(value) {
                    match item.parse::<IpAddr>() {
                        Ok(ip) => dns_servers.push(ip),
                        Err(_) => search_domains.push(item.to_owned()),
                    }
                }
            }

            (Section::Interface, "mtu") => {
                mtu = Some(
                    value
                        .parse::<u16>()
                        .map_err(|_| err("invalid MTU".into()))?,
                );
            }

            (Section::Peer, "publickey") => public_key = Some(key_of(value)?),
            (Section::Peer, "presharedkey") => preshared_key = Some(key_of(value)?),
            (Section::Peer, "allowedips") => {
                for item in list(value) {
                    allowed_ips.push(network(item).map_err(|m| err(format!("AllowedIPs: {m}")))?);
                }
            }
            (Section::Peer, "endpoint") => {
                endpoint = Some(split_endpoint(value).map_err(|m| err(format!("Endpoint: {m}")))?);
            }
            (Section::Peer, "persistentkeepalive") => {
                keepalive = match value {
                    "off" | "0" => None,
                    v => Some(
                        v.parse::<u16>()
                            .map_err(|_| err("invalid PersistentKeepalive".into()))?,
                    ),
                };
            }

            // Options that do not apply to this plugin.
            _ => {}
        }
    }

    let (server, port) = match endpoint {
        Some((host, port)) => (Some(host), port),
        // Endpoint is optional in .conf; fall back to the WireGuard default port.
        None => (None, 51820),
    };

    let config = WireGuardConfig {
        interface: InterfaceConfig {
            private_key: private_key
                .ok_or(ConfigError::Invalid("[Interface] PrivateKey is missing"))?,
            address,
            dns_servers,
            search_domains,
            mtu,
        },
        peer: PeerConfig {
            public_key: public_key.ok_or(ConfigError::Invalid("[Peer] PublicKey is missing"))?,
            preshared_key,
            port,
            allowed_ips,
            excluded_ips: Vec::new(),
            persistent_keepalive: keepalive,
        },
    };
    config.validate()?;
    Ok(Imported { server, config })
}

/// Split a comma separated list, dropping blanks.
fn list(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim).filter(|s| !s.is_empty())
}

/// Parse `addr/prefix`, or a bare address as a host route.
fn network(s: &str) -> Result<IpNetwork, String> {
    if let Ok(net) = s.parse::<IpNetwork>() {
        return Ok(net);
    }
    s.parse::<IpAddr>()
        .map(IpNetwork::from)
        .map_err(|_| format!("`{s}` is not an IP address or CIDR"))
}

/// Split `host:port`, `[v6]:port`.
fn split_endpoint(s: &str) -> Result<(String, u16), String> {
    let (host, port) = s.rsplit_once(':').ok_or("expected host:port")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port = port.parse::<u16>().map_err(|_| "invalid port")?;
    if host.is_empty() {
        return Err("empty host".into());
    }
    Ok((host.to_owned(), port))
}

