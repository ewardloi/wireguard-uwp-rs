# WireGuard UWP

A Universal Windows Platform (UWP) [VPN Plug-in](https://docs.microsoft.com/en-us/uwp/api/windows.networking.vpn.ivpnplugin) for [WireGuard<sup>®</sup>](https://www.wireguard.com/) written in [Rust](https://www.rust-lang.org/).

Windows provides a plug-in based model for adding 3rd-party VPN protocols. VPN profiles
backed by such a plugin are referred to as **Plugin**/**3rd-party**/**UWP** profiles, as opposed
to **Native** profiles (i.e. built-in SSTP, IKEv2).

**WireGuard** is a VPN protocol that aims to be: Fast, Modern and Secure. Principles
which dovetail quite nicely with the Rust programming language. The actual noise-based WireGuard
implementation comes from Cloudflare's [boringtun](https://github.com/cloudflare/boringtun).

With the rapidly maturing [Rust for Windows](https://github.com/microsoft/windows-rs) bindings,
this projects serve as a fun experiment in putting all the above together.

## Building

Make sure you have Rust installed. Then, once you've cloned the repo just simply run:
```console
$ cargo build --release
```

The project currently only builds on Windows but given the Windows-specific nature, that's not
considered a limitation.

## Installing

Once you've successfully built the project, you can install it by running the following commands
in a powershell prompt from the repo root:
```powershell
copy appx\* target\release
Add-AppxPackage -Register .\target\release\AppxManifest.xml
```

**NOTE:** This does an in-place sort of installation in that the installed app will refer to
the binaries in your `target\release` folder. So you may encounter issues if you modify those
after installation. This is just a stop-gap until a proper `.appx` can be generated.

## Running

There are two ways to create and edit a profile: the built-in app (recommended) or PowerShell.

### Using the app

Profiles are created in Windows itself and edited in the app:

1. Open Windows Settings, `Network & Internet > VPN`, `Add a VPN connection`.
2. Choose **WireGuard VPN** as the `VPN provider`, give it a `Connection name`, enter the
   `Server name or address` and hit `Save`.
3. Start **WireGuard VPN** from the Start menu (press **Refresh** if it was already open),
   pick the profile and fill in the fields: server port, your private key and address, the
   server's public key and the allowed IPs. DNS, search domains, MTU, excluded IPs, persistent
    keepalive and the **preshared key** are optional.
4. Press **Copy PowerShell** and paste the command into PowerShell to apply the profile.
5. Connect from the Windows VPN settings.

Already have a standard WireGuard `.conf` file? Press **Load .conf** next to
**Refresh** and choose the file. The fields get filled in so you can review
them before copying the PowerShell command. `ListenPort`, `PostUp` and other options that don't
apply to a Windows VPN plugin are ignored, and only a single `[Peer]` is
supported.

The profile name can't be changed (Windows identifies profiles by name). **Delete** removes
the profile from Windows.

Updating a profile that is currently connected is not possible, so disconnect first.

### Using PowerShell

1. Open Windows Settings and navigate to the VPN page:
`Network & Internet > VPN`.
2. Select `Add a VPN connection`.
3. From the `VPN provider` dropdown select **WireGuard VPN**.
4. Give your new VPN profile a name under `Connection name`.
5. Enter the remote endpoint hostname or IP address under `Server name or address`.
6. Hit `Save`.

The settings you can tweak from the Windows Settings UI are limited to just the profile name
and remote endpoint's hostname. To modify the private key, public key, remote port etc set
those values from a powershell prompt:

```powershell
$vpnConfig = @'
<WireGuard>
    <Interface>
        <PrivateKey>...</PrivateKey>
        <Address>10.0.0.2/32</Address>
        <Address>2001:db8::2/64</Address>
        <DNS>1.1.1.1</DNS>
        <DNSSearch>vpn.example.com</DNSSearch>
        <DNSSearch>foo.corp.example.com</DNSSearch>
        <MTU>1420</MTU>
    </Interface>
    <Peer>
        <PublicKey>...</PublicKey>
        <PresharedKey>...</PresharedKey>
        <Port>51000</Port>
        <AllowedIPs>10.0.0.0/24</AllowedIPs>
        <AllowedIPs>10.10.0.0/24</AllowedIPs>
        <AllowedIPs>10.20.0.0/24</AllowedIPs>
        <AllowedIPs>2001:db8::/64</AllowedIPs>
        <PersistentKeepalive>25</PersistentKeepalive>
    </Peer>
</WireGuard>
'@

Set-VpnConnection -Name ProfileNameHere -CustomConfiguration $vpnConfig
```

The only required values are `PrivateKey`, `Address`, `PublicKey`, `Port` & `AllowedIPs`. The rest are
optional. You may repeat `Address` multiple times to assign multiple IPv4 & IPv6 addresses to the
virtual interface. Similarly, you may specify `AllowedIPs` multiple times to define the routes that
should go over the virtual interface.

You should now be able to select the new profile and hit `Connect`.

**NOTE:** Ideally, you could just specify `Port` colon separated with the hostname but the
corresponding API for retrieving that value is statically typed as a HostName.

**NOTE:** You should make sure to set a `PersistentKeepalive` value on the remote
side for each **WireGuard UWP**-based client because the UWP VPN plugin model
offers limited options for the plugin to perform periodic actions. Generally,
the plugin will only be woken if there are packets that need to be encapsulated or
if there are incoming buffers from the remote that need to be decapsulated. The
platform does provide a `GetKeepAlivePayload` it will call on occasion but the
interval in which it will be called cannot be controlled by the plugin author or
the user but rather the platform itself. Hence it's important to make sure the
server will keep the tunnel alive by sending the periodic keep alives in-band.

This has only been tested on Windows 10 21H1 (19043.1348) but should work on any updated
Windows 10 or 11 release. It'll probably work on older versions but no guarantees.

### Address

You must specify one or more IPv4 and/or IPv6 addresses to assign to the virtual interface.

### MTU

`MTU` (optional, in `Interface`) sets the MTU of the tunnel interface. It defaults to `1500` and
must be between `576` and `1500`: the plugin's packet buffers are 1500 bytes, so larger values
can't work. If large transfers stall or only small packets get through, lower it; `1420` is the
usual value for WireGuard over IPv6-capable links, `1380` leaves more headroom.

### Preshared key

`PresharedKey` (optional) is the base64 key generated with `wg genpsk`. It adds a layer of
symmetric encryption on top of the Curve25519 handshake and must be identical on both sides;
if only one side has it, or the keys differ, the handshake is rejected and the tunnel never
comes up. Leave it empty or omit the element to run without one.

### DNS

DNS servers are plumbed via [Name Resolution Policy Table](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn593632(v=ws.11)) (NRPT) Rules.
You can print the current set of rules applied while a VPN profile backed by the plugin
is connected via either:

CMD:
```cmd
netsh namespace show effectivepolicy
```

PowerShell:
```powershell
Get-DnsClientNrptPolicy -Effective
```

If any number of DNS servers are specified in the config, the plugin will plumb one
NRPT rule with the namespace set to `.`; this means the rule will apply to all
domains. While NRPT rules do support matching based on domain suffixes/prefixes
to apply domain-specific DNS servers, we just use a single wildcard rule.

You will note another rule plumbed while the plugin is connected, for the specific
domain used to connect to the remote endpoint. This is added automatically by the
platform so that if the tunnel is interrupted and needs to be re-established, we
don't end up in a situation wherein we can't resolve the remote's hostname.

You can also specify one more optional search domains. These will be added to the
VPN interface's **Connection-specific DNS Suffix Search List**. The first specified
search domain will also be the primary Connection-specific DNS Suffix, as can be
confirmed with `ipconfig /all` after connecting. You'll see an additional suffix-type
NRPT rule for each such search domain configured, with the specific DNS servers set
to whatever was configured.

### Routing

If you'd like all traffic to flow over the VPN interface while connected, you can
just add a catch-all route (`0.0.0.0/0` or `::/0` as appropriate):

```powershell
$vpnConfig = @'
<WireGuard>
    <Interface>
        <PrivateKey>...</PrivateKey>
        <Address>10.0.0.2/32</Address>
        <DNS>1.1.1.1</DNS>
    </Interface>
    <Peer>
        <PublicKey>...</PublicKey>
        <Port>51000</Port>
        <AllowedIPs>0.0.0.0/0</AllowedIPs>
        <PersistentKeepalive>25</PersistentKeepalive>
    </Peer>
</WireGuard>
'@

Set-VpnConnection -Name ProfileNameHere -CustomConfiguration $vpnConfig
```

If you'd like to exclude certain routes from going over the VPN interface, you
can specify one or more `ExcludedIPs` elements:

```powershell
$vpnConfig = @'
<WireGuard>
    <Interface>
        <PrivateKey>...</PrivateKey>
        <Address>10.0.0.2/32</Address>
        <DNS>1.1.1.1</DNS>
    </Interface>
    <Peer>
        <PublicKey>...</PublicKey>
        <Port>51000</Port>
        <AllowedIPs>0.0.0.0/0</AllowedIPs>
        <ExcludedIPs>192.168.1.0/24</ExcludedIPs>
        <PersistentKeepalive>25</PersistentKeepalive>
    </Peer>
</WireGuard>
'@

Set-VpnConnection -Name ProfileNameHere -CustomConfiguration $vpnConfig
```

This usually only makes sense if you have a catch-all route to carve out some
exceptions. Also note that there will usually already be a specific route
entry for your local subnet so no need to explicitly exclude it.

To print the routing table in `cmd.exe` run:

```cmd
route print
```

## Development

The workspace has three crates:

* `crates/config`: the profile model (XML storage format, `wg-quick` import, form
  validation). It has no Windows dependencies, so its unit tests, including an
  end-to-end handshake test through `boringtun`, run on any OS: `cargo test -p wireguard-config`.
* `crates/plugin`: the `IVpnPlugIn` background task (`wireguard_plugin.dll`).
* `crates/app`: the XAML profile editor.

## Tracing

The plugin emits a number of [ETW](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)
under the Event Provider identified by a specific GUID (`c4522a55-401f-4b81-93f9-aa0d1db734c4`). The events
are emitted with the help of the [rust_win_etw](https://github.com/microsoft/rust_win_etw) crate which
provides a way to define & emit ETW events from your Rust code.

To consume these events, there are a number of different tools which can be used. **rust_win_etw** provides
a quick rundown on how to capture them: https://github.com/microsoft/rust_win_etw#how-to-capture-and-view-events

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

---
<sub><sub>"WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld.</sub></sub>
