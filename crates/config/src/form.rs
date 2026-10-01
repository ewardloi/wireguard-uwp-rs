//! Text-field view of a profile, for UIs.
//!
//! A UI only deals in strings. [`ProfileForm`] holds one string per input
//! field and converts to and from a real [`Profile`], reporting *which* field
//! is wrong so the UI can show a helpful message.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::{
    ConfigError, InterfaceConfig, IpNetwork, Key, PeerConfig, WireGuardConfig, MAX_MTU, MIN_MTU,
};

/// Default WireGuard port used for new profiles.
pub const DEFAULT_PORT: u16 = 51820;

/// A complete VPN profile: what Windows stores plus the WireGuard settings.
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    /// Name shown in the Windows VPN list.
    pub name: String,
    /// Host name or IP address of the remote endpoint.
    pub server: String,
    /// The WireGuard settings stored in the profile's custom configuration.
    pub config: WireGuardConfig,
}

impl Profile {
    /// A PowerShell snippet that applies this profile with `Set-VpnConnection`.
    ///
    /// This is the fallback for when the Windows API refuses to update a profile.
    pub fn powershell_command(&self) -> Result<String, ConfigError> {
        let xml = self.config.to_xml()?;
        // Single-quoted PowerShell strings only need `'` doubled.
        let quote = |s: &str| s.replace('\'', "''");
        Ok(format!(
            "$vpnConfig = @'\n{xml}\n'@\n\nSet-VpnConnection -Name '{}' -ServerAddress '{}' -CustomConfiguration $vpnConfig\n",
            quote(&self.name),
            quote(&self.server),
        ))
    }

    /// The URI Windows stores as the profile's server. The plugin only uses its host.
    pub fn server_uri(&self) -> String {
        if self.server.contains(':') {
            // IPv6 literal
            format!("https://[{}]", self.server)
        } else {
            format!("https://{}", self.server)
        }
    }
}

/// Recover the server name from a `Uri::Host()` value (IPv6 hosts may be bracketed).
pub fn server_from_uri_host(host: &str) -> String {
    host.trim_matches(|c| c == '[' || c == ']').to_owned()
}

/// A validation problem tied to one input field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormError {
    pub field: &'static str,
    pub message: String,
}

impl fmt::Display for FormError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for FormError {}

impl From<ConfigError> for FormError {
    fn from(e: ConfigError) -> Self {
        Self {
            field: "Profile",
            message: e.to_string(),
        }
    }
}

/// One string per input field. List fields accept commas, spaces or new lines
/// as separators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileForm {
    pub name: String,
    pub server: String,
    pub port: String,
    pub private_key: String,
    pub address: String,
    pub dns: String,
    pub search_domains: String,
    pub mtu: String,
    pub public_key: String,
    pub preshared_key: String,
    pub allowed_ips: String,
    pub excluded_ips: String,
    pub persistent_keepalive: String,
}

impl Default for ProfileForm {
    fn default() -> Self {
        Self {
            name: String::new(),
            server: String::new(),
            port: DEFAULT_PORT.to_string(),
            private_key: String::new(),
            address: String::new(),
            dns: String::new(),
            search_domains: String::new(),
            mtu: String::new(),
            public_key: String::new(),
            preshared_key: String::new(),
            allowed_ips: "0.0.0.0/0, ::/0".into(),
            excluded_ips: String::new(),
            persistent_keepalive: "25".into(),
        }
    }
}

impl ProfileForm {
    /// Fill the form from an existing profile.
    pub fn from_profile(profile: &Profile) -> Self {
        let cfg = &profile.config;
        Self {
            name: profile.name.clone(),
            server: profile.server.clone(),
            port: cfg.peer.port.to_string(),
            private_key: cfg.interface.private_key.to_base64(),
            address: join(&cfg.interface.address),
            dns: join(&cfg.interface.dns_servers),
            search_domains: join(&cfg.interface.search_domains),
            mtu: cfg.interface.mtu.map(|v| v.to_string()).unwrap_or_default(),
            public_key: cfg.peer.public_key.to_base64(),
            preshared_key: cfg
                .peer
                .preshared_key
                .as_ref()
                .map(Key::to_base64)
                .unwrap_or_default(),
            allowed_ips: join(&cfg.peer.allowed_ips),
            excluded_ips: join(&cfg.peer.excluded_ips),
            persistent_keepalive: cfg
                .peer
                .persistent_keepalive
                .map(|v| v.to_string())
                .unwrap_or_default(),
        }
    }

    /// Validate every field and build the profile.
    pub fn to_profile(&self) -> Result<Profile, FormError> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err(err("Profile name", "must not be empty"));
        }

        let server = self.server.trim();
        if server.is_empty() || server.contains(|c: char| c.is_whitespace() || c == '/') {
            return Err(err(
                "Server",
                "enter a host name or IP address without a scheme or path",
            ));
        }

        let port = self
            .port
            .trim()
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| err("Port", "must be a number from 1 to 65535"))?;

        let keepalive = match self.persistent_keepalive.trim() {
            "" => None,
            v => Some(
                v.parse::<u16>()
                    .map_err(|_| err("Persistent keepalive", "must be a number of seconds"))?,
            ),
        };

        let mtu = match self.mtu.trim() {
            "" => None,
            v => Some(
                v.parse::<u16>()
                    .ok()
                    .filter(|m| (MIN_MTU..=MAX_MTU).contains(m))
                    .ok_or_else(|| {
                        err(
                            "MTU",
                            format!("must be a number from {MIN_MTU} to {MAX_MTU}"),
                        )
                    })?,
            ),
        };

        let preshared_key = match self.preshared_key.trim() {
            "" => None,
            v => Some(Key::from_base64(v).map_err(|e| err("Preshared key", e))?),
        };

        let config = WireGuardConfig {
            interface: InterfaceConfig {
                private_key: Key::from_base64(&self.private_key)
                    .map_err(|e| err("Private key", e))?,
                address: parse_list::<IpNetwork>(&self.address, "Address")?,
                dns_servers: parse_list::<IpAddr>(&self.dns, "DNS")?,
                search_domains: split(&self.search_domains).map(str::to_owned).collect(),
                mtu,
            },
            peer: PeerConfig {
                public_key: Key::from_base64(&self.public_key).map_err(|e| err("Public key", e))?,
                preshared_key,
                port,
                allowed_ips: parse_list::<IpNetwork>(&self.allowed_ips, "Allowed IPs")?,
                excluded_ips: parse_list::<IpNetwork>(&self.excluded_ips, "Excluded IPs")?,
                persistent_keepalive: keepalive,
            },
        };

        config.validate().map_err(|e| err("Profile", e))?;
        Ok(Profile {
            name: name.to_owned(),
            server: server.to_owned(),
            config,
        })
    }
}

fn err(field: &'static str, message: impl ToString) -> FormError {
    FormError {
        field,
        message: message.to_string(),
    }
}

fn split(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|item| !item.is_empty())
}

fn join<T: ToString>(items: &[T]) -> String {
    items
        .iter()
        .map(T::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn parse_list<T: FromStr>(s: &str, field: &'static str) -> Result<Vec<T>, FormError> {
    split(s)
        .map(|item| {
            item.parse()
                .map_err(|_| err(field, format!("`{item}` is not valid")))
        })
        .collect()
}

