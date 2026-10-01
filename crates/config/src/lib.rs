//! WireGuard profile model shared by the VPN plugin and the foreground app.
//!
//! A profile is stored by Windows in the VPN profile's `CustomConfiguration`
//! field as a small XML document:
//!
//! ```xml
//! <WireGuard>
//!     <Interface>
//!         <PrivateKey>...</PrivateKey>
//!         <Address>10.0.0.2/32</Address>
//!         <DNS>1.1.1.1</DNS>
//!     </Interface>
//!     <Peer>
//!         <PublicKey>...</PublicKey>
//!         <PresharedKey>...</PresharedKey>
//!         <Port>51820</Port>
//!         <AllowedIPs>0.0.0.0/0</AllowedIPs>
//!     </Peer>
//! </WireGuard>
//! ```
//!
//! The crate has no Windows dependencies so it can be unit-tested anywhere.

pub mod form;
mod key;
mod wg_quick;

use std::fmt;
use std::net::IpAddr;

pub use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

pub use key::{Key, KeyError};
pub use wg_quick::{parse_wg_quick, Imported};

/// MTU used when a profile does not set one.
pub const DEFAULT_MTU: u16 = 1500;
/// Smallest accepted MTU (the IPv4 minimum).
pub const MIN_MTU: u16 = 576;
/// Largest accepted MTU. The plugin decrypts into 1500 byte buffers and the platform
/// delivers frames of up to 1600 bytes, so a bigger tunnel MTU cannot work.
pub const MAX_MTU: u16 = 1500;

/// Name of the XML root element.
const ROOT: &str = "WireGuard";

/// Errors produced while reading, writing or validating a profile.
#[derive(Debug)]
pub enum ConfigError {
    /// The XML could not be parsed.
    Xml(quick_xml::DeError),
    /// The profile could not be serialized to XML.
    Serialize(quick_xml::SeError),
    /// A `wg-quick` style `.conf` could not be imported.
    WgQuick { line: usize, message: String },
    /// The profile parsed but is not usable.
    Invalid(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xml(e) => write!(f, "invalid profile XML: {e}"),
            Self::Serialize(e) => write!(f, "cannot serialize profile: {e}"),
            Self::WgQuick { line, message } => write!(f, "line {line}: {message}"),
            Self::Invalid(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ConfigError {}

/// A fully-parsed profile.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct WireGuardConfig {
    /// Local interface configuration.
    pub interface: InterfaceConfig,
    /// Remote peer configuration.
    pub peer: PeerConfig,
}

impl WireGuardConfig {
    /// Parse the XML stored in the VPN profile's custom configuration field.
    pub fn from_xml(s: &str) -> Result<Self, ConfigError> {
        let mut config: Self = quick_xml::de::from_str(s).map_err(ConfigError::Xml)?;
        config.normalize();
        config.validate()?;
        Ok(config)
    }

    /// Serialize into the XML form understood by [`WireGuardConfig::from_xml`].
    pub fn to_xml(&self) -> Result<String, ConfigError> {
        self.validate()?;
        quick_xml::se::to_string_with_root(ROOT, self).map_err(ConfigError::Serialize)
    }

    /// Check the invariants the plugin relies on.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.interface.address.is_empty() {
            return Err(ConfigError::Invalid("at least one Address is required"));
        }
        if let Some(mtu) = self.interface.mtu {
            if !(MIN_MTU..=MAX_MTU).contains(&mtu) {
                return Err(ConfigError::Invalid("MTU must be between 576 and 1500"));
            }
        }
        if self.peer.port == 0 {
            return Err(ConfigError::Invalid("Port must be between 1 and 65535"));
        }
        if self.peer.allowed_ips.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one AllowedIPs entry is required",
            ));
        }
        Ok(())
    }

    /// Treat blank optional values (e.g. an empty `<PresharedKey/>`) as absent.
    fn normalize(&mut self) {
        self.interface
            .search_domains
            .retain(|d| !d.trim().is_empty());
    }
}

/// Local VPN interface specific configuration.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct InterfaceConfig {
    /// Our local private key.
    pub private_key: Key,

    /// Addresses to assign to the local VPN interface.
    pub address: Vec<IpNetwork>,

    /// DNS servers.
    #[serde(default, rename = "DNS", skip_serializing_if = "Vec::is_empty")]
    pub dns_servers: Vec<IpAddr>,

    /// DNS search domains.
    #[serde(default, rename = "DNSSearch", skip_serializing_if = "Vec::is_empty")]
    pub search_domains: Vec<String>,

    /// MTU of the tunnel interface; [`DEFAULT_MTU`] when absent.
    #[serde(default, rename = "MTU", skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
}

impl InterfaceConfig {
    /// The MTU to configure on the tunnel interface.
    pub fn effective_mtu(&self) -> u16 {
        self.mtu.unwrap_or(DEFAULT_MTU)
    }
}

/// Remote peer specific configuration.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PeerConfig {
    /// The remote endpoint's public key.
    pub public_key: Key,

    /// Optional pre-shared key adding a layer of symmetric encryption.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "key::optional"
    )]
    pub preshared_key: Option<Key>,

    /// The port the remote endpoint is listening on.
    pub port: u16,

    /// Addresses that get routed to the remote endpoint.
    #[serde(rename = "AllowedIPs")]
    pub allowed_ips: Vec<IpNetwork>,

    /// Addresses that are carved out of `allowed_ips`.
    #[serde(default, rename = "ExcludedIPs", skip_serializing_if = "Vec::is_empty")]
    pub excluded_ips: Vec<IpNetwork>,

    /// Interval (seconds) at which keepalive packets are sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive: Option<u16>,
}
