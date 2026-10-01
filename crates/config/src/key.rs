//! 32-byte WireGuard key with base64 (de)serialization.

use std::fmt;

use base64::engine::{general_purpose::GeneralPurposeConfig, DecodePaddingMode};
use base64::{alphabet, engine, Engine};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Standard base64 for output, tolerant of missing padding on input.
const BASE64: engine::GeneralPurpose = engine::GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// Why a key could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// Not valid base64.
    Base64,
    /// Valid base64 but not exactly 32 bytes.
    Length,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Base64 => "key is not valid base64",
            Self::Length => "key must decode to exactly 32 bytes",
        })
    }
}

impl std::error::Error for KeyError {}

/// A raw 32-byte Curve25519 / pre-shared key.
///
/// `Debug` is deliberately redacted so keys cannot end up in logs.
#[derive(Clone, PartialEq, Eq)]
pub struct Key([u8; 32]);

impl Key {
    /// Parse a base64 encoded key (surrounding whitespace is ignored).
    pub fn from_base64(s: &str) -> Result<Self, KeyError> {
        let bytes = BASE64.decode(s.trim()).map_err(|_| KeyError::Base64)?;
        <[u8; 32]>::try_from(bytes)
            .map(Self)
            .map_err(|_| KeyError::Length)
    }

    /// Canonical (padded) base64 form.
    pub fn to_base64(&self) -> String {
        BASE64.encode(self.0)
    }

    /// The raw key bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for Key {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

impl Serialize for Key {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_base64(&s).map_err(serde::de::Error::custom)
    }
}

/// serde adapter for `Option<Key>` where a blank string means "absent".
pub(crate) mod optional {
    use super::*;

    pub fn serialize<S: Serializer>(key: &Option<Key>, s: S) -> Result<S::Ok, S::Error> {
        match key {
            Some(key) => key.serialize(s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Key>, D::Error> {
        match Option::<String>::deserialize(d)? {
            Some(s) if !s.trim().is_empty() => Key::from_base64(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            _ => Ok(None),
        }
    }
}

