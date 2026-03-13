use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;

fn random_array<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn encode_hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(LUT[usize::from(byte >> 4)]));
        out.push(char::from(LUT[usize::from(byte & 0x0f)]));
    }
    out
}

/// Deployment-local endpoint identifier used in associated data bindings.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EndpointId(String);

impl EndpointId {
    /// Creates a new endpoint identifier.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for EndpointId {
    fn default() -> Self {
        Self("default-edge".to_string())
    }
}

impl fmt::Display for EndpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Opaque session identifier issued after `S3`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub [u8; 16]);

impl SessionId {
    /// Creates a fresh random session identifier.
    #[must_use]
    pub fn random() -> Self {
        Self(random_array())
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_hex(&self.0))
    }
}

/// Client-generated nonce used to bind admission attempts and cookies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClientNonce(pub [u8; 16]);

impl ClientNonce {
    /// Creates a fresh random client nonce.
    #[must_use]
    pub fn random() -> Self {
        Self(random_array())
    }
}

impl fmt::Display for ClientNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_hex(&self.0))
    }
}
