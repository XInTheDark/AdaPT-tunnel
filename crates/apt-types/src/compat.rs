use serde::{Deserialize, Serialize};

/// Nonce-prefixed opaque encrypted message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueMessage {
    /// XChaCha20-Poly1305 nonce bytes.
    pub nonce: [u8; 24],
    /// Ciphertext and tag bytes.
    pub ciphertext: Vec<u8>,
}

/// Optional short rotating credential lookup hint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LookupHint(pub [u8; 8]);

/// Runtime timing values used across the first-cut implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimingConfig {
    /// Admission epoch size in seconds.
    pub epoch_seconds: u64,
    /// Replay retention in seconds.
    pub replay_retention_seconds: u64,
    /// Cookie lifetime in seconds.
    pub cookie_lifetime_seconds: u64,
    /// Unknown-NAT keepalive baseline in seconds.
    pub unknown_nat_keepalive_seconds: u64,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            epoch_seconds: crate::DEFAULT_ADMISSION_EPOCH_SLOT_SECS,
            replay_retention_seconds: crate::DEFAULT_REPLAY_RETENTION_SECS,
            cookie_lifetime_seconds: crate::DEFAULT_COOKIE_LIFETIME_SECS,
            unknown_nat_keepalive_seconds: u64::from(crate::DEFAULT_IDLE_KEEPALIVE_BASE_SECS),
        }
    }
}

/// Resumption ticket claims carried inside an encrypted ticket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumptionTicketClaims {
    /// User or deployment credential reference.
    pub credential_ref: String,
    /// Server identifier.
    pub server_id: String,
    /// Expiry time in UNIX seconds.
    pub expiry_unix_seconds: u64,
    /// Last successful carrier family.
    pub last_carrier: crate::CarrierBinding,
    /// Last known coarse path class.
    pub last_path_class: crate::PathClass,
    /// Resume-secret binding.
    pub resume_secret: [u8; 32],
}

/// Coarse path/interference signals consumed by policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathSignalEvent {
    /// Repeated handshakes vanish without a response.
    HandshakeBlackhole,
    /// Immediate carrier-native resets occur soon after connect.
    ImmediateReset,
    /// Loss appears concentrated at particular record sizes.
    SizeSpecificLoss,
    /// Passive PMTU discovery indicates blackholing.
    MtuBlackhole,
    /// Round-trip time inflates sharply.
    RttInflation,
    /// NAT rebinding is observed frequently.
    NatRebinding,
    /// Recent fallback attempts also failed.
    FallbackFailure,
    /// Delivery has been stable through the probation window.
    StableDelivery,
}
