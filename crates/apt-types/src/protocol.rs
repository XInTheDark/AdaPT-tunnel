use serde::{Deserialize, Serialize};

/// Supported authentication profile for admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthProfile {
    /// One deployment-wide admission key.
    SharedDeployment,
    /// Per-user admission keys.
    PerUser,
}

/// Supported baseline cipher-suite selections.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    /// Mandatory baseline suite from the spec.
    #[serde(
        rename = "x25519-chachapoly-blake2s",
        alias = "NoiseXxPsk2X25519ChaChaPolyBlake2s"
    )]
    NoiseXxPsk2X25519ChaChaPolyBlake2s,
    /// Optional hybrid post-quantum profile.
    #[serde(rename = "hybrid-mlkem768-x25519", alias = "HybridMlKem768X25519")]
    HybridMlKem768X25519,
}

impl CipherSuite {
    /// Compact numeric code used in capability bitmaps and associated data.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::NoiseXxPsk2X25519ChaChaPolyBlake2s => 0x01,
            Self::HybridMlKem768X25519 => 0x02,
        }
    }

    /// Compact bit used by bitmap helpers.
    #[must_use]
    pub const fn bit(self) -> u16 {
        1 << self.code()
    }

    /// Human-readable symbolic name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoiseXxPsk2X25519ChaChaPolyBlake2s => "x25519-chachapoly-blake2s",
            Self::HybridMlKem768X25519 => "hybrid-mlkem768-x25519",
        }
    }

    /// Alias matching the spec shorthand used across the rest of the workspace.
    #[allow(non_upper_case_globals)]
    pub const X25519ChaChaPolyBlake2s: Self = Self::NoiseXxPsk2X25519ChaChaPolyBlake2s;
}

/// Supported carrier families.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CarrierBinding {
    /// Opaque UDP datagram carrier.
    #[serde(rename = "D1", alias = "d1", alias = "D1DatagramUdp")]
    D1DatagramUdp,
    /// Encrypted datagram-capable general transport.
    #[serde(rename = "D2", alias = "d2", alias = "D2EncryptedDatagram")]
    D2EncryptedDatagram,
    /// Generic encrypted stream carrier.
    #[serde(rename = "S1", alias = "s1", alias = "S1EncryptedStream")]
    S1EncryptedStream,
    /// Request-response fallback carrier.
    #[serde(rename = "H1", alias = "h1", alias = "H1RequestResponse")]
    H1RequestResponse,
}

impl CarrierBinding {
    /// Compact numeric code used in capability bitmaps and associated data.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::D1DatagramUdp => 0x01,
            Self::D2EncryptedDatagram => 0x02,
            Self::S1EncryptedStream => 0x03,
            Self::H1RequestResponse => 0x04,
        }
    }

    /// Alias used by some crates.
    #[must_use]
    pub const fn wire_code(self) -> u8 {
        self.code()
    }

    /// Human-readable symbolic name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::D1DatagramUdp => "D1",
            Self::D2EncryptedDatagram => "D2",
            Self::S1EncryptedStream => "S1",
            Self::H1RequestResponse => "H1",
        }
    }

    /// Returns whether the carrier is datagram-oriented.
    #[must_use]
    pub const fn is_datagram(self) -> bool {
        matches!(self, Self::D1DatagramUdp | Self::D2EncryptedDatagram)
    }

    /// Conservative fallback order.
    #[must_use]
    pub const fn conservative_fallback_order() -> [Self; 4] {
        [
            Self::D1DatagramUdp,
            Self::D2EncryptedDatagram,
            Self::S1EncryptedStream,
            Self::H1RequestResponse,
        ]
    }

    /// Alias matching the spec shorthand used across the rest of the workspace.
    pub const D1: Self = Self::D1DatagramUdp;
    /// Alias matching the spec shorthand used across the rest of the workspace.
    pub const D2: Self = Self::D2EncryptedDatagram;
    /// Alias matching the spec shorthand used across the rest of the workspace.
    pub const S1: Self = Self::S1EncryptedStream;
    /// Alias matching the spec shorthand used across the rest of the workspace.
    pub const H1: Self = Self::H1RequestResponse;
}

/// Policy mode exposed to persona and scheduler subsystems.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyMode {
    /// Maximum camouflage within safe bounds.
    #[serde(rename = "stealth-first", alias = "StealthFirst")]
    StealthFirst,
    /// Balanced latency and camouflage.
    #[serde(rename = "balanced", alias = "Balanced")]
    Balanced,
    /// Performance-favouring mode when policy allows.
    #[serde(rename = "speed-first", alias = "SpeedFirst")]
    SpeedFirst,
}

/// Session role for directional key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionRole {
    /// Client / initiator side.
    Initiator,
    /// Server / responder side.
    Responder,
}

impl SessionRole {
    /// Returns true if this role is the initiator.
    #[must_use]
    pub const fn is_initiator(self) -> bool {
        matches!(self, Self::Initiator)
    }

    /// Returns the opposite role.
    #[must_use]
    pub const fn opposite(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }
}

/// Scheduler pacing family generated by a persona.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacingFamily {
    /// Smooth pacing with mild jitter.
    Smooth,
    /// Small bounded bursts are allowed.
    Bursty,
    /// Path-aware opportunistic pacing.
    Opportunistic,
}

/// Keepalive behaviour for a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeepaliveMode {
    /// Suppress explicit keepalives while application traffic is recent.
    SuppressWhenActive,
    /// Use adaptive NAT-binding keepalives.
    Adaptive,
    /// Idle cover traffic only when policy explicitly enables it.
    SparseCover,
}

/// Idle-resume behaviour after long pauses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdleResumeBehavior {
    /// Resume transmission immediately.
    Immediate,
    /// Resume with a short probationary ramp.
    GentleRamp,
}

/// Reliability class for a control frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlReliability {
    /// Best-effort only.
    BestEffort,
    /// Retransmit until acked or expired.
    Reliable,
}

/// Privacy-safe encrypted close codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloseCode {
    /// Normal closure.
    Normal,
    /// Peer exceeded rekey or lifetime limits.
    RekeyRequired,
    /// Replay or integrity check failure.
    IntegrityFailure,
    /// Peer became unresponsive.
    Timeout,
    /// Peer triggered policy shutdown.
    PolicyViolation,
}

/// Persona/scheduler profile exported to scheduling code.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SchedulerProfile {
    /// Pacing family to use.
    pub pacing_family: PacingFamily,
    /// Target burst size in packets.
    pub burst_size_target: u8,
    /// Packet-size target bins in bytes.
    pub packet_size_bins: Vec<(u16, u16)>,
    /// Padding budget in basis points.
    pub padding_budget_bps: u16,
    /// Keepalive mode.
    pub keepalive_mode: KeepaliveMode,
    /// Idle resume behaviour.
    pub idle_resume: IdleResumeBehavior,
    /// Preferred fallback order.
    pub fallback_order: Vec<CarrierBinding>,
    /// Consecutive impairment events before migration is considered.
    pub migration_threshold: u8,
}

/// How a carrier should react to unauthenticated invalid input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvalidInputBehavior {
    /// Emit no response.
    SilentDrop,
    /// Return a generic non-APT failure.
    GenericFailure,
    /// Surface a decoy surface.
    DecoySurface,
}
