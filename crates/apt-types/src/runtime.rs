use crate::{
    config::{KeepaliveTuning, LatencyBudget, PaddingBudget, RekeyLimits},
    defaults::{
        DEFAULT_ADMISSION_EPOCH_SLOT_SECS, DEFAULT_COOKIE_LIFETIME_SECS,
        DEFAULT_REPLAY_RETENTION_SECS,
    },
    network::PathProfile,
    protocol::{CarrierBinding, CipherSuite, PolicyMode},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Current coarse admission time context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionTimeContext {
    /// Current Unix time in seconds.
    pub unix_seconds: u64,
    /// Admission epoch-slot length in seconds.
    pub epoch_slot_length_secs: u64,
}

impl AdmissionTimeContext {
    /// Returns the current coarse epoch slot.
    #[must_use]
    pub const fn epoch_slot(self) -> u64 {
        self.unix_seconds / self.epoch_slot_length_secs
    }
}

/// Rekey phase marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyPhase(pub u8);

impl KeyPhase {
    /// Returns the next key phase.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

/// Compact tunnel header flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PacketFlags {
    /// Whether the packet carries reliable control frames.
    pub has_reliable_control: bool,
    /// Whether the packet carries explicit padding.
    pub has_padding: bool,
}

impl PacketFlags {
    /// Encodes the flags into the logical packet header bitfield.
    #[must_use]
    pub const fn to_bits(self) -> u8 {
        (self.has_reliable_control as u8) | ((self.has_padding as u8) << 1)
    }

    /// Decodes the flags from the logical packet header bitfield.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self {
            has_reliable_control: bits & 0x01 != 0,
            has_padding: bits & 0x02 != 0,
        }
    }
}

/// High-level tunnel frame kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TunnelFrameKind {
    /// Full IPv4 or IPv6 payload.
    IpData,
    /// Reliable-control acknowledgement.
    CtrlAck,
    /// Path challenge.
    PathChallenge,
    /// Path response.
    PathResponse,
    /// Session update / rekey.
    SessionUpdate,
    /// Lightweight ping.
    Ping,
    /// Close frame.
    Close,
    /// Explicit padding.
    Padding,
}

/// Reliable control-frame kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ControlFrameKind {
    /// ACK for a reliable control frame.
    Ack,
    /// Path challenge.
    PathChallenge,
    /// Path response.
    PathResponse,
    /// Session update / rekey.
    SessionUpdate,
    /// Close request.
    Close,
}

/// Capability bitmap for cipher suites.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SuiteBitmap(pub u16);

impl SuiteBitmap {
    /// Returns an empty bitmap.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Returns the baseline-supported bitmap.
    #[must_use]
    pub const fn baseline() -> Self {
        Self(0).with(CipherSuite::X25519ChaChaPolyBlake2s)
    }

    /// Adds a suite to the bitmap.
    #[must_use]
    pub const fn with(self, suite: CipherSuite) -> Self {
        Self(self.0 | (1 << suite.code()))
    }

    /// Returns true if the suite is supported.
    #[must_use]
    pub const fn supports(self, suite: CipherSuite) -> bool {
        self.0 & (1 << suite.code()) != 0
    }

    /// Alias for `supports` used by some crates.
    #[must_use]
    pub const fn contains(self, suite: CipherSuite) -> bool {
        self.supports(suite)
    }

    /// Inserts a suite into the bitmap.
    pub fn insert(&mut self, suite: CipherSuite) {
        self.0 |= 1 << suite.code();
    }

    /// Chooses the first mutually supported suite in conservative order.
    #[must_use]
    pub fn choose(self, other: Self) -> Option<CipherSuite> {
        [
            CipherSuite::NoiseXxPsk2X25519ChaChaPolyBlake2s,
            CipherSuite::HybridMlKem768X25519,
        ]
        .into_iter()
        .find(|suite| self.supports(*suite) && other.supports(*suite))
    }
}

impl FromIterator<CipherSuite> for SuiteBitmap {
    fn from_iter<T: IntoIterator<Item = CipherSuite>>(iter: T) -> Self {
        let mut bitmap = Self::empty();
        for suite in iter {
            bitmap.insert(suite);
        }
        bitmap
    }
}

/// Capability bitmap for carrier bindings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CarrierBitmap(pub u16);

impl CarrierBitmap {
    /// Returns an empty bitmap.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Returns the practical first-milestone carrier set.
    #[must_use]
    pub const fn baseline() -> Self {
        Self(0)
            .with(CarrierBinding::D1)
            .with(CarrierBinding::D2)
            .with(CarrierBinding::S1)
    }

    /// Adds a carrier to the bitmap.
    #[must_use]
    pub const fn with(self, carrier: CarrierBinding) -> Self {
        Self(self.0 | (1 << carrier.code()))
    }

    /// Returns true if the carrier is supported.
    #[must_use]
    pub const fn supports(self, carrier: CarrierBinding) -> bool {
        self.0 & (1 << carrier.code()) != 0
    }

    /// Alias for `supports` used by some crates.
    #[must_use]
    pub const fn contains(self, carrier: CarrierBinding) -> bool {
        self.supports(carrier)
    }

    /// Inserts a carrier into the bitmap.
    pub fn insert(&mut self, carrier: CarrierBinding) {
        self.0 |= 1 << carrier.code();
    }

    /// Chooses the first mutually supported carrier in conservative order.
    #[must_use]
    pub fn choose(self, other: Self) -> Option<CarrierBinding> {
        CarrierBinding::conservative_fallback_order()
            .into_iter()
            .find(|carrier| self.supports(*carrier) && other.supports(*carrier))
    }
}

impl FromIterator<CarrierBinding> for CarrierBitmap {
    fn from_iter<T: IntoIterator<Item = CarrierBinding>>(iter: T) -> Self {
        let mut bitmap = Self::empty();
        for carrier in iter {
            bitmap.insert(carrier);
        }
        bitmap
    }
}

/// Aggregate defaults frequently shared across higher-level configuration code.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProtocolDefaults {
    /// Initial policy mode.
    pub initial_policy_mode: PolicyMode,
    /// Admission epoch-slot length.
    pub admission_epoch_length: Duration,
    /// Replay-cache retention.
    pub replay_cache_retention: Duration,
    /// Anti-amplification cookie lifetime.
    pub cookie_lifetime: Duration,
    /// Queue latency budgets.
    pub latency_budget: LatencyBudget,
    /// Padding budgets.
    pub padding_budget: PaddingBudget,
    /// Keepalive tuning.
    pub keepalive_tuning: KeepaliveTuning,
    /// Rekey limits.
    pub rekey_limits: RekeyLimits,
    /// Minimum replay window size.
    pub minimum_replay_window: usize,
}

impl Default for ProtocolDefaults {
    fn default() -> Self {
        Self {
            initial_policy_mode: PolicyMode::StealthFirst,
            admission_epoch_length: Duration::from_secs(DEFAULT_ADMISSION_EPOCH_SLOT_SECS),
            replay_cache_retention: Duration::from_secs(DEFAULT_REPLAY_RETENTION_SECS),
            cookie_lifetime: Duration::from_secs(DEFAULT_COOKIE_LIFETIME_SECS),
            latency_budget: LatencyBudget::default(),
            padding_budget: PaddingBudget::default(),
            keepalive_tuning: KeepaliveTuning::default(),
            rekey_limits: RekeyLimits::default(),
            minimum_replay_window: usize::try_from(crate::DEFAULT_MIN_REPLAY_WINDOW)
                .expect("default replay window fits into usize"),
        }
    }
}

/// Alias matching the logical naming used in other crates.
pub type PathClasses = PathProfile;
