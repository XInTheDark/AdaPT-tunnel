//! Shared domain types, configuration primitives, and recommended defaults for
//! Adaptive Persona Tunnel (`APT/1-core`).

mod compat;
mod config;
mod defaults;
mod ids;
mod network;
mod protocol;
mod runtime;

pub use compat::{
    LookupHint, OpaqueMessage, PathSignalEvent, ResumptionTicketClaims, TimingConfig,
};
pub use config::{
    AdmissionDefaults, CredentialIdentity, KeepaliveTuning, LatencyBudget, PaddingBudget,
    RekeyLimits, SchedulerDefaults, SessionPolicy, TunnelDefaults,
};
pub use defaults::{
    DEFAULT_ADMISSION_EPOCH_SLOT_SECS, DEFAULT_BULK_QUEUE_BUDGET_MS, DEFAULT_COOKIE_LIFETIME_SECS,
    DEFAULT_HARD_REKEY_AGE_SECS, DEFAULT_HARD_REKEY_BYTES, DEFAULT_IDLE_KEEPALIVE_BASE_SECS,
    DEFAULT_IDLE_KEEPALIVE_JITTER_PERCENT, DEFAULT_INTERACTIVE_QUEUE_BUDGET_MS,
    DEFAULT_MIN_REPLAY_WINDOW, DEFAULT_PROBATION_PADDING_BPS, DEFAULT_REPLAY_RETENTION_SECS,
    DEFAULT_SOFT_REKEY_AGE_SECS, DEFAULT_SOFT_REKEY_BYTES, DEFAULT_STEADY_PADDING_BPS,
    DEFAULT_TUNNEL_MTU,
};
pub use ids::{ClientNonce, EndpointId, SessionId};
pub use network::{
    ConnectionLongevityClass, GatewayFingerprint, LinkType, LocalNetworkContext, LossClass,
    MtuClass, NatClass, NetworkMetadataObservation, PathClass, PathProfile, PublicRouteHint,
    RttClass,
};
pub use protocol::{
    AuthProfile, CarrierBinding, CipherSuite, CloseCode, ControlReliability, IdleResumeBehavior,
    InvalidInputBehavior, KeepaliveMode, PacingFamily, PolicyMode, SchedulerProfile, SessionRole,
};
pub use runtime::{
    AdmissionTimeContext, CarrierBitmap, ControlFrameKind, KeyPhase, PacketFlags, PathClasses,
    ProtocolDefaults, SuiteBitmap, TunnelFrameKind,
};

/// Alias matching the spec's suite shorthand.
pub type CryptoSuite = CipherSuite;
/// Alias matching the spec's carrier-binding shorthand.
pub type CarrierBindingId = CarrierBinding;
/// Alias matching the spec's tunnel-role naming.
pub type TunnelRole = SessionRole;
/// Alias matching the spec's path summary naming.
pub type PathInfo = PathProfile;

/// Protocol version string for the core profile.
pub const PROTOCOL_VERSION: &str = "APT/1-core";
/// Minimum replay window exported as `usize` for convenience.
pub const MINIMUM_REPLAY_WINDOW: usize = DEFAULT_MIN_REPLAY_WINDOW as usize;
