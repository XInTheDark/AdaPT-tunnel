use crate::{
    defaults::{
        DEFAULT_ADMISSION_EPOCH_SLOT_SECS, DEFAULT_BULK_QUEUE_BUDGET_MS,
        DEFAULT_COOKIE_LIFETIME_SECS, DEFAULT_HARD_REKEY_AGE_SECS, DEFAULT_HARD_REKEY_BYTES,
        DEFAULT_IDLE_KEEPALIVE_BASE_SECS, DEFAULT_IDLE_KEEPALIVE_JITTER_PERCENT,
        DEFAULT_INTERACTIVE_QUEUE_BUDGET_MS, DEFAULT_MIN_REPLAY_WINDOW,
        DEFAULT_PROBATION_PADDING_BPS, DEFAULT_REPLAY_RETENTION_SECS, DEFAULT_SOFT_REKEY_AGE_SECS,
        DEFAULT_SOFT_REKEY_BYTES, DEFAULT_STEADY_PADDING_BPS, DEFAULT_TUNNEL_MTU,
    },
    protocol::PolicyMode,
};
use serde::{Deserialize, Serialize};

/// Admission-plane timing defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionDefaults {
    /// Time bucket size for admission-key derivation.
    pub epoch_slot_secs: u64,
    /// Replay cache retention horizon.
    pub replay_retention_secs: u64,
    /// Anti-amplification cookie lifetime.
    pub cookie_lifetime_secs: u64,
}

impl Default for AdmissionDefaults {
    fn default() -> Self {
        Self {
            epoch_slot_secs: DEFAULT_ADMISSION_EPOCH_SLOT_SECS,
            replay_retention_secs: DEFAULT_REPLAY_RETENTION_SECS,
            cookie_lifetime_secs: DEFAULT_COOKIE_LIFETIME_SECS,
        }
    }
}

/// Rekeying limits for a live tunnel session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RekeyLimits {
    /// Soft byte limit.
    pub soft_bytes: u64,
    /// Hard byte limit.
    pub hard_bytes: u64,
    /// Soft wall-clock age in seconds.
    pub soft_age_secs: u64,
    /// Hard wall-clock age in seconds.
    pub hard_age_secs: u64,
}

impl RekeyLimits {
    /// Conservative recommended limits from the spec.
    #[must_use]
    pub const fn recommended() -> Self {
        Self {
            soft_bytes: DEFAULT_SOFT_REKEY_BYTES,
            hard_bytes: DEFAULT_HARD_REKEY_BYTES,
            soft_age_secs: DEFAULT_SOFT_REKEY_AGE_SECS,
            hard_age_secs: DEFAULT_HARD_REKEY_AGE_SECS,
        }
    }
}

impl Default for RekeyLimits {
    fn default() -> Self {
        Self::recommended()
    }
}

/// Added-latency budgets for the scheduler.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencyBudget {
    /// Added delay budget for interactive traffic.
    pub interactive_ms: u16,
    /// Added delay budget for bulk traffic.
    pub bulk_ms: u16,
}

impl Default for LatencyBudget {
    fn default() -> Self {
        Self {
            interactive_ms: DEFAULT_INTERACTIVE_QUEUE_BUDGET_MS,
            bulk_ms: DEFAULT_BULK_QUEUE_BUDGET_MS,
        }
    }
}

/// Basis-point padding budgets for different shaping phases.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaddingBudget {
    /// Rendezvous / probation padding budget.
    pub probation_bps: u16,
    /// Steady-state padding budget.
    pub steady_state_bps: u16,
    /// Crisis-mode ceiling.
    pub crisis_bps: u16,
}

impl PaddingBudget {
    /// Returns a budget ratio as a floating-point number.
    #[must_use]
    pub fn ratio(basis_points: u16) -> f32 {
        f32::from(basis_points) / 10_000.0
    }
}

impl Default for PaddingBudget {
    fn default() -> Self {
        Self {
            probation_bps: DEFAULT_PROBATION_PADDING_BPS,
            steady_state_bps: DEFAULT_STEADY_PADDING_BPS,
            crisis_bps: DEFAULT_PROBATION_PADDING_BPS.saturating_mul(2),
        }
    }
}

/// Keepalive tuning for NAT binding maintenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeepaliveTuning {
    /// Base interval in seconds when NAT lifetime is unknown.
    pub base_interval_secs: u16,
    /// Symmetric jitter percentage applied around the base interval.
    pub jitter_percent: u8,
    /// Hard minimum interval.
    pub min_interval_secs: u16,
    /// Hard maximum interval.
    pub max_interval_secs: u16,
}

impl Default for KeepaliveTuning {
    fn default() -> Self {
        Self {
            base_interval_secs: DEFAULT_IDLE_KEEPALIVE_BASE_SECS,
            jitter_percent: DEFAULT_IDLE_KEEPALIVE_JITTER_PERCENT,
            min_interval_secs: 15,
            max_interval_secs: 120,
        }
    }
}

/// Scheduler-facing defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerDefaults {
    /// Queue latency budgets.
    pub latency: LatencyBudget,
    /// Padding budgets.
    pub padding: PaddingBudget,
    /// Keepalive tuning.
    pub keepalive: KeepaliveTuning,
}

impl Default for SchedulerDefaults {
    fn default() -> Self {
        Self {
            latency: LatencyBudget::default(),
            padding: PaddingBudget::default(),
            keepalive: KeepaliveTuning::default(),
        }
    }
}

/// Tunnel dataplane defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelDefaults {
    /// Minimum replay window size.
    pub min_replay_window: u64,
    /// Conservative default tunnel MTU.
    pub tunnel_mtu: u16,
}

impl Default for TunnelDefaults {
    fn default() -> Self {
        Self {
            min_replay_window: DEFAULT_MIN_REPLAY_WINDOW,
            tunnel_mtu: DEFAULT_TUNNEL_MTU,
        }
    }
}

/// Provisioned credential identity used in replay/accounting metadata.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CredentialIdentity {
    /// One shared deployment identity.
    SharedDeployment,
    /// Per-user identity.
    User(String),
}

/// Session-wide policy and default knobs chosen for a deployment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPolicy {
    /// Initial policy mode.
    pub initial_mode: PolicyMode,
    /// Whether speed-first mode may ever be entered automatically.
    pub allow_speed_first: bool,
    /// Whether hybrid PQ may be negotiated if both sides support it.
    pub allow_hybrid_pq: bool,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            initial_mode: PolicyMode::StealthFirst,
            allow_speed_first: false,
            allow_hybrid_pq: false,
        }
    }
}
