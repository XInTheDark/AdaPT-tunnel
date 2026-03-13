//! Recommended defaults from `SPEC_v1.md` §25.

/// Admission epoch slot length in seconds.
pub const DEFAULT_ADMISSION_EPOCH_SLOT_SECS: u64 = 300;
/// Replay retention horizon in seconds.
pub const DEFAULT_REPLAY_RETENTION_SECS: u64 = 600;
/// Cookie lifetime in seconds.
pub const DEFAULT_COOKIE_LIFETIME_SECS: u64 = 20;
/// Recommended added latency budget for interactive traffic.
pub const DEFAULT_INTERACTIVE_QUEUE_BUDGET_MS: u16 = 10;
/// Recommended added latency budget for bulk traffic.
pub const DEFAULT_BULK_QUEUE_BUDGET_MS: u16 = 50;
/// Recommended steady-state padding budget in basis points (6%).
pub const DEFAULT_STEADY_PADDING_BPS: u16 = 600;
/// Recommended probation padding budget in basis points (20%).
pub const DEFAULT_PROBATION_PADDING_BPS: u16 = 2_000;
/// Unknown-NAT keepalive base interval in seconds.
pub const DEFAULT_IDLE_KEEPALIVE_BASE_SECS: u16 = 25;
/// Unknown-NAT keepalive jitter percentage (±35%).
pub const DEFAULT_IDLE_KEEPALIVE_JITTER_PERCENT: u8 = 35;
/// Soft rekey byte limit.
pub const DEFAULT_SOFT_REKEY_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Soft rekey wall-clock age in seconds.
pub const DEFAULT_SOFT_REKEY_AGE_SECS: u64 = 20 * 60;
/// Hard rekey byte limit.
pub const DEFAULT_HARD_REKEY_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// Hard rekey wall-clock age in seconds.
pub const DEFAULT_HARD_REKEY_AGE_SECS: u64 = 60 * 60;
/// Minimum replay window size.
pub const DEFAULT_MIN_REPLAY_WINDOW: u64 = 4_096;
/// Conservative default tunnel MTU used before path evidence exists.
pub const DEFAULT_TUNNEL_MTU: u16 = 1_200;
