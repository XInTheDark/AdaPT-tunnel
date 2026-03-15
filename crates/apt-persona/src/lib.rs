//! Persona generation and shaping-profile support.
//!
//! Persona generation remains deterministic per session, but the shaping knobs
//! now scale continuously from the operator-facing numeric `mode` value.

use apt_types::{
    CarrierBinding, IdleResumeBehavior, KeepaliveMode, Mode, PathProfile, PolicyMode,
    SchedulerProfile,
};
use serde::{Deserialize, Serialize};

mod engine;

#[cfg(test)]
mod tests;

/// Optional remembered network profile that can slightly bias persona output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RememberedProfile {
    /// Previously successful primary carrier on the same network.
    pub preferred_carrier: CarrierBinding,
    /// Coarse score describing how permissive the network felt in prior sessions.
    pub permissiveness_score: u8,
}

/// Inputs to persona generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonaInputs {
    /// Session-unique persona seed derived from the handshake.
    pub persona_seed: [u8; 32],
    /// Operator-selected numeric mode.
    pub mode: Mode,
    /// Current coarse path profile.
    pub path_profile: PathProfile,
    /// Chosen carrier family.
    pub chosen_carrier: CarrierBinding,
    /// Current policy mode, used only as a bounded internal bias.
    pub policy_mode: PolicyMode,
    /// Optional remembered profile for this local network.
    pub remembered_profile: Option<RememberedProfile>,
}

/// Additional migration and shaping values produced by a persona.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PersonaProfile {
    /// Scheduler-facing shaping profile.
    pub scheduler: SchedulerProfile,
    /// Whether mild carrier-layer fragmentation is preferred when unavoidable.
    pub prefers_fragmentation: bool,
    /// Soft idle-resume ramp in milliseconds.
    pub idle_resume_ramp_ms: u16,
    /// Suggested standby health-check cadence in seconds.
    pub standby_health_check_secs: u16,
}

/// Stateless persona generator.
#[derive(Clone, Debug, Default)]
pub struct PersonaEngine;
