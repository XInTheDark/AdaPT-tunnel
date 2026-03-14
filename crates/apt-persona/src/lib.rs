//! Persona generation and shaping-profile support.
//!
//! The first-cut implementation is intentionally bounded and deterministic per
//! session. It varies behaviour across sessions and path classes without trying
//! to synthesize arbitrary noise.

use apt_types::{
    CarrierBinding, IdleResumeBehavior, KeepaliveMode, PacingFamily, PathProfile, PolicyMode,
    SchedulerProfile,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    /// Current coarse path profile.
    pub path_profile: PathProfile,
    /// Chosen carrier family.
    pub chosen_carrier: CarrierBinding,
    /// Current policy mode.
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

impl PersonaEngine {
    /// Generates a bounded persona profile for one session.
    #[must_use]
    pub fn generate(inputs: &PersonaInputs) -> PersonaProfile {
        let mut seed_material = Vec::new();
        seed_material.extend_from_slice(&inputs.persona_seed);
        seed_material.push(inputs.chosen_carrier.code());
        seed_material.push(match inputs.policy_mode {
            PolicyMode::StealthFirst => 1,
            PolicyMode::Balanced => 2,
            PolicyMode::SpeedFirst => 3,
        });
        seed_material.push(inputs.path_profile.path as u8);
        seed_material.push(inputs.path_profile.mtu as u8);
        seed_material.push(inputs.path_profile.rtt as u8);
        seed_material.push(inputs.path_profile.loss as u8);
        seed_material.push(inputs.path_profile.nat as u8);
        if let Some(profile) = &inputs.remembered_profile {
            seed_material.push(profile.preferred_carrier.code());
            seed_material.push(profile.permissiveness_score);
        }
        let mut hasher = Sha256::new();
        hasher.update(seed_material);
        let seed: [u8; 32] = hasher.finalize().into();
        let mut rng = ChaCha8Rng::from_seed(seed);

        let pacing_family = match inputs.policy_mode {
            PolicyMode::StealthFirst => {
                if rng.gen_bool(0.6) {
                    PacingFamily::Smooth
                } else {
                    PacingFamily::Bursty
                }
            }
            PolicyMode::Balanced => {
                if rng.gen_bool(0.5) {
                    PacingFamily::Bursty
                } else {
                    PacingFamily::Opportunistic
                }
            }
            PolicyMode::SpeedFirst => PacingFamily::Opportunistic,
        };

        let base_padding_bps = match inputs.policy_mode {
            PolicyMode::StealthFirst => 900,
            PolicyMode::Balanced => 600,
            PolicyMode::SpeedFirst => 250,
        };
        let padding_budget_bps = base_padding_bps + rng.gen_range(0..150);
        let burst_size_target = match inputs.policy_mode {
            PolicyMode::StealthFirst => rng.gen_range(1..=3),
            PolicyMode::Balanced => rng.gen_range(2..=5),
            PolicyMode::SpeedFirst => rng.gen_range(4..=8),
        };
        let keepalive_mode = if matches!(inputs.policy_mode, PolicyMode::SpeedFirst) {
            KeepaliveMode::Adaptive
        } else if rng.gen_bool(0.7) {
            KeepaliveMode::SuppressWhenActive
        } else {
            KeepaliveMode::SparseCover
        };
        let idle_resume = if matches!(inputs.policy_mode, PolicyMode::SpeedFirst) {
            IdleResumeBehavior::Immediate
        } else {
            IdleResumeBehavior::GentleRamp
        };
        let fallback_order = if let Some(profile) = &inputs.remembered_profile {
            let mut order = CarrierBinding::conservative_fallback_order().to_vec();
            if let Some(index) = order
                .iter()
                .position(|binding| *binding == profile.preferred_carrier)
            {
                let preferred = order.remove(index);
                order.insert(0, preferred);
            }
            order
        } else {
            CarrierBinding::conservative_fallback_order().to_vec()
        };
        let first_bin = 220 + rng.gen_range(0..120);
        let second_bin = 520 + rng.gen_range(0..160);
        let third_bin = 920 + rng.gen_range(0..180);
        let scheduler = SchedulerProfile {
            pacing_family,
            burst_size_target,
            packet_size_bins: vec![
                (first_bin, first_bin + 80),
                (second_bin, second_bin + 120),
                (third_bin, third_bin + 180),
            ],
            padding_budget_bps,
            keepalive_mode,
            idle_resume,
            fallback_order,
            migration_threshold: match inputs.policy_mode {
                PolicyMode::StealthFirst => 2,
                PolicyMode::Balanced => 3,
                PolicyMode::SpeedFirst => 4,
            },
        };
        PersonaProfile {
            scheduler,
            prefers_fragmentation: rng.gen_bool(
                matches!(inputs.policy_mode, PolicyMode::StealthFirst)
                    .then_some(0.45)
                    .unwrap_or(0.2),
            ),
            idle_resume_ramp_ms: if matches!(idle_resume, IdleResumeBehavior::GentleRamp) {
                rng.gen_range(25..=90)
            } else {
                0
            },
            standby_health_check_secs: rng.gen_range(15..=45),
        }
    }

    /// Samples a jittered keepalive interval while respecting the safe range from the spec.
    #[must_use]
    pub fn sample_keepalive_interval(
        inputs: &PersonaInputs,
        estimated_binding_secs: Option<u64>,
        sample_index: u64,
    ) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(inputs.persona_seed);
        hasher.update(sample_index.to_be_bytes());
        let seed: [u8; 32] = hasher.finalize().into();
        let mut rng = ChaCha8Rng::from_seed(seed);
        let base = estimated_binding_secs
            .map(|secs| secs.saturating_mul(55) / 100)
            .unwrap_or(25)
            .clamp(15, 120);
        let jitter = rng.gen_range(80..=120);
        base.saturating_mul(jitter) / 100
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apt_types::{CarrierBinding, PathProfile, PolicyMode};

    fn inputs(seed: u8) -> PersonaInputs {
        PersonaInputs {
            persona_seed: [seed; 32],
            path_profile: PathProfile::unknown(),
            chosen_carrier: CarrierBinding::D1DatagramUdp,
            policy_mode: PolicyMode::Balanced,
            remembered_profile: None,
        }
    }

    #[test]
    fn personas_vary_across_sessions() {
        let a = PersonaEngine::generate(&inputs(1));
        let b = PersonaEngine::generate(&inputs(2));
        assert_ne!(a.scheduler.packet_size_bins, b.scheduler.packet_size_bins);
    }

    #[test]
    fn persona_generation_is_coherent_per_session() {
        let input = inputs(7);
        let a = PersonaEngine::generate(&input);
        let b = PersonaEngine::generate(&input);
        assert_eq!(a, b);
    }

    #[test]
    fn keepalive_sampling_stays_within_bounds() {
        let input = inputs(9);
        for index in 0..50 {
            let sample = PersonaEngine::sample_keepalive_interval(&input, Some(80), index);
            assert!((15..=120).contains(&sample));
        }
    }
}
