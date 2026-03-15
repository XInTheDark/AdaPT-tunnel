use super::*;
use apt_types::{MtuClass, NatClass, PacingFamily, PathClass};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};

impl PersonaEngine {
    /// Generates a bounded persona profile for one session.
    #[must_use]
    pub fn generate(inputs: &PersonaInputs) -> PersonaProfile {
        let effective_mode = effective_mode_value(inputs);
        let mut seed_material = Vec::new();
        seed_material.extend_from_slice(&inputs.persona_seed);
        seed_material.push(inputs.mode.value());
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

        let pacing_family = pacing_family_for_mode(effective_mode, &inputs.path_profile, &mut rng);
        let padding_cap_bps = steady_padding_cap_bps(effective_mode);
        let padding_budget_bps = if padding_cap_bps == 0 {
            0
        } else {
            let floor = padding_cap_bps.saturating_mul(3) / 4;
            rng.gen_range(floor..=padding_cap_bps)
        };
        let burst_size_target =
            burst_size_target_for_mode(effective_mode, &inputs.path_profile, &mut rng);
        let keepalive_mode = keepalive_mode_for_mode(effective_mode, inputs, &mut rng);
        let idle_resume_ramp_ms = idle_resume_ramp_ms_for_mode(effective_mode, &mut rng);
        let idle_resume = if idle_resume_ramp_ms == 0 {
            IdleResumeBehavior::Immediate
        } else {
            IdleResumeBehavior::GentleRamp
        };
        let scheduler = SchedulerProfile {
            pacing_family,
            burst_size_target,
            packet_size_bins: packet_size_bins_for_mode(
                effective_mode,
                &inputs.path_profile,
                &mut rng,
            ),
            padding_budget_bps,
            keepalive_mode,
            idle_resume,
            fallback_order: fallback_order_for_mode(effective_mode, inputs),
            migration_threshold: migration_threshold_for_mode(effective_mode),
        };
        PersonaProfile {
            scheduler,
            prefers_fragmentation: rng.gen_range(0..100)
                < fragmentation_probability(effective_mode, &inputs.path_profile),
            idle_resume_ramp_ms,
            standby_health_check_secs: standby_health_check_secs_for_mode(effective_mode, &mut rng),
        }
    }
}

fn effective_mode_value(inputs: &PersonaInputs) -> u8 {
    let mut effective = i16::from(inputs.mode.value());
    effective += match inputs.policy_mode {
        PolicyMode::SpeedFirst => -12,
        PolicyMode::Balanced => 0,
        PolicyMode::StealthFirst => 12,
    };
    effective += match inputs.path_profile.path {
        PathClass::Hostile => 10,
        PathClass::Constrained => 6,
        PathClass::Stable => -4,
        PathClass::Variable | PathClass::Unknown => 0,
    };
    effective += match inputs.path_profile.nat {
        NatClass::Symmetric => 6,
        NatClass::AddressDependent => 3,
        NatClass::OpenInternet => -3,
        NatClass::EndpointIndependent | NatClass::Unknown => 0,
    };
    if let Some(profile) = &inputs.remembered_profile {
        effective += if profile.permissiveness_score >= 192 {
            -6
        } else if profile.permissiveness_score <= 64 {
            6
        } else {
            0
        };
    }
    effective.clamp(i16::from(Mode::MIN), i16::from(Mode::MAX)) as u8
}

fn pacing_family_for_mode(
    effective_mode: u8,
    path_profile: &PathProfile,
    rng: &mut ChaCha8Rng,
) -> PacingFamily {
    if effective_mode == Mode::MIN {
        return PacingFamily::Opportunistic;
    }
    let smooth_chance = segment_lerp_u8(effective_mode, 30, 0, 100, 72)
        .saturating_add(match path_profile.path {
            PathClass::Stable => 8,
            PathClass::Hostile => 6,
            PathClass::Variable | PathClass::Constrained => 4,
            PathClass::Unknown => 0,
        })
        .min(85);
    let bursty_chance = segment_lerp_u8(effective_mode, 5, 12, 100, 46)
        .saturating_sub(smooth_chance / 3)
        .max(10);
    let roll = rng.gen_range(0..100);
    if roll < smooth_chance {
        PacingFamily::Smooth
    } else if effective_mode >= 70 || roll < smooth_chance.saturating_add(bursty_chance) {
        PacingFamily::Bursty
    } else {
        PacingFamily::Opportunistic
    }
}

fn steady_padding_cap_bps(effective_mode: u8) -> u16 {
    if effective_mode == Mode::MIN {
        0
    } else if effective_mode <= 50 {
        segment_lerp_u16(effective_mode, 0, 0, 50, 200)
    } else {
        segment_lerp_u16(effective_mode, 50, 200, 100, 800)
    }
}

fn burst_size_target_for_mode(
    effective_mode: u8,
    path_profile: &PathProfile,
    rng: &mut ChaCha8Rng,
) -> u8 {
    let mut base = if effective_mode <= 50 {
        segment_lerp_u8(effective_mode, 0, 8, 50, 5)
    } else {
        segment_lerp_u8(effective_mode, 50, 5, 100, 2)
    };
    base = match path_profile.path {
        PathClass::Hostile | PathClass::Constrained => base.saturating_sub(1),
        PathClass::Stable if effective_mode <= 20 => base.saturating_add(1),
        PathClass::Variable | PathClass::Unknown | PathClass::Stable => base,
    };
    if matches!(path_profile.mtu, MtuClass::Small) {
        base = base.saturating_sub(1);
    }
    let low = base.saturating_sub(1).max(1);
    let high = base.saturating_add(1).min(8);
    rng.gen_range(low..=high).clamp(1, 8)
}

fn keepalive_mode_for_mode(
    effective_mode: u8,
    inputs: &PersonaInputs,
    rng: &mut ChaCha8Rng,
) -> KeepaliveMode {
    if effective_mode == Mode::MIN {
        return KeepaliveMode::SuppressWhenActive;
    }
    let sparse_cover_chance =
        sparse_cover_probability(effective_mode, &inputs.path_profile, inputs);
    if rng.gen_range(0..100) < sparse_cover_chance {
        KeepaliveMode::SparseCover
    } else {
        KeepaliveMode::Adaptive
    }
}

fn sparse_cover_probability(
    effective_mode: u8,
    path_profile: &PathProfile,
    inputs: &PersonaInputs,
) -> u8 {
    if effective_mode < 70 {
        return 0;
    }
    let mut chance = segment_lerp_u8(effective_mode, 70, 10, 100, 65);
    chance = chance.saturating_add(match path_profile.path {
        PathClass::Hostile => 10,
        PathClass::Constrained => 6,
        PathClass::Stable | PathClass::Variable | PathClass::Unknown => 0,
    });
    chance = chance.saturating_add(match path_profile.nat {
        NatClass::Symmetric => 8,
        NatClass::AddressDependent => 4,
        NatClass::OpenInternet | NatClass::EndpointIndependent | NatClass::Unknown => 0,
    });
    if let Some(profile) = &inputs.remembered_profile {
        chance = chance.saturating_sub(profile.permissiveness_score / 32);
    }
    chance.min(75)
}

fn idle_resume_ramp_ms_for_mode(effective_mode: u8, rng: &mut ChaCha8Rng) -> u16 {
    let cap = if effective_mode <= 20 {
        0
    } else if effective_mode <= 50 {
        segment_lerp_u16(effective_mode, 20, 0, 50, 45)
    } else {
        segment_lerp_u16(effective_mode, 50, 45, 100, 100)
    };
    if cap == 0 {
        0
    } else {
        let floor = cap.saturating_mul(3) / 5;
        rng.gen_range(floor.max(1)..=cap)
    }
}

fn fallback_order_for_mode(effective_mode: u8, inputs: &PersonaInputs) -> Vec<CarrierBinding> {
    let mut scored = CarrierBinding::conservative_fallback_order()
        .into_iter()
        .enumerate()
        .map(|(index, binding)| {
            let mut score = match binding {
                CarrierBinding::D1DatagramUdp => 180 - i16::from(effective_mode),
                CarrierBinding::D2EncryptedDatagram => 135 + i16::from(effective_mode / 3),
                CarrierBinding::S1EncryptedStream => 90 + i16::from(effective_mode),
                CarrierBinding::H1RequestResponse => 10,
            };
            score += match inputs.path_profile.path {
                PathClass::Hostile => match binding {
                    CarrierBinding::S1EncryptedStream => 24,
                    CarrierBinding::D2EncryptedDatagram => 10,
                    CarrierBinding::D1DatagramUdp => -18,
                    CarrierBinding::H1RequestResponse => 0,
                },
                PathClass::Constrained => match binding {
                    CarrierBinding::S1EncryptedStream => 14,
                    CarrierBinding::D2EncryptedDatagram => 6,
                    CarrierBinding::D1DatagramUdp => -8,
                    CarrierBinding::H1RequestResponse => 0,
                },
                PathClass::Stable | PathClass::Variable | PathClass::Unknown => 0,
            };
            if let Some(profile) = &inputs.remembered_profile {
                if binding == profile.preferred_carrier {
                    score += 60;
                }
            }
            (binding, score, index)
        })
        .collect::<Vec<_>>();
    scored.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.2.cmp(&right.2)));
    scored.into_iter().map(|(binding, _, _)| binding).collect()
}

fn packet_size_bins_for_mode(
    effective_mode: u8,
    path_profile: &PathProfile,
    rng: &mut ChaCha8Rng,
) -> Vec<(u16, u16)> {
    let path_penalty = match path_profile.path {
        PathClass::Hostile => 120_u16,
        PathClass::Constrained => 90,
        PathClass::Variable => 40,
        PathClass::Stable | PathClass::Unknown => 0,
    } + match path_profile.mtu {
        MtuClass::Small => 140,
        MtuClass::Medium => 40,
        MtuClass::Large | MtuClass::Unknown => 0,
    };
    let first_center = segment_lerp_u16(effective_mode, 0, 320, 100, 240)
        .saturating_sub(path_penalty / 4)
        .saturating_add(rng.gen_range(0..=24));
    let second_center = segment_lerp_u16(effective_mode, 0, 760, 100, 560)
        .saturating_sub(path_penalty / 2)
        .saturating_add(rng.gen_range(0..=40));
    let third_center = segment_lerp_u16(effective_mode, 0, 1_320, 100, 980)
        .saturating_sub(path_penalty)
        .saturating_add(rng.gen_range(0..=60));
    let first_width = segment_lerp_u16(effective_mode, 0, 110, 100, 80);
    let second_width = segment_lerp_u16(effective_mode, 0, 170, 100, 120);
    let third_width = segment_lerp_u16(effective_mode, 0, 240, 100, 180);
    vec![
        centered_bin(first_center.max(180), first_width),
        centered_bin(second_center.max(420), second_width),
        centered_bin(third_center.max(760), third_width),
    ]
}

fn migration_threshold_for_mode(effective_mode: u8) -> u8 {
    if effective_mode <= 50 {
        segment_lerp_u8(effective_mode, 0, 5, 50, 3)
    } else {
        segment_lerp_u8(effective_mode, 50, 3, 100, 2)
    }
}

fn fragmentation_probability(effective_mode: u8, path_profile: &PathProfile) -> u8 {
    let mut chance = if effective_mode <= 25 {
        0
    } else if effective_mode <= 50 {
        segment_lerp_u8(effective_mode, 25, 0, 50, 20)
    } else {
        segment_lerp_u8(effective_mode, 50, 20, 100, 55)
    };
    chance = chance.saturating_add(match path_profile.mtu {
        MtuClass::Small => 30,
        MtuClass::Medium => 10,
        MtuClass::Large | MtuClass::Unknown => 0,
    });
    chance = chance.saturating_add(match path_profile.path {
        PathClass::Hostile => 20,
        PathClass::Constrained => 12,
        PathClass::Stable | PathClass::Variable | PathClass::Unknown => 0,
    });
    chance.min(85)
}

fn standby_health_check_secs_for_mode(effective_mode: u8, rng: &mut ChaCha8Rng) -> u16 {
    let target = if effective_mode <= 50 {
        segment_lerp_u16(effective_mode, 0, 15, 50, 30)
    } else {
        segment_lerp_u16(effective_mode, 50, 30, 100, 45)
    };
    let floor = target.saturating_sub(4).max(10);
    let ceil = target.saturating_add(4);
    rng.gen_range(floor..=ceil)
}

fn centered_bin(center: u16, width: u16) -> (u16, u16) {
    let half = width / 2;
    (center.saturating_sub(half), center.saturating_add(half))
}

fn segment_lerp_u8(mode: u8, start_mode: u8, start_value: u8, end_mode: u8, end_value: u8) -> u8 {
    segment_lerp_u16(
        mode,
        start_mode,
        u16::from(start_value),
        end_mode,
        u16::from(end_value),
    ) as u8
}

fn segment_lerp_u16(
    mode: u8,
    start_mode: u8,
    start_value: u16,
    end_mode: u8,
    end_value: u16,
) -> u16 {
    if mode <= start_mode {
        return start_value;
    }
    if mode >= end_mode {
        return end_value;
    }
    let span = u32::from(end_mode.saturating_sub(start_mode)).max(1);
    let progress = u32::from(mode.saturating_sub(start_mode));
    let start = u32::from(start_value);
    let end = u32::from(end_value);
    if end >= start {
        (start + ((end - start) * progress + (span / 2)) / span) as u16
    } else {
        (start - ((start - end) * progress + (span / 2)) / span) as u16
    }
}
