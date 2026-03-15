use super::*;
use apt_types::{CarrierBinding, Mode, PacingFamily, PathProfile};

fn inputs(seed: u8, mode: Mode) -> PersonaInputs {
    PersonaInputs {
        persona_seed: [seed; 32],
        mode,
        path_profile: PathProfile::unknown(),
        chosen_carrier: CarrierBinding::D1DatagramUdp,
        remembered_profile: None,
    }
}

#[test]
fn personas_vary_across_sessions() {
    let a = PersonaEngine::generate(&inputs(1, Mode::BALANCED));
    let b = PersonaEngine::generate(&inputs(2, Mode::BALANCED));
    assert_ne!(a.scheduler.packet_size_bins, b.scheduler.packet_size_bins);
}

#[test]
fn persona_generation_is_coherent_per_session() {
    let input = inputs(7, Mode::BALANCED);
    let a = PersonaEngine::generate(&input);
    let b = PersonaEngine::generate(&input);
    assert_eq!(a, b);
}

#[test]
fn low_mode_endpoint_stays_unshaped() {
    for seed in [1_u8, 7, 19] {
        let persona = PersonaEngine::generate(&inputs(seed, Mode::SPEED));
        assert_eq!(persona.scheduler.pacing_family, PacingFamily::Opportunistic);
        assert_eq!(persona.scheduler.padding_budget_bps, 0);
        assert_eq!(
            persona.scheduler.keepalive_mode,
            KeepaliveMode::SuppressWhenActive
        );
        assert_eq!(persona.scheduler.idle_resume, IdleResumeBehavior::Immediate);
        assert_eq!(persona.idle_resume_ramp_ms, 0);
        assert!((4..=8).contains(&persona.scheduler.burst_size_target));
    }
}

#[test]
fn mid_mode_endpoint_stays_within_mild_caps() {
    for seed in [3_u8, 13, 29] {
        let persona = PersonaEngine::generate(&inputs(seed, Mode::BALANCED));
        assert!(persona.scheduler.padding_budget_bps <= 200);
        assert_eq!(persona.scheduler.keepalive_mode, KeepaliveMode::Adaptive);
        assert!(persona.idle_resume_ramp_ms <= 45);
        assert!((3..=6).contains(&persona.scheduler.burst_size_target));
    }
}

#[test]
fn high_mode_endpoint_stays_within_high_mode_caps() {
    for seed in [5_u8, 17, 31] {
        let persona = PersonaEngine::generate(&inputs(seed, Mode::STEALTH));
        assert!((200..=800).contains(&persona.scheduler.padding_budget_bps));
        assert_ne!(
            persona.scheduler.keepalive_mode,
            KeepaliveMode::SuppressWhenActive
        );
        assert!(persona.idle_resume_ramp_ms <= 100);
        assert!((1..=3).contains(&persona.scheduler.burst_size_target));
        assert!(matches!(
            persona.scheduler.pacing_family,
            PacingFamily::Smooth | PacingFamily::Bursty
        ));
    }
}

#[test]
fn neighboring_modes_change_gradually() {
    let persona_49 = PersonaEngine::generate(&inputs(11, Mode::new(49).unwrap()));
    let persona_50 = PersonaEngine::generate(&inputs(11, Mode::BALANCED));
    assert!(
        (i32::from(persona_49.scheduler.padding_budget_bps)
            - i32::from(persona_50.scheduler.padding_budget_bps))
        .abs()
            <= 24
    );
    assert!(
        (i16::from(persona_49.scheduler.burst_size_target)
            - i16::from(persona_50.scheduler.burst_size_target))
        .abs()
            <= 1
    );
    assert!(
        (i32::from(persona_49.idle_resume_ramp_ms) - i32::from(persona_50.idle_resume_ramp_ms))
            .abs()
            <= 12
    );
}
