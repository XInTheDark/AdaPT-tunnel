use super::*;
use crate::config::{PersistedIdleOutcomeSummary, PersistedKeepaliveLearningState};

fn runtime_config(mode: Mode) -> AdaptiveRuntimeConfig {
    AdaptiveRuntimeConfig {
        negotiated_mode: mode,
        persisted_mode: None,
        preferred_carrier: None,
        keepalive_base_interval_secs: 25,
    }
}

fn bootstrapped_profile(context: LocalNetworkContext) -> LocalNormalityProfile {
    let mut profile = LocalNormalityProfile::new(context);
    for _ in 0..3 {
        profile.note_successful_session();
        profile.begin_new_session();
    }
    profile
}

#[test]
fn client_datapath_bootstraps_and_persists_learning() {
    let context = build_client_network_context("edge-a", "198.51.100.10:51820");
    let mut adaptive = AdaptiveDatapath::new_client(
        CarrierBinding::D1DatagramUdp,
        [7_u8; 32],
        context,
        None,
        None,
        runtime_config(Mode::STEALTH),
        PathProfile::unknown(),
        None,
        0,
    );
    adaptive.note_successful_session();
    adaptive.record_outbound(900, 2, 50);
    adaptive.record_inbound(1_050, 75);
    assert!(adaptive.local_normality_profile().is_some());
    assert!(adaptive.remembered_profile().is_some());
}

#[test]
fn keepalive_frames_include_cover_padding_when_sparse_cover_is_active() {
    let context = build_client_network_context("edge-a", "route-a");
    let mut adaptive = AdaptiveDatapath::new_client(
        CarrierBinding::D1DatagramUdp,
        [11_u8; 32],
        context,
        None,
        None,
        runtime_config(Mode::STEALTH),
        PathProfile::unknown(),
        None,
        0,
    );
    adaptive.persona.scheduler.keepalive_mode = KeepaliveMode::SparseCover;
    let frames = adaptive.build_keepalive_frames(80, 10_000);
    assert!(matches!(frames.first(), Some(Frame::Ping)));
    assert!(frames
        .iter()
        .any(|frame| matches!(frame, Frame::Padding(_))));
}

#[test]
fn stable_delivery_reduces_seeded_conservative_bias() {
    let context = build_client_network_context("edge-a", "route-a");
    let mut adaptive = AdaptiveDatapath::new_client(
        CarrierBinding::D1DatagramUdp,
        [19_u8; 32],
        context.clone(),
        Some(bootstrapped_profile(context)),
        None,
        AdaptiveRuntimeConfig {
            negotiated_mode: Mode::BALANCED,
            persisted_mode: Some(Mode::new(72).unwrap()),
            preferred_carrier: None,
            keepalive_base_interval_secs: 25,
        },
        PathProfile::unknown(),
        None,
        0,
    );
    let initial_mode = adaptive.current_mode().value();
    for tick in [15, 30, 45, 60, 75] {
        let _ = adaptive.maybe_observe_stability(tick);
    }
    assert!(adaptive.current_mode().value() < initial_mode);
    assert!(adaptive.current_mode().value() >= Mode::BALANCED.value());
}

#[test]
fn bootstrapped_speed_mode_disables_cover_padding() {
    let context = build_client_network_context("edge-a", "route-a");
    let mut adaptive = AdaptiveDatapath::new_client(
        CarrierBinding::D1DatagramUdp,
        [23_u8; 32],
        context.clone(),
        Some(bootstrapped_profile(context)),
        None,
        runtime_config(Mode::SPEED),
        PathProfile::unknown(),
        None,
        0,
    );
    assert_eq!(adaptive.current_mode(), Mode::SPEED);
    assert!(adaptive.maybe_padding_frame(128, false, 10_000).is_none());
    assert_eq!(
        adaptive.build_keepalive_frames(96, 10_000),
        vec![Frame::Ping]
    );
    assert_eq!(adaptive.keepalive_mode(), KeepaliveMode::SuppressWhenActive);
}

#[test]
fn local_network_profile_key_is_stable_for_equivalent_contexts() {
    let a = LocalNetworkContext {
        link_type: LinkType::Named(" WiFi ".to_string()),
        gateway: GatewayFingerprint(" GW-A ".to_string()),
        local_label: "Home SSID".to_string(),
        public_route: PublicRouteHint("D1:198.51.100.10:51820".to_string()),
    };
    let b = LocalNetworkContext {
        link_type: LinkType::Named("wifi".to_string()),
        gateway: GatewayFingerprint("gw-a".to_string()),
        local_label: "home ssid".to_string(),
        public_route: PublicRouteHint("d1:198.51.100.10:51820".to_string()),
    };
    assert_eq!(local_network_profile_key(&a), local_network_profile_key(&b));
}

#[test]
fn quiet_impairment_records_idle_timeout_evidence() {
    let context = build_client_network_context("edge-a", "route-a");
    let mut adaptive = AdaptiveDatapath::new_client(
        CarrierBinding::D1DatagramUdp,
        [29_u8; 32],
        context,
        None,
        None,
        runtime_config(Mode::BALANCED),
        PathProfile::unknown(),
        None,
        0,
    );
    adaptive.note_keepalive_sent(25);
    let _ = adaptive.maybe_observe_quiet_impairment(70, 0, 0);
    let profile = adaptive.local_normality_profile().unwrap();
    assert_eq!(
        profile
            .carrier_counters(CarrierBinding::D1DatagramUdp)
            .idle_timeouts,
        1
    );
    assert_eq!(adaptive.keepalive_target_interval_secs(), 17);
    assert_eq!(
        adaptive.keepalive_learning_state().last_idle_outcome,
        PersistedIdleOutcomeSummary::QuietTimeout
    );
}

#[test]
fn remembered_profile_comes_from_learned_local_summary_when_available() {
    let context = build_client_network_context("edge-a", "route-a");
    let mut adaptive = AdaptiveDatapath::new_client(
        CarrierBinding::D1DatagramUdp,
        [31_u8; 32],
        context,
        None,
        None,
        runtime_config(Mode::BALANCED),
        PathProfile::unknown(),
        None,
        0,
    );
    for sample in 0..24 {
        adaptive.record_outbound(1_350, 3, sample * 20);
    }
    adaptive.note_successful_session();
    adaptive.note_successful_session();
    let remembered = adaptive.remembered_profile().unwrap();
    assert_eq!(remembered.preferred_carrier, CarrierBinding::D1DatagramUdp);
    assert!(remembered.permissiveness_score >= 128);
}

#[test]
fn adaptive_keepalive_success_grows_target_interval_by_ten_percent() {
    let context = build_client_network_context("edge-a", "route-a");
    let mut adaptive = AdaptiveDatapath::new_client(
        CarrierBinding::D1DatagramUdp,
        [37_u8; 32],
        context,
        None,
        None,
        runtime_config(Mode::BALANCED),
        PathProfile::unknown(),
        None,
        0,
    );
    adaptive.note_keepalive_sent(25);
    adaptive.note_keepalive_sent(50);
    assert_eq!(adaptive.keepalive_target_interval_secs(), 28);
    assert_eq!(
        adaptive.keepalive_learning_state().last_idle_outcome,
        PersistedIdleOutcomeSummary::IdleSurvived
    );
}

#[test]
fn persisted_keepalive_learning_state_is_reused() {
    let context = build_client_network_context("edge-a", "route-a");
    let adaptive = AdaptiveDatapath::new_client(
        CarrierBinding::D1DatagramUdp,
        [41_u8; 32],
        context,
        None,
        None,
        runtime_config(Mode::STEALTH),
        PathProfile::unknown(),
        Some(PersistedKeepaliveLearningState {
            current_target_interval_secs: 60,
            last_idle_outcome: PersistedIdleOutcomeSummary::IdleSurvived,
            success_counter: 4,
            failure_counter: 1,
        }),
        0,
    );
    assert_eq!(adaptive.keepalive_target_interval_secs(), 60);
    assert_eq!(
        adaptive.keepalive_learning_state().last_idle_outcome,
        PersistedIdleOutcomeSummary::IdleSurvived
    );
}

#[test]
fn non_speed_modes_use_real_adaptive_keepalive_paths() {
    let context = build_client_network_context("edge-a", "route-a");
    let mut balanced = AdaptiveDatapath::new_client(
        CarrierBinding::D1DatagramUdp,
        [43_u8; 32],
        context.clone(),
        None,
        None,
        runtime_config(Mode::BALANCED),
        PathProfile::unknown(),
        None,
        0,
    );
    balanced.persona.scheduler.keepalive_mode = KeepaliveMode::SuppressWhenActive;
    assert_eq!(balanced.keepalive_mode(), KeepaliveMode::Adaptive);

    let mut stealth = AdaptiveDatapath::new_client(
        CarrierBinding::D1DatagramUdp,
        [47_u8; 32],
        context,
        None,
        None,
        runtime_config(Mode::STEALTH),
        PathProfile::unknown(),
        None,
        0,
    );
    stealth.persona.scheduler.keepalive_mode = KeepaliveMode::SparseCover;
    assert_eq!(stealth.keepalive_mode(), KeepaliveMode::SparseCover);
}

#[test]
fn constrained_high_mode_prefers_smaller_bursts_and_packing_targets() {
    let context = build_client_network_context("edge-a", "route-a");
    let mut adaptive = AdaptiveDatapath::new_client(
        CarrierBinding::S1EncryptedStream,
        [53_u8; 32],
        context,
        None,
        None,
        runtime_config(Mode::STEALTH),
        PathProfile::unknown(),
        None,
        0,
    );
    adaptive.path_profile.path = PathClass::Constrained;
    adaptive.path_profile.mtu = apt_types::MtuClass::Small;
    adaptive.persona.prefers_fragmentation = true;
    adaptive.begin_outbound_data_send(10_000);
    assert!(adaptive.burst_cap(CarrierBinding::S1EncryptedStream, 10_000) <= 2);
    assert!(adaptive.soft_packing_target_bytes(CarrierBinding::S1EncryptedStream) < 900);
}

#[test]
fn pacing_delay_respects_mode_caps() {
    let balanced_context = build_client_network_context("edge-a", "route-a");
    let mut balanced = AdaptiveDatapath::new_client(
        CarrierBinding::S1EncryptedStream,
        [59_u8; 32],
        balanced_context.clone(),
        Some(bootstrapped_profile(balanced_context)),
        None,
        runtime_config(Mode::BALANCED),
        PathProfile::unknown(),
        None,
        0,
    );
    balanced.persona.scheduler.pacing_family = apt_types::PacingFamily::Smooth;
    let interactive_delay = balanced.pacing_delay_ms(
        CarrierBinding::S1EncryptedStream,
        &[Frame::IpData(vec![0_u8; 200])],
        1,
        0,
        1_000,
    );
    assert!(interactive_delay <= 3);

    let stealth_context = build_client_network_context("edge-a", "route-a");
    let mut stealth = AdaptiveDatapath::new_client(
        CarrierBinding::S1EncryptedStream,
        [61_u8; 32],
        stealth_context,
        None,
        None,
        runtime_config(Mode::STEALTH),
        PathProfile::unknown(),
        None,
        0,
    );
    stealth.persona.scheduler.pacing_family = apt_types::PacingFamily::Smooth;
    let bulk_delay = stealth.pacing_delay_ms(
        CarrierBinding::S1EncryptedStream,
        &[
            Frame::IpData(vec![0_u8; 1_200]),
            Frame::IpData(vec![0_u8; 1_200]),
        ],
        1,
        0,
        1_000,
    );
    assert!(bulk_delay <= 40);
    assert!(bulk_delay > 0);
}

#[test]
fn datagram_paths_skip_steady_per_packet_pacing() {
    let context = build_client_network_context("edge-a", "route-a");
    let mut adaptive = AdaptiveDatapath::new_client(
        CarrierBinding::D1DatagramUdp,
        [67_u8; 32],
        context,
        Some(bootstrapped_profile(build_client_network_context(
            "edge-a", "route-a",
        ))),
        None,
        runtime_config(Mode::STEALTH),
        PathProfile::unknown(),
        None,
        0,
    );
    adaptive.persona.scheduler.pacing_family = apt_types::PacingFamily::Smooth;
    let delay = adaptive.pacing_delay_ms(
        CarrierBinding::D1DatagramUdp,
        &[Frame::IpData(vec![0_u8; 1_200])],
        1,
        0,
        1_000,
    );
    assert_eq!(delay, 0);
}
