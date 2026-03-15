use super::*;
use crate::config::{PersistedIdleOutcomeSummary, PersistedKeepaliveLearningState};

fn runtime_config(initial_mode: PolicyMode, operator_mode: Mode) -> AdaptiveRuntimeConfig {
    AdaptiveRuntimeConfig {
        initial_mode,
        operator_mode,
        allow_speed_first_by_policy: true,
        keepalive_base_interval_secs: 25,
    }
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
        runtime_config(PolicyMode::StealthFirst, Mode::STEALTH),
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
        runtime_config(PolicyMode::StealthFirst, Mode::STEALTH),
        PathProfile::unknown(),
        None,
        0,
    );
    adaptive.persona.scheduler.keepalive_mode = KeepaliveMode::SparseCover;
    let frames = adaptive.build_keepalive_frames(80);
    assert!(matches!(frames.first(), Some(Frame::Ping)));
    assert!(frames
        .iter()
        .any(|frame| matches!(frame, Frame::Padding(_))));
}

#[test]
fn stable_delivery_can_change_policy_mode() {
    let context = build_client_network_context("edge-a", "route-a");
    let mut adaptive = AdaptiveDatapath::new_client(
        CarrierBinding::D1DatagramUdp,
        [19_u8; 32],
        context,
        None,
        None,
        runtime_config(PolicyMode::StealthFirst, Mode::STEALTH),
        PathProfile::unknown(),
        None,
        0,
    );
    for tick in [15, 30, 45, 60, 75] {
        let _ = adaptive.maybe_observe_stability(tick);
    }
    assert_eq!(adaptive.current_mode(), PolicyMode::Balanced);
}

#[test]
fn speed_first_mode_disables_cover_padding() {
    let context = build_client_network_context("edge-a", "route-a");
    let mut adaptive = AdaptiveDatapath::new_client(
        CarrierBinding::D1DatagramUdp,
        [23_u8; 32],
        context,
        None,
        None,
        runtime_config(PolicyMode::SpeedFirst, Mode::SPEED),
        PathProfile::unknown(),
        None,
        0,
    );
    assert!(adaptive.maybe_padding_frame(128, false).is_none());
    assert_eq!(adaptive.build_keepalive_frames(96), vec![Frame::Ping]);
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
        runtime_config(PolicyMode::Balanced, Mode::BALANCED),
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
        runtime_config(PolicyMode::Balanced, Mode::BALANCED),
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
        runtime_config(PolicyMode::Balanced, Mode::BALANCED),
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
        runtime_config(PolicyMode::StealthFirst, Mode::STEALTH),
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
        runtime_config(PolicyMode::Balanced, Mode::BALANCED),
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
        runtime_config(PolicyMode::StealthFirst, Mode::STEALTH),
        PathProfile::unknown(),
        None,
        0,
    );
    stealth.persona.scheduler.keepalive_mode = KeepaliveMode::SparseCover;
    assert_eq!(stealth.keepalive_mode(), KeepaliveMode::SparseCover);
}
