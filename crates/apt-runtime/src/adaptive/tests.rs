use super::*;

#[test]
fn client_datapath_bootstraps_and_persists_learning() {
    let context = build_client_network_context("edge-a", "198.51.100.10:51820");
    let mut adaptive = AdaptiveDatapath::new_client(
        CarrierBinding::D1DatagramUdp,
        [7_u8; 32],
        context,
        None,
        None,
        PolicyMode::StealthFirst,
        true,
        PathProfile::unknown(),
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
        PolicyMode::StealthFirst,
        true,
        PathProfile::unknown(),
        0,
    );
    adaptive.persona.scheduler.keepalive_mode = KeepaliveMode::SparseCover;
    let frames = adaptive.build_keepalive_frames(80, 10);
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
        PolicyMode::StealthFirst,
        true,
        PathProfile::unknown(),
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
        PolicyMode::SpeedFirst,
        true,
        PathProfile::unknown(),
        0,
    );
    assert!(adaptive.maybe_padding_frame(128, false).is_none());
    assert_eq!(adaptive.build_keepalive_frames(96, 10), vec![Frame::Ping]);
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
        PolicyMode::Balanced,
        true,
        PathProfile::unknown(),
        0,
    );
    let _ = adaptive.maybe_observe_quiet_impairment(60, 0);
    let profile = adaptive.local_normality_profile().unwrap();
    assert_eq!(
        profile
            .carrier_counters(CarrierBinding::D1DatagramUdp)
            .idle_timeouts,
        1
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
        PolicyMode::Balanced,
        true,
        PathProfile::unknown(),
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
