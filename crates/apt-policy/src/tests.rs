use super::{LocalNormalityProfile, PolicyController};
use apt_types::{
    ConnectionLongevityClass, GatewayFingerprint, LinkType, LocalNetworkContext, LossClass,
    MtuClass, NatClass, NetworkMetadataObservation, PathClass, PathProfile, PathSignalEvent,
    PolicyMode, PublicRouteHint, RttClass,
};

fn context() -> LocalNetworkContext {
    LocalNetworkContext {
        link_type: LinkType::Wifi,
        gateway: GatewayFingerprint("gw-a".to_string()),
        local_label: "ssid-a".to_string(),
        public_route: PublicRouteHint("route-a".to_string()),
    }
}

fn observation(packet_size: u16, tunnel_traffic: bool) -> NetworkMetadataObservation {
    NetworkMetadataObservation {
        packet_size,
        inter_send_gap_ms: 50,
        burst_length: 4,
        upstream_downstream_ratio_class: 2,
        path_profile: PathProfile {
            path: PathClass::Stable,
            mtu: MtuClass::Medium,
            rtt: RttClass::Moderate,
            loss: LossClass::Low,
            nat: NatClass::EndpointIndependent,
        },
        longevity: ConnectionLongevityClass::Moderate,
        tunnel_traffic,
    }
}

#[test]
fn bootstrap_requires_enough_weight_or_successes() {
    let mut profile = LocalNormalityProfile::new(context());
    for _ in 0..50 {
        profile.record_observation(&observation(700, true));
    }
    assert!(!profile.is_bootstrapped());
    for _ in 0..3 {
        profile.note_successful_session();
    }
    assert!(profile.is_bootstrapped());
}

#[test]
fn tunnel_traffic_counts_less_than_non_tunnel() {
    let mut profile = LocalNormalityProfile::new(context());
    profile.record_observation(&observation(200, true));
    profile.record_observation(&observation(1_400, false));
    let summary = profile.summary().unwrap();
    assert_eq!(summary.median_packet_size, 1_400);
}

#[test]
fn controller_moves_between_modes() {
    let mut controller = PolicyController::new(PolicyMode::StealthFirst, true);
    for _ in 0..5 {
        controller.observe_signal(PathSignalEvent::StableDelivery);
    }
    assert_eq!(controller.current_mode, PolicyMode::Balanced);
    for _ in 0..6 {
        controller.observe_signal(PathSignalEvent::StableDelivery);
    }
    assert_eq!(controller.current_mode, PolicyMode::SpeedFirst);
    controller.observe_signal(PathSignalEvent::ImmediateReset);
    controller.observe_signal(PathSignalEvent::ImmediateReset);
    assert_eq!(controller.current_mode, PolicyMode::StealthFirst);
}
