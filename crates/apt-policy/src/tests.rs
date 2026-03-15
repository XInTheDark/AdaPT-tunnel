use super::{inferred_path_profile, LocalNormalityProfile, PolicyController};
use apt_types::{
    CarrierBinding, ConnectionLongevityClass, GatewayFingerprint, LinkType, LossClass, Mode,
    MtuClass, NatClass, NetworkMetadataObservation, PathClass, PathProfile, PathSignalEvent,
    PublicRouteHint, RttClass,
};

fn context() -> apt_types::LocalNetworkContext {
    apt_types::LocalNetworkContext {
        link_type: LinkType::Wifi,
        gateway: GatewayFingerprint("gw-a".to_string()),
        local_label: "ssid-a".to_string(),
        public_route: PublicRouteHint("route-a".to_string()),
    }
}

fn observation(
    packet_size: u16,
    gap_ms: u32,
    path_profile: PathProfile,
    tunnel_traffic: bool,
) -> NetworkMetadataObservation {
    NetworkMetadataObservation {
        packet_size,
        inter_send_gap_ms: gap_ms,
        burst_length: 4,
        upstream_downstream_ratio_class: 3,
        path_profile,
        longevity: ConnectionLongevityClass::Moderate,
        tunnel_traffic,
    }
}

fn stable_profile() -> PathProfile {
    PathProfile {
        path: PathClass::Stable,
        mtu: MtuClass::Large,
        rtt: RttClass::Low,
        loss: LossClass::Low,
        nat: NatClass::EndpointIndependent,
    }
}

fn hostile_profile() -> PathProfile {
    PathProfile {
        path: PathClass::Hostile,
        mtu: MtuClass::Small,
        rtt: RttClass::Extreme,
        loss: LossClass::High,
        nat: NatClass::Symmetric,
    }
}

#[test]
fn bootstrap_requires_enough_weight_or_successes() {
    let mut profile = LocalNormalityProfile::new(context());
    for _ in 0..50 {
        profile.record_observation(&observation(700, 50, stable_profile(), true));
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
    profile.record_observation(&observation(200, 50, stable_profile(), true));
    profile.record_observation(&observation(1_400, 50, stable_profile(), false));
    let summary = profile.summary().unwrap();
    assert!(summary.median_packet_size >= 1_280);
}

#[test]
fn histogram_updates_are_clipped_per_session() {
    let mut profile = LocalNormalityProfile::new(context());
    for _ in 0..200 {
        profile.record_observation(&observation(1_400, 10, stable_profile(), false));
    }
    let summary = profile.summary().unwrap();
    assert_eq!(summary.weighted_observation_units, 64);

    profile.begin_new_session();
    for _ in 0..8 {
        profile.record_observation(&observation(1_400, 10, stable_profile(), false));
    }
    let summary = profile.summary().unwrap();
    assert_eq!(summary.weighted_observation_units, 96);
    assert!(profile.is_bootstrapped());
}

#[test]
fn carrier_counters_are_bounded_and_failures_promote_more_slowly() {
    let mut profile = LocalNormalityProfile::new(context());
    for _ in 0..8 {
        profile.record_observation(&observation(1_400, 10, stable_profile(), false));
    }

    profile.note_successful_session();
    profile.note_carrier_success(CarrierBinding::D1DatagramUdp);
    profile.begin_new_session();
    profile.note_successful_session();
    profile.note_carrier_success(CarrierBinding::D1DatagramUdp);
    profile.begin_new_session();

    for _ in 0..10 {
        profile.note_carrier_failure(CarrierBinding::D1DatagramUdp);
    }

    let counters = profile.carrier_counters(CarrierBinding::D1DatagramUdp);
    assert_eq!(counters.successes, 2);
    assert_eq!(counters.failures, 2);
    assert_eq!(
        profile.summary().unwrap().preferred_carrier,
        Some(CarrierBinding::D1DatagramUdp)
    );
}

#[test]
fn inferred_path_profile_uses_richer_class_evidence() {
    let mut stable = LocalNormalityProfile::new(context());
    for _ in 0..24 {
        stable.record_observation(&observation(1_400, 10, stable_profile(), false));
    }
    let stable_summary = stable.summary().unwrap();
    let stable_path = inferred_path_profile(&stable_summary);
    assert_eq!(stable_path.path, PathClass::Stable);
    assert_eq!(stable_path.mtu, MtuClass::Large);
    assert_eq!(stable_path.rtt, RttClass::Low);
    assert_eq!(stable_path.loss, LossClass::Low);
    assert_eq!(stable_path.nat, NatClass::EndpointIndependent);

    let mut hostile = LocalNormalityProfile::new(context());
    for _ in 0..24 {
        hostile.record_observation(&observation(200, 300, hostile_profile(), false));
    }
    let hostile_summary = hostile.summary().unwrap();
    let hostile_path = inferred_path_profile(&hostile_summary);
    assert_eq!(hostile_path.path, PathClass::Hostile);
    assert_eq!(hostile_path.loss, LossClass::High);
    assert_eq!(hostile_path.nat, NatClass::Symmetric);
}

#[test]
fn controller_moves_between_modes() {
    let mut controller = PolicyController::new(Mode::SPEED, false, Some(Mode::new(18).unwrap()));
    assert!(controller.current_mode.value() > Mode::SPEED.value());

    controller.set_bootstrapped(true);
    for _ in 0..5 {
        controller.observe_signal(PathSignalEvent::StableDelivery);
    }
    assert_eq!(controller.current_mode, Mode::SPEED);

    controller.observe_signal(PathSignalEvent::FallbackFailure);
    controller.observe_signal(PathSignalEvent::NatRebinding);
    controller.observe_signal(PathSignalEvent::ImmediateReset);
    assert!(controller.current_mode.value() >= 24);
    assert!(controller.should_migrate());

    controller.observe_signal(PathSignalEvent::FallbackSuccess);
    controller.observe_signal(PathSignalEvent::StableDelivery);
    assert!(controller.current_mode.value() <= 20);
}
