use super::*;
use crate::config::{ResolvedClientConfig, RuntimeCarrierPreference, RuntimeMode};
use apt_types::{EndpointId, RekeyLimits};
use std::{net::SocketAddr, path::PathBuf};

fn test_runtime_carriers() -> RuntimeCarriers {
    RuntimeCarriers::new(1_380, false)
}

fn test_runtime_outer_keys() -> RuntimeOuterKeys {
    RuntimeOuterKeys {
        d1: D1OuterKeys {
            send: [0x11; 32],
            recv: [0x22; 32],
        },
        s1: S1OuterKeys {
            send: [0x33; 32],
            recv: [0x44; 32],
        },
    }
}

fn test_tunnel_session() -> TunnelSession {
    TunnelSession::new(
        SessionId([0x55; 16]),
        SessionRole::Initiator,
        apt_crypto::SessionSecretsForRole {
            send_data: [0x01; 32],
            recv_data: [0x02; 32],
            send_ctrl: [0x03; 32],
            recv_ctrl: [0x04; 32],
            rekey: [0x05; 32],
            persona_seed: [0x06; 32],
            resume_secret: [0x07; 32],
        },
        RekeyLimits::default(),
        u64::try_from(MINIMUM_REPLAY_WINDOW).unwrap(),
        0,
    )
}

fn test_client_config() -> ResolvedClientConfig {
    ResolvedClientConfig {
        server_addr: "198.51.100.10:51820".parse::<SocketAddr>().unwrap(),
        runtime_mode: RuntimeMode::Stealth,
        preferred_carrier: RuntimeCarrierPreference::D1,
        strict_preferred_carrier: false,
        endpoint_id: EndpointId::new("adapt-test".to_string()),
        admission_key: [0x11; 32],
        server_static_public_key: [0x22; 32],
        client_static_private_key: [0x33; 32],
        client_identity: None,
        bind: "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
        interface_name: None,
        routes: Vec::new(),
        use_server_pushed_routes: true,
        session_policy: apt_types::SessionPolicy::default(),
        enable_s1_fallback: true,
        stream_server_addr: Some("198.51.100.10:443".parse::<SocketAddr>().unwrap()),
        allow_session_migration: true,
        standby_health_check_secs: 0,
        keepalive_secs: 25,
        session_idle_timeout_secs: 180,
        handshake_timeout_secs: 5,
        handshake_retries: 5,
        udp_recv_buffer_bytes: 1024,
        udp_send_buffer_bytes: 1024,
        state_path: PathBuf::from("/tmp/adapt-test-state.toml"),
    }
}

#[test]
fn ipv4_destination_parsing_works() {
    let packet = [
        0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 17, 0, 0, 10, 77, 0, 2, 8, 8, 8, 8,
    ];
    assert_eq!(
        extract_destination_ipv4(&packet),
        Some(Ipv4Addr::new(8, 8, 8, 8))
    );
}

#[test]
fn candidate_epoch_slots_cover_adjacent_slots() {
    assert_eq!(
        candidate_epoch_slots(DEFAULT_ADMISSION_EPOCH_SLOT_SECS),
        [0, 1, 2]
    );
}

#[test]
fn standby_probe_schedule_is_jittered() {
    let first = jittered_interval_secs(20);
    assert!((16..=24).contains(&first));
}

#[test]
fn effective_d1_tunnel_mtu_stays_within_runtime_bounds() {
    let carriers = RuntimeCarriers::new(1_380, false);
    let effective = effective_runtime_tunnel_mtu(
        1_380,
        &EndpointId::new("adapt-test".to_string()),
        &carriers,
    );
    assert!(effective <= 1_380);
    assert!(effective >= 1_200);
}

#[test]
fn strict_s1_override_uses_only_s1() {
    let mut config = test_client_config();
    config.preferred_carrier = RuntimeCarrierPreference::S1;
    config.strict_preferred_carrier = true;
    let order = client_carrier_attempt_order(&config, &ClientPersistentState::default()).unwrap();
    assert_eq!(order, vec![CarrierBinding::S1EncryptedStream]);
}

#[test]
fn strict_s1_override_without_stream_endpoint_errors() {
    let mut config = test_client_config();
    config.preferred_carrier = RuntimeCarrierPreference::S1;
    config.strict_preferred_carrier = true;
    config.stream_server_addr = None;
    let error =
        client_carrier_attempt_order(&config, &ClientPersistentState::default()).unwrap_err();
    assert!(error
        .to_string()
        .contains("stream_server_addr is not configured"));
}

#[test]
fn oversized_d1_burst_is_split_into_multiple_packets() {
    let carriers = test_runtime_carriers();
    let outer_keys = test_runtime_outer_keys();
    let tunnel = test_tunnel_session();
    let batches = plan_outbound_tunnel_batches(
        &carriers,
        &EndpointId::new("adapt-test".to_string()),
        &outer_keys,
        TunnelEncapsulation::Wrapped,
        CarrierBinding::D1DatagramUdp,
        &tunnel,
        &[Frame::IpData(vec![0_u8; 900]), Frame::IpData(vec![1_u8; 900])],
        0,
    )
    .unwrap();
    assert_eq!(batches.len(), 2);
    assert!(batches.iter().all(|batch| batch.len() == 1));
}

#[test]
fn speed_mode_direct_encapsulation_skips_outer_wrap() {
    let carriers = test_runtime_carriers();
    let outer_keys = test_runtime_outer_keys();
    let mut direct_tunnel = test_tunnel_session();
    let mut baseline_tunnel = direct_tunnel.clone();
    let frames = [Frame::IpData(vec![0x42; 900])];

    let direct = encode_server_tunnel_packet_batch(
        &carriers,
        &EndpointId::new("adapt-test".to_string()),
        &outer_keys,
        TunnelEncapsulation::DirectInnerOnly,
        CarrierBinding::D1DatagramUdp,
        &mut direct_tunnel,
        &frames,
        0,
    )
    .unwrap();
    let baseline = baseline_tunnel.encode_packet(&frames, 0).unwrap().bytes;

    assert_eq!(direct, baseline);
}

#[test]
fn single_oversized_ip_frame_is_dropped_instead_of_failing() {
    let carriers = test_runtime_carriers();
    let outer_keys = test_runtime_outer_keys();
    let tunnel = test_tunnel_session();
    let batches = plan_outbound_tunnel_batches(
        &carriers,
        &EndpointId::new("adapt-test".to_string()),
        &outer_keys,
        TunnelEncapsulation::Wrapped,
        CarrierBinding::D1DatagramUdp,
        &tunnel,
        &[Frame::IpData(vec![0_u8; 3_000])],
        0,
    )
    .unwrap();
    assert!(batches.is_empty());
}
