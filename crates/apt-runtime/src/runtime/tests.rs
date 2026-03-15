use super::*;
use crate::config::{
    ResolvedAuthorizedPeer, ResolvedClientConfig, ResolvedClientD2Config, ResolvedRemoteEndpoint,
    ResolvedServerConfig, RuntimeCarrierPreference,
};
use apt_admission::{initiate_c0, ClientCredential, ClientSessionRequest};
use apt_carriers::D1Carrier;
use apt_types::{AuthProfile, EndpointId, Mode, RekeyLimits};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
};

fn test_runtime_carriers() -> RuntimeCarriers {
    RuntimeCarriers::new(1_380, false, false)
}

fn test_runtime_outer_keys() -> RuntimeOuterKeys {
    RuntimeOuterKeys::new(
        &EndpointId::new("adapt-test".to_string()),
        D1OuterKeys {
            send: [0x11; 32],
            recv: [0x22; 32],
        },
        D2OuterKeys {
            send: [0x55; 32],
            recv: [0x66; 32],
        },
        S1OuterKeys {
            send: [0x33; 32],
            recv: [0x44; 32],
        },
    )
    .unwrap()
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
        mode: Mode::STEALTH,
        preferred_carrier: RuntimeCarrierPreference::D1,
        strict_preferred_carrier: false,
        auth_profile: apt_types::AuthProfile::SharedDeployment,
        endpoint_id: EndpointId::new("adapt-test".to_string()),
        admission_key: [0x11; 32],
        server_static_public_key: [0x22; 32],
        client_static_private_key: [0x33; 32],
        client_identity: None,
        bind: "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
        interface_name: None,
        routes: Vec::new(),
        use_server_pushed_routes: true,
        enable_d2_fallback: false,
        d2: None,
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

fn test_server_config() -> ResolvedServerConfig {
    ResolvedServerConfig {
        bind: "0.0.0.0:51820".parse::<SocketAddr>().unwrap(),
        public_endpoint: "198.51.100.10:51820".to_string(),
        mode: Mode::STEALTH,
        d2: None,
        stream_bind: Some("0.0.0.0:443".parse::<SocketAddr>().unwrap()),
        stream_public_endpoint: Some("198.51.100.10:443".to_string()),
        stream_decoy_surface: false,
        endpoint_id: EndpointId::new("adapt-test".to_string()),
        admission_key: [0x11; 32],
        server_static_private_key: [0x44; 32],
        server_static_public_key: apt_crypto::generate_static_keypair().unwrap().public,
        cookie_key: [0x55; 32],
        ticket_key: [0x66; 32],
        interface_name: Some("aptsrv0".to_string()),
        tunnel_local_ipv4: Ipv4Addr::new(10, 77, 0, 1),
        tunnel_netmask: Ipv4Addr::new(255, 255, 255, 0),
        tunnel_local_ipv6: Some("fd77:77::1".parse().unwrap()),
        tunnel_ipv6_prefix_len: Some(64),
        tunnel_mtu: 1380,
        egress_interface: Some("eth0".to_string()),
        enable_ipv4_forwarding: true,
        nat_ipv4: true,
        enable_ipv6_forwarding: true,
        nat_ipv6: true,
        push_routes: Vec::new(),
        push_dns: Vec::new(),
        session_policy: apt_types::SessionPolicy::default(),
        allow_session_migration: true,
        keepalive_secs: 25,
        session_idle_timeout_secs: 180,
        udp_recv_buffer_bytes: 1024,
        udp_send_buffer_bytes: 1024,
        peers: vec![ResolvedAuthorizedPeer {
            name: "laptop".to_string(),
            auth_profile: AuthProfile::PerUser,
            user_id: "laptop".to_string(),
            admission_key: Some([0x77; 32]),
            client_static_public_key: [0x88; 32],
            tunnel_ipv4: Ipv4Addr::new(10, 77, 0, 2),
            tunnel_ipv6: Some("fd77:77::2".parse().unwrap()),
        }],
    }
}

#[test]
fn ipv4_destination_parsing_works() {
    let packet = [
        0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 17, 0, 0, 10, 77, 0, 2, 8, 8, 8, 8,
    ];
    assert_eq!(
        extract_destination_ip(&packet),
        Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
    );
}

#[test]
fn ipv6_destination_parsing_works() {
    let packet = [
        0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x40, 0xfd, 0x77, 0x00, 0x77, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];
    assert_eq!(
        extract_destination_ip(&packet),
        Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)))
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
    let carriers = RuntimeCarriers::new(1_380, false, false);
    let effective =
        effective_runtime_tunnel_mtu(1_380, &EndpointId::new("adapt-test".to_string()), &carriers);
    assert!(effective <= 1_380);
    assert!(effective >= 1_200);
}

#[test]
fn strict_d2_override_uses_only_d2() {
    let mut config = test_client_config();
    config.preferred_carrier = RuntimeCarrierPreference::D2;
    config.strict_preferred_carrier = true;
    config.d2 = Some(ResolvedClientD2Config {
        endpoint: ResolvedRemoteEndpoint {
            original: "198.51.100.10:443".to_string(),
            addr: "198.51.100.10:443".parse().unwrap(),
            server_name: "198.51.100.10".to_string(),
        },
        server_certificate_der: vec![0xAA; 32],
    });
    let order = client_carrier_attempt_order(&config, &ClientPersistentState::default()).unwrap();
    assert_eq!(order, vec![CarrierBinding::D2EncryptedDatagram]);
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
fn per_user_client_credentials_enable_lookup_hints() {
    let mut config = test_client_config();
    config.auth_profile = AuthProfile::PerUser;
    config.client_identity = Some("laptop".to_string());
    let credential = client_credential(&config);
    assert!(matches!(credential.auth_profile, AuthProfile::PerUser));
    assert_eq!(credential.user_id.as_deref(), Some("laptop"));
    assert!(credential.enable_lookup_hint);
}

#[test]
fn server_outer_admission_decode_accepts_per_user_keys() {
    let config = test_server_config();
    let carrier = D1Carrier::conservative();
    let server_static_public = apt_crypto::generate_static_keypair().unwrap().public;
    let now_secs = DEFAULT_ADMISSION_EPOCH_SLOT_SECS;
    let prepared = initiate_c0(
        ClientCredential {
            auth_profile: AuthProfile::PerUser,
            user_id: Some("laptop".to_string()),
            client_static_private: None,
            admission_key: [0x77; 32],
            server_static_public,
            enable_lookup_hint: true,
        },
        ClientSessionRequest::conservative(config.endpoint_id.clone(), now_secs),
        &carrier,
    )
    .unwrap();
    let outer_key =
        derive_d1_admission_outer_key(&[0x77; 32], now_secs / DEFAULT_ADMISSION_EPOCH_SLOT_SECS)
            .unwrap();
    let datagram =
        encode_admission_datagram(&carrier, &config.endpoint_id, &outer_key, &prepared.packet)
            .unwrap();

    let decoded = decode_server_admission_packet(&config, &carrier, &datagram, now_secs)
        .expect("per-user admission packet should decrypt with a configured user key");
    assert_eq!(decoded.outer_key, outer_key);
    assert_eq!(decoded.packet.lookup_hint, prepared.packet.lookup_hint);
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
        &[
            Frame::IpData(vec![0_u8; 900]),
            Frame::IpData(vec![1_u8; 900]),
        ],
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
fn direct_inner_only_owned_decode_reuses_the_input_buffer() {
    let carriers = test_runtime_carriers();
    let outer_keys = test_runtime_outer_keys();
    let bytes = vec![0x10, 0x20, 0x30, 0x40];
    let input_ptr = bytes.as_ptr();

    let decoded = decode_client_tunnel_packet_owned(
        &carriers,
        &EndpointId::new("adapt-test".to_string()),
        &outer_keys,
        TunnelEncapsulation::DirectInnerOnly,
        CarrierBinding::D1DatagramUdp,
        bytes,
    )
    .unwrap();

    assert_eq!(decoded, vec![0x10, 0x20, 0x30, 0x40]);
    assert_eq!(decoded.as_ptr(), input_ptr);
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
