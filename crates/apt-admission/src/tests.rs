use super::*;
use apt_carriers::D1Carrier;

fn test_server_setup() -> (AdmissionServer, ClientCredential, D1Carrier) {
    let static_keypair = generate_static_keypair().unwrap();
    let admission_key = [7_u8; 32];
    let endpoint = EndpointId::new("edge-test");
    let mut store = CredentialStore::new();
    store.set_shared_deployment_key(admission_key);
    let server = AdmissionServer::new(
        AdmissionConfig::conservative(endpoint.clone()),
        store,
        AdmissionServerSecrets {
            static_keypair: static_keypair.clone(),
            cookie_key: [9_u8; 32],
            ticket_key: [10_u8; 32],
        },
    );
    let client_credential = ClientCredential {
        auth_profile: AuthProfile::SharedDeployment,
        user_id: None,
        client_static_private: None,
        admission_key,
        server_static_public: static_keypair.public,
        enable_lookup_hint: false,
    };
    (server, client_credential, D1Carrier::conservative())
}

fn test_per_user_server_setup() -> (AdmissionServer, ClientCredential, D1Carrier) {
    let static_keypair = generate_static_keypair().unwrap();
    let admission_key = [8_u8; 32];
    let endpoint = EndpointId::new("edge-test");
    let mut store = CredentialStore::new();
    store.add_user(PerUserCredential {
        user_id: "alice".to_string(),
        admission_key,
    });
    let server = AdmissionServer::new(
        AdmissionConfig::conservative(endpoint.clone()),
        store,
        AdmissionServerSecrets {
            static_keypair: static_keypair.clone(),
            cookie_key: [9_u8; 32],
            ticket_key: [10_u8; 32],
        },
    );
    let client_credential = ClientCredential {
        auth_profile: AuthProfile::PerUser,
        user_id: Some("alice".to_string()),
        client_static_private: None,
        admission_key,
        server_static_public: static_keypair.public,
        enable_lookup_hint: true,
    };
    (server, client_credential, D1Carrier::conservative())
}

fn test_slot_binding() -> UpgradeSlotBinding {
    UpgradeSlotBinding {
        family_id: "api-sync".to_string(),
        profile_version: "2026.03".to_string(),
        slot_id: "request-json-metadata".to_string(),
        phase: UpgradeMessagePhase::Request,
        epoch_slot: 77,
        path_hint: "/v1/devices/{device_id}/sync".to_string(),
    }
}

#[test]
fn successful_one_point_five_rtt_establishment() {
    let (mut server, credential, carrier) = test_server_setup();
    let endpoint = EndpointId::new("edge-test");
    let now_secs = 1_700_000_000;
    let request = ClientSessionRequest::conservative(endpoint, now_secs);
    let prepared_c0 = initiate_c0(credential, request, &carrier).unwrap();

    let s1 = match server.handle_c0(
        "127.0.0.1:1111",
        &carrier,
        &prepared_c0.packet,
        512,
        now_secs,
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => panic!("expected reply"),
    };

    let prepared_c2 = prepared_c0.state.handle_s1(&s1, &carrier).unwrap();
    let established = match server.handle_c2(
        "127.0.0.1:1111",
        &carrier,
        &prepared_c2.packet,
        now_secs + 1,
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => panic!("expected reply"),
    };

    let client_session = prepared_c2
        .state
        .handle_s3(&established.packet, &carrier)
        .unwrap();
    assert_eq!(client_session.session_id, established.session.session_id);
    assert_eq!(client_session.chosen_carrier, CarrierBinding::D1DatagramUdp);
}

#[test]
fn replayed_c0_is_silently_dropped() {
    let (mut server, credential, carrier) = test_server_setup();
    let endpoint = EndpointId::new("edge-test");
    let now_secs = 1_700_000_000;
    let request = ClientSessionRequest::conservative(endpoint, now_secs);
    let prepared_c0 = initiate_c0(credential, request, &carrier).unwrap();

    let _ = server.handle_c0(
        "127.0.0.1:1111",
        &carrier,
        &prepared_c0.packet,
        512,
        now_secs,
    );
    let replay = server.handle_c0(
        "127.0.0.1:1111",
        &carrier,
        &prepared_c0.packet,
        512,
        now_secs,
    );
    assert!(matches!(
        replay,
        ServerResponse::Drop(InvalidInputBehavior::Silence)
    ));
}

#[test]
fn expired_cookie_causes_drop() {
    let (mut server, credential, carrier) = test_server_setup();
    let endpoint = EndpointId::new("edge-test");
    let now_secs = 1_700_000_000;
    let request = ClientSessionRequest::conservative(endpoint, now_secs);
    let prepared_c0 = initiate_c0(credential, request, &carrier).unwrap();

    let s1 = match server.handle_c0(
        "127.0.0.1:1111",
        &carrier,
        &prepared_c0.packet,
        512,
        now_secs,
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => panic!("expected reply"),
    };
    let prepared_c2 = prepared_c0.state.handle_s1(&s1, &carrier).unwrap();
    let response = server.handle_c2(
        "127.0.0.1:1111",
        &carrier,
        &prepared_c2.packet,
        now_secs + 60,
    );
    assert!(matches!(
        response,
        ServerResponse::Drop(InvalidInputBehavior::Silence)
    ));
}

#[test]
fn per_user_establishment_uses_lookup_hints() {
    let (mut server, credential, carrier) = test_per_user_server_setup();
    let endpoint = EndpointId::new("edge-test");
    let now_secs = 1_700_000_000;
    let request = ClientSessionRequest::conservative(endpoint, now_secs);
    let prepared_c0 = initiate_c0(credential, request, &carrier).unwrap();
    assert!(prepared_c0.packet.lookup_hint.is_some());

    let s1 = match server.handle_c0(
        "127.0.0.1:1111",
        &carrier,
        &prepared_c0.packet,
        512,
        now_secs,
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => panic!("expected reply"),
    };

    let prepared_c2 = prepared_c0.state.handle_s1(&s1, &carrier).unwrap();
    let established = match server.handle_c2(
        "127.0.0.1:1111",
        &carrier,
        &prepared_c2.packet,
        now_secs + 1,
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => panic!("expected reply"),
    };

    assert!(matches!(
        established.session.credential_identity,
        CredentialIdentity::User(ref user) if user == "alice"
    ));
}

#[test]
fn auth_profile_mismatch_is_dropped() {
    let (mut server, mut credential, carrier) = test_per_user_server_setup();
    credential.auth_profile = AuthProfile::SharedDeployment;
    let endpoint = EndpointId::new("edge-test");
    let now_secs = 1_700_000_000;
    let request = ClientSessionRequest::conservative(endpoint, now_secs);
    let prepared_c0 = initiate_c0(credential, request, &carrier).unwrap();

    let response = server.handle_c0(
        "127.0.0.1:1111",
        &carrier,
        &prepared_c0.packet,
        512,
        now_secs,
    );
    assert!(matches!(
        response,
        ServerResponse::Drop(InvalidInputBehavior::Silence)
    ));
}

#[test]
fn invalid_epoch_slot_causes_drop() {
    let (mut server, credential, carrier) = test_server_setup();
    let endpoint = EndpointId::new("edge-test");
    let now_secs = 1_700_000_000;
    let request = ClientSessionRequest::conservative(endpoint, now_secs - 10_000);
    let prepared_c0 = initiate_c0(credential, request, &carrier).unwrap();
    let response = server.handle_c0(
        "127.0.0.1:1111",
        &carrier,
        &prepared_c0.packet,
        512,
        now_secs,
    );
    assert!(matches!(
        response,
        ServerResponse::Drop(InvalidInputBehavior::Silence)
    ));
}

#[test]
fn malformed_near_miss_does_not_yield_protocol_reply() {
    let (mut server, credential, carrier) = test_server_setup();
    let endpoint = EndpointId::new("edge-test");
    let now_secs = 1_700_000_000;
    let request = ClientSessionRequest::conservative(endpoint, now_secs);
    let mut prepared_c0 = initiate_c0(credential, request, &carrier).unwrap();
    prepared_c0.packet.envelope.ciphertext[0] ^= 0x44;
    let response = server.handle_c0(
        "127.0.0.1:1111",
        &carrier,
        &prepared_c0.packet,
        512,
        now_secs,
    );
    assert!(matches!(
        response,
        ServerResponse::Drop(InvalidInputBehavior::Silence)
    ));
}

#[test]
fn numeric_mode_negotiation_uses_the_more_conservative_value() {
    let (mut server, credential, carrier) = test_server_setup();
    server.config.default_mode = Mode::new(15).unwrap();

    let endpoint = EndpointId::new("edge-test");
    let now_secs = 1_700_000_000;
    let mut request = ClientSessionRequest::conservative(endpoint, now_secs);
    request.mode = Mode::new(8).unwrap();
    let prepared_c0 = initiate_c0(credential, request, &carrier).unwrap();

    let s1 = match server.handle_c0(
        "127.0.0.1:1111",
        &carrier,
        &prepared_c0.packet,
        512,
        now_secs,
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => panic!("expected reply"),
    };

    let prepared_c2 = prepared_c0.state.handle_s1(&s1, &carrier).unwrap();
    let established = match server.handle_c2(
        "127.0.0.1:1111",
        &carrier,
        &prepared_c2.packet,
        now_secs + 1,
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => panic!("expected reply"),
    };

    assert_eq!(established.session.mode, Mode::new(15).unwrap());
}

#[test]
fn mode_negotiation_uses_the_more_conservative_side() {
    let (mut server, _, _) = test_server_setup();

    server.config.default_mode = Mode::new(20).unwrap();
    assert_eq!(
        server.choose_mode(Mode::new(10).unwrap()),
        Mode::new(20).unwrap()
    );
    assert_eq!(
        server.choose_mode(Mode::new(65).unwrap()),
        Mode::new(65).unwrap()
    );

    server.config.default_mode = Mode::new(55).unwrap();
    assert_eq!(
        server.choose_mode(Mode::new(5).unwrap()),
        Mode::new(55).unwrap()
    );
    assert_eq!(
        server.choose_mode(Mode::new(80).unwrap()),
        Mode::new(80).unwrap()
    );

    server.config.default_mode = Mode::STEALTH;
    assert_eq!(server.choose_mode(Mode::SPEED), Mode::STEALTH);
}

#[test]
fn transport_agnostic_ug_capsules_round_trip_without_public_packet_envelope() {
    let ug1 = Ug1 {
        endpoint_id: EndpointId::new("adapt-test".to_string()),
        auth_profile: AuthProfile::PerUser,
        credential_identity: CredentialIdentity::User("laptop".to_string()),
        supported_suites: vec![CipherSuite::NoiseXxPsk2X25519ChaChaPolyBlake2s],
        supported_families: vec![
            CarrierBinding::S1EncryptedStream,
            CarrierBinding::D2EncryptedDatagram,
        ],
        requested_mode: Mode::STEALTH,
        path_profile: PathProfile::unknown(),
        client_nonce: ClientNonce::random(),
        noise_msg1: vec![1, 2, 3],
        optional_resume_ticket: None,
        slot_binding: test_slot_binding(),
        padding: vec![9; 12],
    };
    let ug2 = Ug2 {
        chosen_suite: CipherSuite::NoiseXxPsk2X25519ChaChaPolyBlake2s,
        chosen_family: CarrierBinding::S1EncryptedStream,
        chosen_mode: Mode::BALANCED,
        anti_amplification_cookie: SealedEnvelope {
            nonce: [0x11; 24],
            ciphertext: vec![0x22; 32],
        },
        cookie_expiry: 123,
        noise_msg2: vec![4, 5, 6],
        optional_resume_accept: true,
        slot_binding: test_slot_binding(),
        padding: vec![7; 8],
    };
    let ug3 = Ug3 {
        selected_family_ack: CarrierBinding::S1EncryptedStream,
        anti_amplification_cookie: SealedEnvelope {
            nonce: [0x33; 24],
            ciphertext: vec![0x44; 16],
        },
        noise_msg3: vec![7, 8, 9],
        slot_binding: test_slot_binding(),
        padding: vec![1; 4],
    };
    let ug4 = Ug4 {
        session_id: SessionId([0x55; 16]),
        tunnel_mtu: 1380,
        rekey_limits: RekeyLimits::default(),
        ticket_issue_flag: true,
        optional_resume_ticket: Some(SealedEnvelope {
            nonce: [0x66; 24],
            ciphertext: vec![0x77; 24],
        }),
        slot_binding: test_slot_binding(),
        optional_extensions: vec![vec![0x88; 3]],
    };

    let decoded_ug1: Ug1 = bincode::deserialize(&bincode::serialize(&ug1).unwrap()).unwrap();
    let decoded_ug2: Ug2 = bincode::deserialize(&bincode::serialize(&ug2).unwrap()).unwrap();
    let decoded_ug3: Ug3 = bincode::deserialize(&bincode::serialize(&ug3).unwrap()).unwrap();
    let decoded_ug4: Ug4 = bincode::deserialize(&bincode::serialize(&ug4).unwrap()).unwrap();

    assert_eq!(decoded_ug1, ug1);
    assert_eq!(decoded_ug2, ug2);
    assert_eq!(decoded_ug3, ug3);
    assert_eq!(decoded_ug4, ug4);
}
