use super::*;
use apt_carriers::{CarrierProfile, D1Carrier, InvalidInputBehavior};

#[derive(Clone, Copy, Debug)]
struct TestS1Carrier;

impl CarrierProfile for TestS1Carrier {
    fn binding(&self) -> CarrierBinding {
        CarrierBinding::S1EncryptedStream
    }

    fn max_record_size(&self) -> u16 {
        16_384
    }

    fn tunnel_mtu(&self) -> u16 {
        1_380
    }

    fn invalid_input_behavior(&self) -> InvalidInputBehavior {
        InvalidInputBehavior::Silence
    }
}

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
        authority: "api.example.com".to_string(),
        graph_branch_id: Some("bootstrap-sync".to_string()),
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
    let prepared_ug1 = initiate_ug1(credential, request, &carrier).unwrap();

    let ug2_envelope = match server.handle_ug1(
        "127.0.0.1:1111",
        &carrier,
        prepared_ug1.lookup_hint,
        &prepared_ug1.envelope,
        512,
        now_secs,
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => panic!("expected reply"),
    };

    let prepared_ug3 = prepared_ug1
        .state
        .handle_ug2(&ug2_envelope, &carrier)
        .unwrap();
    let established = match server.handle_ug3(
        "127.0.0.1:1111",
        &carrier,
        prepared_ug3.lookup_hint,
        &prepared_ug3.envelope,
        now_secs + 1,
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => panic!("expected reply"),
    };

    let client_session = prepared_ug3
        .state
        .handle_ug4(&established.envelope, &carrier)
        .unwrap();
    assert_eq!(client_session.session_id, established.session.session_id);
    assert_eq!(client_session.chosen_carrier, CarrierBinding::D1DatagramUdp);
}

#[test]
fn replayed_ug1_is_silently_dropped() {
    let (mut server, credential, carrier) = test_server_setup();
    let endpoint = EndpointId::new("edge-test");
    let now_secs = 1_700_000_000;
    let request = ClientSessionRequest::conservative(endpoint, now_secs);
    let prepared_ug1 = initiate_ug1(credential, request, &carrier).unwrap();

    let _ = server.handle_ug1(
        "127.0.0.1:1111",
        &carrier,
        prepared_ug1.lookup_hint,
        &prepared_ug1.envelope,
        512,
        now_secs,
    );
    let replay = server.handle_ug1(
        "127.0.0.1:1111",
        &carrier,
        prepared_ug1.lookup_hint,
        &prepared_ug1.envelope,
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
    let prepared_ug1 = initiate_ug1(credential, request, &carrier).unwrap();

    let ug2_envelope = match server.handle_ug1(
        "127.0.0.1:1111",
        &carrier,
        prepared_ug1.lookup_hint,
        &prepared_ug1.envelope,
        512,
        now_secs,
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => panic!("expected reply"),
    };
    let prepared_ug3 = prepared_ug1
        .state
        .handle_ug2(&ug2_envelope, &carrier)
        .unwrap();
    let response = server.handle_ug3(
        "127.0.0.1:1111",
        &carrier,
        prepared_ug3.lookup_hint,
        &prepared_ug3.envelope,
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
    let prepared_ug1 = initiate_ug1(credential, request, &carrier).unwrap();
    assert!(prepared_ug1.lookup_hint.is_some());

    let ug2_envelope = match server.handle_ug1(
        "127.0.0.1:1111",
        &carrier,
        prepared_ug1.lookup_hint,
        &prepared_ug1.envelope,
        512,
        now_secs,
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => panic!("expected reply"),
    };

    let prepared_ug3 = prepared_ug1
        .state
        .handle_ug2(&ug2_envelope, &carrier)
        .unwrap();
    let established = match server.handle_ug3(
        "127.0.0.1:1111",
        &carrier,
        prepared_ug3.lookup_hint,
        &prepared_ug3.envelope,
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
    let prepared_ug1 = initiate_ug1(credential, request, &carrier).unwrap();

    let response = server.handle_ug1(
        "127.0.0.1:1111",
        &carrier,
        prepared_ug1.lookup_hint,
        &prepared_ug1.envelope,
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
    let prepared_ug1 = initiate_ug1(credential, request, &carrier).unwrap();
    let response = server.handle_ug1(
        "127.0.0.1:1111",
        &carrier,
        prepared_ug1.lookup_hint,
        &prepared_ug1.envelope,
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
    let mut prepared_ug1 = initiate_ug1(credential, request, &carrier).unwrap();
    prepared_ug1.envelope.ciphertext[0] ^= 0x44;
    let response = server.handle_ug1(
        "127.0.0.1:1111",
        &carrier,
        prepared_ug1.lookup_hint,
        &prepared_ug1.envelope,
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
    let prepared_ug1 = initiate_ug1(credential, request, &carrier).unwrap();

    let ug2_envelope = match server.handle_ug1(
        "127.0.0.1:1111",
        &carrier,
        prepared_ug1.lookup_hint,
        &prepared_ug1.envelope,
        512,
        now_secs,
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => panic!("expected reply"),
    };

    let prepared_ug3 = prepared_ug1
        .state
        .handle_ug2(&ug2_envelope, &carrier)
        .unwrap();
    let established = match server.handle_ug3(
        "127.0.0.1:1111",
        &carrier,
        prepared_ug3.lookup_hint,
        &prepared_ug3.envelope,
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
        public_route_hint: PublicRouteHint("d2:edge.example:443".to_string()),
        path_profile: PathProfile::unknown(),
        client_nonce: ClientNonce::random(),
        noise_msg1: vec![1, 2, 3],
        optional_masked_fallback_ticket: None,
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
        optional_masked_fallback_accept: true,
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
        optional_masked_fallback_ticket: Some(SealedEnvelope {
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

#[test]
fn masked_fallback_ticket_is_issued_and_only_reused_on_matching_route() {
    let (mut server, credential, carrier) = test_server_setup();
    let endpoint = EndpointId::new("edge-test");
    let now_secs = 1_700_000_000;

    let mut first_request = ClientSessionRequest::conservative(endpoint.clone(), now_secs);
    first_request.public_route_hint = PublicRouteHint("d1:198.51.100.10:51820".to_string());
    let prepared_ug1 = initiate_ug1(credential.clone(), first_request, &carrier).unwrap();
    let ug2_envelope = match server.handle_ug1(
        "127.0.0.1:1111",
        &carrier,
        prepared_ug1.lookup_hint,
        &prepared_ug1.envelope,
        512,
        now_secs,
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => panic!("expected reply"),
    };
    let prepared_ug3 = prepared_ug1
        .state
        .handle_ug2(&ug2_envelope, &carrier)
        .unwrap();
    let established = match server.handle_ug3(
        "127.0.0.1:1111",
        &carrier,
        prepared_ug3.lookup_hint,
        &prepared_ug3.envelope,
        now_secs + 1,
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => panic!("expected reply"),
    };
    let masked_fallback_ticket = established
        .session
        .masked_fallback_ticket
        .clone()
        .expect("ticket should be issued");

    let mut matching_request = ClientSessionRequest::conservative(endpoint.clone(), now_secs + 10);
    matching_request.public_route_hint = PublicRouteHint("d1:198.51.100.10:51820".to_string());
    matching_request.masked_fallback_ticket = Some(masked_fallback_ticket.clone());
    let prepared_matching = initiate_ug1(credential.clone(), matching_request, &carrier).unwrap();
    let matching_ug2_envelope = match server.handle_ug1(
        "127.0.0.1:1111",
        &carrier,
        prepared_matching.lookup_hint,
        &prepared_matching.envelope,
        512,
        now_secs + 10,
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => panic!("expected reply"),
    };
    let aad = admission_associated_data(&endpoint, carrier.binding());
    let epoch_slot = (now_secs + 10) / AdmissionDefaults::default().epoch_slot_secs;
    let matching_key = derive_admission_key(&credential.admission_key, epoch_slot);
    let matching_ug2: Ug2 = matching_ug2_envelope.open(&matching_key, &aad).unwrap();
    assert!(matching_ug2.optional_masked_fallback_accept);

    let mut mismatched_request =
        ClientSessionRequest::conservative(endpoint.clone(), now_secs + 20);
    mismatched_request.public_route_hint = PublicRouteHint("d1:203.0.113.44:51820".to_string());
    mismatched_request.masked_fallback_ticket = Some(masked_fallback_ticket);
    let prepared_mismatched =
        initiate_ug1(credential.clone(), mismatched_request, &carrier).unwrap();
    let mismatched_ug2_envelope = match server.handle_ug1(
        "127.0.0.1:1111",
        &carrier,
        prepared_mismatched.lookup_hint,
        &prepared_mismatched.envelope,
        512,
        now_secs + 20,
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => panic!("expected reply"),
    };
    let epoch_slot = (now_secs + 20) / AdmissionDefaults::default().epoch_slot_secs;
    let mismatched_key = derive_admission_key(&credential.admission_key, epoch_slot);
    let mismatched_ug2: Ug2 = mismatched_ug2_envelope.open(&mismatched_key, &aad).unwrap();
    assert!(!mismatched_ug2.optional_masked_fallback_accept);
}

#[test]
fn public_session_context_binds_hidden_upgrade_to_surface_metadata() {
    let (mut server, credential, _) = test_server_setup();
    let carrier = TestS1Carrier;
    server.config.allowed_carriers = vec![CarrierBinding::S1EncryptedStream];
    let endpoint = EndpointId::new("edge-test");
    let now_secs = 1_700_000_000;
    let public_context = PublicSessionUpgradeContext::new(
        CarrierBinding::S1EncryptedStream,
        "api-sync".to_string(),
        "2026.03".to_string(),
        "api.example.com".to_string(),
        None,
        "request-json-metadata".to_string(),
        "/v1/devices/{device_id}/sync".to_string(),
        "response-json-fragment".to_string(),
        "/v1/devices/{device_id}/state".to_string(),
    );
    let mut request = ClientSessionRequest::conservative(endpoint, now_secs);
    request.preferred_carrier = CarrierBinding::S1EncryptedStream;
    request.supported_carriers = vec![CarrierBinding::S1EncryptedStream];
    let prepared =
        initiate_ug1_with_context(credential, request, &carrier, public_context.clone()).unwrap();

    let reply = server.handle_ug1_with_context(
        "h2-client-a",
        &carrier,
        &public_context,
        prepared.lookup_hint,
        &prepared.envelope,
        512,
        now_secs,
    );
    assert!(matches!(reply, ServerResponse::Reply(_)));

    let mismatched_context = PublicSessionUpgradeContext::new(
        CarrierBinding::S1EncryptedStream,
        "api-sync".to_string(),
        "2026.03".to_string(),
        "other.example.com".to_string(),
        None,
        "request-json-metadata".to_string(),
        "/v1/devices/{device_id}/sync".to_string(),
        "response-json-fragment".to_string(),
        "/v1/devices/{device_id}/state".to_string(),
    );
    let dropped = server.handle_ug1_with_context(
        "h2-client-a",
        &carrier,
        &mismatched_context,
        prepared.lookup_hint,
        &prepared.envelope,
        512,
        now_secs,
    );
    assert!(matches!(
        dropped,
        ServerResponse::Drop(InvalidInputBehavior::Silence)
    ));
}
