use super::*;
use apt_admission::{
    initiate_ug1, AdmissionConfig, AdmissionServer, AdmissionServerSecrets, ClientCredential,
    ClientSessionRequest, CredentialStore, EstablishedEnvelopeReply, ServerResponse, Ug1, Ug2,
    UpgradeMessagePhase, UpgradeSlotBinding,
};
use apt_crypto::generate_static_keypair;
use apt_types::{
    AuthProfile, CarrierBinding, CipherSuite, ClientNonce, CredentialIdentity, EndpointId, Mode,
    PathProfile, PublicRouteHint,
};
use serde_json::json;

fn test_slot_binding(phase: UpgradeMessagePhase, slot_id: &str) -> UpgradeSlotBinding {
    UpgradeSlotBinding {
        family_id: "api-sync".to_string(),
        profile_version: "2026.03".to_string(),
        slot_id: slot_id.to_string(),
        phase,
        epoch_slot: 7,
        path_hint: "/v1/devices/{device_id}/sync".to_string(),
    }
}

fn request_len(request: &ApiSyncRequest) -> usize {
    request.path.len() + serde_json::to_vec(&request.body).unwrap().len()
}

fn test_server_setup() -> (AdmissionServer, ClientCredential, ApiSyncH2Carrier) {
    let static_keypair = generate_static_keypair().unwrap();
    let admission_key = [7_u8; 32];
    let endpoint = EndpointId::new("edge-test");
    let mut store = CredentialStore::new();
    store.set_shared_deployment_key(admission_key);
    let mut config = AdmissionConfig::conservative(endpoint.clone());
    config.allowed_carriers = vec![CarrierBinding::S1EncryptedStream];
    let server = AdmissionServer::new(
        config,
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
    (server, client_credential, ApiSyncH2Carrier::conservative())
}

#[test]
fn public_api_sync_messages_are_valid_without_hidden_capsules() {
    let surface = ApiSyncSurface::starter();
    let request = surface.build_state_push_request("device-1", json!({"battery": 91}));
    let response = surface.build_state_pull_response("device-1", json!({"battery": 91}));

    assert_eq!(request.path, "/v1/devices/device-1/sync");
    assert!(request.authenticated_public);
    assert_eq!(request.body["changes"]["battery"], 91);
    assert!(request.body["metadata"]["sync_hint"].is_null());

    assert_eq!(response.status, 200);
    assert_eq!(response.body["state"]["battery"], 91);
    assert!(response.body["server_hints"]["next_cursor"].is_null());
}

#[test]
fn ug_capsules_round_trip_through_legal_json_slots() {
    let surface = ApiSyncSurface::starter();
    let ug1 = Ug1 {
        endpoint_id: EndpointId::new("edge-h2"),
        auth_profile: AuthProfile::SharedDeployment,
        credential_identity: CredentialIdentity::SharedDeployment,
        supported_suites: vec![CipherSuite::NoiseXxPsk2X25519ChaChaPolyBlake2s],
        supported_families: vec![CarrierBinding::S1EncryptedStream],
        requested_mode: Mode::STEALTH,
        public_route_hint: PublicRouteHint("api.example.com:443".to_string()),
        path_profile: PathProfile::unknown(),
        client_nonce: ClientNonce::random(),
        noise_msg1: vec![1, 2, 3, 4],
        optional_masked_fallback_ticket: None,
        slot_binding: test_slot_binding(UpgradeMessagePhase::Request, API_SYNC_REQUEST_SLOT),
        padding: vec![9; 8],
    };
    let ug2 = Ug2 {
        chosen_suite: CipherSuite::NoiseXxPsk2X25519ChaChaPolyBlake2s,
        chosen_family: CarrierBinding::S1EncryptedStream,
        chosen_mode: Mode::STEALTH,
        anti_amplification_cookie: apt_crypto::SealedEnvelope {
            nonce: [0x11; 24],
            ciphertext: vec![0x22; 24],
        },
        cookie_expiry: 123,
        noise_msg2: vec![5, 6, 7],
        optional_masked_fallback_accept: false,
        slot_binding: test_slot_binding(UpgradeMessagePhase::Response, API_SYNC_RESPONSE_SLOT),
        padding: vec![8; 4],
    };

    let mut request = surface.build_state_push_request("device-1", json!({"battery": 91}));
    let mut response = surface.build_state_pull_response("device-1", json!({"battery": 91}));
    surface.embed_request_capsule(&mut request, &ug1).unwrap();
    surface.embed_response_capsule(&mut response, &ug2).unwrap();

    let decoded_ug1: Ug1 = surface.extract_request_capsule(&request).unwrap().unwrap();
    let decoded_ug2: Ug2 = surface
        .extract_response_capsule(&response)
        .unwrap()
        .unwrap();

    assert_eq!(decoded_ug1, ug1);
    assert_eq!(decoded_ug2, ug2);
}

#[test]
fn end_to_end_hidden_upgrade_round_trips_inside_api_sync_messages() {
    let surface = ApiSyncSurface::starter();
    let (mut server, credential, carrier) = test_server_setup();
    let endpoint = EndpointId::new("edge-test");
    let now_secs = 1_700_000_000;

    let mut request_meta = ClientSessionRequest::conservative(endpoint.clone(), now_secs);
    request_meta.preferred_carrier = CarrierBinding::S1EncryptedStream;
    request_meta.supported_carriers = vec![CarrierBinding::S1EncryptedStream];
    request_meta.public_route_hint = PublicRouteHint("api.example.com:443".to_string());
    let prepared_ug1 = initiate_ug1(credential, request_meta, &carrier).unwrap();

    let mut request = surface.build_state_push_request("device-1", json!({"battery": 91}));
    surface
        .embed_request_upgrade_envelope(
            &mut request,
            &ApiSyncRequestUpgradeEnvelope {
                lookup_hint: prepared_ug1.lookup_hint,
                envelope: prepared_ug1.envelope.clone(),
            },
        )
        .unwrap();
    let inbound = surface
        .extract_request_upgrade_envelope(&request)
        .unwrap()
        .unwrap();
    let ug2_envelope = match server.handle_ug1(
        "h2-client-a",
        &carrier,
        inbound.lookup_hint,
        &inbound.envelope,
        request_len(&request),
        now_secs,
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => panic!("expected reply"),
    };

    let mut response = surface.build_state_pull_response("device-1", json!({"battery": 91}));
    surface
        .embed_response_upgrade_envelope(
            &mut response,
            &ApiSyncResponseUpgradeEnvelope {
                envelope: ug2_envelope,
            },
        )
        .unwrap();
    let ug2_field = surface
        .extract_response_upgrade_envelope(&response)
        .unwrap()
        .unwrap();
    let prepared_ug3 = prepared_ug1
        .state
        .handle_ug2(&ug2_field.envelope, &carrier)
        .unwrap();

    let mut confirm_request = surface.build_state_push_request("device-1", json!({"battery": 92}));
    surface
        .embed_request_upgrade_envelope(
            &mut confirm_request,
            &ApiSyncRequestUpgradeEnvelope {
                lookup_hint: prepared_ug3.lookup_hint,
                envelope: prepared_ug3.envelope.clone(),
            },
        )
        .unwrap();
    let inbound = surface
        .extract_request_upgrade_envelope(&confirm_request)
        .unwrap()
        .unwrap();
    let EstablishedEnvelopeReply {
        envelope: ug4_envelope,
        session: server_session,
    } = match server.handle_ug3(
        "h2-client-a",
        &carrier,
        inbound.lookup_hint,
        &inbound.envelope,
        now_secs + 1,
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => panic!("expected reply"),
    };

    let mut final_response = surface.build_state_pull_response("device-1", json!({"battery": 92}));
    surface
        .embed_response_upgrade_envelope(
            &mut final_response,
            &ApiSyncResponseUpgradeEnvelope {
                envelope: ug4_envelope,
            },
        )
        .unwrap();
    let ug4_field = surface
        .extract_response_upgrade_envelope(&final_response)
        .unwrap()
        .unwrap();
    let client_session = prepared_ug3
        .state
        .handle_ug4(&ug4_field.envelope, &carrier)
        .unwrap();

    assert_eq!(client_session.session_id, server_session.session_id);
    assert_eq!(
        client_session.chosen_carrier,
        CarrierBinding::S1EncryptedStream
    );
    assert_eq!(
        server_session.chosen_carrier,
        CarrierBinding::S1EncryptedStream
    );
    assert!(client_session.masked_fallback_ticket.is_some());
    assert!(server_session.masked_fallback_ticket.is_some());
}

#[test]
fn profile_mismatch_is_rejected() {
    let err = ApiSyncSurface::new(OriginFamilyProfile::object_origin()).unwrap_err();
    assert!(matches!(err, SurfaceH2Error::Profile(_)));
}
