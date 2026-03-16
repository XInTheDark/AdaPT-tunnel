use crate::json_slot::{get_nested_string, set_nested_string};
use apt_carriers::{CarrierProfile, InvalidInputBehavior};
use apt_crypto::SealedEnvelope;
use apt_origin::{MessagePhase, OriginFamilyId, OriginFamilyProfile, PublicSessionTransport};
use apt_types::CarrierBinding;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

pub const API_SYNC_REQUEST_SLOT: &str = "request-json-metadata";
pub const API_SYNC_RESPONSE_SLOT: &str = "response-json-fragment";

const REQUEST_SLOT_PATH: &[&str] = &["metadata", "sync_hint"];
const RESPONSE_SLOT_PATH: &[&str] = &["server_hints", "next_cursor"];

#[derive(Clone, Debug, PartialEq)]
pub struct ApiSyncRequest {
    pub path: String,
    pub authenticated_public: bool,
    pub body: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ApiSyncResponse {
    pub status: u16,
    pub body: Value,
}

/// Envelope embedded into a legal API-sync request slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiSyncRequestUpgradeEnvelope {
    pub lookup_hint: Option<[u8; 8]>,
    pub envelope: SealedEnvelope,
}

/// Envelope embedded into a legal API-sync response slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiSyncResponseUpgradeEnvelope {
    pub envelope: SealedEnvelope,
}

/// Carrier metadata for the H2 API-sync public-session family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApiSyncH2Carrier {
    max_record_size: u16,
    tunnel_mtu: u16,
}

impl ApiSyncH2Carrier {
    #[must_use]
    pub const fn new(max_record_size: u16, tunnel_mtu: u16) -> Self {
        Self {
            max_record_size,
            tunnel_mtu,
        }
    }

    #[must_use]
    pub const fn conservative() -> Self {
        Self::new(16_384, 1_380)
    }
}

impl Default for ApiSyncH2Carrier {
    fn default() -> Self {
        Self::conservative()
    }
}

impl CarrierProfile for ApiSyncH2Carrier {
    fn binding(&self) -> CarrierBinding {
        CarrierBinding::S1EncryptedStream
    }

    fn max_record_size(&self) -> u16 {
        self.max_record_size
    }

    fn tunnel_mtu(&self) -> u16 {
        self.tunnel_mtu
    }

    fn invalid_input_behavior(&self) -> InvalidInputBehavior {
        InvalidInputBehavior::DecoySurface
    }
}

#[derive(Debug, Error)]
pub enum SurfaceH2Error {
    #[error("surface profile mismatch: {0}")]
    Profile(&'static str),
    #[error("slot `{0}` is not available for this phase")]
    SlotPhase(String),
    #[error("slot `{0}` is unknown to the api-sync profile")]
    UnknownSlot(String),
    #[error("serialization failure: {0}")]
    Serialization(#[from] Box<bincode::ErrorKind>),
    #[error("json slot error: {0}")]
    Json(&'static str),
}

#[derive(Clone, Debug)]
pub struct ApiSyncSurface {
    profile: OriginFamilyProfile,
}

impl ApiSyncSurface {
    pub fn new(profile: OriginFamilyProfile) -> Result<Self, SurfaceH2Error> {
        if profile.family_id != OriginFamilyId::ApiSync {
            return Err(SurfaceH2Error::Profile("expected api-sync family"));
        }
        if profile.transport != PublicSessionTransport::S1H2 {
            return Err(SurfaceH2Error::Profile("expected S1/H2 transport"));
        }
        Ok(Self { profile })
    }

    #[must_use]
    pub fn starter() -> Self {
        Self::new(OriginFamilyProfile::api_sync()).expect("starter api-sync profile is valid")
    }

    #[must_use]
    pub const fn profile(&self) -> &OriginFamilyProfile {
        &self.profile
    }

    #[must_use]
    pub fn build_state_push_request(&self, device_id: &str, changes: Value) -> ApiSyncRequest {
        ApiSyncRequest {
            path: format!("/v1/devices/{device_id}/sync"),
            authenticated_public: true,
            body: json!({
                "device_id": device_id,
                "changes": changes,
                "metadata": {
                    "sync_hint": Value::Null,
                    "client_time_ms": 0,
                },
            }),
        }
    }

    #[must_use]
    pub fn build_state_pull_response(&self, device_id: &str, snapshot: Value) -> ApiSyncResponse {
        ApiSyncResponse {
            status: 200,
            body: json!({
                "device_id": device_id,
                "state": snapshot,
                "server_hints": {
                    "next_cursor": Value::Null,
                },
            }),
        }
    }

    pub fn embed_request_capsule<T: Serialize>(
        &self,
        request: &mut ApiSyncRequest,
        capsule: &T,
    ) -> Result<(), SurfaceH2Error> {
        self.validate_slot_phase(API_SYNC_REQUEST_SLOT, MessagePhase::Request)?;
        let encoded = URL_SAFE_NO_PAD.encode(bincode::serialize(capsule)?);
        set_nested_string(&mut request.body, REQUEST_SLOT_PATH, encoded)
            .map_err(SurfaceH2Error::Json)
    }

    pub fn extract_request_capsule<T: DeserializeOwned>(
        &self,
        request: &ApiSyncRequest,
    ) -> Result<Option<T>, SurfaceH2Error> {
        self.validate_slot_phase(API_SYNC_REQUEST_SLOT, MessagePhase::Request)?;
        decode_slot_value(get_nested_string(&request.body, REQUEST_SLOT_PATH))
    }

    pub fn embed_response_capsule<T: Serialize>(
        &self,
        response: &mut ApiSyncResponse,
        capsule: &T,
    ) -> Result<(), SurfaceH2Error> {
        self.validate_slot_phase(API_SYNC_RESPONSE_SLOT, MessagePhase::Response)?;
        let encoded = URL_SAFE_NO_PAD.encode(bincode::serialize(capsule)?);
        set_nested_string(&mut response.body, RESPONSE_SLOT_PATH, encoded)
            .map_err(SurfaceH2Error::Json)
    }

    pub fn extract_response_capsule<T: DeserializeOwned>(
        &self,
        response: &ApiSyncResponse,
    ) -> Result<Option<T>, SurfaceH2Error> {
        self.validate_slot_phase(API_SYNC_RESPONSE_SLOT, MessagePhase::Response)?;
        decode_slot_value(get_nested_string(&response.body, RESPONSE_SLOT_PATH))
    }

    pub fn embed_request_upgrade_envelope(
        &self,
        request: &mut ApiSyncRequest,
        upgrade: &ApiSyncRequestUpgradeEnvelope,
    ) -> Result<(), SurfaceH2Error> {
        self.embed_request_capsule(request, upgrade)
    }

    pub fn extract_request_upgrade_envelope(
        &self,
        request: &ApiSyncRequest,
    ) -> Result<Option<ApiSyncRequestUpgradeEnvelope>, SurfaceH2Error> {
        self.extract_request_capsule(request)
    }

    pub fn embed_response_upgrade_envelope(
        &self,
        response: &mut ApiSyncResponse,
        upgrade: &ApiSyncResponseUpgradeEnvelope,
    ) -> Result<(), SurfaceH2Error> {
        self.embed_response_capsule(response, upgrade)
    }

    pub fn extract_response_upgrade_envelope(
        &self,
        response: &ApiSyncResponse,
    ) -> Result<Option<ApiSyncResponseUpgradeEnvelope>, SurfaceH2Error> {
        self.extract_response_capsule(response)
    }

    fn validate_slot_phase(
        &self,
        slot_name: &str,
        expected_phase: MessagePhase,
    ) -> Result<(), SurfaceH2Error> {
        let slot = self
            .profile
            .upgrade_slot(slot_name)
            .ok_or_else(|| SurfaceH2Error::UnknownSlot(slot_name.to_string()))?;
        if slot.phase != expected_phase {
            return Err(SurfaceH2Error::SlotPhase(slot_name.to_string()));
        }
        Ok(())
    }
}

fn decode_slot_value<T: DeserializeOwned>(
    encoded: Option<&str>,
) -> Result<Option<T>, SurfaceH2Error> {
    let Some(encoded) = encoded else {
        return Ok(None);
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| SurfaceH2Error::Json("invalid base64 in json slot"))?;
    Ok(Some(bincode::deserialize(&bytes)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use apt_admission::{
        initiate_ug1, AdmissionConfig, AdmissionServer, AdmissionServerSecrets, ClientCredential,
        ClientSessionRequest, CredentialStore, EstablishedEnvelopeReply, ServerResponse, Ug1, Ug2,
        UpgradeMessagePhase, UpgradeSlotBinding,
    };
    use apt_crypto::generate_static_keypair;
    use apt_types::{
        AuthProfile, CarrierBinding, CipherSuite, ClientNonce, CredentialIdentity, EndpointId,
        Mode, PathProfile, PublicRouteHint,
    };

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
            anti_amplification_cookie: SealedEnvelope {
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

        let mut confirm_request =
            surface.build_state_push_request("device-1", json!({"battery": 92}));
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

        let mut final_response =
            surface.build_state_pull_response("device-1", json!({"battery": 92}));
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
}
