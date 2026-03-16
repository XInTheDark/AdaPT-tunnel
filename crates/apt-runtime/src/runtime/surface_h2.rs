use super::*;
use apt_admission::{
    initiate_ug1, AdmissionServer, ClientPendingS1, ClientPendingS3, EstablishedEnvelopeReply,
    EstablishedSession, ServerResponse,
};
use apt_surface_h2::{
    ApiSyncH2Carrier, ApiSyncRequest, ApiSyncRequestUpgradeEnvelope, ApiSyncResponse,
    ApiSyncResponseUpgradeEnvelope, ApiSyncSurface,
};
use serde_json::json;

#[derive(Debug)]
pub struct PreparedApiSyncUg1Request {
    pub request: ApiSyncRequest,
    pub state: ClientPendingS1,
}

#[derive(Debug)]
pub struct PreparedApiSyncUg3Request {
    pub request: ApiSyncRequest,
    pub state: ClientPendingS3,
}

pub fn prepare_api_sync_ug1_request(
    config: &ResolvedClientConfig,
    persistent_state: &ClientPersistentState,
    surface: &ApiSyncSurface,
    now_secs: u64,
) -> Result<PreparedApiSyncUg1Request, RuntimeError> {
    let carrier = ApiSyncH2Carrier::conservative();
    let request = client_session_request(
        config,
        persistent_state,
        CarrierBinding::S1EncryptedStream,
        &[CarrierBinding::S1EncryptedStream],
        persistent_state
            .resume_ticket
            .as_ref()
            .map(|bytes| bincode::deserialize::<SealedEnvelope>(bytes))
            .transpose()?,
        now_secs,
    );
    let prepared = initiate_ug1(client_credential(config), request, &carrier)?;
    let device_id = config.client_identity.as_deref().unwrap_or("shared-device");
    let mut public_request =
        surface.build_state_push_request(device_id, json!({ "mode": config.mode.value() }));
    surface.embed_request_upgrade_envelope(
        &mut public_request,
        &ApiSyncRequestUpgradeEnvelope {
            lookup_hint: prepared.lookup_hint,
            envelope: prepared.envelope,
        },
    )?;
    Ok(PreparedApiSyncUg1Request {
        request: public_request,
        state: prepared.state,
    })
}

pub fn handle_api_sync_ug2_response(
    surface: &ApiSyncSurface,
    response: &ApiSyncResponse,
    state: ClientPendingS1,
) -> Result<PreparedApiSyncUg3Request, RuntimeError> {
    let carrier = ApiSyncH2Carrier::conservative();
    let upgrade =
        surface
            .extract_response_upgrade_envelope(response)?
            .ok_or(RuntimeError::InvalidConfig(
                "api-sync response missing hidden-upgrade envelope".to_string(),
            ))?;
    let prepared = state.handle_ug2(&upgrade.envelope, &carrier)?;
    let device_id = response.body["device_id"]
        .as_str()
        .unwrap_or("shared-device");
    let mut public_request =
        surface.build_state_push_request(device_id, json!({ "confirm": true }));
    surface.embed_request_upgrade_envelope(
        &mut public_request,
        &ApiSyncRequestUpgradeEnvelope {
            lookup_hint: prepared.lookup_hint,
            envelope: prepared.envelope,
        },
    )?;
    Ok(PreparedApiSyncUg3Request {
        request: public_request,
        state: prepared.state,
    })
}

pub fn handle_api_sync_ug4_response(
    surface: &ApiSyncSurface,
    response: &ApiSyncResponse,
    state: ClientPendingS3,
) -> Result<EstablishedSession, RuntimeError> {
    let carrier = ApiSyncH2Carrier::conservative();
    let upgrade =
        surface
            .extract_response_upgrade_envelope(response)?
            .ok_or(RuntimeError::InvalidConfig(
                "api-sync response missing final hidden-upgrade envelope".to_string(),
            ))?;
    Ok(state.handle_ug4(&upgrade.envelope, &carrier)?)
}

pub fn respond_api_sync_ug1_request(
    admission: &mut AdmissionServer,
    surface: &ApiSyncSurface,
    request: &ApiSyncRequest,
    source_id: &str,
    now_secs: u64,
) -> Result<Option<ApiSyncResponse>, RuntimeError> {
    let carrier = ApiSyncH2Carrier::conservative();
    let Some(upgrade) = surface.extract_request_upgrade_envelope(request)? else {
        return Ok(None);
    };
    let received_len = request.path.len()
        + serde_json::to_vec(&request.body)
            .map_err(|error| {
                RuntimeError::InvalidConfig(format!(
                    "api-sync request serialization failed: {error}"
                ))
            })?
            .len();
    let device_id = request.body["device_id"]
        .as_str()
        .unwrap_or("shared-device");
    match admission.handle_ug1(
        source_id,
        &carrier,
        upgrade.lookup_hint,
        &upgrade.envelope,
        received_len,
        now_secs,
    ) {
        ServerResponse::Reply(envelope) => {
            let mut public_response =
                surface.build_state_pull_response(device_id, json!({ "accepted": true }));
            surface.embed_response_upgrade_envelope(
                &mut public_response,
                &ApiSyncResponseUpgradeEnvelope { envelope },
            )?;
            Ok(Some(public_response))
        }
        ServerResponse::Drop(_) => Ok(None),
    }
}

pub fn respond_api_sync_ug3_request(
    admission: &mut AdmissionServer,
    surface: &ApiSyncSurface,
    request: &ApiSyncRequest,
    source_id: &str,
    now_secs: u64,
) -> Result<Option<(ApiSyncResponse, EstablishedSession)>, RuntimeError> {
    let carrier = ApiSyncH2Carrier::conservative();
    let Some(upgrade) = surface.extract_request_upgrade_envelope(request)? else {
        return Ok(None);
    };
    let device_id = request.body["device_id"]
        .as_str()
        .unwrap_or("shared-device");
    match admission.handle_ug3(
        source_id,
        &carrier,
        upgrade.lookup_hint,
        &upgrade.envelope,
        now_secs,
    ) {
        ServerResponse::Reply(EstablishedEnvelopeReply { envelope, session }) => {
            let mut public_response =
                surface.build_state_pull_response(device_id, json!({ "accepted": true }));
            surface.embed_response_upgrade_envelope(
                &mut public_response,
                &ApiSyncResponseUpgradeEnvelope { envelope },
            )?;
            Ok(Some((public_response, session)))
        }
        ServerResponse::Drop(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RuntimeCarrierPreference;
    use apt_admission::{AdmissionConfig, AdmissionServerSecrets, CredentialStore};
    use apt_crypto::generate_static_keypair;
    use apt_types::{AuthProfile, EndpointId, Mode, SessionPolicy};
    use std::{net::SocketAddr, path::PathBuf};

    fn test_client_config() -> ResolvedClientConfig {
        ResolvedClientConfig {
            server_addr: "198.51.100.10:51820".parse::<SocketAddr>().unwrap(),
            mode: Mode::STEALTH,
            preferred_carrier: RuntimeCarrierPreference::Auto,
            strict_preferred_carrier: false,
            auth_profile: AuthProfile::SharedDeployment,
            endpoint_id: EndpointId::new("edge-h2"),
            admission_key: [0x11; 32],
            server_static_public_key: [0x22; 32],
            client_static_private_key: [0x33; 32],
            client_identity: Some("device-a".to_string()),
            bind: "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
            interface_name: None,
            routes: Vec::new(),
            use_server_pushed_routes: true,
            enable_d2_fallback: false,
            d2: None,
            session_policy: SessionPolicy::default(),
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

    fn test_server() -> (AdmissionServer, [u8; 32]) {
        let static_keypair = generate_static_keypair().unwrap();
        let mut store = CredentialStore::new();
        store.set_shared_deployment_key([0x11; 32]);
        let mut config = AdmissionConfig::conservative(EndpointId::new("edge-h2"));
        config.allowed_carriers = vec![CarrierBinding::S1EncryptedStream];
        (
            AdmissionServer::new(
                config,
                store,
                AdmissionServerSecrets {
                    static_keypair: static_keypair.clone(),
                    cookie_key: [0x55; 32],
                    ticket_key: [0x66; 32],
                },
            ),
            static_keypair.public,
        )
    }

    #[test]
    fn runtime_bridge_drives_api_sync_hidden_upgrade_round_trip() {
        let surface = ApiSyncSurface::starter();
        let (mut server, server_static_public_key) = test_server();
        let now_secs = 1_700_100_000;
        let persistent_state = ClientPersistentState::default();
        let mut client_config = test_client_config();
        client_config.server_static_public_key = server_static_public_key;

        let prepared_ug1 =
            prepare_api_sync_ug1_request(&client_config, &persistent_state, &surface, now_secs)
                .unwrap();
        let response_ug2 = respond_api_sync_ug1_request(
            &mut server,
            &surface,
            &prepared_ug1.request,
            "h2-client-a",
            now_secs,
        )
        .unwrap()
        .expect("expected UG2 response");
        let prepared_ug3 =
            handle_api_sync_ug2_response(&surface, &response_ug2, prepared_ug1.state).unwrap();
        let (response_ug4, server_session) = respond_api_sync_ug3_request(
            &mut server,
            &surface,
            &prepared_ug3.request,
            "h2-client-a",
            now_secs + 1,
        )
        .unwrap()
        .expect("expected UG4 response");
        let client_session =
            handle_api_sync_ug4_response(&surface, &response_ug4, prepared_ug3.state).unwrap();

        assert_eq!(client_session.session_id, server_session.session_id);
        assert_eq!(
            client_session.chosen_carrier,
            CarrierBinding::S1EncryptedStream
        );
        assert!(client_session.masked_fallback_ticket.is_some());
        assert!(server_session.masked_fallback_ticket.is_some());
    }

    #[test]
    fn runtime_bridge_returns_none_for_plain_public_requests() {
        let surface = ApiSyncSurface::starter();
        let (mut server, _) = test_server();
        let public_request =
            surface.build_state_push_request("device-a", json!({ "mode": Mode::STEALTH.value() }));
        let reply = respond_api_sync_ug1_request(
            &mut server,
            &surface,
            &public_request,
            "h2-client-a",
            1_700_100_000,
        )
        .unwrap();
        assert!(reply.is_none());
    }
}
