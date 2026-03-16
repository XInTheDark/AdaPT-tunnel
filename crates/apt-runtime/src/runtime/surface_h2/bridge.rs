use super::*;
use apt_admission::{
    initiate_ug1_with_context, AdmissionError, AdmissionServer, ClientPendingS1, ClientPendingS3,
    EstablishedEnvelopeReply, EstablishedSession, ServerResponse,
};
use apt_crypto::SealedEnvelope;
use apt_surface_h2::{
    ApiSyncH2Carrier, ApiSyncRequestUpgradeEnvelope, ApiSyncResponseUpgradeEnvelope,
};
use serde_json::json;

#[derive(Debug)]
pub struct PreparedApiSyncUg1Request {
    pub authority: String,
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
    let authority = config.surface_plan.authority.clone();
    let upgrade_context = surface.upgrade_context(&authority)?;
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
    let prepared = initiate_ug1_with_context(
        client_credential(config),
        request,
        &carrier,
        upgrade_context,
    )?;
    let device_id = config.client_identity.as_deref().unwrap_or("shared-device");
    let mut public_request = surface.build_state_push_request(
        &authority,
        device_id,
        json!({ "mode": config.mode.value() }),
    );
    surface.embed_request_upgrade_envelope(
        &mut public_request,
        &ApiSyncRequestUpgradeEnvelope {
            lookup_hint: prepared.lookup_hint,
            envelope: prepared.envelope,
        },
    )?;
    Ok(PreparedApiSyncUg1Request {
        authority,
        request: public_request,
        state: prepared.state,
    })
}

pub fn handle_api_sync_ug2_response(
    surface: &ApiSyncSurface,
    authority: &str,
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
        surface.build_state_push_request(authority, device_id, json!({ "confirm": true }));
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
    let upgrade_context = surface.request_upgrade_context(request)?;
    let received_len = request.authority.len()
        + request.path.len()
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
    match admission.handle_ug1_with_context(
        source_id,
        &carrier,
        &upgrade_context,
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
    respond_api_sync_ug3_request_with_extension_builder(
        admission,
        surface,
        request,
        source_id,
        now_secs,
        |_| Ok(Vec::new()),
    )
}

pub fn respond_api_sync_ug3_request_with_extension_builder<F>(
    admission: &mut AdmissionServer,
    surface: &ApiSyncSurface,
    request: &ApiSyncRequest,
    source_id: &str,
    now_secs: u64,
    extension_builder: F,
) -> Result<Option<(ApiSyncResponse, EstablishedSession)>, RuntimeError>
where
    F: FnOnce(&EstablishedSession) -> Result<Vec<Vec<u8>>, AdmissionError>,
{
    let carrier = ApiSyncH2Carrier::conservative();
    let Some(upgrade) = surface.extract_request_upgrade_envelope(request)? else {
        return Ok(None);
    };
    let upgrade_context = surface.request_upgrade_context(request)?;
    let device_id = request.body["device_id"]
        .as_str()
        .unwrap_or("shared-device");
    match admission.handle_ug3_with_context_and_extension_builder(
        source_id,
        &carrier,
        &upgrade_context,
        upgrade.lookup_hint,
        &upgrade.envelope,
        now_secs,
        extension_builder,
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
