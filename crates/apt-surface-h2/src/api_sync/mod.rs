use crate::json_slot::{get_nested_string, set_nested_string};
use apt_origin::{MessagePhase, OriginFamilyId, OriginFamilyProfile, PublicSessionTransport};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

#[cfg(test)]
mod tests;
mod transport;

pub use self::transport::{
    ApiSyncH2Carrier, ApiSyncRequestUpgradeEnvelope, ApiSyncResponseUpgradeEnvelope,
};

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
