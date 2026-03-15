//! Public-service family descriptions for AdaPT v2 surface planning.
//!
//! This crate intentionally stays data-model oriented for now: it describes the
//! honest public-service families, legal request/response shapes, and upgrade
//! slot classes that later `apt-surface-h2` / `apt-surface-h3` implementations
//! will consume.
#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OriginFamilyId {
    ApiSync,
    ObjectOrigin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicSessionTransport {
    S1H2,
    D2H3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequestMethod {
    Get,
    Post,
    Put,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MessagePhase {
    Request,
    Response,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpgradeSlotKind {
    JsonFieldValue,
    BinaryObjectFragment,
    EncryptedMetadataField,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpgradeSlotVisibility {
    PublicUnauthenticated,
    PublicAuthenticated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestPattern {
    pub name: String,
    pub method: RequestMethod,
    pub path_template: String,
    pub request_content_type: String,
    pub response_content_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeSlot {
    pub name: String,
    pub phase: MessagePhase,
    pub slot_kind: UpgradeSlotKind,
    pub path_hint: String,
    pub content_type: String,
    pub min_object_bytes: u32,
    pub max_object_bytes: u32,
    pub visibility: UpgradeSlotVisibility,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginFamilyProfile {
    pub family_id: OriginFamilyId,
    pub transport: PublicSessionTransport,
    pub display_name: String,
    pub request_patterns: Vec<RequestPattern>,
    pub upgrade_slots: Vec<UpgradeSlot>,
}

impl OriginFamilyProfile {
    #[must_use]
    pub fn api_sync() -> Self {
        Self {
            family_id: OriginFamilyId::ApiSync,
            transport: PublicSessionTransport::S1H2,
            display_name: "api-sync".to_string(),
            request_patterns: vec![
                RequestPattern {
                    name: "device-state-pull".to_string(),
                    method: RequestMethod::Get,
                    path_template: "/v1/devices/{device_id}/state".to_string(),
                    request_content_type: "application/json".to_string(),
                    response_content_type: "application/json".to_string(),
                },
                RequestPattern {
                    name: "device-state-push".to_string(),
                    method: RequestMethod::Post,
                    path_template: "/v1/devices/{device_id}/sync".to_string(),
                    request_content_type: "application/json".to_string(),
                    response_content_type: "application/json".to_string(),
                },
            ],
            upgrade_slots: vec![
                UpgradeSlot {
                    name: "request-json-metadata".to_string(),
                    phase: MessagePhase::Request,
                    slot_kind: UpgradeSlotKind::JsonFieldValue,
                    path_hint: "/v1/devices/{device_id}/sync".to_string(),
                    content_type: "application/json".to_string(),
                    min_object_bytes: 48,
                    max_object_bytes: 512,
                    visibility: UpgradeSlotVisibility::PublicAuthenticated,
                },
                UpgradeSlot {
                    name: "response-json-fragment".to_string(),
                    phase: MessagePhase::Response,
                    slot_kind: UpgradeSlotKind::EncryptedMetadataField,
                    path_hint: "/v1/devices/{device_id}/state".to_string(),
                    content_type: "application/json".to_string(),
                    min_object_bytes: 48,
                    max_object_bytes: 384,
                    visibility: UpgradeSlotVisibility::PublicAuthenticated,
                },
            ],
        }
    }

    #[must_use]
    pub fn object_origin() -> Self {
        Self {
            family_id: OriginFamilyId::ObjectOrigin,
            transport: PublicSessionTransport::D2H3,
            display_name: "object-origin".to_string(),
            request_patterns: vec![
                RequestPattern {
                    name: "object-download".to_string(),
                    method: RequestMethod::Get,
                    path_template: "/objects/{bucket}/{object_id}".to_string(),
                    request_content_type: "application/octet-stream".to_string(),
                    response_content_type: "application/octet-stream".to_string(),
                },
                RequestPattern {
                    name: "object-upload".to_string(),
                    method: RequestMethod::Put,
                    path_template: "/objects/{bucket}/{object_id}".to_string(),
                    request_content_type: "application/octet-stream".to_string(),
                    response_content_type: "application/json".to_string(),
                },
            ],
            upgrade_slots: vec![
                UpgradeSlot {
                    name: "upload-body-fragment".to_string(),
                    phase: MessagePhase::Request,
                    slot_kind: UpgradeSlotKind::BinaryObjectFragment,
                    path_hint: "/objects/{bucket}/{object_id}".to_string(),
                    content_type: "application/octet-stream".to_string(),
                    min_object_bytes: 256,
                    max_object_bytes: 4096,
                    visibility: UpgradeSlotVisibility::PublicAuthenticated,
                },
                UpgradeSlot {
                    name: "download-metadata-tail".to_string(),
                    phase: MessagePhase::Response,
                    slot_kind: UpgradeSlotKind::EncryptedMetadataField,
                    path_hint: "/objects/{bucket}/{object_id}".to_string(),
                    content_type: "application/octet-stream".to_string(),
                    min_object_bytes: 128,
                    max_object_bytes: 2048,
                    visibility: UpgradeSlotVisibility::PublicAuthenticated,
                },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_sync_profile_targets_h2_and_json_slots() {
        let profile = OriginFamilyProfile::api_sync();
        assert_eq!(profile.family_id, OriginFamilyId::ApiSync);
        assert_eq!(profile.transport, PublicSessionTransport::S1H2);
        assert!(profile
            .upgrade_slots
            .iter()
            .all(|slot| slot.content_type == "application/json"));
        assert!(profile
            .request_patterns
            .iter()
            .any(|pattern| pattern.method == RequestMethod::Post));
    }

    #[test]
    fn object_origin_profile_targets_h3_and_binary_slots() {
        let profile = OriginFamilyProfile::object_origin();
        assert_eq!(profile.family_id, OriginFamilyId::ObjectOrigin);
        assert_eq!(profile.transport, PublicSessionTransport::D2H3);
        assert!(profile.upgrade_slots.iter().any(|slot| {
            slot.slot_kind == UpgradeSlotKind::BinaryObjectFragment
                && slot.content_type == "application/octet-stream"
        }));
        assert!(profile
            .request_patterns
            .iter()
            .any(|pattern| pattern.method == RequestMethod::Put));
    }
}
