use crate::{
    FeatureWeights, IdleConvergenceRules, MessagePhase, OriginFamilyId, OriginFamilyProfile,
    PublicSessionTransport, RequestGraphBranch, RequestMethod, RequestPattern, ShadowLaneKind,
    ShadowLaneRules, SizeTimingEnvelope, StreamConcurrencyRules, UpgradeSlot, UpgradeSlotKind,
    UpgradeSlotVisibility,
};

const STARTER_PROFILE_VERSION: &str = "2026.03";

impl OriginFamilyProfile {
    #[must_use]
    pub fn starter_profile(name: &str) -> Option<Self> {
        match name {
            "api-sync" => Some(Self::api_sync()),
            "object-origin" => Some(Self::object_origin()),
            _ => None,
        }
    }

    #[must_use]
    pub fn api_sync() -> Self {
        Self {
            family_id: OriginFamilyId::ApiSync,
            transport: PublicSessionTransport::S1H2,
            profile_version: STARTER_PROFILE_VERSION.to_string(),
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
            request_graphs: vec![
                RequestGraphBranch {
                    branch_id: "bootstrap-sync".to_string(),
                    entry_pattern: "device-state-pull".to_string(),
                    request_sequence: vec![
                        "device-state-pull".to_string(),
                        "device-state-push".to_string(),
                    ],
                    legal_upgrade_slots: vec![
                        "request-json-metadata".to_string(),
                        "response-json-fragment".to_string(),
                    ],
                },
                RequestGraphBranch {
                    branch_id: "steady-sync".to_string(),
                    entry_pattern: "device-state-push".to_string(),
                    request_sequence: vec!["device-state-push".to_string()],
                    legal_upgrade_slots: vec!["request-json-metadata".to_string()],
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
            concurrency_rules: StreamConcurrencyRules {
                max_parallel_requests: 2,
                preserves_request_order: true,
                allows_background_polling: true,
            },
            size_timing: SizeTimingEnvelope {
                min_payload_bytes: 96,
                max_payload_bytes: 4_096,
                target_inter_request_ms: 1_000,
                idle_timeout_secs: 30,
            },
            idle_convergence: IdleConvergenceRules {
                public_idle_floor_secs: 15,
                convergence_timeout_secs: 45,
                require_public_semantics_after_idle: true,
            },
            shadow_lane_rules: ShadowLaneRules {
                allowed_lanes: Vec::new(),
                remembered_safe_only: true,
            },
            feature_weights: FeatureWeights {
                timing: 5,
                sizes: 4,
                concurrency: 3,
                ordering: 5,
            },
        }
    }

    #[must_use]
    pub fn object_origin() -> Self {
        Self {
            family_id: OriginFamilyId::ObjectOrigin,
            transport: PublicSessionTransport::D2H3,
            profile_version: STARTER_PROFILE_VERSION.to_string(),
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
            request_graphs: vec![
                RequestGraphBranch {
                    branch_id: "upload-stream".to_string(),
                    entry_pattern: "object-upload".to_string(),
                    request_sequence: vec!["object-upload".to_string()],
                    legal_upgrade_slots: vec!["upload-body-fragment".to_string()],
                },
                RequestGraphBranch {
                    branch_id: "download-stream".to_string(),
                    entry_pattern: "object-download".to_string(),
                    request_sequence: vec!["object-download".to_string()],
                    legal_upgrade_slots: vec!["download-metadata-tail".to_string()],
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
                    max_object_bytes: 4_096,
                    visibility: UpgradeSlotVisibility::PublicAuthenticated,
                },
                UpgradeSlot {
                    name: "download-metadata-tail".to_string(),
                    phase: MessagePhase::Response,
                    slot_kind: UpgradeSlotKind::EncryptedMetadataField,
                    path_hint: "/objects/{bucket}/{object_id}".to_string(),
                    content_type: "application/octet-stream".to_string(),
                    min_object_bytes: 128,
                    max_object_bytes: 2_048,
                    visibility: UpgradeSlotVisibility::PublicAuthenticated,
                },
            ],
            concurrency_rules: StreamConcurrencyRules {
                max_parallel_requests: 4,
                preserves_request_order: false,
                allows_background_polling: false,
            },
            size_timing: SizeTimingEnvelope {
                min_payload_bytes: 512,
                max_payload_bytes: 65_536,
                target_inter_request_ms: 250,
                idle_timeout_secs: 20,
            },
            idle_convergence: IdleConvergenceRules {
                public_idle_floor_secs: 10,
                convergence_timeout_secs: 30,
                require_public_semantics_after_idle: true,
            },
            shadow_lane_rules: ShadowLaneRules {
                allowed_lanes: vec![ShadowLaneKind::H3Datagram],
                remembered_safe_only: true,
            },
            feature_weights: FeatureWeights {
                timing: 4,
                sizes: 5,
                concurrency: 5,
                ordering: 2,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_sync_profile_exposes_graphs_and_runtime_metadata() {
        let profile = OriginFamilyProfile::api_sync();
        assert_eq!(profile.family_id, OriginFamilyId::ApiSync);
        assert_eq!(profile.transport, PublicSessionTransport::S1H2);
        assert_eq!(profile.profile_version, STARTER_PROFILE_VERSION);
        assert_eq!(profile.concurrency_rules.max_parallel_requests, 2);
        assert!(profile.idle_convergence.require_public_semantics_after_idle);
        assert!(!profile.supports_shadow_lane(ShadowLaneKind::H3Datagram));

        let branch = profile.request_graph("bootstrap-sync").unwrap();
        assert_eq!(branch.entry_pattern, "device-state-pull");
        assert!(branch
            .legal_upgrade_slots
            .contains(&"response-json-fragment".to_string()));
        assert!(profile.request_pattern("device-state-push").is_some());
        assert!(profile.upgrade_slot("request-json-metadata").is_some());
    }

    #[test]
    fn object_origin_profile_exposes_h3_ready_metadata() {
        let profile = OriginFamilyProfile::object_origin();
        assert_eq!(profile.family_id, OriginFamilyId::ObjectOrigin);
        assert_eq!(profile.transport, PublicSessionTransport::D2H3);
        assert!(profile.supports_shadow_lane(ShadowLaneKind::H3Datagram));
        assert!(profile.shadow_lane_rules.remembered_safe_only);
        assert_eq!(profile.size_timing.max_payload_bytes, 65_536);

        let branch = profile.request_graph("upload-stream").unwrap();
        assert_eq!(branch.entry_pattern, "object-upload");
        assert!(branch
            .legal_upgrade_slots
            .contains(&"upload-body-fragment".to_string()));
        assert!(profile.request_pattern("object-download").is_some());
        assert!(profile.upgrade_slot("download-metadata-tail").is_some());
    }

    #[test]
    fn starter_profile_lookup_uses_cover_family_names() {
        assert_eq!(
            OriginFamilyProfile::starter_profile("api-sync")
                .unwrap()
                .family_id,
            OriginFamilyId::ApiSync
        );
        assert_eq!(
            OriginFamilyProfile::starter_profile("object-origin")
                .unwrap()
                .family_id,
            OriginFamilyId::ObjectOrigin
        );
        assert!(OriginFamilyProfile::starter_profile("unknown-family").is_none());
    }
}
