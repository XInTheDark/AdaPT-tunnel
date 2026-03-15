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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShadowLaneKind {
    H3Datagram,
    WebTransportLike,
    D1OpaqueFallback,
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
pub struct RequestGraphBranch {
    pub branch_id: String,
    pub entry_pattern: String,
    pub request_sequence: Vec<String>,
    pub legal_upgrade_slots: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamConcurrencyRules {
    pub max_parallel_requests: u8,
    pub preserves_request_order: bool,
    pub allows_background_polling: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeTimingEnvelope {
    pub min_payload_bytes: u32,
    pub max_payload_bytes: u32,
    pub target_inter_request_ms: u32,
    pub idle_timeout_secs: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdleConvergenceRules {
    pub public_idle_floor_secs: u16,
    pub convergence_timeout_secs: u16,
    pub require_public_semantics_after_idle: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowLaneRules {
    pub allowed_lanes: Vec<ShadowLaneKind>,
    pub remembered_safe_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureWeights {
    pub timing: u8,
    pub sizes: u8,
    pub concurrency: u8,
    pub ordering: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginFamilyProfile {
    pub family_id: OriginFamilyId,
    pub transport: PublicSessionTransport,
    pub profile_version: String,
    pub display_name: String,
    pub request_patterns: Vec<RequestPattern>,
    pub request_graphs: Vec<RequestGraphBranch>,
    pub upgrade_slots: Vec<UpgradeSlot>,
    pub concurrency_rules: StreamConcurrencyRules,
    pub size_timing: SizeTimingEnvelope,
    pub idle_convergence: IdleConvergenceRules,
    pub shadow_lane_rules: ShadowLaneRules,
    pub feature_weights: FeatureWeights,
}

impl OriginFamilyProfile {
    #[must_use]
    pub fn request_pattern(&self, name: &str) -> Option<&RequestPattern> {
        self.request_patterns
            .iter()
            .find(|pattern| pattern.name == name)
    }

    #[must_use]
    pub fn request_graph(&self, branch_id: &str) -> Option<&RequestGraphBranch> {
        self.request_graphs
            .iter()
            .find(|branch| branch.branch_id == branch_id)
    }

    #[must_use]
    pub fn upgrade_slot(&self, name: &str) -> Option<&UpgradeSlot> {
        self.upgrade_slots.iter().find(|slot| slot.name == name)
    }

    #[must_use]
    pub fn supports_shadow_lane(&self, lane: ShadowLaneKind) -> bool {
        self.shadow_lane_rules.allowed_lanes.contains(&lane)
    }
}
