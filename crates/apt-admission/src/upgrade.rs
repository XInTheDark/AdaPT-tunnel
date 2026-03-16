#![allow(missing_docs)]

use super::*;

/// Which public-message direction legally carries the hidden-upgrade capsule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpgradeMessagePhase {
    Request,
    Response,
}

/// Transport-agnostic slot binding for one hidden-upgrade message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeSlotBinding {
    pub family_id: String,
    pub profile_version: String,
    pub authority: String,
    #[serde(default)]
    pub graph_branch_id: Option<String>,
    pub slot_id: String,
    pub phase: UpgradeMessagePhase,
    pub epoch_slot: u64,
    pub path_hint: String,
}

/// Public-session context used to bind hidden-upgrade envelopes to a real
/// surface family/profile/slot layout rather than a legacy packet wrapper.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicSessionUpgradeContext {
    pub carrier: CarrierBinding,
    pub family_id: String,
    pub profile_version: String,
    pub authority: String,
    #[serde(default)]
    pub graph_branch_id: Option<String>,
    pub request_slot_id: String,
    pub request_path_hint: String,
    pub response_slot_id: String,
    pub response_path_hint: String,
}

impl PublicSessionUpgradeContext {
    #[must_use]
    pub fn new(
        carrier: CarrierBinding,
        family_id: String,
        profile_version: String,
        authority: String,
        graph_branch_id: Option<String>,
        request_slot_id: String,
        request_path_hint: String,
        response_slot_id: String,
        response_path_hint: String,
    ) -> Self {
        Self {
            carrier,
            family_id,
            profile_version,
            authority,
            graph_branch_id,
            request_slot_id,
            request_path_hint,
            response_slot_id,
            response_path_hint,
        }
    }

    #[must_use]
    pub fn request_binding(&self, epoch_slot: u64) -> UpgradeSlotBinding {
        self.binding(
            UpgradeMessagePhase::Request,
            &self.request_slot_id,
            &self.request_path_hint,
            epoch_slot,
        )
    }

    #[must_use]
    pub fn response_binding(&self, epoch_slot: u64) -> UpgradeSlotBinding {
        self.binding(
            UpgradeMessagePhase::Response,
            &self.response_slot_id,
            &self.response_path_hint,
            epoch_slot,
        )
    }

    fn binding(
        &self,
        phase: UpgradeMessagePhase,
        slot_id: &str,
        path_hint: &str,
        epoch_slot: u64,
    ) -> UpgradeSlotBinding {
        UpgradeSlotBinding {
            family_id: self.family_id.clone(),
            profile_version: self.profile_version.clone(),
            authority: self.authority.clone(),
            graph_branch_id: self.graph_branch_id.clone(),
            slot_id: slot_id.to_string(),
            phase,
            epoch_slot,
            path_hint: path_hint.to_string(),
        }
    }
}

pub(crate) fn public_session_associated_data(
    endpoint_id: &EndpointId,
    context: &PublicSessionUpgradeContext,
) -> Result<Vec<u8>, AdmissionError> {
    Ok(bincode::serialize(&(endpoint_id.as_str(), context))?)
}

pub(crate) fn slot_bound_associated_data(
    endpoint_id: &EndpointId,
    context: &PublicSessionUpgradeContext,
    phase: UpgradeMessagePhase,
    epoch_slot: u64,
) -> Result<Vec<u8>, AdmissionError> {
    let binding = match phase {
        UpgradeMessagePhase::Request => context.request_binding(epoch_slot),
        UpgradeMessagePhase::Response => context.response_binding(epoch_slot),
    };
    Ok(bincode::serialize(&(
        public_session_associated_data(endpoint_id, context)?,
        binding,
    ))?)
}

/// Logical `UG1` client upgrade capsule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ug1 {
    pub endpoint_id: EndpointId,
    pub auth_profile: AuthProfile,
    pub credential_identity: CredentialIdentity,
    pub supported_suites: Vec<CipherSuite>,
    pub supported_families: Vec<CarrierBinding>,
    pub requested_mode: Mode,
    pub public_route_hint: PublicRouteHint,
    pub path_profile: PathProfile,
    pub client_nonce: ClientNonce,
    pub noise_msg1: Vec<u8>,
    pub optional_masked_fallback_ticket: Option<SealedEnvelope>,
    pub slot_binding: UpgradeSlotBinding,
    pub padding: Vec<u8>,
}

/// Logical `UG2` server upgrade reply capsule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ug2 {
    pub chosen_suite: CipherSuite,
    pub chosen_family: CarrierBinding,
    pub chosen_mode: Mode,
    pub anti_amplification_cookie: SealedEnvelope,
    pub cookie_expiry: u64,
    pub noise_msg2: Vec<u8>,
    pub optional_masked_fallback_accept: bool,
    pub slot_binding: UpgradeSlotBinding,
    pub padding: Vec<u8>,
}

/// Logical `UG3` client confirmation capsule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ug3 {
    pub selected_family_ack: CarrierBinding,
    pub anti_amplification_cookie: SealedEnvelope,
    pub noise_msg3: Vec<u8>,
    pub slot_binding: UpgradeSlotBinding,
    pub padding: Vec<u8>,
}

/// Logical `UG4` server session-seal capsule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ug4 {
    pub session_id: SessionId,
    pub tunnel_mtu: u16,
    pub rekey_limits: RekeyLimits,
    pub ticket_issue_flag: bool,
    pub optional_masked_fallback_ticket: Option<SealedEnvelope>,
    pub slot_binding: UpgradeSlotBinding,
    pub optional_extensions: Vec<Vec<u8>>,
}

pub(crate) fn legacy_upgrade_slot_binding(
    endpoint_id: &EndpointId,
    carrier: CarrierBinding,
    phase: UpgradeMessagePhase,
    slot_id: &str,
    epoch_slot: u64,
) -> UpgradeSlotBinding {
    UpgradeSlotBinding {
        family_id: "legacy-admission".to_string(),
        profile_version: VERSION.to_string(),
        authority: endpoint_id.as_str().to_string(),
        graph_branch_id: None,
        slot_id: slot_id.to_string(),
        phase,
        epoch_slot,
        path_hint: format!("{}::{}", endpoint_id.as_str(), carrier.as_str()),
    }
}
