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
    pub slot_id: String,
    pub phase: UpgradeMessagePhase,
    pub epoch_slot: u64,
    pub path_hint: String,
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
    pub path_profile: PathProfile,
    pub client_nonce: ClientNonce,
    pub noise_msg1: Vec<u8>,
    pub optional_resume_ticket: Option<SealedEnvelope>,
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
    pub optional_resume_accept: bool,
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
    pub optional_resume_ticket: Option<SealedEnvelope>,
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
        slot_id: slot_id.to_string(),
        phase,
        epoch_slot,
        path_hint: format!("{}::{}", endpoint_id.as_str(), carrier.as_str()),
    }
}
