use super::*;

/// Policy flags offered during `UG1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyFlags {
    /// Whether hybrid PQ mode is permitted by local policy.
    pub allow_hybrid_pq: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct NoiseResponderPayload {
    pub server_contribution: [u8; 32],
    pub masked_fallback_ticket_accept: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct NoiseInitiatorPayload {
    pub client_contribution: [u8; 32],
    pub user_identity: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct CookiePayload {
    pub source_id: String,
    pub endpoint_id: EndpointId,
    pub carrier: CarrierBinding,
    pub slot_binding: UpgradeSlotBinding,
    pub client_nonce: ClientNonce,
    pub epoch_slot: u64,
    pub expires_at_secs: u64,
    pub noise_msg1: Vec<u8>,
    pub chosen_suite: CipherSuite,
    pub chosen_carrier: CarrierBinding,
    pub chosen_mode: Mode,
    pub credential_label: String,
    pub lookup_hint: Option<[u8; 8]>,
    pub public_route_hint: PublicRouteHint,
    pub path_profile: PathProfile,
    pub masked_fallback_ticket_accepted: bool,
}
