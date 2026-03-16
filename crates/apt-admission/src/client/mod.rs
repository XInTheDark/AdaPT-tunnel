use super::*;

mod envelope;
mod wrapper;

pub use self::{
    envelope::{initiate_ug1, initiate_ug1_with_context},
    wrapper::{initiate_c0, PreparedC0, PreparedC2},
};

/// Provisioned client credential.
#[derive(Clone, Debug)]
pub struct ClientCredential {
    /// Admission profile.
    pub auth_profile: AuthProfile,
    /// Optional per-user identifier.
    pub user_id: Option<String>,
    /// Optional stable client static private key used to keep a deployment-local
    /// identity even when authentication is still shared-deployment based.
    pub client_static_private: Option<[u8; 32]>,
    /// Raw admission key.
    pub admission_key: [u8; 32],
    /// Server static public key.
    pub server_static_public: [u8; 32],
    /// Whether to emit a rotating lookup hint.
    pub enable_lookup_hint: bool,
}

/// Client request metadata for a new session attempt.
#[derive(Clone, Debug)]
pub struct ClientSessionRequest {
    /// Remote endpoint identifier.
    pub endpoint_id: EndpointId,
    /// Preferred carrier for the initial attempt.
    pub preferred_carrier: CarrierBinding,
    /// Supported carriers.
    pub supported_carriers: Vec<CarrierBinding>,
    /// Supported cipher suites.
    pub supported_suites: Vec<CipherSuite>,
    /// Desired numeric mode.
    pub mode: Mode,
    /// Coarse public-route hint for the current network context.
    pub public_route_hint: PublicRouteHint,
    /// Coarse current path profile.
    pub path_profile: PathProfile,
    /// Current UNIX timestamp.
    pub now_secs: u64,
    /// Optional masked fallback ticket.
    pub masked_fallback_ticket: Option<SealedEnvelope>,
    /// Requested random padding for `C0`.
    pub c0_padding_len: usize,
    /// Requested random padding for `C2`.
    pub c2_padding_len: usize,
    /// Policy flags.
    pub policy_flags: PolicyFlags,
}

impl ClientSessionRequest {
    /// Creates a conservative request with spec-aligned defaults.
    #[must_use]
    pub fn conservative(endpoint_id: EndpointId, now_secs: u64) -> Self {
        let public_route_hint = PublicRouteHint(endpoint_id.as_str().to_string());
        Self {
            endpoint_id,
            preferred_carrier: CarrierBinding::D1DatagramUdp,
            supported_carriers: vec![
                CarrierBinding::D1DatagramUdp,
                CarrierBinding::D2EncryptedDatagram,
            ],
            supported_suites: vec![CipherSuite::NoiseXxPsk2X25519ChaChaPolyBlake2s],
            mode: Mode::STEALTH,
            public_route_hint,
            path_profile: PathProfile::unknown(),
            now_secs,
            masked_fallback_ticket: None,
            c0_padding_len: 24,
            c2_padding_len: 16,
            policy_flags: PolicyFlags {
                allow_hybrid_pq: false,
            },
        }
    }
}

/// Result of initiating the first hidden-upgrade request without any public-wire
/// packet wrapper.
#[derive(Debug)]
pub struct PreparedUg1Envelope {
    /// Optional rotating lookup hint carried by the surrounding surface.
    pub lookup_hint: Option<[u8; 8]>,
    /// Encrypted hidden-upgrade envelope that may be embedded into a legal slot.
    pub envelope: SealedEnvelope,
    /// State required to process the server's first hidden-upgrade reply.
    pub state: ClientPendingS1,
}

/// Result of processing `UG2` and emitting `UG3` without any public-wire packet
/// wrapper.
#[derive(Debug)]
pub struct PreparedUg3Envelope {
    /// Optional rotating lookup hint carried by the surrounding surface.
    pub lookup_hint: Option<[u8; 8]>,
    /// Encrypted hidden-upgrade envelope that may be embedded into a legal slot.
    pub envelope: SealedEnvelope,
    /// State required to process the final server seal.
    pub state: ClientPendingS3,
}

/// Client state waiting for the server's first hidden-upgrade reply.
#[derive(Debug)]
pub struct ClientPendingS1 {
    pub(super) credential: ClientCredential,
    pub(super) endpoint_id: EndpointId,
    pub(super) _preferred_carrier: CarrierBinding,
    pub(super) supported_carriers: Vec<CarrierBinding>,
    pub(super) supported_suites: Vec<CipherSuite>,
    pub(super) _mode: Mode,
    pub(super) admission_epoch_slot: u64,
    pub(super) admission_key: [u8; 32],
    pub(super) noise: NoiseHandshake,
    pub(super) _client_nonce: ClientNonce,
    pub(super) client_contribution: [u8; 32],
    pub(super) c2_padding_len: usize,
    pub(super) public_session_context: Option<PublicSessionUpgradeContext>,
}

/// Client state waiting for the final server seal.
#[derive(Debug)]
pub struct ClientPendingS3 {
    pub(super) endpoint_id: EndpointId,
    pub(super) chosen_carrier: CarrierBinding,
    pub(super) chosen_suite: CipherSuite,
    pub(super) _mode: Mode,
    pub(super) credential_identity: CredentialIdentity,
    pub(super) secrets: SessionSecretsForRole,
    pub(super) admission_epoch_slot: u64,
    pub(super) public_session_context: Option<PublicSessionUpgradeContext>,
}

pub(super) fn chosen_credential_identity(credential: &ClientCredential) -> CredentialIdentity {
    match (&credential.auth_profile, &credential.user_id) {
        (AuthProfile::SharedDeployment, _) => CredentialIdentity::SharedDeployment,
        (AuthProfile::PerUser, Some(user_id)) => CredentialIdentity::User(user_id.clone()),
        (AuthProfile::PerUser, None) => CredentialIdentity::User("unknown-user".to_string()),
    }
}
