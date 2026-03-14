//! Admission-plane logical messages and validation state machine for APT.
//!
//! The implementation keeps the admission plane carrier-agnostic while still
//! binding every encrypted admission message to the active carrier and endpoint.

use apt_carriers::{CarrierProfile, InvalidInputBehavior};
use apt_crypto::{
    admission_associated_data, derive_admission_key, derive_lookup_hint,
    derive_server_contribution, derive_session_secrets, derive_stateless_private_key,
    generate_static_keypair, NoiseHandshake, NoiseHandshakeConfig, RawSplitKeys, ResumeTicket,
    SealedEnvelope, SessionSecretsForRole, StaticKeypair, TokenProtector,
};
use apt_types::{
    AdmissionDefaults, AuthProfile, CarrierBinding, CipherSuite, ClientNonce, CredentialIdentity,
    EndpointId, PathProfile, PolicyMode, RekeyLimits, SessionId, SessionRole,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

const VERSION: &str = "APT/1-core";
const ACCEPTABLE_SLOT_SKEW: i64 = 1;
const ADMISSION_FLAG_LOOKUP_HINT: u8 = 0x01;
const ENVELOPE_NONCE_LEN: usize = 24;

fn random_padding(len: usize) -> Vec<u8> {
    let mut out = vec![0_u8; len];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

fn epoch_slot(now_secs: u64, slot_len_secs: u64) -> u64 {
    now_secs / slot_len_secs
}

fn candidate_slots(now_slot: u64) -> [u64; 3] {
    [
        now_slot.saturating_sub(1),
        now_slot,
        now_slot.saturating_add(1),
    ]
}

/// Errors produced by the admission logic.
#[derive(Debug, Error)]
pub enum AdmissionError {
    /// Crypto failure.
    #[error("crypto failure: {0}")]
    Crypto(#[from] apt_crypto::CryptoError),
    /// Serialization failure.
    #[error("serialization failure: {0}")]
    Serialization(#[from] Box<bincode::ErrorKind>),
    /// The input violated the spec.
    #[error("validation failure: {0}")]
    Validation(&'static str),
    /// The message was replayed.
    #[error("replay detected")]
    Replay,
}

/// Wire wrapper used for `C0`, `S1`, and `C2`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionPacket {
    /// Rotating lookup hint for per-user credentials.
    pub lookup_hint: Option<[u8; 8]>,
    /// Encrypted payload.
    pub envelope: SealedEnvelope,
}

impl AdmissionPacket {
    /// Encodes the carrier-visible admission packet without exposing a stable
    /// bincode layout on the wire.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            1 + self.lookup_hint.map_or(0, |_| 8)
                + ENVELOPE_NONCE_LEN
                + self.envelope.ciphertext.len(),
        );
        let mut flags = 0_u8;
        if self.lookup_hint.is_some() {
            flags |= ADMISSION_FLAG_LOOKUP_HINT;
        }
        out.push(flags);
        if let Some(lookup_hint) = self.lookup_hint {
            out.extend_from_slice(&lookup_hint);
        }
        out.extend_from_slice(&self.envelope.nonce);
        out.extend_from_slice(&self.envelope.ciphertext);
        out
    }

    /// Decodes the carrier-visible admission packet.
    pub fn decode(bytes: &[u8]) -> Result<Self, AdmissionError> {
        if bytes.len() < 1 + ENVELOPE_NONCE_LEN {
            return Err(AdmissionError::Validation("malformed admission packet"));
        }
        let flags = bytes[0];
        if flags & !ADMISSION_FLAG_LOOKUP_HINT != 0 {
            return Err(AdmissionError::Validation("malformed admission packet"));
        }
        let mut cursor = 1_usize;
        let lookup_hint = if flags & ADMISSION_FLAG_LOOKUP_HINT != 0 {
            if bytes.len() < cursor + 8 + ENVELOPE_NONCE_LEN {
                return Err(AdmissionError::Validation("malformed admission packet"));
            }
            let hint: [u8; 8] = bytes[cursor..cursor + 8]
                .try_into()
                .map_err(|_| AdmissionError::Validation("malformed admission packet"))?;
            cursor += 8;
            Some(hint)
        } else {
            None
        };
        if bytes.len() <= cursor + ENVELOPE_NONCE_LEN {
            return Err(AdmissionError::Validation("malformed admission packet"));
        }
        let nonce: [u8; ENVELOPE_NONCE_LEN] = bytes[cursor..cursor + ENVELOPE_NONCE_LEN]
            .try_into()
            .map_err(|_| AdmissionError::Validation("malformed admission packet"))?;
        let ciphertext = bytes[cursor + ENVELOPE_NONCE_LEN..].to_vec();
        Ok(Self {
            lookup_hint,
            envelope: SealedEnvelope { nonce, ciphertext },
        })
    }
}

/// Encrypted server confirmation sent after the tunnel keys exist.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfirmationPacket {
    /// Encrypted payload.
    pub envelope: SealedEnvelope,
}

impl ServerConfirmationPacket {
    /// Encodes the encrypted server confirmation packet.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENVELOPE_NONCE_LEN + self.envelope.ciphertext.len());
        out.extend_from_slice(&self.envelope.nonce);
        out.extend_from_slice(&self.envelope.ciphertext);
        out
    }

    /// Decodes the encrypted server confirmation packet.
    pub fn decode(bytes: &[u8]) -> Result<Self, AdmissionError> {
        if bytes.len() <= ENVELOPE_NONCE_LEN {
            return Err(AdmissionError::Validation(
                "malformed server confirmation packet",
            ));
        }
        let nonce: [u8; ENVELOPE_NONCE_LEN] = bytes[..ENVELOPE_NONCE_LEN]
            .try_into()
            .map_err(|_| AdmissionError::Validation("malformed server confirmation packet"))?;
        Ok(Self {
            envelope: SealedEnvelope {
                nonce,
                ciphertext: bytes[ENVELOPE_NONCE_LEN..].to_vec(),
            },
        })
    }
}

/// Policy flags offered during `C0`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyFlags {
    /// Whether speed-first mode is allowed by local policy.
    pub allow_speed_first: bool,
    /// Whether hybrid PQ mode is permitted by local policy.
    pub allow_hybrid_pq: bool,
}

/// Logical `C0` contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct C0 {
    /// Protocol version string.
    pub version: String,
    /// Authentication profile requested by the client.
    pub auth_profile: AuthProfile,
    /// Offered cipher suites.
    pub suite_bitmap: Vec<CipherSuite>,
    /// Offered carriers.
    pub carrier_bitmap: Vec<CarrierBinding>,
    /// Offered policy flags.
    pub policy_flags: PolicyFlags,
    /// Coarse admission epoch slot.
    pub epoch_slot: u64,
    /// Per-attempt client nonce.
    pub client_nonce: ClientNonce,
    /// Coarse path profile.
    pub path_profile: PathProfile,
    /// First Noise handshake message.
    pub noise_msg1: Vec<u8>,
    /// Optional resume ticket.
    pub optional_resume_ticket: Option<SealedEnvelope>,
    /// Opaque extensions.
    pub optional_extensions: Vec<Vec<u8>>,
    /// Variable padding.
    pub padding: Vec<u8>,
}

/// Logical `S1` contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct S1 {
    /// Protocol version string.
    pub version: String,
    /// Chosen cipher suite.
    pub chosen_suite: CipherSuite,
    /// Chosen carrier family.
    pub chosen_carrier: CarrierBinding,
    /// Chosen policy mode.
    pub chosen_policy: PolicyMode,
    /// Cookie expiry timestamp.
    pub cookie_expiry: u64,
    /// Stateless anti-amplification cookie.
    pub anti_amplification_cookie: SealedEnvelope,
    /// Second Noise handshake message.
    pub noise_msg2: Vec<u8>,
    /// Maximum carrier record size.
    pub max_record_size: u16,
    /// Idle binding hint in seconds.
    pub idle_binding_hint_secs: u16,
    /// Whether a supplied resumption ticket was accepted.
    pub optional_resume_accept: bool,
    /// Opaque extensions.
    pub optional_extensions: Vec<Vec<u8>>,
    /// Variable padding.
    pub padding: Vec<u8>,
}

/// Logical `C2` contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct C2 {
    /// Protocol version string.
    pub version: String,
    /// Echoed anti-amplification cookie.
    pub anti_amplification_cookie: SealedEnvelope,
    /// Third Noise handshake message.
    pub noise_msg3: Vec<u8>,
    /// Confirmation of the selected carrier.
    pub selected_transport_ack: CarrierBinding,
    /// Opaque extensions.
    pub optional_extensions: Vec<Vec<u8>>,
    /// Variable padding.
    pub padding: Vec<u8>,
}

/// Logical `S3` contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3 {
    /// Protocol version string.
    pub version: String,
    /// Allocated session identifier.
    pub session_id: SessionId,
    /// Effective tunnel MTU.
    pub tunnel_mtu: u16,
    /// Rekey limits.
    pub rekey_limits: RekeyLimits,
    /// Whether a new resume ticket was issued.
    pub ticket_issue_flag: bool,
    /// Optional opaque resume ticket.
    pub optional_resume_ticket: Option<SealedEnvelope>,
    /// Opaque extensions.
    pub optional_extensions: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct NoiseResponderPayload {
    server_contribution: [u8; 32],
    resume_accept: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct NoiseInitiatorPayload {
    client_contribution: [u8; 32],
    user_identity: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CookiePayload {
    source_id: String,
    endpoint_id: EndpointId,
    carrier: CarrierBinding,
    client_nonce: ClientNonce,
    epoch_slot: u64,
    expires_at_secs: u64,
    noise_msg1: Vec<u8>,
    chosen_suite: CipherSuite,
    chosen_carrier: CarrierBinding,
    chosen_policy: PolicyMode,
    credential_label: String,
    lookup_hint: Option<[u8; 8]>,
    path_profile: PathProfile,
    resume_accepted: bool,
}

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
    /// Desired policy mode.
    pub policy_mode: PolicyMode,
    /// Coarse current path profile.
    pub path_profile: PathProfile,
    /// Current UNIX timestamp.
    pub now_secs: u64,
    /// Optional resume ticket.
    pub resume_ticket: Option<SealedEnvelope>,
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
        Self {
            endpoint_id,
            preferred_carrier: CarrierBinding::D1DatagramUdp,
            supported_carriers: vec![
                CarrierBinding::D1DatagramUdp,
                CarrierBinding::S1EncryptedStream,
            ],
            supported_suites: vec![CipherSuite::NoiseXxPsk2X25519ChaChaPolyBlake2s],
            policy_mode: PolicyMode::StealthFirst,
            path_profile: PathProfile::unknown(),
            now_secs,
            resume_ticket: None,
            c0_padding_len: 24,
            c2_padding_len: 16,
            policy_flags: PolicyFlags {
                allow_speed_first: false,
                allow_hybrid_pq: false,
            },
        }
    }
}

/// Server-side per-user credential.
#[derive(Clone, Debug)]
pub struct PerUserCredential {
    /// User identifier.
    pub user_id: String,
    /// Admission key.
    pub admission_key: [u8; 32],
}

/// Store of server-side admission credentials.
#[derive(Clone, Debug, Default)]
pub struct CredentialStore {
    shared_deployment_key: Option<[u8; 32]>,
    users: Vec<PerUserCredential>,
}

impl CredentialStore {
    /// Creates an empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            shared_deployment_key: None,
            users: Vec::new(),
        }
    }

    /// Sets the shared deployment admission key.
    pub fn set_shared_deployment_key(&mut self, key: [u8; 32]) {
        self.shared_deployment_key = Some(key);
    }

    /// Adds a per-user credential.
    pub fn add_user(&mut self, credential: PerUserCredential) {
        self.users.push(credential);
    }

    fn resolve_candidates(
        &self,
        lookup_hint: Option<[u8; 8]>,
        now_slot: u64,
    ) -> Vec<ResolvedCredential> {
        let slots = candidate_slots(now_slot);
        if let Some(hint) = lookup_hint {
            self.users
                .iter()
                .filter_map(|credential| {
                    slots.into_iter().find_map(|slot| {
                        let candidate = derive_lookup_hint(&credential.admission_key, slot);
                        (candidate == hint).then(|| ResolvedCredential {
                            identity: CredentialIdentity::User(credential.user_id.clone()),
                            admission_key: credential.admission_key,
                            epoch_slot: slot,
                            lookup_hint: Some(hint),
                        })
                    })
                })
                .collect()
        } else {
            self.shared_deployment_key
                .map(|key| {
                    slots
                        .into_iter()
                        .map(|slot| ResolvedCredential {
                            identity: CredentialIdentity::SharedDeployment,
                            admission_key: key,
                            epoch_slot: slot,
                            lookup_hint: None,
                        })
                        .collect()
                })
                .unwrap_or_default()
        }
    }
}

#[derive(Clone, Debug)]
struct ResolvedCredential {
    identity: CredentialIdentity,
    admission_key: [u8; 32],
    epoch_slot: u64,
    lookup_hint: Option<[u8; 8]>,
}

impl ResolvedCredential {
    fn label(&self) -> String {
        match &self.identity {
            CredentialIdentity::SharedDeployment => "shared-deployment".to_string(),
            CredentialIdentity::User(user) => format!("user:{user}"),
        }
    }
}

#[derive(Clone, Debug)]
struct ReplayEntry {
    expires_at_secs: u64,
}

/// Server-side secret material.
#[derive(Clone, Debug)]
pub struct AdmissionServerSecrets {
    /// Server static keypair.
    pub static_keypair: StaticKeypair,
    /// Cookie protection key.
    pub cookie_key: [u8; 32],
    /// Resumption ticket protection key.
    pub ticket_key: [u8; 32],
}

impl AdmissionServerSecrets {
    /// Generates a fresh set of server secrets.
    pub fn generate() -> Result<Self, AdmissionError> {
        Ok(Self {
            static_keypair: generate_static_keypair()?,
            cookie_key: rand::random(),
            ticket_key: rand::random(),
        })
    }
}

/// Runtime admission configuration.
#[derive(Clone, Debug)]
pub struct AdmissionConfig {
    /// Local endpoint identifier.
    pub endpoint_id: EndpointId,
    /// Offered/allowed suites.
    pub allowed_suites: Vec<CipherSuite>,
    /// Offered/allowed carriers.
    pub allowed_carriers: Vec<CarrierBinding>,
    /// Default policy mode.
    pub default_policy: PolicyMode,
    /// Timing defaults.
    pub defaults: AdmissionDefaults,
    /// Max carrier record size to advertise.
    pub max_record_size: u16,
    /// Idle binding hint.
    pub idle_binding_hint_secs: u16,
    /// Initial tunnel MTU.
    pub tunnel_mtu: u16,
    /// Rekey limits.
    pub rekey_limits: RekeyLimits,
    /// Whether to issue resumption tickets.
    pub issue_resumption_tickets: bool,
    /// Lifetime of new resumption tickets.
    pub ticket_lifetime_secs: u64,
}

impl AdmissionConfig {
    /// Conservative milestone-1 defaults.
    #[must_use]
    pub fn conservative(endpoint_id: EndpointId) -> Self {
        Self {
            endpoint_id,
            allowed_suites: vec![CipherSuite::NoiseXxPsk2X25519ChaChaPolyBlake2s],
            allowed_carriers: vec![
                CarrierBinding::D1DatagramUdp,
                CarrierBinding::S1EncryptedStream,
            ],
            default_policy: PolicyMode::StealthFirst,
            defaults: AdmissionDefaults::default(),
            max_record_size: 1_200,
            idle_binding_hint_secs: 25,
            tunnel_mtu: 1_160,
            rekey_limits: RekeyLimits::recommended(),
            issue_resumption_tickets: true,
            ticket_lifetime_secs: 3_600,
        }
    }
}

/// Session material returned after `S3` is prepared or accepted.
#[derive(Clone, Debug)]
pub struct EstablishedSession {
    /// Session identifier.
    pub session_id: SessionId,
    /// Local role.
    pub role: SessionRole,
    /// Chosen carrier.
    pub chosen_carrier: CarrierBinding,
    /// Chosen suite.
    pub chosen_suite: CipherSuite,
    /// Active policy mode.
    pub policy_mode: PolicyMode,
    /// Authenticated credential identity.
    pub credential_identity: CredentialIdentity,
    /// Role-oriented session secrets.
    pub secrets: SessionSecretsForRole,
    /// Effective tunnel MTU.
    pub tunnel_mtu: u16,
    /// Rekey limits.
    pub rekey_limits: RekeyLimits,
    /// Optional fresh resumption ticket.
    pub resume_ticket: Option<SealedEnvelope>,
    /// Optional client identity surfaced inside the encrypted Noise payload.
    pub client_identity: Option<String>,
    /// Optional client static public key observed during the Noise handshake.
    pub client_static_public: Option<[u8; 32]>,
    /// Optional encrypted extensions delivered during `S3`.
    pub optional_extensions: Vec<Vec<u8>>,
}

/// Result of initiating `C0`.
#[derive(Debug)]
pub struct PreparedC0 {
    /// Encrypted `C0` packet.
    pub packet: AdmissionPacket,
    /// State required to process `S1`.
    pub state: ClientPendingS1,
}

/// Client state waiting for `S1`.
#[derive(Debug)]
pub struct ClientPendingS1 {
    credential: ClientCredential,
    endpoint_id: EndpointId,
    _preferred_carrier: CarrierBinding,
    supported_carriers: Vec<CarrierBinding>,
    supported_suites: Vec<CipherSuite>,
    _policy_mode: PolicyMode,
    admission_epoch_slot: u64,
    admission_key: [u8; 32],
    noise: NoiseHandshake,
    _client_nonce: ClientNonce,
    client_contribution: [u8; 32],
    c2_padding_len: usize,
}

/// Result of processing `S1` and emitting `C2`.
#[derive(Debug)]
pub struct PreparedC2 {
    /// Encrypted `C2` packet.
    pub packet: AdmissionPacket,
    /// State required to process `S3`.
    pub state: ClientPendingS3,
}

/// Client state waiting for `S3`.
#[derive(Debug)]
pub struct ClientPendingS3 {
    endpoint_id: EndpointId,
    chosen_carrier: CarrierBinding,
    chosen_suite: CipherSuite,
    _policy_mode: PolicyMode,
    credential_identity: CredentialIdentity,
    secrets: SessionSecretsForRole,
}

/// Server-side response to a packet.
#[derive(Debug)]
pub enum ServerResponse<T> {
    /// A valid protocol reply should be emitted.
    Reply(T),
    /// Invalid input should be handled carrier-natively.
    Drop(InvalidInputBehavior),
}

/// Server response after `C2`.
#[derive(Debug)]
pub struct EstablishedServerReply {
    /// Encrypted `S3` packet.
    pub packet: ServerConfirmationPacket,
    /// Local session material.
    pub session: EstablishedSession,
}

/// Stateful admission server.
#[derive(Debug)]
pub struct AdmissionServer {
    config: AdmissionConfig,
    credentials: CredentialStore,
    cookie_protector: TokenProtector,
    cookie_key: [u8; 32],
    ticket_protector: TokenProtector,
    server_static_private: [u8; 32],
    replay_cache: HashMap<(CredentialIdentity, ClientNonce, u64), ReplayEntry>,
}

impl AdmissionServer {
    /// Creates a new admission server.
    #[must_use]
    pub fn new(
        config: AdmissionConfig,
        credentials: CredentialStore,
        secrets: AdmissionServerSecrets,
    ) -> Self {
        Self {
            config,
            credentials,
            cookie_protector: TokenProtector::new(secrets.cookie_key),
            cookie_key: secrets.cookie_key,
            ticket_protector: TokenProtector::new(secrets.ticket_key),
            server_static_private: secrets.static_keypair.private,
            replay_cache: HashMap::new(),
        }
    }

    fn cleanup_replay_cache(&mut self, now_secs: u64) {
        self.replay_cache
            .retain(|_, entry| entry.expires_at_secs > now_secs);
    }

    fn choose_suite(&self, offered: &[CipherSuite]) -> Result<CipherSuite, AdmissionError> {
        self.config
            .allowed_suites
            .iter()
            .copied()
            .find(|suite| offered.contains(suite))
            .ok_or(AdmissionError::Validation("no common cipher suite"))
    }

    fn choose_carrier(
        &self,
        offered: &[CarrierBinding],
        requested: CarrierBinding,
    ) -> Result<CarrierBinding, AdmissionError> {
        if offered.contains(&requested) && self.config.allowed_carriers.contains(&requested) {
            Ok(requested)
        } else {
            self.config
                .allowed_carriers
                .iter()
                .copied()
                .find(|carrier| offered.contains(carrier))
                .ok_or(AdmissionError::Validation("no common carrier"))
        }
    }

    fn validate_epoch_slot(&self, msg_slot: u64, now_slot: u64) -> Result<(), AdmissionError> {
        let delta = i128::from(msg_slot) - i128::from(now_slot);
        if delta.unsigned_abs() > ACCEPTABLE_SLOT_SKEW as u128 {
            return Err(AdmissionError::Validation(
                "epoch slot outside acceptance window",
            ));
        }
        Ok(())
    }

    fn replay_check(
        &mut self,
        identity: CredentialIdentity,
        client_nonce: ClientNonce,
        epoch_slot: u64,
        now_secs: u64,
    ) -> Result<(), AdmissionError> {
        self.cleanup_replay_cache(now_secs);
        let key = (identity.clone(), client_nonce, epoch_slot);
        if self.replay_cache.contains_key(&key) {
            return Err(AdmissionError::Replay);
        }
        self.replay_cache.insert(
            key,
            ReplayEntry {
                expires_at_secs: now_secs + self.config.defaults.replay_retention_secs,
            },
        );
        Ok(())
    }

    fn open_c0(
        &self,
        packet: &AdmissionPacket,
        carrier: CarrierBinding,
        now_secs: u64,
    ) -> Result<(C0, ResolvedCredential), AdmissionError> {
        let now_slot = epoch_slot(now_secs, self.config.defaults.epoch_slot_secs);
        let aad = admission_associated_data(&self.config.endpoint_id, carrier);
        for resolved in self
            .credentials
            .resolve_candidates(packet.lookup_hint, now_slot)
        {
            let admission_key = derive_admission_key(&resolved.admission_key, resolved.epoch_slot);
            if let Ok(c0) = packet.envelope.open::<C0>(&admission_key, &aad) {
                return Ok((c0, resolved));
            }
        }
        Err(AdmissionError::Validation("unable to decrypt c0"))
    }

    fn open_c2(
        &self,
        packet: &AdmissionPacket,
        carrier: CarrierBinding,
        now_secs: u64,
    ) -> Result<(C2, ResolvedCredential), AdmissionError> {
        let now_slot = epoch_slot(now_secs, self.config.defaults.epoch_slot_secs);
        let aad = admission_associated_data(&self.config.endpoint_id, carrier);
        for resolved in self
            .credentials
            .resolve_candidates(packet.lookup_hint, now_slot)
        {
            let admission_key = derive_admission_key(&resolved.admission_key, resolved.epoch_slot);
            if let Ok(c2) = packet.envelope.open::<C2>(&admission_key, &aad) {
                return Ok((c2, resolved));
            }
        }
        Err(AdmissionError::Validation("unable to decrypt c2"))
    }

    fn build_cookie_context(payload: &CookiePayload) -> Result<Vec<u8>, AdmissionError> {
        Ok(bincode::serialize(payload)?)
    }

    fn issue_ticket(
        &self,
        identity: &CredentialIdentity,
        chosen_carrier: CarrierBinding,
        path_profile: PathProfile,
        resume_secret: [u8; 32],
        now_secs: u64,
    ) -> Result<Option<SealedEnvelope>, AdmissionError> {
        if !self.config.issue_resumption_tickets {
            return Ok(None);
        }
        let ticket = ResumeTicket {
            credential_label: match identity {
                CredentialIdentity::SharedDeployment => "shared-deployment".to_string(),
                CredentialIdentity::User(user_id) => format!("user:{user_id}"),
            },
            server_id: self.config.endpoint_id.to_string(),
            expires_at_secs: now_secs + self.config.ticket_lifetime_secs,
            last_successful_carrier: chosen_carrier,
            last_path_profile: path_profile,
            resume_secret,
        };
        Ok(Some(self.ticket_protector.seal(&ticket)?))
    }

    /// Handles a `C0` packet and returns either `S1` or an invalid-input action.
    pub fn handle_c0<C: CarrierProfile>(
        &mut self,
        source_id: &str,
        carrier: &C,
        packet: &AdmissionPacket,
        received_len: usize,
        now_secs: u64,
    ) -> ServerResponse<AdmissionPacket> {
        let result = (|| -> Result<AdmissionPacket, AdmissionError> {
            if !self.config.allowed_carriers.contains(&carrier.binding()) {
                return Err(AdmissionError::Validation("carrier not allowed"));
            }
            let (c0, resolved) = self.open_c0(packet, carrier.binding(), now_secs)?;
            if c0.version != VERSION {
                return Err(AdmissionError::Validation("unsupported version"));
            }
            self.validate_epoch_slot(
                c0.epoch_slot,
                epoch_slot(now_secs, self.config.defaults.epoch_slot_secs),
            )?;
            self.replay_check(
                resolved.identity.clone(),
                c0.client_nonce,
                c0.epoch_slot,
                now_secs,
            )?;
            let chosen_suite = self.choose_suite(&c0.suite_bitmap)?;
            let chosen_carrier = self.choose_carrier(&c0.carrier_bitmap, carrier.binding())?;
            let chosen_policy = if matches!(self.config.default_policy, PolicyMode::StealthFirst)
                || matches!(c0.policy_flags.allow_speed_first, false)
            {
                self.config.default_policy
            } else {
                c0.policy_flags
                    .allow_speed_first
                    .then_some(PolicyMode::Balanced)
                    .unwrap_or(self.config.default_policy)
            };

            let resume_accepted = c0
                .optional_resume_ticket
                .as_ref()
                .and_then(|ticket| self.ticket_protector.open::<ResumeTicket>(ticket).ok())
                .is_some_and(|ticket| ticket.expires_at_secs > now_secs);

            let cookie_payload = CookiePayload {
                source_id: source_id.to_string(),
                endpoint_id: self.config.endpoint_id.clone(),
                carrier: carrier.binding(),
                client_nonce: c0.client_nonce,
                epoch_slot: c0.epoch_slot,
                expires_at_secs: now_secs + self.config.defaults.cookie_lifetime_secs,
                noise_msg1: c0.noise_msg1.clone(),
                chosen_suite,
                chosen_carrier,
                chosen_policy,
                credential_label: resolved.label(),
                lookup_hint: resolved.lookup_hint,
                path_profile: c0.path_profile,
                resume_accepted,
            };
            let cookie_context = Self::build_cookie_context(&cookie_payload)?;
            let fixed_ephemeral_private =
                derive_stateless_private_key(&self.cookie_key, &cookie_context);
            let server_contribution = derive_server_contribution(&self.cookie_key, &cookie_context);

            let mut noise = NoiseHandshake::new(NoiseHandshakeConfig {
                role: SessionRole::Responder,
                psk: derive_admission_key(&resolved.admission_key, c0.epoch_slot),
                prologue: admission_associated_data(&self.config.endpoint_id, carrier.binding()),
                local_static_private: Some(self.server_static_private),
                remote_static_public: None,
                fixed_ephemeral_private: Some(fixed_ephemeral_private),
            })?;
            noise.read_message(&c0.noise_msg1)?;
            let noise_msg2 = noise.write_message(&bincode::serialize(&NoiseResponderPayload {
                server_contribution,
                resume_accept: resume_accepted,
            })?)?;

            let cookie = self.cookie_protector.seal(&cookie_payload)?;
            let s1 = S1 {
                version: VERSION.to_string(),
                chosen_suite,
                chosen_carrier,
                chosen_policy,
                cookie_expiry: cookie_payload.expires_at_secs,
                anti_amplification_cookie: cookie,
                noise_msg2,
                max_record_size: self.config.max_record_size,
                idle_binding_hint_secs: self.config.idle_binding_hint_secs,
                optional_resume_accept: resume_accepted,
                optional_extensions: Vec::new(),
                padding: random_padding(12),
            };
            let aad = admission_associated_data(&self.config.endpoint_id, carrier.binding());
            let envelope = SealedEnvelope::seal(
                &derive_admission_key(&resolved.admission_key, c0.epoch_slot),
                &aad,
                &s1,
            )?;
            let encoded_len = AdmissionPacket {
                lookup_hint: None,
                envelope: envelope.clone(),
            }
            .encode()
            .len();
            if encoded_len > carrier.anti_amplification_budget(received_len) {
                return Err(AdmissionError::Validation(
                    "s1 exceeds anti-amplification budget",
                ));
            }
            Ok(AdmissionPacket {
                lookup_hint: None,
                envelope,
            })
        })();

        match result {
            Ok(packet) => ServerResponse::Reply(packet),
            Err(AdmissionError::Validation(_)) | Err(AdmissionError::Replay) => {
                ServerResponse::Drop(carrier.invalid_input_behavior())
            }
            Err(_) => ServerResponse::Drop(carrier.invalid_input_behavior()),
        }
    }

    /// Handles a `C2` packet and returns either `S3` plus session material or an
    /// invalid-input action.
    pub fn handle_c2<C: CarrierProfile>(
        &mut self,
        source_id: &str,
        carrier: &C,
        packet: &AdmissionPacket,
        now_secs: u64,
    ) -> ServerResponse<EstablishedServerReply> {
        self.handle_c2_with_extension_builder(source_id, carrier, packet, now_secs, |_| {
            Ok(Vec::new())
        })
    }

    /// Handles a `C2` packet while allowing the runtime to attach encrypted
    /// `S3` extensions such as tunnel address assignments.
    pub fn handle_c2_with_extensions<C: CarrierProfile>(
        &mut self,
        source_id: &str,
        carrier: &C,
        packet: &AdmissionPacket,
        now_secs: u64,
        s3_extensions: Vec<Vec<u8>>,
    ) -> ServerResponse<EstablishedServerReply> {
        self.handle_c2_with_extension_builder(source_id, carrier, packet, now_secs, move |_| {
            Ok(s3_extensions)
        })
    }

    /// Handles a `C2` packet while allowing the caller to compute encrypted
    /// `S3` extensions from the tentative established session.
    pub fn handle_c2_with_extension_builder<C, F>(
        &mut self,
        source_id: &str,
        carrier: &C,
        packet: &AdmissionPacket,
        now_secs: u64,
        extension_builder: F,
    ) -> ServerResponse<EstablishedServerReply>
    where
        C: CarrierProfile,
        F: FnOnce(&EstablishedSession) -> Result<Vec<Vec<u8>>, AdmissionError>,
    {
        let result = (|| -> Result<EstablishedServerReply, AdmissionError> {
            let (c2, resolved) = self.open_c2(packet, carrier.binding(), now_secs)?;
            if c2.version != VERSION {
                return Err(AdmissionError::Validation("unsupported version"));
            }
            if c2.selected_transport_ack != carrier.binding() {
                return Err(AdmissionError::Validation(
                    "unexpected selected transport ack",
                ));
            }

            let cookie_payload: CookiePayload =
                self.cookie_protector.open(&c2.anti_amplification_cookie)?;
            if cookie_payload.source_id != source_id
                || cookie_payload.endpoint_id != self.config.endpoint_id
                || cookie_payload.carrier != carrier.binding()
                || cookie_payload.expires_at_secs <= now_secs
            {
                return Err(AdmissionError::Validation("cookie validation failed"));
            }

            let credential_label = resolved.label();
            if credential_label != cookie_payload.credential_label {
                return Err(AdmissionError::Validation("credential mismatch"));
            }

            let cookie_context = Self::build_cookie_context(&cookie_payload)?;
            let fixed_ephemeral_private =
                derive_stateless_private_key(&self.cookie_key, &cookie_context);
            let server_contribution = derive_server_contribution(&self.cookie_key, &cookie_context);

            let admission_key =
                derive_admission_key(&resolved.admission_key, cookie_payload.epoch_slot);
            let mut noise = NoiseHandshake::new(NoiseHandshakeConfig {
                role: SessionRole::Responder,
                psk: admission_key,
                prologue: admission_associated_data(&self.config.endpoint_id, carrier.binding()),
                local_static_private: Some(self.server_static_private),
                remote_static_public: None,
                fixed_ephemeral_private: Some(fixed_ephemeral_private),
            })?;
            noise.read_message(&cookie_payload.noise_msg1)?;
            let responder_payload = bincode::serialize(&NoiseResponderPayload {
                server_contribution,
                resume_accept: cookie_payload.resume_accepted,
            })?;
            let _replayed_msg2 = noise.write_message(&responder_payload)?;
            let client_payload_bytes = noise.read_message(&c2.noise_msg3)?;
            let client_payload: NoiseInitiatorPayload =
                bincode::deserialize(&client_payload_bytes)?;
            let client_static_public = noise.remote_static_public();
            let handshake_hash = noise.handshake_hash();
            let raw_split = noise.raw_split()?;
            let secrets = derive_session_secrets(
                RawSplitKeys {
                    initiator_to_responder: raw_split.initiator_to_responder,
                    responder_to_initiator: raw_split.responder_to_initiator,
                },
                &client_payload.client_contribution,
                &server_contribution,
                &handshake_hash,
            )?
            .for_role(SessionRole::Responder);

            let session_id = SessionId::random();
            let resume_ticket = self.issue_ticket(
                &resolved.identity,
                cookie_payload.chosen_carrier,
                cookie_payload.path_profile,
                secrets.resume_secret,
                now_secs,
            )?;
            let tentative_session = EstablishedSession {
                session_id,
                role: SessionRole::Responder,
                chosen_carrier: cookie_payload.chosen_carrier,
                chosen_suite: cookie_payload.chosen_suite,
                policy_mode: cookie_payload.chosen_policy,
                credential_identity: resolved.identity.clone(),
                secrets,
                tunnel_mtu: self.config.tunnel_mtu,
                rekey_limits: self.config.rekey_limits,
                resume_ticket: resume_ticket.clone(),
                client_identity: client_payload.user_identity.clone(),
                client_static_public,
                optional_extensions: Vec::new(),
            };
            let s3_extensions = extension_builder(&tentative_session)?;
            let s3 = S3 {
                version: VERSION.to_string(),
                session_id,
                tunnel_mtu: self.config.tunnel_mtu,
                rekey_limits: self.config.rekey_limits,
                ticket_issue_flag: resume_ticket.is_some(),
                optional_resume_ticket: resume_ticket.clone(),
                optional_extensions: s3_extensions.clone(),
            };
            let confirmation = ServerConfirmationPacket {
                envelope: SealedEnvelope::seal(
                    &secrets.send_ctrl,
                    &admission_associated_data(&self.config.endpoint_id, carrier.binding()),
                    &s3,
                )?,
            };
            let session = EstablishedSession {
                session_id,
                role: SessionRole::Responder,
                chosen_carrier: cookie_payload.chosen_carrier,
                chosen_suite: cookie_payload.chosen_suite,
                policy_mode: cookie_payload.chosen_policy,
                credential_identity: resolved.identity,
                secrets,
                tunnel_mtu: self.config.tunnel_mtu,
                rekey_limits: self.config.rekey_limits,
                resume_ticket,
                client_identity: client_payload.user_identity,
                client_static_public,
                optional_extensions: s3_extensions,
            };
            Ok(EstablishedServerReply {
                packet: confirmation,
                session,
            })
        })();

        match result {
            Ok(reply) => ServerResponse::Reply(reply),
            Err(AdmissionError::Validation(_)) | Err(AdmissionError::Replay) => {
                ServerResponse::Drop(carrier.invalid_input_behavior())
            }
            Err(_) => ServerResponse::Drop(carrier.invalid_input_behavior()),
        }
    }
}

fn chosen_credential_identity(credential: &ClientCredential) -> CredentialIdentity {
    match (&credential.auth_profile, &credential.user_id) {
        (AuthProfile::SharedDeployment, _) => CredentialIdentity::SharedDeployment,
        (AuthProfile::PerUser, Some(user_id)) => CredentialIdentity::User(user_id.clone()),
        (AuthProfile::PerUser, None) => CredentialIdentity::User("unknown-user".to_string()),
    }
}

/// Initiates an admission attempt and emits `C0`.
pub fn initiate_c0<C: CarrierProfile>(
    credential: ClientCredential,
    request: ClientSessionRequest,
    carrier: &C,
) -> Result<PreparedC0, AdmissionError> {
    if request.preferred_carrier != carrier.binding() {
        return Err(AdmissionError::Validation(
            "carrier mismatch for initiate_c0",
        ));
    }
    if !request.supported_carriers.contains(&carrier.binding()) {
        return Err(AdmissionError::Validation(
            "preferred carrier not in supported set",
        ));
    }
    let current_epoch_slot = epoch_slot(
        request.now_secs,
        AdmissionDefaults::default().epoch_slot_secs,
    );
    let per_epoch_admission_key =
        derive_admission_key(&credential.admission_key, current_epoch_slot);
    let aad = admission_associated_data(&request.endpoint_id, carrier.binding());
    let mut noise = NoiseHandshake::new(NoiseHandshakeConfig {
        role: SessionRole::Initiator,
        psk: per_epoch_admission_key,
        prologue: aad.clone(),
        local_static_private: credential.client_static_private,
        remote_static_public: None,
        fixed_ephemeral_private: None,
    })?;
    let noise_msg1 = noise.write_message(&[])?;
    let client_nonce = ClientNonce::random();
    let c0 = C0 {
        version: VERSION.to_string(),
        auth_profile: credential.auth_profile,
        suite_bitmap: request.supported_suites.clone(),
        carrier_bitmap: request.supported_carriers.clone(),
        policy_flags: request.policy_flags,
        epoch_slot: current_epoch_slot,
        client_nonce,
        path_profile: request.path_profile,
        noise_msg1,
        optional_resume_ticket: request.resume_ticket.clone(),
        optional_extensions: Vec::new(),
        padding: random_padding(request.c0_padding_len),
    };
    let lookup_hint = credential
        .enable_lookup_hint
        .then(|| derive_lookup_hint(&credential.admission_key, current_epoch_slot));
    let envelope = SealedEnvelope::seal(&per_epoch_admission_key, &aad, &c0)?;
    Ok(PreparedC0 {
        packet: AdmissionPacket {
            lookup_hint,
            envelope,
        },
        state: ClientPendingS1 {
            credential,
            endpoint_id: request.endpoint_id,
            _preferred_carrier: request.preferred_carrier,
            supported_carriers: request.supported_carriers,
            supported_suites: request.supported_suites,
            _policy_mode: request.policy_mode,
            admission_epoch_slot: current_epoch_slot,
            admission_key: per_epoch_admission_key,
            noise,
            _client_nonce: client_nonce,
            client_contribution: rand::random(),
            c2_padding_len: request.c2_padding_len,
        },
    })
}

impl ClientPendingS1 {
    /// Handles `S1`, produces `C2`, and returns state waiting for `S3`.
    pub fn handle_s1<C: CarrierProfile>(
        mut self,
        packet: &AdmissionPacket,
        carrier: &C,
    ) -> Result<PreparedC2, AdmissionError> {
        let aad = admission_associated_data(&self.endpoint_id, carrier.binding());
        let s1: S1 = packet.envelope.open(&self.admission_key, &aad)?;
        if s1.version != VERSION {
            return Err(AdmissionError::Validation("unsupported version"));
        }
        if !self.supported_suites.contains(&s1.chosen_suite) {
            return Err(AdmissionError::Validation("server chose unsupported suite"));
        }
        if !self.supported_carriers.contains(&s1.chosen_carrier) {
            return Err(AdmissionError::Validation(
                "server chose unsupported carrier",
            ));
        }
        let responder_payload_bytes = self.noise.read_message(&s1.noise_msg2)?;
        let responder_payload: NoiseResponderPayload =
            bincode::deserialize(&responder_payload_bytes)?;
        let observed_server_static =
            self.noise
                .remote_static_public()
                .ok_or(AdmissionError::Validation(
                    "server static key not revealed by handshake",
                ))?;
        if observed_server_static != self.credential.server_static_public {
            return Err(AdmissionError::Validation("server static key mismatch"));
        }
        let user_identity = match self.credential.auth_profile {
            AuthProfile::PerUser => self.credential.user_id.clone(),
            AuthProfile::SharedDeployment => None,
        };
        let initiator_payload = NoiseInitiatorPayload {
            client_contribution: self.client_contribution,
            user_identity,
        };
        let noise_msg3 = self
            .noise
            .write_message(&bincode::serialize(&initiator_payload)?)?;
        let handshake_hash = self.noise.handshake_hash();
        let raw_split = self.noise.raw_split()?;
        let secrets = derive_session_secrets(
            raw_split,
            &self.client_contribution,
            &responder_payload.server_contribution,
            &handshake_hash,
        )?
        .for_role(SessionRole::Initiator);
        let c2 = C2 {
            version: VERSION.to_string(),
            anti_amplification_cookie: s1.anti_amplification_cookie,
            noise_msg3,
            selected_transport_ack: s1.chosen_carrier,
            optional_extensions: Vec::new(),
            padding: random_padding(self.c2_padding_len),
        };
        let c2_envelope = SealedEnvelope::seal(&self.admission_key, &aad, &c2)?;
        let packet = AdmissionPacket {
            lookup_hint: self.credential.enable_lookup_hint.then(|| {
                derive_lookup_hint(&self.credential.admission_key, self.admission_epoch_slot)
            }),
            envelope: c2_envelope,
        };
        Ok(PreparedC2 {
            packet,
            state: ClientPendingS3 {
                endpoint_id: self.endpoint_id,
                chosen_carrier: s1.chosen_carrier,
                chosen_suite: s1.chosen_suite,
                _policy_mode: s1.chosen_policy,
                credential_identity: chosen_credential_identity(&self.credential),
                secrets,
            },
        })
    }
}

impl ClientPendingS3 {
    /// Returns the receive-direction control key that may be used to wrap the
    /// outer carrier record for the encrypted `S3` confirmation.
    #[must_use]
    pub const fn confirmation_recv_ctrl_key(&self) -> &[u8; 32] {
        &self.secrets.recv_ctrl
    }

    /// Handles `S3` and finalizes the session.
    pub fn handle_s3<C: CarrierProfile>(
        self,
        packet: &ServerConfirmationPacket,
        carrier: &C,
    ) -> Result<EstablishedSession, AdmissionError> {
        let aad = admission_associated_data(&self.endpoint_id, carrier.binding());
        let s3: S3 = packet.envelope.open(&self.secrets.recv_ctrl, &aad)?;
        if s3.version != VERSION {
            return Err(AdmissionError::Validation("unsupported version"));
        }
        Ok(EstablishedSession {
            session_id: s3.session_id,
            role: SessionRole::Initiator,
            chosen_carrier: self.chosen_carrier,
            chosen_suite: self.chosen_suite,
            policy_mode: self._policy_mode,
            credential_identity: self.credential_identity,
            secrets: self.secrets,
            tunnel_mtu: s3.tunnel_mtu,
            rekey_limits: s3.rekey_limits,
            resume_ticket: s3.optional_resume_ticket,
            client_identity: None,
            client_static_public: None,
            optional_extensions: s3.optional_extensions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apt_carriers::D1Carrier;

    fn test_server_setup() -> (AdmissionServer, ClientCredential, D1Carrier) {
        let static_keypair = generate_static_keypair().unwrap();
        let admission_key = [7_u8; 32];
        let endpoint = EndpointId::new("edge-test");
        let mut store = CredentialStore::new();
        store.set_shared_deployment_key(admission_key);
        let server = AdmissionServer::new(
            AdmissionConfig::conservative(endpoint.clone()),
            store,
            AdmissionServerSecrets {
                static_keypair: static_keypair.clone(),
                cookie_key: [9_u8; 32],
                ticket_key: [10_u8; 32],
            },
        );
        let client_credential = ClientCredential {
            auth_profile: AuthProfile::SharedDeployment,
            user_id: None,
            client_static_private: None,
            admission_key,
            server_static_public: static_keypair.public,
            enable_lookup_hint: false,
        };
        (server, client_credential, D1Carrier::conservative())
    }

    #[test]
    fn successful_one_point_five_rtt_establishment() {
        let (mut server, credential, carrier) = test_server_setup();
        let endpoint = EndpointId::new("edge-test");
        let now_secs = 1_700_000_000;
        let request = ClientSessionRequest::conservative(endpoint, now_secs);
        let prepared_c0 = initiate_c0(credential, request, &carrier).unwrap();

        let s1 = match server.handle_c0(
            "127.0.0.1:1111",
            &carrier,
            &prepared_c0.packet,
            512,
            now_secs,
        ) {
            ServerResponse::Reply(reply) => reply,
            ServerResponse::Drop(_) => panic!("expected reply"),
        };

        let prepared_c2 = prepared_c0.state.handle_s1(&s1, &carrier).unwrap();
        let established = match server.handle_c2(
            "127.0.0.1:1111",
            &carrier,
            &prepared_c2.packet,
            now_secs + 1,
        ) {
            ServerResponse::Reply(reply) => reply,
            ServerResponse::Drop(_) => panic!("expected reply"),
        };

        let client_session = prepared_c2
            .state
            .handle_s3(&established.packet, &carrier)
            .unwrap();
        assert_eq!(client_session.session_id, established.session.session_id);
        assert_eq!(client_session.chosen_carrier, CarrierBinding::D1DatagramUdp);
    }

    #[test]
    fn replayed_c0_is_silently_dropped() {
        let (mut server, credential, carrier) = test_server_setup();
        let endpoint = EndpointId::new("edge-test");
        let now_secs = 1_700_000_000;
        let request = ClientSessionRequest::conservative(endpoint, now_secs);
        let prepared_c0 = initiate_c0(credential, request, &carrier).unwrap();

        let _ = server.handle_c0(
            "127.0.0.1:1111",
            &carrier,
            &prepared_c0.packet,
            512,
            now_secs,
        );
        let replay = server.handle_c0(
            "127.0.0.1:1111",
            &carrier,
            &prepared_c0.packet,
            512,
            now_secs,
        );
        assert!(matches!(
            replay,
            ServerResponse::Drop(InvalidInputBehavior::Silence)
        ));
    }

    #[test]
    fn expired_cookie_causes_drop() {
        let (mut server, credential, carrier) = test_server_setup();
        let endpoint = EndpointId::new("edge-test");
        let now_secs = 1_700_000_000;
        let request = ClientSessionRequest::conservative(endpoint, now_secs);
        let prepared_c0 = initiate_c0(credential, request, &carrier).unwrap();

        let s1 = match server.handle_c0(
            "127.0.0.1:1111",
            &carrier,
            &prepared_c0.packet,
            512,
            now_secs,
        ) {
            ServerResponse::Reply(reply) => reply,
            ServerResponse::Drop(_) => panic!("expected reply"),
        };
        let prepared_c2 = prepared_c0.state.handle_s1(&s1, &carrier).unwrap();
        let response = server.handle_c2(
            "127.0.0.1:1111",
            &carrier,
            &prepared_c2.packet,
            now_secs + 60,
        );
        assert!(matches!(
            response,
            ServerResponse::Drop(InvalidInputBehavior::Silence)
        ));
    }

    #[test]
    fn invalid_epoch_slot_causes_drop() {
        let (mut server, credential, carrier) = test_server_setup();
        let endpoint = EndpointId::new("edge-test");
        let now_secs = 1_700_000_000;
        let request = ClientSessionRequest::conservative(endpoint, now_secs - 10_000);
        let prepared_c0 = initiate_c0(credential, request, &carrier).unwrap();
        let response = server.handle_c0(
            "127.0.0.1:1111",
            &carrier,
            &prepared_c0.packet,
            512,
            now_secs,
        );
        assert!(matches!(
            response,
            ServerResponse::Drop(InvalidInputBehavior::Silence)
        ));
    }

    #[test]
    fn malformed_near_miss_does_not_yield_protocol_reply() {
        let (mut server, credential, carrier) = test_server_setup();
        let endpoint = EndpointId::new("edge-test");
        let now_secs = 1_700_000_000;
        let request = ClientSessionRequest::conservative(endpoint, now_secs);
        let mut prepared_c0 = initiate_c0(credential, request, &carrier).unwrap();
        prepared_c0.packet.envelope.ciphertext[0] ^= 0x44;
        let response = server.handle_c0(
            "127.0.0.1:1111",
            &carrier,
            &prepared_c0.packet,
            512,
            now_secs,
        );
        assert!(matches!(
            response,
            ServerResponse::Drop(InvalidInputBehavior::Silence)
        ));
    }
}
