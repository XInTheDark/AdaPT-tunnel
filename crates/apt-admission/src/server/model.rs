use super::*;
use crate::packet::CookiePayload;

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

    pub(super) fn resolve_candidates(
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
pub(super) struct ResolvedCredential {
    pub identity: CredentialIdentity,
    pub admission_key: [u8; 32],
    pub epoch_slot: u64,
    pub lookup_hint: Option<[u8; 8]>,
}

impl ResolvedCredential {
    pub(super) fn label(&self) -> String {
        match &self.identity {
            CredentialIdentity::SharedDeployment => "shared-deployment".to_string(),
            CredentialIdentity::User(user) => format!("user:{user}"),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct ReplayEntry {
    pub expires_at_secs: u64,
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
                CarrierBinding::D2EncryptedDatagram,
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
    pub(crate) config: AdmissionConfig,
    pub(super) credentials: CredentialStore,
    pub(super) cookie_protector: TokenProtector,
    pub(super) cookie_key: [u8; 32],
    pub(super) ticket_protector: TokenProtector,
    pub(super) server_static_private: [u8; 32],
    pub(super) replay_cache: HashMap<(CredentialIdentity, ClientNonce, u64), ReplayEntry>,
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

    pub(super) fn cleanup_replay_cache(&mut self, now_secs: u64) {
        self.replay_cache
            .retain(|_, entry| entry.expires_at_secs > now_secs);
    }

    pub(super) fn choose_suite(
        &self,
        offered: &[CipherSuite],
    ) -> Result<CipherSuite, AdmissionError> {
        self.config
            .allowed_suites
            .iter()
            .copied()
            .find(|suite| offered.contains(suite))
            .ok_or(AdmissionError::Validation("no common cipher suite"))
    }

    pub(super) fn choose_carrier(
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

    pub(crate) fn choose_policy_mode(
        &self,
        requested: PolicyMode,
        allow_speed_first: bool,
    ) -> PolicyMode {
        fn rank(mode: PolicyMode) -> u8 {
            match mode {
                PolicyMode::StealthFirst => 0,
                PolicyMode::Balanced => 1,
                PolicyMode::SpeedFirst => 2,
            }
        }

        fn from_rank(rank: u8) -> PolicyMode {
            match rank {
                0 => PolicyMode::StealthFirst,
                1 => PolicyMode::Balanced,
                _ => PolicyMode::SpeedFirst,
            }
        }

        let server_rank = rank(self.config.default_policy);
        let requested_rank = rank(requested);
        let client_rank = if allow_speed_first {
            requested_rank
        } else {
            requested_rank.min(rank(PolicyMode::Balanced))
        };

        from_rank(server_rank.min(client_rank))
    }

    pub(super) fn validate_epoch_slot(
        &self,
        msg_slot: u64,
        now_slot: u64,
    ) -> Result<(), AdmissionError> {
        let delta = i128::from(msg_slot) - i128::from(now_slot);
        if delta.unsigned_abs() > ACCEPTABLE_SLOT_SKEW as u128 {
            return Err(AdmissionError::Validation(
                "epoch slot outside acceptance window",
            ));
        }
        Ok(())
    }

    pub(super) fn replay_check(
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

    pub(super) fn open_c0(
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

    pub(super) fn open_c2(
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

    pub(super) fn build_cookie_context(payload: &CookiePayload) -> Result<Vec<u8>, AdmissionError> {
        Ok(bincode::serialize(payload)?)
    }

    pub(super) fn issue_ticket(
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
}
