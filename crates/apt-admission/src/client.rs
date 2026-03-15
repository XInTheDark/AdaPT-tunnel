use super::*;
use crate::packet::{NoiseInitiatorPayload, NoiseResponderPayload};

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

/// Result of initiating the first hidden-upgrade request.
#[derive(Debug)]
pub struct PreparedC0 {
    /// Encrypted first-stage packet wrapper.
    pub packet: AdmissionPacket,
    /// State required to process the server's first hidden-upgrade reply.
    pub state: ClientPendingS1,
}

/// Client state waiting for the server's first hidden-upgrade reply.
#[derive(Debug)]
pub struct ClientPendingS1 {
    credential: ClientCredential,
    endpoint_id: EndpointId,
    _preferred_carrier: CarrierBinding,
    supported_carriers: Vec<CarrierBinding>,
    supported_suites: Vec<CipherSuite>,
    _mode: Mode,
    admission_epoch_slot: u64,
    admission_key: [u8; 32],
    noise: NoiseHandshake,
    _client_nonce: ClientNonce,
    client_contribution: [u8; 32],
    c2_padding_len: usize,
}

/// Result of processing the first server reply and emitting the client confirmation.
#[derive(Debug)]
pub struct PreparedC2 {
    /// Encrypted client confirmation packet wrapper.
    pub packet: AdmissionPacket,
    /// State required to process the final server seal.
    pub state: ClientPendingS3,
}

/// Client state waiting for the final server seal.
#[derive(Debug)]
pub struct ClientPendingS3 {
    endpoint_id: EndpointId,
    chosen_carrier: CarrierBinding,
    chosen_suite: CipherSuite,
    _mode: Mode,
    credential_identity: CredentialIdentity,
    secrets: SessionSecretsForRole,
}

fn chosen_credential_identity(credential: &ClientCredential) -> CredentialIdentity {
    match (&credential.auth_profile, &credential.user_id) {
        (AuthProfile::SharedDeployment, _) => CredentialIdentity::SharedDeployment,
        (AuthProfile::PerUser, Some(user_id)) => CredentialIdentity::User(user_id.clone()),
        (AuthProfile::PerUser, None) => CredentialIdentity::User("unknown-user".to_string()),
    }
}

/// Initiates an admission attempt and emits the first hidden-upgrade request.
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
    let ug1 = Ug1 {
        endpoint_id: request.endpoint_id.clone(),
        auth_profile: credential.auth_profile,
        credential_identity: chosen_credential_identity(&credential),
        supported_suites: request.supported_suites.clone(),
        supported_families: request.supported_carriers.clone(),
        requested_mode: request.mode,
        public_route_hint: request.public_route_hint,
        path_profile: request.path_profile,
        client_nonce,
        noise_msg1,
        optional_masked_fallback_ticket: request.masked_fallback_ticket.clone(),
        slot_binding: legacy_upgrade_slot_binding(
            &request.endpoint_id,
            carrier.binding(),
            UpgradeMessagePhase::Request,
            "legacy-ug1",
            current_epoch_slot,
        ),
        padding: random_padding(request.c0_padding_len),
    };
    let lookup_hint = credential
        .enable_lookup_hint
        .then(|| derive_lookup_hint(&credential.admission_key, current_epoch_slot));
    let envelope = SealedEnvelope::seal(&per_epoch_admission_key, &aad, &ug1)?;
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
            _mode: request.mode,
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
    /// Handles the first server reply, produces the client confirmation, and
    /// returns state waiting for the final server seal.
    pub fn handle_s1<C: CarrierProfile>(
        mut self,
        packet: &AdmissionPacket,
        carrier: &C,
    ) -> Result<PreparedC2, AdmissionError> {
        let aad = admission_associated_data(&self.endpoint_id, carrier.binding());
        let ug2: Ug2 = packet.envelope.open(&self.admission_key, &aad)?;
        if !self.supported_suites.contains(&ug2.chosen_suite) {
            return Err(AdmissionError::Validation("server chose unsupported suite"));
        }
        if !self.supported_carriers.contains(&ug2.chosen_family) {
            return Err(AdmissionError::Validation(
                "server chose unsupported carrier",
            ));
        }
        if ug2.slot_binding.phase != UpgradeMessagePhase::Response {
            return Err(AdmissionError::Validation("unexpected upgrade-slot phase"));
        }
        let responder_payload_bytes = self.noise.read_message(&ug2.noise_msg2)?;
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
        let ug3 = Ug3 {
            selected_family_ack: ug2.chosen_family,
            anti_amplification_cookie: ug2.anti_amplification_cookie.clone(),
            noise_msg3: noise_msg3.clone(),
            slot_binding: legacy_upgrade_slot_binding(
                &self.endpoint_id,
                carrier.binding(),
                UpgradeMessagePhase::Request,
                "legacy-ug3",
                self.admission_epoch_slot,
            ),
            padding: random_padding(self.c2_padding_len),
        };
        let c2_envelope = SealedEnvelope::seal(&self.admission_key, &aad, &ug3)?;
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
                chosen_carrier: ug2.chosen_family,
                chosen_suite: ug2.chosen_suite,
                _mode: ug2.chosen_mode,
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

    /// Handles the final server seal and finalizes the session.
    pub fn handle_s3<C: CarrierProfile>(
        self,
        packet: &ServerConfirmationPacket,
        carrier: &C,
    ) -> Result<EstablishedSession, AdmissionError> {
        let aad = admission_associated_data(&self.endpoint_id, carrier.binding());
        let ug4: Ug4 = packet.envelope.open(&self.secrets.recv_ctrl, &aad)?;
        if ug4.slot_binding.phase != UpgradeMessagePhase::Response {
            return Err(AdmissionError::Validation("unexpected upgrade-slot phase"));
        }
        Ok(EstablishedSession {
            session_id: ug4.session_id,
            role: SessionRole::Initiator,
            chosen_carrier: self.chosen_carrier,
            chosen_suite: self.chosen_suite,
            mode: self._mode,
            credential_identity: self.credential_identity,
            secrets: self.secrets,
            tunnel_mtu: ug4.tunnel_mtu,
            rekey_limits: ug4.rekey_limits,
            masked_fallback_ticket: ug4.optional_masked_fallback_ticket,
            client_identity: None,
            client_static_public: None,
            optional_extensions: ug4.optional_extensions,
        })
    }
}
