use super::*;
use crate::packet::{NoiseInitiatorPayload, NoiseResponderPayload};

fn handshake_prologue(
    endpoint_id: &EndpointId,
    carrier: CarrierBinding,
    public_session_context: Option<&PublicSessionUpgradeContext>,
) -> Result<Vec<u8>, AdmissionError> {
    match public_session_context {
        Some(context) => public_session_associated_data(endpoint_id, context),
        None => Ok(admission_associated_data(endpoint_id, carrier)),
    }
}

fn envelope_aad(
    endpoint_id: &EndpointId,
    carrier: CarrierBinding,
    public_session_context: Option<&PublicSessionUpgradeContext>,
    phase: UpgradeMessagePhase,
    epoch_slot: u64,
) -> Result<Vec<u8>, AdmissionError> {
    match public_session_context {
        Some(context) => slot_bound_associated_data(endpoint_id, context, phase, epoch_slot),
        None => Ok(admission_associated_data(endpoint_id, carrier)),
    }
}

fn phase_slot_binding(
    endpoint_id: &EndpointId,
    carrier: CarrierBinding,
    public_session_context: Option<&PublicSessionUpgradeContext>,
    phase: UpgradeMessagePhase,
    legacy_slot_id: &str,
    epoch_slot: u64,
) -> UpgradeSlotBinding {
    match public_session_context {
        Some(context) => match phase {
            UpgradeMessagePhase::Request => context.request_binding(epoch_slot),
            UpgradeMessagePhase::Response => context.response_binding(epoch_slot),
        },
        None => {
            legacy_upgrade_slot_binding(endpoint_id, carrier, phase, legacy_slot_id, epoch_slot)
        }
    }
}

fn initiate_ug1_impl<C: CarrierProfile>(
    credential: ClientCredential,
    request: ClientSessionRequest,
    carrier: &C,
    public_session_context: Option<PublicSessionUpgradeContext>,
) -> Result<PreparedUg1Envelope, AdmissionError> {
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
    let prologue = handshake_prologue(
        &request.endpoint_id,
        carrier.binding(),
        public_session_context.as_ref(),
    )?;
    let mut noise = NoiseHandshake::new(NoiseHandshakeConfig {
        role: SessionRole::Initiator,
        psk: per_epoch_admission_key,
        prologue,
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
        slot_binding: phase_slot_binding(
            &request.endpoint_id,
            carrier.binding(),
            public_session_context.as_ref(),
            UpgradeMessagePhase::Request,
            "legacy-ug1",
            current_epoch_slot,
        ),
        padding: random_padding(request.c0_padding_len),
    };
    let lookup_hint = credential
        .enable_lookup_hint
        .then(|| derive_lookup_hint(&credential.admission_key, current_epoch_slot));
    let aad = envelope_aad(
        &request.endpoint_id,
        carrier.binding(),
        public_session_context.as_ref(),
        UpgradeMessagePhase::Request,
        current_epoch_slot,
    )?;
    let envelope = SealedEnvelope::seal(&per_epoch_admission_key, &aad, &ug1)?;
    Ok(PreparedUg1Envelope {
        lookup_hint,
        envelope,
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
            public_session_context,
        },
    })
}

/// Initiates an admission attempt and emits the first hidden-upgrade request.
pub fn initiate_ug1<C: CarrierProfile>(
    credential: ClientCredential,
    request: ClientSessionRequest,
    carrier: &C,
) -> Result<PreparedUg1Envelope, AdmissionError> {
    initiate_ug1_impl(credential, request, carrier, None)
}

/// Initiates a public-session hidden-upgrade request bound to an explicit
/// surface family/profile/slot context.
pub fn initiate_ug1_with_context<C: CarrierProfile>(
    credential: ClientCredential,
    request: ClientSessionRequest,
    carrier: &C,
    public_session_context: PublicSessionUpgradeContext,
) -> Result<PreparedUg1Envelope, AdmissionError> {
    initiate_ug1_impl(credential, request, carrier, Some(public_session_context))
}

impl ClientPendingS1 {
    /// Handles `UG2` directly, produces the encrypted `UG3` envelope, and
    /// returns state waiting for the final server seal.
    pub fn handle_ug2<C: CarrierProfile>(
        self,
        envelope: &SealedEnvelope,
        carrier: &C,
    ) -> Result<PreparedUg3Envelope, AdmissionError> {
        let aad = envelope_aad(
            &self.endpoint_id,
            carrier.binding(),
            self.public_session_context.as_ref(),
            UpgradeMessagePhase::Response,
            self.admission_epoch_slot,
        )?;
        let ug2: Ug2 = envelope.open(&self.admission_key, &aad)?;
        self.finish_ug2(ug2, carrier)
    }

    fn finish_ug2<C: CarrierProfile>(
        mut self,
        ug2: Ug2,
        carrier: &C,
    ) -> Result<PreparedUg3Envelope, AdmissionError> {
        if !self.supported_suites.contains(&ug2.chosen_suite) {
            return Err(AdmissionError::Validation("server chose unsupported suite"));
        }
        if !self.supported_carriers.contains(&ug2.chosen_family) {
            return Err(AdmissionError::Validation(
                "server chose unsupported carrier",
            ));
        }
        let expected_response_binding = phase_slot_binding(
            &self.endpoint_id,
            carrier.binding(),
            self.public_session_context.as_ref(),
            UpgradeMessagePhase::Response,
            "legacy-ug2",
            self.admission_epoch_slot,
        );
        if ug2.slot_binding != expected_response_binding {
            return Err(AdmissionError::Validation(
                "unexpected upgrade-slot binding",
            ));
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
            noise_msg3,
            slot_binding: phase_slot_binding(
                &self.endpoint_id,
                carrier.binding(),
                self.public_session_context.as_ref(),
                UpgradeMessagePhase::Request,
                "legacy-ug3",
                self.admission_epoch_slot,
            ),
            padding: random_padding(self.c2_padding_len),
        };
        let request_aad = envelope_aad(
            &self.endpoint_id,
            carrier.binding(),
            self.public_session_context.as_ref(),
            UpgradeMessagePhase::Request,
            self.admission_epoch_slot,
        )?;
        let ug3_envelope = SealedEnvelope::seal(&self.admission_key, &request_aad, &ug3)?;
        let lookup_hint = self
            .credential
            .enable_lookup_hint
            .then(|| derive_lookup_hint(&self.credential.admission_key, self.admission_epoch_slot));
        Ok(PreparedUg3Envelope {
            lookup_hint,
            envelope: ug3_envelope,
            state: ClientPendingS3 {
                endpoint_id: self.endpoint_id,
                chosen_carrier: ug2.chosen_family,
                chosen_suite: ug2.chosen_suite,
                _mode: ug2.chosen_mode,
                credential_identity: chosen_credential_identity(&self.credential),
                secrets,
                admission_epoch_slot: self.admission_epoch_slot,
                public_session_context: self.public_session_context,
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

    /// Handles `UG4` directly and finalizes the session without any public-wire
    /// server-confirmation packet wrapper.
    pub fn handle_ug4<C: CarrierProfile>(
        self,
        envelope: &SealedEnvelope,
        carrier: &C,
    ) -> Result<EstablishedSession, AdmissionError> {
        let aad = envelope_aad(
            &self.endpoint_id,
            carrier.binding(),
            self.public_session_context.as_ref(),
            UpgradeMessagePhase::Response,
            self.admission_epoch_slot,
        )?;
        let ug4: Ug4 = envelope.open(&self.secrets.recv_ctrl, &aad)?;
        let expected_response_binding = phase_slot_binding(
            &self.endpoint_id,
            carrier.binding(),
            self.public_session_context.as_ref(),
            UpgradeMessagePhase::Response,
            "legacy-ug4",
            self.admission_epoch_slot,
        );
        if ug4.slot_binding != expected_response_binding {
            return Err(AdmissionError::Validation(
                "unexpected upgrade-slot binding",
            ));
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
