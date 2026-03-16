use super::helpers::{envelope_aad, handshake_prologue, validate_auth_profile};
use super::*;

impl AdmissionServer {
    /// Handles `UG1` directly and returns an encrypted `UG2` envelope or an
    /// invalid-input action without any public-wire packet wrapper.
    pub fn handle_ug1<C: CarrierProfile>(
        &mut self,
        source_id: &str,
        carrier: &C,
        lookup_hint: Option<[u8; 8]>,
        envelope: &SealedEnvelope,
        received_len: usize,
        now_secs: u64,
    ) -> ServerResponse<SealedEnvelope> {
        self.handle_ug1_impl(
            source_id,
            carrier,
            lookup_hint,
            envelope,
            received_len,
            now_secs,
            None,
        )
    }

    /// Handles `UG1` while binding the hidden upgrade to a concrete
    /// public-session surface context.
    pub fn handle_ug1_with_context<C: CarrierProfile>(
        &mut self,
        source_id: &str,
        carrier: &C,
        public_session_context: &PublicSessionUpgradeContext,
        lookup_hint: Option<[u8; 8]>,
        envelope: &SealedEnvelope,
        received_len: usize,
        now_secs: u64,
    ) -> ServerResponse<SealedEnvelope> {
        self.handle_ug1_impl(
            source_id,
            carrier,
            lookup_hint,
            envelope,
            received_len,
            now_secs,
            Some(public_session_context),
        )
    }

    fn handle_ug1_impl<C: CarrierProfile>(
        &mut self,
        source_id: &str,
        carrier: &C,
        lookup_hint: Option<[u8; 8]>,
        envelope: &SealedEnvelope,
        received_len: usize,
        now_secs: u64,
        public_session_context: Option<&PublicSessionUpgradeContext>,
    ) -> ServerResponse<SealedEnvelope> {
        let result = (|| -> Result<SealedEnvelope, AdmissionError> {
            let active_binding = carrier.binding();
            if !self.config.allowed_carriers.contains(&active_binding) {
                return Err(AdmissionError::Validation("carrier not allowed"));
            }
            if public_session_context.is_some_and(|context| context.carrier != active_binding) {
                return Err(AdmissionError::Validation(
                    "public-session carrier mismatch",
                ));
            }
            let (ug1, resolved) = match public_session_context {
                Some(context) => {
                    self.open_ug1_envelope_with_context(lookup_hint, envelope, context, now_secs)?
                }
                None => self.open_ug1_envelope(lookup_hint, envelope, active_binding, now_secs)?,
            };
            if ug1.endpoint_id != self.config.endpoint_id {
                return Err(AdmissionError::Validation("endpoint mismatch"));
            }
            if ug1.slot_binding.phase != UpgradeMessagePhase::Request {
                return Err(AdmissionError::Validation("unexpected upgrade-slot phase"));
            }
            validate_auth_profile(ug1.auth_profile, &resolved.identity)?;
            self.validate_epoch_slot(
                ug1.slot_binding.epoch_slot,
                epoch_slot(now_secs, self.config.defaults.epoch_slot_secs),
            )?;
            self.replay_check(
                resolved.identity.clone(),
                ug1.client_nonce,
                ug1.slot_binding.epoch_slot,
                now_secs,
            )?;
            let chosen_suite = self.choose_suite(&ug1.supported_suites)?;
            let chosen_carrier = self.choose_carrier(&ug1.supported_families, active_binding)?;
            let chosen_mode = self.choose_mode(ug1.requested_mode);

            let masked_fallback_ticket_accepted = ug1
                .optional_masked_fallback_ticket
                .as_ref()
                .and_then(|ticket| {
                    self.open_masked_fallback_ticket(
                        ticket,
                        active_binding,
                        &ug1.public_route_hint,
                        ug1.path_profile,
                        now_secs,
                    )
                    .ok()
                })
                .unwrap_or(false);

            let cookie_payload = CookiePayload {
                source_id: source_id.to_string(),
                endpoint_id: self.config.endpoint_id.clone(),
                carrier: active_binding,
                slot_binding: ug1.slot_binding.clone(),
                client_nonce: ug1.client_nonce,
                epoch_slot: ug1.slot_binding.epoch_slot,
                expires_at_secs: now_secs + self.config.defaults.cookie_lifetime_secs,
                noise_msg1: ug1.noise_msg1.clone(),
                chosen_suite,
                chosen_carrier,
                chosen_mode,
                credential_label: resolved.label(),
                lookup_hint: resolved.lookup_hint,
                public_route_hint: ug1.public_route_hint,
                path_profile: ug1.path_profile,
                masked_fallback_ticket_accepted,
            };
            let cookie_context = Self::build_cookie_context(&cookie_payload)?;
            let fixed_ephemeral_private =
                derive_stateless_private_key(&self.cookie_key, &cookie_context);
            let server_contribution = derive_server_contribution(&self.cookie_key, &cookie_context);

            let mut noise = NoiseHandshake::new(NoiseHandshakeConfig {
                role: SessionRole::Responder,
                psk: derive_admission_key(&resolved.admission_key, ug1.slot_binding.epoch_slot),
                prologue: handshake_prologue(
                    &self.config.endpoint_id,
                    active_binding,
                    public_session_context,
                )?,
                local_static_private: Some(self.server_static_private),
                remote_static_public: None,
                fixed_ephemeral_private: Some(fixed_ephemeral_private),
            })?;
            noise.read_message(&ug1.noise_msg1)?;
            let noise_msg2 = noise.write_message(&bincode::serialize(&NoiseResponderPayload {
                server_contribution,
                masked_fallback_ticket_accept: masked_fallback_ticket_accepted,
            })?)?;

            let cookie = self.cookie_protector.seal(&cookie_payload)?;
            let ug2 = Ug2 {
                chosen_suite,
                chosen_family: chosen_carrier,
                chosen_mode,
                anti_amplification_cookie: cookie,
                cookie_expiry: cookie_payload.expires_at_secs,
                noise_msg2,
                optional_masked_fallback_accept: masked_fallback_ticket_accepted,
                slot_binding: match public_session_context {
                    Some(context) => context.response_binding(ug1.slot_binding.epoch_slot),
                    None => legacy_upgrade_slot_binding(
                        &self.config.endpoint_id,
                        active_binding,
                        UpgradeMessagePhase::Response,
                        "legacy-ug2",
                        ug1.slot_binding.epoch_slot,
                    ),
                },
                padding: random_padding(12),
            };
            let aad = envelope_aad(
                &self.config.endpoint_id,
                active_binding,
                public_session_context,
                UpgradeMessagePhase::Response,
                ug1.slot_binding.epoch_slot,
            )?;
            let response_envelope = SealedEnvelope::seal(
                &derive_admission_key(&resolved.admission_key, ug1.slot_binding.epoch_slot),
                &aad,
                &ug2,
            )?;
            let encoded_len = response_envelope.nonce.len() + response_envelope.ciphertext.len();
            if encoded_len > carrier.anti_amplification_budget(received_len) {
                return Err(AdmissionError::Validation(
                    "s1 exceeds anti-amplification budget",
                ));
            }
            Ok(response_envelope)
        })();

        match result {
            Ok(reply_envelope) => ServerResponse::Reply(reply_envelope),
            Err(AdmissionError::Validation(_)) | Err(AdmissionError::Replay) => {
                ServerResponse::Drop(carrier.invalid_input_behavior())
            }
            Err(_) => ServerResponse::Drop(carrier.invalid_input_behavior()),
        }
    }

    fn open_ug1_envelope_with_context(
        &self,
        lookup_hint: Option<[u8; 8]>,
        envelope: &SealedEnvelope,
        public_session_context: &PublicSessionUpgradeContext,
        now_secs: u64,
    ) -> Result<(Ug1, ResolvedCredential), AdmissionError> {
        let now_slot = epoch_slot(now_secs, self.config.defaults.epoch_slot_secs);
        for resolved in self.credentials.resolve_candidates(lookup_hint, now_slot) {
            let admission_key = derive_admission_key(&resolved.admission_key, resolved.epoch_slot);
            let aad = envelope_aad(
                &self.config.endpoint_id,
                public_session_context.carrier,
                Some(public_session_context),
                UpgradeMessagePhase::Request,
                resolved.epoch_slot,
            )?;
            if let Ok(ug1) = envelope.open::<Ug1>(&admission_key, &aad) {
                if ug1.slot_binding != public_session_context.request_binding(resolved.epoch_slot) {
                    return Err(AdmissionError::Validation(
                        "unexpected upgrade-slot binding",
                    ));
                }
                return Ok((ug1, resolved));
            }
        }
        Err(AdmissionError::Validation("unable to decrypt c0"))
    }
}
