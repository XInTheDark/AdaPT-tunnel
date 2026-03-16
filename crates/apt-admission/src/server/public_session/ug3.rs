use super::helpers::{envelope_aad, handshake_prologue, validate_client_identity};
use super::*;

impl AdmissionServer {
    /// Handles `UG3` directly and returns either `UG4` plus session material or
    /// an invalid-input action without any public-wire packet wrapper.
    pub fn handle_ug3<C: CarrierProfile>(
        &mut self,
        source_id: &str,
        carrier: &C,
        lookup_hint: Option<[u8; 8]>,
        envelope: &SealedEnvelope,
        now_secs: u64,
    ) -> ServerResponse<EstablishedEnvelopeReply> {
        self.handle_ug3_with_extension_builder(
            source_id,
            carrier,
            lookup_hint,
            envelope,
            now_secs,
            |_| Ok(Vec::new()),
        )
    }

    /// Handles `UG3` while binding the hidden upgrade to a concrete
    /// public-session surface context.
    pub fn handle_ug3_with_context<C: CarrierProfile>(
        &mut self,
        source_id: &str,
        carrier: &C,
        public_session_context: &PublicSessionUpgradeContext,
        lookup_hint: Option<[u8; 8]>,
        envelope: &SealedEnvelope,
        now_secs: u64,
    ) -> ServerResponse<EstablishedEnvelopeReply> {
        self.handle_ug3_with_context_and_extension_builder(
            source_id,
            carrier,
            public_session_context,
            lookup_hint,
            envelope,
            now_secs,
            |_| Ok(Vec::new()),
        )
    }

    /// Handles `UG3` while binding the hidden upgrade to a concrete
    /// public-session surface context and allowing encrypted `UG4` extensions.
    pub fn handle_ug3_with_context_and_extension_builder<C, F>(
        &mut self,
        source_id: &str,
        carrier: &C,
        public_session_context: &PublicSessionUpgradeContext,
        lookup_hint: Option<[u8; 8]>,
        envelope: &SealedEnvelope,
        now_secs: u64,
        extension_builder: F,
    ) -> ServerResponse<EstablishedEnvelopeReply>
    where
        C: CarrierProfile,
        F: FnOnce(&EstablishedSession) -> Result<Vec<Vec<u8>>, AdmissionError>,
    {
        self.handle_ug3_impl(
            source_id,
            carrier,
            lookup_hint,
            envelope,
            now_secs,
            Some(public_session_context),
            extension_builder,
        )
    }

    /// Handles `UG3` while allowing the caller to compute encrypted `UG4`
    /// extensions from the tentative established session.
    pub fn handle_ug3_with_extension_builder<C, F>(
        &mut self,
        source_id: &str,
        carrier: &C,
        lookup_hint: Option<[u8; 8]>,
        envelope: &SealedEnvelope,
        now_secs: u64,
        extension_builder: F,
    ) -> ServerResponse<EstablishedEnvelopeReply>
    where
        C: CarrierProfile,
        F: FnOnce(&EstablishedSession) -> Result<Vec<Vec<u8>>, AdmissionError>,
    {
        self.handle_ug3_impl(
            source_id,
            carrier,
            lookup_hint,
            envelope,
            now_secs,
            None,
            extension_builder,
        )
    }

    fn handle_ug3_impl<C, F>(
        &mut self,
        source_id: &str,
        carrier: &C,
        lookup_hint: Option<[u8; 8]>,
        envelope: &SealedEnvelope,
        now_secs: u64,
        public_session_context: Option<&PublicSessionUpgradeContext>,
        extension_builder: F,
    ) -> ServerResponse<EstablishedEnvelopeReply>
    where
        C: CarrierProfile,
        F: FnOnce(&EstablishedSession) -> Result<Vec<Vec<u8>>, AdmissionError>,
    {
        let result = (|| -> Result<EstablishedEnvelopeReply, AdmissionError> {
            let active_binding = carrier.binding();
            if public_session_context.is_some_and(|context| context.carrier != active_binding) {
                return Err(AdmissionError::Validation(
                    "public-session carrier mismatch",
                ));
            }
            let (ug3, resolved) = match public_session_context {
                Some(context) => {
                    self.open_ug3_envelope_with_context(lookup_hint, envelope, context, now_secs)?
                }
                None => self.open_ug3_envelope(lookup_hint, envelope, active_binding, now_secs)?,
            };
            if ug3.slot_binding.phase != UpgradeMessagePhase::Request {
                return Err(AdmissionError::Validation("unexpected upgrade-slot phase"));
            }
            if ug3.selected_family_ack != active_binding {
                return Err(AdmissionError::Validation(
                    "unexpected selected transport ack",
                ));
            }

            let cookie_payload: CookiePayload =
                self.cookie_protector.open(&ug3.anti_amplification_cookie)?;
            if cookie_payload.source_id != source_id
                || cookie_payload.endpoint_id != self.config.endpoint_id
                || cookie_payload.carrier != active_binding
                || cookie_payload.expires_at_secs <= now_secs
            {
                return Err(AdmissionError::Validation("cookie validation failed"));
            }
            let slot_binding_matches = match public_session_context {
                Some(context) => {
                    ug3.slot_binding == context.request_binding(cookie_payload.epoch_slot)
                }
                None => {
                    ug3.slot_binding.epoch_slot == cookie_payload.slot_binding.epoch_slot
                        && ug3.slot_binding.family_id == cookie_payload.slot_binding.family_id
                }
            };
            if !slot_binding_matches {
                return Err(AdmissionError::Validation("slot binding mismatch"));
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
                prologue: handshake_prologue(
                    &self.config.endpoint_id,
                    active_binding,
                    public_session_context,
                )?,
                local_static_private: Some(self.server_static_private),
                remote_static_public: None,
                fixed_ephemeral_private: Some(fixed_ephemeral_private),
            })?;
            noise.read_message(&cookie_payload.noise_msg1)?;
            let responder_payload = bincode::serialize(&NoiseResponderPayload {
                server_contribution,
                masked_fallback_ticket_accept: cookie_payload.masked_fallback_ticket_accepted,
            })?;
            let _replayed_msg2 = noise.write_message(&responder_payload)?;
            let client_payload_bytes = noise.read_message(&ug3.noise_msg3)?;
            let client_payload: NoiseInitiatorPayload =
                bincode::deserialize(&client_payload_bytes)?;
            validate_client_identity(&resolved.identity, client_payload.user_identity.as_deref())?;
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
            let masked_fallback_ticket = self.issue_masked_fallback_ticket(
                cookie_payload.chosen_carrier,
                &cookie_payload.public_route_hint,
                cookie_payload.path_profile,
                now_secs,
            )?;
            let tentative_session = EstablishedSession {
                session_id,
                role: SessionRole::Responder,
                chosen_carrier: cookie_payload.chosen_carrier,
                chosen_suite: cookie_payload.chosen_suite,
                mode: cookie_payload.chosen_mode,
                credential_identity: resolved.identity.clone(),
                secrets,
                tunnel_mtu: self.config.tunnel_mtu,
                rekey_limits: self.config.rekey_limits,
                masked_fallback_ticket: masked_fallback_ticket.clone(),
                client_identity: client_payload.user_identity.clone(),
                client_static_public,
                optional_extensions: Vec::new(),
            };
            let ug4_extensions = extension_builder(&tentative_session)?;
            let ug4 = Ug4 {
                session_id,
                tunnel_mtu: self.config.tunnel_mtu,
                rekey_limits: self.config.rekey_limits,
                ticket_issue_flag: masked_fallback_ticket.is_some(),
                optional_masked_fallback_ticket: masked_fallback_ticket.clone(),
                slot_binding: match public_session_context {
                    Some(context) => {
                        context.response_binding(cookie_payload.slot_binding.epoch_slot)
                    }
                    None => legacy_upgrade_slot_binding(
                        &self.config.endpoint_id,
                        active_binding,
                        UpgradeMessagePhase::Response,
                        "baseline-ug4",
                        cookie_payload.slot_binding.epoch_slot,
                    ),
                },
                optional_extensions: ug4_extensions.clone(),
            };
            let response_envelope = SealedEnvelope::seal(
                &tentative_session.secrets.send_ctrl,
                &envelope_aad(
                    &self.config.endpoint_id,
                    active_binding,
                    public_session_context,
                    UpgradeMessagePhase::Response,
                    cookie_payload.slot_binding.epoch_slot,
                )?,
                &ug4,
            )?;
            let session = EstablishedSession {
                session_id,
                role: SessionRole::Responder,
                chosen_carrier: cookie_payload.chosen_carrier,
                chosen_suite: cookie_payload.chosen_suite,
                mode: cookie_payload.chosen_mode,
                credential_identity: resolved.identity,
                secrets: tentative_session.secrets,
                tunnel_mtu: self.config.tunnel_mtu,
                rekey_limits: self.config.rekey_limits,
                masked_fallback_ticket,
                client_identity: client_payload.user_identity,
                client_static_public,
                optional_extensions: ug4_extensions,
            };
            Ok(EstablishedEnvelopeReply {
                envelope: response_envelope,
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

    fn open_ug3_envelope_with_context(
        &self,
        lookup_hint: Option<[u8; 8]>,
        envelope: &SealedEnvelope,
        public_session_context: &PublicSessionUpgradeContext,
        now_secs: u64,
    ) -> Result<(Ug3, ResolvedCredential), AdmissionError> {
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
            if let Ok(ug3) = envelope.open::<Ug3>(&admission_key, &aad) {
                if ug3.slot_binding != public_session_context.request_binding(resolved.epoch_slot) {
                    return Err(AdmissionError::Validation(
                        "unexpected upgrade-slot binding",
                    ));
                }
                return Ok((ug3, resolved));
            }
        }
        Err(AdmissionError::Validation("unable to decrypt ug3 envelope"))
    }
}
