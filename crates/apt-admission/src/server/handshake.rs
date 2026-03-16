use super::*;
use crate::packet::{CookiePayload, NoiseInitiatorPayload, NoiseResponderPayload};

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
        let result = (|| -> Result<SealedEnvelope, AdmissionError> {
            let active_binding = carrier.binding();
            if !self.config.allowed_carriers.contains(&active_binding) {
                return Err(AdmissionError::Validation("carrier not allowed"));
            }
            let (ug1, resolved) =
                self.open_ug1_envelope(lookup_hint, envelope, active_binding, now_secs)?;
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
                prologue: admission_associated_data(&self.config.endpoint_id, active_binding),
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
                slot_binding: legacy_upgrade_slot_binding(
                    &self.config.endpoint_id,
                    active_binding,
                    UpgradeMessagePhase::Response,
                    "legacy-ug2",
                    ug1.slot_binding.epoch_slot,
                ),
                padding: random_padding(12),
            };
            let aad = admission_associated_data(&self.config.endpoint_id, active_binding);
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

    /// Handles a `C0` packet and returns either `S1` or an invalid-input action.
    pub fn handle_c0<C: CarrierProfile>(
        &mut self,
        source_id: &str,
        carrier: &C,
        packet: &AdmissionPacket,
        received_len: usize,
        now_secs: u64,
    ) -> ServerResponse<AdmissionPacket> {
        match self.handle_ug1(
            source_id,
            carrier,
            packet.lookup_hint,
            &packet.envelope,
            received_len,
            now_secs,
        ) {
            ServerResponse::Reply(envelope) => ServerResponse::Reply(AdmissionPacket {
                lookup_hint: None,
                envelope,
            }),
            ServerResponse::Drop(behavior) => ServerResponse::Drop(behavior),
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
        match self.handle_ug3_with_extensions(
            source_id,
            carrier,
            packet.lookup_hint,
            &packet.envelope,
            now_secs,
            s3_extensions,
        ) {
            ServerResponse::Reply(reply) => ServerResponse::Reply(EstablishedServerReply {
                packet: ServerConfirmationPacket {
                    envelope: reply.envelope,
                },
                session: reply.session,
            }),
            ServerResponse::Drop(behavior) => ServerResponse::Drop(behavior),
        }
    }

    /// Handles `UG3` while allowing the runtime to attach encrypted `UG4`
    /// extensions such as tunnel address assignments.
    pub fn handle_ug3_with_extensions<C: CarrierProfile>(
        &mut self,
        source_id: &str,
        carrier: &C,
        lookup_hint: Option<[u8; 8]>,
        envelope: &SealedEnvelope,
        now_secs: u64,
        ug4_extensions: Vec<Vec<u8>>,
    ) -> ServerResponse<EstablishedEnvelopeReply> {
        self.handle_ug3_with_extension_builder(
            source_id,
            carrier,
            lookup_hint,
            envelope,
            now_secs,
            move |_| Ok(ug4_extensions),
        )
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
        match self.handle_ug3_with_extension_builder(
            source_id,
            carrier,
            packet.lookup_hint,
            &packet.envelope,
            now_secs,
            extension_builder,
        ) {
            ServerResponse::Reply(reply) => ServerResponse::Reply(EstablishedServerReply {
                packet: ServerConfirmationPacket {
                    envelope: reply.envelope,
                },
                session: reply.session,
            }),
            ServerResponse::Drop(behavior) => ServerResponse::Drop(behavior),
        }
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
        let result = (|| -> Result<EstablishedEnvelopeReply, AdmissionError> {
            let active_binding = carrier.binding();
            let (ug3, resolved) =
                self.open_ug3_envelope(lookup_hint, envelope, active_binding, now_secs)?;
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
            if ug3.slot_binding.epoch_slot != cookie_payload.slot_binding.epoch_slot
                || ug3.slot_binding.family_id != cookie_payload.slot_binding.family_id
            {
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
                prologue: admission_associated_data(&self.config.endpoint_id, active_binding),
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
                slot_binding: legacy_upgrade_slot_binding(
                    &self.config.endpoint_id,
                    active_binding,
                    UpgradeMessagePhase::Response,
                    "legacy-ug4",
                    cookie_payload.slot_binding.epoch_slot,
                ),
                optional_extensions: ug4_extensions.clone(),
            };
            let response_envelope = SealedEnvelope::seal(
                &tentative_session.secrets.send_ctrl,
                &admission_associated_data(&self.config.endpoint_id, active_binding),
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
}

fn validate_auth_profile(
    auth_profile: AuthProfile,
    identity: &CredentialIdentity,
) -> Result<(), AdmissionError> {
    match (auth_profile, identity) {
        (AuthProfile::SharedDeployment, CredentialIdentity::SharedDeployment)
        | (AuthProfile::PerUser, CredentialIdentity::User(_)) => Ok(()),
        (AuthProfile::SharedDeployment, CredentialIdentity::User(_)) => Err(
            AdmissionError::Validation("shared auth profile used with user credential"),
        ),
        (AuthProfile::PerUser, CredentialIdentity::SharedDeployment) => Err(
            AdmissionError::Validation("per-user auth profile used with shared credential"),
        ),
    }
}

fn validate_client_identity(
    identity: &CredentialIdentity,
    claimed_user_identity: Option<&str>,
) -> Result<(), AdmissionError> {
    match (identity, claimed_user_identity) {
        (CredentialIdentity::SharedDeployment, None) => Ok(()),
        (CredentialIdentity::SharedDeployment, Some(_)) => Err(AdmissionError::Validation(
            "shared credential unexpectedly claimed a user identity",
        )),
        (CredentialIdentity::User(expected), Some(claimed)) if expected == claimed => Ok(()),
        (CredentialIdentity::User(_), None) => Err(AdmissionError::Validation(
            "per-user credential omitted the encrypted user identity",
        )),
        (CredentialIdentity::User(_), Some(_)) => Err(AdmissionError::Validation(
            "per-user credential claimed the wrong user identity",
        )),
    }
}
