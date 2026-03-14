use super::*;

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
    /// Requested policy mode.
    pub policy_mode: PolicyMode,
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
pub(super) struct NoiseResponderPayload {
    pub server_contribution: [u8; 32],
    pub resume_accept: bool,
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
    pub client_nonce: ClientNonce,
    pub epoch_slot: u64,
    pub expires_at_secs: u64,
    pub noise_msg1: Vec<u8>,
    pub chosen_suite: CipherSuite,
    pub chosen_carrier: CarrierBinding,
    pub chosen_policy: PolicyMode,
    pub credential_label: String,
    pub lookup_hint: Option<[u8; 8]>,
    pub path_profile: PathProfile,
    pub resume_accepted: bool,
}
