use crate::{
    deserialize_value, random_bytes, serialize_value, CryptoError, AEAD_KEY_LEN, COOKIE_NONCE_LEN,
};
use apt_types::{CarrierBinding, OpaqueMessage, PathProfile, PublicRouteHint};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Cached XChaCha20-Poly1305 outer cipher for repeated opaque-record operations.
pub struct OpaqueAead {
    key: [u8; AEAD_KEY_LEN],
    cipher: XChaCha20Poly1305,
}

impl OpaqueAead {
    /// Builds a cached outer-record AEAD instance.
    pub fn new(key: &[u8; AEAD_KEY_LEN]) -> Result<Self, CryptoError> {
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidInput("invalid XChaCha key"))?;
        Ok(Self { key: *key, cipher })
    }

    /// Encrypts raw bytes with an explicit XChaCha20 nonce.
    pub fn seal_with_nonce(
        &self,
        nonce: &[u8; COOKIE_NONCE_LEN],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.cipher
            .encrypt(
                nonce.into(),
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::Aead)
    }

    /// Decrypts raw bytes with an explicit XChaCha20 nonce.
    pub fn open_with_nonce(
        &self,
        nonce: &[u8; COOKIE_NONCE_LEN],
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.cipher
            .decrypt(
                nonce.into(),
                Payload {
                    msg: ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::Aead)
    }

    /// Encrypts raw bytes into an opaque XChaCha20-Poly1305 message.
    pub fn seal_payload(
        &self,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<OpaqueMessage, CryptoError> {
        let nonce = random_bytes();
        let ciphertext = self.seal_with_nonce(&nonce, associated_data, plaintext)?;
        Ok(OpaqueMessage { nonce, ciphertext })
    }

    /// Encrypts raw bytes into a nonce-prefixed opaque XChaCha20-Poly1305 payload.
    pub fn seal_payload_bytes(
        &self,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let nonce = random_bytes();
        let mut ciphertext = self.seal_with_nonce(&nonce, associated_data, plaintext)?;
        let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.append(&mut ciphertext);
        Ok(out)
    }

    /// Decrypts raw bytes from an opaque XChaCha20-Poly1305 message.
    pub fn open_payload(
        &self,
        associated_data: &[u8],
        message: &OpaqueMessage,
    ) -> Result<Vec<u8>, CryptoError> {
        self.open_with_nonce(&message.nonce, associated_data, &message.ciphertext)
    }

    /// Decrypts raw bytes from a nonce-prefixed opaque XChaCha20-Poly1305 payload.
    pub fn open_payload_bytes(
        &self,
        associated_data: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if payload.len() <= COOKIE_NONCE_LEN {
            return Err(CryptoError::InvalidInput("malformed opaque payload"));
        }
        let (nonce, ciphertext) = payload.split_at(COOKIE_NONCE_LEN);
        let nonce: [u8; COOKIE_NONCE_LEN] = nonce
            .try_into()
            .map_err(|_| CryptoError::InvalidInput("malformed opaque payload"))?;
        self.open_with_nonce(&nonce, associated_data, ciphertext)
    }
}

impl Clone for OpaqueAead {
    fn clone(&self) -> Self {
        Self::new(&self.key).expect("cached opaque cipher key was validated at construction")
    }
}

impl fmt::Debug for OpaqueAead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueAead")
            .field("key", &"[redacted]")
            .finish()
    }
}

/// Opaque nonce+ciphertext bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedEnvelope {
    /// XChaCha20 nonce.
    pub nonce: [u8; COOKIE_NONCE_LEN],
    /// Ciphertext including authentication tag.
    pub ciphertext: Vec<u8>,
}

impl SealedEnvelope {
    /// Serializes a value with bincode and encrypts it using XChaCha20-Poly1305.
    pub fn seal<T: Serialize>(
        key: &[u8; AEAD_KEY_LEN],
        associated_data: &[u8],
        value: &T,
    ) -> Result<Self, CryptoError> {
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidInput("invalid XChaCha key"))?;
        let nonce = random_bytes();
        let plaintext = serialize_value(value)?;
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::Aead)?;
        Ok(Self { nonce, ciphertext })
    }

    /// Decrypts and deserializes a bincode-encoded value.
    pub fn open<T: DeserializeOwned>(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        associated_data: &[u8],
    ) -> Result<T, CryptoError> {
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidInput("invalid XChaCha key"))?;
        let plaintext = cipher
            .decrypt(
                (&self.nonce).into(),
                Payload {
                    msg: &self.ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::Aead)?;
        deserialize_value(&plaintext)
    }
}

/// Generic stateless protector for cookies and sealed ticket-style tokens.
#[derive(Clone, Debug)]
pub struct TokenProtector {
    key: [u8; AEAD_KEY_LEN],
}

impl TokenProtector {
    /// Creates a new token protector from raw key material.
    #[must_use]
    pub const fn new(key: [u8; AEAD_KEY_LEN]) -> Self {
        Self { key }
    }

    /// Seals any serializable payload into an opaque token.
    pub fn seal<T: Serialize>(&self, value: &T) -> Result<SealedEnvelope, CryptoError> {
        self.seal_with_aad(&[], value)
    }

    /// Opens an opaque token into a typed payload.
    pub fn open<T: DeserializeOwned>(&self, envelope: &SealedEnvelope) -> Result<T, CryptoError> {
        self.open_with_aad(envelope, &[])
    }

    /// Seals any serializable payload into an opaque token bound to caller-supplied AAD.
    pub fn seal_with_aad<T: Serialize>(
        &self,
        associated_data: &[u8],
        value: &T,
    ) -> Result<SealedEnvelope, CryptoError> {
        SealedEnvelope::seal(&self.key, associated_data, value)
    }

    /// Opens an opaque token into a typed payload bound to caller-supplied AAD.
    pub fn open_with_aad<T: DeserializeOwned>(
        &self,
        envelope: &SealedEnvelope,
        associated_data: &[u8],
    ) -> Result<T, CryptoError> {
        envelope.open(&self.key, associated_data)
    }

    /// Seals a masked fallback ticket for the supplied coarse network context.
    pub fn seal_masked_fallback_ticket(
        &self,
        context: &MaskedFallbackContext,
        expires_at_secs: u64,
        preferred_family: CarrierBinding,
        evidence: MaskedFallbackEvidence,
        allow_shadow_lane: bool,
    ) -> Result<SealedEnvelope, CryptoError> {
        let ticket = MaskedFallbackTicket {
            server_id: context.server_id.clone(),
            expires_at_secs,
            network_context_hash: context.network_context_hash()?,
            preferred_family,
            evidence,
            allow_shadow_lane,
        };
        self.seal_with_aad(&context.ticket_associated_data()?, &ticket)
    }

    /// Opens a masked fallback ticket for the supplied coarse network context.
    pub fn open_masked_fallback_ticket(
        &self,
        envelope: &SealedEnvelope,
        context: &MaskedFallbackContext,
    ) -> Result<MaskedFallbackTicket, CryptoError> {
        let ticket: MaskedFallbackTicket =
            self.open_with_aad(envelope, &context.ticket_associated_data()?)?;
        if ticket.network_context_hash != context.network_context_hash()? {
            return Err(CryptoError::InvalidInput(
                "masked fallback ticket context mismatch",
            ));
        }
        if ticket.server_id != context.server_id {
            return Err(CryptoError::InvalidInput(
                "masked fallback ticket server mismatch",
            ));
        }
        Ok(ticket)
    }
}

/// Resume ticket claims sealed by the server under `TK`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeTicket {
    /// Credential reference for accounting and revocation.
    pub credential_label: String,
    /// Server identifier that issued the ticket.
    pub server_id: String,
    /// Absolute UNIX timestamp after which the ticket is invalid.
    pub expires_at_secs: u64,
    /// Last successful carrier family.
    pub last_successful_carrier: CarrierBinding,
    /// Last-known coarse path profile.
    pub last_path_profile: PathProfile,
    /// Secret binding to the prior session.
    pub resume_secret: [u8; 32],
}

/// Coarse network context bound into a masked fallback ticket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskedFallbackContext {
    /// Deployment-local server identifier.
    pub server_id: String,
    /// Coarse public-route label for the current network.
    pub public_route: PublicRouteHint,
    /// Coarse path profile observed for the route.
    pub path_profile: PathProfile,
}

impl MaskedFallbackContext {
    /// Returns the coarse network-context hash stored inside the sealed ticket.
    pub fn network_context_hash(&self) -> Result<[u8; 32], CryptoError> {
        let encoded = serialize_value(self)?;
        let mut hasher = Sha256::new();
        hasher.update(b"adapt-masked-fallback-context-v1\n");
        hasher.update(&encoded);
        let digest = hasher.finalize();
        let mut out = [0_u8; 32];
        out.copy_from_slice(&digest);
        Ok(out)
    }

    /// Returns associated data used while sealing/opening masked fallback tickets.
    pub fn ticket_associated_data(&self) -> Result<Vec<u8>, CryptoError> {
        let mut aad = b"adapt-masked-fallback-ticket-v1\n".to_vec();
        aad.extend_from_slice(&serialize_value(self)?);
        Ok(aad)
    }
}

/// Confidence/evidence level encoded into a masked fallback ticket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaskedFallbackEvidence {
    /// Minimal evidence: the route worked once.
    ObservedSafe,
    /// Stronger evidence: the route looked stable while succeeding.
    ObservedStable,
}

/// Opaque remembered-safe fallback ticket carried across hidden-upgrade attempts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskedFallbackTicket {
    /// Deployment-local server identifier that minted the ticket.
    pub server_id: String,
    /// Absolute UNIX timestamp after which the ticket is invalid.
    pub expires_at_secs: u64,
    /// Coarse bound network-context hash.
    pub network_context_hash: [u8; 32],
    /// Likely-good public-session family for the remembered context.
    pub preferred_family: CarrierBinding,
    /// Confidence level associated with the observation.
    pub evidence: MaskedFallbackEvidence,
    /// Whether remembered-safe shadow lanes were permitted for the route.
    pub allow_shadow_lane: bool,
}

/// Encrypts raw bytes into an opaque XChaCha20-Poly1305 message.
pub fn seal_opaque_payload(
    key: &[u8; AEAD_KEY_LEN],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<OpaqueMessage, CryptoError> {
    OpaqueAead::new(key)?.seal_payload(associated_data, plaintext)
}

/// Encrypts raw bytes into a nonce-prefixed opaque XChaCha20-Poly1305 payload.
pub fn seal_opaque_payload_bytes(
    key: &[u8; AEAD_KEY_LEN],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    OpaqueAead::new(key)?.seal_payload_bytes(associated_data, plaintext)
}

/// Decrypts raw bytes from an opaque XChaCha20-Poly1305 message.
pub fn open_opaque_payload(
    key: &[u8; AEAD_KEY_LEN],
    associated_data: &[u8],
    message: &OpaqueMessage,
) -> Result<Vec<u8>, CryptoError> {
    OpaqueAead::new(key)?.open_payload(associated_data, message)
}

/// Decrypts raw bytes from a nonce-prefixed opaque XChaCha20-Poly1305 payload.
pub fn open_opaque_payload_bytes(
    key: &[u8; AEAD_KEY_LEN],
    associated_data: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    OpaqueAead::new(key)?.open_payload_bytes(associated_data, payload)
}
