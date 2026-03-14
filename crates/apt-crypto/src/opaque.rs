use crate::{
    deserialize_value, random_bytes, serialize_value, CryptoError, AEAD_KEY_LEN, COOKIE_NONCE_LEN,
};
use apt_types::{CarrierBinding, OpaqueMessage, PathProfile};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
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

/// Generic stateless protector for cookies and resumption tickets.
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
        SealedEnvelope::seal(&self.key, &[], value)
    }

    /// Opens an opaque token into a typed payload.
    pub fn open<T: DeserializeOwned>(&self, envelope: &SealedEnvelope) -> Result<T, CryptoError> {
        envelope.open(&self.key, &[])
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

/// Encrypts raw bytes into an opaque XChaCha20-Poly1305 message.
pub fn seal_opaque_payload(
    key: &[u8; AEAD_KEY_LEN],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<OpaqueMessage, CryptoError> {
    let cipher = OpaqueAead::new(key)?;
    let nonce = random_bytes();
    let ciphertext = cipher.seal_with_nonce(&nonce, associated_data, plaintext)?;
    Ok(OpaqueMessage { nonce, ciphertext })
}

/// Encrypts raw bytes into a nonce-prefixed opaque XChaCha20-Poly1305 payload.
pub fn seal_opaque_payload_bytes(
    key: &[u8; AEAD_KEY_LEN],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let message = seal_opaque_payload(key, associated_data, plaintext)?;
    let mut out = Vec::with_capacity(message.nonce.len() + message.ciphertext.len());
    out.extend_from_slice(&message.nonce);
    out.extend_from_slice(&message.ciphertext);
    Ok(out)
}

/// Decrypts raw bytes from an opaque XChaCha20-Poly1305 message.
pub fn open_opaque_payload(
    key: &[u8; AEAD_KEY_LEN],
    associated_data: &[u8],
    message: &OpaqueMessage,
) -> Result<Vec<u8>, CryptoError> {
    OpaqueAead::new(key)?.open_with_nonce(&message.nonce, associated_data, &message.ciphertext)
}

/// Decrypts raw bytes from a nonce-prefixed opaque XChaCha20-Poly1305 payload.
pub fn open_opaque_payload_bytes(
    key: &[u8; AEAD_KEY_LEN],
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
    OpaqueAead::new(key)?.open_with_nonce(&nonce, associated_data, ciphertext)
}
