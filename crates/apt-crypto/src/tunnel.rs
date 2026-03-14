use crate::{CryptoError, AEAD_KEY_LEN, TUNNEL_NONCE_LEN};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use std::fmt;

/// Cached ChaCha20-Poly1305 tunnel cipher for repeated packet operations.
pub struct TunnelAead {
    key: [u8; AEAD_KEY_LEN],
    cipher: ChaCha20Poly1305,
}

impl TunnelAead {
    /// Builds a cached tunnel AEAD instance for one direction.
    pub fn new(key: &[u8; AEAD_KEY_LEN]) -> Result<Self, CryptoError> {
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidInput("invalid ChaCha20-Poly1305 key"))?;
        Ok(Self { key: *key, cipher })
    }

    /// Encrypts tunnel payload bytes with a packet-number-derived nonce.
    pub fn seal(
        &self,
        packet_number: u64,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.seal_with_nonce(
            &super::tunnel_nonce_from_packet_number(packet_number),
            associated_data,
            plaintext,
        )
    }

    /// Encrypts tunnel payload bytes with an explicit 96-bit nonce.
    pub fn seal_with_nonce(
        &self,
        nonce: &[u8; TUNNEL_NONCE_LEN],
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

    /// Decrypts tunnel payload bytes with a packet-number-derived nonce.
    pub fn open(
        &self,
        packet_number: u64,
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.open_with_nonce(
            &super::tunnel_nonce_from_packet_number(packet_number),
            associated_data,
            ciphertext,
        )
    }

    /// Decrypts tunnel payload bytes with an explicit 96-bit nonce.
    pub fn open_with_nonce(
        &self,
        nonce: &[u8; TUNNEL_NONCE_LEN],
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

impl Clone for TunnelAead {
    fn clone(&self) -> Self {
        Self::new(&self.key).expect("cached tunnel cipher key was validated at construction")
    }
}

impl fmt::Debug for TunnelAead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelAead")
            .field("key", &"[redacted]")
            .finish()
    }
}
