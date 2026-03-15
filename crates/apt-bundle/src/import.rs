use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use thiserror::Error;

const CLIENT_BUNDLE_IMPORT_MAGIC: &[u8; 8] = b"APTIMPT1";
const CLIENT_BUNDLE_IMPORT_VERSION: u16 = 1;
const HEADER_LEN: usize = CLIENT_BUNDLE_IMPORT_MAGIC.len() + 2 + 24;

pub const CLIENT_BUNDLE_IMPORT_KEY_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum ClientBundleImportError {
    #[error("import payload was truncated or malformed")]
    Malformed,
    #[error("import payload version {0} is not supported")]
    UnsupportedVersion(u16),
    #[error("import payload authentication failed")]
    Integrity,
}

pub fn protect_client_bundle_for_import(
    bundle_bytes: &[u8],
    key_bytes: &[u8; CLIENT_BUNDLE_IMPORT_KEY_LEN],
) -> Result<Vec<u8>, ClientBundleImportError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let mut nonce = [0_u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), bundle_bytes)
        .map_err(|_| ClientBundleImportError::Integrity)?;
    let mut protected = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    protected.extend_from_slice(CLIENT_BUNDLE_IMPORT_MAGIC);
    protected.extend_from_slice(&CLIENT_BUNDLE_IMPORT_VERSION.to_le_bytes());
    protected.extend_from_slice(&nonce);
    protected.extend_from_slice(&ciphertext);
    Ok(protected)
}

pub fn unprotect_client_bundle_from_import(
    protected: &[u8],
    key_bytes: &[u8; CLIENT_BUNDLE_IMPORT_KEY_LEN],
) -> Result<Vec<u8>, ClientBundleImportError> {
    if protected.len() < HEADER_LEN {
        return Err(ClientBundleImportError::Malformed);
    }
    let (magic, remainder) = protected.split_at(CLIENT_BUNDLE_IMPORT_MAGIC.len());
    if magic != CLIENT_BUNDLE_IMPORT_MAGIC {
        return Err(ClientBundleImportError::Malformed);
    }
    let version = u16::from_le_bytes(
        remainder[..2]
            .try_into()
            .map_err(|_| ClientBundleImportError::Malformed)?,
    );
    if version != CLIENT_BUNDLE_IMPORT_VERSION {
        return Err(ClientBundleImportError::UnsupportedVersion(version));
    }
    let nonce: [u8; 24] = remainder[2..26]
        .try_into()
        .map_err(|_| ClientBundleImportError::Malformed)?;
    let ciphertext = &remainder[26..];
    if ciphertext.is_empty() {
        return Err(ClientBundleImportError::Malformed);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key_bytes));
    cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext)
        .map_err(|_| ClientBundleImportError::Integrity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_payload_round_trips() {
        let key = [0x41_u8; CLIENT_BUNDLE_IMPORT_KEY_LEN];
        let payload = b"test client bundle bytes";
        let protected = protect_client_bundle_for_import(payload, &key).unwrap();
        let recovered = unprotect_client_bundle_from_import(&protected, &key).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn import_payload_rejects_wrong_key() {
        let key = [0x41_u8; CLIENT_BUNDLE_IMPORT_KEY_LEN];
        let wrong_key = [0x42_u8; CLIENT_BUNDLE_IMPORT_KEY_LEN];
        let payload = b"test client bundle bytes";
        let protected = protect_client_bundle_for_import(payload, &key).unwrap();
        let error = unprotect_client_bundle_from_import(&protected, &wrong_key).unwrap_err();
        assert!(matches!(error, ClientBundleImportError::Integrity));
    }
}
