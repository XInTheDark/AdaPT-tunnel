//! Single-file client bundle support for the APT operator/client CLIs.
#![allow(missing_docs)]

mod client_override;
mod import;

use apt_runtime::ClientConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    path::{Path, PathBuf},
};
use thiserror::Error;

const CLIENT_BUNDLE_MAGIC: &[u8; 8] = b"APTBNDL1";
const CLIENT_BUNDLE_FORMAT_VERSION: u16 = 1;
const SHA256_LEN: usize = 32;
const HEADER_LEN: usize = CLIENT_BUNDLE_MAGIC.len() + 2 + 8 + SHA256_LEN;
const DEFAULT_ZSTD_LEVEL: i32 = 9;

pub const CLIENT_BUNDLE_EXTENSION: &str = "aptbundle";
pub const DEFAULT_CLIENT_BUNDLE_FILE_NAME: &str = "client.aptbundle";

pub use self::import::{
    protect_client_bundle_for_import, unprotect_client_bundle_from_import, ClientBundleImportError,
    CLIENT_BUNDLE_IMPORT_KEY_LEN,
};
pub use client_override::{
    apply_optional_client_override, ensure_client_override_file, ClientOverrideConfig,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientBundle {
    pub client_name: String,
    pub config: ClientConfig,
}

#[derive(Debug, Error)]
pub enum BundleError {
    #[error("bundle file was truncated or malformed")]
    Malformed,
    #[error("bundle magic did not match the expected APT client bundle format")]
    InvalidMagic,
    #[error("bundle format version {0} is not supported")]
    UnsupportedVersion(u16),
    #[error("bundle integrity check failed")]
    Integrity,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Serialization(#[from] Box<bincode::ErrorKind>),
}

pub fn encode_client_bundle(bundle: &ClientBundle) -> Result<Vec<u8>, BundleError> {
    let payload = bincode::serialize(bundle)?;
    let compressed = zstd::encode_all(payload.as_slice(), DEFAULT_ZSTD_LEVEL)?;
    let digest = Sha256::digest(&compressed);
    let mut encoded = Vec::with_capacity(HEADER_LEN + compressed.len());
    encoded.extend_from_slice(CLIENT_BUNDLE_MAGIC);
    encoded.extend_from_slice(&CLIENT_BUNDLE_FORMAT_VERSION.to_le_bytes());
    encoded.extend_from_slice(&(compressed.len() as u64).to_le_bytes());
    encoded.extend_from_slice(digest.as_slice());
    encoded.extend_from_slice(&compressed);
    Ok(encoded)
}

pub fn decode_client_bundle(bytes: &[u8]) -> Result<ClientBundle, BundleError> {
    if bytes.len() < HEADER_LEN {
        return Err(BundleError::Malformed);
    }
    let (magic, remainder) = bytes.split_at(CLIENT_BUNDLE_MAGIC.len());
    if magic != CLIENT_BUNDLE_MAGIC {
        return Err(BundleError::InvalidMagic);
    }
    let version = u16::from_le_bytes(
        remainder[..2]
            .try_into()
            .map_err(|_| BundleError::Malformed)?,
    );
    if version != CLIENT_BUNDLE_FORMAT_VERSION {
        return Err(BundleError::UnsupportedVersion(version));
    }
    let payload_len = u64::from_le_bytes(
        remainder[2..10]
            .try_into()
            .map_err(|_| BundleError::Malformed)?,
    );
    let payload_len = usize::try_from(payload_len).map_err(|_| BundleError::Malformed)?;
    let expected_digest = &remainder[10..(10 + SHA256_LEN)];
    let payload = &remainder[(10 + SHA256_LEN)..];
    if payload.len() != payload_len {
        return Err(BundleError::Malformed);
    }
    let actual_digest = Sha256::digest(payload);
    if actual_digest.as_slice() != expected_digest {
        return Err(BundleError::Integrity);
    }
    let decoded = zstd::decode_all(payload)?;
    bincode::deserialize::<ClientBundle>(&decoded).map_err(BundleError::Serialization)
}

pub fn store_client_bundle(
    path: impl AsRef<Path>,
    bundle: &ClientBundle,
) -> Result<(), BundleError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let encoded = encode_client_bundle(bundle)?;
    fs::write(path, encoded)?;
    Ok(())
}

pub fn load_client_bundle(path: impl AsRef<Path>) -> Result<ClientBundle, BundleError> {
    let bytes = fs::read(path)?;
    decode_client_bundle(&bytes)
}

pub fn default_client_bundle_path(dir: impl AsRef<Path>) -> PathBuf {
    dir.as_ref().join(DEFAULT_CLIENT_BUNDLE_FILE_NAME)
}

pub fn client_bundle_override_path(bundle_path: impl AsRef<Path>) -> PathBuf {
    let bundle_path = bundle_path.as_ref();
    let parent = bundle_path.parent().unwrap_or_else(|| Path::new("."));
    let stem = bundle_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("client");
    parent.join(format!("{stem}.override.toml"))
}

pub fn client_bundle_state_path(bundle_path: impl AsRef<Path>) -> PathBuf {
    let bundle_path = bundle_path.as_ref();
    let parent = bundle_path.parent().unwrap_or_else(|| Path::new("."));
    let stem = bundle_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("client");
    parent.join(format!("{stem}.state.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use apt_runtime::{Mode, SessionPolicy, V2DeploymentStrength};
    use apt_types::AuthProfile;
    use std::net::SocketAddr;

    fn test_bundle() -> ClientBundle {
        ClientBundle {
            client_name: "laptop".to_string(),
            config: ClientConfig {
                server_addr: "198.51.100.10:443".to_string(),
                authority: "api.example.com".to_string(),
                server_name: Some("api.example.com".to_string()),
                server_roots: None,
                server_certificate: Some("BASE64-H2-CERT".to_string()),
                deployment_strength: V2DeploymentStrength::SelfContained,
                mode: Mode::STEALTH,
                auth_profile: AuthProfile::PerUser,
                endpoint_id: "adapt-demo".to_string(),
                admission_key: "11".repeat(32),
                server_static_public_key: "22".repeat(32),
                client_static_private_key: "33".repeat(32),
                client_identity: Some("laptop".to_string()),
                bind: "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
                interface_name: None,
                routes: Vec::new(),
                use_server_pushed_routes: true,
                session_policy: SessionPolicy::default(),
                allow_session_migration: true,
                standby_health_check_secs: 0,
                keepalive_secs: 25,
                session_idle_timeout_secs: 180,
                handshake_timeout_secs: 5,
                handshake_retries: 5,
                udp_recv_buffer_bytes: 4 * 1024 * 1024,
                udp_send_buffer_bytes: 4 * 1024 * 1024,
                state_path: PathBuf::from("client-state.toml"),
            },
        }
    }

    #[test]
    fn bundle_round_trips() {
        let bundle = test_bundle();
        let encoded = encode_client_bundle(&bundle).unwrap();
        let decoded = decode_client_bundle(&encoded).unwrap();
        assert_eq!(decoded, bundle);
    }

    #[test]
    fn bundle_rejects_bad_magic() {
        let mut encoded = encode_client_bundle(&test_bundle()).unwrap();
        encoded[0] ^= 0xFF;
        let error = decode_client_bundle(&encoded).unwrap_err();
        assert!(matches!(error, BundleError::InvalidMagic));
    }

    #[test]
    fn bundle_rejects_digest_mismatch() {
        let mut encoded = encode_client_bundle(&test_bundle()).unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 0x01;
        let error = decode_client_bundle(&encoded).unwrap_err();
        assert!(matches!(error, BundleError::Integrity));
    }

    #[test]
    fn bundle_state_path_uses_bundle_stem() {
        assert_eq!(
            client_bundle_state_path("/etc/adapt/laptop.aptbundle"),
            PathBuf::from("/etc/adapt/laptop.state.toml")
        );
    }

    #[test]
    fn default_install_path_uses_bundle_local_state() {
        assert_eq!(
            client_bundle_state_path("/etc/adapt/client.aptbundle"),
            PathBuf::from("/etc/adapt/client.state.toml")
        );
    }

    #[test]
    fn override_path_uses_bundle_stem() {
        assert_eq!(
            client_bundle_override_path("/etc/adapt/laptop.aptbundle"),
            PathBuf::from("/etc/adapt/laptop.override.toml")
        );
    }
}
