//! Single-file client bundle support for the APT operator/client CLIs.
#![allow(missing_docs)]

use apt_runtime::{ClientConfig, Mode, RuntimeCarrierPreference, SessionPolicy};
use apt_types::AuthProfile;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    net::SocketAddr,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientBundle {
    pub client_name: String,
    pub config: ClientConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LegacyClientBundle {
    client_name: String,
    config: LegacyClientConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum LegacyRuntimeMode {
    Stealth,
    Balanced,
    Speed,
}

impl LegacyRuntimeMode {
    fn into_mode(self) -> Mode {
        match self {
            Self::Speed => Mode::SPEED,
            Self::Balanced => Mode::BALANCED,
            Self::Stealth => Mode::STEALTH,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LegacyClientConfig {
    server_addr: String,
    runtime_mode: LegacyRuntimeMode,
    preferred_carrier: RuntimeCarrierPreference,
    auth_profile: AuthProfile,
    endpoint_id: String,
    admission_key: String,
    server_static_public_key: String,
    client_static_private_key: String,
    client_identity: Option<String>,
    bind: SocketAddr,
    interface_name: Option<String>,
    routes: Vec<IpNet>,
    use_server_pushed_routes: bool,
    enable_d2_fallback: bool,
    d2_server_addr: Option<String>,
    d2_server_certificate: Option<String>,
    session_policy: SessionPolicy,
    enable_s1_fallback: bool,
    stream_server_addr: Option<String>,
    allow_session_migration: bool,
    standby_health_check_secs: u64,
    keepalive_secs: u64,
    session_idle_timeout_secs: u64,
    handshake_timeout_secs: u64,
    handshake_retries: u8,
    udp_recv_buffer_bytes: usize,
    udp_send_buffer_bytes: usize,
    state_path: PathBuf,
}

impl From<LegacyClientBundle> for ClientBundle {
    fn from(value: LegacyClientBundle) -> Self {
        Self {
            client_name: value.client_name,
            config: ClientConfig {
                server_addr: value.config.server_addr,
                mode: value.config.runtime_mode.into_mode(),
                preferred_carrier: value.config.preferred_carrier,
                auth_profile: value.config.auth_profile,
                endpoint_id: value.config.endpoint_id,
                admission_key: value.config.admission_key,
                server_static_public_key: value.config.server_static_public_key,
                client_static_private_key: value.config.client_static_private_key,
                client_identity: value.config.client_identity,
                bind: value.config.bind,
                interface_name: value.config.interface_name,
                routes: value.config.routes,
                use_server_pushed_routes: value.config.use_server_pushed_routes,
                enable_d2_fallback: value.config.enable_d2_fallback,
                d2_server_addr: value.config.d2_server_addr,
                d2_server_certificate: value.config.d2_server_certificate,
                session_policy: value.config.session_policy,
                enable_s1_fallback: value.config.enable_s1_fallback,
                stream_server_addr: value.config.stream_server_addr,
                allow_session_migration: value.config.allow_session_migration,
                standby_health_check_secs: value.config.standby_health_check_secs,
                keepalive_secs: value.config.keepalive_secs,
                session_idle_timeout_secs: value.config.session_idle_timeout_secs,
                handshake_timeout_secs: value.config.handshake_timeout_secs,
                handshake_retries: value.config.handshake_retries,
                udp_recv_buffer_bytes: value.config.udp_recv_buffer_bytes,
                udp_send_buffer_bytes: value.config.udp_send_buffer_bytes,
                state_path: value.config.state_path,
            },
        }
    }
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
    match bincode::deserialize(&decoded) {
        Ok(bundle) => Ok(bundle),
        Err(primary_error) => match bincode::deserialize::<LegacyClientBundle>(&decoded) {
            Ok(bundle) => Ok(bundle.into()),
            Err(_) => Err(BundleError::Serialization(primary_error)),
        },
    }
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
    if bundle_path == Path::new("/etc/adapt").join(DEFAULT_CLIENT_BUNDLE_FILE_NAME) {
        return PathBuf::from("/var/lib/adapt/client-state.toml");
    }
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

    fn test_bundle() -> ClientBundle {
        ClientBundle {
            client_name: "laptop".to_string(),
            config: ClientConfig {
                server_addr: "198.51.100.10:51820".to_string(),
                mode: Mode::STEALTH,
                preferred_carrier: RuntimeCarrierPreference::D1,
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
                enable_d2_fallback: true,
                d2_server_addr: Some("198.51.100.10:443".to_string()),
                d2_server_certificate: Some("BASE64-D2-CERT".to_string()),
                session_policy: SessionPolicy::default(),
                enable_s1_fallback: true,
                stream_server_addr: Some("198.51.100.10:443".to_string()),
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
    fn legacy_bundle_with_named_mode_still_decodes() {
        let legacy = LegacyClientBundle {
            client_name: "laptop".to_string(),
            config: LegacyClientConfig {
                server_addr: "198.51.100.10:51820".to_string(),
                runtime_mode: LegacyRuntimeMode::Stealth,
                preferred_carrier: RuntimeCarrierPreference::D1,
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
                enable_d2_fallback: true,
                d2_server_addr: Some("198.51.100.10:443".to_string()),
                d2_server_certificate: Some("BASE64-D2-CERT".to_string()),
                session_policy: SessionPolicy::default(),
                enable_s1_fallback: true,
                stream_server_addr: Some("198.51.100.10:443".to_string()),
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
        };
        let payload = bincode::serialize(&legacy).unwrap();
        let compressed = zstd::encode_all(payload.as_slice(), DEFAULT_ZSTD_LEVEL).unwrap();
        let digest = Sha256::digest(&compressed);
        let mut encoded = Vec::new();
        encoded.extend_from_slice(CLIENT_BUNDLE_MAGIC);
        encoded.extend_from_slice(&CLIENT_BUNDLE_FORMAT_VERSION.to_le_bytes());
        encoded.extend_from_slice(&(compressed.len() as u64).to_le_bytes());
        encoded.extend_from_slice(digest.as_slice());
        encoded.extend_from_slice(&compressed);

        let decoded = decode_client_bundle(&encoded).unwrap();
        assert_eq!(decoded.client_name, "laptop");
        assert_eq!(decoded.config.mode, Mode::STEALTH);
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
    fn default_install_path_uses_var_lib_state() {
        assert_eq!(
            client_bundle_state_path("/etc/adapt/client.aptbundle"),
            PathBuf::from("/var/lib/adapt/client-state.toml")
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
