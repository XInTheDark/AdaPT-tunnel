use crate::{config::encode_key_hex, error::RuntimeError};
use apt_crypto::generate_static_keypair;
use rand::random;
use std::{collections::BTreeSet, fs, path::Path};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedServerKeyset {
    pub admission_key: [u8; 32],
    pub server_static_private_key: [u8; 32],
    pub server_static_public_key: [u8; 32],
    pub cookie_key: [u8; 32],
    pub ticket_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedClientIdentity {
    pub client_static_private_key: [u8; 32],
    pub client_static_public_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedD2TlsIdentity {
    pub certificate_der: Vec<u8>,
    pub certificate_pem: String,
    pub private_key_pem: String,
}

pub fn generate_server_keyset() -> Result<GeneratedServerKeyset, RuntimeError> {
    let static_keypair = generate_static_keypair()
        .map_err(|error| RuntimeError::CommandFailed(error.to_string()))?;
    Ok(GeneratedServerKeyset {
        admission_key: random(),
        server_static_private_key: static_keypair.private,
        server_static_public_key: static_keypair.public,
        cookie_key: random(),
        ticket_key: random(),
    })
}

pub fn generate_client_identity() -> Result<GeneratedClientIdentity, RuntimeError> {
    let static_keypair = generate_static_keypair()
        .map_err(|error| RuntimeError::CommandFailed(error.to_string()))?;
    Ok(GeneratedClientIdentity {
        client_static_private_key: static_keypair.private,
        client_static_public_key: static_keypair.public,
    })
}

pub fn generate_d2_tls_identity(
    subject_alt_names: Vec<String>,
) -> Result<GeneratedD2TlsIdentity, RuntimeError> {
    let subject_alt_names = normalize_subject_alt_names(subject_alt_names);
    let certified = rcgen::generate_simple_self_signed(subject_alt_names)
        .map_err(|error| RuntimeError::Quic(error.to_string()))?;
    let certificate_der = certified.cert.der().to_vec();
    let certificate_pem = certified.cert.pem();
    let private_key_pem = certified.signing_key.serialize_pem();
    Ok(GeneratedD2TlsIdentity {
        certificate_der,
        certificate_pem,
        private_key_pem,
    })
}

pub fn write_key_file(path: &Path, key: &[u8; 32]) -> Result<(), RuntimeError> {
    write_secret_file(path, format!("{}\n", encode_key_hex(key)).as_bytes())
}

pub fn write_secret_file(path: &Path, contents: &[u8]) -> Result<(), RuntimeError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| RuntimeError::IoWithPath {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    fs::write(path, contents).map_err(|source| RuntimeError::IoWithPath {
        path: path.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions).map_err(|source| RuntimeError::IoWithPath {
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn normalize_subject_alt_names(subject_alt_names: Vec<String>) -> Vec<String> {
    let mut names = BTreeSet::new();
    for value in subject_alt_names {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            names.insert(trimmed.to_string());
        }
    }
    if names.is_empty() {
        names.insert("localhost".to_string());
        names.insert("127.0.0.1".to_string());
        names.insert("::1".to_string());
    }
    names.into_iter().collect()
}
