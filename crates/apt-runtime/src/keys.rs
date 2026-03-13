use crate::{config::encode_key_hex, error::RuntimeError};
use apt_crypto::generate_static_keypair;
use rand::random;
use std::{fs, path::Path};

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

pub fn generate_server_keyset() -> Result<GeneratedServerKeyset, RuntimeError> {
    let static_keypair = generate_static_keypair().map_err(|error| RuntimeError::CommandFailed(error.to_string()))?;
    Ok(GeneratedServerKeyset {
        admission_key: random(),
        server_static_private_key: static_keypair.private,
        server_static_public_key: static_keypair.public,
        cookie_key: random(),
        ticket_key: random(),
    })
}

pub fn generate_client_identity() -> Result<GeneratedClientIdentity, RuntimeError> {
    let static_keypair = generate_static_keypair().map_err(|error| RuntimeError::CommandFailed(error.to_string()))?;
    Ok(GeneratedClientIdentity {
        client_static_private_key: static_keypair.private,
        client_static_public_key: static_keypair.public,
    })
}

pub fn write_key_file(path: &Path, key: &[u8; 32]) -> Result<(), RuntimeError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| RuntimeError::IoWithPath {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    fs::write(path, format!("{}\n", encode_key_hex(key))).map_err(|source| RuntimeError::IoWithPath {
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
