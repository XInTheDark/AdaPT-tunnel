use crate::error::RuntimeError;
use base64::Engine as _;
use rustls::{pki_types::CertificateDer, pki_types::PrivateKeyDer};
use rustls_pemfile::{certs, private_key};
use std::{io::Cursor, path::PathBuf};

pub fn load_certificate_der(spec: &str) -> Result<Vec<u8>, RuntimeError> {
    let chain = load_certificate_chain(spec)?;
    chain
        .into_iter()
        .next()
        .map(|cert| cert.as_ref().to_vec())
        .ok_or_else(|| RuntimeError::InvalidConfig("no certificates were found".to_string()))
}

pub(crate) fn load_certificate_chain(
    spec: &str,
) -> Result<Vec<CertificateDer<'static>>, RuntimeError> {
    let bytes = load_spec_bytes(spec)?;
    if bytes.starts_with(b"-----BEGIN CERTIFICATE-----")
        || spec.ends_with(".pem")
        || spec.ends_with(".crt")
    {
        certs(&mut Cursor::new(bytes))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                RuntimeError::InvalidConfig(format!("invalid PEM certificate: {error}"))
            })
    } else {
        Ok(vec![CertificateDer::from(bytes)])
    }
}

pub(crate) fn load_private_key(spec: &str) -> Result<PrivateKeyDer<'static>, RuntimeError> {
    let bytes = load_spec_bytes(spec)?;
    if bytes.starts_with(b"-----BEGIN") || spec.ends_with(".pem") {
        private_key(&mut Cursor::new(bytes))
            .map_err(|error| {
                RuntimeError::InvalidConfig(format!("invalid PEM private key: {error}"))
            })?
            .ok_or_else(|| RuntimeError::InvalidConfig("no private key found".to_string()))
    } else {
        PrivateKeyDer::try_from(bytes)
            .map_err(|error| RuntimeError::InvalidConfig(format!("invalid private key: {error}")))
    }
}

fn load_spec_bytes(spec: &str) -> Result<Vec<u8>, RuntimeError> {
    if let Some(path) = spec.strip_prefix("file:") {
        return std::fs::read(path).map_err(|source| RuntimeError::IoWithPath {
            path: PathBuf::from(path),
            source,
        });
    }

    let trimmed = spec.trim();
    if trimmed.starts_with("-----BEGIN") {
        return Ok(trimmed.as_bytes().to_vec());
    }

    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|error| {
            RuntimeError::InvalidConfig(format!("invalid base64 certificate/key data: {error}"))
        })
}
