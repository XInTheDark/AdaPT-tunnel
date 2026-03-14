use std::{io, path::PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("io failure at {path}: {source}")]
    IoWithPath { path: PathBuf, source: io::Error },
    #[error("io failure: {0}")]
    Io(#[from] io::Error),
    #[error("config parse failure: {0}")]
    TomlDeserialize(#[from] toml::de::Error),
    #[error("config serialization failure: {0}")]
    TomlSerialize(#[from] toml::ser::Error),
    #[error("admission failure: {0}")]
    Admission(#[from] apt_admission::AdmissionError),
    #[error("carrier failure: {0}")]
    Carrier(#[from] apt_carriers::CarrierError),
    #[error("crypto failure: {0}")]
    Crypto(#[from] apt_crypto::CryptoError),
    #[error("tunnel failure: {0}")]
    Tunnel(#[from] apt_tunnel::TunnelError),
    #[error("serialization failure: {0}")]
    Serialization(#[from] Box<bincode::ErrorKind>),
    #[error("invalid key material: {0}")]
    InvalidKeyMaterial(String),
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("timeout while waiting for {0}")]
    Timeout(&'static str),
    #[error("client is not authorized on the server")]
    UnauthorizedPeer,
    #[error("no active session owns destination {0}")]
    UnknownTunnelDestination(String),
    #[error("unsupported platform operation: {0}")]
    UnsupportedPlatform(&'static str),
    #[error("system command failed: {0}")]
    CommandFailed(String),
}
