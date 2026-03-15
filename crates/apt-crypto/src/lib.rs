//! Cryptographic helpers and suite integration for APT/1-core.
//!
//! The crate intentionally keeps cryptographic concerns separate from carrier and
//! state-machine logic. It provides:
//! - admission-plane AEAD helpers
//! - ticket/cookie token sealing
//! - Noise `XXpsk2` handshake wrappers
//! - HKDF-based session and rekey derivation helpers

use bincode::Options;
use hkdf::Hkdf;
use rand::RngCore;
use serde::{de::DeserializeOwned, Serialize};
use sha2::Sha256;
use snow::params::NoiseParams;
use thiserror::Error;

mod admission;
mod noise;
mod opaque;
mod session;
mod tunnel;

#[cfg(test)]
mod tests;

pub use self::{
    admission::{
        admission_associated_data, derive_admission_key, derive_lookup_hint, derive_runtime_key,
        derive_server_contribution, derive_stateless_private_key,
    },
    noise::{generate_static_keypair, NoiseHandshake, NoiseHandshakeConfig, StaticKeypair},
    opaque::{
        open_opaque_payload, open_opaque_payload_bytes, seal_opaque_payload,
        seal_opaque_payload_bytes, MaskedFallbackContext, MaskedFallbackEvidence,
        MaskedFallbackTicket, OpaqueAead, ResumeTicket, SealedEnvelope, TokenProtector,
    },
    session::{
        derive_rekey_phase, derive_session_secrets, open_tunnel_payload,
        open_tunnel_payload_with_nonce, seal_tunnel_payload, seal_tunnel_payload_with_nonce,
        tunnel_nonce_from_packet_number, DirectionalSessionSecrets, RawSplitKeys,
        RekeyPhaseSecrets, SessionSecretsForRole,
    },
    tunnel::TunnelAead,
};

/// Noise pattern mandated by the spec.
pub const NOISE_PATTERN: &str = "Noise_XXpsk2_25519_ChaChaPoly_BLAKE2s";
pub(crate) const AEAD_KEY_LEN: usize = 32;
pub(crate) const COOKIE_NONCE_LEN: usize = 24;
pub(crate) const TUNNEL_NONCE_LEN: usize = 12;

fn default_bincode() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
}

fn serialize_value<T: Serialize>(value: &T) -> Result<Vec<u8>, CryptoError> {
    Ok(default_bincode().serialize(value)?)
}

fn deserialize_value<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CryptoError> {
    Ok(default_bincode().deserialize(bytes)?)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0_u8; N];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

fn expand_hkdf(secret: &[u8], info: &[u8]) -> Result<[u8; 32], CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut out = [0_u8; 32];
    hk.expand(info, &mut out)
        .map_err(|_| CryptoError::InvalidInput("hkdf expand failed"))?;
    Ok(out)
}

fn expand_hkdf_salted(salt: &[u8], secret: &[u8], info: &[u8]) -> Result<[u8; 32], CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut out = [0_u8; 32];
    hk.expand(info, &mut out)
        .map_err(|_| CryptoError::InvalidInput("hkdf expand failed"))?;
    Ok(out)
}

fn parse_noise_params() -> Result<NoiseParams, CryptoError> {
    NOISE_PATTERN
        .parse()
        .map_err(|_| CryptoError::InvalidInput("invalid noise params"))
}

/// Errors produced by the crypto helpers.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Serialization or deserialization failed.
    #[error("serialization failure: {0}")]
    Serialization(#[from] Box<bincode::ErrorKind>),
    /// Noise framework returned an error.
    #[error("noise failure: {0}")]
    Noise(#[from] snow::Error),
    /// AEAD open or seal failed.
    #[error("aead failure")]
    Aead,
    /// Input violated a required invariant.
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
}
