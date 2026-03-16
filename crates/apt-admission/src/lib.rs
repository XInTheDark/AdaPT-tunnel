//! Admission-plane logical messages and validation state machine for APT.
//!
//! The implementation keeps the admission plane carrier-agnostic while still
//! binding every encrypted admission message to the active carrier and endpoint.

use apt_carriers::{CarrierProfile, InvalidInputBehavior};
use apt_crypto::{
    admission_associated_data, derive_admission_key, derive_lookup_hint,
    derive_server_contribution, derive_session_secrets, derive_stateless_private_key,
    generate_static_keypair, MaskedFallbackContext, MaskedFallbackEvidence, NoiseHandshake,
    NoiseHandshakeConfig, RawSplitKeys, SealedEnvelope, SessionSecretsForRole, StaticKeypair,
    TokenProtector,
};
use apt_types::{
    AdmissionDefaults, AuthProfile, CarrierBinding, CipherSuite, ClientNonce, CredentialIdentity,
    EndpointId, Mode, PathProfile, PublicRouteHint, RekeyLimits, SessionId, SessionRole,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

mod client;
mod payload;
mod server;
mod upgrade;

#[cfg(test)]
mod tests;

use self::upgrade::{
    legacy_upgrade_slot_binding, public_session_associated_data, slot_bound_associated_data,
};
pub use self::{
    client::{
        initiate_ug1, initiate_ug1_with_context, ClientCredential, ClientPendingS1,
        ClientPendingS3, ClientSessionRequest, PreparedUg1Envelope, PreparedUg3Envelope,
    },
    payload::PolicyFlags,
    server::{
        AdmissionConfig, AdmissionServer, AdmissionServerSecrets, CredentialStore,
        EstablishedEnvelopeReply, EstablishedSession, PerUserCredential, ServerResponse,
    },
    upgrade::{
        PublicSessionUpgradeContext, Ug1, Ug2, Ug3, Ug4, UpgradeMessagePhase, UpgradeSlotBinding,
    },
};

const VERSION: &str = "APT/1-core";
const ACCEPTABLE_SLOT_SKEW: i64 = 1;

fn random_padding(len: usize) -> Vec<u8> {
    let mut out = vec![0_u8; len];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

fn epoch_slot(now_secs: u64, slot_len_secs: u64) -> u64 {
    now_secs / slot_len_secs
}

fn candidate_slots(now_slot: u64) -> [u64; 3] {
    [
        now_slot.saturating_sub(1),
        now_slot,
        now_slot.saturating_add(1),
    ]
}

/// Errors produced by the admission logic.
#[derive(Debug, Error)]
pub enum AdmissionError {
    /// Crypto failure.
    #[error("crypto failure: {0}")]
    Crypto(#[from] apt_crypto::CryptoError),
    /// Serialization failure.
    #[error("serialization failure: {0}")]
    Serialization(#[from] Box<bincode::ErrorKind>),
    /// The input violated the spec.
    #[error("validation failure: {0}")]
    Validation(&'static str),
    /// The message was replayed.
    #[error("replay detected")]
    Replay,
}
