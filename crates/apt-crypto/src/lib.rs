//! Cryptographic helpers and suite integration for APT/1-core.
//!
//! The crate intentionally keeps cryptographic concerns separate from carrier and
//! state-machine logic. It provides:
//! - admission-plane AEAD helpers
//! - ticket/cookie token sealing
//! - Noise `XXpsk2` handshake wrappers
//! - HKDF-based session and rekey derivation helpers

use apt_types::{CarrierBinding, EndpointId, OpaqueMessage, PathProfile, SessionRole};
use bincode::Options;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, XChaCha20Poly1305,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;
use snow::{params::NoiseParams, Builder, HandshakeState};
use std::fmt;
use thiserror::Error;

/// Noise pattern mandated by the spec.
pub const NOISE_PATTERN: &str = "Noise_XXpsk2_25519_ChaChaPoly_BLAKE2s";
const AEAD_KEY_LEN: usize = 32;
const COOKIE_NONCE_LEN: usize = 24;
const TUNNEL_NONCE_LEN: usize = 12;

fn default_bincode() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
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

/// Derives a fresh runtime-scoped key from existing 32-byte key material.
pub fn derive_runtime_key(secret: &[u8; 32], label: &[u8]) -> Result<[u8; 32], CryptoError> {
    expand_hkdf(secret, &[b"apt runtime", label].concat())
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

/// Opaque nonce+ciphertext bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedEnvelope {
    /// XChaCha20 nonce.
    pub nonce: [u8; COOKIE_NONCE_LEN],
    /// Ciphertext including authentication tag.
    pub ciphertext: Vec<u8>,
}

impl SealedEnvelope {
    /// Serializes a value with bincode and encrypts it using XChaCha20-Poly1305.
    pub fn seal<T: Serialize>(
        key: &[u8; AEAD_KEY_LEN],
        associated_data: &[u8],
        value: &T,
    ) -> Result<Self, CryptoError> {
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidInput("invalid XChaCha key"))?;
        let nonce = random_bytes();
        let plaintext = default_bincode().serialize(value)?;
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::Aead)?;
        Ok(Self { nonce, ciphertext })
    }

    /// Decrypts and deserializes a bincode-encoded value.
    pub fn open<T: DeserializeOwned>(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        associated_data: &[u8],
    ) -> Result<T, CryptoError> {
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidInput("invalid XChaCha key"))?;
        let plaintext = cipher
            .decrypt(
                (&self.nonce).into(),
                Payload {
                    msg: &self.ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::Aead)?;
        Ok(default_bincode().deserialize(&plaintext)?)
    }
}

/// Generic stateless protector for cookies and resumption tickets.
#[derive(Clone, Debug)]
pub struct TokenProtector {
    key: [u8; AEAD_KEY_LEN],
}

impl TokenProtector {
    /// Creates a new token protector from raw key material.
    #[must_use]
    pub const fn new(key: [u8; AEAD_KEY_LEN]) -> Self {
        Self { key }
    }

    /// Seals any serializable payload into an opaque token.
    pub fn seal<T: Serialize>(&self, value: &T) -> Result<SealedEnvelope, CryptoError> {
        SealedEnvelope::seal(&self.key, &[], value)
    }

    /// Opens an opaque token into a typed payload.
    pub fn open<T: DeserializeOwned>(&self, envelope: &SealedEnvelope) -> Result<T, CryptoError> {
        envelope.open(&self.key, &[])
    }
}

/// Resume ticket claims sealed by the server under `TK`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeTicket {
    /// Credential reference for accounting and revocation.
    pub credential_label: String,
    /// Server identifier that issued the ticket.
    pub server_id: String,
    /// Absolute UNIX timestamp after which the ticket is invalid.
    pub expires_at_secs: u64,
    /// Last successful carrier family.
    pub last_successful_carrier: CarrierBinding,
    /// Last-known coarse path profile.
    pub last_path_profile: PathProfile,
    /// Secret binding to the prior session.
    pub resume_secret: [u8; 32],
}

/// Helper for producing admission associated-data bindings.
#[must_use]
pub fn admission_associated_data(endpoint_id: &EndpointId, carrier: CarrierBinding) -> Vec<u8> {
    let mut out = Vec::with_capacity(endpoint_id.as_str().len() + 8);
    out.extend_from_slice(endpoint_id.as_str().as_bytes());
    out.push(0xff);
    out.extend_from_slice(format!("{carrier:?}").as_bytes());
    out
}

/// Encrypts raw bytes into an opaque XChaCha20-Poly1305 message.
pub fn seal_opaque_payload(
    key: &[u8; AEAD_KEY_LEN],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<OpaqueMessage, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidInput("invalid XChaCha key"))?;
    let nonce = random_bytes();
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::Aead)?;
    Ok(OpaqueMessage { nonce, ciphertext })
}

/// Decrypts raw bytes from an opaque XChaCha20-Poly1305 message.
pub fn open_opaque_payload(
    key: &[u8; AEAD_KEY_LEN],
    associated_data: &[u8],
    message: &OpaqueMessage,
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidInput("invalid XChaCha key"))?;
    cipher
        .decrypt(
            (&message.nonce).into(),
            Payload {
                msg: &message.ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

/// Derives the per-epoch admission AEAD key from a provisioned admission secret.
#[must_use]
pub fn derive_admission_key(admission_key: &[u8; 32], epoch_slot: u64) -> [u8; 32] {
    let mut info = Vec::from(epoch_slot.to_be_bytes());
    info.extend_from_slice(b"apt admission");
    expand_hkdf(admission_key, &info).expect("fixed-size hkdf expansion cannot fail")
}

/// Derives a rotating lookup hint for per-user credentials.
#[must_use]
pub fn derive_lookup_hint(admission_key: &[u8; 32], epoch_slot: u64) -> [u8; 8] {
    let mut info = Vec::from(epoch_slot.to_be_bytes());
    info.extend_from_slice(b"apt lookup hint");
    let full = expand_hkdf(admission_key, &info).expect("fixed-size hkdf expansion cannot fail");
    full[..8].try_into().expect("slice length is fixed")
}

/// Produces a deterministic private key used to reconstruct stateless server
/// handshake state between `S1` and `C2`.
#[must_use]
pub fn derive_stateless_private_key(seed: &[u8; 32], context: &[u8]) -> [u8; 32] {
    expand_hkdf(seed, &[b"apt stateless e", context].concat())
        .expect("fixed-size hkdf expansion cannot fail")
}

/// Produces a deterministic server contribution used in Noise payloads.
#[must_use]
pub fn derive_server_contribution(seed: &[u8; 32], context: &[u8]) -> [u8; 32] {
    expand_hkdf(
        seed,
        &[b"apt stateless server contribution", context].concat(),
    )
    .expect("fixed-size hkdf expansion cannot fail")
}

/// Raw split keys returned after the Noise handshake completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawSplitKeys {
    /// Initiator-to-responder cipher key.
    pub initiator_to_responder: [u8; 32],
    /// Responder-to-initiator cipher key.
    pub responder_to_initiator: [u8; 32],
}

/// Derived long-lived secrets for the tunnel session.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DirectionalSessionSecrets {
    /// Tunnel data key for initiator-to-responder traffic.
    pub initiator_to_responder_data: [u8; 32],
    /// Tunnel data key for responder-to-initiator traffic.
    pub responder_to_initiator_data: [u8; 32],
    /// Control-plane key for initiator-to-responder traffic.
    pub initiator_to_responder_ctrl: [u8; 32],
    /// Control-plane key for responder-to-initiator traffic.
    pub responder_to_initiator_ctrl: [u8; 32],
    /// Rekey base secret.
    pub rekey: [u8; 32],
    /// Persona derivation seed.
    pub persona_seed: [u8; 32],
    /// Resumption binding secret.
    pub resume_secret: [u8; 32],
}

impl fmt::Debug for DirectionalSessionSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectionalSessionSecrets")
            .field("initiator_to_responder_data", &"[redacted]")
            .field("responder_to_initiator_data", &"[redacted]")
            .field("initiator_to_responder_ctrl", &"[redacted]")
            .field("responder_to_initiator_ctrl", &"[redacted]")
            .field("rekey", &"[redacted]")
            .field("persona_seed", &"[redacted]")
            .field("resume_secret", &"[redacted]")
            .finish()
    }
}

impl DirectionalSessionSecrets {
    /// Selects role-oriented send/receive keys.
    #[must_use]
    pub fn for_role(self, role: SessionRole) -> SessionSecretsForRole {
        match role {
            SessionRole::Initiator => SessionSecretsForRole {
                send_data: self.initiator_to_responder_data,
                recv_data: self.responder_to_initiator_data,
                send_ctrl: self.initiator_to_responder_ctrl,
                recv_ctrl: self.responder_to_initiator_ctrl,
                rekey: self.rekey,
                persona_seed: self.persona_seed,
                resume_secret: self.resume_secret,
            },
            SessionRole::Responder => SessionSecretsForRole {
                send_data: self.responder_to_initiator_data,
                recv_data: self.initiator_to_responder_data,
                send_ctrl: self.responder_to_initiator_ctrl,
                recv_ctrl: self.initiator_to_responder_ctrl,
                rekey: self.rekey,
                persona_seed: self.persona_seed,
                resume_secret: self.resume_secret,
            },
        }
    }
}

/// Role-oriented session secrets.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionSecretsForRole {
    /// Current send-direction data key.
    pub send_data: [u8; 32],
    /// Current receive-direction data key.
    pub recv_data: [u8; 32],
    /// Current send-direction control key.
    pub send_ctrl: [u8; 32],
    /// Current receive-direction control key.
    pub recv_ctrl: [u8; 32],
    /// Rekey base secret.
    pub rekey: [u8; 32],
    /// Persona seed.
    pub persona_seed: [u8; 32],
    /// Resumption secret.
    pub resume_secret: [u8; 32],
}

impl fmt::Debug for SessionSecretsForRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionSecretsForRole")
            .field("send_data", &"[redacted]")
            .field("recv_data", &"[redacted]")
            .field("send_ctrl", &"[redacted]")
            .field("recv_ctrl", &"[redacted]")
            .field("rekey", &"[redacted]")
            .field("persona_seed", &"[redacted]")
            .field("resume_secret", &"[redacted]")
            .finish()
    }
}

/// Directional material for a new rekey phase.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RekeyPhaseSecrets {
    /// New data key for initiator-to-responder traffic.
    pub initiator_to_responder_data: [u8; 32],
    /// New data key for responder-to-initiator traffic.
    pub responder_to_initiator_data: [u8; 32],
    /// New control key for initiator-to-responder traffic.
    pub initiator_to_responder_ctrl: [u8; 32],
    /// New control key for responder-to-initiator traffic.
    pub responder_to_initiator_ctrl: [u8; 32],
    /// Next rekey base secret.
    pub next_rekey: [u8; 32],
}

impl fmt::Debug for RekeyPhaseSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RekeyPhaseSecrets")
            .field("initiator_to_responder_data", &"[redacted]")
            .field("responder_to_initiator_data", &"[redacted]")
            .field("initiator_to_responder_ctrl", &"[redacted]")
            .field("responder_to_initiator_ctrl", &"[redacted]")
            .field("next_rekey", &"[redacted]")
            .finish()
    }
}

/// Derives the complete session secret set from Noise split keys plus encrypted
/// handshake payload contributions.
pub fn derive_session_secrets(
    raw_split: RawSplitKeys,
    client_contribution: &[u8; 32],
    server_contribution: &[u8; 32],
    handshake_hash: &[u8],
) -> Result<DirectionalSessionSecrets, CryptoError> {
    let mut ikm = Vec::with_capacity(32 * 4 + handshake_hash.len());
    ikm.extend_from_slice(&raw_split.initiator_to_responder);
    ikm.extend_from_slice(&raw_split.responder_to_initiator);
    ikm.extend_from_slice(client_contribution);
    ikm.extend_from_slice(server_contribution);
    ikm.extend_from_slice(handshake_hash);
    let master = expand_hkdf_salted(b"apt session master", &ikm, b"apt session master v1")?;
    Ok(DirectionalSessionSecrets {
        initiator_to_responder_data: expand_hkdf(&master, b"apt i2r data")?,
        responder_to_initiator_data: expand_hkdf(&master, b"apt r2i data")?,
        initiator_to_responder_ctrl: expand_hkdf(&master, b"apt i2r ctrl")?,
        responder_to_initiator_ctrl: expand_hkdf(&master, b"apt r2i ctrl")?,
        rekey: expand_hkdf(&master, b"apt rekey")?,
        persona_seed: expand_hkdf(&master, b"apt persona")?,
        resume_secret: expand_hkdf(&master, b"apt resume")?,
    })
}

/// Derives the next phase keys from the current rekey secret and an encrypted
/// `SESSION_UPDATE` contribution.
pub fn derive_rekey_phase(
    rekey_secret: &[u8; 32],
    next_phase: u8,
    contribution: &[u8; 32],
) -> Result<RekeyPhaseSecrets, CryptoError> {
    let mut info = Vec::with_capacity(1 + contribution.len());
    info.push(next_phase);
    info.extend_from_slice(contribution);
    let phase_master = expand_hkdf_salted(b"apt phase master", rekey_secret, &info)?;
    Ok(RekeyPhaseSecrets {
        initiator_to_responder_data: expand_hkdf(&phase_master, b"apt phase i2r data")?,
        responder_to_initiator_data: expand_hkdf(&phase_master, b"apt phase r2i data")?,
        initiator_to_responder_ctrl: expand_hkdf(&phase_master, b"apt phase i2r ctrl")?,
        responder_to_initiator_ctrl: expand_hkdf(&phase_master, b"apt phase r2i ctrl")?,
        next_rekey: expand_hkdf(&phase_master, b"apt phase next rekey")?,
    })
}

/// Builds a 96-bit nonce from a packet number.
#[must_use]
pub fn tunnel_nonce_from_packet_number(packet_number: u64) -> [u8; TUNNEL_NONCE_LEN] {
    let mut nonce = [0_u8; TUNNEL_NONCE_LEN];
    nonce[4..].copy_from_slice(&packet_number.to_be_bytes());
    nonce
}

/// Encrypts tunnel payload bytes with a packet-number-derived nonce.
pub fn seal_tunnel_payload(
    key: &[u8; 32],
    packet_number: u64,
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    seal_tunnel_payload_with_nonce(
        key,
        &tunnel_nonce_from_packet_number(packet_number),
        associated_data,
        plaintext,
    )
}

/// Encrypts tunnel payload bytes with an explicit 96-bit nonce.
pub fn seal_tunnel_payload_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; TUNNEL_NONCE_LEN],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidInput("invalid ChaCha20-Poly1305 key"))?;
    cipher
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
pub fn open_tunnel_payload(
    key: &[u8; 32],
    packet_number: u64,
    associated_data: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    open_tunnel_payload_with_nonce(
        key,
        &tunnel_nonce_from_packet_number(packet_number),
        associated_data,
        ciphertext,
    )
}

/// Decrypts tunnel payload bytes with an explicit 96-bit nonce.
pub fn open_tunnel_payload_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; TUNNEL_NONCE_LEN],
    associated_data: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidInput("invalid ChaCha20-Poly1305 key"))?;
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

/// X25519 keypair used by the server static identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticKeypair {
    /// Raw private key bytes.
    pub private: [u8; 32],
    /// Raw public key bytes.
    pub public: [u8; 32],
}

/// Generates a fresh static keypair compatible with the configured Noise pattern.
pub fn generate_static_keypair() -> Result<StaticKeypair, CryptoError> {
    let builder = Builder::new(parse_noise_params()?);
    let keypair = builder.generate_keypair()?;
    Ok(StaticKeypair {
        private: keypair
            .private
            .try_into()
            .map_err(|_| CryptoError::InvalidInput("unexpected private key length"))?,
        public: keypair
            .public
            .try_into()
            .map_err(|_| CryptoError::InvalidInput("unexpected public key length"))?,
    })
}

/// Configuration for one side of a Noise `XXpsk2` handshake.
#[derive(Clone, Debug)]
pub struct NoiseHandshakeConfig {
    /// Local role in the handshake.
    pub role: SessionRole,
    /// The pre-shared admission key.
    pub psk: [u8; 32],
    /// Prologue binding specific to this carrier/session context.
    pub prologue: Vec<u8>,
    /// Local static private key for responders.
    pub local_static_private: Option<[u8; 32]>,
    /// Expected remote static public key for initiators.
    pub remote_static_public: Option<[u8; 32]>,
    /// Optional deterministic responder ephemeral key.
    pub fixed_ephemeral_private: Option<[u8; 32]>,
}

/// Thin safe wrapper around `snow::HandshakeState`.
pub struct NoiseHandshake {
    state: HandshakeState,
}

impl fmt::Debug for NoiseHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseHandshake")
            .field("finished", &self.is_finished())
            .finish()
    }
}

impl NoiseHandshake {
    /// Builds a new `XXpsk2` handshake state.
    pub fn new(config: NoiseHandshakeConfig) -> Result<Self, CryptoError> {
        let params = parse_noise_params()?;
        let generated_local_static = if config.local_static_private.is_none()
            && matches!(config.role, SessionRole::Initiator)
        {
            Some(generate_static_keypair()?)
        } else {
            None
        };
        let mut builder = Builder::new(params)
            .prologue(&config.prologue)?
            .psk(2, &config.psk)?;

        if let Some(local_static_private) = config
            .local_static_private
            .as_ref()
            .or_else(|| generated_local_static.as_ref().map(|pair| &pair.private))
        {
            builder = builder.local_private_key(local_static_private)?;
        }
        let _ = config.remote_static_public.as_ref();
        if let Some(fixed_ephemeral_private) = config.fixed_ephemeral_private.as_ref() {
            builder = builder.fixed_ephemeral_key_for_testing_only(fixed_ephemeral_private);
        }

        let state = match config.role {
            SessionRole::Initiator => builder.build_initiator()?,
            SessionRole::Responder => builder.build_responder()?,
        };
        Ok(Self { state })
    }

    /// Encrypts or emits the next outbound Noise handshake message.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut out = vec![0_u8; 65_535];
        let len = self.state.write_message(payload, &mut out)?;
        out.truncate(len);
        Ok(out)
    }

    /// Processes the next inbound Noise handshake message.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut out = vec![0_u8; 65_535];
        let len = self.state.read_message(message, &mut out)?;
        out.truncate(len);
        Ok(out)
    }

    /// Returns true once the handshake is complete.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Returns the current transcript hash.
    #[must_use]
    pub fn handshake_hash(&self) -> Vec<u8> {
        self.state.get_handshake_hash().to_vec()
    }

    /// Returns the remote static public key when the handshake has revealed it.
    #[must_use]
    pub fn remote_static_public(&self) -> Option<[u8; 32]> {
        self.state
            .get_remote_static()
            .and_then(|value| value.try_into().ok())
    }

    /// Returns the raw split keys after the handshake has completed.
    pub fn raw_split(&mut self) -> Result<RawSplitKeys, CryptoError> {
        if !self.state.is_handshake_finished() {
            return Err(CryptoError::InvalidInput(
                "noise raw split requested before handshake completion",
            ));
        }
        let (initiator_to_responder, responder_to_initiator) =
            self.state.dangerously_get_raw_split();
        Ok(RawSplitKeys {
            initiator_to_responder,
            responder_to_initiator,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apt_types::SessionRole;

    #[test]
    fn lookup_hint_rotates_by_epoch() {
        let key = [7_u8; 32];
        assert_ne!(derive_lookup_hint(&key, 1), derive_lookup_hint(&key, 2));
    }

    #[test]
    fn sealed_envelopes_fail_with_wrong_aad() {
        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
        struct PayloadType {
            value: u32,
        }

        let key = [9_u8; 32];
        let sealed = SealedEnvelope::seal(&key, b"a", &PayloadType { value: 7 }).unwrap();
        let err = sealed.open::<PayloadType>(&key, b"b").unwrap_err();
        assert!(matches!(err, CryptoError::Aead));
    }

    #[test]
    fn ticket_round_trip_and_integrity_failure() {
        let protector = TokenProtector::new([5_u8; 32]);
        let ticket = ResumeTicket {
            credential_label: "alice".to_string(),
            server_id: "edge-a".to_string(),
            expires_at_secs: 999,
            last_successful_carrier: CarrierBinding::D1DatagramUdp,
            last_path_profile: PathProfile::unknown(),
            resume_secret: [8_u8; 32],
        };
        let mut sealed = protector.seal(&ticket).unwrap();
        let opened: ResumeTicket = protector.open(&sealed).unwrap();
        assert_eq!(opened, ticket);

        sealed.ciphertext[0] ^= 0x01;
        let err = protector.open::<ResumeTicket>(&sealed).unwrap_err();
        assert!(matches!(err, CryptoError::Aead));
    }

    #[test]
    fn opaque_payload_round_trip_and_integrity_failure() {
        let key = derive_runtime_key(&[4_u8; 32], b"d1 outer").unwrap();
        let sealed = seal_opaque_payload(&key, b"aad", b"hello opaque").unwrap();
        let opened = open_opaque_payload(&key, b"aad", &sealed).unwrap();
        assert_eq!(opened, b"hello opaque");

        let err = open_opaque_payload(&key, b"wrong", &sealed).unwrap_err();
        assert!(matches!(err, CryptoError::Aead));
    }

    #[test]
    fn noise_session_derivation_round_trip() {
        let psk = [3_u8; 32];
        let responder_static = generate_static_keypair().unwrap();
        let prologue = b"apt-test".to_vec();
        let mut fixed_ephemeral = [5_u8; 32];
        fixed_ephemeral[0] &= 248;
        fixed_ephemeral[31] &= 127;
        fixed_ephemeral[31] |= 64;

        let mut initiator = NoiseHandshake::new(NoiseHandshakeConfig {
            role: SessionRole::Initiator,
            psk,
            prologue: prologue.clone(),
            local_static_private: None,
            remote_static_public: None,
            fixed_ephemeral_private: None,
        })
        .unwrap();
        let mut responder = NoiseHandshake::new(NoiseHandshakeConfig {
            role: SessionRole::Responder,
            psk,
            prologue,
            local_static_private: Some(responder_static.private),
            remote_static_public: None,
            fixed_ephemeral_private: Some(fixed_ephemeral),
        })
        .unwrap();

        let msg1 = initiator.write_message(&[]).unwrap();
        responder.read_message(&msg1).unwrap();
        let server_contrib = [11_u8; 32];
        let msg2 = responder.write_message(&server_contrib).unwrap();
        let server_payload = initiator.read_message(&msg2).unwrap();
        assert_eq!(server_payload, server_contrib);
        let client_contrib = [13_u8; 32];
        let msg3 = initiator.write_message(&client_contrib).unwrap();
        let client_payload = responder.read_message(&msg3).unwrap();
        assert_eq!(client_payload, client_contrib);

        let initiator_split = initiator.raw_split().unwrap();
        let responder_split = responder.raw_split().unwrap();
        assert_eq!(initiator_split, responder_split);

        let init_hash = initiator.handshake_hash();
        let resp_hash = responder.handshake_hash();
        assert_eq!(init_hash, resp_hash);

        let init_secrets = derive_session_secrets(
            initiator_split,
            &client_contrib,
            &server_contrib,
            &init_hash,
        )
        .unwrap();
        let resp_secrets = derive_session_secrets(
            responder_split,
            &client_contrib,
            &server_contrib,
            &resp_hash,
        )
        .unwrap();
        assert_eq!(
            init_secrets.initiator_to_responder_data,
            resp_secrets.initiator_to_responder_data
        );
        assert_eq!(
            init_secrets.responder_to_initiator_ctrl,
            resp_secrets.responder_to_initiator_ctrl
        );
    }

    #[test]
    fn rekey_derivation_depends_on_phase_and_contribution() {
        let rekey = [17_u8; 32];
        let a = derive_rekey_phase(&rekey, 1, &[21_u8; 32]).unwrap();
        let b = derive_rekey_phase(&rekey, 2, &[21_u8; 32]).unwrap();
        let c = derive_rekey_phase(&rekey, 1, &[22_u8; 32]).unwrap();
        assert_ne!(a.initiator_to_responder_data, b.initiator_to_responder_data);
        assert_ne!(a.initiator_to_responder_data, c.initiator_to_responder_data);
    }

    #[test]
    fn tunnel_nonce_is_packet_number_based() {
        let n1 = tunnel_nonce_from_packet_number(1);
        let n2 = tunnel_nonce_from_packet_number(2);
        assert_ne!(n1, n2);
        assert_eq!(u64::from_be_bytes(n1[4..].try_into().unwrap()), 1);
    }
}
