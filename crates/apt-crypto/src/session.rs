use crate::{expand_hkdf, expand_hkdf_salted, CryptoError, TUNNEL_NONCE_LEN};
use apt_types::SessionRole;
use std::fmt;

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
    super::TunnelAead::new(key)?.seal_with_nonce(nonce, associated_data, plaintext)
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
    super::TunnelAead::new(key)?.open_with_nonce(nonce, associated_data, ciphertext)
}
