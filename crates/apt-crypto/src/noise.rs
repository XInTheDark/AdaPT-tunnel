use crate::{parse_noise_params, CryptoError};
use apt_types::SessionRole;
use snow::{Builder, HandshakeState};
use std::fmt;

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
    pub fn raw_split(&mut self) -> Result<super::RawSplitKeys, CryptoError> {
        if !self.state.is_handshake_finished() {
            return Err(CryptoError::InvalidInput(
                "noise raw split requested before handshake completion",
            ));
        }
        let (initiator_to_responder, responder_to_initiator) =
            self.state.dangerously_get_raw_split();
        Ok(super::RawSplitKeys {
            initiator_to_responder,
            responder_to_initiator,
        })
    }
}
