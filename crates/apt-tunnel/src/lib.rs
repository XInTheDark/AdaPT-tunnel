//! Inner encrypted tunnel primitives for APT/1-core.
//!
//! The tunnel packet format is datagram-oriented and protects one or more frames
//! inside an AEAD-encrypted packet. Reliable control frames are retransmitted by
//! the session helper until acknowledged or expired.

use thiserror::Error;

mod codec;
mod frame;
mod packet;
mod rekey;
mod replay;
mod session;

#[cfg(test)]
mod tests;

pub use self::{
    frame::Frame,
    packet::{DecodedPacket, EncodedPacket, TunnelPacketHeader},
    rekey::RekeyStatus,
    session::TunnelSession,
};

/// Errors returned by the tunnel layer.
#[derive(Debug, Error)]
pub enum TunnelError {
    /// Packet bytes were malformed.
    #[error("malformed tunnel packet")]
    MalformedPacket,
    /// Replay protection rejected a packet.
    #[error("replay detected")]
    Replay,
    /// Cryptographic processing failed.
    #[error("crypto failure: {0}")]
    Crypto(#[from] apt_crypto::CryptoError),
    /// Serialization failure.
    #[error("serialization failure: {0}")]
    Serialization(#[from] Box<bincode::ErrorKind>),
    /// Invalid state transition.
    #[error("invalid tunnel state: {0}")]
    InvalidState(&'static str),
}
