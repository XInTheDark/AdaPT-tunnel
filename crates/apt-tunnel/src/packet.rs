use crate::{frame::WireFrame, Frame};
use serde::{Deserialize, Serialize};

/// Fixed tunnel packet header authenticated as AEAD associated data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelPacketHeader {
    /// Packet flags.
    pub flags: u8,
    /// Key phase.
    pub key_phase: u8,
    /// Monotonic packet number.
    pub packet_number: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WirePacketBody {
    pub(crate) header: TunnelPacketHeader,
    pub(crate) frames: Vec<WireFrame>,
}

/// Decoded tunnel packet plus any ack frames the caller may want to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedPacket {
    /// Parsed header.
    pub header: TunnelPacketHeader,
    /// Decrypted frames.
    pub frames: Vec<Frame>,
    /// Ack frames suggested for reliable control frames.
    pub ack_suggestions: Vec<Frame>,
}

/// Encoded packet returned by `TunnelSession::encode_packet`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedPacket {
    /// Parsed header for the packet that was emitted.
    pub header: TunnelPacketHeader,
    /// Serialized bytes ready for a carrier record.
    pub bytes: Vec<u8>,
}
