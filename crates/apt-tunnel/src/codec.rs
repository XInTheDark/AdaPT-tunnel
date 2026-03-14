use crate::{packet::WirePacketBody, TunnelError, TunnelPacketHeader};

pub(crate) const FLAG_HAS_CONTROL: u8 = 0x01;
pub(crate) const PACKET_NONCE_LEN: usize = 12;
pub(crate) const FAST_PATH_SINGLE_IP_DATA_TAG: u8 = 0xA1;

pub(crate) fn encode_fast_path_single_ip_data(
    header: TunnelPacketHeader,
    packet: &[u8],
) -> Result<Vec<u8>, TunnelError> {
    let packet_len = u16::try_from(packet.len())
        .map_err(|_| TunnelError::InvalidState("ip packet too large"))?;
    let mut plaintext = Vec::with_capacity(1 + 1 + 1 + 8 + 2 + packet.len());
    plaintext.push(FAST_PATH_SINGLE_IP_DATA_TAG);
    plaintext.push(header.flags);
    plaintext.push(header.key_phase);
    plaintext.extend_from_slice(&header.packet_number.to_be_bytes());
    plaintext.extend_from_slice(&packet_len.to_be_bytes());
    plaintext.extend_from_slice(packet);
    Ok(plaintext)
}

fn decode_fast_path_header(plaintext: &[u8]) -> Option<TunnelPacketHeader> {
    if plaintext.len() < 13 || plaintext.first().copied()? != FAST_PATH_SINGLE_IP_DATA_TAG {
        return None;
    }
    Some(TunnelPacketHeader {
        flags: plaintext.get(1).copied()?,
        key_phase: plaintext.get(2).copied()?,
        packet_number: u64::from_be_bytes(plaintext.get(3..11)?.try_into().ok()?),
    })
}

pub(crate) enum DecodedPlaintext {
    FastPath {
        header: TunnelPacketHeader,
        packet: Vec<u8>,
    },
    Standard(WirePacketBody),
}

impl DecodedPlaintext {
    pub(crate) fn header(&self) -> TunnelPacketHeader {
        match self {
            Self::FastPath { header, .. } => *header,
            Self::Standard(body) => body.header,
        }
    }
}

pub(crate) fn decode_packet_plaintext(plaintext: &[u8]) -> Result<DecodedPlaintext, TunnelError> {
    if let Some(header) = decode_fast_path_header(plaintext) {
        let packet_len = u16::from_be_bytes(
            plaintext
                .get(11..13)
                .ok_or(TunnelError::MalformedPacket)?
                .try_into()
                .map_err(|_| TunnelError::MalformedPacket)?,
        ) as usize;
        let packet = plaintext.get(13..).ok_or(TunnelError::MalformedPacket)?;
        if packet.len() != packet_len {
            return Err(TunnelError::MalformedPacket);
        }
        return Ok(DecodedPlaintext::FastPath {
            header,
            packet: packet.to_vec(),
        });
    }

    Ok(DecodedPlaintext::Standard(bincode::deserialize(plaintext)?))
}
