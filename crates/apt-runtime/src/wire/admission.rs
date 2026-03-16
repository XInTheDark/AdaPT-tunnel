use crate::error::RuntimeError;
use apt_carriers::{D1Carrier, D2Carrier};
use apt_crypto::{
    admission_associated_data, open_opaque_payload, seal_opaque_payload, SealedEnvelope,
};
use apt_types::{CarrierBinding, EndpointId, OpaqueMessage};
use serde::{Deserialize, Serialize};

const ADMISSION_FLAG_LOOKUP_HINT: u8 = 0x01;
const ENVELOPE_NONCE_LEN: usize = 24;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionWirePacket {
    pub lookup_hint: Option<[u8; 8]>,
    pub envelope: SealedEnvelope,
}

impl AdmissionWirePacket {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            1 + self.lookup_hint.map_or(0, |_| 8)
                + ENVELOPE_NONCE_LEN
                + self.envelope.ciphertext.len(),
        );
        let mut flags = 0_u8;
        if self.lookup_hint.is_some() {
            flags |= ADMISSION_FLAG_LOOKUP_HINT;
        }
        out.push(flags);
        if let Some(lookup_hint) = self.lookup_hint {
            out.extend_from_slice(&lookup_hint);
        }
        out.extend_from_slice(&self.envelope.nonce);
        out.extend_from_slice(&self.envelope.ciphertext);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RuntimeError> {
        if bytes.len() < 1 + ENVELOPE_NONCE_LEN {
            return Err(RuntimeError::InvalidConfig(
                "malformed admission packet".to_string(),
            ));
        }
        let flags = bytes[0];
        if flags & !ADMISSION_FLAG_LOOKUP_HINT != 0 {
            return Err(RuntimeError::InvalidConfig(
                "malformed admission packet".to_string(),
            ));
        }
        let mut cursor = 1_usize;
        let lookup_hint = if flags & ADMISSION_FLAG_LOOKUP_HINT != 0 {
            if bytes.len() < cursor + 8 + ENVELOPE_NONCE_LEN {
                return Err(RuntimeError::InvalidConfig(
                    "malformed admission packet".to_string(),
                ));
            }
            let hint: [u8; 8] = bytes[cursor..cursor + 8].try_into().map_err(|_| {
                RuntimeError::InvalidConfig("malformed admission packet".to_string())
            })?;
            cursor += 8;
            Some(hint)
        } else {
            None
        };
        if bytes.len() <= cursor + ENVELOPE_NONCE_LEN {
            return Err(RuntimeError::InvalidConfig(
                "malformed admission packet".to_string(),
            ));
        }
        let nonce: [u8; ENVELOPE_NONCE_LEN] = bytes[cursor..cursor + ENVELOPE_NONCE_LEN]
            .try_into()
            .map_err(|_| RuntimeError::InvalidConfig("malformed admission packet".to_string()))?;
        Ok(Self {
            lookup_hint,
            envelope: SealedEnvelope {
                nonce,
                ciphertext: bytes[cursor + ENVELOPE_NONCE_LEN..].to_vec(),
            },
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmationWirePacket {
    pub envelope: SealedEnvelope,
}

impl ConfirmationWirePacket {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENVELOPE_NONCE_LEN + self.envelope.ciphertext.len());
        out.extend_from_slice(&self.envelope.nonce);
        out.extend_from_slice(&self.envelope.ciphertext);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RuntimeError> {
        if bytes.len() <= ENVELOPE_NONCE_LEN {
            return Err(RuntimeError::InvalidConfig(
                "malformed server confirmation packet".to_string(),
            ));
        }
        let nonce: [u8; ENVELOPE_NONCE_LEN] =
            bytes[..ENVELOPE_NONCE_LEN].try_into().map_err(|_| {
                RuntimeError::InvalidConfig("malformed server confirmation packet".to_string())
            })?;
        Ok(Self {
            envelope: SealedEnvelope {
                nonce,
                ciphertext: bytes[ENVELOPE_NONCE_LEN..].to_vec(),
            },
        })
    }
}

fn d1_outer_aad(endpoint_id: &EndpointId) -> Vec<u8> {
    admission_associated_data(endpoint_id, CarrierBinding::D1DatagramUdp)
}

fn d2_outer_aad(endpoint_id: &EndpointId) -> Vec<u8> {
    admission_associated_data(endpoint_id, CarrierBinding::D2EncryptedDatagram)
}

pub fn encode_admission_datagram(
    carrier: &D1Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    packet: &AdmissionWirePacket,
) -> Result<Vec<u8>, RuntimeError> {
    encode_opaque_datagram(carrier, endpoint_id, outer_key, &packet.encode())
}

pub fn decode_admission_datagram(
    carrier: &D1Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    datagram: &[u8],
) -> Result<AdmissionWirePacket, RuntimeError> {
    let plaintext = decode_opaque_datagram(carrier, endpoint_id, outer_key, datagram)?;
    AdmissionWirePacket::decode(&plaintext)
}

pub fn encode_admission_d2_datagram(
    carrier: &D2Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    packet: &AdmissionWirePacket,
) -> Result<Vec<u8>, RuntimeError> {
    encode_opaque_d2_datagram(carrier, endpoint_id, outer_key, &packet.encode())
}

pub fn decode_admission_d2_datagram(
    carrier: &D2Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    datagram: &[u8],
) -> Result<AdmissionWirePacket, RuntimeError> {
    let plaintext = decode_opaque_d2_datagram(carrier, endpoint_id, outer_key, datagram)?;
    AdmissionWirePacket::decode(&plaintext)
}

pub fn encode_confirmation_datagram(
    carrier: &D1Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    packet: &ConfirmationWirePacket,
) -> Result<Vec<u8>, RuntimeError> {
    encode_opaque_datagram(carrier, endpoint_id, outer_key, &packet.encode())
}

pub fn decode_confirmation_datagram(
    carrier: &D1Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    datagram: &[u8],
) -> Result<ConfirmationWirePacket, RuntimeError> {
    let plaintext = decode_opaque_datagram(carrier, endpoint_id, outer_key, datagram)?;
    ConfirmationWirePacket::decode(&plaintext)
}

pub fn encode_confirmation_d2_datagram(
    carrier: &D2Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    packet: &ConfirmationWirePacket,
) -> Result<Vec<u8>, RuntimeError> {
    encode_opaque_d2_datagram(carrier, endpoint_id, outer_key, &packet.encode())
}

pub fn decode_confirmation_d2_datagram(
    carrier: &D2Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    datagram: &[u8],
) -> Result<ConfirmationWirePacket, RuntimeError> {
    let plaintext = decode_opaque_d2_datagram(carrier, endpoint_id, outer_key, datagram)?;
    ConfirmationWirePacket::decode(&plaintext)
}

fn encode_opaque_datagram(
    carrier: &D1Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    let message = seal_opaque_message(&d1_outer_aad(endpoint_id), outer_key, plaintext)?;
    Ok(carrier.encode_opaque_record(&message)?)
}

fn decode_opaque_datagram(
    carrier: &D1Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    datagram: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    decode_opaque_message(
        &d1_outer_aad(endpoint_id),
        outer_key,
        &carrier.decode_opaque_record(datagram)?,
    )
}

fn encode_opaque_d2_datagram(
    carrier: &D2Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    let message = seal_opaque_message(&d2_outer_aad(endpoint_id), outer_key, plaintext)?;
    Ok(carrier.encode_opaque_record(&message)?)
}

fn decode_opaque_d2_datagram(
    carrier: &D2Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    datagram: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    decode_opaque_message(
        &d2_outer_aad(endpoint_id),
        outer_key,
        &carrier.decode_opaque_record(datagram)?,
    )
}

fn seal_opaque_message(
    aad: &[u8],
    outer_key: &[u8; 32],
    plaintext: &[u8],
) -> Result<OpaqueMessage, RuntimeError> {
    Ok(seal_opaque_payload(outer_key, aad, plaintext)?)
}

fn decode_opaque_message(
    aad: &[u8],
    outer_key: &[u8; 32],
    message: &OpaqueMessage,
) -> Result<Vec<u8>, RuntimeError> {
    Ok(open_opaque_payload(outer_key, aad, message)?)
}
