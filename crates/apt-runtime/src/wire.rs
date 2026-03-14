use crate::error::RuntimeError;
use apt_admission::{AdmissionPacket, ServerConfirmationPacket};
use apt_carriers::D1Carrier;
use apt_crypto::{
    admission_associated_data, derive_admission_key, derive_runtime_key, open_opaque_payload,
    seal_opaque_payload, SessionSecretsForRole,
};
use apt_types::{CarrierBinding, EndpointId, OpaqueMessage};

const D1_ADMISSION_OUTER_LABEL: &[u8] = b"d1 admission outer";
const D1_CONFIRMATION_OUTER_LABEL: &[u8] = b"d1 confirmation outer";
const D1_TUNNEL_OUTER_LABEL: &[u8] = b"d1 tunnel outer";
const S1_ADMISSION_OUTER_LABEL: &[u8] = b"s1 admission outer";
const S1_CONFIRMATION_OUTER_LABEL: &[u8] = b"s1 confirmation outer";
const S1_TUNNEL_OUTER_LABEL: &[u8] = b"s1 tunnel outer";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct D1OuterKeys {
    pub send: [u8; 32],
    pub recv: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S1OuterKeys {
    pub send: [u8; 32],
    pub recv: [u8; 32],
}

fn d1_outer_aad(endpoint_id: &EndpointId) -> Vec<u8> {
    admission_associated_data(endpoint_id, CarrierBinding::D1DatagramUdp)
}

fn s1_outer_aad(endpoint_id: &EndpointId) -> Vec<u8> {
    admission_associated_data(endpoint_id, CarrierBinding::S1EncryptedStream)
}

pub fn derive_d1_admission_outer_key(
    admission_key: &[u8; 32],
    epoch_slot: u64,
) -> Result<[u8; 32], RuntimeError> {
    let per_epoch = derive_admission_key(admission_key, epoch_slot);
    Ok(derive_runtime_key(&per_epoch, D1_ADMISSION_OUTER_LABEL)?)
}

pub fn derive_d1_confirmation_outer_key(ctrl_key: &[u8; 32]) -> Result<[u8; 32], RuntimeError> {
    Ok(derive_runtime_key(ctrl_key, D1_CONFIRMATION_OUTER_LABEL)?)
}

pub fn derive_s1_admission_outer_key(
    admission_key: &[u8; 32],
    epoch_slot: u64,
) -> Result<[u8; 32], RuntimeError> {
    let per_epoch = derive_admission_key(admission_key, epoch_slot);
    Ok(derive_runtime_key(&per_epoch, S1_ADMISSION_OUTER_LABEL)?)
}

pub fn derive_s1_confirmation_outer_key(ctrl_key: &[u8; 32]) -> Result<[u8; 32], RuntimeError> {
    Ok(derive_runtime_key(ctrl_key, S1_CONFIRMATION_OUTER_LABEL)?)
}

pub fn derive_d1_tunnel_outer_keys(
    secrets: &SessionSecretsForRole,
) -> Result<D1OuterKeys, RuntimeError> {
    Ok(D1OuterKeys {
        send: derive_runtime_key(&secrets.send_data, D1_TUNNEL_OUTER_LABEL)?,
        recv: derive_runtime_key(&secrets.recv_data, D1_TUNNEL_OUTER_LABEL)?,
    })
}

pub fn derive_s1_tunnel_outer_keys(
    secrets: &SessionSecretsForRole,
) -> Result<S1OuterKeys, RuntimeError> {
    Ok(S1OuterKeys {
        send: derive_runtime_key(&secrets.send_data, S1_TUNNEL_OUTER_LABEL)?,
        recv: derive_runtime_key(&secrets.recv_data, S1_TUNNEL_OUTER_LABEL)?,
    })
}

pub fn encode_admission_datagram(
    carrier: &D1Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    packet: &AdmissionPacket,
) -> Result<Vec<u8>, RuntimeError> {
    encode_opaque_datagram(carrier, endpoint_id, outer_key, &packet.encode())
}

pub fn decode_admission_datagram(
    carrier: &D1Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    datagram: &[u8],
) -> Result<AdmissionPacket, RuntimeError> {
    let plaintext = decode_opaque_datagram(carrier, endpoint_id, outer_key, datagram)?;
    Ok(AdmissionPacket::decode(&plaintext)?)
}

pub fn encode_admission_stream_payload(
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    packet: &AdmissionPacket,
) -> Result<Vec<u8>, RuntimeError> {
    encode_opaque_bytes(&s1_outer_aad(endpoint_id), outer_key, &packet.encode())
}

pub fn decode_admission_stream_payload(
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    payload: &[u8],
) -> Result<AdmissionPacket, RuntimeError> {
    let plaintext = decode_opaque_bytes(&s1_outer_aad(endpoint_id), outer_key, payload)?;
    Ok(AdmissionPacket::decode(&plaintext)?)
}

pub fn encode_confirmation_datagram(
    carrier: &D1Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    packet: &ServerConfirmationPacket,
) -> Result<Vec<u8>, RuntimeError> {
    encode_opaque_datagram(carrier, endpoint_id, outer_key, &packet.encode())
}

pub fn decode_confirmation_datagram(
    carrier: &D1Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    datagram: &[u8],
) -> Result<ServerConfirmationPacket, RuntimeError> {
    let plaintext = decode_opaque_datagram(carrier, endpoint_id, outer_key, datagram)?;
    Ok(ServerConfirmationPacket::decode(&plaintext)?)
}

pub fn encode_confirmation_stream_payload(
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    packet: &ServerConfirmationPacket,
) -> Result<Vec<u8>, RuntimeError> {
    encode_opaque_bytes(&s1_outer_aad(endpoint_id), outer_key, &packet.encode())
}

pub fn decode_confirmation_stream_payload(
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    payload: &[u8],
) -> Result<ServerConfirmationPacket, RuntimeError> {
    let plaintext = decode_opaque_bytes(&s1_outer_aad(endpoint_id), outer_key, payload)?;
    Ok(ServerConfirmationPacket::decode(&plaintext)?)
}

pub fn encode_tunnel_datagram(
    carrier: &D1Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    packet_bytes: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    encode_opaque_datagram(carrier, endpoint_id, outer_key, packet_bytes)
}

pub fn decode_tunnel_datagram(
    carrier: &D1Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    datagram: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    decode_opaque_datagram(carrier, endpoint_id, outer_key, datagram)
}

pub fn encode_tunnel_stream_payload(
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    packet_bytes: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    encode_opaque_bytes(&s1_outer_aad(endpoint_id), outer_key, packet_bytes)
}

pub fn decode_tunnel_stream_payload(
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    decode_opaque_bytes(&s1_outer_aad(endpoint_id), outer_key, payload)
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

fn encode_opaque_bytes(
    aad: &[u8],
    outer_key: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    Ok(encode_opaque_message_bytes(&seal_opaque_message(
        aad, outer_key, plaintext,
    )?))
}

fn decode_opaque_bytes(
    aad: &[u8],
    outer_key: &[u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    decode_opaque_message(aad, outer_key, &decode_opaque_message_bytes(payload)?)
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

fn encode_opaque_message_bytes(message: &OpaqueMessage) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.nonce.len() + message.ciphertext.len());
    out.extend_from_slice(&message.nonce);
    out.extend_from_slice(&message.ciphertext);
    out
}

fn decode_opaque_message_bytes(payload: &[u8]) -> Result<OpaqueMessage, RuntimeError> {
    if payload.len() <= 24 {
        return Err(RuntimeError::InvalidConfig(
            "malformed opaque carrier payload".to_string(),
        ));
    }
    let (nonce, ciphertext) = payload.split_at(24);
    Ok(OpaqueMessage {
        nonce: nonce.try_into().map_err(|_| {
            RuntimeError::InvalidConfig("malformed opaque carrier payload".to_string())
        })?,
        ciphertext: ciphertext.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use apt_admission::{AdmissionPacket, ServerConfirmationPacket};
    use apt_carriers::D1Carrier;
    use apt_crypto::SealedEnvelope;
    use apt_types::{EndpointId, SessionId};

    #[test]
    fn admission_datagram_round_trip() {
        let carrier = D1Carrier::conservative();
        let endpoint_id = EndpointId::new("edge-a");
        let key = derive_d1_admission_outer_key(&[3_u8; 32], 77).unwrap();
        let packet = AdmissionPacket {
            lookup_hint: Some([9_u8; 8]),
            envelope: SealedEnvelope {
                nonce: [7_u8; 24],
                ciphertext: b"admission".to_vec(),
            },
        };
        let encoded = encode_admission_datagram(&carrier, &endpoint_id, &key, &packet).unwrap();
        let decoded = decode_admission_datagram(&carrier, &endpoint_id, &key, &encoded).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn confirmation_datagram_round_trip() {
        let carrier = D1Carrier::conservative();
        let endpoint_id = EndpointId::new("edge-a");
        let key = derive_d1_confirmation_outer_key(&[5_u8; 32]).unwrap();
        let packet = ServerConfirmationPacket {
            envelope: SealedEnvelope {
                nonce: [1_u8; 24],
                ciphertext: b"confirmation".to_vec(),
            },
        };
        let encoded = encode_confirmation_datagram(&carrier, &endpoint_id, &key, &packet).unwrap();
        let decoded = decode_confirmation_datagram(&carrier, &endpoint_id, &key, &encoded).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn tunnel_outer_keys_are_directional() {
        let keys = derive_d1_tunnel_outer_keys(&SessionSecretsForRole {
            send_data: [1_u8; 32],
            recv_data: [2_u8; 32],
            send_ctrl: [3_u8; 32],
            recv_ctrl: [4_u8; 32],
            rekey: [5_u8; 32],
            persona_seed: [6_u8; 32],
            resume_secret: [7_u8; 32],
        })
        .unwrap();
        assert_ne!(keys.send, keys.recv);

        let carrier = D1Carrier::conservative();
        let endpoint_id = EndpointId::new("edge-a");
        let payload = SessionId([8_u8; 16]).0.to_vec();
        let encoded = encode_tunnel_datagram(&carrier, &endpoint_id, &keys.send, &payload).unwrap();
        let decoded = decode_tunnel_datagram(&carrier, &endpoint_id, &keys.send, &encoded).unwrap();
        assert_eq!(decoded, payload);
    }
}
