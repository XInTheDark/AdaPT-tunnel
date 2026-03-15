use crate::error::RuntimeError;
use apt_admission::{AdmissionPacket, ServerConfirmationPacket};
use apt_carriers::{D1Carrier, D2Carrier};
use apt_crypto::{admission_associated_data, open_opaque_payload, seal_opaque_payload};
use apt_types::{CarrierBinding, EndpointId, OpaqueMessage};

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

pub fn encode_admission_d2_datagram(
    carrier: &D2Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    packet: &AdmissionPacket,
) -> Result<Vec<u8>, RuntimeError> {
    encode_opaque_d2_datagram(carrier, endpoint_id, outer_key, &packet.encode())
}

pub fn decode_admission_d2_datagram(
    carrier: &D2Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    datagram: &[u8],
) -> Result<AdmissionPacket, RuntimeError> {
    let plaintext = decode_opaque_d2_datagram(carrier, endpoint_id, outer_key, datagram)?;
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

pub fn encode_confirmation_d2_datagram(
    carrier: &D2Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    packet: &ServerConfirmationPacket,
) -> Result<Vec<u8>, RuntimeError> {
    encode_opaque_d2_datagram(carrier, endpoint_id, outer_key, &packet.encode())
}

pub fn decode_confirmation_d2_datagram(
    carrier: &D2Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    datagram: &[u8],
) -> Result<ServerConfirmationPacket, RuntimeError> {
    let plaintext = decode_opaque_d2_datagram(carrier, endpoint_id, outer_key, datagram)?;
    Ok(ServerConfirmationPacket::decode(&plaintext)?)
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
