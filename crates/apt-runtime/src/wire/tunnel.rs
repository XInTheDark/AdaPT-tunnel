use crate::error::RuntimeError;
use apt_carriers::{CarrierError, CarrierProfile, D1Carrier, D2Carrier};
use apt_crypto::{admission_associated_data, OpaqueAead};
use apt_types::{CarrierBinding, EndpointId};

#[derive(Clone, Debug)]
pub(crate) struct CachedTunnelOuterCrypto {
    aad: Box<[u8]>,
    send_aead: OpaqueAead,
    recv_aead: OpaqueAead,
}

impl CachedTunnelOuterCrypto {
    pub(crate) fn new(
        endpoint_id: &EndpointId,
        binding: CarrierBinding,
        send_key: [u8; 32],
        recv_key: [u8; 32],
    ) -> Result<Self, RuntimeError> {
        Ok(Self {
            aad: admission_associated_data(endpoint_id, binding).into_boxed_slice(),
            send_aead: OpaqueAead::new(&send_key)?,
            recv_aead: OpaqueAead::new(&recv_key)?,
        })
    }

    pub(crate) fn send_parts(&self) -> (&OpaqueAead, &[u8]) {
        (&self.send_aead, &self.aad)
    }

    pub(crate) fn recv_parts(&self) -> (&OpaqueAead, &[u8]) {
        (&self.recv_aead, &self.aad)
    }
}

#[cfg(test)]
pub fn encode_tunnel_datagram(
    carrier: &D1Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    packet_bytes: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    let aead = OpaqueAead::new(outer_key)?;
    encode_tunnel_datagram_cached(
        carrier,
        &aead,
        &admission_associated_data(endpoint_id, CarrierBinding::D1DatagramUdp),
        packet_bytes,
    )
}

#[cfg(test)]
pub fn decode_tunnel_datagram(
    carrier: &D1Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    datagram: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    let aead = OpaqueAead::new(outer_key)?;
    decode_tunnel_datagram_cached(
        carrier,
        &aead,
        &admission_associated_data(endpoint_id, CarrierBinding::D1DatagramUdp),
        datagram,
    )
}

#[cfg(test)]
pub fn encode_tunnel_d2_datagram(
    carrier: &D2Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    packet_bytes: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    let aead = OpaqueAead::new(outer_key)?;
    encode_tunnel_d2_datagram_cached(
        carrier,
        &aead,
        &admission_associated_data(endpoint_id, CarrierBinding::D2EncryptedDatagram),
        packet_bytes,
    )
}

#[cfg(test)]
pub fn decode_tunnel_d2_datagram(
    carrier: &D2Carrier,
    endpoint_id: &EndpointId,
    outer_key: &[u8; 32],
    datagram: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    let aead = OpaqueAead::new(outer_key)?;
    decode_tunnel_d2_datagram_cached(
        carrier,
        &aead,
        &admission_associated_data(endpoint_id, CarrierBinding::D2EncryptedDatagram),
        datagram,
    )
}

pub(crate) fn encode_tunnel_datagram_cached(
    carrier: &D1Carrier,
    aead: &OpaqueAead,
    aad: &[u8],
    packet_bytes: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    let datagram = aead.seal_payload_bytes(aad, packet_bytes)?;
    validate_record_size(datagram.len(), carrier.max_record_size())?;
    Ok(datagram)
}

pub(crate) fn decode_tunnel_datagram_cached(
    carrier: &D1Carrier,
    aead: &OpaqueAead,
    aad: &[u8],
    datagram: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    validate_payload(datagram, carrier.max_record_size())?;
    Ok(aead.open_payload_bytes(aad, datagram)?)
}

pub(crate) fn encode_tunnel_d2_datagram_cached(
    carrier: &D2Carrier,
    aead: &OpaqueAead,
    aad: &[u8],
    packet_bytes: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    let datagram = aead.seal_payload_bytes(aad, packet_bytes)?;
    validate_record_size(datagram.len(), carrier.max_record_size())?;
    Ok(datagram)
}

pub(crate) fn decode_tunnel_d2_datagram_cached(
    carrier: &D2Carrier,
    aead: &OpaqueAead,
    aad: &[u8],
    datagram: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    validate_payload(datagram, carrier.max_record_size())?;
    Ok(aead.open_payload_bytes(aad, datagram)?)
}

pub(crate) fn encode_tunnel_stream_payload_cached(
    aead: &OpaqueAead,
    aad: &[u8],
    packet_bytes: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    Ok(aead.seal_payload_bytes(aad, packet_bytes)?)
}

pub(crate) fn decode_tunnel_stream_payload_cached(
    aead: &OpaqueAead,
    aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    Ok(aead.open_payload_bytes(aad, payload)?)
}

fn validate_record_size(len: usize, max_record_size: u16) -> Result<(), RuntimeError> {
    if len > usize::from(max_record_size) {
        return Err(RuntimeError::Carrier(CarrierError::Oversize));
    }
    Ok(())
}

fn validate_payload(payload: &[u8], max_record_size: u16) -> Result<(), RuntimeError> {
    if payload.is_empty() || payload.len() > usize::from(max_record_size) {
        return Err(RuntimeError::Carrier(CarrierError::MalformedRecord));
    }
    Ok(())
}
