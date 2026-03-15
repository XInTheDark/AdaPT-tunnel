//! Carrier abstractions and concrete outer transport helpers.
//!
//! APT defines logical messages. This crate describes per-carrier limits,
//! associated-data bindings, invalid-input behaviour, and simple record framing
//! for the currently shipped datagram carriers.

use apt_types::{CarrierBinding, EndpointId, OpaqueMessage};
use thiserror::Error;

/// Errors produced by carrier helpers.
#[derive(Debug, Error)]
pub enum CarrierError {
    /// Payload exceeded the carrier record budget.
    #[error("payload exceeds carrier record size limit")]
    Oversize,
    /// Record framing was malformed.
    #[error("malformed record")]
    MalformedRecord,
}

/// Required behaviour when a carrier receives invalid unauthenticated input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidInputBehavior {
    /// Drop silently.
    Silence,
    /// Return only a generic carrier-native failure.
    GenericFailure,
    /// Surface a decoy-compatible response.
    DecoySurface,
}

/// Metadata and framing behaviour shared by all carrier bindings.
pub trait CarrierProfile {
    /// Returns the binding identifier.
    fn binding(&self) -> CarrierBinding;

    /// Returns the maximum record size supported by the carrier.
    fn max_record_size(&self) -> u16;

    /// Returns the effective tunnel MTU exposed to the inner tunnel.
    fn tunnel_mtu(&self) -> u16;

    /// Returns the invalid-input behaviour required for this carrier.
    fn invalid_input_behavior(&self) -> InvalidInputBehavior;

    /// Returns the anti-amplification budget for a reply to an inbound record.
    fn anti_amplification_budget(&self, inbound_len: usize) -> usize {
        usize::from(self.max_record_size()).min(inbound_len.saturating_mul(3))
    }

    /// Builds the associated-data context required by the spec.
    fn associated_data(&self, endpoint_id: &EndpointId) -> Vec<u8> {
        format!("{}::{:?}", endpoint_id.as_str(), self.binding()).into_bytes()
    }
}

/// Opaque datagram carrier over UDP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct D1Carrier {
    max_record_size: u16,
    tunnel_mtu: u16,
}

impl D1Carrier {
    /// Creates a new datagram carrier profile.
    #[must_use]
    pub const fn new(max_record_size: u16, tunnel_mtu: u16) -> Self {
        Self {
            max_record_size,
            tunnel_mtu,
        }
    }

    /// Conservative milestone-1 defaults.
    #[must_use]
    pub const fn conservative() -> Self {
        Self::new(1_472, 1_380)
    }

    /// Emits a single opaque datagram record.
    pub fn encode_record(&self, payload: &[u8]) -> Result<Vec<u8>, CarrierError> {
        if payload.len() > usize::from(self.max_record_size) {
            return Err(CarrierError::Oversize);
        }
        Ok(payload.to_vec())
    }

    /// Accepts a datagram record without any carrier-native cleartext headers.
    pub fn decode_record(&self, datagram: &[u8]) -> Result<Vec<u8>, CarrierError> {
        if datagram.is_empty() || datagram.len() > usize::from(self.max_record_size) {
            return Err(CarrierError::MalformedRecord);
        }
        Ok(datagram.to_vec())
    }

    /// Emits one opaque datagram record using the carrier's raw wire format.
    pub fn encode_opaque_record(&self, message: &OpaqueMessage) -> Result<Vec<u8>, CarrierError> {
        let mut datagram = Vec::with_capacity(message.nonce.len() + message.ciphertext.len());
        datagram.extend_from_slice(&message.nonce);
        datagram.extend_from_slice(&message.ciphertext);
        self.encode_record(&datagram)
    }

    /// Decodes one opaque datagram record back into its nonce/ciphertext parts.
    pub fn decode_opaque_record(&self, datagram: &[u8]) -> Result<OpaqueMessage, CarrierError> {
        let bytes = self.decode_record(datagram)?;
        if bytes.len() <= 24 {
            return Err(CarrierError::MalformedRecord);
        }
        let (nonce, ciphertext) = bytes.split_at(24);
        Ok(OpaqueMessage {
            nonce: nonce
                .try_into()
                .map_err(|_| CarrierError::MalformedRecord)?,
            ciphertext: ciphertext.to_vec(),
        })
    }
}

impl Default for D1Carrier {
    fn default() -> Self {
        Self::conservative()
    }
}

impl CarrierProfile for D1Carrier {
    fn binding(&self) -> CarrierBinding {
        CarrierBinding::D1DatagramUdp
    }

    fn max_record_size(&self) -> u16 {
        self.max_record_size
    }

    fn tunnel_mtu(&self) -> u16 {
        self.tunnel_mtu
    }

    fn invalid_input_behavior(&self) -> InvalidInputBehavior {
        InvalidInputBehavior::Silence
    }
}

/// Opaque datagram carrier over an encrypted general transport such as QUIC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct D2Carrier {
    max_record_size: u16,
    tunnel_mtu: u16,
}

impl D2Carrier {
    /// Creates a new encrypted datagram carrier profile.
    #[must_use]
    pub const fn new(max_record_size: u16, tunnel_mtu: u16) -> Self {
        Self {
            max_record_size,
            tunnel_mtu,
        }
    }

    /// Conservative runtime defaults sized for the minimum practical encrypted
    /// datagram budget without depending on path MTU discovery.
    #[must_use]
    pub const fn conservative() -> Self {
        Self::new(1_120, 1_040)
    }

    /// Emits a single opaque datagram record.
    pub fn encode_record(&self, payload: &[u8]) -> Result<Vec<u8>, CarrierError> {
        if payload.is_empty() || payload.len() > usize::from(self.max_record_size) {
            return Err(CarrierError::Oversize);
        }
        Ok(payload.to_vec())
    }

    /// Accepts a datagram record without any carrier-native cleartext headers.
    pub fn decode_record(&self, datagram: &[u8]) -> Result<Vec<u8>, CarrierError> {
        if datagram.is_empty() || datagram.len() > usize::from(self.max_record_size) {
            return Err(CarrierError::MalformedRecord);
        }
        Ok(datagram.to_vec())
    }

    /// Emits one opaque datagram record using the carrier's raw wire format.
    pub fn encode_opaque_record(&self, message: &OpaqueMessage) -> Result<Vec<u8>, CarrierError> {
        let mut datagram = Vec::with_capacity(message.nonce.len() + message.ciphertext.len());
        datagram.extend_from_slice(&message.nonce);
        datagram.extend_from_slice(&message.ciphertext);
        self.encode_record(&datagram)
    }

    /// Decodes one opaque datagram record back into its nonce/ciphertext parts.
    pub fn decode_opaque_record(&self, datagram: &[u8]) -> Result<OpaqueMessage, CarrierError> {
        let bytes = self.decode_record(datagram)?;
        if bytes.len() <= 24 {
            return Err(CarrierError::MalformedRecord);
        }
        let (nonce, ciphertext) = bytes.split_at(24);
        Ok(OpaqueMessage {
            nonce: nonce
                .try_into()
                .map_err(|_| CarrierError::MalformedRecord)?,
            ciphertext: ciphertext.to_vec(),
        })
    }
}

impl Default for D2Carrier {
    fn default() -> Self {
        Self::conservative()
    }
}

impl CarrierProfile for D2Carrier {
    fn binding(&self) -> CarrierBinding {
        CarrierBinding::D2EncryptedDatagram
    }

    fn max_record_size(&self) -> u16 {
        self.max_record_size
    }

    fn tunnel_mtu(&self) -> u16 {
        self.tunnel_mtu
    }

    fn invalid_input_behavior(&self) -> InvalidInputBehavior {
        InvalidInputBehavior::Silence
    }

    fn anti_amplification_budget(&self, _inbound_len: usize) -> usize {
        usize::from(self.max_record_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_budget_is_bounded() {
        let carrier = D1Carrier::conservative();
        assert_eq!(carrier.anti_amplification_budget(100), 300);
        assert_eq!(carrier.anti_amplification_budget(10_000), 1_472);
    }

    #[test]
    fn datagram_round_trip() {
        let carrier = D1Carrier::conservative();
        let payload = b"hello world";
        let encoded = carrier.encode_record(payload).unwrap();
        let decoded = carrier.decode_record(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn opaque_datagram_round_trip() {
        let carrier = D1Carrier::conservative();
        let encoded = carrier
            .encode_opaque_record(&OpaqueMessage {
                nonce: [7_u8; 24],
                ciphertext: b"ciphertext".to_vec(),
            })
            .unwrap();
        let decoded = carrier.decode_opaque_record(&encoded).unwrap();
        assert_eq!(decoded.nonce, [7_u8; 24]);
        assert_eq!(decoded.ciphertext, b"ciphertext");
    }

    #[test]
    fn d2_opaque_datagram_round_trip() {
        let carrier = D2Carrier::conservative();
        let encoded = carrier
            .encode_opaque_record(&OpaqueMessage {
                nonce: [0x22; 24],
                ciphertext: b"d2".to_vec(),
            })
            .unwrap();
        let decoded = carrier.decode_opaque_record(&encoded).unwrap();
        assert_eq!(decoded.nonce, [0x22; 24]);
        assert_eq!(decoded.ciphertext, b"d2");
    }

    #[test]
    fn connection_oriented_reply_budget_uses_full_record_size() {
        let d2 = D2Carrier::conservative();
        assert_eq!(
            d2.anti_amplification_budget(0),
            usize::from(d2.max_record_size())
        );
    }
}
