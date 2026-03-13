//! Carrier abstractions and concrete outer transport helpers.
//!
//! APT defines logical messages. This crate describes per-carrier limits,
//! associated-data bindings, invalid-input behaviour, and simple record framing
//! for the milestone-1 datagram and stream carriers.

use apt_types::{CarrierBinding, EndpointId};
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
        Self::new(1_200, 1_160)
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

/// Generic encrypted stream carrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct S1Carrier {
    max_record_size: u16,
    tunnel_mtu: u16,
    decoy_surface: bool,
}

impl S1Carrier {
    /// Creates a new stream carrier profile.
    #[must_use]
    pub const fn new(max_record_size: u16, tunnel_mtu: u16, decoy_surface: bool) -> Self {
        Self {
            max_record_size,
            tunnel_mtu,
            decoy_surface,
        }
    }

    /// Conservative milestone-1 defaults.
    #[must_use]
    pub const fn conservative() -> Self {
        Self::new(16_384, 1_120, false)
    }

    /// Encodes payload bytes into length-prefixed records suitable for an
    /// already-encrypted stream transport.
    pub fn encode_records(&self, payload: &[u8]) -> Result<Vec<Vec<u8>>, CarrierError> {
        if payload.is_empty() {
            return Err(CarrierError::MalformedRecord);
        }
        let chunk_budget = usize::from(self.max_record_size);
        let mut records = Vec::new();
        for chunk in payload.chunks(chunk_budget) {
            let len = u16::try_from(chunk.len()).map_err(|_| CarrierError::Oversize)?;
            let mut record = Vec::with_capacity(usize::from(len) + 2);
            record.extend_from_slice(&len.to_be_bytes());
            record.extend_from_slice(chunk);
            records.push(record);
        }
        Ok(records)
    }

    /// Decodes one or more length-prefixed records.
    pub fn decode_records(&self, encoded: &[u8]) -> Result<Vec<Vec<u8>>, CarrierError> {
        let mut cursor = 0_usize;
        let mut out = Vec::new();
        while cursor < encoded.len() {
            if cursor + 2 > encoded.len() {
                return Err(CarrierError::MalformedRecord);
            }
            let len = u16::from_be_bytes([encoded[cursor], encoded[cursor + 1]]);
            cursor += 2;
            let end = cursor + usize::from(len);
            if end > encoded.len() || usize::from(len) > usize::from(self.max_record_size) {
                return Err(CarrierError::MalformedRecord);
            }
            out.push(encoded[cursor..end].to_vec());
            cursor = end;
        }
        if out.is_empty() {
            return Err(CarrierError::MalformedRecord);
        }
        Ok(out)
    }
}

impl Default for S1Carrier {
    fn default() -> Self {
        Self::conservative()
    }
}

impl CarrierProfile for S1Carrier {
    fn binding(&self) -> CarrierBinding {
        CarrierBinding::S1EncryptedStream
    }

    fn max_record_size(&self) -> u16 {
        self.max_record_size
    }

    fn tunnel_mtu(&self) -> u16 {
        self.tunnel_mtu
    }

    fn invalid_input_behavior(&self) -> InvalidInputBehavior {
        if self.decoy_surface {
            InvalidInputBehavior::DecoySurface
        } else {
            InvalidInputBehavior::GenericFailure
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_budget_is_bounded() {
        let carrier = D1Carrier::conservative();
        assert_eq!(carrier.anti_amplification_budget(100), 300);
        assert_eq!(carrier.anti_amplification_budget(10_000), 1_200);
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
    fn stream_record_round_trip() {
        let carrier = S1Carrier::new(8, 900, true);
        let encoded = carrier.encode_records(b"abcdefghijkl").unwrap();
        let wire: Vec<u8> = encoded.concat();
        let decoded = carrier.decode_records(&wire).unwrap();
        assert_eq!(decoded.concat(), b"abcdefghijkl");
        assert_eq!(carrier.invalid_input_behavior(), InvalidInputBehavior::DecoySurface);
    }
}
