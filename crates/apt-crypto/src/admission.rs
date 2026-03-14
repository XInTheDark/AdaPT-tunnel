use crate::{expand_hkdf, CryptoError};
use apt_types::{CarrierBinding, EndpointId};

/// Derives a fresh runtime-scoped key from existing 32-byte key material.
pub fn derive_runtime_key(secret: &[u8; 32], label: &[u8]) -> Result<[u8; 32], CryptoError> {
    expand_hkdf(secret, &[b"apt runtime", label].concat())
}

/// Helper for producing admission associated-data bindings.
#[must_use]
pub fn admission_associated_data(endpoint_id: &EndpointId, carrier: CarrierBinding) -> Vec<u8> {
    let carrier_label: &[u8] = match carrier {
        CarrierBinding::D1DatagramUdp => b"D1DatagramUdp",
        CarrierBinding::S1EncryptedStream => b"S1EncryptedStream",
        CarrierBinding::D2EncryptedDatagram => b"D2EncryptedDatagram",
        CarrierBinding::H1RequestResponse => b"H1RequestResponse",
    };
    let mut out = Vec::with_capacity(endpoint_id.as_str().len() + 1 + carrier_label.len());
    out.extend_from_slice(endpoint_id.as_str().as_bytes());
    out.push(0xff);
    out.extend_from_slice(carrier_label);
    out
}

/// Derives the per-epoch admission AEAD key from a provisioned admission secret.
#[must_use]
pub fn derive_admission_key(admission_key: &[u8; 32], epoch_slot: u64) -> [u8; 32] {
    let mut info = Vec::from(epoch_slot.to_be_bytes());
    info.extend_from_slice(b"apt admission");
    expand_hkdf(admission_key, &info).expect("fixed-size hkdf expansion cannot fail")
}

/// Derives a rotating lookup hint for per-user credentials.
#[must_use]
pub fn derive_lookup_hint(admission_key: &[u8; 32], epoch_slot: u64) -> [u8; 8] {
    let mut info = Vec::from(epoch_slot.to_be_bytes());
    info.extend_from_slice(b"apt lookup hint");
    let full = expand_hkdf(admission_key, &info).expect("fixed-size hkdf expansion cannot fail");
    full[..8].try_into().expect("slice length is fixed")
}

/// Produces a deterministic private key used to reconstruct stateless server
/// handshake state between `S1` and `C2`.
#[must_use]
pub fn derive_stateless_private_key(seed: &[u8; 32], context: &[u8]) -> [u8; 32] {
    expand_hkdf(seed, &[b"apt stateless e", context].concat())
        .expect("fixed-size hkdf expansion cannot fail")
}

/// Produces a deterministic server contribution used in Noise payloads.
#[must_use]
pub fn derive_server_contribution(seed: &[u8; 32], context: &[u8]) -> [u8; 32] {
    expand_hkdf(
        seed,
        &[b"apt stateless server contribution", context].concat(),
    )
    .expect("fixed-size hkdf expansion cannot fail")
}
