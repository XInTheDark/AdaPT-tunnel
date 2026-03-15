mod admission;
mod keys;
mod tunnel;

#[cfg(test)]
mod tests;

pub use admission::{
    decode_admission_d2_datagram, decode_admission_datagram, decode_admission_stream_payload,
    decode_confirmation_d2_datagram, decode_confirmation_datagram,
    decode_confirmation_stream_payload, encode_admission_d2_datagram, encode_admission_datagram,
    encode_admission_stream_payload, encode_confirmation_d2_datagram, encode_confirmation_datagram,
    encode_confirmation_stream_payload,
};
pub use keys::{
    derive_d1_admission_outer_key, derive_d1_confirmation_outer_key, derive_d1_tunnel_outer_keys,
    derive_d2_admission_outer_key, derive_d2_confirmation_outer_key, derive_d2_tunnel_outer_keys,
    derive_s1_admission_outer_key, derive_s1_confirmation_outer_key, derive_s1_tunnel_outer_keys,
    D1OuterKeys, D2OuterKeys, S1OuterKeys,
};
pub(crate) use tunnel::CachedTunnelOuterCrypto;
pub(crate) use tunnel::{
    decode_tunnel_d2_datagram_cached, decode_tunnel_datagram_cached,
    decode_tunnel_stream_payload_cached, encode_tunnel_d2_datagram_cached,
    encode_tunnel_datagram_cached, encode_tunnel_stream_payload_cached,
};

#[cfg(test)]
pub use tunnel::{
    decode_tunnel_d2_datagram, decode_tunnel_datagram, encode_tunnel_d2_datagram,
    encode_tunnel_datagram,
};
