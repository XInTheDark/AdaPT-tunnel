use super::*;

pub(super) fn plan_outbound_tunnel_batches(
    carriers: &RuntimeCarriers,
    endpoint_id: &apt_types::EndpointId,
    outer_keys: &RuntimeOuterKeys,
    encapsulation: TunnelEncapsulation,
    binding: CarrierBinding,
    tunnel: &TunnelSession,
    frames: &[Frame],
    now: u64,
) -> Result<Vec<Vec<Frame>>, RuntimeError> {
    let mut remaining = frames.to_vec();
    let mut trial_tunnel = tunnel.clone();
    let mut batches = Vec::new();
    while !remaining.is_empty() {
        if let Some((count, next_tunnel)) = largest_fitting_frame_prefix(
            carriers,
            endpoint_id,
            outer_keys,
            encapsulation,
            binding,
            &trial_tunnel,
            &remaining,
            now,
        )? {
            batches.push(remaining.drain(..count).collect());
            trial_tunnel = next_tunnel;
            continue;
        }

        let frame = remaining.remove(0);
        match frame {
            Frame::IpData(packet) => {
                debug!(
                    carrier = binding.as_str(),
                    packet_len = packet.len(),
                    "dropping outbound IP packet that exceeds the current carrier budget; consider lowering the tunnel MTU"
                );
            }
            Frame::Padding(bytes) => {
                debug!(
                    carrier = binding.as_str(),
                    padding_len = bytes.len(),
                    "dropping oversized outbound padding frame"
                );
            }
            _ => return Err(RuntimeError::Carrier(CarrierError::Oversize)),
        }
    }
    Ok(batches)
}

fn largest_fitting_frame_prefix(
    carriers: &RuntimeCarriers,
    endpoint_id: &apt_types::EndpointId,
    outer_keys: &RuntimeOuterKeys,
    encapsulation: TunnelEncapsulation,
    binding: CarrierBinding,
    tunnel: &TunnelSession,
    frames: &[Frame],
    now: u64,
) -> Result<Option<(usize, TunnelSession)>, RuntimeError> {
    for count in (1..=frames.len()).rev() {
        let mut candidate_tunnel = tunnel.clone();
        match encode_server_tunnel_packet_batch(
            carriers,
            endpoint_id,
            outer_keys,
            encapsulation,
            binding,
            &mut candidate_tunnel,
            &frames[..count],
            now,
        ) {
            Ok(_) => return Ok(Some((count, candidate_tunnel))),
            Err(RuntimeError::Carrier(CarrierError::Oversize)) => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

pub(super) fn encode_client_tunnel_packet_batch(
    carriers: &RuntimeCarriers,
    endpoint_id: &apt_types::EndpointId,
    outer_keys: &RuntimeOuterKeys,
    encapsulation: TunnelEncapsulation,
    binding: CarrierBinding,
    tunnel: &mut TunnelSession,
    frames: &[Frame],
    now: u64,
) -> Result<Vec<u8>, RuntimeError> {
    encode_server_tunnel_packet_batch(
        carriers,
        endpoint_id,
        outer_keys,
        encapsulation,
        binding,
        tunnel,
        frames,
        now,
    )
}

pub(super) fn encode_server_tunnel_packet_batch(
    carriers: &RuntimeCarriers,
    _endpoint_id: &apt_types::EndpointId,
    outer_keys: &RuntimeOuterKeys,
    encapsulation: TunnelEncapsulation,
    binding: CarrierBinding,
    tunnel: &mut TunnelSession,
    frames: &[Frame],
    now: u64,
) -> Result<Vec<u8>, RuntimeError> {
    let encoded = tunnel.encode_packet(frames, now)?;
    encode_server_tunnel_packet(carriers, outer_keys, encapsulation, binding, encoded.bytes)
}

fn encode_server_tunnel_packet(
    carriers: &RuntimeCarriers,
    outer_keys: &RuntimeOuterKeys,
    encapsulation: TunnelEncapsulation,
    binding: CarrierBinding,
    packet_bytes: Vec<u8>,
) -> Result<Vec<u8>, RuntimeError> {
    if matches!(encapsulation, TunnelEncapsulation::DirectInnerOnly) {
        return Ok(packet_bytes);
    }
    match binding {
        CarrierBinding::D1DatagramUdp => {
            let crypto = outer_keys.send_for(binding)?;
            let (aead, aad) = crypto.send_parts();
            crate::wire::encode_tunnel_datagram_cached(carriers.d1(), aead, aad, &packet_bytes)
        }
        CarrierBinding::D2EncryptedDatagram => {
            let carrier = carriers.d2().ok_or_else(|| {
                RuntimeError::InvalidConfig("D2 runtime carrier is not configured".to_string())
            })?;
            let crypto = outer_keys.send_for(binding)?;
            let (aead, aad) = crypto.send_parts();
            crate::wire::encode_tunnel_d2_datagram_cached(carrier, aead, aad, &packet_bytes)
        }
        _ => Err(RuntimeError::InvalidConfig(
            "unsupported runtime carrier".to_string(),
        )),
    }
}

pub(super) fn decode_client_tunnel_packet_owned(
    carriers: &RuntimeCarriers,
    _endpoint_id: &apt_types::EndpointId,
    outer_keys: &RuntimeOuterKeys,
    encapsulation: TunnelEncapsulation,
    binding: CarrierBinding,
    bytes: Vec<u8>,
) -> Result<Vec<u8>, RuntimeError> {
    decode_server_tunnel_packet_owned(carriers, outer_keys, encapsulation, binding, bytes).map_err(
        |error| {
            debug!(
                error = %error,
                carrier = %binding.as_str(),
                "failed to decode client tunnel packet"
            );
            error
        },
    )
}

pub(super) fn decode_server_tunnel_packet_owned(
    carriers: &RuntimeCarriers,
    outer_keys: &RuntimeOuterKeys,
    encapsulation: TunnelEncapsulation,
    binding: CarrierBinding,
    bytes: Vec<u8>,
) -> Result<Vec<u8>, RuntimeError> {
    if matches!(encapsulation, TunnelEncapsulation::DirectInnerOnly) {
        return Ok(bytes);
    }
    decode_server_tunnel_packet_direct(carriers, outer_keys, encapsulation, binding, &bytes)
}

pub(super) fn decode_server_tunnel_packet_direct(
    carriers: &RuntimeCarriers,
    outer_keys: &RuntimeOuterKeys,
    encapsulation: TunnelEncapsulation,
    binding: CarrierBinding,
    bytes: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    if matches!(encapsulation, TunnelEncapsulation::DirectInnerOnly) {
        return Ok(bytes.to_vec());
    }
    match binding {
        CarrierBinding::D1DatagramUdp => {
            let crypto = outer_keys.recv_for(binding)?;
            let (aead, aad) = crypto.recv_parts();
            crate::wire::decode_tunnel_datagram_cached(carriers.d1(), aead, aad, bytes)
        }
        CarrierBinding::D2EncryptedDatagram => {
            let carrier = carriers.d2().ok_or_else(|| {
                RuntimeError::InvalidConfig("D2 runtime carrier is not configured".to_string())
            })?;
            let crypto = outer_keys.recv_for(binding)?;
            let (aead, aad) = crypto.recv_parts();
            crate::wire::decode_tunnel_d2_datagram_cached(carrier, aead, aad, bytes)
        }
        _ => Err(RuntimeError::InvalidConfig(
            "unsupported runtime carrier".to_string(),
        )),
    }
}

fn runtime_d1_carrier(tunnel_mtu: u16) -> D1Carrier {
    D1Carrier::new(1_472, tunnel_mtu)
}

fn runtime_d2_carrier(tunnel_mtu: u16) -> D2Carrier {
    D2Carrier::new(crate::quic::D2_DEFAULT_RECORD_SIZE, tunnel_mtu)
}

#[derive(Clone, Copy, Debug)]
pub(super) struct RuntimeCarriers {
    d1: D1Carrier,
    d2: Option<D2Carrier>,
}

impl RuntimeCarriers {
    pub(super) fn new(tunnel_mtu: u16, enable_d2: bool) -> Self {
        Self {
            d1: runtime_d1_carrier(tunnel_mtu),
            d2: enable_d2
                .then(|| runtime_d2_carrier(tunnel_mtu.min(crate::quic::D2_DEFAULT_TUNNEL_MTU))),
        }
    }

    pub(super) fn d1(&self) -> &D1Carrier {
        &self.d1
    }

    pub(super) fn d2(&self) -> Option<&D2Carrier> {
        self.d2.as_ref()
    }
}

pub(super) fn effective_runtime_tunnel_mtu(
    configured_tunnel_mtu: u16,
    endpoint_id: &apt_types::EndpointId,
    carriers: &RuntimeCarriers,
) -> u16 {
    let mut effective =
        configured_tunnel_mtu.min(effective_d1_tunnel_mtu(endpoint_id, carriers.d1()));
    if let Some(d2) = carriers.d2() {
        effective = effective.min(effective_d2_tunnel_mtu(endpoint_id, d2));
    }
    effective
}

fn effective_d1_tunnel_mtu(endpoint_id: &apt_types::EndpointId, carrier: &D1Carrier) -> u16 {
    let outer_keys = RuntimeOuterKeys::new(
        endpoint_id,
        D1OuterKeys {
            send: [0x11; 32],
            recv: [0x22; 32],
        },
        D2OuterKeys {
            send: [0x55; 32],
            recv: [0x66; 32],
        },
    )
    .expect("fixed test keys should produce cached outer state");
    let template_session = TunnelSession::new(
        SessionId([0xAB; 16]),
        SessionRole::Initiator,
        SessionSecretsForRole {
            send_data: [0x01; 32],
            recv_data: [0x02; 32],
            send_ctrl: [0x03; 32],
            recv_ctrl: [0x04; 32],
            rekey: [0x05; 32],
            persona_seed: [0x06; 32],
            resume_secret: [0x07; 32],
        },
        apt_types::RekeyLimits::default(),
        MINIMUM_REPLAY_WINDOW as u64,
        0,
    );

    for mtu in (1..=carrier.tunnel_mtu()).rev() {
        let mut tunnel = template_session.clone();
        let frames = [Frame::IpData(vec![0_u8; usize::from(mtu)])];
        let outer = encode_server_tunnel_packet_batch(
            &RuntimeCarriers {
                d1: *carrier,
                d2: Some(runtime_d2_carrier(crate::quic::D2_DEFAULT_TUNNEL_MTU)),
            },
            endpoint_id,
            &outer_keys,
            TunnelEncapsulation::Wrapped,
            CarrierBinding::D1DatagramUdp,
            &mut tunnel,
            &frames,
            0,
        );
        if outer.is_ok() {
            return mtu;
        }
    }

    carrier.tunnel_mtu().min(1_200)
}

fn effective_d2_tunnel_mtu(endpoint_id: &apt_types::EndpointId, carrier: &D2Carrier) -> u16 {
    let outer_keys = RuntimeOuterKeys::new(
        endpoint_id,
        D1OuterKeys {
            send: [0x11; 32],
            recv: [0x22; 32],
        },
        D2OuterKeys {
            send: [0x55; 32],
            recv: [0x66; 32],
        },
    )
    .expect("fixed test keys should produce cached outer state");
    let template_session = TunnelSession::new(
        SessionId([0xAB; 16]),
        SessionRole::Initiator,
        SessionSecretsForRole {
            send_data: [0x01; 32],
            recv_data: [0x02; 32],
            send_ctrl: [0x03; 32],
            recv_ctrl: [0x04; 32],
            rekey: [0x05; 32],
            persona_seed: [0x06; 32],
            resume_secret: [0x07; 32],
        },
        apt_types::RekeyLimits::default(),
        MINIMUM_REPLAY_WINDOW as u64,
        0,
    );

    for mtu in (1..=carrier.tunnel_mtu()).rev() {
        let mut tunnel = template_session.clone();
        let frames = [Frame::IpData(vec![0_u8; usize::from(mtu)])];
        let outer = encode_server_tunnel_packet_batch(
            &RuntimeCarriers {
                d1: runtime_d1_carrier(1_380),
                d2: Some(*carrier),
            },
            endpoint_id,
            &outer_keys,
            TunnelEncapsulation::Wrapped,
            CarrierBinding::D2EncryptedDatagram,
            &mut tunnel,
            &frames,
            0,
        );
        if outer.is_ok() {
            return mtu;
        }
    }

    carrier.tunnel_mtu().min(1_000)
}
