use super::*;

pub(super) async fn send_frames_on_client_path(
    carriers: &RuntimeCarriers,
    endpoint_id: &apt_types::EndpointId,
    outer_keys: &RuntimeOuterKeys,
    encapsulation: TunnelEncapsulation,
    adaptive: &AdaptiveDatapath,
    path: &ClientPathState,
    tunnel: &mut TunnelSession,
    frames: &[Frame],
    now: u64,
) -> Result<(), RuntimeError> {
    if let Ok(outer) = encode_client_tunnel_packet_batch(
        carriers,
        endpoint_id,
        outer_keys,
        encapsulation,
        path.binding,
        tunnel,
        frames,
        now,
    ) {
        maybe_apply_pacing_delay(adaptive, path.binding, frames, 1, 0, now).await;
        return queue_path_payload(&path.sender, outer);
    }
    let batches = plan_outbound_tunnel_batches(
        carriers,
        endpoint_id,
        outer_keys,
        encapsulation,
        path.binding,
        tunnel,
        frames,
        now,
    )?;
    let batch_count = batches.len();
    for (index, batch) in batches.into_iter().enumerate() {
        maybe_apply_pacing_delay(adaptive, path.binding, &batch, batch_count, index, now).await;
        let outer = encode_client_tunnel_packet_batch(
            carriers,
            endpoint_id,
            outer_keys,
            encapsulation,
            path.binding,
            tunnel,
            &batch,
            now,
        )?;
        queue_path_payload(&path.sender, outer)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn send_frames_to_server_path(
    udp_socket: &UdpSocket,
    d2_peers: &HashMap<u64, ServerD2Peer>,
    carriers: &RuntimeCarriers,
    endpoint_id: &apt_types::EndpointId,
    session: &mut ServerSessionState,
    path: PathHandle,
    binding: CarrierBinding,
    frames: &[Frame],
    now: u64,
) -> Result<(), RuntimeError> {
    send_frames_to_path_handle(
        udp_socket,
        d2_peers,
        carriers,
        endpoint_id,
        &session.outer_keys,
        session.encapsulation,
        Some(&session.adaptive),
        &path,
        binding,
        &mut session.tunnel,
        frames,
        now,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn send_frames_to_path_handle(
    udp_socket: &UdpSocket,
    d2_peers: &HashMap<u64, ServerD2Peer>,
    carriers: &RuntimeCarriers,
    endpoint_id: &apt_types::EndpointId,
    outer_keys: &RuntimeOuterKeys,
    encapsulation: TunnelEncapsulation,
    adaptive: Option<&AdaptiveDatapath>,
    path: &PathHandle,
    binding: CarrierBinding,
    tunnel: &mut TunnelSession,
    frames: &[Frame],
    now: u64,
) -> Result<(), RuntimeError> {
    if let Ok(outer) = encode_server_tunnel_packet_batch(
        carriers,
        endpoint_id,
        outer_keys,
        encapsulation,
        binding,
        tunnel,
        frames,
        now,
    ) {
        if let Some(adaptive) = adaptive {
            maybe_apply_pacing_delay(adaptive, binding, frames, 1, 0, now).await;
        }
        return send_outer_to_path(udp_socket, d2_peers, path, outer).await;
    }
    let batches = plan_outbound_tunnel_batches(
        carriers,
        endpoint_id,
        outer_keys,
        encapsulation,
        binding,
        tunnel,
        frames,
        now,
    )?;
    let batch_count = batches.len();
    for (index, batch) in batches.into_iter().enumerate() {
        if let Some(adaptive) = adaptive {
            maybe_apply_pacing_delay(adaptive, binding, &batch, batch_count, index, now).await;
        }
        let outer = encode_server_tunnel_packet_batch(
            carriers,
            endpoint_id,
            outer_keys,
            encapsulation,
            binding,
            tunnel,
            &batch,
            now,
        )?;
        send_outer_to_path(udp_socket, d2_peers, path, outer).await?;
    }
    Ok(())
}

async fn maybe_apply_pacing_delay(
    adaptive: &AdaptiveDatapath,
    binding: CarrierBinding,
    frames: &[Frame],
    batch_count: usize,
    batch_index: usize,
    now_secs: u64,
) {
    let delay_ms = adaptive.pacing_delay_ms(
        binding,
        frames,
        batch_count,
        batch_index,
        now_secs.saturating_mul(1_000),
    );
    if delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(u64::from(delay_ms))).await;
    }
}

async fn send_outer_to_path(
    udp_socket: &UdpSocket,
    d2_peers: &HashMap<u64, ServerD2Peer>,
    path: &PathHandle,
    outer: Vec<u8>,
) -> Result<(), RuntimeError> {
    match path {
        PathHandle::Datagram(peer_addr) => {
            udp_socket.send_to(&outer, peer_addr).await?;
        }
        PathHandle::D2(conn_id) => {
            let Some(peer) = d2_peers.get(conn_id) else {
                return Err(RuntimeError::InvalidConfig(
                    "missing D2 peer sender".to_string(),
                ));
            };
            queue_path_payload(&PathSender::D2(peer.sender.clone()), outer)?;
        }
    }
    Ok(())
}

pub(super) fn queue_path_payload(
    sender: &PathSender,
    payload: Vec<u8>,
) -> Result<(), RuntimeError> {
    match sender {
        PathSender::Datagram(tx) => tx
            .send(payload)
            .map_err(|_| RuntimeError::InvalidConfig("datagram path closed".to_string())),
        PathSender::D2(tx) => tx
            .send(payload)
            .map_err(|_| RuntimeError::InvalidConfig("D2 path closed".to_string())),
    }
}

pub(super) fn is_path_sender_unavailable(error: &RuntimeError) -> bool {
    matches!(
        error,
        RuntimeError::InvalidConfig(message)
            if matches!(
                message.as_str(),
                "missing D2 peer sender"
                    | "datagram path closed"
                    | "D2 path closed"
            )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_missing_or_closed_path_senders_as_soft_failures() {
        assert!(is_path_sender_unavailable(&RuntimeError::InvalidConfig(
            "missing D2 peer sender".to_string(),
        )));
        assert!(is_path_sender_unavailable(&RuntimeError::InvalidConfig(
            "D2 path closed".to_string(),
        )));

        assert!(!is_path_sender_unavailable(&RuntimeError::InvalidConfig(
            "bad bundle".to_string(),
        )));
        assert!(!is_path_sender_unavailable(&RuntimeError::Timeout(
            "live session"
        )));
    }
}
