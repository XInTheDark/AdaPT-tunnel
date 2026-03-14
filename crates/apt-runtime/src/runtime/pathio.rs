use super::*;

pub(super) async fn send_frames_on_client_path(
    carriers: &RuntimeCarriers,
    endpoint_id: &apt_types::EndpointId,
    outer_keys: &RuntimeOuterKeys,
    encapsulation: TunnelEncapsulation,
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
        return queue_path_payload(&path.sender, outer);
    }
    for batch in plan_outbound_tunnel_batches(
        carriers,
        endpoint_id,
        outer_keys,
        encapsulation,
        path.binding,
        tunnel,
        frames,
        now,
    )? {
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
    stream_peers: &HashMap<u64, ServerStreamPeer>,
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
        stream_peers,
        carriers,
        endpoint_id,
        &session.outer_keys,
        session.encapsulation,
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
    stream_peers: &HashMap<u64, ServerStreamPeer>,
    carriers: &RuntimeCarriers,
    endpoint_id: &apt_types::EndpointId,
    outer_keys: &RuntimeOuterKeys,
    encapsulation: TunnelEncapsulation,
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
        return send_outer_to_path(udp_socket, d2_peers, stream_peers, path, outer).await;
    }
    for batch in plan_outbound_tunnel_batches(
        carriers,
        endpoint_id,
        outer_keys,
        encapsulation,
        binding,
        tunnel,
        frames,
        now,
    )? {
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
        send_outer_to_path(udp_socket, d2_peers, stream_peers, path, outer).await?;
    }
    Ok(())
}

async fn send_outer_to_path(
    udp_socket: &UdpSocket,
    d2_peers: &HashMap<u64, ServerD2Peer>,
    stream_peers: &HashMap<u64, ServerStreamPeer>,
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
        PathHandle::Stream(conn_id) => {
            let Some(peer) = stream_peers.get(conn_id) else {
                return Err(RuntimeError::InvalidConfig(
                    "missing stream peer sender".to_string(),
                ));
            };
            queue_path_payload(&PathSender::Stream(peer.sender.clone()), outer)?;
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
        PathSender::Stream(tx) => tx
            .send(StreamWrite::CarrierPayload(payload))
            .map_err(|_| RuntimeError::InvalidConfig("stream path closed".to_string())),
    }
}
