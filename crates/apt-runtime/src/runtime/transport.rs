use super::*;

pub(super) async fn open_client_standby_path(
    path_id: u64,
    binding: CarrierBinding,
    config: &ResolvedClientConfig,
    carriers: &RuntimeCarriers,
    event_tx: mpsc::UnboundedSender<ClientTransportEvent>,
) -> Result<ClientPathState, RuntimeError> {
    match binding {
        CarrierBinding::D1DatagramUdp => {
            let socket = build_udp_socket(
                config.bind,
                config.udp_recv_buffer_bytes,
                config.udp_send_buffer_bytes,
            )?;
            socket.connect(config.server_addr).await?;
            spawn_client_transport_path(
                path_id,
                binding,
                HandshakeTransport::Datagram(socket),
                event_tx,
                carriers,
            )
        }
        CarrierBinding::S1EncryptedStream => {
            let Some(addr) = config.stream_server_addr else {
                return Err(RuntimeError::InvalidConfig(
                    "stream_server_addr is not configured".to_string(),
                ));
            };
            let stream = TcpStream::connect(addr).await?;
            let _ = stream.set_nodelay(true);
            spawn_client_transport_path(
                path_id,
                binding,
                HandshakeTransport::Stream(stream),
                event_tx,
                carriers,
            )
        }
        _ => Err(RuntimeError::InvalidConfig(
            "unsupported standby carrier".to_string(),
        )),
    }
}

pub(super) fn spawn_client_transport_path(
    path_id: u64,
    binding: CarrierBinding,
    transport: HandshakeTransport,
    event_tx: mpsc::UnboundedSender<ClientTransportEvent>,
    carriers: &RuntimeCarriers,
) -> Result<ClientPathState, RuntimeError> {
    match transport {
        HandshakeTransport::Datagram(socket) => {
            let socket = Arc::new(socket);
            let (send_tx, mut send_rx) = mpsc::unbounded_channel::<Vec<u8>>();
            let reader_socket = socket.clone();
            let writer_socket = socket.clone();
            let event_tx_reader = event_tx.clone();
            tokio::spawn(async move {
                let mut recv_buf = vec![0_u8; DATAGRAM_BUFFER_SIZE];
                loop {
                    match reader_socket.recv(&mut recv_buf).await {
                        Ok(len) => {
                            if event_tx_reader
                                .send(ClientTransportEvent::Inbound {
                                    path_id,
                                    bytes: recv_buf[..len].to_vec(),
                                })
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(_) => {
                            let _ = event_tx_reader.send(ClientTransportEvent::Closed {
                                path_id,
                                reason: "udp closed",
                            });
                            break;
                        }
                    }
                }
            });
            tokio::spawn(async move {
                while let Some(bytes) = send_rx.recv().await {
                    if writer_socket.send(&bytes).await.is_err() {
                        break;
                    }
                }
            });
            Ok(ClientPathState {
                id: path_id,
                binding,
                sender: PathSender::Datagram(send_tx),
                validated: true,
                pending_probe_challenge: None,
                last_send_secs: now_secs(),
                last_recv_secs: now_secs(),
            })
        }
        HandshakeTransport::Stream(stream) => {
            let (mut reader, mut writer) = stream.into_split();
            let (send_tx, mut send_rx) = mpsc::unbounded_channel();
            let event_tx_reader = event_tx.clone();
            let carrier = *carriers.s1();
            tokio::spawn(async move {
                loop {
                    match read_s1_payload(&mut reader, &carrier).await {
                        Ok(bytes) => {
                            if event_tx_reader
                                .send(ClientTransportEvent::Inbound { path_id, bytes })
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(_) => {
                            let _ = event_tx_reader.send(ClientTransportEvent::Closed {
                                path_id,
                                reason: "stream closed",
                            });
                            break;
                        }
                    }
                }
            });
            tokio::spawn(async move {
                while let Some(write) = send_rx.recv().await {
                    let result = match write {
                        StreamWrite::CarrierPayload(payload) => {
                            write_s1_payload(&mut writer, &carrier, &payload).await
                        }
                        StreamWrite::Raw(bytes) => {
                            writer.write_all(&bytes).await.map_err(RuntimeError::from)
                        }
                    };
                    if result.is_err() {
                        break;
                    }
                }
                let _ = writer.shutdown().await;
            });
            Ok(ClientPathState {
                id: path_id,
                binding,
                sender: PathSender::Stream(send_tx),
                validated: true,
                pending_probe_challenge: None,
                last_send_secs: now_secs(),
                last_recv_secs: now_secs(),
            })
        }
    }
}

pub(super) fn spawn_server_udp_receiver(
    socket: Arc<UdpSocket>,
    tx: mpsc::UnboundedSender<ServerTransportEvent>,
) {
    tokio::spawn(async move {
        let mut recv_buf = vec![0_u8; DATAGRAM_BUFFER_SIZE];
        loop {
            match socket.recv_from(&mut recv_buf).await {
                Ok((len, peer_addr)) => {
                    if tx
                        .send(ServerTransportEvent::Datagram {
                            peer_addr,
                            bytes: recv_buf[..len].to_vec(),
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                Err(error) => {
                    warn!(error = %error, "udp receiver stopped");
                    break;
                }
            }
        }
    });
}

pub(super) fn spawn_server_tcp_listener(
    listener: TcpListener,
    tx: mpsc::UnboundedSender<ServerTransportEvent>,
    carrier: &S1Carrier,
) {
    let carrier = *carrier;
    tokio::spawn(async move {
        let mut next_conn_id = 1_u64;
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let conn_id = next_conn_id;
                    next_conn_id = next_conn_id.saturating_add(1);
                    let (send_tx, mut send_rx) = mpsc::unbounded_channel();
                    if tx
                        .send(ServerTransportEvent::StreamOpened {
                            conn_id,
                            peer_addr,
                            sender: send_tx.clone(),
                        })
                        .is_err()
                    {
                        break;
                    }
                    let (mut reader, mut writer) = stream.into_split();
                    let tx_reader = tx.clone();
                    tokio::spawn(async move {
                        loop {
                            match read_s1_payload(&mut reader, &carrier).await {
                                Ok(bytes) => {
                                    if tx_reader
                                        .send(ServerTransportEvent::StreamRecord { conn_id, bytes })
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                Err(error) => {
                                    let malformed = error.kind() == io::ErrorKind::InvalidData;
                                    let _ = tx_reader.send(ServerTransportEvent::StreamClosed {
                                        conn_id,
                                        malformed,
                                    });
                                    break;
                                }
                            }
                        }
                    });
                    tokio::spawn(async move {
                        while let Some(write) = send_rx.recv().await {
                            let result = match write {
                                StreamWrite::CarrierPayload(payload) => {
                                    write_s1_payload(&mut writer, &carrier, &payload).await
                                }
                                StreamWrite::Raw(bytes) => {
                                    writer.write_all(&bytes).await.map_err(RuntimeError::from)
                                }
                            };
                            if result.is_err() {
                                break;
                            }
                        }
                        let _ = writer.shutdown().await;
                    });
                }
                Err(error) => {
                    warn!(error = %error, "tcp listener stopped");
                    break;
                }
            }
        }
    });
}

pub(super) fn send_invalid_stream_response(
    stream_peers: &HashMap<u64, ServerStreamPeer>,
    conn_id: u64,
    decoy_surface: bool,
) -> Result<(), RuntimeError> {
    let Some(peer) = stream_peers.get(&conn_id) else {
        return Ok(());
    };
    peer.sender
        .send(StreamWrite::Raw(if decoy_surface {
            decoy_http_response().into_bytes()
        } else {
            generic_http_failure().as_bytes().to_vec()
        }))
        .map_err(|_| RuntimeError::InvalidConfig("stream response channel closed".to_string()))
}

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

pub(super) async fn send_frames_to_server_path(
    udp_socket: &UdpSocket,
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
        return send_outer_to_path(udp_socket, stream_peers, path, outer).await;
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
        send_outer_to_path(udp_socket, stream_peers, path, outer).await?;
    }
    Ok(())
}

async fn send_outer_to_path(
    udp_socket: &UdpSocket,
    stream_peers: &HashMap<u64, ServerStreamPeer>,
    path: &PathHandle,
    outer: Vec<u8>,
) -> Result<(), RuntimeError> {
    match path {
        PathHandle::Datagram(peer_addr) => {
            udp_socket.send_to(&outer, peer_addr).await?;
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

pub(super) fn queue_path_payload(sender: &PathSender, payload: Vec<u8>) -> Result<(), RuntimeError> {
    match sender {
        PathSender::Datagram(tx) => tx
            .send(payload)
            .map_err(|_| RuntimeError::InvalidConfig("datagram path closed".to_string())),
        PathSender::Stream(tx) => tx
            .send(StreamWrite::CarrierPayload(payload))
            .map_err(|_| RuntimeError::InvalidConfig("stream path closed".to_string())),
    }
}

pub(super) fn build_udp_socket(
    bind: SocketAddr,
    recv_buffer_bytes: usize,
    send_buffer_bytes: usize,
) -> Result<UdpSocket, RuntimeError> {
    let domain = match bind {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.set_recv_buffer_size(recv_buffer_bytes)?;
    socket.set_send_buffer_size(send_buffer_bytes)?;
    socket.bind(&bind.into())?;
    let std_socket: std::net::UdpSocket = socket.into();
    Ok(UdpSocket::from_std(std_socket)?)
}

pub(super) async fn write_s1_payload<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    carrier: &S1Carrier,
    payload: &[u8],
) -> Result<(), RuntimeError> {
    let mut records = carrier.encode_records(payload)?;
    let record = records
        .drain(..)
        .next()
        .ok_or(RuntimeError::Carrier(CarrierError::MalformedRecord))?;
    writer.write_all(&record).await?;
    Ok(())
}

pub(super) async fn read_s1_payload<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    carrier: &S1Carrier,
) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header).await?;
    let len = u16::from_be_bytes(header) as usize;
    if len == 0 || len > usize::from(carrier.max_record_size()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed stream record",
        ));
    }
    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

fn generic_http_failure() -> &'static str {
    "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
}

fn decoy_http_response() -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
        STREAM_DECOY_BODY.len(),
        STREAM_DECOY_BODY,
    )
}
