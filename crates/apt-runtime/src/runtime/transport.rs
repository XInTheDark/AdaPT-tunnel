use super::*;

mod s1;

pub(super) use self::s1::{
    read_s1_payload, send_invalid_stream_response, spawn_server_tcp_listener, write_s1_payload,
};

pub(super) async fn open_client_standby_path(
    path_id: u64,
    binding: CarrierBinding,
    config: &ResolvedClientConfig,
    event_tx: mpsc::UnboundedSender<ClientTransportEvent>,
) -> Result<ClientPathState, RuntimeError> {
    match binding {
        CarrierBinding::D1DatagramUdp => {
            let socket = build_udp_socket(
                client_bind_for_remote(config.bind, config.server_addr),
                config.udp_recv_buffer_bytes,
                config.udp_send_buffer_bytes,
            )?;
            socket.connect(config.server_addr).await?;
            spawn_client_transport_path(
                path_id,
                binding,
                HandshakeTransport::Datagram(socket),
                event_tx,
            )
        }
        CarrierBinding::D2EncryptedDatagram => {
            let (endpoint, connection) = open_client_d2_connection(config).await?;
            Ok(spawn_client_d2_path(
                path_id, endpoint, connection, event_tx,
            ))
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
        HandshakeTransport::D2 {
            endpoint,
            connection,
        } => Ok(spawn_client_d2_path(
            path_id, endpoint, connection, event_tx,
        )),
        HandshakeTransport::Stream(stream) => {
            let (mut reader, mut writer) = stream.into_split();
            let (send_tx, mut send_rx) = mpsc::unbounded_channel();
            let event_tx_reader = event_tx.clone();
            let carrier = S1Carrier::conservative();
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
    if bind.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    socket.set_recv_buffer_size(recv_buffer_bytes)?;
    socket.set_send_buffer_size(send_buffer_bytes)?;
    socket.bind(&bind.into())?;
    let std_socket: std::net::UdpSocket = socket.into();
    Ok(UdpSocket::from_std(std_socket)?)
}

pub(super) fn client_bind_for_remote(bind: SocketAddr, remote: SocketAddr) -> SocketAddr {
    match (bind, remote) {
        (SocketAddr::V4(bind_v4), SocketAddr::V6(_)) if bind_v4.ip().is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), bind_v4.port())
        }
        (SocketAddr::V6(bind_v6), SocketAddr::V4(_)) if bind_v6.ip().is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), bind_v6.port())
        }
        _ => bind,
    }
}
