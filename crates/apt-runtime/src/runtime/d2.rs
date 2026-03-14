use super::*;
use crate::quic::{
    build_d2_client_config, build_d2_server_config, ensure_d2_datagram_support,
    load_certificate_chain, load_private_key,
};
use bytes::Bytes;

pub(super) async fn open_client_d2_connection(
    config: &ResolvedClientConfig,
) -> Result<(quinn::Endpoint, quinn::Connection), RuntimeError> {
    let d2 = config.d2.as_ref().ok_or_else(|| {
        RuntimeError::InvalidConfig("D2 was requested, but it is not configured".to_string())
    })?;
    let client_config = build_d2_client_config(
        d2.server_certificate_der.clone(),
        config.session_idle_timeout_secs,
    )?;
    let endpoint = build_client_d2_endpoint(
        config.bind,
        config.udp_recv_buffer_bytes,
        config.udp_send_buffer_bytes,
        client_config,
    )?;
    let connection = endpoint
        .connect(d2.endpoint.addr, &d2.endpoint.server_name)
        .map_err(|error| RuntimeError::Quic(error.to_string()))?
        .await
        .map_err(|error| RuntimeError::Quic(error.to_string()))?;
    ensure_d2_datagram_support(&connection)?;
    Ok((endpoint, connection))
}

pub(super) fn spawn_client_d2_path(
    path_id: u64,
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    event_tx: mpsc::UnboundedSender<ClientTransportEvent>,
) -> ClientPathState {
    let (send_tx, mut send_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        let _endpoint_guard = endpoint;
        loop {
            tokio::select! {
                maybe_bytes = send_rx.recv() => {
                    match maybe_bytes {
                        Some(bytes) => {
                            if connection
                                .send_datagram_wait(Bytes::from(bytes))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                inbound = connection.read_datagram() => {
                    match inbound {
                        Ok(bytes) => {
                            if event_tx
                                .send(ClientTransportEvent::Inbound {
                                    path_id,
                                    bytes: bytes.to_vec(),
                                })
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        let _ = event_tx.send(ClientTransportEvent::Closed {
            path_id,
            reason: "d2 closed",
        });
        connection.close(0u32.into(), b"path closed");
    });

    ClientPathState {
        id: path_id,
        binding: CarrierBinding::D2EncryptedDatagram,
        sender: PathSender::D2(send_tx),
        validated: true,
        pending_probe_challenge: None,
        last_send_secs: now_secs(),
        last_recv_secs: now_secs(),
    }
}

pub(super) fn build_server_d2_endpoint(
    config: &ResolvedServerConfig,
) -> Result<Option<quinn::Endpoint>, RuntimeError> {
    let Some(d2) = config.d2.as_ref() else {
        return Ok(None);
    };
    let socket = build_quic_udp_socket(
        d2.bind,
        config.udp_recv_buffer_bytes,
        config.udp_send_buffer_bytes,
    )?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| RuntimeError::Quic("no async runtime found".to_string()))?;
    let server_config = build_d2_server_config(
        load_certificate_chain(&d2.certificate_spec)?,
        load_private_key(&d2.private_key_spec)?,
        config.session_idle_timeout_secs,
    )?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        runtime,
    )
    .map_err(|error| RuntimeError::Quic(error.to_string()))?;
    Ok(Some(endpoint))
}

pub(super) fn spawn_server_d2_listener(
    endpoint: quinn::Endpoint,
    tx: mpsc::UnboundedSender<ServerTransportEvent>,
) {
    tokio::spawn(async move {
        let mut next_conn_id = 1_u64;
        while let Some(incoming) = endpoint.accept().await {
            let conn_id = next_conn_id;
            next_conn_id = next_conn_id.saturating_add(1);
            let tx_connection = tx.clone();
            tokio::spawn(async move {
                match incoming.await {
                    Ok(connection) => {
                        if ensure_d2_datagram_support(&connection).is_err() {
                            connection.close(0u32.into(), b"d2 datagrams unavailable");
                            return;
                        }
                        let peer_addr = connection.remote_address();
                        let (send_tx, mut send_rx) = mpsc::unbounded_channel::<Vec<u8>>();
                        if tx_connection
                            .send(ServerTransportEvent::D2Opened {
                                conn_id,
                                peer_addr,
                                sender: send_tx,
                            })
                            .is_err()
                        {
                            connection.close(0u32.into(), b"runtime stopped");
                            return;
                        }

                        loop {
                            tokio::select! {
                                maybe_bytes = send_rx.recv() => {
                                    match maybe_bytes {
                                        Some(bytes) => {
                                            if connection
                                                .send_datagram_wait(Bytes::from(bytes))
                                                .await
                                                .is_err()
                                            {
                                                break;
                                            }
                                        }
                                        None => break,
                                    }
                                }
                                inbound = connection.read_datagram() => {
                                    match inbound {
                                        Ok(bytes) => {
                                            if tx_connection
                                                .send(ServerTransportEvent::D2Datagram {
                                                    conn_id,
                                                    bytes: bytes.to_vec(),
                                                })
                                                .is_err()
                                            {
                                                break;
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                            }
                        }

                        let _ = tx_connection.send(ServerTransportEvent::D2Closed { conn_id });
                        connection.close(0u32.into(), b"listener closed");
                    }
                    Err(error) => {
                        warn!(error = %error, "d2 listener handshake failed");
                    }
                }
            });
        }
    });
}

fn build_client_d2_endpoint(
    bind: SocketAddr,
    recv_buffer_bytes: usize,
    send_buffer_bytes: usize,
    client_config: quinn::ClientConfig,
) -> Result<quinn::Endpoint, RuntimeError> {
    let socket = build_quic_udp_socket(bind, recv_buffer_bytes, send_buffer_bytes)?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| RuntimeError::Quic("no async runtime found".to_string()))?;
    let mut endpoint =
        quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
            .map_err(|error| RuntimeError::Quic(error.to_string()))?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

fn build_quic_udp_socket(
    bind: SocketAddr,
    recv_buffer_bytes: usize,
    send_buffer_bytes: usize,
) -> Result<std::net::UdpSocket, RuntimeError> {
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
    Ok(socket.into())
}
