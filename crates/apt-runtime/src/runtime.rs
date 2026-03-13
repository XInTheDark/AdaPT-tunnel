use crate::{
    config::{
        ClientPersistentState, ResolvedAuthorizedPeer, ResolvedClientConfig, ResolvedServerConfig,
        ServerSessionExtension, SessionTransportParameters,
    },
    error::RuntimeError,
    route::{configure_client_network, configure_server_network},
    status::{ClientStatus, RuntimeStatus, ServerStatus},
    tun::{spawn_tun_worker, TunHandle, TunInterfaceConfig},
};
use apt_admission::{
    initiate_c0, AdmissionConfig, AdmissionPacket, AdmissionServer, AdmissionServerSecrets,
    ClientCredential, ClientSessionRequest, CredentialStore, EstablishedSession, ServerConfirmationPacket,
    ServerResponse, AdmissionError,
};
use apt_carriers::D1Carrier;
use apt_crypto::{SealedEnvelope, StaticKeypair};
use apt_observability::{record_event, AptEvent, ObservabilityConfig, TelemetrySnapshot};
use apt_tunnel::{Frame, RekeyStatus, TunnelSession};
use apt_types::{
    AuthProfile, CarrierBinding, CredentialIdentity, SessionRole, MINIMUM_REPLAY_WINDOW,
};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, SystemTime},
};
use tokio::{
    net::UdpSocket,
    sync::mpsc,
    time::{interval, timeout},
};
use tracing::{debug, info};

const DATAGRAM_BUFFER_SIZE: usize = 65_535;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientRuntimeResult {
    pub status: ClientStatus,
    pub telemetry: TelemetrySnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerRuntimeResult {
    pub status: ServerStatus,
    pub telemetry: TelemetrySnapshot,
}

#[derive(Debug)]
struct ServerSessionState {
    peer_addr: SocketAddr,
    assigned_ipv4: Ipv4Addr,
    tunnel: TunnelSession,
    last_send_secs: u64,
    last_recv_secs: u64,
}

pub async fn run_client(config: ResolvedClientConfig) -> Result<ClientRuntimeResult, RuntimeError> {
    let observability = ObservabilityConfig::default();
    let mut telemetry = TelemetrySnapshot::new("apt-client");
    let carrier = D1Carrier::conservative();
    let socket = build_udp_socket(config.bind, config.udp_recv_buffer_bytes, config.udp_send_buffer_bytes)?;
    socket.connect(config.server_addr).await?;

    let mut persistent_state = ClientPersistentState::load(&config.state_path)?;
    persistent_state.last_status = Some(RuntimeStatus::Starting);
    persistent_state.store(&config.state_path)?;

    let established = perform_client_handshake(&socket, &config, &mut persistent_state, &carrier).await?;
    let transport = extract_tunnel_parameters(&established)?;
    let tun = spawn_tun_worker(TunInterfaceConfig {
        name: config.interface_name.clone(),
        local_ipv4: transport.client_ipv4,
        peer_ipv4: transport.server_ipv4,
        netmask: transport.netmask,
        mtu: transport.mtu,
    })
    .await?;

    let effective_routes = if config.use_server_pushed_routes && !transport.routes.is_empty() {
        transport.routes.clone()
    } else {
        config.routes.clone()
    };
    let _route_guard = configure_client_network(&tun.interface_name, config.server_addr, &effective_routes)?;

    let credential_label = redact_credential(&established.credential_identity);
    record_event(
        &mut telemetry,
        &AptEvent::AdmissionAccepted {
            session_id: established.session_id,
            carrier: established.chosen_carrier,
            credential_identity: credential_label,
        },
        None,
        &observability,
    );
    record_event(
        &mut telemetry,
        &AptEvent::TunnelEstablished {
            session_id: established.session_id,
            carrier: established.chosen_carrier,
            mode: established.policy_mode,
        },
        None,
        &observability,
    );

    let status = run_client_session_loop(&socket, &config, tun, established, transport, &mut persistent_state).await?;
    persistent_state.last_status = Some(status.status.clone());
    persistent_state.store(&config.state_path)?;
    Ok(ClientRuntimeResult { status, telemetry })
}

pub async fn run_server(config: ResolvedServerConfig) -> Result<ServerRuntimeResult, RuntimeError> {
    let observability = ObservabilityConfig::default();
    let mut telemetry = TelemetrySnapshot::new("apt-edge");
    let carrier = D1Carrier::conservative();
    let socket = build_udp_socket(config.bind, config.udp_recv_buffer_bytes, config.udp_send_buffer_bytes)?;
    let tun = spawn_tun_worker(TunInterfaceConfig {
        name: config.interface_name.clone(),
        local_ipv4: config.tunnel_local_ipv4,
        peer_ipv4: config.tunnel_local_ipv4,
        netmask: config.tunnel_netmask,
        mtu: config.tunnel_mtu,
    })
    .await?;
    let _server_net_guard = configure_server_network(&tun.interface_name, &config)?;

    let mut credentials = CredentialStore::default();
    credentials.set_shared_deployment_key(config.admission_key);
    let mut admission = AdmissionServer::new(
        admission_config(&config),
        credentials,
        AdmissionServerSecrets {
            static_keypair: StaticKeypair {
                private: config.server_static_private_key,
                public: config.server_static_public_key,
            },
            cookie_key: config.cookie_key,
            ticket_key: config.ticket_key,
        },
    );

    let mut sessions_by_addr: HashMap<SocketAddr, ServerSessionState> = HashMap::new();
    let mut sessions_by_client_ip: HashMap<Ipv4Addr, SocketAddr> = HashMap::new();
    let mut recv_buf = vec![0_u8; DATAGRAM_BUFFER_SIZE];
    let mut tick = interval(Duration::from_secs(1));
    let mut tun_rx = tun.inbound_rx;
    let tun_tx = tun.outbound_tx.clone();

    loop {
        tokio::select! {
            recv = socket.recv_from(&mut recv_buf) => {
                let (len, peer_addr) = recv?;
                let bytes = &recv_buf[..len];
                let now = now_secs();
                if let Some(session) = sessions_by_addr.get_mut(&peer_addr) {
                    if process_server_tunnel_packet(
                        &socket,
                        session,
                        bytes,
                        now,
                        &tun_tx,
                    ).await? {
                        continue;
                    }
                }

                if let Ok(packet) = bincode::deserialize::<AdmissionPacket>(bytes) {
                    if handle_server_admission_packet(
                        &socket,
                        &mut admission,
                        &config,
                        &carrier,
                        peer_addr,
                        len,
                        packet,
                        &mut sessions_by_addr,
                        &mut sessions_by_client_ip,
                        &mut telemetry,
                        &observability,
                    )
                    .await?
                    {
                        continue;
                    }
                }
            }
            tun_packet = tun_rx.recv() => {
                if let Some(packet) = tun_packet {
                    if let Some(destination) = extract_destination_ipv4(&packet) {
                        if let Some(peer_addr) = sessions_by_client_ip.get(&destination).copied() {
                            if let Some(session) = sessions_by_addr.get_mut(&peer_addr) {
                                send_frames_to_peer(&socket, peer_addr, &mut session.tunnel, &[Frame::IpData(packet)], now_secs()).await?;
                                session.last_send_secs = now_secs();
                            }
                        }
                    }
                } else {
                    break;
                }
            }
            _ = tick.tick() => {
                let now = now_secs();
                let mut expired = Vec::new();
                for (peer_addr, session) in &mut sessions_by_addr {
                    if now.saturating_sub(session.last_recv_secs) > config.session_idle_timeout_secs {
                        expired.push(*peer_addr);
                        continue;
                    }
                    let mut frames = session.tunnel.collect_due_control_frames(now);
                    if now.saturating_sub(session.last_send_secs) >= config.keepalive_secs {
                        frames.push(Frame::Ping);
                    }
                    match session.tunnel.rekey_status(now) {
                        RekeyStatus::SoftLimitReached => {
                            if let Ok(frame) = session.tunnel.initiate_rekey(now) {
                                frames.push(frame);
                            }
                        }
                        RekeyStatus::HardLimitReached => {
                            expired.push(*peer_addr);
                        }
                        RekeyStatus::Healthy => {}
                    }
                    if !frames.is_empty() {
                        send_frames_to_peer(&socket, *peer_addr, &mut session.tunnel, &frames, now).await?;
                        session.last_send_secs = now;
                    }
                }
                for peer_addr in expired {
                    if let Some(removed) = sessions_by_addr.remove(&peer_addr) {
                        sessions_by_client_ip.remove(&removed.assigned_ipv4);
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown requested");
                break;
            }
        }
    }

    Ok(ServerRuntimeResult {
        status: ServerStatus {
            bind: config.bind.to_string(),
            interface_name: Some(tun.interface_name),
            active_sessions: sessions_by_addr.len(),
        },
        telemetry,
    })
}

async fn perform_client_handshake(
    socket: &UdpSocket,
    config: &ResolvedClientConfig,
    persistent_state: &mut ClientPersistentState,
    carrier: &D1Carrier,
) -> Result<EstablishedSession, RuntimeError> {
    let resume_ticket = persistent_state
        .resume_ticket
        .as_ref()
        .map(|bytes| bincode::deserialize::<SealedEnvelope>(bytes))
        .transpose()?;

    for _attempt in 0..config.handshake_retries {
        let now = now_secs();
        let credential = ClientCredential {
            auth_profile: AuthProfile::SharedDeployment,
            user_id: config.client_identity.clone(),
            client_static_private: Some(config.client_static_private_key),
            admission_key: config.admission_key,
            server_static_public: config.server_static_public_key,
            enable_lookup_hint: false,
        };
        let mut request = ClientSessionRequest::conservative(config.endpoint_id.clone(), now);
        request.preferred_carrier = CarrierBinding::D1DatagramUdp;
        request.supported_carriers = vec![CarrierBinding::D1DatagramUdp];
        request.resume_ticket = resume_ticket.clone();
        let prepared_c0 = initiate_c0(credential, request, carrier)?;
        let c0_bytes = bincode::serialize(&prepared_c0.packet)?;
        socket.send(&c0_bytes).await?;

        let mut recv_buf = vec![0_u8; DATAGRAM_BUFFER_SIZE];
        let s1_bytes = timeout(Duration::from_secs(config.handshake_timeout_secs), socket.recv(&mut recv_buf))
            .await
            .map_err(|_| RuntimeError::Timeout("S1"))??;
        let s1: AdmissionPacket = bincode::deserialize(&recv_buf[..s1_bytes])?;
        let prepared_c2 = prepared_c0.state.handle_s1(&s1, carrier)?;
        let c2_bytes = bincode::serialize(&prepared_c2.packet)?;
        socket.send(&c2_bytes).await?;

        let s3_bytes = timeout(Duration::from_secs(config.handshake_timeout_secs), socket.recv(&mut recv_buf))
            .await
            .map_err(|_| RuntimeError::Timeout("S3"))??;
        let s3: ServerConfirmationPacket = bincode::deserialize(&recv_buf[..s3_bytes])?;
        let session = prepared_c2.state.handle_s3(&s3, carrier)?;
        persistent_state.resume_ticket = session
            .resume_ticket
            .as_ref()
            .map(bincode::serialize)
            .transpose()?;
        persistent_state.store(&config.state_path)?;
        return Ok(session);
    }

    Err(RuntimeError::Timeout("admission handshake"))
}

async fn run_client_session_loop(
    socket: &UdpSocket,
    config: &ResolvedClientConfig,
    tun: TunHandle,
    established: EstablishedSession,
    transport: SessionTransportParameters,
    persistent_state: &mut ClientPersistentState,
) -> Result<ClientStatus, RuntimeError> {
    let mut tunnel = TunnelSession::new(
        established.session_id,
        SessionRole::Initiator,
        established.secrets,
        established.rekey_limits,
        MINIMUM_REPLAY_WINDOW as u64,
        now_secs(),
    );
    let mut recv_buf = vec![0_u8; DATAGRAM_BUFFER_SIZE];
    let mut tick = interval(Duration::from_secs(1));
    let mut tun_rx = tun.inbound_rx;
    let tun_tx = tun.outbound_tx.clone();
    let mut last_send_secs = now_secs();
    let mut last_recv_secs = now_secs();

    loop {
        tokio::select! {
            recv = socket.recv(&mut recv_buf) => {
                let len = recv?;
                let decoded = tunnel.decode_packet(&recv_buf[..len], now_secs())?;
                last_recv_secs = now_secs();
                for frame in decoded.frames {
                    match frame {
                        Frame::IpData(packet) => {
                            let _ = tun_tx.send(packet).await;
                        }
                        Frame::Close { .. } => {
                            let status = ClientStatus::new(
                                RuntimeStatus::Disconnected,
                                config.server_addr.to_string(),
                                Some(IpAddr::V4(transport.client_ipv4)),
                                Some(tun.interface_name.clone()),
                            );
                            persistent_state.last_status = Some(status.status.clone());
                            persistent_state.store(&config.state_path)?;
                            return Ok(status);
                        }
                        _ => {}
                    }
                }
                if !decoded.ack_suggestions.is_empty() {
                    send_frames_connected(socket, &mut tunnel, &decoded.ack_suggestions, now_secs()).await?;
                    last_send_secs = now_secs();
                }
            }
            packet = tun_rx.recv() => {
                match packet {
                    Some(packet) => {
                        send_frames_connected(socket, &mut tunnel, &[Frame::IpData(packet)], now_secs()).await?;
                        last_send_secs = now_secs();
                    }
                    None => break,
                }
            }
            _ = tick.tick() => {
                let now = now_secs();
                if now.saturating_sub(last_recv_secs) > config.session_idle_timeout_secs {
                    return Err(RuntimeError::Timeout("live session"));
                }
                let mut frames = tunnel.collect_due_control_frames(now);
                if now.saturating_sub(last_send_secs) >= config.keepalive_secs {
                    frames.push(Frame::Ping);
                }
                match tunnel.rekey_status(now) {
                    RekeyStatus::SoftLimitReached => {
                        if let Ok(frame) = tunnel.initiate_rekey(now) {
                            frames.push(frame);
                        }
                    }
                    RekeyStatus::HardLimitReached => {
                        return Err(RuntimeError::Timeout("rekey hard limit reached"));
                    }
                    RekeyStatus::Healthy => {}
                }
                if !frames.is_empty() {
                    send_frames_connected(socket, &mut tunnel, &frames, now).await?;
                    last_send_secs = now;
                }
            }
            _ = tokio::signal::ctrl_c() => {
                break;
            }
        }
    }

    let status = ClientStatus::new(
        RuntimeStatus::Disconnected,
        config.server_addr.to_string(),
        Some(IpAddr::V4(transport.client_ipv4)),
        Some(tun.interface_name),
    );
    persistent_state.last_status = Some(status.status.clone());
    Ok(status)
}

async fn process_server_tunnel_packet(
    socket: &UdpSocket,
    session: &mut ServerSessionState,
    bytes: &[u8],
    now: u64,
    tun_tx: &mpsc::Sender<Vec<u8>>,
) -> Result<bool, RuntimeError> {
    match session.tunnel.decode_packet(bytes, now) {
        Ok(decoded) => {
            session.last_recv_secs = now;
            for frame in decoded.frames {
                match frame {
                    Frame::IpData(packet) => {
                        let _ = tun_tx.send(packet).await;
                    }
                    Frame::Close { .. } => {
                        return Ok(false);
                    }
                    _ => {}
                }
            }
            if !decoded.ack_suggestions.is_empty() {
                send_frames_to_peer(socket, session.peer_addr, &mut session.tunnel, &decoded.ack_suggestions, now).await?;
                session.last_send_secs = now;
            }
            Ok(true)
        }
        Err(error) => {
            debug!(error = %error, peer = %session.peer_addr, "failed to decode tunnel packet; attempting admission parse");
            Ok(false)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_server_admission_packet(
    socket: &UdpSocket,
    admission: &mut AdmissionServer,
    config: &ResolvedServerConfig,
    carrier: &D1Carrier,
    peer_addr: SocketAddr,
    received_len: usize,
    packet: AdmissionPacket,
    sessions_by_addr: &mut HashMap<SocketAddr, ServerSessionState>,
    sessions_by_client_ip: &mut HashMap<Ipv4Addr, SocketAddr>,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
) -> Result<bool, RuntimeError> {
    match admission.handle_c0(&peer_addr.to_string(), carrier, &packet, received_len, now_secs()) {
        ServerResponse::Reply(reply) => {
            let bytes = bincode::serialize(&reply)?;
            socket.send_to(&bytes, peer_addr).await?;
            return Ok(true);
        }
        ServerResponse::Drop(_) => {}
    }

    let server_reply = match admission.handle_c2_with_extension_builder(
        &peer_addr.to_string(),
        carrier,
        &packet,
        now_secs(),
        |session| {
            let peer = authorize_established_session(config, session)
                .map_err(|_| AdmissionError::Validation("unauthorized peer"))?;
            Ok(vec![bincode::serialize(&ServerSessionExtension::TunnelParameters(
                assign_transport_parameters(config, peer),
            ))?])
        },
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => return Ok(false),
    };

    let peer = authorize_established_session(config, &server_reply.session)?;
    let bytes = bincode::serialize(&server_reply.packet)?;
    socket.send_to(&bytes, peer_addr).await?;

    if let Some(existing_addr) = sessions_by_client_ip.insert(peer.tunnel_ipv4, peer_addr) {
        sessions_by_addr.remove(&existing_addr);
    }
    let tunnel = TunnelSession::new(
        server_reply.session.session_id,
        SessionRole::Responder,
        server_reply.session.secrets,
        server_reply.session.rekey_limits,
        MINIMUM_REPLAY_WINDOW as u64,
        now_secs(),
    );
    sessions_by_addr.insert(
        peer_addr,
        ServerSessionState {
            peer_addr,
            assigned_ipv4: peer.tunnel_ipv4,
            tunnel,
            last_send_secs: now_secs(),
            last_recv_secs: now_secs(),
        },
    );

    let credential_label = redact_credential(&server_reply.session.credential_identity);
    record_event(
        telemetry,
        &AptEvent::AdmissionAccepted {
            session_id: server_reply.session.session_id,
            carrier: server_reply.session.chosen_carrier,
            credential_identity: credential_label,
        },
        None,
        observability,
    );
    record_event(
        telemetry,
        &AptEvent::TunnelEstablished {
            session_id: server_reply.session.session_id,
            carrier: server_reply.session.chosen_carrier,
            mode: server_reply.session.policy_mode,
        },
        None,
        observability,
    );
    Ok(true)
}

async fn send_frames_connected(
    socket: &UdpSocket,
    tunnel: &mut TunnelSession,
    frames: &[Frame],
    now: u64,
) -> Result<(), RuntimeError> {
    let encoded = tunnel.encode_packet(frames, now)?;
    socket.send(&encoded.bytes).await?;
    Ok(())
}

async fn send_frames_to_peer(
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    tunnel: &mut TunnelSession,
    frames: &[Frame],
    now: u64,
) -> Result<(), RuntimeError> {
    let encoded = tunnel.encode_packet(frames, now)?;
    socket.send_to(&encoded.bytes, peer_addr).await?;
    Ok(())
}

fn extract_tunnel_parameters(session: &EstablishedSession) -> Result<SessionTransportParameters, RuntimeError> {
    for extension in &session.optional_extensions {
        let decoded: ServerSessionExtension = bincode::deserialize(extension)?;
        match decoded {
            ServerSessionExtension::TunnelParameters(parameters) => return Ok(parameters),
        }
    }
    Err(RuntimeError::InvalidConfig(
        "server did not provide tunnel transport parameters".to_string(),
    ))
}

fn authorize_established_session(
    config: &ResolvedServerConfig,
    session: &EstablishedSession,
) -> Result<ResolvedAuthorizedPeer, RuntimeError> {
    let client_static_public = session.client_static_public.ok_or(RuntimeError::UnauthorizedPeer)?;
    config
        .peers
        .iter()
        .find(|peer| peer.client_static_public_key == client_static_public)
        .cloned()
        .ok_or(RuntimeError::UnauthorizedPeer)
}

fn assign_transport_parameters(
    config: &ResolvedServerConfig,
    peer: ResolvedAuthorizedPeer,
) -> SessionTransportParameters {
    SessionTransportParameters {
        client_ipv4: peer.tunnel_ipv4,
        server_ipv4: config.tunnel_local_ipv4,
        netmask: config.tunnel_netmask,
        mtu: config.tunnel_mtu,
        routes: config.push_routes.clone(),
        dns_servers: config.push_dns.clone(),
    }
}

fn admission_config(config: &ResolvedServerConfig) -> AdmissionConfig {
    let mut admission = AdmissionConfig::conservative(config.endpoint_id.clone());
    admission.allowed_carriers = vec![CarrierBinding::D1DatagramUdp];
    admission.max_record_size = 1_200;
    admission.tunnel_mtu = config.tunnel_mtu;
    admission
}

fn build_udp_socket(bind: SocketAddr, recv_buffer_bytes: usize, send_buffer_bytes: usize) -> Result<UdpSocket, RuntimeError> {
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

fn extract_destination_ipv4(packet: &[u8]) -> Option<Ipv4Addr> {
    let version = packet.first().map(|value| value >> 4)?;
    if version == 4 && packet.len() >= 20 {
        Some(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]))
    } else {
        None
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn redact_credential(identity: &CredentialIdentity) -> String {
    match identity {
        CredentialIdentity::SharedDeployment => "shared-deployment".to_string(),
        CredentialIdentity::User(user) => format!("user:{user}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_destination_parsing_works() {
        let packet = [
            0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 17, 0, 0, 10, 77, 0, 2, 8, 8, 8, 8,
        ];
        assert_eq!(extract_destination_ipv4(&packet), Some(Ipv4Addr::new(8, 8, 8, 8)));
    }
}
