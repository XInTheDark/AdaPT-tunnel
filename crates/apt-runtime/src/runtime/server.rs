use super::*;

mod admission;
mod events;
mod maintenance;
mod session;

use self::{
    events::{
        handle_d2_closed, handle_d2_datagram_event, handle_d2_opened, handle_datagram_event,
        handle_stream_closed, handle_stream_opened, handle_stream_record_event,
    },
    maintenance::{handle_tun_packet, run_tick},
};

use self::{
    admission::{
        handle_server_admission_d2, handle_server_admission_datagram,
        handle_server_admission_stream,
    },
    session::{
        expire_server_session, handle_server_path_loss, process_known_server_path,
        process_migrated_server_path, try_match_server_session,
    },
};

pub(super) async fn run_server(
    config: ResolvedServerConfig,
) -> Result<ServerRuntimeResult, RuntimeError> {
    let observability = ObservabilityConfig::default();
    let mut telemetry = TelemetrySnapshot::new("apt-edge");
    let bootstrap_carriers = RuntimeCarriers::new(
        config.tunnel_mtu,
        config.stream_decoy_surface,
        config.d2.is_some(),
    );
    let effective_tunnel_mtu =
        effective_runtime_tunnel_mtu(config.tunnel_mtu, &config.endpoint_id, &bootstrap_carriers);
    if effective_tunnel_mtu < config.tunnel_mtu {
        warn!(
            configured_mtu = config.tunnel_mtu,
            effective_mtu = effective_tunnel_mtu,
            "configured tunnel MTU exceeds the smallest enabled datagram-carrier payload budget; capping runtime MTU"
        );
    }
    let carriers = RuntimeCarriers::new(
        effective_tunnel_mtu,
        config.stream_decoy_surface,
        config.d2.is_some(),
    );

    let udp_socket = Arc::new(build_udp_socket(
        config.bind,
        config.udp_recv_buffer_bytes,
        config.udp_send_buffer_bytes,
    )?);
    let d2_endpoint = build_server_d2_endpoint(&config)?;
    let tcp_listener = if config.allow_session_migration || config.stream_bind.is_some() {
        let bind = config.stream_bind.unwrap_or(config.bind);
        Some(TcpListener::bind(bind).await?)
    } else {
        None
    };

    let tun = spawn_tun_worker(TunInterfaceConfig {
        name: config.interface_name.clone(),
        local_ipv4: config.tunnel_local_ipv4,
        peer_ipv4: config.tunnel_local_ipv4,
        netmask: config.tunnel_netmask,
        local_ipv6: config.tunnel_local_ipv6,
        ipv6_prefix_len: config.tunnel_ipv6_prefix_len,
        mtu: effective_tunnel_mtu,
    })
    .await?;
    let _server_net_guard = configure_server_network(&tun.interface_name, &config)?;

    let mut credentials = CredentialStore::default();
    credentials.set_shared_deployment_key(config.admission_key);
    for peer in &config.peers {
        if matches!(peer.auth_profile, AuthProfile::PerUser) {
            credentials.add_user(PerUserCredential {
                user_id: peer.user_id.clone(),
                admission_key: peer.admission_key.ok_or_else(|| {
                    RuntimeError::InvalidConfig(format!(
                        "peer `{}` is missing its per-user admission key",
                        peer.name
                    ))
                })?,
            });
        }
    }
    let mut admission = AdmissionServer::new(
        admission_config(&config, &carriers, effective_tunnel_mtu),
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

    let (transport_tx, mut transport_rx) = mpsc::unbounded_channel();
    spawn_server_udp_receiver(udp_socket.clone(), transport_tx.clone());
    if let Some(endpoint) = d2_endpoint {
        spawn_server_d2_listener(endpoint, transport_tx.clone());
    }
    if let Some(listener) = tcp_listener {
        spawn_server_tcp_listener(listener, transport_tx.clone(), carriers.s1());
    }

    let mut sessions: HashMap<SessionId, ServerSessionState> = HashMap::new();
    let mut path_to_session: HashMap<PathHandle, SessionId> = HashMap::new();
    let mut sessions_by_tunnel_ip: HashMap<IpAddr, SessionId> = HashMap::new();
    let mut d2_peers: HashMap<u64, ServerD2Peer> = HashMap::new();
    let mut stream_peers: HashMap<u64, ServerStreamPeer> = HashMap::new();
    let mut tick = interval(Duration::from_secs(1));
    let mut tun_rx = tun.inbound_rx;
    let tun_tx = tun.outbound_tx.clone();

    loop {
        tokio::select! {
            maybe_event = transport_rx.recv() => {
                let Some(event) = maybe_event else { break; };
                match event {
                    ServerTransportEvent::Datagram { peer_addr, bytes } => {
                        handle_datagram_event(
                            &udp_socket,
                            &d2_peers,
                            &stream_peers,
                            &mut admission,
                            &config,
                            &carriers,
                            effective_tunnel_mtu,
                            &tun_tx,
                            &mut sessions,
                            &mut path_to_session,
                            &mut sessions_by_tunnel_ip,
                            &mut telemetry,
                            &observability,
                            peer_addr,
                            bytes,
                        ).await?;
                    }
                    ServerTransportEvent::D2Opened { conn_id, peer_addr, sender } => {
                        handle_d2_opened(&mut d2_peers, conn_id, peer_addr, sender);
                    }
                    ServerTransportEvent::D2Datagram { conn_id, bytes } => {
                        handle_d2_datagram_event(
                            &udp_socket,
                            &d2_peers,
                            &stream_peers,
                            &mut admission,
                            &config,
                            &carriers,
                            effective_tunnel_mtu,
                            &tun_tx,
                            &mut sessions,
                            &mut path_to_session,
                            &mut sessions_by_tunnel_ip,
                            &mut telemetry,
                            &observability,
                            conn_id,
                            bytes,
                        ).await?;
                    }
                    ServerTransportEvent::D2Closed { conn_id } => {
                        handle_d2_closed(
                            &mut d2_peers,
                            &mut sessions,
                            &mut path_to_session,
                            &mut telemetry,
                            &observability,
                            conn_id,
                        );
                    }
                    ServerTransportEvent::StreamOpened { conn_id, peer_addr, sender } => {
                        handle_stream_opened(&mut stream_peers, conn_id, peer_addr, sender);
                    }
                    ServerTransportEvent::StreamRecord { conn_id, bytes } => {
                        handle_stream_record_event(
                            &udp_socket,
                            &d2_peers,
                            &mut stream_peers,
                            &mut admission,
                            &config,
                            &carriers,
                            effective_tunnel_mtu,
                            &tun_tx,
                            &mut sessions,
                            &mut path_to_session,
                            &mut sessions_by_tunnel_ip,
                            &mut telemetry,
                            &observability,
                            conn_id,
                            bytes,
                        ).await?;
                    }
                    ServerTransportEvent::StreamClosed { conn_id, malformed } => {
                        handle_stream_closed(
                            &mut stream_peers,
                            &mut sessions,
                            &mut path_to_session,
                            &mut telemetry,
                            &observability,
                            config.stream_decoy_surface,
                            conn_id,
                            malformed,
                        );
                    }
                }
            }
            tun_packet = tun_rx.recv() => {
                if let Some(packet) = tun_packet {
                    handle_tun_packet(
                        &udp_socket,
                        &d2_peers,
                        &stream_peers,
                        &carriers,
                        &config,
                        &mut tun_rx,
                        &mut sessions,
                        &sessions_by_tunnel_ip,
                        packet,
                    ).await?;
                } else {
                    break;
                }
            }
            _ = tick.tick() => {
                run_tick(
                    &udp_socket,
                    &d2_peers,
                    &stream_peers,
                    &carriers,
                    &config,
                    &mut sessions,
                    &mut path_to_session,
                    &mut sessions_by_tunnel_ip,
                    &mut telemetry,
                    &observability,
                ).await?;
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
            listening_carriers: {
                let mut carriers = vec![CarrierBinding::D1DatagramUdp];
                if config.d2.is_some() {
                    carriers.push(CarrierBinding::D2EncryptedDatagram);
                }
                carriers.push(CarrierBinding::S1EncryptedStream);
                carriers
            },
            active_sessions: sessions.len(),
            active_carrier: None,
            standby_carrier: None,
            mode: None,
        },
        telemetry,
    })
}
