use super::*;

pub(super) async fn perform_client_handshake(
    config: &ResolvedClientConfig,
    persistent_state: &mut ClientPersistentState,
    carriers: &RuntimeCarriers,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
) -> Result<HandshakeSuccess, RuntimeError> {
    let resume_ticket = persistent_state
        .resume_ticket
        .as_ref()
        .map(|bytes| bincode::deserialize::<SealedEnvelope>(bytes))
        .transpose()?;
    let order = client_carrier_attempt_order(config, persistent_state)?;
    let mut last_error = None;

    for (index, binding) in order.iter().copied().enumerate() {
        let attempt = match binding {
            CarrierBinding::D1DatagramUdp => {
                attempt_client_handshake_d1(
                    config,
                    persistent_state,
                    carriers.d1(),
                    resume_ticket.clone(),
                    &order,
                )
                .await
            }
            CarrierBinding::D2EncryptedDatagram => {
                let Some(carrier) = carriers.d2() else {
                    return Err(RuntimeError::InvalidConfig(
                        "D2 handshake was requested, but the runtime D2 carrier is unavailable"
                            .to_string(),
                    ));
                };
                attempt_client_handshake_d2(
                    config,
                    persistent_state,
                    carrier,
                    resume_ticket.clone(),
                    &order,
                )
                .await
            }
            CarrierBinding::S1EncryptedStream => {
                attempt_client_handshake_s1(
                    config,
                    persistent_state,
                    carriers.s1(),
                    resume_ticket.clone(),
                    &order,
                )
                .await
            }
            _ => continue,
        };
        match attempt {
            Ok(success) => {
                persistent_state.resume_ticket = success
                    .established
                    .resume_ticket
                    .as_ref()
                    .map(bincode::serialize)
                    .transpose()?;
                persistent_state.last_successful_carrier = Some(binding);
                persistent_state.store(&config.state_path)?;
                if index > 0 {
                    record_event(
                        telemetry,
                        &AptEvent::CarrierFallback {
                            session_id: success.established.session_id,
                            from: None,
                            to: binding,
                            reason: "fallback-success",
                        },
                        None,
                        observability,
                    );
                }
                return Ok(success);
            }
            Err(error) => {
                warn!(carrier = %binding.as_str(), error = %error, "handshake attempt failed");
                last_error = Some(error);
            }
        }
    }

    Err(last_error.unwrap_or(RuntimeError::Timeout("admission handshake")))
}

async fn attempt_client_handshake_d1(
    config: &ResolvedClientConfig,
    persistent_state: &ClientPersistentState,
    carrier: &D1Carrier,
    resume_ticket: Option<SealedEnvelope>,
    supported_carriers: &[CarrierBinding],
) -> Result<HandshakeSuccess, RuntimeError> {
    let socket = build_udp_socket(
        client_bind_for_remote(config.bind, config.server_addr),
        config.udp_recv_buffer_bytes,
        config.udp_send_buffer_bytes,
    )?;
    socket.connect(config.server_addr).await?;

    for _ in 0..config.handshake_retries {
        let now = now_secs();
        let current_epoch_slot = now / DEFAULT_ADMISSION_EPOCH_SLOT_SECS;
        let outer_key = derive_d1_admission_outer_key(&config.admission_key, current_epoch_slot)?;
        let credential = client_credential(config);
        let request = client_session_request(
            config,
            persistent_state,
            CarrierBinding::D1DatagramUdp,
            supported_carriers,
            resume_ticket.clone(),
            now,
        );
        let prepared_c0 = initiate_c0(credential, request, carrier)?;
        let c0_bytes = encode_admission_datagram(
            carrier,
            &config.endpoint_id,
            &outer_key,
            &prepared_c0.packet,
        )?;
        socket.send(&c0_bytes).await?;

        let mut recv_buf = vec![0_u8; DATAGRAM_BUFFER_SIZE];
        let s1_len = match timeout(
            Duration::from_secs(config.handshake_timeout_secs),
            socket.recv(&mut recv_buf),
        )
        .await
        {
            Ok(Ok(len)) => len,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => continue,
        };
        let s1 = match decode_client_admission_packet(
            config,
            carrier,
            &recv_buf[..s1_len],
            now_secs(),
        ) {
            Some(packet) => packet,
            None => continue,
        };
        let prepared_c2 = prepared_c0.state.handle_s1(&s1, carrier)?;
        let c2_bytes = encode_admission_datagram(
            carrier,
            &config.endpoint_id,
            &outer_key,
            &prepared_c2.packet,
        )?;
        socket.send(&c2_bytes).await?;

        let confirmation_outer_key =
            derive_d1_confirmation_outer_key(prepared_c2.state.confirmation_recv_ctrl_key())?;
        let s3_len = match timeout(
            Duration::from_secs(config.handshake_timeout_secs),
            socket.recv(&mut recv_buf),
        )
        .await
        {
            Ok(Ok(len)) => len,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => continue,
        };
        let s3: ServerConfirmationPacket = decode_confirmation_datagram(
            carrier,
            &config.endpoint_id,
            &confirmation_outer_key,
            &recv_buf[..s3_len],
        )?;
        let session = prepared_c2.state.handle_s3(&s3, carrier)?;
        return Ok(HandshakeSuccess {
            binding: CarrierBinding::D1DatagramUdp,
            established: session,
            transport: HandshakeTransport::Datagram(socket),
        });
    }

    Err(RuntimeError::Timeout("admission handshake"))
}

async fn attempt_client_handshake_d2(
    config: &ResolvedClientConfig,
    persistent_state: &ClientPersistentState,
    carrier: &D2Carrier,
    resume_ticket: Option<SealedEnvelope>,
    supported_carriers: &[CarrierBinding],
) -> Result<HandshakeSuccess, RuntimeError> {
    let (endpoint, connection) = open_client_d2_connection(config).await?;

    for _ in 0..config.handshake_retries {
        let now = now_secs();
        let current_epoch_slot = now / DEFAULT_ADMISSION_EPOCH_SLOT_SECS;
        let outer_key = derive_d2_admission_outer_key(&config.admission_key, current_epoch_slot)?;
        let credential = client_credential(config);
        let request = client_session_request(
            config,
            persistent_state,
            CarrierBinding::D2EncryptedDatagram,
            supported_carriers,
            resume_ticket.clone(),
            now,
        );
        let prepared_c0 = initiate_c0(credential, request, carrier)?;
        let c0_bytes = encode_admission_d2_datagram(
            carrier,
            &config.endpoint_id,
            &outer_key,
            &prepared_c0.packet,
        )?;
        connection
            .send_datagram_wait(bytes::Bytes::from(c0_bytes))
            .await
            .map_err(|error| RuntimeError::Quic(error.to_string()))?;

        let s1_bytes = match timeout(
            Duration::from_secs(config.handshake_timeout_secs),
            connection.read_datagram(),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(error)) => return Err(RuntimeError::Quic(error.to_string())),
            Err(_) => continue,
        };
        let s1 = match decode_client_d2_admission_packet(config, carrier, &s1_bytes, now_secs()) {
            Some(packet) => packet,
            None => continue,
        };
        let prepared_c2 = prepared_c0.state.handle_s1(&s1, carrier)?;
        let c2_bytes = encode_admission_d2_datagram(
            carrier,
            &config.endpoint_id,
            &outer_key,
            &prepared_c2.packet,
        )?;
        connection
            .send_datagram_wait(bytes::Bytes::from(c2_bytes))
            .await
            .map_err(|error| RuntimeError::Quic(error.to_string()))?;

        let confirmation_outer_key =
            derive_d2_confirmation_outer_key(prepared_c2.state.confirmation_recv_ctrl_key())?;
        let s3_bytes = match timeout(
            Duration::from_secs(config.handshake_timeout_secs),
            connection.read_datagram(),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(error)) => return Err(RuntimeError::Quic(error.to_string())),
            Err(_) => continue,
        };
        let s3: ServerConfirmationPacket = decode_confirmation_d2_datagram(
            carrier,
            &config.endpoint_id,
            &confirmation_outer_key,
            &s3_bytes,
        )?;
        let session = prepared_c2.state.handle_s3(&s3, carrier)?;
        return Ok(HandshakeSuccess {
            binding: CarrierBinding::D2EncryptedDatagram,
            established: session,
            transport: HandshakeTransport::D2 {
                endpoint,
                connection,
            },
        });
    }

    Err(RuntimeError::Timeout("admission handshake"))
}

async fn attempt_client_handshake_s1(
    config: &ResolvedClientConfig,
    persistent_state: &ClientPersistentState,
    carrier: &S1Carrier,
    resume_ticket: Option<SealedEnvelope>,
    supported_carriers: &[CarrierBinding],
) -> Result<HandshakeSuccess, RuntimeError> {
    let Some(server_addr) = config.stream_server_addr else {
        return Err(RuntimeError::InvalidConfig(
            "stream fallback is enabled but no stream_server_addr is configured".to_string(),
        ));
    };
    for _ in 0..config.handshake_retries {
        let mut stream = TcpStream::connect(server_addr).await?;
        let _ = stream.set_nodelay(true);
        let now = now_secs();
        let current_epoch_slot = now / DEFAULT_ADMISSION_EPOCH_SLOT_SECS;
        let outer_key = derive_s1_admission_outer_key(&config.admission_key, current_epoch_slot)?;
        let credential = client_credential(config);
        let request = client_session_request(
            config,
            persistent_state,
            CarrierBinding::S1EncryptedStream,
            supported_carriers,
            resume_ticket.clone(),
            now,
        );
        let prepared_c0 = initiate_c0(credential, request, carrier)?;
        let c0_payload =
            encode_admission_stream_payload(&config.endpoint_id, &outer_key, &prepared_c0.packet)?;
        write_s1_payload(&mut stream, carrier, &c0_payload).await?;

        let s1_payload = match timeout(
            Duration::from_secs(config.handshake_timeout_secs),
            read_s1_payload(&mut stream, carrier),
        )
        .await
        {
            Ok(Ok(payload)) => payload,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => continue,
        };
        let s1 = match decode_client_stream_admission_packet(config, &s1_payload, now_secs()) {
            Some(packet) => packet,
            None => continue,
        };
        let prepared_c2 = prepared_c0.state.handle_s1(&s1, carrier)?;
        let c2_payload =
            encode_admission_stream_payload(&config.endpoint_id, &outer_key, &prepared_c2.packet)?;
        write_s1_payload(&mut stream, carrier, &c2_payload).await?;

        let confirmation_outer_key =
            derive_s1_confirmation_outer_key(prepared_c2.state.confirmation_recv_ctrl_key())?;
        let s3_payload = match timeout(
            Duration::from_secs(config.handshake_timeout_secs),
            read_s1_payload(&mut stream, carrier),
        )
        .await
        {
            Ok(Ok(payload)) => payload,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => continue,
        };
        let s3: ServerConfirmationPacket = decode_confirmation_stream_payload(
            &config.endpoint_id,
            &confirmation_outer_key,
            &s3_payload,
        )?;
        let session = prepared_c2.state.handle_s3(&s3, carrier)?;
        return Ok(HandshakeSuccess {
            binding: CarrierBinding::S1EncryptedStream,
            established: session,
            transport: HandshakeTransport::Stream(stream),
        });
    }

    Err(RuntimeError::Timeout("admission handshake"))
}

pub(super) fn decode_client_admission_packet(
    config: &ResolvedClientConfig,
    carrier: &D1Carrier,
    datagram: &[u8],
    now_secs: u64,
) -> Option<AdmissionPacket> {
    candidate_epoch_slots(now_secs)
        .into_iter()
        .find_map(|epoch_slot| {
            let outer_key =
                derive_d1_admission_outer_key(&config.admission_key, epoch_slot).ok()?;
            decode_admission_datagram(carrier, &config.endpoint_id, &outer_key, datagram).ok()
        })
}

pub(super) fn decode_client_stream_admission_packet(
    config: &ResolvedClientConfig,
    payload: &[u8],
    now_secs: u64,
) -> Option<AdmissionPacket> {
    candidate_epoch_slots(now_secs)
        .into_iter()
        .find_map(|epoch_slot| {
            let outer_key =
                derive_s1_admission_outer_key(&config.admission_key, epoch_slot).ok()?;
            decode_admission_stream_payload(&config.endpoint_id, &outer_key, payload).ok()
        })
}

pub(super) fn decode_client_d2_admission_packet(
    config: &ResolvedClientConfig,
    carrier: &D2Carrier,
    datagram: &[u8],
    now_secs: u64,
) -> Option<AdmissionPacket> {
    candidate_epoch_slots(now_secs)
        .into_iter()
        .find_map(|epoch_slot| {
            let outer_key =
                derive_d2_admission_outer_key(&config.admission_key, epoch_slot).ok()?;
            decode_admission_d2_datagram(carrier, &config.endpoint_id, &outer_key, datagram).ok()
        })
}

pub(super) fn decode_server_admission_packet(
    config: &ResolvedServerConfig,
    carrier: &D1Carrier,
    datagram: &[u8],
    now_secs: u64,
) -> Option<DecodedServerAdmissionPacket> {
    server_admission_keys(config)
        .into_iter()
        .find_map(|admission_key| {
            candidate_epoch_slots(now_secs)
                .into_iter()
                .find_map(|epoch_slot| {
                    let outer_key =
                        derive_d1_admission_outer_key(&admission_key, epoch_slot).ok()?;
                    let packet = decode_admission_datagram(
                        carrier,
                        &config.endpoint_id,
                        &outer_key,
                        datagram,
                    )
                    .ok()?;
                    Some(DecodedServerAdmissionPacket { packet, outer_key })
                })
        })
}

pub(super) fn decode_server_stream_admission_packet(
    config: &ResolvedServerConfig,
    payload: &[u8],
    now_secs: u64,
) -> Option<DecodedServerAdmissionPacket> {
    server_admission_keys(config)
        .into_iter()
        .find_map(|admission_key| {
            candidate_epoch_slots(now_secs)
                .into_iter()
                .find_map(|epoch_slot| {
                    let outer_key =
                        derive_s1_admission_outer_key(&admission_key, epoch_slot).ok()?;
                    let packet =
                        decode_admission_stream_payload(&config.endpoint_id, &outer_key, payload)
                            .ok()?;
                    Some(DecodedServerAdmissionPacket { packet, outer_key })
                })
        })
}

pub(super) fn decode_server_d2_admission_packet(
    config: &ResolvedServerConfig,
    carrier: &D2Carrier,
    datagram: &[u8],
    now_secs: u64,
) -> Option<DecodedServerAdmissionPacket> {
    server_admission_keys(config)
        .into_iter()
        .find_map(|admission_key| {
            candidate_epoch_slots(now_secs)
                .into_iter()
                .find_map(|epoch_slot| {
                    let outer_key =
                        derive_d2_admission_outer_key(&admission_key, epoch_slot).ok()?;
                    let packet = decode_admission_d2_datagram(
                        carrier,
                        &config.endpoint_id,
                        &outer_key,
                        datagram,
                    )
                    .ok()?;
                    Some(DecodedServerAdmissionPacket { packet, outer_key })
                })
        })
}

#[derive(Clone, Debug)]
pub(super) struct DecodedServerAdmissionPacket {
    pub(super) packet: AdmissionPacket,
    pub(super) outer_key: [u8; 32],
}

fn server_admission_keys(config: &ResolvedServerConfig) -> Vec<[u8; 32]> {
    let mut keys = vec![config.admission_key];
    for peer in &config.peers {
        if let Some(admission_key) = peer.admission_key {
            if !keys.contains(&admission_key) {
                keys.push(admission_key);
            }
        }
    }
    keys
}

pub(super) fn admission_config(
    config: &ResolvedServerConfig,
    carriers: &RuntimeCarriers,
    effective_tunnel_mtu: u16,
) -> AdmissionConfig {
    let mut admission = AdmissionConfig::conservative(config.endpoint_id.clone());
    admission.allowed_carriers = vec![CarrierBinding::D1DatagramUdp];
    if config.d2.is_some() {
        admission
            .allowed_carriers
            .push(CarrierBinding::D2EncryptedDatagram);
    }
    admission
        .allowed_carriers
        .push(CarrierBinding::S1EncryptedStream);
    admission.default_policy = config.session_policy.initial_mode;
    admission.max_record_size = carriers.d1().max_record_size();
    admission.tunnel_mtu = effective_tunnel_mtu;
    admission.allowed_suites = vec![CipherSuite::NoiseXxPsk2X25519ChaChaPolyBlake2s];
    admission
}

pub(super) fn assign_transport_parameters(
    config: &ResolvedServerConfig,
    peer: ResolvedAuthorizedPeer,
    effective_tunnel_mtu: u16,
) -> SessionTransportParameters {
    SessionTransportParameters {
        client_ipv4: peer.tunnel_ipv4,
        server_ipv4: config.tunnel_local_ipv4,
        netmask: config.tunnel_netmask,
        client_ipv6: peer.tunnel_ipv6,
        server_ipv6: config.tunnel_local_ipv6,
        ipv6_prefix_len: config.tunnel_ipv6_prefix_len,
        mtu: effective_tunnel_mtu,
        routes: config.push_routes.clone(),
        dns_servers: config.push_dns.clone(),
    }
}

pub(super) fn authorize_established_session(
    config: &ResolvedServerConfig,
    session: &EstablishedSession,
) -> Result<ResolvedAuthorizedPeer, RuntimeError> {
    let client_static_public = session
        .client_static_public
        .ok_or(RuntimeError::UnauthorizedPeer)?;
    config
        .peers
        .iter()
        .find(|peer| peer.client_static_public_key == client_static_public)
        .cloned()
        .ok_or(RuntimeError::UnauthorizedPeer)
}

pub(super) fn extract_tunnel_parameters(
    session: &EstablishedSession,
) -> Result<SessionTransportParameters, RuntimeError> {
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
