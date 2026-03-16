use super::*;

pub(crate) async fn perform_client_handshake(
    config: &ResolvedClientConfig,
    persistent_state: &mut ClientPersistentState,
    carriers: &RuntimeCarriers,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
) -> Result<HandshakeSuccess, RuntimeError> {
    let masked_fallback_ticket = persistent_state
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
                    masked_fallback_ticket.clone(),
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
                    masked_fallback_ticket.clone(),
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
                    .masked_fallback_ticket
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
    masked_fallback_ticket: Option<SealedEnvelope>,
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
            masked_fallback_ticket.clone(),
            now,
        );
        let prepared_ug1 = initiate_ug1(credential, request, carrier)?;
        let c0_bytes = encode_admission_datagram(
            carrier,
            &config.endpoint_id,
            &outer_key,
            &AdmissionWirePacket {
                lookup_hint: prepared_ug1.lookup_hint,
                envelope: prepared_ug1.envelope.clone(),
            },
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
        let prepared_ug3 = prepared_ug1.state.handle_ug2(&s1.envelope, carrier)?;
        let c2_bytes = encode_admission_datagram(
            carrier,
            &config.endpoint_id,
            &outer_key,
            &AdmissionWirePacket {
                lookup_hint: prepared_ug3.lookup_hint,
                envelope: prepared_ug3.envelope.clone(),
            },
        )?;
        socket.send(&c2_bytes).await?;

        let confirmation_outer_key =
            derive_d1_confirmation_outer_key(prepared_ug3.state.confirmation_recv_ctrl_key())?;
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
        let s3 = decode_confirmation_datagram(
            carrier,
            &config.endpoint_id,
            &confirmation_outer_key,
            &recv_buf[..s3_len],
        )?;
        let session = prepared_ug3.state.handle_ug4(&s3.envelope, carrier)?;
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
    masked_fallback_ticket: Option<SealedEnvelope>,
    supported_carriers: &[CarrierBinding],
) -> Result<HandshakeSuccess, RuntimeError> {
    let (endpoint, connection) =
        open_client_d2_connection(config, config.handshake_timeout_secs).await?;

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
            masked_fallback_ticket.clone(),
            now,
        );
        let prepared_ug1 = initiate_ug1(credential, request, carrier)?;
        let c0_bytes = encode_admission_d2_datagram(
            carrier,
            &config.endpoint_id,
            &outer_key,
            &AdmissionWirePacket {
                lookup_hint: prepared_ug1.lookup_hint,
                envelope: prepared_ug1.envelope.clone(),
            },
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
        let prepared_ug3 = prepared_ug1.state.handle_ug2(&s1.envelope, carrier)?;
        let c2_bytes = encode_admission_d2_datagram(
            carrier,
            &config.endpoint_id,
            &outer_key,
            &AdmissionWirePacket {
                lookup_hint: prepared_ug3.lookup_hint,
                envelope: prepared_ug3.envelope.clone(),
            },
        )?;
        connection
            .send_datagram_wait(bytes::Bytes::from(c2_bytes))
            .await
            .map_err(|error| RuntimeError::Quic(error.to_string()))?;

        let confirmation_outer_key =
            derive_d2_confirmation_outer_key(prepared_ug3.state.confirmation_recv_ctrl_key())?;
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
        let s3 = decode_confirmation_d2_datagram(
            carrier,
            &config.endpoint_id,
            &confirmation_outer_key,
            &s3_bytes,
        )?;
        let session = prepared_ug3.state.handle_ug4(&s3.envelope, carrier)?;
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
