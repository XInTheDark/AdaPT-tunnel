use super::*;

pub(in super::super) fn spawn_server_tcp_listener(
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

pub(in super::super) fn send_invalid_stream_response(
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

pub(in super::super) async fn write_s1_payload<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    carrier: &S1Carrier,
    payload: &[u8],
) -> Result<(), RuntimeError> {
    let record = carrier.encode_record(payload)?;
    writer.write_all(&record).await?;
    Ok(())
}

pub(in super::super) async fn read_s1_payload<R: AsyncReadExt + Unpin>(
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
