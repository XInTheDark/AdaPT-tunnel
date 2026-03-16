use super::super::*;
use crate::runtime::surface_h2::ApiSyncTunnelDispatch;
use apt_admission::{AdmissionError, AdmissionServerSecrets, CredentialStore, PerUserCredential};
use apt_surface_h2::{ApiSyncH2Carrier, ApiSyncRequest, ApiSyncResponse, ApiSyncSurface};
use apt_tunnel::Frame;
use apt_types::{CipherSuite, SessionId};
use serde_json::json;
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::TcpListener, sync::Notify};

pub(super) async fn run_h2_server(
    config: ResolvedServerConfig,
) -> Result<ServerRuntimeResult, RuntimeError> {
    let _observability = ObservabilityConfig::default();
    let telemetry = TelemetrySnapshot::new("apt-edge");
    let surface = ApiSyncSurface::new(config.surface_plan.profile.clone())?;
    let request_handler = ApiSyncH2RequestHandler::new(surface.clone());
    let tls_config = build_api_sync_h2_tls_server_config_for_surface_plan(
        &config.surface_plan,
        &config.certificate_spec,
        &config.private_key_spec,
    )?;
    let listener = TcpListener::bind(config.bind).await?;
    let tun = spawn_tun_worker(TunInterfaceConfig {
        name: config.interface_name.clone(),
        local_ipv4: config.tunnel_local_ipv4,
        peer_ipv4: config.tunnel_local_ipv4,
        netmask: config.tunnel_netmask,
        local_ipv6: config.tunnel_local_ipv6,
        ipv6_prefix_len: config.tunnel_ipv6_prefix_len,
        mtu: config.tunnel_mtu,
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
    let admission = Arc::new(tokio::sync::Mutex::new(AdmissionServer::new(
        surface_h2_admission_config(&config),
        credentials,
        AdmissionServerSecrets {
            static_keypair: StaticKeypair {
                private: config.server_static_private_key,
                public: config.server_static_public_key,
            },
            cookie_key: config.cookie_key,
            ticket_key: config.ticket_key,
        },
    )));
    let runtime_state = Arc::new(Mutex::new(H2ServerRuntimeState::default()));
    let public_service = Arc::new(tokio::sync::Mutex::new(H2ServerPublicService {
        config: config.clone(),
        state: Arc::clone(&runtime_state),
        tun_tx: tun.outbound_tx.clone(),
    }));

    let tun_task = tokio::spawn(drive_server_tun(tun.inbound_rx, Arc::clone(&runtime_state)));
    let maintenance_task = tokio::spawn(run_server_maintenance(
        Arc::clone(&runtime_state),
        config.session_idle_timeout_secs,
    ));

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, peer_addr) = accept?;
                let tls_config = tls_config.clone();
                let request_handler = request_handler.clone();
                let admission = Arc::clone(&admission);
                let public_service = Arc::clone(&public_service);
                tokio::spawn(async move {
                    if let Err(error) = serve_api_sync_h2_tls_connection(
                        stream,
                        tls_config,
                        request_handler,
                        admission,
                        public_service,
                        peer_addr.to_string(),
                        now_secs,
                    )
                    .await {
                        warn!(error = %error, peer = %peer_addr, "H2 connection terminated with error");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                info!(bind = %config.bind, "shutdown requested");
                break;
            }
        }
    }

    tun_task.abort();
    maintenance_task.abort();
    let active_sessions = runtime_state.lock().unwrap().sessions.len();
    Ok(ServerRuntimeResult {
        status: ServerStatus {
            bind: config.bind.to_string(),
            interface_name: Some(tun.interface_name),
            listening_carriers: vec![CarrierBinding::S1EncryptedStream],
            active_sessions,
            active_carrier: Some(CarrierBinding::S1EncryptedStream),
            standby_carrier: None,
            mode: Some(config.mode),
        },
        telemetry,
    })
}

#[derive(Default)]
struct H2ServerRuntimeState {
    sessions: HashMap<SessionId, H2ServerSessionState>,
    sessions_by_tunnel_ip: HashMap<IpAddr, SessionId>,
}

struct H2ServerSessionState {
    assigned_ips: Vec<IpAddr>,
    outbound_frames: VecDeque<Frame>,
    last_activity_secs: u64,
    outbound_notify: Arc<Notify>,
}

impl H2ServerRuntimeState {
    fn install_session(&mut self, session_id: SessionId, assigned_ips: Vec<IpAddr>, now_secs: u64) {
        for assigned_ip in &assigned_ips {
            if let Some(existing_session_id) = self.sessions_by_tunnel_ip.remove(assigned_ip) {
                if let Some(existing) = self.sessions.remove(&existing_session_id) {
                    for ip in existing.assigned_ips {
                        self.sessions_by_tunnel_ip.remove(&ip);
                    }
                }
            }
        }
        for assigned_ip in &assigned_ips {
            self.sessions_by_tunnel_ip.insert(*assigned_ip, session_id);
        }
        self.sessions.insert(
            session_id,
            H2ServerSessionState {
                assigned_ips,
                outbound_frames: VecDeque::new(),
                last_activity_secs: now_secs,
                outbound_notify: Arc::new(Notify::new()),
            },
        );
    }

    fn remove_session(&mut self, session_id: SessionId) {
        if let Some(session) = self.sessions.remove(&session_id) {
            session.outbound_notify.notify_waiters();
            for assigned_ip in session.assigned_ips {
                self.sessions_by_tunnel_ip.remove(&assigned_ip);
            }
        }
    }

    fn drain_outbound(&mut self, session_id: SessionId, limit: usize) -> Vec<Frame> {
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return Vec::new();
        };
        session.last_activity_secs = now_secs();
        let mut frames = Vec::new();
        for _ in 0..limit {
            let Some(frame) = session.outbound_frames.pop_front() else {
                break;
            };
            frames.push(frame);
        }
        frames
    }

    fn session_notify(&self, session_id: SessionId) -> Option<Arc<Notify>> {
        self.sessions
            .get(&session_id)
            .map(|session| Arc::clone(&session.outbound_notify))
    }
}

#[derive(Clone)]
struct H2ServerTunnelDispatch {
    state: Arc<Mutex<H2ServerRuntimeState>>,
}

impl ApiSyncTunnelDispatch for H2ServerTunnelDispatch {
    fn wait_for_outbound_frames<'a>(
        &'a self,
        session_id: SessionId,
        limit: usize,
        timeout: Duration,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Frame>, RuntimeError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let timeout_sleep = tokio::time::sleep(timeout);
            tokio::pin!(timeout_sleep);
            loop {
                let notify = {
                    let state = self.state.lock().unwrap();
                    let Some(notify) = state.session_notify(session_id) else {
                        return Ok(Vec::new());
                    };
                    notify
                };
                let notified = notify.notified();
                tokio::pin!(notified);
                let frames = self.state.lock().unwrap().drain_outbound(session_id, limit);
                if !frames.is_empty() {
                    return Ok(frames);
                }
                tokio::select! {
                    _ = &mut timeout_sleep => return Ok(Vec::new()),
                    _ = &mut notified => {}
                }
            }
        })
    }
}

struct H2ServerPublicService {
    config: ResolvedServerConfig,
    state: Arc<Mutex<H2ServerRuntimeState>>,
    tun_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl ApiSyncPublicService for H2ServerPublicService {
    fn handle_public_request(
        &mut self,
        surface: &ApiSyncSurface,
        request: &ApiSyncRequest,
    ) -> Result<ApiSyncResponse, RuntimeError> {
        let device_id = request.body["device_id"]
            .as_str()
            .unwrap_or("shared-device");
        let accepted_mode = request.body["changes"]["mode"].as_u64().unwrap_or(0);
        Ok(surface.build_state_pull_response(
            device_id,
            json!({
                "authority": request.authority,
                "path": request.path,
                "accepted_mode": accepted_mode,
                "server_time_secs": now_secs(),
            }),
        ))
    }

    fn build_ug4_extensions(
        &mut self,
        established_session: &EstablishedSession,
    ) -> Result<Vec<Vec<u8>>, AdmissionError> {
        let peer = authorize_established_session(&self.config, established_session)
            .map_err(|_| AdmissionError::Validation("unauthorized peer"))?;
        Ok(vec![bincode::serialize(
            &ServerSessionExtension::TunnelParameters(assign_transport_parameters(
                &self.config,
                peer,
                self.config.tunnel_mtu,
            )),
        )?])
    }

    fn note_established_session(
        &mut self,
        _surface: &ApiSyncSurface,
        established_session: &EstablishedSession,
    ) -> Result<(), RuntimeError> {
        let peer = authorize_established_session(&self.config, established_session)?;
        let mut assigned_ips = vec![IpAddr::V4(peer.tunnel_ipv4)];
        if let Some(ipv6) = peer.tunnel_ipv6 {
            assigned_ips.push(IpAddr::V6(ipv6));
        }
        self.state.lock().unwrap().install_session(
            established_session.session_id,
            assigned_ips,
            now_secs(),
        );
        Ok(())
    }

    fn note_closed_session(&mut self, established_session: &EstablishedSession) {
        self.state
            .lock()
            .unwrap()
            .remove_session(established_session.session_id);
    }

    fn tunnel_dispatch(&self) -> Option<Arc<dyn ApiSyncTunnelDispatch>> {
        Some(Arc::new(H2ServerTunnelDispatch {
            state: Arc::clone(&self.state),
        }))
    }

    fn handle_established_request(
        &mut self,
        surface: &ApiSyncSurface,
        request: &ApiSyncRequest,
        established_session: &EstablishedSession,
        decoded_packet: &apt_tunnel::DecodedPacket,
    ) -> Result<(ApiSyncResponse, Vec<Frame>), RuntimeError> {
        {
            let mut state = self.state.lock().unwrap();
            if let Some(session) = state.sessions.get_mut(&established_session.session_id) {
                session.last_activity_secs = now_secs();
            }
        }
        for frame in &decoded_packet.frames {
            if let Frame::IpData(packet) = frame {
                let _ = self.tun_tx.try_send(packet.clone());
            }
        }
        let response = self.handle_public_request(surface, request)?;
        let outbound_frames = self
            .state
            .lock()
            .unwrap()
            .drain_outbound(established_session.session_id, 32);
        Ok((response, outbound_frames))
    }
}

async fn drive_server_tun(
    mut tun_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    state: Arc<Mutex<H2ServerRuntimeState>>,
) {
    while let Some(packet) = tun_rx.recv().await {
        let Some(destination) = extract_destination_ip(&packet) else {
            continue;
        };
        let mut state = state.lock().unwrap();
        let Some(session_id) = state.sessions_by_tunnel_ip.get(&destination).copied() else {
            continue;
        };
        if let Some(session) = state.sessions.get_mut(&session_id) {
            session.outbound_frames.push_back(Frame::IpData(packet));
            session.last_activity_secs = now_secs();
            session.outbound_notify.notify_one();
        }
    }
}

async fn run_server_maintenance(
    state: Arc<Mutex<H2ServerRuntimeState>>,
    session_idle_timeout_secs: u64,
) {
    let mut tick = interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        let now = now_secs();
        let expired = {
            let state = state.lock().unwrap();
            state
                .sessions
                .iter()
                .filter_map(|(session_id, session)| {
                    (now.saturating_sub(session.last_activity_secs) > session_idle_timeout_secs)
                        .then_some(*session_id)
                })
                .collect::<Vec<_>>()
        };
        if expired.is_empty() {
            continue;
        }
        let mut state = state.lock().unwrap();
        for session_id in expired {
            state.remove_session(session_id);
        }
    }
}

fn surface_h2_admission_config(config: &ResolvedServerConfig) -> AdmissionConfig {
    let mut admission = AdmissionConfig::conservative(config.endpoint_id.clone());
    admission.allowed_carriers = vec![CarrierBinding::S1EncryptedStream];
    admission.default_mode = config.mode;
    admission.max_record_size = ApiSyncH2Carrier::conservative().max_record_size();
    admission.tunnel_mtu = config.tunnel_mtu;
    admission.allowed_suites = vec![CipherSuite::NoiseXxPsk2X25519ChaChaPolyBlake2s];
    admission
}
