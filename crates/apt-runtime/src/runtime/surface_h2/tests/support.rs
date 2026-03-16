use super::super::*;
use crate::config::RuntimeCarrierPreference;
use apt_admission::{AdmissionConfig, AdmissionServerSecrets, CredentialStore};
use apt_crypto::generate_static_keypair;
use apt_tunnel::{DecodedPacket, Frame};
use apt_types::{AuthProfile, EndpointId, Mode, SessionPolicy};
use serde_json::json;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::{net::TcpListener, sync::Mutex, task::JoinHandle};

pub(super) fn test_client_config() -> ResolvedClientConfig {
    ResolvedClientConfig {
        server_addr: "198.51.100.10:51820".parse::<SocketAddr>().unwrap(),
        mode: Mode::STEALTH,
        preferred_carrier: RuntimeCarrierPreference::Auto,
        strict_preferred_carrier: false,
        auth_profile: AuthProfile::SharedDeployment,
        endpoint_id: EndpointId::new("edge-h2"),
        admission_key: [0x11; 32],
        server_static_public_key: [0x22; 32],
        client_static_private_key: [0x33; 32],
        client_identity: Some("device-a".to_string()),
        bind: "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
        interface_name: None,
        routes: Vec::new(),
        use_server_pushed_routes: true,
        enable_d2_fallback: false,
        d2: None,
        session_policy: SessionPolicy::default(),
        allow_session_migration: true,
        standby_health_check_secs: 0,
        keepalive_secs: 25,
        session_idle_timeout_secs: 180,
        handshake_timeout_secs: 5,
        handshake_retries: 5,
        udp_recv_buffer_bytes: 1024,
        udp_send_buffer_bytes: 1024,
        state_path: PathBuf::from("/tmp/adapt-test-state.toml"),
    }
}

pub(super) fn test_server() -> (AdmissionServer, [u8; 32]) {
    let static_keypair = generate_static_keypair().unwrap();
    let mut store = CredentialStore::new();
    store.set_shared_deployment_key([0x11; 32]);
    let mut config = AdmissionConfig::conservative(EndpointId::new("edge-h2"));
    config.allowed_carriers = vec![CarrierBinding::S1EncryptedStream];
    (
        AdmissionServer::new(
            config,
            store,
            AdmissionServerSecrets {
                static_keypair: static_keypair.clone(),
                cookie_key: [0x55; 32],
                ticket_key: [0x66; 32],
            },
        ),
        static_keypair.public,
    )
}

pub(super) fn public_service_response(
    surface: &ApiSyncSurface,
    request: &ApiSyncRequest,
) -> Result<ApiSyncResponse, RuntimeError> {
    let device_id = request.body["device_id"]
        .as_str()
        .unwrap_or("shared-device");
    let confirm = request.body["changes"]["confirm"]
        .as_bool()
        .unwrap_or(false);
    let accepted = request.body["changes"]["mode"].as_u64().unwrap_or(0);
    Ok(surface.build_state_pull_response(
        device_id,
        json!({
            "battery": if confirm { 92 } else { 91 },
            "accepted_mode": accepted,
            "path": request.path,
            "authority": request.authority,
        }),
    ))
}

#[derive(Default)]
pub(super) struct TestPublicService;

impl ApiSyncPublicService for TestPublicService {
    fn handle_public_request(
        &mut self,
        surface: &ApiSyncSurface,
        request: &ApiSyncRequest,
    ) -> Result<ApiSyncResponse, RuntimeError> {
        public_service_response(surface, request)
    }
}

#[derive(Default)]
pub(super) struct EchoTunnelPublicService;

impl ApiSyncPublicService for EchoTunnelPublicService {
    fn handle_public_request(
        &mut self,
        surface: &ApiSyncSurface,
        request: &ApiSyncRequest,
    ) -> Result<ApiSyncResponse, RuntimeError> {
        public_service_response(surface, request)
    }

    fn handle_established_request(
        &mut self,
        surface: &ApiSyncSurface,
        request: &ApiSyncRequest,
        _established_session: &EstablishedSession,
        decoded_packet: &DecodedPacket,
    ) -> Result<(ApiSyncResponse, Vec<Frame>), RuntimeError> {
        let response = public_service_response(surface, request)?;
        let outbound_frames = decoded_packet
            .frames
            .iter()
            .filter_map(|frame| match frame {
                Frame::IpData(packet) => Some(Frame::IpData(packet.clone())),
                _ => None,
            })
            .collect();
        Ok((response, outbound_frames))
    }
}

pub(super) async fn spawn_runtime_h2_server(
    admission: AdmissionServer,
    now_secs: u64,
) -> (SocketAddr, JoinHandle<()>) {
    spawn_runtime_h2_server_with_public_service(admission, now_secs, TestPublicService).await
}

pub(super) async fn spawn_runtime_h2_server_with_public_service<S>(
    admission: AdmissionServer,
    now_secs: u64,
    public_service: S,
) -> (SocketAddr, JoinHandle<()>)
where
    S: ApiSyncPublicService + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = ApiSyncH2RequestHandler::new(ApiSyncSurface::starter());
    let admission = Arc::new(Mutex::new(admission));
    let public_service = Arc::new(Mutex::new(public_service));
    let task = tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        serve_api_sync_h2_connection(
            stream,
            handler,
            admission,
            public_service,
            peer_addr.to_string(),
            move || now_secs,
        )
        .await
        .unwrap();
    });
    (addr, task)
}
