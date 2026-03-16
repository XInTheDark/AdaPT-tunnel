use super::*;
use crate::config::RuntimeCarrierPreference;
use apt_admission::{AdmissionConfig, AdmissionServerSecrets, CredentialStore};
use apt_crypto::generate_static_keypair;
use apt_types::{AuthProfile, EndpointId, Mode, SessionPolicy};
use serde_json::json;
use std::{future::ready, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
};

fn test_client_config() -> ResolvedClientConfig {
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

fn test_server() -> (AdmissionServer, [u8; 32]) {
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

fn public_service_response(
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
struct TestPublicService;

impl ApiSyncPublicService for TestPublicService {
    fn handle_public_request(
        &mut self,
        surface: &ApiSyncSurface,
        request: &ApiSyncRequest,
    ) -> Result<ApiSyncResponse, RuntimeError> {
        public_service_response(surface, request)
    }
}

async fn spawn_runtime_h2_server(
    admission: AdmissionServer,
    now_secs: u64,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = ApiSyncH2RequestHandler::new(ApiSyncSurface::starter());
    let admission = Arc::new(Mutex::new(admission));
    let public_service = Arc::new(Mutex::new(TestPublicService));
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

#[test]
fn runtime_bridge_drives_api_sync_hidden_upgrade_round_trip() {
    let surface = ApiSyncSurface::starter();
    let (mut server, server_static_public_key) = test_server();
    let now_secs = 1_700_100_000;
    let persistent_state = ClientPersistentState::default();
    let mut client_config = test_client_config();
    client_config.server_static_public_key = server_static_public_key;

    let prepared_ug1 =
        prepare_api_sync_ug1_request(&client_config, &persistent_state, &surface, now_secs)
            .unwrap();
    let response_ug2 = respond_api_sync_ug1_request(
        &mut server,
        &surface,
        &prepared_ug1.request,
        "h2-client-a",
        now_secs,
    )
    .unwrap()
    .expect("expected UG2 response");
    let prepared_ug3 = handle_api_sync_ug2_response(
        &surface,
        &prepared_ug1.authority,
        &response_ug2,
        prepared_ug1.state,
    )
    .unwrap();
    let (response_ug4, server_session) = respond_api_sync_ug3_request(
        &mut server,
        &surface,
        &prepared_ug3.request,
        "h2-client-a",
        now_secs + 1,
    )
    .unwrap()
    .expect("expected UG4 response");
    let client_session =
        handle_api_sync_ug4_response(&surface, &response_ug4, prepared_ug3.state).unwrap();

    assert_eq!(client_session.session_id, server_session.session_id);
    assert_eq!(
        client_session.chosen_carrier,
        CarrierBinding::S1EncryptedStream
    );
    assert!(client_session.masked_fallback_ticket.is_some());
    assert!(server_session.masked_fallback_ticket.is_some());
}

#[test]
fn runtime_bridge_returns_none_for_plain_public_requests() {
    let surface = ApiSyncSurface::starter();
    let (mut server, _) = test_server();
    let public_request = surface.build_state_push_request(
        "api.example.com",
        "device-a",
        json!({ "mode": Mode::STEALTH.value() }),
    );
    let reply = respond_api_sync_ug1_request(
        &mut server,
        &surface,
        &public_request,
        "h2-client-a",
        1_700_100_000,
    )
    .unwrap();
    assert!(reply.is_none());
}

#[tokio::test]
async fn client_driver_and_request_handler_complete_api_sync_hidden_upgrade() {
    let surface = ApiSyncSurface::starter();
    let driver = ApiSyncH2ClientDriver::new(surface.clone());
    let handler = ApiSyncH2RequestHandler::new(surface);
    let now_secs = 1_700_200_000;
    let (mut admission, server_static_public_key) = test_server();
    let persistent_state = ClientPersistentState::default();
    let mut client_config = test_client_config();
    client_config.server_static_public_key = server_static_public_key;
    let mut public_service = public_service_response;
    let mut server_session = None;

    let client_session = driver
        .establish_hidden_upgrade(
            &client_config,
            &persistent_state,
            |request| {
                let handled = handler
                    .handle_request(
                        &mut admission,
                        &mut public_service,
                        &request,
                        "h2-client-a",
                        now_secs,
                    )
                    .unwrap();
                if let Some(session) = handled.established_session().cloned() {
                    server_session = Some(session);
                }
                ready(Ok(handled.into_response()))
            },
            now_secs,
        )
        .await
        .unwrap();

    let server_session = server_session.expect("server should establish the same session");
    assert_eq!(client_session.session_id, server_session.session_id);
    assert_eq!(
        client_session.chosen_carrier,
        CarrierBinding::S1EncryptedStream
    );
    assert!(client_session.masked_fallback_ticket.is_some());
    assert!(server_session.masked_fallback_ticket.is_some());
}

#[test]
fn request_handler_preserves_public_service_for_plain_requests() {
    let surface = ApiSyncSurface::starter();
    let handler = ApiSyncH2RequestHandler::new(surface.clone());
    let (mut admission, _) = test_server();
    let request =
        surface.build_state_push_request("api.example.com", "device-a", json!({ "mode": 7 }));
    let mut public_service = public_service_response;

    let handled = handler
        .handle_request(
            &mut admission,
            &mut public_service,
            &request,
            "h2-client-a",
            1_700_200_000,
        )
        .unwrap();

    match handled {
        ApiSyncHandledRequest::Public(response) => {
            assert_eq!(response.status, 200);
            assert_eq!(response.body["state"]["battery"], 91);
            assert_eq!(response.body["state"]["accepted_mode"], 7);
            assert_eq!(response.body["state"]["authority"], "api.example.com");
            assert!(response.body["server_hints"]["next_cursor"].is_null());
        }
        other => panic!("expected public-only response, got {other:?}"),
    }
}

#[test]
fn request_handler_treats_malformed_probe_slots_as_public_requests() {
    let surface = ApiSyncSurface::starter();
    let handler = ApiSyncH2RequestHandler::new(surface.clone());
    let (mut admission, _) = test_server();
    let mut request =
        surface.build_state_push_request("api.example.com", "device-a", json!({ "mode": 7 }));
    request.body["metadata"]["sync_hint"] = json!("not-valid-base64!!!");
    let mut public_service = public_service_response;

    let handled = handler
        .handle_request(
            &mut admission,
            &mut public_service,
            &request,
            "h2-client-a",
            1_700_200_000,
        )
        .unwrap();

    match handled {
        ApiSyncHandledRequest::Public(response) => {
            assert_eq!(response.status, 200);
            assert_eq!(response.body["state"]["battery"], 91);
            assert_eq!(response.body["state"]["accepted_mode"], 7);
            assert_eq!(response.body["state"]["authority"], "api.example.com");
            assert!(response.body["server_hints"]["next_cursor"].is_null());
        }
        other => panic!("expected public-only response, got {other:?}"),
    }
}

#[tokio::test]
async fn hyper_backend_client_and_server_complete_hidden_upgrade() {
    let now_secs = 1_700_300_000;
    let (admission, server_static_public_key) = test_server();
    let (addr, server_task) = spawn_runtime_h2_server(admission, now_secs).await;
    let surface = ApiSyncSurface::starter();
    let driver = ApiSyncH2ClientDriver::new(surface);
    let mut client_config = test_client_config();
    client_config.server_static_public_key = server_static_public_key;
    let persistent_state = ClientPersistentState::default();

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut backend = ApiSyncH2HyperClient::connect(stream).await.unwrap();
    let session = driver
        .establish_hidden_upgrade_with_hyper_client(
            &client_config,
            &persistent_state,
            &mut backend,
            now_secs,
        )
        .await
        .unwrap();

    assert_eq!(session.chosen_carrier, CarrierBinding::S1EncryptedStream);
    assert!(session.masked_fallback_ticket.is_some());
    drop(backend);
    server_task.abort();
}

#[tokio::test]
async fn hyper_backend_preserves_plain_public_service_semantics() {
    let now_secs = 1_700_300_100;
    let (admission, _) = test_server();
    let (addr, server_task) = spawn_runtime_h2_server(admission, now_secs).await;
    let surface = ApiSyncSurface::starter();
    let mut backend = ApiSyncH2HyperClient::connect(TcpStream::connect(addr).await.unwrap())
        .await
        .unwrap();
    let request =
        surface.build_state_push_request("api.example.com", "device-a", json!({ "mode": 7 }));

    let response = backend.round_trip(&surface, request).await.unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(response.body["state"]["accepted_mode"], 7);
    assert_eq!(response.body["state"]["authority"], "api.example.com");
    assert!(response.body["server_hints"]["next_cursor"].is_null());
    drop(backend);
    server_task.abort();
}
