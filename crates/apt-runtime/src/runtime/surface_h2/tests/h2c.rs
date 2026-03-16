use super::{super::*, support::*};
use serde_json::json;
use tokio::net::TcpStream;

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
