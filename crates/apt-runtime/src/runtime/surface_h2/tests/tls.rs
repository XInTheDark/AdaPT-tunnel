use super::{super::*, support::*};
use crate::{
    generate_d2_tls_identity, V2ClientFamilyConfig, V2ClientSurfacePlan, V2DeploymentStrength,
    V2ServerSurfaceConfig, V2ServerSurfacePlan, V2SurfaceTrustConfig,
};
use apt_origin::{OriginFamilyProfile, PublicSessionTransport};
use serde_json::json;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, sync::Mutex, task::JoinHandle};

const TEST_AUTHORITY: &str = "api.example.com";

#[tokio::test]
async fn tls_surface_plan_client_and_server_complete_hidden_upgrade() {
    let now_secs = 1_700_400_000;
    let (admission, server_static_public_key) = test_server();
    let identity_dir = write_test_tls_identity().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client_plan, server_plan) = tls_surface_plans(addr, &identity_dir.cert_path);
    let server_task = spawn_runtime_h2_tls_server(
        listener,
        admission,
        now_secs,
        &server_plan,
        &identity_dir.cert_path,
        &identity_dir.key_path,
    )
    .await;

    let surface = ApiSyncSurface::starter();
    let driver = ApiSyncH2ClientDriver::new(surface);
    let mut client_config = test_client_config();
    client_config.server_static_public_key = server_static_public_key;
    let persistent_state = ClientPersistentState::default();

    let session = driver
        .establish_hidden_upgrade_with_surface_plan(
            &client_config,
            &persistent_state,
            &client_plan,
            now_secs,
        )
        .await
        .unwrap();

    assert_eq!(session.chosen_carrier, CarrierBinding::S1EncryptedStream);
    assert!(session.masked_fallback_ticket.is_some());
    server_task.abort();
}

#[tokio::test]
async fn tls_surface_plan_preserves_plain_public_service_semantics() {
    let now_secs = 1_700_400_100;
    let (admission, _) = test_server();
    let identity_dir = write_test_tls_identity().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client_plan, server_plan) = tls_surface_plans(addr, &identity_dir.cert_path);
    let server_task = spawn_runtime_h2_tls_server(
        listener,
        admission,
        now_secs,
        &server_plan,
        &identity_dir.cert_path,
        &identity_dir.key_path,
    )
    .await;

    let surface = ApiSyncSurface::starter();
    let mut backend = ApiSyncH2HyperClient::connect_tls_with_surface_plan(&client_plan)
        .await
        .unwrap();
    let request =
        surface.build_state_push_request(TEST_AUTHORITY, "device-a", json!({ "mode": 7 }));

    let response = backend.round_trip(&surface, request).await.unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(response.body["state"]["accepted_mode"], 7);
    assert_eq!(response.body["state"]["authority"], TEST_AUTHORITY);
    assert!(response.body["server_hints"]["next_cursor"].is_null());
    drop(backend);
    server_task.abort();
}

#[test]
fn tls_client_config_uses_surface_plan_authority_as_default_server_name() {
    let temp_identity = write_test_tls_identity().unwrap();
    let plan = V2ClientFamilyConfig {
        authority: TEST_AUTHORITY.to_string(),
        endpoint: "127.0.0.1:443".to_string(),
        trust: V2SurfaceTrustConfig {
            pinned_certificate: Some(format!("file:{}", temp_identity.cert_path.display())),
            ..V2SurfaceTrustConfig::default()
        },
        cover_family: "api-sync".to_string(),
        profile_version: OriginFamilyProfile::api_sync().profile_version,
        deployment_strength: V2DeploymentStrength::Lab,
    }
    .to_surface_plan(PublicSessionTransport::S1H2)
    .unwrap();

    let tls = build_api_sync_h2_tls_client_config(&plan).unwrap();
    assert_eq!(tls.server_name(), TEST_AUTHORITY);
}

async fn spawn_runtime_h2_tls_server(
    listener: TcpListener,
    admission: AdmissionServer,
    now_secs: u64,
    server_plan: &V2ServerSurfacePlan,
    cert_path: &Path,
    key_path: &Path,
) -> JoinHandle<()> {
    let handler = ApiSyncH2RequestHandler::new(ApiSyncSurface::starter());
    let admission = Arc::new(Mutex::new(admission));
    let public_service = Arc::new(Mutex::new(TestPublicService));
    let tls_config = build_api_sync_h2_tls_server_config_for_surface_plan(
        server_plan,
        &format!("file:{}", cert_path.display()),
        &format!("file:{}", key_path.display()),
    )
    .unwrap();
    tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        serve_api_sync_h2_tls_connection(
            stream,
            tls_config,
            handler,
            admission,
            public_service,
            peer_addr.to_string(),
            move || now_secs,
        )
        .await
        .unwrap();
    })
}

fn tls_surface_plans(
    addr: SocketAddr,
    cert_path: &Path,
) -> (V2ClientSurfacePlan, V2ServerSurfacePlan) {
    let profile_version = OriginFamilyProfile::api_sync().profile_version;
    let trust = V2SurfaceTrustConfig {
        server_name: Some(TEST_AUTHORITY.to_string()),
        pinned_certificate: Some(format!("file:{}", cert_path.display())),
        ..V2SurfaceTrustConfig::default()
    };
    let client_plan = V2ClientFamilyConfig {
        authority: TEST_AUTHORITY.to_string(),
        endpoint: addr.to_string(),
        trust: trust.clone(),
        cover_family: "api-sync".to_string(),
        profile_version: profile_version.clone(),
        deployment_strength: V2DeploymentStrength::SelfContained,
    }
    .to_surface_plan(PublicSessionTransport::S1H2)
    .unwrap();
    let server_plan = V2ServerSurfaceConfig {
        authority: TEST_AUTHORITY.to_string(),
        bind: addr,
        public_endpoint: addr.to_string(),
        trust,
        cover_family: "api-sync".to_string(),
        profile_version,
        deployment_strength: V2DeploymentStrength::SelfContained,
        origin_backend: Some("https://origin.internal".to_string()),
    }
    .to_surface_plan(PublicSessionTransport::S1H2)
    .unwrap();
    (client_plan, server_plan)
}

struct TestTlsIdentityPaths {
    cert_path: PathBuf,
    key_path: PathBuf,
}

fn write_test_tls_identity() -> Result<TestTlsIdentityPaths, RuntimeError> {
    let temp_dir = std::env::temp_dir().join(format!(
        "adapt-h2-tls-test-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).map_err(|source| RuntimeError::IoWithPath {
        path: temp_dir.clone(),
        source,
    })?;
    let cert_path = temp_dir.join("api-sync-cert.pem");
    let key_path = temp_dir.join("api-sync-key.pem");
    let identity = generate_d2_tls_identity(vec![TEST_AUTHORITY.to_string()])?;
    std::fs::write(&cert_path, &identity.certificate_pem).map_err(|source| {
        RuntimeError::IoWithPath {
            path: cert_path.clone(),
            source,
        }
    })?;
    std::fs::write(&key_path, &identity.private_key_pem).map_err(|source| {
        RuntimeError::IoWithPath {
            path: key_path.clone(),
            source,
        }
    })?;
    Ok(TestTlsIdentityPaths {
        cert_path,
        key_path,
    })
}
