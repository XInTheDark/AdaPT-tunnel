use crate::{
    adaptive::{
        admission_path_profile, build_client_network_context, discover_client_network_context,
        AdaptiveDatapath, AdaptiveRuntimeConfig,
    },
    client_runtime::ClientRuntimeHooks,
    config::{
        ClientPersistentState, PersistedNetworkProfile, ResolvedAuthorizedPeer,
        ResolvedClientConfig, ResolvedServerConfig, ServerSessionExtension,
        SessionTransportParameters,
    },
    error::RuntimeError,
    route::{configure_client_network_for_endpoints, configure_server_network},
    status::{ClientStatus, RuntimeStatus, ServerStatus},
    tun::{spawn_tun_worker, TunHandle, TunInterfaceConfig},
};
use apt_admission::{
    AdmissionConfig, AdmissionServer, ClientCredential, ClientSessionRequest, EstablishedSession,
};
use apt_carriers::CarrierProfile;
use apt_crypto::{SealedEnvelope, StaticKeypair};
use apt_observability::{record_event, AptEvent, ObservabilityConfig, TelemetrySnapshot};
use apt_tunnel::Frame;
use apt_types::{AuthProfile, CarrierBinding, CredentialIdentity, Mode};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, SystemTime},
};
use tokio::{sync::mpsc, time::interval};
use tracing::{info, warn};

mod client;
mod scheduler;
mod server;
mod session_transport;
mod support;
mod surface_h2;

pub use self::surface_h2::{
    build_api_sync_h2_tls_client_config, build_api_sync_h2_tls_server_config_for_surface_plan,
    handle_api_sync_ug2_response, handle_api_sync_ug4_response, prepare_api_sync_ug1_request,
    respond_api_sync_ug1_request, respond_api_sync_ug3_request,
    respond_api_sync_ug3_request_with_extension_builder, serve_api_sync_h2_connection,
    serve_api_sync_h2_tls_connection, ApiSyncH2ClientDriver, ApiSyncH2ClientSession,
    ApiSyncH2ConnectionState, ApiSyncH2HyperClient, ApiSyncH2RequestHandler,
    ApiSyncH2TlsClientConfig, ApiSyncHandledRequest, ApiSyncPublicService,
    PreparedApiSyncUg1Request, PreparedApiSyncUg3Request,
};

use self::{scheduler::*, session_transport::*, support::*};

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

pub async fn run_client(config: ResolvedClientConfig) -> Result<ClientRuntimeResult, RuntimeError> {
    client::run_client(config, ClientRuntimeHooks::default()).await
}

pub async fn run_client_with_hooks(
    config: ResolvedClientConfig,
    hooks: ClientRuntimeHooks,
) -> Result<ClientRuntimeResult, RuntimeError> {
    client::run_client(config, hooks).await
}

pub async fn run_server(config: ResolvedServerConfig) -> Result<ServerRuntimeResult, RuntimeError> {
    server::run_server(config).await
}
