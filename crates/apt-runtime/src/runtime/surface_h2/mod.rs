use super::*;
use apt_surface_h2::{ApiSyncRequest, ApiSyncResponse, ApiSyncSurface};

mod backend;
mod bridge;
mod client;
mod server;

#[cfg(test)]
mod tests;

pub use self::backend::{
    build_api_sync_h2_tls_client_config, build_api_sync_h2_tls_server_config_for_surface_plan,
    serve_api_sync_h2_connection, serve_api_sync_h2_tls_connection, ApiSyncH2HyperClient,
    ApiSyncH2TlsClientConfig,
};
pub use self::bridge::{
    handle_api_sync_ug2_response, handle_api_sync_ug4_response, prepare_api_sync_ug1_request,
    respond_api_sync_ug1_request, respond_api_sync_ug3_request,
    respond_api_sync_ug3_request_with_extension_builder, PreparedApiSyncUg1Request,
    PreparedApiSyncUg3Request,
};
pub use self::client::{ApiSyncH2ClientDriver, ApiSyncH2ClientSession};
pub use self::server::{
    ApiSyncH2ConnectionState, ApiSyncH2RequestHandler, ApiSyncHandledRequest, ApiSyncPublicService,
};

fn is_ignorable_api_sync_probe_error(error: &RuntimeError) -> bool {
    matches!(
        error,
        RuntimeError::SurfaceH2(_) | RuntimeError::Serialization(_) | RuntimeError::Tunnel(_)
    )
}
