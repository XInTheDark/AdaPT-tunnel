use super::*;
use apt_surface_h2::{ApiSyncRequest, ApiSyncResponse, ApiSyncSurface};

mod backend;
mod bridge;
mod client;
mod server;

#[cfg(test)]
mod tests;

pub use self::backend::{serve_api_sync_h2_connection, ApiSyncH2HyperClient};
pub use self::bridge::{
    handle_api_sync_ug2_response, handle_api_sync_ug4_response, prepare_api_sync_ug1_request,
    respond_api_sync_ug1_request, respond_api_sync_ug3_request, PreparedApiSyncUg1Request,
    PreparedApiSyncUg3Request,
};
pub use self::client::ApiSyncH2ClientDriver;
pub use self::server::{ApiSyncH2RequestHandler, ApiSyncHandledRequest, ApiSyncPublicService};

fn is_ignorable_api_sync_probe_error(error: &RuntimeError) -> bool {
    matches!(
        error,
        RuntimeError::SurfaceH2(_) | RuntimeError::Serialization(_)
    )
}
