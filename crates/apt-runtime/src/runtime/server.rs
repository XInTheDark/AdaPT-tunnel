use super::*;

mod h2_service;

pub(super) async fn run_server(
    config: ResolvedServerConfig,
) -> Result<ServerRuntimeResult, RuntimeError> {
    h2_service::run_h2_server(config).await
}
