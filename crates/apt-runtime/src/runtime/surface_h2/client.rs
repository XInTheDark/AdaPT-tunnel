use super::*;
use std::future::Future;

#[derive(Clone, Debug)]
pub struct ApiSyncH2ClientDriver {
    surface: ApiSyncSurface,
}

impl ApiSyncH2ClientDriver {
    #[must_use]
    pub const fn new(surface: ApiSyncSurface) -> Self {
        Self { surface }
    }

    #[must_use]
    pub const fn surface(&self) -> &ApiSyncSurface {
        &self.surface
    }

    pub async fn establish_hidden_upgrade<F, Fut>(
        &self,
        config: &ResolvedClientConfig,
        persistent_state: &ClientPersistentState,
        mut round_trip: F,
        now_secs: u64,
    ) -> Result<EstablishedSession, RuntimeError>
    where
        F: FnMut(ApiSyncRequest) -> Fut,
        Fut: Future<Output = Result<ApiSyncResponse, RuntimeError>>,
    {
        let prepared_ug1 =
            prepare_api_sync_ug1_request(config, persistent_state, &self.surface, now_secs)?;
        let response_ug2 = round_trip(prepared_ug1.request).await?;
        let prepared_ug3 = handle_api_sync_ug2_response(
            &self.surface,
            &prepared_ug1.authority,
            &response_ug2,
            prepared_ug1.state,
        )?;
        let response_ug4 = round_trip(prepared_ug3.request).await?;
        handle_api_sync_ug4_response(&self.surface, &response_ug4, prepared_ug3.state)
    }

    pub async fn establish_hidden_upgrade_with_hyper_client(
        &self,
        config: &ResolvedClientConfig,
        persistent_state: &ClientPersistentState,
        backend: &mut ApiSyncH2HyperClient,
        now_secs: u64,
    ) -> Result<EstablishedSession, RuntimeError> {
        let prepared_ug1 =
            prepare_api_sync_ug1_request(config, persistent_state, &self.surface, now_secs)?;
        let response_ug2 = backend
            .round_trip(&self.surface, prepared_ug1.request)
            .await?;
        let prepared_ug3 = handle_api_sync_ug2_response(
            &self.surface,
            &prepared_ug1.authority,
            &response_ug2,
            prepared_ug1.state,
        )?;
        let response_ug4 = backend
            .round_trip(&self.surface, prepared_ug3.request)
            .await?;
        handle_api_sync_ug4_response(&self.surface, &response_ug4, prepared_ug3.state)
    }
}
