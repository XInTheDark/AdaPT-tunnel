use super::*;
use apt_surface_h2::ApiSyncRequestTunnelEnvelope;
use apt_tunnel::{DecodedPacket, Frame, TunnelSession};
use apt_types::MINIMUM_REPLAY_WINDOW;
use serde_json::json;
use std::future::Future;

#[derive(Clone, Debug)]
pub struct ApiSyncH2ClientSession {
    surface: ApiSyncSurface,
    authority: String,
    device_id: String,
    established: EstablishedSession,
    tunnel: TunnelSession,
}

impl ApiSyncH2ClientSession {
    fn new(
        surface: ApiSyncSurface,
        authority: String,
        device_id: String,
        established: EstablishedSession,
        now_secs: u64,
    ) -> Self {
        let tunnel = TunnelSession::new(
            established.session_id,
            established.role,
            established.secrets.clone(),
            established.rekey_limits,
            u64::try_from(MINIMUM_REPLAY_WINDOW).expect("replay window fits into u64"),
            now_secs,
        );
        Self {
            surface,
            authority,
            device_id,
            established,
            tunnel,
        }
    }

    #[must_use]
    pub const fn surface(&self) -> &ApiSyncSurface {
        &self.surface
    }

    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    #[must_use]
    pub const fn established(&self) -> &EstablishedSession {
        &self.established
    }

    pub fn prepare_tunnel_request(
        &mut self,
        frames: &[Frame],
        now_secs: u64,
    ) -> Result<ApiSyncRequest, RuntimeError> {
        let encoded = self.tunnel.encode_packet(frames, now_secs)?;
        let mut request = self.surface.build_state_push_request(
            &self.authority,
            &self.device_id,
            json!({ "delta": true }),
        );
        self.surface.embed_request_tunnel_envelope(
            &mut request,
            &ApiSyncRequestTunnelEnvelope {
                session_id: self.established.session_id,
                packet: encoded.bytes,
            },
        )?;
        Ok(request)
    }

    pub fn handle_tunnel_response(
        &mut self,
        response: &ApiSyncResponse,
        now_secs: u64,
    ) -> Result<Option<DecodedPacket>, RuntimeError> {
        let Some(tunnel) = self.surface.extract_response_tunnel_envelope(response)? else {
            return Ok(None);
        };
        if tunnel.session_id != self.established.session_id {
            return Err(RuntimeError::InvalidConfig(
                "api-sync tunnel response session id mismatch".to_string(),
            ));
        }
        Ok(Some(self.tunnel.decode_packet(&tunnel.packet, now_secs)?))
    }

    pub async fn exchange_tunnel_frames<F, Fut>(
        &mut self,
        mut round_trip: F,
        frames: &[Frame],
        now_secs: u64,
    ) -> Result<Option<DecodedPacket>, RuntimeError>
    where
        F: FnMut(ApiSyncRequest) -> Fut,
        Fut: Future<Output = Result<ApiSyncResponse, RuntimeError>>,
    {
        let request = self.prepare_tunnel_request(frames, now_secs)?;
        let response = round_trip(request).await?;
        self.handle_tunnel_response(&response, now_secs)
    }

    pub async fn exchange_tunnel_frames_with_hyper_client(
        &mut self,
        backend: &mut ApiSyncH2HyperClient,
        frames: &[Frame],
        now_secs: u64,
    ) -> Result<Option<DecodedPacket>, RuntimeError> {
        let request = self.prepare_tunnel_request(frames, now_secs)?;
        let response = backend.round_trip(&self.surface, request).await?;
        self.handle_tunnel_response(&response, now_secs)
    }
}

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
        round_trip: F,
        now_secs: u64,
    ) -> Result<EstablishedSession, RuntimeError>
    where
        F: FnMut(ApiSyncRequest) -> Fut,
        Fut: Future<Output = Result<ApiSyncResponse, RuntimeError>>,
    {
        Ok(self
            .establish_tunnel_session(config, persistent_state, round_trip, now_secs)
            .await?
            .established)
    }

    pub async fn establish_tunnel_session<F, Fut>(
        &self,
        config: &ResolvedClientConfig,
        persistent_state: &ClientPersistentState,
        mut round_trip: F,
        now_secs: u64,
    ) -> Result<ApiSyncH2ClientSession, RuntimeError>
    where
        F: FnMut(ApiSyncRequest) -> Fut,
        Fut: Future<Output = Result<ApiSyncResponse, RuntimeError>>,
    {
        let prepared_ug1 =
            prepare_api_sync_ug1_request(config, persistent_state, &self.surface, now_secs)?;
        let authority = prepared_ug1.authority.clone();
        let device_id = config
            .client_identity
            .clone()
            .unwrap_or_else(|| "shared-device".to_string());
        let response_ug2 = round_trip(prepared_ug1.request).await?;
        let prepared_ug3 = handle_api_sync_ug2_response(
            &self.surface,
            &authority,
            &response_ug2,
            prepared_ug1.state,
        )?;
        let response_ug4 = round_trip(prepared_ug3.request).await?;
        let session =
            handle_api_sync_ug4_response(&self.surface, &response_ug4, prepared_ug3.state)?;
        Ok(ApiSyncH2ClientSession::new(
            self.surface.clone(),
            authority,
            device_id,
            session,
            now_secs,
        ))
    }

    pub async fn establish_hidden_upgrade_with_hyper_client(
        &self,
        config: &ResolvedClientConfig,
        persistent_state: &ClientPersistentState,
        backend: &mut ApiSyncH2HyperClient,
        now_secs: u64,
    ) -> Result<EstablishedSession, RuntimeError> {
        Ok(self
            .establish_tunnel_session_with_hyper_client(config, persistent_state, backend, now_secs)
            .await?
            .established)
    }

    pub async fn establish_tunnel_session_with_hyper_client(
        &self,
        config: &ResolvedClientConfig,
        persistent_state: &ClientPersistentState,
        backend: &mut ApiSyncH2HyperClient,
        now_secs: u64,
    ) -> Result<ApiSyncH2ClientSession, RuntimeError> {
        let prepared_ug1 =
            prepare_api_sync_ug1_request(config, persistent_state, &self.surface, now_secs)?;
        let authority = prepared_ug1.authority.clone();
        let device_id = config
            .client_identity
            .clone()
            .unwrap_or_else(|| "shared-device".to_string());
        let response_ug2 = backend
            .round_trip(&self.surface, prepared_ug1.request)
            .await?;
        let prepared_ug3 = handle_api_sync_ug2_response(
            &self.surface,
            &authority,
            &response_ug2,
            prepared_ug1.state,
        )?;
        let response_ug4 = backend
            .round_trip(&self.surface, prepared_ug3.request)
            .await?;
        let session =
            handle_api_sync_ug4_response(&self.surface, &response_ug4, prepared_ug3.state)?;
        Ok(ApiSyncH2ClientSession::new(
            self.surface.clone(),
            authority,
            device_id,
            session,
            now_secs,
        ))
    }

    pub async fn establish_hidden_upgrade_with_surface_plan(
        &self,
        config: &ResolvedClientConfig,
        persistent_state: &ClientPersistentState,
        surface_plan: &crate::V2ClientSurfacePlan,
        now_secs: u64,
    ) -> Result<EstablishedSession, RuntimeError> {
        Ok(self
            .establish_tunnel_session_with_surface_plan(
                config,
                persistent_state,
                surface_plan,
                now_secs,
            )
            .await?
            .established)
    }

    pub async fn establish_tunnel_session_with_surface_plan(
        &self,
        config: &ResolvedClientConfig,
        persistent_state: &ClientPersistentState,
        surface_plan: &crate::V2ClientSurfacePlan,
        now_secs: u64,
    ) -> Result<ApiSyncH2ClientSession, RuntimeError> {
        let mut backend = ApiSyncH2HyperClient::connect_tls_with_surface_plan(surface_plan).await?;
        self.establish_tunnel_session_with_hyper_client(
            config,
            persistent_state,
            &mut backend,
            now_secs,
        )
        .await
    }
}
