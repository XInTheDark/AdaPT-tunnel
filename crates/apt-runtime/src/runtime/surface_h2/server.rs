use super::*;
use apt_admission::{AdmissionError, EstablishedSession};
use apt_surface_h2::{
    ApiSyncRequestTunnelEnvelope, ApiSyncRequestTunnelPollEnvelope, ApiSyncResponseTunnelEnvelope,
};
use apt_tunnel::{DecodedPacket, Frame, TunnelSession};
use apt_types::{SessionId, MINIMUM_REPLAY_WINDOW};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

pub trait ApiSyncTunnelDispatch: Send + Sync {
    fn wait_for_outbound_frames<'a>(
        &'a self,
        session_id: SessionId,
        limit: usize,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Frame>, RuntimeError>> + Send + 'a>>;
}

pub trait ApiSyncPublicService {
    fn handle_public_request(
        &mut self,
        surface: &ApiSyncSurface,
        request: &ApiSyncRequest,
    ) -> Result<ApiSyncResponse, RuntimeError>;

    fn build_ug4_extensions(
        &mut self,
        _established_session: &EstablishedSession,
    ) -> Result<Vec<Vec<u8>>, AdmissionError> {
        Ok(Vec::new())
    }

    fn note_established_session(
        &mut self,
        _surface: &ApiSyncSurface,
        _established_session: &EstablishedSession,
    ) -> Result<(), RuntimeError> {
        Ok(())
    }

    fn note_closed_session(&mut self, _established_session: &EstablishedSession) {}

    fn tunnel_dispatch(&self) -> Option<Arc<dyn ApiSyncTunnelDispatch>> {
        None
    }

    fn handle_established_request(
        &mut self,
        surface: &ApiSyncSurface,
        request: &ApiSyncRequest,
        established_session: &EstablishedSession,
        decoded_packet: &DecodedPacket,
    ) -> Result<(ApiSyncResponse, Vec<Frame>), RuntimeError> {
        let _ = established_session;
        let _ = decoded_packet;
        let response = self.handle_public_request(surface, request)?;
        Ok((response, Vec::new()))
    }
}

impl<F> ApiSyncPublicService for F
where
    F: FnMut(&ApiSyncSurface, &ApiSyncRequest) -> Result<ApiSyncResponse, RuntimeError>,
{
    fn handle_public_request(
        &mut self,
        surface: &ApiSyncSurface,
        request: &ApiSyncRequest,
    ) -> Result<ApiSyncResponse, RuntimeError> {
        self(surface, request)
    }
}

#[derive(Clone, Debug)]
pub enum ApiSyncHandledRequest {
    Public(ApiSyncResponse),
    HiddenUpgrade {
        response: ApiSyncResponse,
        established_session: Option<EstablishedSession>,
    },
    TunnelData {
        response: ApiSyncResponse,
        decoded_packet: DecodedPacket,
    },
}

impl ApiSyncHandledRequest {
    #[must_use]
    pub fn established_session(&self) -> Option<&EstablishedSession> {
        match self {
            Self::Public(_) | Self::TunnelData { .. } => None,
            Self::HiddenUpgrade {
                established_session,
                ..
            } => established_session.as_ref(),
        }
    }

    #[must_use]
    pub fn decoded_packet(&self) -> Option<&DecodedPacket> {
        match self {
            Self::TunnelData { decoded_packet, .. } => Some(decoded_packet),
            Self::Public(_) | Self::HiddenUpgrade { .. } => None,
        }
    }

    #[must_use]
    pub fn into_response(self) -> ApiSyncResponse {
        match self {
            Self::Public(response)
            | Self::HiddenUpgrade { response, .. }
            | Self::TunnelData { response, .. } => response,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ApiSyncH2ConnectionState {
    established_session: Option<EstablishedSession>,
    tunnel: Option<TunnelSession>,
}

impl ApiSyncH2ConnectionState {
    #[must_use]
    pub fn established_session(&self) -> Option<&EstablishedSession> {
        self.established_session.as_ref()
    }

    pub fn established_tunnel_poll_session(
        &self,
        surface: &ApiSyncSurface,
        request: &ApiSyncRequest,
    ) -> Result<Option<EstablishedSession>, RuntimeError> {
        let Some(established_session) = self.established_session.clone() else {
            return Ok(None);
        };
        let session_id = match surface.extract_request_tunnel_poll_envelope(request) {
            Ok(Some(ApiSyncRequestTunnelPollEnvelope { session_id })) => session_id,
            Ok(None) => return Ok(None),
            Err(error) => {
                let runtime_error = RuntimeError::from(error);
                if is_ignorable_api_sync_probe_error(&runtime_error) {
                    return Ok(None);
                }
                return Err(runtime_error);
            }
        };
        if session_id != established_session.session_id {
            return Ok(None);
        }
        Ok(Some(established_session))
    }

    fn note_established_session(&mut self, session: EstablishedSession, now_secs: u64) {
        let tunnel = TunnelSession::new(
            session.session_id,
            session.role,
            session.secrets.clone(),
            session.rekey_limits,
            u64::try_from(MINIMUM_REPLAY_WINDOW).expect("replay window fits into u64"),
            now_secs,
        );
        self.established_session = Some(session);
        self.tunnel = Some(tunnel);
    }

    fn handle_tunnel_request<S>(
        &mut self,
        surface: &ApiSyncSurface,
        public_service: &mut S,
        request: &ApiSyncRequest,
        now_secs: u64,
    ) -> Result<Option<ApiSyncHandledRequest>, RuntimeError>
    where
        S: ApiSyncPublicService,
    {
        let Some(established_session) = self.established_session.clone() else {
            return Ok(None);
        };
        let Some(ApiSyncRequestTunnelEnvelope { session_id, packet }) =
            surface.extract_request_tunnel_envelope(request)?
        else {
            return Ok(None);
        };
        if session_id != established_session.session_id {
            return Ok(None);
        }
        let tunnel = self.tunnel.as_mut().ok_or(RuntimeError::InvalidConfig(
            "api-sync connection lost established tunnel state".to_string(),
        ))?;
        let decoded_packet = tunnel.decode_packet(&packet, now_secs)?;
        let (mut response, mut outbound_frames) = public_service.handle_established_request(
            surface,
            request,
            &established_session,
            &decoded_packet,
        )?;
        outbound_frames.extend(decoded_packet.ack_suggestions.clone());
        if !outbound_frames.is_empty() {
            let encoded = tunnel.encode_packet(&outbound_frames, now_secs)?;
            surface.embed_response_tunnel_envelope(
                &mut response,
                &ApiSyncResponseTunnelEnvelope {
                    session_id: established_session.session_id,
                    packet: encoded.bytes,
                },
            )?;
        }
        Ok(Some(ApiSyncHandledRequest::TunnelData {
            response,
            decoded_packet,
        }))
    }

    pub fn embed_outbound_tunnel_frames(
        &mut self,
        surface: &ApiSyncSurface,
        response: &mut ApiSyncResponse,
        session_id: SessionId,
        outbound_frames: &[Frame],
        now_secs: u64,
    ) -> Result<(), RuntimeError> {
        if outbound_frames.is_empty() {
            return Ok(());
        }
        let tunnel = self.tunnel.as_mut().ok_or(RuntimeError::InvalidConfig(
            "api-sync connection lost established tunnel state".to_string(),
        ))?;
        let encoded = tunnel.encode_packet(outbound_frames, now_secs)?;
        surface.embed_response_tunnel_envelope(
            response,
            &ApiSyncResponseTunnelEnvelope {
                session_id,
                packet: encoded.bytes,
            },
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ApiSyncH2RequestHandler {
    surface: ApiSyncSurface,
}

impl ApiSyncH2RequestHandler {
    #[must_use]
    pub const fn new(surface: ApiSyncSurface) -> Self {
        Self { surface }
    }

    #[must_use]
    pub const fn surface(&self) -> &ApiSyncSurface {
        &self.surface
    }

    pub fn handle_request<S>(
        &self,
        admission: &mut AdmissionServer,
        public_service: &mut S,
        request: &ApiSyncRequest,
        source_id: &str,
        now_secs: u64,
    ) -> Result<ApiSyncHandledRequest, RuntimeError>
    where
        S: ApiSyncPublicService,
    {
        let mut connection_state = ApiSyncH2ConnectionState::default();
        self.handle_request_with_state(
            admission,
            &mut connection_state,
            public_service,
            request,
            source_id,
            now_secs,
        )
    }

    pub fn handle_request_with_state<S>(
        &self,
        admission: &mut AdmissionServer,
        connection_state: &mut ApiSyncH2ConnectionState,
        public_service: &mut S,
        request: &ApiSyncRequest,
        source_id: &str,
        now_secs: u64,
    ) -> Result<ApiSyncHandledRequest, RuntimeError>
    where
        S: ApiSyncPublicService,
    {
        match connection_state.handle_tunnel_request(
            &self.surface,
            public_service,
            request,
            now_secs,
        ) {
            Ok(Some(handled)) => return Ok(handled),
            Ok(None) => {}
            Err(error) if is_ignorable_api_sync_probe_error(&error) => {
                return public_service
                    .handle_public_request(&self.surface, request)
                    .map(ApiSyncHandledRequest::Public);
            }
            Err(error) => return Err(error),
        }

        match respond_api_sync_ug1_request(admission, &self.surface, request, source_id, now_secs) {
            Ok(Some(response)) => {
                return Ok(ApiSyncHandledRequest::HiddenUpgrade {
                    response,
                    established_session: None,
                });
            }
            Ok(None) => {}
            Err(error) if is_ignorable_api_sync_probe_error(&error) => {
                return public_service
                    .handle_public_request(&self.surface, request)
                    .map(ApiSyncHandledRequest::Public);
            }
            Err(error) => return Err(error),
        }

        match respond_api_sync_ug3_request_with_extension_builder(
            admission,
            &self.surface,
            request,
            source_id,
            now_secs,
            |session| public_service.build_ug4_extensions(session),
        ) {
            Ok(Some((response, established_session))) => {
                connection_state.note_established_session(established_session.clone(), now_secs);
                Ok(ApiSyncHandledRequest::HiddenUpgrade {
                    response,
                    established_session: Some(established_session),
                })
            }
            Ok(None) => public_service
                .handle_public_request(&self.surface, request)
                .map(ApiSyncHandledRequest::Public),
            Err(error) if is_ignorable_api_sync_probe_error(&error) => public_service
                .handle_public_request(&self.surface, request)
                .map(ApiSyncHandledRequest::Public),
            Err(error) => Err(error),
        }
    }
}
