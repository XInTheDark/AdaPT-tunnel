use super::*;

pub trait ApiSyncPublicService {
    fn handle_public_request(
        &mut self,
        surface: &ApiSyncSurface,
        request: &ApiSyncRequest,
    ) -> Result<ApiSyncResponse, RuntimeError>;
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
}

impl ApiSyncHandledRequest {
    #[must_use]
    pub fn established_session(&self) -> Option<&EstablishedSession> {
        match self {
            Self::Public(_) => None,
            Self::HiddenUpgrade {
                established_session,
                ..
            } => established_session.as_ref(),
        }
    }

    #[must_use]
    pub fn into_response(self) -> ApiSyncResponse {
        match self {
            Self::Public(response) | Self::HiddenUpgrade { response, .. } => response,
        }
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

        match respond_api_sync_ug3_request(admission, &self.surface, request, source_id, now_secs) {
            Ok(Some((response, established_session))) => Ok(ApiSyncHandledRequest::HiddenUpgrade {
                response,
                established_session: Some(established_session),
            }),
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
