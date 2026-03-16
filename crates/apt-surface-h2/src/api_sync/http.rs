use super::*;
use ::http::{
    header::{CONTENT_TYPE, HOST},
    HeaderValue, Method, Request as HttpRequest, Response as HttpResponse, StatusCode,
};

const API_SYNC_JSON_CONTENT_TYPE: &str = "application/json";

impl ApiSyncSurface {
    pub fn encode_http_request(
        &self,
        request: &ApiSyncRequest,
    ) -> Result<HttpRequest<Vec<u8>>, SurfaceH2Error> {
        let body = serde_json::to_vec(&request.body).map_err(|error| {
            SurfaceH2Error::Http(format!("request json encode failed: {error}"))
        })?;
        let host = HeaderValue::from_str(&request.authority)
            .map_err(|_| SurfaceH2Error::Http("invalid request authority".to_string()))?;
        let content_type = HeaderValue::from_static(API_SYNC_JSON_CONTENT_TYPE);
        HttpRequest::builder()
            .method(Method::POST)
            .uri(&request.path)
            .header(HOST, host)
            .header(CONTENT_TYPE, content_type)
            .body(body)
            .map_err(|error| SurfaceH2Error::Http(format!("http request build failed: {error}")))
    }

    pub fn decode_http_request(
        &self,
        request: &HttpRequest<Vec<u8>>,
    ) -> Result<ApiSyncRequest, SurfaceH2Error> {
        if request.method() != Method::POST {
            return Err(SurfaceH2Error::Http(format!(
                "unexpected api-sync method {}",
                request.method()
            )));
        }
        let authority = request
            .headers()
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .or_else(|| {
                request
                    .uri()
                    .authority()
                    .map(|authority| authority.as_str())
            })
            .ok_or_else(|| {
                SurfaceH2Error::Http("api-sync request missing authority".to_string())
            })?;
        let body = serde_json::from_slice(request.body()).map_err(|error| {
            SurfaceH2Error::Http(format!("request json decode failed: {error}"))
        })?;
        Ok(ApiSyncRequest {
            authority: authority.to_string(),
            path: request.uri().path().to_string(),
            authenticated_public: true,
            body,
        })
    }

    pub fn encode_http_response(
        &self,
        response: &ApiSyncResponse,
    ) -> Result<HttpResponse<Vec<u8>>, SurfaceH2Error> {
        let status = StatusCode::from_u16(response.status)
            .map_err(|_| SurfaceH2Error::Http("invalid api-sync status code".to_string()))?;
        let body = serde_json::to_vec(&response.body).map_err(|error| {
            SurfaceH2Error::Http(format!("response json encode failed: {error}"))
        })?;
        HttpResponse::builder()
            .status(status)
            .header(
                CONTENT_TYPE,
                HeaderValue::from_static(API_SYNC_JSON_CONTENT_TYPE),
            )
            .body(body)
            .map_err(|error| SurfaceH2Error::Http(format!("http response build failed: {error}")))
    }

    pub fn decode_http_response(
        &self,
        response: &HttpResponse<Vec<u8>>,
    ) -> Result<ApiSyncResponse, SurfaceH2Error> {
        let body = serde_json::from_slice(response.body()).map_err(|error| {
            SurfaceH2Error::Http(format!("response json decode failed: {error}"))
        })?;
        Ok(ApiSyncResponse {
            status: response.status().as_u16(),
            body,
        })
    }
}
