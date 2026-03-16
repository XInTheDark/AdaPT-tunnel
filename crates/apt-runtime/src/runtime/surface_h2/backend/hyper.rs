use super::*;
use ::hyper::{
    body::Incoming,
    client::conn::http2::{Builder as ClientBuilder, SendRequest},
    rt::{Read as HyperRead, Write as HyperWrite},
    server::conn::http2::Builder as ServerBuilder,
    service::service_fn,
};
use bytes::Bytes;
use http::{Request as HttpRequest, Response as HttpResponse, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use tokio::{net::TcpStream, sync::Mutex};

pub struct ApiSyncH2HyperClient {
    sender: SendRequest<Full<Bytes>>,
}

impl ApiSyncH2HyperClient {
    pub async fn connect(stream: TcpStream) -> Result<Self, RuntimeError> {
        Self::connect_io(TokioIo::new(stream)).await
    }

    pub(super) async fn connect_io<I>(io: I) -> Result<Self, RuntimeError>
    where
        I: HyperRead + HyperWrite + Unpin + Send + 'static,
    {
        let (sender, connection) = ClientBuilder::new(TokioExecutor::new())
            .handshake(io)
            .await
            .map_err(|error| RuntimeError::Http(format!("h2 client handshake failed: {error}")))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Self { sender })
    }

    pub async fn round_trip(
        &mut self,
        surface: &ApiSyncSurface,
        request: ApiSyncRequest,
    ) -> Result<ApiSyncResponse, RuntimeError> {
        self.sender
            .ready()
            .await
            .map_err(|error| RuntimeError::Http(format!("h2 client not ready: {error}")))?;
        let request = http_request_with_body(surface.encode_http_request(&request)?);
        let response = self
            .sender
            .send_request(request)
            .await
            .map_err(|error| RuntimeError::Http(format!("h2 request failed: {error}")))?;
        surface
            .decode_http_response(&collect_http_response(response).await?)
            .map_err(RuntimeError::from)
    }
}

pub async fn serve_api_sync_h2_connection<S, N>(
    stream: TcpStream,
    request_handler: ApiSyncH2RequestHandler,
    admission: Arc<Mutex<AdmissionServer>>,
    public_service: Arc<Mutex<S>>,
    source_id: String,
    now_fn: N,
) -> Result<(), RuntimeError>
where
    S: ApiSyncPublicService + Send + 'static,
    N: Fn() -> u64 + Clone + Send + Sync + 'static,
{
    serve_api_sync_h2_io(
        TokioIo::new(stream),
        request_handler,
        admission,
        public_service,
        source_id,
        now_fn,
    )
    .await
}

pub(super) async fn serve_api_sync_h2_io<S, N, I>(
    io: I,
    request_handler: ApiSyncH2RequestHandler,
    admission: Arc<Mutex<AdmissionServer>>,
    public_service: Arc<Mutex<S>>,
    source_id: String,
    now_fn: N,
) -> Result<(), RuntimeError>
where
    S: ApiSyncPublicService + Send + 'static,
    N: Fn() -> u64 + Clone + Send + Sync + 'static,
    I: HyperRead + HyperWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request| {
        let request_handler = request_handler.clone();
        let admission = Arc::clone(&admission);
        let public_service = Arc::clone(&public_service);
        let source_id = source_id.clone();
        let now_fn = now_fn.clone();
        async move {
            let response = match handle_http_request(
                request_handler,
                admission,
                public_service,
                source_id,
                now_fn(),
                request,
            )
            .await
            {
                Ok(response) => response,
                Err(error) => runtime_error_http_response(error),
            };
            Ok::<_, std::convert::Infallible>(http_response_with_body(response))
        }
    });
    ServerBuilder::new(TokioExecutor::new())
        .serve_connection(io, service)
        .await
        .map_err(|error| RuntimeError::Http(format!("h2 server connection failed: {error}")))
}

async fn handle_http_request<S>(
    request_handler: ApiSyncH2RequestHandler,
    admission: Arc<Mutex<AdmissionServer>>,
    public_service: Arc<Mutex<S>>,
    source_id: String,
    now_secs: u64,
    request: HttpRequest<Incoming>,
) -> Result<HttpResponse<Vec<u8>>, RuntimeError>
where
    S: ApiSyncPublicService + Send + 'static,
{
    let request = collect_http_request(request).await?;
    let api_request = request_handler.surface().decode_http_request(&request)?;
    let mut admission = admission.lock().await;
    let mut public_service = public_service.lock().await;
    let handled = request_handler.handle_request(
        &mut admission,
        &mut *public_service,
        &api_request,
        &source_id,
        now_secs,
    )?;
    request_handler
        .surface()
        .encode_http_response(&handled.into_response())
        .map_err(RuntimeError::from)
}

async fn collect_http_request(
    request: HttpRequest<Incoming>,
) -> Result<HttpRequest<Vec<u8>>, RuntimeError> {
    let (parts, body) = request.into_parts();
    let body = body
        .collect()
        .await
        .map_err(|error| RuntimeError::Http(format!("request body read failed: {error}")))?
        .to_bytes()
        .to_vec();
    Ok(HttpRequest::from_parts(parts, body))
}

async fn collect_http_response(
    response: HttpResponse<Incoming>,
) -> Result<HttpResponse<Vec<u8>>, RuntimeError> {
    let (parts, body) = response.into_parts();
    let body = body
        .collect()
        .await
        .map_err(|error| RuntimeError::Http(format!("response body read failed: {error}")))?
        .to_bytes()
        .to_vec();
    Ok(HttpResponse::from_parts(parts, body))
}

fn http_request_with_body(request: HttpRequest<Vec<u8>>) -> HttpRequest<Full<Bytes>> {
    let (parts, body) = request.into_parts();
    HttpRequest::from_parts(parts, Full::new(Bytes::from(body)))
}

fn http_response_with_body(response: HttpResponse<Vec<u8>>) -> HttpResponse<Full<Bytes>> {
    let (parts, body) = response.into_parts();
    HttpResponse::from_parts(parts, Full::new(Bytes::from(body)))
}

fn runtime_error_http_response(error: RuntimeError) -> HttpResponse<Vec<u8>> {
    let status = match error {
        RuntimeError::SurfaceH2(_) | RuntimeError::Serialization(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    HttpResponse::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_vec(&serde_json::json!({
                "error": if status == StatusCode::BAD_REQUEST {
                    "bad-request"
                } else {
                    "service-unavailable"
                }
            }))
            .expect("json serialization for static error body cannot fail"),
        )
        .expect("static http error response must build")
}
