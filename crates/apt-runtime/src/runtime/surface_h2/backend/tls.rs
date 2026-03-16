use super::{hyper::serve_api_sync_h2_io, *};
use crate::{V2ClientSurfacePlan, V2ServerSurfacePlan};
use apt_origin::PublicSessionTransport;
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore, ServerConfig};
use std::sync::{Arc, Once};
use tokio::{net::TcpStream, sync::Mutex};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const H2_ALPN_PROTOCOL: &[u8] = b"h2";

fn ensure_rustls_provider_installed() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[derive(Clone, Debug)]
pub struct ApiSyncH2TlsClientConfig {
    server_name: String,
    config: Arc<ClientConfig>,
}

impl ApiSyncH2TlsClientConfig {
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    #[must_use]
    pub fn config(&self) -> &Arc<ClientConfig> {
        &self.config
    }
}

impl ApiSyncH2HyperClient {
    pub async fn connect_tls(
        stream: TcpStream,
        tls: &ApiSyncH2TlsClientConfig,
    ) -> Result<Self, RuntimeError> {
        let connector = TlsConnector::from(Arc::clone(&tls.config));
        let server_name = ServerName::try_from(tls.server_name.clone()).map_err(|error| {
            RuntimeError::InvalidConfig(format!(
                "invalid H2 TLS server name `{}`: {error}",
                tls.server_name
            ))
        })?;
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|error| RuntimeError::Http(format!("h2 tls connect failed: {error}")))?;
        Self::connect_io(hyper_util::rt::TokioIo::new(tls_stream)).await
    }

    pub async fn connect_tls_with_surface_plan(
        plan: &V2ClientSurfacePlan,
    ) -> Result<Self, RuntimeError> {
        let tls = build_api_sync_h2_tls_client_config(plan)?;
        let addr = crate::config::resolve_socket_addr(&plan.endpoint)?;
        let stream = TcpStream::connect(addr).await?;
        Self::connect_tls(stream, &tls).await
    }
}

pub fn build_api_sync_h2_tls_client_config(
    plan: &V2ClientSurfacePlan,
) -> Result<ApiSyncH2TlsClientConfig, RuntimeError> {
    ensure_rustls_provider_installed();
    ensure_h2_surface_transport(plan.transport, "client")?;
    if plan.trust.pinned_spki.is_some() {
        return Err(RuntimeError::InvalidConfig(
            "H2 TLS SPKI pinning is not wired yet; use pinned_certificate or roots for now"
                .to_string(),
        ));
    }

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    extend_root_store(&mut roots, plan.trust.roots.as_deref())?;
    if let Some(spec) = plan.trust.pinned_certificate.as_deref() {
        extend_root_store(&mut roots, Some(spec))?;
    }

    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![H2_ALPN_PROTOCOL.to_vec()];

    let server_name = plan
        .trust
        .server_name
        .clone()
        .unwrap_or_else(|| plan.authority.clone());
    Ok(ApiSyncH2TlsClientConfig {
        server_name,
        config: Arc::new(config),
    })
}

pub fn build_api_sync_h2_tls_server_config_for_surface_plan(
    plan: &V2ServerSurfacePlan,
    certificate_chain_spec: &str,
    private_key_spec: &str,
) -> Result<Arc<ServerConfig>, RuntimeError> {
    ensure_rustls_provider_installed();
    ensure_h2_surface_transport(plan.transport, "server")?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            crate::quic::load_certificate_chain(certificate_chain_spec)?,
            crate::quic::load_private_key(private_key_spec)?,
        )
        .map_err(|error| RuntimeError::Http(format!("h2 tls server config failed: {error}")))?;
    config.alpn_protocols = vec![H2_ALPN_PROTOCOL.to_vec()];
    Ok(Arc::new(config))
}

pub async fn serve_api_sync_h2_tls_connection<S, N>(
    stream: TcpStream,
    tls_config: Arc<ServerConfig>,
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
    let acceptor = TlsAcceptor::from(tls_config);
    let tls_stream = acceptor
        .accept(stream)
        .await
        .map_err(|error| RuntimeError::Http(format!("h2 tls accept failed: {error}")))?;
    serve_api_sync_h2_io(
        hyper_util::rt::TokioIo::new(tls_stream),
        request_handler,
        admission,
        public_service,
        source_id,
        now_fn,
    )
    .await
}

fn ensure_h2_surface_transport(
    transport: PublicSessionTransport,
    role: &str,
) -> Result<(), RuntimeError> {
    if transport != PublicSessionTransport::S1H2 {
        return Err(RuntimeError::InvalidConfig(format!(
            "{role} H2 surface plan must use S1/H2 transport"
        )));
    }
    Ok(())
}

fn extend_root_store(roots: &mut RootCertStore, spec: Option<&str>) -> Result<(), RuntimeError> {
    let Some(spec) = spec else {
        return Ok(());
    };
    for certificate in crate::quic::load_certificate_chain(spec)? {
        roots
            .add(certificate)
            .map_err(|error| RuntimeError::Http(format!("invalid H2 TLS trust anchor: {error}")))?;
    }
    Ok(())
}
