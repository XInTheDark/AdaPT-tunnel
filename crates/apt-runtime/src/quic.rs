use crate::{config::ResolvedRemoteEndpoint, error::RuntimeError};
use base64::Engine as _;
use quinn::{ClientConfig, Connection, ServerConfig, TransportConfig};
use rustls::{pki_types::CertificateDer, pki_types::PrivateKeyDer, RootCertStore};
use rustls_pemfile::{certs, private_key};
use std::{io::Cursor, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

pub const D2_DEFAULT_PORT: u16 = 443;
pub(crate) const D2_DEFAULT_RECORD_SIZE: u16 = 1_120;
pub(crate) const D2_DEFAULT_TUNNEL_MTU: u16 = 1_040;
const D2_DEFAULT_DATAGRAM_BUFFER_BYTES: usize = 1024 * 1024;
const D2_IDLE_TIMEOUT_FLOOR_SECS: u64 = 90;

pub fn d2_default_bind() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], D2_DEFAULT_PORT))
}

pub fn derive_d2_public_endpoint(endpoint: &str) -> Option<String> {
    let host = split_endpoint_host(endpoint)?;
    Some(format!("{host}:{D2_DEFAULT_PORT}"))
}

pub fn d2_certificate_subject_alt_names(endpoint: &str) -> Vec<String> {
    let mut names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if let Some(host) = split_endpoint_host(endpoint) {
        if !names.contains(&host) {
            names.push(host);
        }
    }
    names
}

pub(crate) fn resolve_d2_remote_endpoint(
    spec: &str,
) -> Result<ResolvedRemoteEndpoint, RuntimeError> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err(RuntimeError::InvalidConfig(
            "D2 endpoint cannot be empty".to_string(),
        ));
    }
    if trimmed.contains("example.com") {
        return Err(RuntimeError::InvalidConfig(format!(
            "D2 endpoint `{trimmed}` still uses the example placeholder; replace it with the server's reachable IP:port or DNS name"
        )));
    }
    let addr = crate::config::resolve_socket_addr(trimmed)?;
    let server_name = split_endpoint_host(trimmed).ok_or_else(|| {
        RuntimeError::InvalidConfig(format!(
            "unable to extract a server name from D2 endpoint `{trimmed}`"
        ))
    })?;
    Ok(ResolvedRemoteEndpoint {
        original: trimmed.to_string(),
        addr,
        server_name,
    })
}

pub fn load_certificate_der(spec: &str) -> Result<Vec<u8>, RuntimeError> {
    let chain = load_certificate_chain(spec)?;
    chain
        .into_iter()
        .next()
        .map(|cert| cert.as_ref().to_vec())
        .ok_or_else(|| RuntimeError::InvalidConfig("no certificates were found".to_string()))
}

pub(crate) fn load_certificate_chain(
    spec: &str,
) -> Result<Vec<CertificateDer<'static>>, RuntimeError> {
    let bytes = load_spec_bytes(spec)?;
    if bytes.starts_with(b"-----BEGIN CERTIFICATE-----")
        || spec.ends_with(".pem")
        || spec.ends_with(".crt")
    {
        certs(&mut Cursor::new(bytes))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                RuntimeError::InvalidConfig(format!("invalid PEM certificate: {error}"))
            })
    } else {
        Ok(vec![CertificateDer::from(bytes)])
    }
}

pub(crate) fn load_private_key(spec: &str) -> Result<PrivateKeyDer<'static>, RuntimeError> {
    let bytes = load_spec_bytes(spec)?;
    if bytes.starts_with(b"-----BEGIN") || spec.ends_with(".pem") {
        private_key(&mut Cursor::new(bytes))
            .map_err(|error| {
                RuntimeError::InvalidConfig(format!("invalid PEM private key: {error}"))
            })?
            .ok_or_else(|| RuntimeError::InvalidConfig("no private key found".to_string()))
    } else {
        PrivateKeyDer::try_from(bytes)
            .map_err(|error| RuntimeError::InvalidConfig(format!("invalid private key: {error}")))
    }
}

pub(crate) fn build_d2_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    idle_timeout_secs: u64,
) -> Result<ServerConfig, RuntimeError> {
    let mut server_config = ServerConfig::with_single_cert(cert_chain, private_key)
        .map_err(|error| RuntimeError::Quic(error.to_string()))?;
    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(0_u8.into());
    transport.max_concurrent_uni_streams(0_u8.into());
    transport.datagram_receive_buffer_size(Some(D2_DEFAULT_DATAGRAM_BUFFER_BYTES));
    transport.datagram_send_buffer_size(D2_DEFAULT_DATAGRAM_BUFFER_BYTES);
    let idle_timeout = quinn::IdleTimeout::try_from(Duration::from_secs(
        idle_timeout_secs.max(D2_IDLE_TIMEOUT_FLOOR_SECS),
    ))
    .map_err(|error| RuntimeError::Quic(error.to_string()))?;
    transport.max_idle_timeout(Some(idle_timeout));
    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}

pub(crate) fn build_d2_client_config(
    server_certificate_der: Vec<u8>,
    idle_timeout_secs: u64,
) -> Result<ClientConfig, RuntimeError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(server_certificate_der))
        .map_err(|error| RuntimeError::Quic(error.to_string()))?;
    let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots))
        .map_err(|error| RuntimeError::Quic(error.to_string()))?;
    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(0_u8.into());
    transport.max_concurrent_uni_streams(0_u8.into());
    transport.datagram_receive_buffer_size(Some(D2_DEFAULT_DATAGRAM_BUFFER_BYTES));
    transport.datagram_send_buffer_size(D2_DEFAULT_DATAGRAM_BUFFER_BYTES);
    let idle_timeout = quinn::IdleTimeout::try_from(Duration::from_secs(
        idle_timeout_secs.max(D2_IDLE_TIMEOUT_FLOOR_SECS),
    ))
    .map_err(|error| RuntimeError::Quic(error.to_string()))?;
    transport.max_idle_timeout(Some(idle_timeout));
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

pub(crate) fn ensure_d2_datagram_support(connection: &Connection) -> Result<(), RuntimeError> {
    let Some(max_datagram_size) = connection.max_datagram_size() else {
        return Err(RuntimeError::Quic(
            "the remote QUIC endpoint does not support datagrams".to_string(),
        ));
    };
    if max_datagram_size < usize::from(D2_DEFAULT_RECORD_SIZE) {
        return Err(RuntimeError::Quic(format!(
            "the negotiated QUIC datagram budget ({max_datagram_size} bytes) is smaller than the required D2 record size ({})",
            D2_DEFAULT_RECORD_SIZE
        )));
    }
    Ok(())
}

fn load_spec_bytes(spec: &str) -> Result<Vec<u8>, RuntimeError> {
    if let Some(path) = spec.strip_prefix("file:") {
        return std::fs::read(path).map_err(|source| RuntimeError::IoWithPath {
            path: PathBuf::from(path),
            source,
        });
    }

    let trimmed = spec.trim();
    if trimmed.starts_with("-----BEGIN") {
        return Ok(trimmed.as_bytes().to_vec());
    }

    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|error| {
            RuntimeError::InvalidConfig(format!("invalid base64 certificate/key data: {error}"))
        })
}

fn split_endpoint_host(endpoint: &str) -> Option<String> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(socket_addr) = trimmed.parse::<SocketAddr>() {
        return Some(socket_addr.ip().to_string());
    }
    let (host, _) = trimmed.rsplit_once(':')?;
    Some(host.trim_matches('[').trim_matches(']').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_d2_tls_identity;
    use bytes::Bytes;

    #[tokio::test]
    async fn generated_certificate_supports_d2_quic_datagrams() {
        let identity = generate_d2_tls_identity(d2_certificate_subject_alt_names("127.0.0.1:443"))
            .expect("self-signed D2 identity generation should succeed");

        let temp_dir = std::env::temp_dir().join(format!(
            "adapt-d2-cert-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).expect("temp dir should be creatable");
        let cert_path = temp_dir.join("d2-cert.pem");
        let key_path = temp_dir.join("d2-key.pem");
        std::fs::write(&cert_path, &identity.certificate_pem).expect("cert should be writable");
        std::fs::write(&key_path, &identity.private_key_pem).expect("key should be writable");

        let server_config = build_d2_server_config(
            load_certificate_chain(&format!("file:{}", cert_path.display()))
                .expect("cert chain should load"),
            load_private_key(&format!("file:{}", key_path.display())).expect("key should load"),
            180,
        )
        .expect("server config should build");
        let server_endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
                .expect("server endpoint should bind");
        let server_addr = server_endpoint
            .local_addr()
            .expect("server addr should exist");

        let client_config = build_d2_client_config(identity.certificate_der.clone(), 180)
            .expect("client config should build");
        let mut client_endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .expect("client endpoint should bind");
        client_endpoint.set_default_client_config(client_config);

        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint
                .accept()
                .await
                .expect("server should accept one incoming connection");
            let connection = incoming
                .await
                .expect("incoming connection should finish handshake");
            let datagram = connection
                .read_datagram()
                .await
                .expect("server should receive a datagram");
            connection
                .send_datagram_wait(Bytes::from_static(b"server-reply"))
                .await
                .expect("server should send a datagram reply");
            let _ = connection.closed().await;
            datagram
        });

        let connection = client_endpoint
            .connect(server_addr, "127.0.0.1")
            .expect("client connect should be creatable")
            .await
            .expect("client handshake should succeed");
        ensure_d2_datagram_support(&connection).expect("datagrams should be available");
        connection
            .send_datagram(Bytes::from_static(b"client-hello"))
            .expect("client should send a datagram");
        let reply = connection
            .read_datagram()
            .await
            .expect("client should receive a reply datagram");
        assert_eq!(reply.as_ref(), b"server-reply");

        connection.close(0u32.into(), b"done");
        client_endpoint.wait_idle().await;
        let observed = server_task.await.expect("server task should join");
        assert_eq!(observed.as_ref(), b"client-hello");
        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
