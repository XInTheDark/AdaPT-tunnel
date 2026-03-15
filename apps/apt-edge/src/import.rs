use super::*;
use apt_bundle::protect_client_bundle_for_import;
use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    time::Duration,
};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::sleep};

const DEFAULT_IMPORT_BIND_ADDR: &str = "0.0.0.0:0";
pub(super) const DEFAULT_IMPORT_TIMEOUT_SECS: u64 = 600;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ClientImportOffer {
    pub endpoint: String,
    pub temporary_key: String,
    pub timeout_secs: u64,
}

pub(super) fn spawn_client_bundle_import_offer(
    bundle_path: &Path,
    public_endpoint: &str,
    import_host: Option<&str>,
    import_bind: Option<SocketAddr>,
    timeout_secs: u64,
) -> CliResult<ClientImportOffer> {
    let public_host = import_host
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| derive_import_host(public_endpoint));
    let bind_addr = import_bind.unwrap_or_else(default_import_bind_addr);
    let temporary_key_bytes: [u8; 32] = rand::random();
    let temporary_key = encode_key_hex(&temporary_key_bytes);
    let current_exe = std::env::current_exe()?;
    let mut child = Command::new(current_exe)
        .arg("serve-import")
        .arg("--bundle")
        .arg(bundle_path)
        .arg("--bind")
        .arg(bind_addr.to_string())
        .arg("--key")
        .arg(&temporary_key)
        .arg("--timeout-secs")
        .arg(timeout_secs.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let Some(stdout) = child.stdout.take() else {
        return Err("temporary import helper did not expose stdout".into());
    };
    let mut line = String::new();
    let bytes_read = BufReader::new(stdout).read_line(&mut line)?;
    if bytes_read == 0 {
        return Err("temporary import helper exited before reporting its listening port".into());
    }
    let listen_addr: SocketAddr = line.trim().parse()?;
    Ok(ClientImportOffer {
        endpoint: format_import_endpoint(&public_host, listen_addr.port()),
        temporary_key,
        timeout_secs,
    })
}

pub(super) async fn serve_client_bundle_import(
    bundle_path: PathBuf,
    bind: SocketAddr,
    key: String,
    timeout_secs: u64,
) -> CliResult {
    let bundle_bytes = fs::read(&bundle_path)?;
    let key_bytes = load_key32(&key)?;
    let protected = protect_client_bundle_for_import(&bundle_bytes, &key_bytes)?;
    let listener = TcpListener::bind(bind).await?;
    let listen_addr = listener.local_addr()?;
    println!("{listen_addr}");
    io::stdout().flush()?;

    tokio::select! {
        accept_result = listener.accept() => {
            let (mut stream, _) = accept_result?;
            stream.write_all(&protected).await?;
            stream.shutdown().await?;
        }
        _ = sleep(Duration::from_secs(timeout_secs)) => {}
    }

    Ok(())
}

fn default_import_bind_addr() -> SocketAddr {
    DEFAULT_IMPORT_BIND_ADDR
        .parse()
        .expect("default import bind address is valid")
}

fn derive_import_host(public_endpoint: &str) -> String {
    if let Ok(socket_addr) = public_endpoint.parse::<SocketAddr>() {
        return socket_addr.ip().to_string();
    }
    if let Some(stripped) = public_endpoint.strip_prefix('[') {
        if let Some((host, _rest)) = stripped.split_once(']') {
            return host.to_string();
        }
    }
    public_endpoint
        .rsplit_once(':')
        .map_or_else(|| public_endpoint.to_string(), |(host, _)| host.to_string())
}

fn format_import_endpoint(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_import_host_from_ipv4_public_endpoint() {
        assert_eq!(derive_import_host("203.0.113.10:51820"), "203.0.113.10");
    }

    #[test]
    fn derives_import_host_from_bracketed_ipv6_public_endpoint() {
        assert_eq!(derive_import_host("[2001:db8::10]:51820"), "2001:db8::10");
    }

    #[test]
    fn formats_ipv6_import_endpoint_with_brackets() {
        assert_eq!(
            format_import_endpoint("2001:db8::10", 40123),
            "[2001:db8::10]:40123"
        );
    }
}
