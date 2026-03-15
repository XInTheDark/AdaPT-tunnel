use super::*;
use apt_bundle::{
    client_bundle_override_path, decode_client_bundle, store_client_bundle,
    unprotect_client_bundle_from_import,
};
use apt_runtime::load_key32;
use tokio::{io::AsyncReadExt, net::TcpStream};

pub(super) async fn import_client_bundle(
    server: String,
    key: String,
    bundle_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let target_path = bundle_path.unwrap_or_else(default_client_bundle_install_path);
    println!("Connecting to temporary import service at {server}...");
    let protected = download_import_payload(&server).await?;
    let key_bytes = load_key32(&key)?;
    let bundle_bytes = unprotect_client_bundle_from_import(&protected, &key_bytes)?;
    let bundle = decode_client_bundle(&bundle_bytes)?;
    store_client_bundle(&target_path, &bundle)?;

    println!("Client bundle imported to {}", target_path.display());
    println!(
        "Local override file will be {}",
        client_bundle_override_path(&target_path).display()
    );
    if target_path == default_client_bundle_install_path() {
        println!("Next step: sudo apt-client up");
    } else {
        println!(
            "Next step: sudo apt-client up --bundle {}",
            target_path.display()
        );
    }
    Ok(())
}

async fn download_import_payload(server: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(server).await?;
    let mut payload = Vec::new();
    stream.read_to_end(&mut payload).await?;
    if payload.is_empty() {
        return Err("temporary import service returned an empty payload".into());
    }
    Ok(payload)
}

fn default_client_bundle_install_path() -> PathBuf {
    PathBuf::from("/etc/adapt").join(DEFAULT_CLIENT_BUNDLE_FILE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bundle_install_path_matches_cli_expectation() {
        assert_eq!(
            default_client_bundle_install_path(),
            PathBuf::from("/etc/adapt").join(DEFAULT_CLIENT_BUNDLE_FILE_NAME)
        );
    }
}
