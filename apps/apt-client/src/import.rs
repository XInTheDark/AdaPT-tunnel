use apt_bundle::{
    client_bundle_override_path, decode_client_bundle, ensure_client_override_file,
    store_client_bundle, unprotect_client_bundle_from_import,
};
use apt_client_control::{default_client_bundle_path, ensure_client_root_dir};
use apt_runtime::load_key32;
use std::path::PathBuf;
use tokio::{io::AsyncReadExt, net::TcpStream};

pub(super) async fn import_client_bundle(
    server: String,
    key: String,
    bundle_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let default_target = default_client_bundle_install_path()?;
    let target_path = bundle_path.unwrap_or_else(|| default_target.clone());
    if target_path == default_target {
        let _ = ensure_client_root_dir()?;
    }
    println!("Connecting to temporary import service at {server}...");
    let protected = download_import_payload(&server).await?;
    let key_bytes = load_key32(&key)?;
    let bundle_bytes = unprotect_client_bundle_from_import(&protected, &key_bytes)?;
    let bundle = decode_client_bundle(&bundle_bytes)?;
    store_client_bundle(&target_path, &bundle)?;
    let _ = ensure_client_override_file(&target_path)?;

    println!("Client bundle imported to {}", target_path.display());
    println!(
        "Local override file will be {}",
        client_bundle_override_path(&target_path).display()
    );
    if target_path == default_target {
        println!("Next step: apt-client up");
    } else {
        println!(
            "Next step: apt-client up --bundle {}",
            target_path.display()
        );
    }
    println!("If this machine has not installed the local client daemon yet, run: sudo apt-client service install");
    Ok(())
}

async fn download_import_payload(
    server: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = TcpStream::connect(server).await?;
    let mut payload = Vec::new();
    stream.read_to_end(&mut payload).await?;
    if payload.is_empty() {
        return Err("temporary import service returned an empty payload".into());
    }
    Ok(payload)
}

fn default_client_bundle_install_path() -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>>
{
    Ok(default_client_bundle_path()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bundle_install_path_matches_cli_expectation() {
        assert_eq!(
            default_client_bundle_install_path().unwrap(),
            default_client_bundle_path().unwrap()
        );
    }
}
