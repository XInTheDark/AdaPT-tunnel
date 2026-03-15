use crate::{
    cli::Cli,
    ipc::{read_request, write_event, write_response, DynError},
    supervisor::DaemonHandle,
};
use apt_client_control::ClientDaemonRequest;
use std::{fs, path::Path};
use tokio::net::UnixListener;
use tracing::info;

pub(crate) async fn run(cli: Cli) -> Result<(), DynError> {
    let root_dir = cli.resolved_root_dir()?;
    if !root_dir.exists() {
        fs::create_dir_all(&root_dir)?;
    }
    let socket_path = cli.resolved_socket_path()?;
    remove_stale_socket(&socket_path)?;
    let listener = UnixListener::bind(&socket_path)?;
    set_socket_permissions(&socket_path)?;

    let handle = DaemonHandle::new(root_dir.clone());
    info!(root_dir = %root_dir.display(), socket = %socket_path.display(), "apt-clientd listening");

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(handle_connection(stream, handle.clone()));
    }
}

async fn handle_connection(
    stream: tokio::net::UnixStream,
    handle: DaemonHandle,
) -> Result<(), DynError> {
    let (request, stream) = read_request(stream).await?;
    match request {
        ClientDaemonRequest::Subscribe => {
            let mut events = handle.subscribe();
            let response = handle.dispatch(ClientDaemonRequest::Subscribe).await;
            let (_, mut writer) = stream.into_split();
            write_response(&mut writer, response).await?;
            while let Ok(event) = events.recv().await {
                if write_event(&mut writer, event).await.is_err() {
                    break;
                }
            }
        }
        other => {
            let response = handle.dispatch(other).await;
            let (_, mut writer) = stream.into_split();
            write_response(&mut writer, response).await?;
        }
    }
    Ok(())
}

fn remove_stale_socket(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if path.is_file() {
        fs::remove_file(path)?;
    } else {
        let _ = fs::remove_file(path);
    }
    Ok(())
}

#[cfg(unix)]
fn set_socket_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let permissions = fs::Permissions::from_mode(0o666);
    fs::set_permissions(path, permissions)
}
