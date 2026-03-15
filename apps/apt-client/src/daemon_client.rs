use apt_client_control::{
    default_client_socket_path, ClientDaemonEvent, ClientDaemonRequest, ClientDaemonResponse,
    ClientDaemonSnapshot, ClientDaemonWireMessage,
};
use std::{error::Error, path::PathBuf};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{unix::OwnedReadHalf, UnixStream},
};

pub(super) type CliResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

pub(super) struct DaemonSubscription {
    reader: BufReader<OwnedReadHalf>,
    pub initial_snapshot: ClientDaemonSnapshot,
}

impl DaemonSubscription {
    pub(super) async fn next_event(&mut self) -> CliResult<Option<ClientDaemonEvent>> {
        let mut line = String::new();
        let read = self.reader.read_line(&mut line).await?;
        if read == 0 {
            return Ok(None);
        }
        let message: ClientDaemonWireMessage = serde_json::from_str(line.trim())?;
        match message {
            ClientDaemonWireMessage::Event(event) => Ok(Some(event)),
            ClientDaemonWireMessage::Response(response) => {
                Err(format!("unexpected daemon response while subscribed: {response:?}").into())
            }
        }
    }
}

pub(super) async fn send_request(request: ClientDaemonRequest) -> CliResult<ClientDaemonResponse> {
    let socket_path = socket_path()?;
    ensure_socket_exists(&socket_path)?;
    let mut stream = UnixStream::connect(&socket_path).await?;
    write_request(&mut stream, &request).await?;
    read_response(stream).await
}

pub(super) async fn subscribe() -> CliResult<DaemonSubscription> {
    let socket_path = socket_path()?;
    ensure_socket_exists(&socket_path)?;
    let mut stream = UnixStream::connect(&socket_path).await?;
    write_request(&mut stream, &ClientDaemonRequest::Subscribe).await?;
    let (read_half, _) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    let read = reader.read_line(&mut line).await?;
    if read == 0 {
        return Err("client daemon closed the socket before subscribing".into());
    }
    let message: ClientDaemonWireMessage = serde_json::from_str(line.trim())?;
    let initial_snapshot = match message {
        ClientDaemonWireMessage::Response(ClientDaemonResponse::Subscribed { snapshot }) => {
            snapshot
        }
        ClientDaemonWireMessage::Response(ClientDaemonResponse::Error { message }) => {
            return Err(message.into())
        }
        other => return Err(format!("unexpected subscribe response: {other:?}").into()),
    };
    Ok(DaemonSubscription {
        reader,
        initial_snapshot,
    })
}

fn socket_path() -> CliResult<PathBuf> {
    Ok(default_client_socket_path()?)
}

fn ensure_socket_exists(path: &PathBuf) -> CliResult<()> {
    if path.exists() {
        return Ok(());
    }
    Err(format!(
        "client daemon socket {} is not available; run `sudo apt-client service install` once first",
        path.display()
    )
    .into())
}

async fn write_request(stream: &mut UnixStream, request: &ClientDaemonRequest) -> CliResult<()> {
    let encoded = serde_json::to_vec(request)?;
    stream.write_all(&encoded).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;
    Ok(())
}

async fn read_response(stream: UnixStream) -> CliResult<ClientDaemonResponse> {
    let (read_half, _) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    let read = reader.read_line(&mut line).await?;
    if read == 0 {
        return Err("client daemon closed the socket before replying".into());
    }
    let message: ClientDaemonWireMessage = serde_json::from_str(line.trim())?;
    match message {
        ClientDaemonWireMessage::Response(response) => Ok(response),
        ClientDaemonWireMessage::Event(event) => {
            Err(format!("unexpected daemon event while waiting for response: {event:?}").into())
        }
    }
}
