use apt_client_control::{
    ClientDaemonEvent, ClientDaemonRequest, ClientDaemonResponse, ClientDaemonWireMessage,
};
use serde::Serialize;
use std::error::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{unix::OwnedReadHalf, UnixStream},
};

pub(crate) type DynError = Box<dyn Error + Send + Sync>;

pub(crate) async fn read_request(
    stream: UnixStream,
) -> Result<(ClientDaemonRequest, UnixStream), DynError> {
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let request = read_request_from_reader(&mut reader).await?;
    let stream = reader.into_inner().reunite(write_half)?;
    Ok((request, stream))
}

pub(crate) async fn read_request_from_reader(
    reader: &mut BufReader<OwnedReadHalf>,
) -> Result<ClientDaemonRequest, DynError> {
    let mut line = String::new();
    let read = reader.read_line(&mut line).await?;
    if read == 0 {
        return Err("control socket closed before a request was received".into());
    }
    Ok(serde_json::from_str(line.trim())?)
}

pub(crate) async fn write_response<W>(
    writer: &mut W,
    response: ClientDaemonResponse,
) -> Result<(), DynError>
where
    W: AsyncWrite + Unpin,
{
    write_wire_message(writer, ClientDaemonWireMessage::Response(response)).await
}

pub(crate) async fn write_event<W>(writer: &mut W, event: ClientDaemonEvent) -> Result<(), DynError>
where
    W: AsyncWrite + Unpin,
{
    write_wire_message(writer, ClientDaemonWireMessage::Event(event)).await
}

async fn write_wire_message<W>(
    writer: &mut W,
    message: ClientDaemonWireMessage,
) -> Result<(), DynError>
where
    W: AsyncWrite + Unpin,
{
    write_json_line(writer, &message).await
}

async fn write_json_line<W, T>(writer: &mut W, value: &T) -> Result<(), DynError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let encoded = serde_json::to_vec(value)?;
    writer.write_all(&encoded).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}
