use crate::{
    adaptive::{admission_path_profile, build_client_network_context, AdaptiveDatapath},
    config::{
        ClientPersistentState, PersistedNetworkProfile, ResolvedAuthorizedPeer,
        ResolvedClientConfig, ResolvedServerConfig, ServerSessionExtension,
        SessionTransportParameters,
    },
    error::RuntimeError,
    route::{configure_client_network_for_endpoints, configure_server_network},
    status::{ClientStatus, RuntimeStatus, ServerStatus},
    tun::{spawn_tun_worker, TunHandle, TunInterfaceConfig},
    wire::{
        decode_admission_d2_datagram, decode_admission_datagram, decode_admission_stream_payload,
        decode_confirmation_d2_datagram, decode_confirmation_datagram,
        decode_confirmation_stream_payload, decode_tunnel_d2_datagram, decode_tunnel_datagram,
        decode_tunnel_stream_payload, derive_d1_admission_outer_key,
        derive_d1_confirmation_outer_key, derive_d1_tunnel_outer_keys,
        derive_d2_admission_outer_key, derive_d2_confirmation_outer_key,
        derive_d2_tunnel_outer_keys, derive_s1_admission_outer_key,
        derive_s1_confirmation_outer_key, derive_s1_tunnel_outer_keys,
        encode_admission_d2_datagram, encode_admission_datagram, encode_admission_stream_payload,
        encode_confirmation_d2_datagram, encode_confirmation_datagram,
        encode_confirmation_stream_payload, encode_tunnel_d2_datagram, encode_tunnel_datagram,
        encode_tunnel_stream_payload, D1OuterKeys, D2OuterKeys, S1OuterKeys,
    },
};
use apt_admission::{
    initiate_c0, AdmissionConfig, AdmissionError, AdmissionPacket, AdmissionServer,
    AdmissionServerSecrets, ClientCredential, ClientSessionRequest, CredentialStore,
    EstablishedSession, PerUserCredential, ServerConfirmationPacket, ServerResponse,
};
use apt_carriers::{CarrierError, CarrierProfile, D1Carrier, D2Carrier, S1Carrier};
use apt_crypto::{SealedEnvelope, SessionSecretsForRole, StaticKeypair};
use apt_observability::{record_event, AptEvent, ObservabilityConfig, TelemetrySnapshot};
use apt_tunnel::{Frame, RekeyStatus, TunnelSession};
use apt_types::{
    AuthProfile, CarrierBinding, CipherSuite, CredentialIdentity, PathSignalEvent, PolicyMode,
    SessionId, SessionRole, DEFAULT_ADMISSION_EPOCH_SLOT_SECS, MINIMUM_REPLAY_WINDOW,
};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
    time::{interval, timeout},
};
use tracing::{debug, info, warn};

mod client;
mod d2;
mod handshake;
mod packets;
mod pathio;
mod server;
mod support;
mod transport;

#[cfg(test)]
mod tests;

use self::{d2::*, handshake::*, packets::*, pathio::*, support::*, transport::*};

const DATAGRAM_BUFFER_SIZE: usize = 65_535;
const PATH_VALIDATION_TIMEOUT_SECS: u64 = 10;
const PATH_VALIDATION_RETRY_SECS: u64 = 2;
const STREAM_DECOY_BODY: &str = "<html><body><h1>It works</h1></body></html>";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientRuntimeResult {
    pub status: ClientStatus,
    pub telemetry: TelemetrySnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerRuntimeResult {
    pub status: ServerStatus,
    pub telemetry: TelemetrySnapshot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum PathHandle {
    Datagram(SocketAddr),
    D2(u64),
    Stream(u64),
}

#[derive(Clone, Debug)]
struct RuntimeOuterKeys {
    d1: D1OuterKeys,
    d2: D2OuterKeys,
    s1: S1OuterKeys,
}

impl RuntimeOuterKeys {
    fn send_for(&self, binding: CarrierBinding) -> Result<&[u8; 32], RuntimeError> {
        match binding {
            CarrierBinding::D1DatagramUdp => Ok(&self.d1.send),
            CarrierBinding::D2EncryptedDatagram => Ok(&self.d2.send),
            CarrierBinding::S1EncryptedStream => Ok(&self.s1.send),
            _ => Err(RuntimeError::InvalidConfig(format!(
                "unsupported runtime carrier {binding:?}"
            ))),
        }
    }

    fn recv_for(&self, binding: CarrierBinding) -> Result<&[u8; 32], RuntimeError> {
        match binding {
            CarrierBinding::D1DatagramUdp => Ok(&self.d1.recv),
            CarrierBinding::D2EncryptedDatagram => Ok(&self.d2.recv),
            CarrierBinding::S1EncryptedStream => Ok(&self.s1.recv),
            _ => Err(RuntimeError::InvalidConfig(format!(
                "unsupported runtime carrier {binding:?}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TunnelEncapsulation {
    Wrapped,
    DirectInnerOnly,
}

impl TunnelEncapsulation {
    const fn for_policy(mode: PolicyMode) -> Self {
        if matches!(mode, PolicyMode::SpeedFirst) {
            Self::DirectInnerOnly
        } else {
            Self::Wrapped
        }
    }
}

#[derive(Clone, Debug)]
enum StreamWrite {
    CarrierPayload(Vec<u8>),
    Raw(Vec<u8>),
}

#[derive(Clone, Debug)]
enum PathSender {
    Datagram(mpsc::UnboundedSender<Vec<u8>>),
    D2(mpsc::UnboundedSender<Vec<u8>>),
    Stream(mpsc::UnboundedSender<StreamWrite>),
}

#[derive(Debug)]
struct ClientPathState {
    id: u64,
    binding: CarrierBinding,
    sender: PathSender,
    validated: bool,
    pending_probe_challenge: Option<[u8; 8]>,
    last_send_secs: u64,
    last_recv_secs: u64,
}

#[derive(Debug)]
enum ClientTransportEvent {
    Inbound { path_id: u64, bytes: Vec<u8> },
    Closed { path_id: u64, reason: &'static str },
}

#[derive(Debug)]
enum HandshakeTransport {
    Datagram(UdpSocket),
    D2 {
        endpoint: quinn::Endpoint,
        connection: quinn::Connection,
    },
    Stream(TcpStream),
}

#[derive(Debug)]
struct HandshakeSuccess {
    binding: CarrierBinding,
    established: EstablishedSession,
    transport: HandshakeTransport,
}

#[derive(Clone, Debug)]
struct ServerPathState {
    handle: PathHandle,
    binding: CarrierBinding,
    last_send_secs: u64,
    last_recv_secs: u64,
}

#[derive(Clone, Debug)]
struct PendingPathValidation {
    handle: PathHandle,
    binding: CarrierBinding,
    challenge: [u8; 8],
    issued_secs: u64,
    retries: u8,
}

#[derive(Debug)]
struct ServerSessionState {
    session_id: SessionId,
    assigned_ipv4: Ipv4Addr,
    assigned_ipv6: Option<Ipv6Addr>,
    tunnel: TunnelSession,
    adaptive: AdaptiveDatapath,
    outer_keys: RuntimeOuterKeys,
    encapsulation: TunnelEncapsulation,
    primary_path: ServerPathState,
    standby_path: Option<ServerPathState>,
    pending_validation: Option<PendingPathValidation>,
}

#[derive(Clone, Debug)]
struct ServerStreamPeer {
    peer_addr: SocketAddr,
    sender: mpsc::UnboundedSender<StreamWrite>,
}

#[derive(Clone, Debug)]
struct ServerD2Peer {
    peer_addr: SocketAddr,
    sender: mpsc::UnboundedSender<Vec<u8>>,
}

#[derive(Debug)]
enum ServerTransportEvent {
    Datagram {
        peer_addr: SocketAddr,
        bytes: Vec<u8>,
    },
    D2Opened {
        conn_id: u64,
        peer_addr: SocketAddr,
        sender: mpsc::UnboundedSender<Vec<u8>>,
    },
    D2Datagram {
        conn_id: u64,
        bytes: Vec<u8>,
    },
    D2Closed {
        conn_id: u64,
    },
    StreamOpened {
        conn_id: u64,
        peer_addr: SocketAddr,
        sender: mpsc::UnboundedSender<StreamWrite>,
    },
    StreamRecord {
        conn_id: u64,
        bytes: Vec<u8>,
    },
    StreamClosed {
        conn_id: u64,
        malformed: bool,
    },
}

#[derive(Debug)]
struct MatchedServerPacket {
    session_id: SessionId,
    tunnel: TunnelSession,
    decoded: apt_tunnel::DecodedPacket,
    tunnel_bytes_len: usize,
}

pub async fn run_client(config: ResolvedClientConfig) -> Result<ClientRuntimeResult, RuntimeError> {
    client::run_client(config).await
}

pub async fn run_server(config: ResolvedServerConfig) -> Result<ServerRuntimeResult, RuntimeError> {
    server::run_server(config).await
}
