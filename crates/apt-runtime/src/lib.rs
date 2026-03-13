//! Production runtime support for the APT protocol core.
//!
//! This crate adds the missing deployment layer above the protocol engine:
//! configuration loading, UDP transport runtime, TUN wiring, basic routing/NAT
//! orchestration, and thin operational helpers for the client and combined
//! server daemon.
#![allow(missing_docs)]

mod config;
mod error;
mod keys;
mod route;
mod runtime;
mod status;
mod tun;

pub use config::{
    encode_key_hex, load_key32, ClientConfig, ClientPersistentState, ResolvedClientConfig,
    ResolvedServerConfig, ServerConfig, ServerSessionExtension, SessionTransportParameters,
};
pub use error::RuntimeError;
pub use keys::{
    generate_client_identity, generate_server_keyset, write_key_file, GeneratedClientIdentity,
    GeneratedServerKeyset,
};
pub use runtime::{run_client, run_server, ClientRuntimeResult, ServerRuntimeResult};
pub use status::{ClientStatus, RuntimeStatus, ServerStatus, SessionSummary};
