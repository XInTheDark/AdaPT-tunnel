//! Production runtime support for the APT protocol core.
//!
//! This crate adds the missing deployment layer above the protocol engine:
//! configuration loading, UDP transport runtime, TUN wiring, basic route/DNS/NAT
//! orchestration, and thin operational helpers for the client and combined
//! server daemon.
#![allow(missing_docs)]

mod adaptive;
mod client_runtime;
mod config;
mod dns;
mod error;
mod keys;
mod quic;
mod route;
mod runtime;
mod status;
mod tun;
mod wire;

pub use apt_types::{Mode, SessionPolicy};
pub use client_runtime::{ClientRuntimeHooks, ClientRuntimeStats};
pub use config::{
    encode_key_hex, load_key32, AuthorizedPeerConfig, ClientConfig, ClientPersistentState,
    ResolvedClientConfig, ResolvedClientD2Config, ResolvedRemoteEndpoint, ResolvedServerConfig,
    ResolvedServerD2Config, RuntimeCarrierPreference, ServerConfig, ServerSessionExtension,
    SessionTransportParameters, V2ClientFamilyConfig, V2ClientSurfacePlan,
    V2ClientTransportConfigDraft, V2D1FallbackPolicy, V2DeploymentStrength,
    V2FamilyPreference, V2OriginPlanError, V2SchemaVersion, V2ServerSurfaceConfig,
    V2ServerSurfacePlan, V2ServerTransportConfigDraft, V2SurfaceTrustConfig,
};
pub use error::RuntimeError;
pub use keys::{
    generate_client_identity, generate_d2_tls_identity, generate_server_keyset, write_key_file,
    write_secret_file, GeneratedClientIdentity, GeneratedD2TlsIdentity, GeneratedServerKeyset,
};
pub use quic::{
    d2_certificate_subject_alt_names, d2_default_bind, derive_d2_public_endpoint,
    load_certificate_der, D2_DEFAULT_PORT,
};
pub use runtime::{
    run_client, run_client_with_hooks, run_server, ClientRuntimeResult, ServerRuntimeResult,
};
pub use status::{ClientStatus, RuntimeStatus, ServerStatus, SessionSummary};
