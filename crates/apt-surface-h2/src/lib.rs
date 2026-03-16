//! H2-facing public-session helpers for the v2 API-sync cover family.
//!
//! This initial slice is intentionally surface-model oriented rather than a full
//! HTTP/2 implementation: it models honest API-sync request/response bodies and
//! legal hidden-upgrade slot insertion/extraction so later runtime/network code
//! can consume a focused interface.
#![allow(missing_docs)]

mod api_sync;
mod json_slot;

pub use self::api_sync::{
    ApiSyncH2Carrier, ApiSyncRequest, ApiSyncRequestUpgradeEnvelope, ApiSyncResponse,
    ApiSyncResponseUpgradeEnvelope, ApiSyncSurface, SurfaceH2Error, API_SYNC_REQUEST_SLOT,
    API_SYNC_RESPONSE_SLOT,
};
