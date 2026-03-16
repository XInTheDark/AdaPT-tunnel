//! H2-facing public-session helpers for the v2 API-sync cover family.
//!
//! The crate models honest API-sync request/response bodies, legal hidden-upgrade
//! slot insertion/extraction, HTTP request/response codecs, and the same legal
//! slot shapes reused for post-upgrade tunnel packets.
#![allow(missing_docs)]

mod api_sync;
mod json_slot;

pub use self::api_sync::{
    ApiSyncH2Carrier, ApiSyncRequest, ApiSyncRequestTunnelEnvelope,
    ApiSyncRequestTunnelPollEnvelope, ApiSyncRequestUpgradeEnvelope, ApiSyncResponse,
    ApiSyncResponseTunnelEnvelope, ApiSyncResponseUpgradeEnvelope, ApiSyncSurface, SurfaceH2Error,
    API_SYNC_REQUEST_SLOT, API_SYNC_RESPONSE_SLOT,
};
