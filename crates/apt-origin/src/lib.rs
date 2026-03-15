//! Public-service family descriptions for AdaPT v2 surface planning.
//!
//! This crate stays data-model oriented for now: it describes honest public
//! service families, legal request graphs, upgrade slot classes, and
//! runtime-facing cover metadata that later `apt-surface-h2` /
//! `apt-surface-h3` implementations will consume.
#![allow(missing_docs)]

mod model;
mod profiles;

pub use self::model::{
    FeatureWeights, IdleConvergenceRules, MessagePhase, OriginFamilyId, OriginFamilyProfile,
    PublicSessionTransport, RequestGraphBranch, RequestMethod, RequestPattern, ShadowLaneKind,
    ShadowLaneRules, SizeTimingEnvelope, StreamConcurrencyRules, UpgradeSlot, UpgradeSlotKind,
    UpgradeSlotVisibility,
};
