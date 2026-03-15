use apt_persona::{PersonaEngine, PersonaInputs, PersonaProfile, RememberedProfile};
use apt_policy::{LocalNormalityProfile, PolicyController};
use apt_tunnel::Frame;
use apt_types::{
    CarrierBinding, ConnectionLongevityClass, GatewayFingerprint, KeepaliveMode, LinkType,
    LocalNetworkContext, LossClass, MtuClass, NatClass, NetworkMetadataObservation, PathClass,
    PathProfile, PathSignalEvent, PolicyMode, PublicRouteHint, RttClass,
};

mod context;
mod datapath;
mod keepalive;
mod normality;
mod shaping;

#[cfg(test)]
mod tests;

const POLICY_OBSERVATION_INTERVAL_SECS: u64 = 15;
const QUIET_IMPAIRMENT_THRESHOLD_SECS: u64 = 45;
const PROFILE_REFRESH_EVERY_OBSERVATIONS: u16 = 64;

pub(crate) use context::{
    build_client_network_context, canonicalize_local_network_context,
    discover_client_network_context, local_network_profile_key,
};
pub(crate) use datapath::AdaptiveDatapath;
pub(crate) use normality::admission_path_profile;
