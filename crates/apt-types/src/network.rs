use serde::{Deserialize, Serialize};

/// Coarse path-class estimate for the current network.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathClass {
    /// No evidence has been collected yet.
    #[default]
    Unknown,
    /// Path is permissive and steady.
    Stable,
    /// Path is workable but variable.
    Variable,
    /// Path is constrained or partially interfered with.
    Constrained,
    /// Path shows strong blocking or impairment behaviour.
    Hostile,
}

/// Coarse path MTU class.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum MtuClass {
    /// Unknown MTU.
    #[default]
    Unknown,
    /// Small MTU / blackhole-prone path.
    Small,
    /// Moderate MTU.
    Medium,
    /// Large / permissive MTU.
    Large,
}

/// Coarse RTT class.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RttClass {
    /// No RTT estimate is available.
    #[default]
    Unknown,
    /// Roughly LAN / very low RTT.
    Low,
    /// Moderate RTT.
    Moderate,
    /// High RTT.
    High,
    /// Extremely high RTT or unstable delay.
    Extreme,
}

/// Coarse loss estimate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum LossClass {
    /// No estimate is available.
    #[default]
    Unknown,
    /// Low packet loss.
    Low,
    /// Medium packet loss.
    Medium,
    /// High packet loss.
    High,
}

/// Coarse NAT behaviour class.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatClass {
    /// No NAT information is available.
    #[default]
    Unknown,
    /// No NAT or broadly open path.
    OpenInternet,
    /// Endpoint-independent behaviour.
    EndpointIndependent,
    /// Address-dependent behaviour.
    AddressDependent,
    /// Symmetric / highly restrictive behaviour.
    Symmetric,
}

/// Coarse connection longevity class used by local-normality modelling.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionLongevityClass {
    /// Unknown longevity.
    #[default]
    Unknown,
    /// Short-lived flows dominate.
    Ephemeral,
    /// Medium-lived flows dominate.
    Moderate,
    /// Long-lived flows are common.
    LongLived,
}

/// Packet-path summary carried through admission and policy layers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathProfile {
    /// Coarse overall path class.
    pub path: PathClass,
    /// Coarse MTU class.
    pub mtu: MtuClass,
    /// Coarse RTT class.
    pub rtt: RttClass,
    /// Coarse loss class.
    pub loss: LossClass,
    /// Coarse NAT class.
    pub nat: NatClass,
}

impl PathProfile {
    /// Returns a fully unknown profile for bootstrap use.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            path: PathClass::Unknown,
            mtu: MtuClass::Unknown,
            rtt: RttClass::Unknown,
            loss: LossClass::Unknown,
            nat: NatClass::Unknown,
        }
    }
}

/// Coarse local link type.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LinkType {
    /// Unknown or unclassified link type.
    #[default]
    Unknown,
    /// Wi-Fi / WLAN.
    Wifi,
    /// Cellular or WWAN.
    Cellular,
    /// Ethernet or wired LAN.
    Ethernet,
    /// Overlay / virtual link.
    Virtual,
    /// Other deployment-specific link label.
    Named(String),
}

/// Privacy-preserving gateway fingerprint material.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GatewayFingerprint(pub String);

/// Coarse public route hint used for local profile bucketing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicRouteHint(pub String);

/// Client-side network context key used for local-normality profiles.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LocalNetworkContext {
    /// Link type.
    pub link_type: LinkType,
    /// Local gateway fingerprint or label.
    pub gateway: GatewayFingerprint,
    /// Local SSID or equivalent label.
    pub local_label: String,
    /// Coarse public route hint.
    pub public_route: PublicRouteHint,
}

/// Allowed metadata-only observation used for local-normality modelling.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkMetadataObservation {
    /// Packet size in bytes.
    pub packet_size: u16,
    /// Inter-send gap in milliseconds.
    pub inter_send_gap_ms: u32,
    /// Burst length.
    pub burst_length: u16,
    /// Upstream/downstream byte-ratio class represented as an ordinal bucket.
    pub upstream_downstream_ratio_class: u8,
    /// Coarse path profile at the time of observation.
    pub path_profile: PathProfile,
    /// Coarse connection longevity class.
    pub longevity: ConnectionLongevityClass,
    /// Whether the observation came from APT tunnel traffic.
    pub tunnel_traffic: bool,
}
