use apt_types::{CarrierBinding, PolicyMode};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, time::SystemTime};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeStatus {
    Starting,
    Connected,
    Disconnected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientStatus {
    pub status: RuntimeStatus,
    pub server: String,
    pub active_carrier: Option<CarrierBinding>,
    pub standby_carrier: Option<CarrierBinding>,
    pub policy_mode: Option<PolicyMode>,
    pub tunnel_address: Option<IpAddr>,
    #[serde(default)]
    pub tunnel_addresses: Vec<IpAddr>,
    pub interface_name: Option<String>,
    pub last_transition_unix_secs: u64,
}

impl ClientStatus {
    #[must_use]
    pub fn new(
        status: RuntimeStatus,
        server: String,
        tunnel_address: Option<IpAddr>,
        tunnel_addresses: Vec<IpAddr>,
        interface_name: Option<String>,
        active_carrier: Option<CarrierBinding>,
        standby_carrier: Option<CarrierBinding>,
        policy_mode: Option<PolicyMode>,
    ) -> Self {
        Self {
            status,
            server,
            tunnel_address,
            tunnel_addresses,
            interface_name,
            active_carrier,
            standby_carrier,
            policy_mode,
            last_transition_unix_secs: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    pub peer: String,
    pub carrier: CarrierBinding,
    pub assigned_ipv4: Option<IpAddr>,
    pub assigned_ipv6: Option<IpAddr>,
    pub established_unix_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerStatus {
    pub bind: String,
    pub interface_name: Option<String>,
    pub listening_carriers: Vec<CarrierBinding>,
    pub active_sessions: usize,
    pub active_carrier: Option<CarrierBinding>,
    pub standby_carrier: Option<CarrierBinding>,
    pub policy_mode: Option<PolicyMode>,
}
