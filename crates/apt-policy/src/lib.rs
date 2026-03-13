//! Policy control and local-normality bootstrap support.
//!
//! The first-cut policy layer keeps learning intentionally conservative. It uses
//! only metadata permitted by the spec, clips updates, weights tunnel traffic
//! less than ambient traffic, and exposes simple mode-transition logic.

use apt_types::{
    CarrierBinding, LocalNetworkContext, NetworkMetadataObservation, PathSignalEvent, PolicyMode,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_STORED_SAMPLES: usize = 512;
const TUNNEL_TRAFFIC_WEIGHT: f32 = 0.25;
const NON_TUNNEL_TRAFFIC_WEIGHT: f32 = 1.0;
const BOOTSTRAP_OBSERVATIONS: f32 = 200.0;
const BOOTSTRAP_SUCCESSFUL_SESSIONS: u32 = 3;

/// Errors returned by the policy layer.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// A quantile was requested before data existed.
    #[error("insufficient data for requested summary")]
    InsufficientData,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct WeightedSample<T> {
    value: T,
    weight: f32,
}

/// Summary statistics exposed by a local-normality profile.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProfileSummary {
    /// Approximate weighted median packet size.
    pub median_packet_size: u16,
    /// Approximate weighted median inter-send gap.
    pub median_gap_ms: u32,
    /// Approximate weighted median burst length.
    pub median_burst_length: u16,
    /// Number of successful APT sessions on this network context.
    pub successful_sessions: u32,
    /// Weighted observation count.
    pub weighted_observations: f32,
}

/// Per-network local-normality profile.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LocalNormalityProfile {
    /// Network context key.
    pub context: LocalNetworkContext,
    /// Successful APT sessions observed on this context.
    pub successful_sessions: u32,
    packet_sizes: Vec<WeightedSample<u16>>,
    gaps_ms: Vec<WeightedSample<u32>>,
    bursts: Vec<WeightedSample<u16>>,
    weighted_observations: f32,
}

impl LocalNormalityProfile {
    /// Creates a new empty profile for the supplied context.
    #[must_use]
    pub fn new(context: LocalNetworkContext) -> Self {
        Self {
            context,
            successful_sessions: 0,
            packet_sizes: Vec::new(),
            gaps_ms: Vec::new(),
            bursts: Vec::new(),
            weighted_observations: 0.0,
        }
    }

    /// Records a metadata-only observation with clipped updates.
    pub fn record_observation(&mut self, observation: &NetworkMetadataObservation) {
        let weight = if observation.tunnel_traffic {
            TUNNEL_TRAFFIC_WEIGHT
        } else {
            NON_TUNNEL_TRAFFIC_WEIGHT
        };
        self.weighted_observations += weight;
        push_weighted(&mut self.packet_sizes, WeightedSample { value: observation.packet_size.clamp(64, 4_096), weight });
        push_weighted(
            &mut self.gaps_ms,
            WeightedSample { value: observation.inter_send_gap_ms.clamp(0, 60_000), weight },
        );
        push_weighted(
            &mut self.bursts,
            WeightedSample { value: observation.burst_length.clamp(1, 256), weight },
        );
    }

    /// Notes one successful APT session.
    pub fn note_successful_session(&mut self) {
        self.successful_sessions = self.successful_sessions.saturating_add(1);
    }

    /// Returns whether the profile has enough evidence to leave bootstrap mode.
    #[must_use]
    pub fn is_bootstrapped(&self) -> bool {
        self.weighted_observations >= BOOTSTRAP_OBSERVATIONS
            || self.successful_sessions >= BOOTSTRAP_SUCCESSFUL_SESSIONS
    }

    /// Produces a robust median-based summary.
    pub fn summary(&self) -> Result<ProfileSummary, PolicyError> {
        Ok(ProfileSummary {
            median_packet_size: weighted_quantile_u16(&self.packet_sizes, 0.5)?,
            median_gap_ms: weighted_quantile_u32(&self.gaps_ms, 0.5)?,
            median_burst_length: weighted_quantile_u16(&self.bursts, 0.5)?,
            successful_sessions: self.successful_sessions,
            weighted_observations: self.weighted_observations,
        })
    }
}

/// Runtime controller for policy-mode transitions and migration pressure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyController {
    /// Current policy mode.
    pub current_mode: PolicyMode,
    /// Whether automatic speed-first mode is allowed.
    pub allow_speed_first: bool,
    stable_score: i16,
    impairment_score: i16,
}

impl PolicyController {
    /// Creates a new controller.
    #[must_use]
    pub fn new(initial_mode: PolicyMode, allow_speed_first: bool) -> Self {
        Self { current_mode: initial_mode, allow_speed_first, stable_score: 0, impairment_score: 0 }
    }

    /// Applies a path signal and returns the updated mode.
    pub fn observe_signal(&mut self, signal: PathSignalEvent) -> PolicyMode {
        match signal {
            PathSignalEvent::StableDelivery => {
                self.stable_score = (self.stable_score + 1).min(16);
                self.impairment_score = (self.impairment_score - 1).max(0);
            }
            PathSignalEvent::HandshakeBlackhole
            | PathSignalEvent::ImmediateReset
            | PathSignalEvent::FallbackFailure => {
                self.impairment_score = (self.impairment_score + 2).min(16);
                self.stable_score = (self.stable_score - 2).max(0);
            }
            PathSignalEvent::SizeSpecificLoss
            | PathSignalEvent::MtuBlackhole
            | PathSignalEvent::RttInflation
            | PathSignalEvent::NatRebinding => {
                self.impairment_score = (self.impairment_score + 1).min(16);
                self.stable_score = (self.stable_score - 1).max(0);
            }
        }
        self.current_mode = if self.impairment_score >= 2 {
            PolicyMode::StealthFirst
        } else if self.allow_speed_first && self.stable_score >= 10 {
            PolicyMode::SpeedFirst
        } else if self.stable_score >= 4 {
            PolicyMode::Balanced
        } else {
            self.current_mode
        };
        self.current_mode
    }

    /// Returns whether current impairment pressure justifies migration.
    #[must_use]
    pub fn should_migrate(&self) -> bool {
        self.impairment_score >= 3
    }

    /// Produces a conservative fallback order with the impaired carrier deprioritized.
    #[must_use]
    pub fn fallback_order(&self, current: CarrierBinding) -> Vec<CarrierBinding> {
        let mut order = CarrierBinding::conservative_fallback_order().to_vec();
        if self.should_migrate() {
            if let Some(index) = order.iter().position(|carrier| *carrier == current) {
                let current_binding = order.remove(index);
                order.push(current_binding);
            }
        }
        order
    }
}

fn push_weighted<T>(values: &mut Vec<WeightedSample<T>>, sample: WeightedSample<T>) {
    if values.len() == MAX_STORED_SAMPLES {
        values.remove(0);
    }
    values.push(sample);
}

fn weighted_quantile_u16(values: &[WeightedSample<u16>], quantile: f32) -> Result<u16, PolicyError> {
    if values.is_empty() {
        return Err(PolicyError::InsufficientData);
    }
    let mut sorted = values.to_vec();
    sorted.sort_by_key(|sample| sample.value);
    let total_weight: f32 = sorted.iter().map(|sample| sample.weight).sum();
    let target = total_weight * quantile;
    let mut cumulative = 0.0;
    for sample in sorted {
        cumulative += sample.weight;
        if cumulative >= target {
            return Ok(sample.value);
        }
    }
    Ok(values.last().expect("checked non-empty").value)
}

fn weighted_quantile_u32(values: &[WeightedSample<u32>], quantile: f32) -> Result<u32, PolicyError> {
    if values.is_empty() {
        return Err(PolicyError::InsufficientData);
    }
    let mut sorted = values.to_vec();
    sorted.sort_by_key(|sample| sample.value);
    let total_weight: f32 = sorted.iter().map(|sample| sample.weight).sum();
    let target = total_weight * quantile;
    let mut cumulative = 0.0;
    for sample in sorted {
        cumulative += sample.weight;
        if cumulative >= target {
            return Ok(sample.value);
        }
    }
    Ok(values.last().expect("checked non-empty").value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use apt_types::{
        ConnectionLongevityClass, GatewayFingerprint, LinkType, LossClass, MtuClass, NatClass,
        PathClass, PathProfile, PublicRouteHint, RttClass,
    };

    fn context() -> LocalNetworkContext {
        LocalNetworkContext {
            link_type: LinkType::Wifi,
            gateway: GatewayFingerprint("gw-a".to_string()),
            local_label: "ssid-a".to_string(),
            public_route: PublicRouteHint("route-a".to_string()),
        }
    }

    fn observation(packet_size: u16, tunnel_traffic: bool) -> NetworkMetadataObservation {
        NetworkMetadataObservation {
            packet_size,
            inter_send_gap_ms: 50,
            burst_length: 4,
            upstream_downstream_ratio_class: 2,
            path_profile: PathProfile {
                path: PathClass::Stable,
                mtu: MtuClass::Medium,
                rtt: RttClass::Moderate,
                loss: LossClass::Low,
                nat: NatClass::EndpointIndependent,
            },
            longevity: ConnectionLongevityClass::Moderate,
            tunnel_traffic,
        }
    }

    #[test]
    fn bootstrap_requires_enough_weight_or_successes() {
        let mut profile = LocalNormalityProfile::new(context());
        for _ in 0..50 {
            profile.record_observation(&observation(700, true));
        }
        assert!(!profile.is_bootstrapped());
        for _ in 0..3 {
            profile.note_successful_session();
        }
        assert!(profile.is_bootstrapped());
    }

    #[test]
    fn tunnel_traffic_counts_less_than_non_tunnel() {
        let mut profile = LocalNormalityProfile::new(context());
        profile.record_observation(&observation(200, true));
        profile.record_observation(&observation(1_400, false));
        let summary = profile.summary().unwrap();
        assert_eq!(summary.median_packet_size, 1_400);
    }

    #[test]
    fn controller_moves_between_modes() {
        let mut controller = PolicyController::new(PolicyMode::StealthFirst, true);
        for _ in 0..5 {
            controller.observe_signal(PathSignalEvent::StableDelivery);
        }
        assert_eq!(controller.current_mode, PolicyMode::Balanced);
        for _ in 0..6 {
            controller.observe_signal(PathSignalEvent::StableDelivery);
        }
        assert_eq!(controller.current_mode, PolicyMode::SpeedFirst);
        controller.observe_signal(PathSignalEvent::ImmediateReset);
        controller.observe_signal(PathSignalEvent::ImmediateReset);
        assert_eq!(controller.current_mode, PolicyMode::StealthFirst);
    }
}
