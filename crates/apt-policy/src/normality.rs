use apt_types::{LocalNetworkContext, NetworkMetadataObservation};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
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
    packet_sizes: VecDeque<WeightedSample<u16>>,
    gaps_ms: VecDeque<WeightedSample<u32>>,
    bursts: VecDeque<WeightedSample<u16>>,
    weighted_observations: f32,
}

impl LocalNormalityProfile {
    /// Creates a new empty profile for the supplied context.
    #[must_use]
    pub fn new(context: LocalNetworkContext) -> Self {
        Self {
            context,
            successful_sessions: 0,
            packet_sizes: VecDeque::new(),
            gaps_ms: VecDeque::new(),
            bursts: VecDeque::new(),
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
        push_weighted(
            &mut self.packet_sizes,
            WeightedSample {
                value: observation.packet_size.clamp(64, 4_096),
                weight,
            },
        );
        push_weighted(
            &mut self.gaps_ms,
            WeightedSample {
                value: observation.inter_send_gap_ms.clamp(0, 60_000),
                weight,
            },
        );
        push_weighted(
            &mut self.bursts,
            WeightedSample {
                value: observation.burst_length.clamp(1, 256),
                weight,
            },
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

fn push_weighted<T>(values: &mut VecDeque<WeightedSample<T>>, sample: WeightedSample<T>) {
    if values.len() == MAX_STORED_SAMPLES {
        values.pop_front();
    }
    values.push_back(sample);
}

fn weighted_quantile_u16(
    values: &VecDeque<WeightedSample<u16>>,
    quantile: f32,
) -> Result<u16, PolicyError> {
    if values.is_empty() {
        return Err(PolicyError::InsufficientData);
    }
    let mut sorted: Vec<_> = values.iter().cloned().collect();
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
    Ok(values.back().expect("checked non-empty").value)
}

fn weighted_quantile_u32(
    values: &VecDeque<WeightedSample<u32>>,
    quantile: f32,
) -> Result<u32, PolicyError> {
    if values.is_empty() {
        return Err(PolicyError::InsufficientData);
    }
    let mut sorted: Vec<_> = values.iter().cloned().collect();
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
    Ok(values.back().expect("checked non-empty").value)
}
