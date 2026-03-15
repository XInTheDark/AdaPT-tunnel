use self::{buckets::*, classify::*};
use apt_types::{
    CarrierBinding, ConnectionLongevityClass, LocalNetworkContext, LossClass, MtuClass, NatClass,
    NetworkMetadataObservation, RttClass,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod buckets;
mod classify;

const TUNNEL_TRAFFIC_WEIGHT_UNITS: u16 = 1;
const NON_TUNNEL_TRAFFIC_WEIGHT_UNITS: u16 = 4;
const MIN_BOOTSTRAP_EVIDENCE_UNITS: u32 = 96;
const BOOTSTRAP_SUCCESSFUL_SESSIONS: u32 = 3;
const MAX_SESSION_OBSERVATION_UNITS: u16 = 64;
const MAX_SESSION_SUCCESS_UPDATES: u16 = 1;
const MAX_SESSION_FAILURE_UPDATES: u16 = 2;
const MAX_SESSION_REBINDING_UPDATES: u16 = 2;
const MAX_SESSION_IDLE_TIMEOUT_UPDATES: u16 = 2;

/// Errors returned by the policy layer.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// A summary was requested before enough data existed.
    #[error("insufficient data for requested summary")]
    InsufficientData,
}

/// Per-carrier bounded counters remembered inside the local-normality profile.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarrierCounters {
    /// Successful sessions completed on this carrier.
    pub successes: u16,
    /// Generic failure or impairment events observed on this carrier.
    pub failures: u16,
    /// NAT rebinding or similar path churn observed on this carrier.
    pub rebindings: u16,
    /// Idle-timeout or quiet-timeout symptoms observed on this carrier.
    pub idle_timeouts: u16,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SessionClipState {
    observation_units: u16,
    success_updates: [u16; 4],
    failure_updates: [u16; 4],
    rebinding_updates: [u16; 4],
    idle_timeout_updates: [u16; 4],
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
struct LegacyWeightedSampleU16 {
    value: u16,
    weight: f32,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
struct LegacyWeightedSampleU32 {
    value: u32,
    weight: f32,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct LocalNormalityProfileSerde {
    context: LocalNetworkContext,
    #[serde(default)]
    successful_sessions: u32,
    #[serde(default)]
    packet_size_buckets: [u16; 8],
    #[serde(default)]
    gap_buckets_ms: [u16; 8],
    #[serde(default)]
    burst_buckets: [u16; 6],
    #[serde(default)]
    ratio_buckets: [u16; 7],
    #[serde(default)]
    rtt_class_counts: [u16; 5],
    #[serde(default)]
    loss_class_counts: [u16; 4],
    #[serde(default)]
    mtu_class_counts: [u16; 4],
    #[serde(default)]
    nat_class_counts: [u16; 5],
    #[serde(default)]
    longevity_counts: [u16; 4],
    #[serde(default)]
    carrier_counters: [CarrierCounters; 4],
    #[serde(default)]
    weighted_observation_units: u32,
    #[serde(default)]
    packet_sizes: Vec<LegacyWeightedSampleU16>,
    #[serde(default)]
    gaps_ms: Vec<LegacyWeightedSampleU32>,
    #[serde(default)]
    bursts: Vec<LegacyWeightedSampleU16>,
}

/// Summary statistics exposed by a local-normality profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSummary {
    /// Approximate weighted median packet size.
    pub median_packet_size: u16,
    /// Approximate weighted median inter-send gap.
    pub median_gap_ms: u32,
    /// Approximate weighted median burst length.
    pub median_burst_length: u16,
    /// Dominant upstream/downstream ratio bucket.
    pub dominant_ratio_bucket: u8,
    /// Dominant RTT class after applying evidence thresholds.
    pub dominant_rtt: RttClass,
    /// Dominant loss class after applying evidence thresholds.
    pub dominant_loss: LossClass,
    /// Dominant MTU class after applying evidence thresholds.
    pub dominant_mtu: MtuClass,
    /// Dominant NAT class after applying evidence thresholds.
    pub dominant_nat: NatClass,
    /// Dominant connection longevity class after applying evidence thresholds.
    pub dominant_longevity: ConnectionLongevityClass,
    /// Number of successful APT sessions on this network context.
    pub successful_sessions: u32,
    /// Weighted observation count after clipping.
    pub weighted_observation_units: u32,
    /// Preferred carrier inferred from bounded per-carrier evidence.
    pub preferred_carrier: Option<CarrierBinding>,
    /// Coarse permissiveness score derived from the learned statistics.
    pub permissiveness_score: u8,
}

/// Per-network local-normality profile.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LocalNormalityProfile {
    /// Network context key.
    pub context: LocalNetworkContext,
    /// Successful APT sessions observed on this context.
    pub successful_sessions: u32,
    packet_size_buckets: [u16; 8],
    gap_buckets_ms: [u16; 8],
    burst_buckets: [u16; 6],
    ratio_buckets: [u16; 7],
    rtt_class_counts: [u16; 5],
    loss_class_counts: [u16; 4],
    mtu_class_counts: [u16; 4],
    nat_class_counts: [u16; 5],
    longevity_counts: [u16; 4],
    carrier_counters: [CarrierCounters; 4],
    weighted_observation_units: u32,
    #[serde(skip, default)]
    session_clip: SessionClipState,
}

impl<'de> Deserialize<'de> for LocalNormalityProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = LocalNormalityProfileSerde::deserialize(deserializer)?;
        Ok(Self::from(value))
    }
}

impl From<LocalNormalityProfileSerde> for LocalNormalityProfile {
    fn from(value: LocalNormalityProfileSerde) -> Self {
        let mut profile = Self {
            context: value.context,
            successful_sessions: value.successful_sessions,
            packet_size_buckets: value.packet_size_buckets,
            gap_buckets_ms: value.gap_buckets_ms,
            burst_buckets: value.burst_buckets,
            ratio_buckets: value.ratio_buckets,
            rtt_class_counts: value.rtt_class_counts,
            loss_class_counts: value.loss_class_counts,
            mtu_class_counts: value.mtu_class_counts,
            nat_class_counts: value.nat_class_counts,
            longevity_counts: value.longevity_counts,
            carrier_counters: value.carrier_counters,
            weighted_observation_units: value.weighted_observation_units,
            session_clip: SessionClipState::default(),
        };

        let has_legacy_samples =
            !value.packet_sizes.is_empty() || !value.gaps_ms.is_empty() || !value.bursts.is_empty();
        if profile.weighted_observation_units == 0 && has_legacy_samples {
            for sample in value.packet_sizes {
                let weight = legacy_weight_units(sample.weight);
                if weight == 0 {
                    continue;
                }
                let index = packet_size_bucket_index(sample.value);
                bump_bucket(&mut profile.packet_size_buckets, index, weight);
                profile.weighted_observation_units = profile
                    .weighted_observation_units
                    .saturating_add(u32::from(weight));
            }
            for sample in value.gaps_ms {
                let weight = legacy_weight_units(sample.weight);
                if weight > 0 {
                    bump_bucket(
                        &mut profile.gap_buckets_ms,
                        gap_bucket_index(sample.value),
                        weight,
                    );
                }
            }
            for sample in value.bursts {
                let weight = legacy_weight_units(sample.weight);
                if weight > 0 {
                    bump_bucket(
                        &mut profile.burst_buckets,
                        burst_bucket_index(sample.value),
                        weight,
                    );
                }
            }
        }

        profile.begin_new_session();
        profile
    }
}

impl LocalNormalityProfile {
    /// Creates a new empty profile for the supplied context.
    #[must_use]
    pub fn new(context: LocalNetworkContext) -> Self {
        Self {
            context,
            successful_sessions: 0,
            packet_size_buckets: [0; 8],
            gap_buckets_ms: [0; 8],
            burst_buckets: [0; 6],
            ratio_buckets: [0; 7],
            rtt_class_counts: [0; 5],
            loss_class_counts: [0; 4],
            mtu_class_counts: [0; 4],
            nat_class_counts: [0; 5],
            longevity_counts: [0; 4],
            carrier_counters: [CarrierCounters::default(); 4],
            weighted_observation_units: 0,
            session_clip: SessionClipState::default(),
        }
    }

    /// Resets transient per-session clipping state when a new tunnel session starts.
    pub fn begin_new_session(&mut self) {
        self.session_clip = SessionClipState::default();
    }

    /// Records a metadata-only observation with bounded per-session clipping.
    pub fn record_observation(&mut self, observation: &NetworkMetadataObservation) {
        let requested_units = if observation.tunnel_traffic {
            TUNNEL_TRAFFIC_WEIGHT_UNITS
        } else {
            NON_TUNNEL_TRAFFIC_WEIGHT_UNITS
        };
        let allowed_units = allow_observation_units(&mut self.session_clip, requested_units);
        if allowed_units == 0 {
            return;
        }

        self.weighted_observation_units = self
            .weighted_observation_units
            .saturating_add(u32::from(allowed_units));
        bump_bucket(
            &mut self.packet_size_buckets,
            packet_size_bucket_index(observation.packet_size),
            allowed_units,
        );
        bump_bucket(
            &mut self.gap_buckets_ms,
            gap_bucket_index(observation.inter_send_gap_ms),
            allowed_units,
        );
        bump_bucket(
            &mut self.burst_buckets,
            burst_bucket_index(observation.burst_length),
            allowed_units,
        );
        bump_bucket(
            &mut self.ratio_buckets,
            ratio_bucket_index(observation.upstream_downstream_ratio_class),
            allowed_units,
        );
        bump_bucket(
            &mut self.rtt_class_counts,
            rtt_index(observation.path_profile.rtt),
            allowed_units,
        );
        bump_bucket(
            &mut self.loss_class_counts,
            loss_index(observation.path_profile.loss),
            allowed_units,
        );
        bump_bucket(
            &mut self.mtu_class_counts,
            mtu_index(observation.path_profile.mtu),
            allowed_units,
        );
        bump_bucket(
            &mut self.nat_class_counts,
            nat_index(observation.path_profile.nat),
            allowed_units,
        );
        bump_bucket(
            &mut self.longevity_counts,
            longevity_index(observation.longevity),
            allowed_units,
        );
    }

    /// Notes one successful APT session.
    pub fn note_successful_session(&mut self) {
        self.successful_sessions = self.successful_sessions.saturating_add(1);
    }

    /// Notes one successful session for the supplied carrier.
    pub fn note_carrier_success(&mut self, carrier: CarrierBinding) {
        if allow_carrier_event(
            &mut self.session_clip.success_updates,
            carrier,
            MAX_SESSION_SUCCESS_UPDATES,
        ) {
            self.carrier_counters[carrier_index(carrier)].successes = self.carrier_counters
                [carrier_index(carrier)]
            .successes
            .saturating_add(1);
        }
    }

    /// Notes one generic failure/impairment signal for the supplied carrier.
    pub fn note_carrier_failure(&mut self, carrier: CarrierBinding) {
        if allow_carrier_event(
            &mut self.session_clip.failure_updates,
            carrier,
            MAX_SESSION_FAILURE_UPDATES,
        ) {
            self.carrier_counters[carrier_index(carrier)].failures = self.carrier_counters
                [carrier_index(carrier)]
            .failures
            .saturating_add(1);
        }
    }

    /// Notes one NAT rebinding signal for the supplied carrier.
    pub fn note_carrier_rebinding(&mut self, carrier: CarrierBinding) {
        if allow_carrier_event(
            &mut self.session_clip.rebinding_updates,
            carrier,
            MAX_SESSION_REBINDING_UPDATES,
        ) {
            self.carrier_counters[carrier_index(carrier)].rebindings = self.carrier_counters
                [carrier_index(carrier)]
            .rebindings
            .saturating_add(1);
        }
    }

    /// Notes one idle-timeout/quiet-timeout symptom for the supplied carrier.
    pub fn note_carrier_idle_timeout(&mut self, carrier: CarrierBinding) {
        if allow_carrier_event(
            &mut self.session_clip.idle_timeout_updates,
            carrier,
            MAX_SESSION_IDLE_TIMEOUT_UPDATES,
        ) {
            self.carrier_counters[carrier_index(carrier)].idle_timeouts = self.carrier_counters
                [carrier_index(carrier)]
            .idle_timeouts
            .saturating_add(1);
        }
    }

    /// Returns whether the profile has enough evidence to leave bootstrap mode.
    #[must_use]
    pub fn is_bootstrapped(&self) -> bool {
        self.weighted_observation_units >= MIN_BOOTSTRAP_EVIDENCE_UNITS
            || self.successful_sessions >= BOOTSTRAP_SUCCESSFUL_SESSIONS
    }

    /// Returns the bounded per-carrier counters for one binding.
    #[must_use]
    pub fn carrier_counters(&self, carrier: CarrierBinding) -> CarrierCounters {
        self.carrier_counters[carrier_index(carrier)]
    }

    /// Produces a bounded histogram-based summary.
    pub fn summary(&self) -> Result<ProfileSummary, PolicyError> {
        if self.weighted_observation_units == 0 && self.successful_sessions == 0 {
            return Err(PolicyError::InsufficientData);
        }

        let median_packet_size = quantile_u16(
            &self.packet_size_buckets,
            &PACKET_SIZE_BUCKET_REPRESENTATIVES,
        )
        .ok_or(PolicyError::InsufficientData)?;
        let median_gap_ms = quantile_u32(&self.gap_buckets_ms, &GAP_BUCKET_REPRESENTATIVES_MS)
            .ok_or(PolicyError::InsufficientData)?;
        let median_burst_length = quantile_u16(&self.burst_buckets, &BURST_BUCKET_REPRESENTATIVES)
            .ok_or(PolicyError::InsufficientData)?;

        let dominant_rtt = class_or_fallback_rtt(&self.rtt_class_counts, median_gap_ms);
        let dominant_mtu = class_or_fallback_mtu(&self.mtu_class_counts, median_packet_size);
        let dominant_loss = dominant_loss_class(&self.loss_class_counts);
        let dominant_nat = dominant_nat_class(&self.nat_class_counts);
        let dominant_longevity =
            class_or_fallback_longevity(&self.longevity_counts, self.successful_sessions);
        let dominant_ratio_bucket = dominant_bucket_index(&self.ratio_buckets).unwrap_or(3) as u8;
        let inferred_path = infer_path_class(
            self.weighted_observation_units,
            median_gap_ms,
            median_burst_length,
            dominant_rtt,
            dominant_loss,
            dominant_mtu,
            dominant_nat,
        );
        let preferred_carrier = infer_preferred_carrier(&self.carrier_counters);
        let permissiveness_score = permissiveness_score(
            inferred_path,
            dominant_rtt,
            dominant_loss,
            dominant_mtu,
            dominant_nat,
            dominant_longevity,
        );

        Ok(ProfileSummary {
            median_packet_size,
            median_gap_ms,
            median_burst_length,
            dominant_ratio_bucket,
            dominant_rtt,
            dominant_loss,
            dominant_mtu,
            dominant_nat,
            dominant_longevity,
            successful_sessions: self.successful_sessions,
            weighted_observation_units: self.weighted_observation_units,
            preferred_carrier,
            permissiveness_score,
        })
    }
}

fn allow_observation_units(session_clip: &mut SessionClipState, requested_units: u16) -> u16 {
    let remaining = MAX_SESSION_OBSERVATION_UNITS.saturating_sub(session_clip.observation_units);
    let allowed = remaining.min(requested_units);
    session_clip.observation_units = session_clip.observation_units.saturating_add(allowed);
    allowed
}

fn allow_carrier_event(slots: &mut [u16; 4], carrier: CarrierBinding, max_updates: u16) -> bool {
    let slot = &mut slots[carrier_index(carrier)];
    if *slot >= max_updates {
        return false;
    }
    *slot = slot.saturating_add(1);
    true
}

fn legacy_weight_units(weight: f32) -> u16 {
    if weight >= 0.75 {
        NON_TUNNEL_TRAFFIC_WEIGHT_UNITS
    } else if weight > 0.0 {
        TUNNEL_TRAFFIC_WEIGHT_UNITS
    } else {
        0
    }
}

pub use classify::inferred_path_profile;
