use super::*;
use crate::config::PersistedIdleOutcomeSummary;

impl AdaptiveDatapath {
    pub fn note_successful_session(&mut self) {
        if let Some(profile) = &mut self.local_normality {
            profile.note_successful_session();
            profile.note_carrier_success(self.chosen_carrier);
            self.controller.allow_speed_first =
                self.allow_speed_first_by_policy && profile.is_bootstrapped();
            self.path_profile = infer_path_profile(profile).unwrap_or(self.path_profile);
        } else {
            self.controller.allow_speed_first = self.allow_speed_first_by_policy;
        }
        self.refresh_remembered_profile();
    }

    pub fn record_outbound(&mut self, payload_bytes: usize, burst_len: usize, now_millis: u64) {
        let gap_ms = now_millis.saturating_sub(self.last_send_millis.unwrap_or(now_millis));
        self.session_outbound_bytes = self
            .session_outbound_bytes
            .saturating_add(payload_bytes as u64);
        self.record_observation(
            payload_bytes,
            burst_len,
            gap_ms.clamp(0, 60_000) as u32,
            now_millis,
            true,
        );
        self.last_send_millis = Some(now_millis);
    }

    pub fn record_inbound(&mut self, payload_bytes: usize, now_millis: u64) {
        let gap_ms = now_millis.saturating_sub(self.last_recv_millis.unwrap_or(now_millis));
        self.session_inbound_bytes = self
            .session_inbound_bytes
            .saturating_add(payload_bytes as u64);
        self.record_observation(
            payload_bytes,
            1,
            gap_ms.clamp(0, 60_000) as u32,
            now_millis,
            true,
        );
        self.last_recv_millis = Some(now_millis);
    }

    pub fn maybe_observe_stability(&mut self, now_secs: u64) -> Option<PolicyMode> {
        if now_secs.saturating_sub(self.last_policy_observation_secs)
            < POLICY_OBSERVATION_INTERVAL_SECS
        {
            return None;
        }
        self.last_policy_observation_secs = now_secs;
        self.apply_signal(PathSignalEvent::StableDelivery, now_secs)
    }

    pub fn maybe_observe_quiet_impairment(
        &mut self,
        now_secs: u64,
        _last_send_secs: u64,
        _last_recv_secs: u64,
    ) -> Option<PolicyMode> {
        if !self.keepalive.should_treat_as_idle_impairment(now_secs) {
            return None;
        }
        if let Some(profile) = &mut self.local_normality {
            profile.note_carrier_idle_timeout(self.chosen_carrier);
        }
        self.note_idle_impairment(now_secs);
        self.apply_signal(PathSignalEvent::RttInflation, now_secs)
    }

    pub fn apply_signal(&mut self, signal: PathSignalEvent, now_secs: u64) -> Option<PolicyMode> {
        if let Some(profile) = &mut self.local_normality {
            match signal {
                PathSignalEvent::HandshakeBlackhole
                | PathSignalEvent::ImmediateReset
                | PathSignalEvent::SizeSpecificLoss
                | PathSignalEvent::MtuBlackhole
                | PathSignalEvent::FallbackFailure => {
                    profile.note_carrier_failure(self.chosen_carrier);
                }
                PathSignalEvent::NatRebinding => {
                    profile.note_carrier_rebinding(self.chosen_carrier);
                }
                PathSignalEvent::RttInflation | PathSignalEvent::StableDelivery => {}
            }
            self.controller.allow_speed_first =
                self.allow_speed_first_by_policy && profile.is_bootstrapped();
        } else {
            self.controller.allow_speed_first = self.allow_speed_first_by_policy;
        }
        match signal {
            PathSignalEvent::ImmediateReset => {
                self.keepalive.note_idle_impairment(
                    now_secs,
                    self.persona.scheduler.keepalive_mode,
                    PersistedIdleOutcomeSummary::Impaired,
                );
            }
            PathSignalEvent::NatRebinding => {
                self.keepalive.note_idle_impairment(
                    now_secs,
                    self.persona.scheduler.keepalive_mode,
                    PersistedIdleOutcomeSummary::Rebinding,
                );
            }
            PathSignalEvent::HandshakeBlackhole
            | PathSignalEvent::SizeSpecificLoss
            | PathSignalEvent::MtuBlackhole
            | PathSignalEvent::FallbackFailure
            | PathSignalEvent::RttInflation
            | PathSignalEvent::StableDelivery => {}
        }
        let previous = self.controller.current_mode;
        let current = self.controller.observe_signal(signal);
        if current != previous {
            self.regenerate_persona();
            self.refresh_remembered_profile();
            self.reschedule_keepalive(now_secs);
            Some(current)
        } else {
            None
        }
    }

    pub(super) fn refresh_remembered_profile(&mut self) {
        if let Some(profile) = &self.local_normality {
            if let Ok(summary) = profile.summary() {
                self.remembered_profile = Some(RememberedProfile {
                    preferred_carrier: summary.preferred_carrier.unwrap_or(self.chosen_carrier),
                    permissiveness_score: summary.permissiveness_score,
                });
                return;
            }
        }
        let permissiveness_score = match self.controller.current_mode {
            PolicyMode::StealthFirst => 48,
            PolicyMode::Balanced => 144,
            PolicyMode::SpeedFirst => 224,
        };
        self.remembered_profile = Some(RememberedProfile {
            preferred_carrier: self.chosen_carrier,
            permissiveness_score,
        });
    }

    fn record_observation(
        &mut self,
        payload_bytes: usize,
        burst_len: usize,
        gap_ms: u32,
        now_millis: u64,
        tunnel_traffic: bool,
    ) {
        let Some(profile) = &mut self.local_normality else {
            return;
        };
        profile.record_observation(&NetworkMetadataObservation {
            packet_size: payload_bytes.clamp(64, 4_096) as u16,
            inter_send_gap_ms: gap_ms.clamp(0, 60_000),
            burst_length: burst_len.clamp(1, 256) as u16,
            upstream_downstream_ratio_class: current_ratio_class(
                self.session_outbound_bytes,
                self.session_inbound_bytes,
            ),
            path_profile: self.path_profile,
            longevity: current_longevity_class(self.session_started_millis, now_millis),
            tunnel_traffic,
        });
        self.observations_since_path_refresh =
            self.observations_since_path_refresh.saturating_add(1);
        if self.observations_since_path_refresh >= PROFILE_REFRESH_EVERY_OBSERVATIONS {
            self.path_profile = infer_path_profile(profile).unwrap_or(self.path_profile);
            self.refresh_remembered_profile();
            self.observations_since_path_refresh = 0;
        }
    }
}

#[must_use]
pub fn admission_path_profile(stored_profile: Option<&LocalNormalityProfile>) -> PathProfile {
    stored_profile
        .and_then(infer_path_profile)
        .unwrap_or_else(PathProfile::unknown)
}

pub(super) fn infer_path_profile(profile: &LocalNormalityProfile) -> Option<PathProfile> {
    let summary = profile.summary().ok()?;
    let inferred = inferred_path_profile(&summary);
    (!matches!(inferred.path, PathClass::Unknown)).then_some(inferred)
}

fn current_ratio_class(outbound_bytes: u64, inbound_bytes: u64) -> u8 {
    let outbound = outbound_bytes.max(1);
    let inbound = inbound_bytes.max(1);
    let ratio_times_100 = outbound.saturating_mul(100) / inbound;
    match ratio_times_100 {
        0..=24 => 0,
        25..=49 => 1,
        50..=74 => 2,
        75..=133 => 3,
        134..=199 => 4,
        200..=399 => 5,
        _ => 6,
    }
}

fn current_longevity_class(
    session_started_millis: u64,
    now_millis: u64,
) -> ConnectionLongevityClass {
    let elapsed_secs = now_millis
        .saturating_sub(session_started_millis)
        .saturating_div(1_000);
    match elapsed_secs {
        0..=29 => ConnectionLongevityClass::Ephemeral,
        30..=299 => ConnectionLongevityClass::Moderate,
        _ => ConnectionLongevityClass::LongLived,
    }
}
