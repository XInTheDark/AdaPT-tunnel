use super::*;

impl AdaptiveDatapath {
    pub fn note_successful_session(&mut self) {
        if let Some(profile) = &mut self.local_normality {
            profile.note_successful_session();
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
        self.record_observation(
            payload_bytes,
            burst_len,
            gap_ms.clamp(0, 60_000) as u32,
            true,
        );
        self.last_send_millis = Some(now_millis);
    }

    pub fn record_inbound(&mut self, payload_bytes: usize, now_millis: u64) {
        let gap_ms = now_millis.saturating_sub(self.last_recv_millis.unwrap_or(now_millis));
        self.record_observation(payload_bytes, 1, gap_ms.clamp(0, 60_000) as u32, true);
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
        last_recv_secs: u64,
    ) -> Option<PolicyMode> {
        if now_secs.saturating_sub(last_recv_secs) < QUIET_IMPAIRMENT_THRESHOLD_SECS {
            return None;
        }
        self.apply_signal(PathSignalEvent::RttInflation, now_secs)
    }

    pub fn apply_signal(&mut self, signal: PathSignalEvent, now_secs: u64) -> Option<PolicyMode> {
        if let Some(profile) = &self.local_normality {
            self.controller.allow_speed_first =
                self.allow_speed_first_by_policy && profile.is_bootstrapped();
        } else {
            self.controller.allow_speed_first = self.allow_speed_first_by_policy;
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
        tunnel_traffic: bool,
    ) {
        let Some(profile) = &mut self.local_normality else {
            return;
        };
        profile.record_observation(&NetworkMetadataObservation {
            packet_size: payload_bytes.clamp(64, 4_096) as u16,
            inter_send_gap_ms: gap_ms.clamp(0, 60_000),
            burst_length: burst_len.clamp(1, 256) as u16,
            upstream_downstream_ratio_class: 2,
            path_profile: self.path_profile,
            longevity: if profile.successful_sessions > 0 {
                ConnectionLongevityClass::Moderate
            } else {
                ConnectionLongevityClass::Ephemeral
            },
            tunnel_traffic,
        });
        self.observations_since_path_refresh =
            self.observations_since_path_refresh.saturating_add(1);
        if self.observations_since_path_refresh >= PROFILE_REFRESH_EVERY_OBSERVATIONS {
            self.path_profile = infer_path_profile(profile).unwrap_or(self.path_profile);
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
    let path = if summary.weighted_observations >= 200.0 && summary.median_gap_ms <= 30 {
        PathClass::Stable
    } else if summary.median_gap_ms <= 80 {
        PathClass::Variable
    } else {
        PathClass::Constrained
    };
    let mtu = if summary.median_packet_size >= 1_200 {
        MtuClass::Large
    } else if summary.median_packet_size >= 800 {
        MtuClass::Medium
    } else {
        MtuClass::Small
    };
    let rtt = if summary.median_gap_ms <= 20 {
        RttClass::Low
    } else if summary.median_gap_ms <= 75 {
        RttClass::Moderate
    } else {
        RttClass::High
    };
    Some(PathProfile {
        path,
        mtu,
        rtt,
        loss: LossClass::Unknown,
        nat: NatClass::Unknown,
    })
}
