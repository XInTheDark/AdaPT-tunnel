use super::*;
const LONG_IDLE_RESUME_TRIGGER_MS: u64 = 5_000;
const MAX_STREAM_PACKING_TARGET_BYTES: usize = 1_600;
const MIN_STREAM_PACKING_TARGET_BYTES: usize = 640;
const BULK_PADDING_THRESHOLD_BYTES: usize = 1_200;

impl AdaptiveDatapath {
    pub fn burst_cap(&self, binding: CarrierBinding, now_millis: u64) -> usize {
        if !matches!(binding, CarrierBinding::S1EncryptedStream) {
            return 1;
        }
        let mut cap = usize::from(self.persona.scheduler.burst_size_target.max(1));
        if self.in_idle_resume_window(now_millis) {
            cap = cap.min(2);
        }
        if self.path_is_constrained() {
            cap = cap.min(3);
        }
        if self.persona.prefers_fragmentation {
            cap = cap.min(2);
        }
        cap.max(1)
    }

    pub fn soft_packing_target_bytes(&self, binding: CarrierBinding) -> usize {
        if !matches!(binding, CarrierBinding::S1EncryptedStream) {
            return MAX_STREAM_PACKING_TARGET_BYTES;
        }
        let mode = self.behavior_mode().value();
        let mut target = if mode <= 50 {
            segment_lerp_usize(mode, 0, MAX_STREAM_PACKING_TARGET_BYTES, 50, 1_200)
        } else {
            segment_lerp_usize(mode, 50, 1_200, 100, 920)
        };
        if self.path_is_constrained() {
            target = target.saturating_sub(segment_lerp_usize(mode, 0, 0, 100, 180));
        }
        if matches!(self.path_profile.mtu, apt_types::MtuClass::Small) {
            target = target.saturating_sub(segment_lerp_usize(mode, 0, 0, 100, 220));
        }
        if self.persona.prefers_fragmentation {
            target = target.saturating_sub(segment_lerp_usize(mode, 0, 0, 100, 180));
        }
        target.clamp(
            MIN_STREAM_PACKING_TARGET_BYTES,
            MAX_STREAM_PACKING_TARGET_BYTES,
        )
    }

    pub fn maybe_padding_frame(
        &self,
        payload_bytes: usize,
        keepalive_only: bool,
        now_millis: u64,
    ) -> Option<Frame> {
        if keepalive_only && !matches!(self.keepalive_mode(), KeepaliveMode::SparseCover) {
            return None;
        }
        if !keepalive_only && payload_bytes > BULK_PADDING_THRESHOLD_BYTES {
            return None;
        }
        let padding_budget_bps = self.padding_budget_bps(keepalive_only, now_millis);
        if padding_budget_bps == 0 {
            return None;
        }
        let max_padding = payload_bytes.saturating_mul(usize::from(padding_budget_bps)) / 10_000;
        let target_padding = self
            .persona
            .scheduler
            .packet_size_bins
            .iter()
            .find(|(_, upper)| usize::from(*upper) > payload_bytes)
            .map(|(lower, upper)| {
                let midpoint = (usize::from(*lower) + usize::from(*upper)) / 2;
                midpoint.saturating_sub(payload_bytes)
            })
            .unwrap_or_default();
        let minimum_cover = if keepalive_only { 24 } else { 0 };
        let padding_len = target_padding.min(max_padding).max(minimum_cover);
        (padding_len >= 8).then(|| Frame::Padding(vec![0_u8; padding_len]))
    }

    pub fn begin_outbound_data_send(&mut self, now_millis: u64) {
        let ramp_ms = u64::from(self.persona.idle_resume_ramp_ms);
        if ramp_ms == 0 {
            self.idle_resume_until_millis = None;
            return;
        }
        if self.in_idle_resume_window(now_millis) {
            return;
        }
        let last_activity = self.last_send_millis.max(self.last_recv_millis);
        if last_activity
            .is_some_and(|last| now_millis.saturating_sub(last) >= LONG_IDLE_RESUME_TRIGGER_MS)
        {
            self.idle_resume_until_millis = Some(now_millis.saturating_add(ramp_ms));
        } else {
            self.idle_resume_until_millis = None;
        }
    }

    pub(super) fn regenerate_persona(&mut self) {
        self.path_profile = self
            .local_normality
            .as_ref()
            .and_then(super::normality::infer_path_profile)
            .unwrap_or(self.path_profile);
        self.persona = generate_persona(
            self.chosen_carrier,
            self.persona_seed,
            self.controller.current_mode,
            self.path_profile,
            self.remembered_profile.clone(),
        );
        self.keepalive.set_mode(self.controller.current_mode);
    }

    fn in_idle_resume_window(&self, now_millis: u64) -> bool {
        self.idle_resume_until_millis
            .is_some_and(|until| now_millis < until)
    }

    fn path_is_constrained(&self) -> bool {
        matches!(
            self.path_profile.path,
            PathClass::Constrained | PathClass::Hostile
        ) || matches!(self.path_profile.mtu, apt_types::MtuClass::Small)
    }

    fn padding_budget_bps(&self, keepalive_only: bool, now_millis: u64) -> u16 {
        if keepalive_only {
            return if matches!(self.keepalive_mode(), KeepaliveMode::SparseCover) {
                self.persona.scheduler.padding_budget_bps.max(200)
            } else {
                0
            };
        }
        let steady = self.persona.scheduler.padding_budget_bps;
        if steady == 0 {
            return 0;
        }
        if self.in_idle_resume_window(now_millis) || !self.profile_is_bootstrapped() {
            steady.max(probation_padding_budget_bps(
                self.behavior_mode().value(),
                steady,
            ))
        } else {
            steady
        }
    }

    fn profile_is_bootstrapped(&self) -> bool {
        self.local_normality
            .as_ref()
            .is_none_or(LocalNormalityProfile::is_bootstrapped)
    }

    fn behavior_mode(&self) -> Mode {
        self.controller.current_mode
    }
}

pub(super) fn generate_persona(
    chosen_carrier: CarrierBinding,
    persona_seed: [u8; 32],
    mode: Mode,
    path_profile: PathProfile,
    remembered_profile: Option<RememberedProfile>,
) -> PersonaProfile {
    PersonaEngine::generate(&PersonaInputs {
        persona_seed,
        mode,
        path_profile,
        chosen_carrier,
        remembered_profile,
    })
}

fn probation_padding_budget_bps(mode: u8, steady_budget_bps: u16) -> u16 {
    if mode <= 50 {
        steady_budget_bps
    } else {
        segment_lerp_u16(mode, 50, steady_budget_bps.max(200), 100, 2_000)
    }
}

fn segment_lerp_u16(
    mode: u8,
    start_mode: u8,
    start_value: u16,
    end_mode: u8,
    end_value: u16,
) -> u16 {
    if mode <= start_mode {
        return start_value;
    }
    if mode >= end_mode {
        return end_value;
    }
    let span = u32::from(end_mode.saturating_sub(start_mode)).max(1);
    let progress = u32::from(mode.saturating_sub(start_mode));
    let start = u32::from(start_value);
    let end = u32::from(end_value);
    if end >= start {
        (start + ((end - start) * progress + (span / 2)) / span) as u16
    } else {
        (start - ((start - end) * progress + (span / 2)) / span) as u16
    }
}

fn segment_lerp_usize(
    mode: u8,
    start_mode: u8,
    start_value: usize,
    end_mode: u8,
    end_value: usize,
) -> usize {
    if mode <= start_mode {
        return start_value;
    }
    if mode >= end_mode {
        return end_value;
    }
    let span = usize::from(end_mode.saturating_sub(start_mode)).max(1);
    let progress = usize::from(mode.saturating_sub(start_mode));
    if end_value >= start_value {
        start_value + ((end_value - start_value) * progress + (span / 2)) / span
    } else {
        start_value - ((start_value - end_value) * progress + (span / 2)) / span
    }
}
