use super::*;
use apt_types::PacingFamily;

const LONG_IDLE_RESUME_TRIGGER_MS: u64 = 5_000;
const MAX_STREAM_PACKING_TARGET_BYTES: usize = 1_600;
const MIN_STREAM_PACKING_TARGET_BYTES: usize = 640;
const INTERACTIVE_FRAME_BYTES: usize = 384;
const BULK_PADDING_THRESHOLD_BYTES: usize = 1_200;

impl AdaptiveDatapath {
    pub fn fallback_order(&self) -> Vec<CarrierBinding> {
        let mut order = self.persona.scheduler.fallback_order.clone();
        let controller_order = self.controller.fallback_order(self.chosen_carrier);
        for carrier in controller_order.into_iter().rev() {
            if let Some(index) = order.iter().position(|value| *value == carrier) {
                let existing = order.remove(index);
                order.insert(0, existing);
            } else {
                order.insert(0, carrier);
            }
        }
        order
    }

    pub fn standby_health_check_secs(&self) -> u64 {
        u64::from(self.persona.standby_health_check_secs)
    }

    pub fn migration_threshold(&self) -> u8 {
        self.persona.scheduler.migration_threshold
    }

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
        let mode = self.operator_mode.value();
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

    pub fn pacing_delay_ms(
        &self,
        frames: &[Frame],
        batch_count: usize,
        batch_index: usize,
        now_millis: u64,
    ) -> u16 {
        if self.operator_mode == Mode::SPEED
            || !frames.iter().any(|frame| matches!(frame, Frame::IpData(_)))
        {
            return 0;
        }
        let (payload_bytes, ip_frames) = frame_metrics(frames);
        let interactive = payload_bytes <= INTERACTIVE_FRAME_BYTES && ip_frames <= 1;
        let total_cap = if interactive {
            interactive_latency_cap_ms(self.operator_mode.value())
        } else {
            bulk_latency_cap_ms(self.operator_mode.value())
        };
        if total_cap == 0 {
            return 0;
        }
        let in_idle_resume = self.in_idle_resume_window(now_millis);
        let total_delay = match self.persona.scheduler.pacing_family {
            PacingFamily::Opportunistic => {
                if in_idle_resume && self.operator_mode.value() >= 60 {
                    total_cap.saturating_mul(25) / 100
                } else {
                    0
                }
            }
            PacingFamily::Bursty => {
                if batch_count <= 1 && !in_idle_resume {
                    0
                } else if in_idle_resume {
                    total_cap.saturating_mul(35) / 100
                } else {
                    total_cap.saturating_mul(25) / 100
                }
            }
            PacingFamily::Smooth => {
                if in_idle_resume {
                    total_cap.saturating_mul(70) / 100
                } else {
                    total_cap.saturating_mul(55) / 100
                }
            }
        };
        if total_delay == 0 {
            return 0;
        }
        let per_batch = ceil_div_u16(total_delay, u16::try_from(batch_count.max(1)).unwrap_or(1));
        match self.persona.scheduler.pacing_family {
            PacingFamily::Bursty if batch_index == 0 && !in_idle_resume => 0,
            _ if in_idle_resume => per_batch.max(1),
            _ => per_batch,
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
            self.operator_mode,
            self.controller.current_mode,
            self.path_profile,
            self.remembered_profile.clone(),
        );
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
                self.operator_mode.value(),
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
}

pub(super) fn generate_persona(
    chosen_carrier: CarrierBinding,
    persona_seed: [u8; 32],
    mode: Mode,
    policy_mode: PolicyMode,
    path_profile: PathProfile,
    remembered_profile: Option<RememberedProfile>,
) -> PersonaProfile {
    PersonaEngine::generate(&PersonaInputs {
        persona_seed,
        mode,
        path_profile,
        chosen_carrier,
        policy_mode,
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

fn interactive_latency_cap_ms(mode: u8) -> u16 {
    if mode == Mode::MIN {
        0
    } else if mode <= 50 {
        segment_lerp_u16(mode, 0, 0, 50, 3)
    } else {
        segment_lerp_u16(mode, 50, 3, 100, 10)
    }
}

fn bulk_latency_cap_ms(mode: u8) -> u16 {
    if mode == Mode::MIN {
        0
    } else if mode <= 50 {
        segment_lerp_u16(mode, 0, 0, 50, 10)
    } else {
        segment_lerp_u16(mode, 50, 10, 100, 40)
    }
}

fn frame_metrics(frames: &[Frame]) -> (usize, usize) {
    frames
        .iter()
        .fold((0, 0), |(bytes, ip_count), frame| match frame {
            Frame::IpData(packet) => (bytes.saturating_add(packet.len()), ip_count + 1),
            Frame::Padding(bytes_) => (bytes.saturating_add(bytes_.len()), ip_count),
            Frame::CtrlAck { .. } => (bytes.saturating_add(16), ip_count),
            Frame::PathChallenge { .. } | Frame::PathResponse { .. } => {
                (bytes.saturating_add(24), ip_count)
            }
            Frame::SessionUpdate { .. } => (bytes.saturating_add(48), ip_count),
            Frame::Ping => (bytes.saturating_add(8), ip_count),
            Frame::Close { reason, .. } => (bytes.saturating_add(16 + reason.len()), ip_count),
        })
}

fn ceil_div_u16(value: u16, divisor: u16) -> u16 {
    if divisor <= 1 {
        value
    } else {
        (value.saturating_add(divisor - 1)) / divisor
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
