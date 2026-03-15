use super::*;
use crate::config::{PersistedIdleOutcomeSummary, PersistedKeepaliveLearningState};
use apt_types::KeepaliveTuning;
use sha2::{Digest, Sha256};

const KEEPALIVE_ACTIVE_SUPPRESSION_SECS: u64 = 5;
const SPARSE_COVER_MIN_MODE: u8 = 70;
const KEEPALIVE_COUNTER_MAX: u16 = 255;
const KEEPALIVE_INTERVAL_FAILURE_GRACE_SECS: u64 = 5;

#[derive(Clone, Copy, Debug)]
struct PendingIdleProbe {
    sent_at_secs: u64,
    probe_target_interval_secs: u64,
}

#[derive(Clone, Debug)]
pub(super) struct AdaptiveKeepaliveController {
    persona_seed: [u8; 32],
    operator_mode: Mode,
    base_interval_secs: u64,
    min_interval_secs: u64,
    max_interval_secs: u64,
    learning: PersistedKeepaliveLearningState,
    sample_index: u64,
    scheduled_interval_secs: u64,
    next_due_secs: u64,
    last_non_keepalive_activity_secs: u64,
    pending_idle_probe: Option<PendingIdleProbe>,
}

impl AdaptiveKeepaliveController {
    pub(super) fn new(
        persona_seed: [u8; 32],
        operator_mode: Mode,
        base_interval_secs: u64,
        persisted: Option<PersistedKeepaliveLearningState>,
        now_secs: u64,
    ) -> Self {
        let tuning = KeepaliveTuning::default();
        let min_interval_secs = u64::from(tuning.min_interval_secs);
        let max_interval_secs = u64::from(tuning.max_interval_secs.max(tuning.min_interval_secs));
        let base_interval_secs = base_interval_secs
            .max(min_interval_secs)
            .min(max_interval_secs);
        let mut learning = persisted.unwrap_or_default();
        learning.current_target_interval_secs = if learning.current_target_interval_secs == 0 {
            base_interval_secs
        } else {
            learning
                .current_target_interval_secs
                .clamp(min_interval_secs, max_interval_secs)
        };
        Self {
            persona_seed,
            operator_mode,
            base_interval_secs,
            min_interval_secs,
            max_interval_secs,
            learning,
            sample_index: 0,
            scheduled_interval_secs: base_interval_secs,
            next_due_secs: now_secs,
            last_non_keepalive_activity_secs: now_secs,
            pending_idle_probe: None,
        }
    }

    pub(super) fn effective_mode(&self, persona_mode: KeepaliveMode) -> KeepaliveMode {
        if self.operator_mode == Mode::SPEED {
            KeepaliveMode::SuppressWhenActive
        } else if self.operator_mode.value() >= SPARSE_COVER_MIN_MODE
            && matches!(persona_mode, KeepaliveMode::SparseCover)
        {
            KeepaliveMode::SparseCover
        } else {
            KeepaliveMode::Adaptive
        }
    }

    pub(super) fn due(&self, now_secs: u64, persona_mode: KeepaliveMode) -> bool {
        if now_secs < self.next_due_secs {
            return false;
        }
        !matches!(
            self.effective_mode(persona_mode),
            KeepaliveMode::SuppressWhenActive
        ) || now_secs.saturating_sub(self.last_non_keepalive_activity_secs)
            >= KEEPALIVE_ACTIVE_SUPPRESSION_SECS
    }

    pub(super) fn note_activity(&mut self, now_secs: u64, persona_mode: KeepaliveMode) {
        self.last_non_keepalive_activity_secs = now_secs;
        self.pending_idle_probe = None;
        self.reschedule(now_secs, persona_mode);
    }

    pub(super) fn note_keepalive_sent(&mut self, now_secs: u64, persona_mode: KeepaliveMode) {
        if self.pending_probe_survived(now_secs) {
            self.note_idle_success();
        }
        self.pending_idle_probe = Some(PendingIdleProbe {
            sent_at_secs: now_secs,
            probe_target_interval_secs: self.effective_target_interval_secs(persona_mode),
        });
        self.reschedule(now_secs, persona_mode);
    }

    pub(super) fn note_idle_impairment(
        &mut self,
        now_secs: u64,
        persona_mode: KeepaliveMode,
        outcome: PersistedIdleOutcomeSummary,
    ) {
        if self.pending_idle_probe.take().is_none() {
            return;
        }
        self.note_idle_failure(outcome);
        self.reschedule(now_secs, persona_mode);
    }

    pub(super) fn should_treat_as_idle_impairment(&self, now_secs: u64) -> bool {
        let Some(pending) = self.pending_idle_probe else {
            return false;
        };
        let quiet_threshold_secs = QUIET_IMPAIRMENT_THRESHOLD_SECS.max(
            pending
                .probe_target_interval_secs
                .saturating_add(KEEPALIVE_INTERVAL_FAILURE_GRACE_SECS),
        );
        now_secs.saturating_sub(self.last_non_keepalive_activity_secs) >= quiet_threshold_secs
    }

    pub(super) fn learning_state(&self) -> PersistedKeepaliveLearningState {
        self.learning.clone()
    }

    pub(super) fn target_interval_secs(&self) -> u64 {
        self.learning
            .current_target_interval_secs
            .clamp(self.min_interval_secs, self.max_interval_secs)
    }

    pub(super) fn reschedule(&mut self, now_secs: u64, persona_mode: KeepaliveMode) {
        let interval = match self.effective_mode(persona_mode) {
            KeepaliveMode::SuppressWhenActive => self.base_interval_secs,
            KeepaliveMode::Adaptive | KeepaliveMode::SparseCover => {
                let target = self.effective_target_interval_secs(persona_mode);
                let (low_percent, high_percent) = self.jitter_bounds_percent(persona_mode);
                let jittered = target
                    .saturating_mul(u64::from(self.sample_percent(low_percent, high_percent)))
                    / 100;
                jittered.clamp(self.min_interval_secs, self.max_interval_secs)
            }
        };
        self.scheduled_interval_secs = interval.max(1);
        self.next_due_secs = now_secs.saturating_add(self.scheduled_interval_secs);
    }

    fn effective_target_interval_secs(&self, persona_mode: KeepaliveMode) -> u64 {
        let effective_mode = self.effective_mode(persona_mode);
        if matches!(effective_mode, KeepaliveMode::SuppressWhenActive) {
            return self.base_interval_secs;
        }
        interpolate_interval(
            self.base_interval_secs,
            self.target_interval_secs(),
            self.operator_mode.value(),
        )
        .clamp(self.min_interval_secs, self.max_interval_secs)
    }

    fn pending_probe_survived(&self, now_secs: u64) -> bool {
        self.pending_idle_probe.is_some_and(|probe| {
            now_secs.saturating_sub(probe.sent_at_secs) >= probe.probe_target_interval_secs
        })
    }

    fn note_idle_success(&mut self) {
        let current = self.target_interval_secs();
        let increased = current
            .saturating_add(percent_ceil(current, 10))
            .clamp(self.min_interval_secs, self.max_interval_secs);
        self.learning.current_target_interval_secs = increased;
        self.learning.last_idle_outcome = PersistedIdleOutcomeSummary::IdleSurvived;
        self.learning.success_counter = self
            .learning
            .success_counter
            .saturating_add(1)
            .min(KEEPALIVE_COUNTER_MAX);
        self.learning.failure_counter = self.learning.failure_counter.saturating_sub(1);
    }

    fn note_idle_failure(&mut self, outcome: PersistedIdleOutcomeSummary) {
        let current = self.target_interval_secs();
        let decrease_secs = percent_ceil(current, 30).max(5);
        let decreased = current
            .saturating_sub(decrease_secs)
            .clamp(self.min_interval_secs, self.max_interval_secs);
        self.learning.current_target_interval_secs = decreased;
        self.learning.last_idle_outcome = outcome;
        self.learning.failure_counter = self
            .learning
            .failure_counter
            .saturating_add(1)
            .min(KEEPALIVE_COUNTER_MAX);
        self.learning.success_counter = self.learning.success_counter.saturating_sub(1);
    }

    fn jitter_bounds_percent(&self, persona_mode: KeepaliveMode) -> (u16, u16) {
        match self.effective_mode(persona_mode) {
            KeepaliveMode::SuppressWhenActive => (100, 100),
            KeepaliveMode::Adaptive => {
                let spread = scaled_percent_cap(self.operator_mode.value(), 15);
                (
                    100_u16.saturating_sub(spread),
                    100_u16.saturating_add(spread),
                )
            }
            KeepaliveMode::SparseCover => {
                let low_spread = scaled_percent_cap(self.operator_mode.value(), 20);
                let high_spread = scaled_percent_cap(self.operator_mode.value(), 10);
                (
                    100_u16.saturating_sub(low_spread),
                    100_u16.saturating_add(high_spread),
                )
            }
        }
    }

    fn sample_percent(&mut self, low: u16, high: u16) -> u16 {
        if low >= high {
            return low;
        }
        let mut hasher = Sha256::new();
        hasher.update(self.persona_seed);
        hasher.update(self.sample_index.to_be_bytes());
        let digest = hasher.finalize();
        self.sample_index = self.sample_index.saturating_add(1);
        let sample = u16::from_be_bytes([digest[0], digest[1]]);
        let width = high.saturating_sub(low).saturating_add(1);
        low.saturating_add(sample % width)
    }
}

fn percent_ceil(value: u64, percent: u64) -> u64 {
    value
        .saturating_mul(percent)
        .saturating_add(99)
        .saturating_div(100)
}

fn scaled_percent_cap(mode: u8, max_percent: u16) -> u16 {
    (u16::from(mode)
        .saturating_mul(max_percent)
        .saturating_add(u16::from(Mode::MAX) - 1))
        / u16::from(Mode::MAX)
}

fn interpolate_interval(base_interval_secs: u64, target_interval_secs: u64, mode: u8) -> u64 {
    if base_interval_secs == target_interval_secs || mode == Mode::MIN {
        return base_interval_secs;
    }
    let delta = target_interval_secs as i64 - base_interval_secs as i64;
    let scaled_delta = delta.saturating_mul(i64::from(mode)) / i64::from(Mode::MAX);
    (base_interval_secs as i64)
        .saturating_add(scaled_delta)
        .max(1) as u64
}

impl AdaptiveDatapath {
    pub fn keepalive_due(&self, now_secs: u64) -> bool {
        self.keepalive
            .due(now_secs, self.persona.scheduler.keepalive_mode)
    }

    pub fn build_keepalive_frames(&mut self, payload_hint: usize, now_millis: u64) -> Vec<Frame> {
        let mut frames = vec![Frame::Ping];
        if let Some(padding) = self.maybe_padding_frame(payload_hint.max(64), true, now_millis) {
            frames.push(padding);
        }
        frames
    }

    pub fn note_activity(&mut self, now_secs: u64) {
        self.keepalive
            .note_activity(now_secs, self.persona.scheduler.keepalive_mode);
    }

    pub fn note_keepalive_sent(&mut self, now_secs: u64) {
        self.keepalive
            .note_keepalive_sent(now_secs, self.persona.scheduler.keepalive_mode);
    }

    pub(super) fn note_idle_impairment(&mut self, now_secs: u64) {
        self.keepalive.note_idle_impairment(
            now_secs,
            self.persona.scheduler.keepalive_mode,
            PersistedIdleOutcomeSummary::QuietTimeout,
        );
    }

    pub(super) fn reschedule_keepalive(&mut self, now_secs: u64) {
        self.keepalive
            .reschedule(now_secs, self.persona.scheduler.keepalive_mode);
    }
}
