use super::*;

impl AdaptiveDatapath {
    pub fn keepalive_due(&self, now_secs: u64, last_send_secs: u64) -> bool {
        if now_secs < self.next_keepalive_due_secs {
            return false;
        }
        !matches!(
            self.persona.scheduler.keepalive_mode,
            KeepaliveMode::SuppressWhenActive
        ) || now_secs.saturating_sub(last_send_secs) >= 5
    }

    pub fn build_keepalive_frames(&mut self, payload_hint: usize, now_secs: u64) -> Vec<Frame> {
        let mut frames = vec![Frame::Ping];
        if let Some(padding) = self.maybe_padding_frame(payload_hint.max(64), true) {
            frames.push(padding);
        }
        self.reschedule_keepalive(now_secs);
        frames
    }

    pub fn note_activity(&mut self, now_secs: u64) {
        self.next_keepalive_due_secs = now_secs.saturating_add(self.keepalive_interval_secs);
    }

    pub(super) fn reschedule_keepalive(&mut self, now_secs: u64) {
        let interval = PersonaEngine::sample_keepalive_interval(
            &PersonaInputs {
                persona_seed: self.persona_seed,
                path_profile: self.path_profile,
                chosen_carrier: self.chosen_carrier,
                policy_mode: self.controller.current_mode,
                remembered_profile: self.remembered_profile.clone(),
            },
            None,
            self.keepalive_sample_index,
        );
        self.keepalive_sample_index = self.keepalive_sample_index.saturating_add(1);
        self.keepalive_interval_secs = interval;
        self.next_keepalive_due_secs = now_secs.saturating_add(interval);
    }
}
