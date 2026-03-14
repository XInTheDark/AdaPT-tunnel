use crate::TunnelError;
use std::collections::BTreeSet;

#[derive(Clone, Debug)]
pub(crate) struct ReplayWindow {
    largest_seen: Option<u64>,
    seen: BTreeSet<u64>,
    window_size: u64,
}

impl ReplayWindow {
    pub(crate) fn new(window_size: u64) -> Self {
        Self {
            largest_seen: None,
            seen: BTreeSet::new(),
            window_size,
        }
    }

    pub(crate) fn check_and_insert(&mut self, packet_number: u64) -> Result<(), TunnelError> {
        if let Some(largest) = self.largest_seen {
            if packet_number + self.window_size < largest {
                return Err(TunnelError::Replay);
            }
            if self.seen.contains(&packet_number) {
                return Err(TunnelError::Replay);
            }
            if packet_number > largest {
                self.largest_seen = Some(packet_number);
            }
        } else {
            self.largest_seen = Some(packet_number);
        }
        self.seen.insert(packet_number);
        if let Some(largest) = self.largest_seen {
            let floor = largest.saturating_sub(self.window_size);
            while let Some(oldest) = self.seen.iter().next().copied() {
                if oldest >= floor {
                    break;
                }
                self.seen.remove(&oldest);
            }
        }
        Ok(())
    }
}
