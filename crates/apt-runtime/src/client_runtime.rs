use apt_client_control::ClientRuntimeEvent;
use tokio::sync::{mpsc, watch};

#[derive(Clone, Debug, Default)]
pub struct ClientRuntimeHooks {
    pub shutdown_rx: Option<watch::Receiver<bool>>,
    pub event_tx: Option<mpsc::UnboundedSender<ClientRuntimeEvent>>,
}

impl ClientRuntimeHooks {
    pub fn emit(&self, event: ClientRuntimeEvent) {
        if let Some(sender) = self.event_tx.as_ref() {
            let _ = sender.send(event);
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientRuntimeStats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}
