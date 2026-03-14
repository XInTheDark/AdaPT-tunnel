use apt_crypto::TunnelAead;

/// Rekey limit state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RekeyStatus {
    /// Limits have not yet been crossed.
    Healthy,
    /// Soft limit reached: initiate rekey soon.
    SoftLimitReached,
    /// Hard limit reached: close the session rather than continue.
    HardLimitReached,
}

#[derive(Clone, Debug)]
pub(crate) struct PendingSendRekey {
    pub(crate) control_id: u64,
    pub(crate) next_phase: u8,
    pub(crate) next_send_data: [u8; 32],
    pub(crate) next_send_ctrl: [u8; 32],
    pub(crate) next_send_data_aead: TunnelAead,
    pub(crate) next_send_ctrl_aead: TunnelAead,
    pub(crate) next_rekey: [u8; 32],
}

#[derive(Clone, Debug)]
pub(crate) struct StagedRecvRekey {
    pub(crate) next_phase: u8,
    pub(crate) next_recv_data: [u8; 32],
    pub(crate) next_recv_ctrl: [u8; 32],
    pub(crate) next_recv_data_aead: TunnelAead,
    pub(crate) next_recv_ctrl_aead: TunnelAead,
    pub(crate) next_rekey: [u8; 32],
}
