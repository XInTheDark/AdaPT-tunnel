use crate::error::RuntimeError;
use apt_crypto::{derive_admission_key, derive_runtime_key, SessionSecretsForRole};

const D1_ADMISSION_OUTER_LABEL: &[u8] = b"d1 admission outer";
const D1_CONFIRMATION_OUTER_LABEL: &[u8] = b"d1 confirmation outer";
const D1_TUNNEL_OUTER_LABEL: &[u8] = b"d1 tunnel outer";
const D2_ADMISSION_OUTER_LABEL: &[u8] = b"d2 admission outer";
const D2_CONFIRMATION_OUTER_LABEL: &[u8] = b"d2 confirmation outer";
const D2_TUNNEL_OUTER_LABEL: &[u8] = b"d2 tunnel outer";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct D1OuterKeys {
    pub send: [u8; 32],
    pub recv: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct D2OuterKeys {
    pub send: [u8; 32],
    pub recv: [u8; 32],
}

pub fn derive_d1_admission_outer_key(
    admission_key: &[u8; 32],
    epoch_slot: u64,
) -> Result<[u8; 32], RuntimeError> {
    let per_epoch = derive_admission_key(admission_key, epoch_slot);
    Ok(derive_runtime_key(&per_epoch, D1_ADMISSION_OUTER_LABEL)?)
}

pub fn derive_d1_confirmation_outer_key(ctrl_key: &[u8; 32]) -> Result<[u8; 32], RuntimeError> {
    Ok(derive_runtime_key(ctrl_key, D1_CONFIRMATION_OUTER_LABEL)?)
}

pub fn derive_d2_admission_outer_key(
    admission_key: &[u8; 32],
    epoch_slot: u64,
) -> Result<[u8; 32], RuntimeError> {
    let per_epoch = derive_admission_key(admission_key, epoch_slot);
    Ok(derive_runtime_key(&per_epoch, D2_ADMISSION_OUTER_LABEL)?)
}

pub fn derive_d2_confirmation_outer_key(ctrl_key: &[u8; 32]) -> Result<[u8; 32], RuntimeError> {
    Ok(derive_runtime_key(ctrl_key, D2_CONFIRMATION_OUTER_LABEL)?)
}

pub fn derive_d1_tunnel_outer_keys(
    secrets: &SessionSecretsForRole,
) -> Result<D1OuterKeys, RuntimeError> {
    Ok(D1OuterKeys {
        send: derive_runtime_key(&secrets.send_data, D1_TUNNEL_OUTER_LABEL)?,
        recv: derive_runtime_key(&secrets.recv_data, D1_TUNNEL_OUTER_LABEL)?,
    })
}

pub fn derive_d2_tunnel_outer_keys(
    secrets: &SessionSecretsForRole,
) -> Result<D2OuterKeys, RuntimeError> {
    Ok(D2OuterKeys {
        send: derive_runtime_key(&secrets.send_data, D2_TUNNEL_OUTER_LABEL)?,
        recv: derive_runtime_key(&secrets.recv_data, D2_TUNNEL_OUTER_LABEL)?,
    })
}
