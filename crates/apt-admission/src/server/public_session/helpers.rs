use super::*;

pub(super) fn handshake_prologue(
    endpoint_id: &EndpointId,
    carrier: CarrierBinding,
    public_session_context: Option<&PublicSessionUpgradeContext>,
) -> Result<Vec<u8>, AdmissionError> {
    match public_session_context {
        Some(context) => public_session_associated_data(endpoint_id, context),
        None => Ok(admission_associated_data(endpoint_id, carrier)),
    }
}

pub(super) fn envelope_aad(
    endpoint_id: &EndpointId,
    carrier: CarrierBinding,
    public_session_context: Option<&PublicSessionUpgradeContext>,
    phase: UpgradeMessagePhase,
    epoch_slot: u64,
) -> Result<Vec<u8>, AdmissionError> {
    match public_session_context {
        Some(context) => slot_bound_associated_data(endpoint_id, context, phase, epoch_slot),
        None => Ok(admission_associated_data(endpoint_id, carrier)),
    }
}

pub(super) fn validate_auth_profile(
    auth_profile: AuthProfile,
    identity: &CredentialIdentity,
) -> Result<(), AdmissionError> {
    match (auth_profile, identity) {
        (AuthProfile::SharedDeployment, CredentialIdentity::SharedDeployment)
        | (AuthProfile::PerUser, CredentialIdentity::User(_)) => Ok(()),
        (AuthProfile::SharedDeployment, CredentialIdentity::User(_)) => Err(
            AdmissionError::Validation("shared auth profile used with user credential"),
        ),
        (AuthProfile::PerUser, CredentialIdentity::SharedDeployment) => Err(
            AdmissionError::Validation("per-user auth profile used with shared credential"),
        ),
    }
}

pub(super) fn validate_client_identity(
    identity: &CredentialIdentity,
    claimed_user_identity: Option<&str>,
) -> Result<(), AdmissionError> {
    match (identity, claimed_user_identity) {
        (CredentialIdentity::SharedDeployment, None) => Ok(()),
        (CredentialIdentity::SharedDeployment, Some(_)) => Err(AdmissionError::Validation(
            "shared credential unexpectedly claimed a user identity",
        )),
        (CredentialIdentity::User(expected), Some(claimed)) if expected == claimed => Ok(()),
        (CredentialIdentity::User(_), None) => Err(AdmissionError::Validation(
            "per-user credential omitted the encrypted user identity",
        )),
        (CredentialIdentity::User(_), Some(_)) => Err(AdmissionError::Validation(
            "per-user credential claimed the wrong user identity",
        )),
    }
}
