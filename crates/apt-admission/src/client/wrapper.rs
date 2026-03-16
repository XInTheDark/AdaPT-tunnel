use super::*;

/// Result of initiating the first hidden-upgrade request.
#[derive(Debug)]
pub struct PreparedC0 {
    /// Encrypted first-stage packet wrapper.
    pub packet: AdmissionPacket,
    /// State required to process the server's first hidden-upgrade reply.
    pub state: ClientPendingS1,
}

/// Result of processing the first server reply and emitting the client confirmation.
#[derive(Debug)]
pub struct PreparedC2 {
    /// Encrypted client confirmation packet wrapper.
    pub packet: AdmissionPacket,
    /// State required to process the final server seal.
    pub state: ClientPendingS3,
}

/// Initiates an admission attempt and emits the first hidden-upgrade request.
pub fn initiate_c0<C: CarrierProfile>(
    credential: ClientCredential,
    request: ClientSessionRequest,
    carrier: &C,
) -> Result<PreparedC0, AdmissionError> {
    let prepared = initiate_ug1(credential, request, carrier)?;
    Ok(PreparedC0 {
        packet: AdmissionPacket {
            lookup_hint: prepared.lookup_hint,
            envelope: prepared.envelope,
        },
        state: prepared.state,
    })
}

impl ClientPendingS1 {
    /// Handles the first server reply, produces the client confirmation, and
    /// returns state waiting for the final server seal.
    pub fn handle_s1<C: CarrierProfile>(
        self,
        packet: &AdmissionPacket,
        carrier: &C,
    ) -> Result<PreparedC2, AdmissionError> {
        self.handle_ug2(&packet.envelope, carrier)
            .map(|prepared| PreparedC2 {
                packet: AdmissionPacket {
                    lookup_hint: prepared.lookup_hint,
                    envelope: prepared.envelope,
                },
                state: prepared.state,
            })
    }
}

impl ClientPendingS3 {
    /// Handles the final server seal and finalizes the session.
    pub fn handle_s3<C: CarrierProfile>(
        self,
        packet: &ServerConfirmationPacket,
        carrier: &C,
    ) -> Result<EstablishedSession, AdmissionError> {
        self.handle_ug4(&packet.envelope, carrier)
    }
}
