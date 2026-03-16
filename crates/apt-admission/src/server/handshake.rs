use super::*;

impl AdmissionServer {
    /// Handles a `C0` packet and returns either `S1` or an invalid-input action.
    pub fn handle_c0<C: CarrierProfile>(
        &mut self,
        source_id: &str,
        carrier: &C,
        packet: &AdmissionPacket,
        received_len: usize,
        now_secs: u64,
    ) -> ServerResponse<AdmissionPacket> {
        match self.handle_ug1(
            source_id,
            carrier,
            packet.lookup_hint,
            &packet.envelope,
            received_len,
            now_secs,
        ) {
            ServerResponse::Reply(envelope) => ServerResponse::Reply(AdmissionPacket {
                lookup_hint: None,
                envelope,
            }),
            ServerResponse::Drop(behavior) => ServerResponse::Drop(behavior),
        }
    }

    /// Handles a `C2` packet and returns either `S3` plus session material or an
    /// invalid-input action.
    pub fn handle_c2<C: CarrierProfile>(
        &mut self,
        source_id: &str,
        carrier: &C,
        packet: &AdmissionPacket,
        now_secs: u64,
    ) -> ServerResponse<EstablishedServerReply> {
        self.handle_c2_with_extension_builder(source_id, carrier, packet, now_secs, |_| {
            Ok(Vec::new())
        })
    }

    /// Handles a `C2` packet while allowing the runtime to attach encrypted
    /// `S3` extensions such as tunnel address assignments.
    pub fn handle_c2_with_extensions<C: CarrierProfile>(
        &mut self,
        source_id: &str,
        carrier: &C,
        packet: &AdmissionPacket,
        now_secs: u64,
        s3_extensions: Vec<Vec<u8>>,
    ) -> ServerResponse<EstablishedServerReply> {
        match self.handle_ug3_with_extensions(
            source_id,
            carrier,
            packet.lookup_hint,
            &packet.envelope,
            now_secs,
            s3_extensions,
        ) {
            ServerResponse::Reply(reply) => ServerResponse::Reply(EstablishedServerReply {
                packet: ServerConfirmationPacket {
                    envelope: reply.envelope,
                },
                session: reply.session,
            }),
            ServerResponse::Drop(behavior) => ServerResponse::Drop(behavior),
        }
    }

    /// Handles `UG3` while allowing the runtime to attach encrypted `UG4`
    /// extensions such as tunnel address assignments.
    pub fn handle_ug3_with_extensions<C: CarrierProfile>(
        &mut self,
        source_id: &str,
        carrier: &C,
        lookup_hint: Option<[u8; 8]>,
        envelope: &SealedEnvelope,
        now_secs: u64,
        ug4_extensions: Vec<Vec<u8>>,
    ) -> ServerResponse<EstablishedEnvelopeReply> {
        self.handle_ug3_with_extension_builder(
            source_id,
            carrier,
            lookup_hint,
            envelope,
            now_secs,
            move |_| Ok(ug4_extensions),
        )
    }

    /// Handles a `C2` packet while allowing the caller to compute encrypted
    /// `S3` extensions from the tentative established session.
    pub fn handle_c2_with_extension_builder<C, F>(
        &mut self,
        source_id: &str,
        carrier: &C,
        packet: &AdmissionPacket,
        now_secs: u64,
        extension_builder: F,
    ) -> ServerResponse<EstablishedServerReply>
    where
        C: CarrierProfile,
        F: FnOnce(&EstablishedSession) -> Result<Vec<Vec<u8>>, AdmissionError>,
    {
        match self.handle_ug3_with_extension_builder(
            source_id,
            carrier,
            packet.lookup_hint,
            &packet.envelope,
            now_secs,
            extension_builder,
        ) {
            ServerResponse::Reply(reply) => ServerResponse::Reply(EstablishedServerReply {
                packet: ServerConfirmationPacket {
                    envelope: reply.envelope,
                },
                session: reply.session,
            }),
            ServerResponse::Drop(behavior) => ServerResponse::Drop(behavior),
        }
    }
}
