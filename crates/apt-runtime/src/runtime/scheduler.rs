use super::*;

const SOFT_PACKING_HEADROOM_BYTES: usize = 256;

pub(super) fn collect_outbound_tun_frames(
    first_packet: Vec<u8>,
    tun_rx: &mut mpsc::Receiver<Vec<u8>>,
    adaptive: &mut AdaptiveDatapath,
    binding: CarrierBinding,
    now_millis: u64,
) -> (Vec<Frame>, usize, usize) {
    adaptive.begin_outbound_data_send(now_millis);
    let mut frames = vec![Frame::IpData(first_packet)];
    let mut payload_bytes = match &frames[0] {
        Frame::IpData(packet) => packet.len(),
        _ => 0,
    };
    let mut burst_len = 1;
    let burst_cap = adaptive.burst_cap(binding, now_millis);
    let packing_target = adaptive
        .soft_packing_target_bytes(binding)
        .saturating_sub(SOFT_PACKING_HEADROOM_BYTES);
    while matches!(binding, CarrierBinding::S1EncryptedStream)
        && burst_len < burst_cap
        && payload_bytes < packing_target
    {
        match tun_rx.try_recv() {
            Ok(packet) => {
                payload_bytes = payload_bytes.saturating_add(packet.len());
                frames.push(Frame::IpData(packet));
                burst_len += 1;
            }
            Err(_) => break,
        }
    }
    if let Some(padding) = adaptive.maybe_padding_frame(payload_bytes, false, now_millis) {
        payload_bytes = payload_bytes.saturating_add(padding_len(&padding));
        frames.push(padding);
    }
    (frames, payload_bytes, burst_len)
}

pub(super) fn approximate_frame_bytes(frames: &[Frame]) -> usize {
    frames.iter().map(frame_weight).sum::<usize>().max(64)
}

fn frame_weight(frame: &Frame) -> usize {
    match frame {
        Frame::IpData(packet) | Frame::Padding(packet) => packet.len(),
        Frame::CtrlAck { .. } => 16,
        Frame::PathChallenge { .. } | Frame::PathResponse { .. } => 24,
        Frame::SessionUpdate { .. } => 48,
        Frame::Ping => 8,
        Frame::Close { reason, .. } => 16 + reason.len(),
    }
}

fn padding_len(frame: &Frame) -> usize {
    match frame {
        Frame::Padding(bytes) => bytes.len(),
        _ => 0,
    }
}
