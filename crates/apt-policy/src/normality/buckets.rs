use apt_types::{
    CarrierBinding, ConnectionLongevityClass, LossClass, MtuClass, NatClass, RttClass,
};

pub(super) const MIN_CLASS_EVIDENCE_UNITS: u32 = 24;
pub(super) const PACKET_SIZE_BUCKET_REPRESENTATIVES: [u16; 8] =
    [96, 192, 384, 640, 896, 1_152, 1_408, 2_048];
pub(super) const GAP_BUCKET_REPRESENTATIVES_MS: [u32; 8] = [2, 10, 22, 45, 90, 180, 625, 2_000];
pub(super) const BURST_BUCKET_REPRESENTATIVES: [u16; 6] = [1, 2, 4, 8, 16, 32];

pub(super) fn bump_bucket<const N: usize>(buckets: &mut [u16; N], index: usize, amount: u16) {
    buckets[index] = buckets[index].saturating_add(amount);
}

pub(super) fn quantile_u16<const N: usize>(
    counts: &[u16; N],
    representatives: &[u16; N],
) -> Option<u16> {
    quantile_index(counts).map(|index| representatives[index])
}

pub(super) fn quantile_u32<const N: usize>(
    counts: &[u16; N],
    representatives: &[u32; N],
) -> Option<u32> {
    quantile_index(counts).map(|index| representatives[index])
}

pub(super) fn dominant_bucket_index<const N: usize>(counts: &[u16; N]) -> Option<usize> {
    let total: u32 = counts.iter().map(|count| u32::from(*count)).sum();
    if total < MIN_CLASS_EVIDENCE_UNITS {
        return None;
    }
    counts
        .iter()
        .enumerate()
        .max_by(|left, right| left.1.cmp(right.1).then_with(|| right.0.cmp(&left.0)))
        .map(|(index, _)| index)
}

fn quantile_index<const N: usize>(counts: &[u16; N]) -> Option<usize> {
    let total: u32 = counts.iter().map(|count| u32::from(*count)).sum();
    if total == 0 {
        return None;
    }
    let target = total.div_ceil(2);
    let mut cumulative = 0_u32;
    for (index, count) in counts.iter().enumerate() {
        cumulative = cumulative.saturating_add(u32::from(*count));
        if cumulative >= target {
            return Some(index);
        }
    }
    counts.iter().rposition(|count| *count > 0)
}

pub(super) fn packet_size_bucket_index(packet_size: u16) -> usize {
    match packet_size {
        0..=127 => 0,
        128..=255 => 1,
        256..=511 => 2,
        512..=767 => 3,
        768..=1_023 => 4,
        1_024..=1_279 => 5,
        1_280..=1_535 => 6,
        _ => 7,
    }
}

pub(super) fn gap_bucket_index(gap_ms: u32) -> usize {
    match gap_ms {
        0..=4 => 0,
        5..=14 => 1,
        15..=29 => 2,
        30..=59 => 3,
        60..=119 => 4,
        120..=249 => 5,
        250..=999 => 6,
        _ => 7,
    }
}

pub(super) fn burst_bucket_index(burst_length: u16) -> usize {
    match burst_length {
        0 | 1 => 0,
        2 => 1,
        3..=4 => 2,
        5..=8 => 3,
        9..=16 => 4,
        _ => 5,
    }
}

pub(super) fn ratio_bucket_index(bucket: u8) -> usize {
    usize::from(bucket.min(6))
}

pub(super) fn carrier_index(carrier: CarrierBinding) -> usize {
    match carrier {
        CarrierBinding::D1DatagramUdp => 0,
        CarrierBinding::D2EncryptedDatagram => 1,
        CarrierBinding::S1EncryptedStream => 2,
        CarrierBinding::H1RequestResponse => 3,
    }
}

pub(super) fn rtt_index(class: RttClass) -> usize {
    match class {
        RttClass::Unknown => 0,
        RttClass::Low => 1,
        RttClass::Moderate => 2,
        RttClass::High => 3,
        RttClass::Extreme => 4,
    }
}

pub(super) fn index_to_rtt(index: usize) -> RttClass {
    match index {
        1 => RttClass::Low,
        2 => RttClass::Moderate,
        3 => RttClass::High,
        4 => RttClass::Extreme,
        _ => RttClass::Unknown,
    }
}

pub(super) fn loss_index(class: LossClass) -> usize {
    match class {
        LossClass::Unknown => 0,
        LossClass::Low => 1,
        LossClass::Medium => 2,
        LossClass::High => 3,
    }
}

pub(super) fn index_to_loss(index: usize) -> LossClass {
    match index {
        1 => LossClass::Low,
        2 => LossClass::Medium,
        3 => LossClass::High,
        _ => LossClass::Unknown,
    }
}

pub(super) fn mtu_index(class: MtuClass) -> usize {
    match class {
        MtuClass::Unknown => 0,
        MtuClass::Small => 1,
        MtuClass::Medium => 2,
        MtuClass::Large => 3,
    }
}

pub(super) fn index_to_mtu(index: usize) -> MtuClass {
    match index {
        1 => MtuClass::Small,
        2 => MtuClass::Medium,
        3 => MtuClass::Large,
        _ => MtuClass::Unknown,
    }
}

pub(super) fn nat_index(class: NatClass) -> usize {
    match class {
        NatClass::Unknown => 0,
        NatClass::OpenInternet => 1,
        NatClass::EndpointIndependent => 2,
        NatClass::AddressDependent => 3,
        NatClass::Symmetric => 4,
    }
}

pub(super) fn index_to_nat(index: usize) -> NatClass {
    match index {
        1 => NatClass::OpenInternet,
        2 => NatClass::EndpointIndependent,
        3 => NatClass::AddressDependent,
        4 => NatClass::Symmetric,
        _ => NatClass::Unknown,
    }
}

pub(super) fn longevity_index(class: ConnectionLongevityClass) -> usize {
    match class {
        ConnectionLongevityClass::Unknown => 0,
        ConnectionLongevityClass::Ephemeral => 1,
        ConnectionLongevityClass::Moderate => 2,
        ConnectionLongevityClass::LongLived => 3,
    }
}

pub(super) fn index_to_longevity(index: usize) -> ConnectionLongevityClass {
    match index {
        1 => ConnectionLongevityClass::Ephemeral,
        2 => ConnectionLongevityClass::Moderate,
        3 => ConnectionLongevityClass::LongLived,
        _ => ConnectionLongevityClass::Unknown,
    }
}
