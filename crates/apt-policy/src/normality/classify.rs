use super::{buckets::*, CarrierCounters, ProfileSummary};
use apt_types::{
    CarrierBinding, ConnectionLongevityClass, LossClass, MtuClass, NatClass, PathClass,
    PathProfile, RttClass,
};

pub(super) fn class_or_fallback_rtt(counts: &[u16; 5], median_gap_ms: u32) -> RttClass {
    dominant_bucket_index(counts)
        .map(index_to_rtt)
        .unwrap_or_else(|| fallback_rtt_class(median_gap_ms))
}

pub(super) fn class_or_fallback_mtu(counts: &[u16; 4], median_packet_size: u16) -> MtuClass {
    dominant_bucket_index(counts)
        .map(index_to_mtu)
        .unwrap_or_else(|| fallback_mtu_class(median_packet_size))
}

pub(super) fn class_or_fallback_longevity(
    counts: &[u16; 4],
    successful_sessions: u32,
) -> ConnectionLongevityClass {
    dominant_bucket_index(counts)
        .map(index_to_longevity)
        .unwrap_or_else(|| {
            if successful_sessions >= 3 {
                ConnectionLongevityClass::LongLived
            } else if successful_sessions > 0 {
                ConnectionLongevityClass::Moderate
            } else {
                ConnectionLongevityClass::Unknown
            }
        })
}

pub(super) fn dominant_loss_class(counts: &[u16; 4]) -> LossClass {
    dominant_bucket_index(counts)
        .map(index_to_loss)
        .unwrap_or(LossClass::Unknown)
}

pub(super) fn dominant_nat_class(counts: &[u16; 5]) -> NatClass {
    dominant_bucket_index(counts)
        .map(index_to_nat)
        .unwrap_or(NatClass::Unknown)
}

pub(super) fn infer_preferred_carrier(counters: &[CarrierCounters; 4]) -> Option<CarrierBinding> {
    let mut best: Option<(CarrierBinding, i32, u16)> = None;
    for carrier in CarrierBinding::conservative_fallback_order() {
        let counters = counters[carrier_index(carrier)];
        if counters.successes < 2 {
            continue;
        }
        let positive = i32::from(counters.successes) * 3;
        let negative = i32::from(counters.failures) * 2
            + i32::from(counters.rebindings) * 3
            + i32::from(counters.idle_timeouts) * 3;
        let score = positive - negative;
        if score <= 0 {
            continue;
        }
        match best {
            Some((_, best_score, best_successes))
                if best_score > score
                    || (best_score == score && best_successes >= counters.successes) => {}
            _ => best = Some((carrier, score, counters.successes)),
        }
    }
    best.map(|(carrier, _, _)| carrier)
}

pub(super) fn infer_path_class(
    weighted_observation_units: u32,
    median_gap_ms: u32,
    median_burst_length: u16,
    dominant_rtt: RttClass,
    dominant_loss: LossClass,
    dominant_mtu: MtuClass,
    dominant_nat: NatClass,
) -> PathClass {
    if weighted_observation_units < MIN_CLASS_EVIDENCE_UNITS {
        return PathClass::Unknown;
    }
    if matches!(dominant_loss, LossClass::High)
        || matches!(dominant_nat, NatClass::Symmetric)
        || matches!(dominant_rtt, RttClass::Extreme)
    {
        return PathClass::Hostile;
    }
    if matches!(dominant_loss, LossClass::Medium)
        || matches!(dominant_nat, NatClass::AddressDependent)
        || matches!(dominant_mtu, MtuClass::Small)
        || median_gap_ms > 120
        || median_burst_length <= 1
    {
        return PathClass::Constrained;
    }
    if median_gap_ms <= 30
        && matches!(dominant_rtt, RttClass::Low | RttClass::Moderate)
        && !matches!(dominant_loss, LossClass::Medium | LossClass::High)
        && !matches!(dominant_mtu, MtuClass::Small)
    {
        PathClass::Stable
    } else {
        PathClass::Variable
    }
}

pub(super) fn permissiveness_score(
    path: PathClass,
    rtt: RttClass,
    loss: LossClass,
    mtu: MtuClass,
    nat: NatClass,
    longevity: ConnectionLongevityClass,
) -> u8 {
    let mut score = 128_i16;
    score += match path {
        PathClass::Stable => 28,
        PathClass::Variable => 10,
        PathClass::Constrained => -18,
        PathClass::Hostile => -42,
        PathClass::Unknown => 0,
    };
    score += match rtt {
        RttClass::Low => 18,
        RttClass::Moderate => 8,
        RttClass::High => -12,
        RttClass::Extreme => -24,
        RttClass::Unknown => 0,
    };
    score += match loss {
        LossClass::Low => 14,
        LossClass::Medium => -10,
        LossClass::High => -22,
        LossClass::Unknown => 0,
    };
    score += match mtu {
        MtuClass::Large => 18,
        MtuClass::Medium => 8,
        MtuClass::Small => -18,
        MtuClass::Unknown => 0,
    };
    score += match nat {
        NatClass::OpenInternet => 10,
        NatClass::EndpointIndependent => 6,
        NatClass::AddressDependent => -10,
        NatClass::Symmetric => -22,
        NatClass::Unknown => 0,
    };
    score += match longevity {
        ConnectionLongevityClass::LongLived => 10,
        ConnectionLongevityClass::Moderate => 4,
        ConnectionLongevityClass::Ephemeral => -8,
        ConnectionLongevityClass::Unknown => 0,
    };
    score.clamp(32, 224) as u8
}

pub(super) fn fallback_mtu_class(median_packet_size: u16) -> MtuClass {
    if median_packet_size >= 1_280 {
        MtuClass::Large
    } else if median_packet_size >= 800 {
        MtuClass::Medium
    } else {
        MtuClass::Small
    }
}

pub(super) fn fallback_rtt_class(median_gap_ms: u32) -> RttClass {
    if median_gap_ms <= 20 {
        RttClass::Low
    } else if median_gap_ms <= 75 {
        RttClass::Moderate
    } else if median_gap_ms <= 200 {
        RttClass::High
    } else {
        RttClass::Extreme
    }
}

/// Builds a conservative path profile from a bounded local-normality summary.
#[must_use]
pub fn inferred_path_profile(summary: &ProfileSummary) -> PathProfile {
    PathProfile {
        path: infer_path_class(
            summary.weighted_observation_units,
            summary.median_gap_ms,
            summary.median_burst_length,
            summary.dominant_rtt,
            summary.dominant_loss,
            summary.dominant_mtu,
            summary.dominant_nat,
        ),
        mtu: summary.dominant_mtu,
        rtt: summary.dominant_rtt,
        loss: summary.dominant_loss,
        nat: summary.dominant_nat,
    }
}
