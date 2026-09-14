//! Process-local timing counters for non-consensus proof diagnostics.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
pub(crate) enum Phase {
    Setup,
    PackedRelationEvaluation,
    Commit,
    RomLookup,
    MutableMemoryProof,
    ContinuityProof,
    ProtocolLogProof,
    Sumcheck,
    Opening,
    Encode,
    Verify,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct PhaseTotals {
    pub(crate) setup_nanos: u64,
    pub(crate) packed_relation_evaluation_nanos: u64,
    pub(crate) commit_nanos: u64,
    pub(crate) rom_lookup_nanos: u64,
    pub(crate) mutable_memory_nanos: u64,
    pub(crate) continuity_nanos: u64,
    pub(crate) protocol_log_nanos: u64,
    pub(crate) sumcheck_nanos: u64,
    pub(crate) opening_nanos: u64,
    pub(crate) encode_nanos: u64,
    pub(crate) verify_nanos: u64,
}

pub(crate) struct PhaseTimer {
    phase: Phase,
    started: Instant,
}

struct AtomicPhaseTotals {
    setup_nanos: AtomicU64,
    packed_relation_evaluation_nanos: AtomicU64,
    commit_nanos: AtomicU64,
    rom_lookup_nanos: AtomicU64,
    mutable_memory_nanos: AtomicU64,
    continuity_nanos: AtomicU64,
    protocol_log_nanos: AtomicU64,
    sumcheck_nanos: AtomicU64,
    opening_nanos: AtomicU64,
    encode_nanos: AtomicU64,
    verify_nanos: AtomicU64,
}

static TOTALS: AtomicPhaseTotals = AtomicPhaseTotals {
    setup_nanos: AtomicU64::new(0),
    packed_relation_evaluation_nanos: AtomicU64::new(0),
    commit_nanos: AtomicU64::new(0),
    rom_lookup_nanos: AtomicU64::new(0),
    mutable_memory_nanos: AtomicU64::new(0),
    continuity_nanos: AtomicU64::new(0),
    protocol_log_nanos: AtomicU64::new(0),
    sumcheck_nanos: AtomicU64::new(0),
    opening_nanos: AtomicU64::new(0),
    encode_nanos: AtomicU64::new(0),
    verify_nanos: AtomicU64::new(0),
};

/// Process-local cumulative wall times for diagnostic proof phases.
///
/// Counters are not part of a receipt or its consensus identity. Component
/// buckets can overlap nested setup, commitment, sumcheck, and opening work.
/// Concurrent proof work in the same process contributes to the same totals.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeProofPhaseMetrics {
    setup: Duration,
    packed_relation_evaluation: Duration,
    commit: Duration,
    rom_lookup: Duration,
    mutable_memory: Duration,
    continuity: Duration,
    protocol_log: Duration,
    sumcheck: Duration,
    opening: Duration,
    encode: Duration,
    verify: Duration,
}

impl NativeProofPhaseMetrics {
    /// Returns a saturating delta from an earlier process-local snapshot.
    #[must_use]
    pub fn since(self, earlier: Self) -> Self {
        Self {
            setup: self.setup.saturating_sub(earlier.setup),
            packed_relation_evaluation: self
                .packed_relation_evaluation
                .saturating_sub(earlier.packed_relation_evaluation),
            commit: self.commit.saturating_sub(earlier.commit),
            rom_lookup: self.rom_lookup.saturating_sub(earlier.rom_lookup),
            mutable_memory: self.mutable_memory.saturating_sub(earlier.mutable_memory),
            continuity: self.continuity.saturating_sub(earlier.continuity),
            protocol_log: self.protocol_log.saturating_sub(earlier.protocol_log),
            sumcheck: self.sumcheck.saturating_sub(earlier.sumcheck),
            opening: self.opening.saturating_sub(earlier.opening),
            encode: self.encode.saturating_sub(earlier.encode),
            verify: self.verify.saturating_sub(earlier.verify),
        }
    }

    /// Returns time spent constructing cached PCS setup contexts.
    #[must_use]
    pub const fn setup(self) -> Duration {
        self.setup
    }

    /// Returns time spent evaluating native relations outside sumcheck.
    #[must_use]
    pub const fn packed_relation_evaluation(self) -> Duration {
        self.packed_relation_evaluation
    }

    /// Returns time spent committing polynomial groups.
    #[must_use]
    pub const fn commit(self) -> Duration {
        self.commit
    }

    /// Returns time spent proving immutable-ROM lookup claims.
    #[must_use]
    pub const fn rom_lookup(self) -> Duration {
        self.rom_lookup
    }

    /// Returns time spent proving mutable-memory chronology claims.
    #[must_use]
    pub const fn mutable_memory(self) -> Duration {
        self.mutable_memory
    }

    /// Returns time spent proving cross-row state-continuity claims.
    #[must_use]
    pub const fn continuity(self) -> Duration {
        self.continuity
    }

    /// Returns time spent proving ordered protocol-log claims.
    #[must_use]
    pub const fn protocol_log(self) -> Duration {
        self.protocol_log
    }

    /// Returns time spent constructing algebraic sumcheck proofs.
    #[must_use]
    pub const fn sumcheck(self) -> Duration {
        self.sumcheck
    }

    /// Returns time spent constructing PCS openings.
    #[must_use]
    pub const fn opening(self) -> Duration {
        self.opening
    }

    /// Returns time spent encoding completed segment proof frames.
    #[must_use]
    pub const fn encode(self) -> Duration {
        self.encode
    }

    /// Returns time spent verifying complete native segment proofs.
    #[must_use]
    pub const fn verify(self) -> Duration {
        self.verify
    }
}

/// Returns the current process-local proof-phase timing snapshot.
#[must_use]
pub fn native_proof_phase_metrics() -> NativeProofPhaseMetrics {
    let totals = snapshot();
    NativeProofPhaseMetrics {
        setup: duration(totals.setup_nanos),
        packed_relation_evaluation: duration(totals.packed_relation_evaluation_nanos),
        commit: duration(totals.commit_nanos),
        rom_lookup: duration(totals.rom_lookup_nanos),
        mutable_memory: duration(totals.mutable_memory_nanos),
        continuity: duration(totals.continuity_nanos),
        protocol_log: duration(totals.protocol_log_nanos),
        sumcheck: duration(totals.sumcheck_nanos),
        opening: duration(totals.opening_nanos),
        encode: duration(totals.encode_nanos),
        verify: duration(totals.verify_nanos),
    }
}

pub(crate) fn start(phase: Phase) -> PhaseTimer {
    PhaseTimer {
        phase,
        started: Instant::now(),
    }
}

pub(crate) fn snapshot() -> PhaseTotals {
    PhaseTotals {
        setup_nanos: TOTALS.setup_nanos.load(Ordering::Relaxed),
        packed_relation_evaluation_nanos: TOTALS
            .packed_relation_evaluation_nanos
            .load(Ordering::Relaxed),
        commit_nanos: TOTALS.commit_nanos.load(Ordering::Relaxed),
        rom_lookup_nanos: TOTALS.rom_lookup_nanos.load(Ordering::Relaxed),
        mutable_memory_nanos: TOTALS.mutable_memory_nanos.load(Ordering::Relaxed),
        continuity_nanos: TOTALS.continuity_nanos.load(Ordering::Relaxed),
        protocol_log_nanos: TOTALS.protocol_log_nanos.load(Ordering::Relaxed),
        sumcheck_nanos: TOTALS.sumcheck_nanos.load(Ordering::Relaxed),
        opening_nanos: TOTALS.opening_nanos.load(Ordering::Relaxed),
        encode_nanos: TOTALS.encode_nanos.load(Ordering::Relaxed),
        verify_nanos: TOTALS.verify_nanos.load(Ordering::Relaxed),
    }
}

impl Drop for PhaseTimer {
    fn drop(&mut self) {
        let nanos = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let counter = match self.phase {
            Phase::Setup => &TOTALS.setup_nanos,
            Phase::PackedRelationEvaluation => &TOTALS.packed_relation_evaluation_nanos,
            Phase::Commit => &TOTALS.commit_nanos,
            Phase::RomLookup => &TOTALS.rom_lookup_nanos,
            Phase::MutableMemoryProof => &TOTALS.mutable_memory_nanos,
            Phase::ContinuityProof => &TOTALS.continuity_nanos,
            Phase::ProtocolLogProof => &TOTALS.protocol_log_nanos,
            Phase::Sumcheck => &TOTALS.sumcheck_nanos,
            Phase::Opening => &TOTALS.opening_nanos,
            Phase::Encode => &TOTALS.encode_nanos,
            Phase::Verify => &TOTALS.verify_nanos,
        };
        let _previous = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_add(nanos))
        });
    }
}

pub(crate) fn duration(nanos: u64) -> Duration {
    Duration::from_nanos(nanos)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::NativeProofPhaseMetrics;

    #[test]
    fn metric_deltas_saturate_instead_of_wrapping() {
        let later = NativeProofPhaseMetrics {
            setup: Duration::from_nanos(9),
            mutable_memory: Duration::from_nanos(7),
            verify: Duration::from_nanos(2),
            ..NativeProofPhaseMetrics::default()
        };
        let earlier = NativeProofPhaseMetrics {
            setup: Duration::from_nanos(4),
            mutable_memory: Duration::from_nanos(5),
            verify: Duration::from_nanos(3),
            ..NativeProofPhaseMetrics::default()
        };
        let delta = later.since(earlier);
        assert_eq!(delta.setup(), Duration::from_nanos(5));
        assert_eq!(delta.mutable_memory(), Duration::from_nanos(2));
        assert_eq!(delta.verify(), Duration::ZERO);
    }
}
