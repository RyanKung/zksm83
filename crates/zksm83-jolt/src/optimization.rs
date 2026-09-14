//! Benchmark, obligation, and optimization metadata for the native proof path.

/// Benchmark bucket required before making native proving performance claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeBenchmarkBucket {
    /// Time spent building validated packed witnesses from source execution.
    WitnessConstruction,
    /// Time spent evaluating the packed CPU/device relation outside sumcheck.
    PackedRelationEvaluation,
    /// Time spent committing the shared witness plane.
    WitnessCommitment,
    /// Time spent proving immutable-ROM lookup claims.
    RomLookup,
    /// Time spent proving mutable-memory chronology claims.
    MutableMemoryProof,
    /// Time spent proving cross-row state continuity claims.
    ContinuityProof,
    /// Time spent proving ordered protocol-log claims.
    ProtocolLogProof,
    /// Time spent proving algebraic sumcheck claims.
    Sumcheck,
    /// Time spent constructing Akita opening proofs.
    Opening,
    /// Time spent serializing proof frames and receipts.
    Encoding,
    /// Time spent verifying a receipt or segment proof.
    VerifierTime,
    /// Size of the produced proof or receipt bytes.
    ProofBytes,
}

/// Unit reported by one benchmark bucket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeBenchmarkUnit {
    /// Wall-clock duration.
    WallTime,
    /// Serialized byte count.
    Bytes,
}

/// Current status of a benchmark bucket in local diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkInstrumentation {
    /// The bucket has process-local instrumentation today.
    Instrumented,
    /// The bucket is listed as required, but needs dedicated measurement code.
    Planned,
}

/// One required benchmark report row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeBenchmarkPlanItem {
    /// Component measured by this row.
    pub bucket: NativeBenchmarkBucket,
    /// Unit used by this row.
    pub unit: NativeBenchmarkUnit,
    /// Whether current diagnostics directly measure this row.
    pub instrumentation: BenchmarkInstrumentation,
}

/// Relation family that must match before folding or accumulating obligations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofObligationFamily {
    /// Packed CPU instruction semantics.
    Cpu,
    /// Packed device and MMIO semantics carried by the row relation.
    Device,
    /// Fixed-ISA lookup claims.
    FixedIsaLookup,
    /// Byte-operation execution-table lookup claims.
    ExecutionLookup,
    /// Immutable-ROM lookup claims.
    ImmutableRomLookup,
    /// Mutable-memory chronology claims.
    MutableMemory,
    /// Cross-row state-continuity claims.
    Continuity,
    /// Ordered input, output, bus, and ISA log claims.
    ProtocolLog,
}

/// Fiat-Shamir or verifier binding point for one proof obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvaluationPointBinding {
    /// The packed-row relation is checked at the uniform sumcheck terminal point.
    PackedRowSumcheckTerminal,
    /// The claim opens selected witness columns at the shared terminal point.
    SharedWitnessOpening,
    /// The claim evaluates a separately committed table or image.
    TableOpening,
    /// The claim uses continuity challenges over public segment boundaries.
    SegmentBoundaryChallenge,
    /// The claim uses ordered-log challenges and canonical positions.
    ProtocolLogChallenge,
}

/// Typed obligation metadata used to keep future accumulation family-safe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofObligationMetadata {
    /// Relation family.
    pub family: ProofObligationFamily,
    /// Evaluation or challenge binding.
    pub evaluation: EvaluationPointBinding,
    /// Source component that currently carries the obligation.
    pub carrier: &'static str,
    /// Whether future folding may consider this obligation once the same-point rule is met.
    pub accumulation_candidate: bool,
}

impl ProofObligationMetadata {
    /// Returns whether two obligations are eligible for same-lane accumulation.
    #[must_use]
    pub const fn can_accumulate_with(self, other: Self) -> bool {
        self.accumulation_candidate
            && other.accumulation_candidate
            && self.family as u8 == other.family as u8
            && self.evaluation as u8 == other.evaluation as u8
    }
}

/// Akita-side optimization track inspired by Nightstream-style engineering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AkitaOptimizationTrack {
    /// Seeded public-parameter generation or verifier-side derivation.
    SeededParameters,
    /// Chunked commitment construction for large witness groups.
    ChunkedCommitment,
    /// Specialized path for Boolean-heavy committed columns.
    BinaryColumnFastPath,
}

/// Current decision for one Akita-side optimization track.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AkitaOptimizationDecision {
    /// Can be evaluated as a prover implementation detail without changing receipts.
    ProverSideCandidate,
    /// Requires a new pinned schedule or verifier-relevant protocol revision.
    RequiresProtocolRevision,
    /// Requires upstream Akita API and security analysis before implementation.
    RequiresUpstreamSupport,
}

/// One Akita optimization assessment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AkitaOptimizationAssessment {
    /// Optimization track.
    pub track: AkitaOptimizationTrack,
    /// Current decision.
    pub decision: AkitaOptimizationDecision,
    /// Short reason for the decision.
    pub rationale: &'static str,
}

const BENCHMARK_PLAN: [NativeBenchmarkPlanItem; 12] = [
    NativeBenchmarkPlanItem {
        bucket: NativeBenchmarkBucket::WitnessConstruction,
        unit: NativeBenchmarkUnit::WallTime,
        instrumentation: BenchmarkInstrumentation::Planned,
    },
    NativeBenchmarkPlanItem {
        bucket: NativeBenchmarkBucket::PackedRelationEvaluation,
        unit: NativeBenchmarkUnit::WallTime,
        instrumentation: BenchmarkInstrumentation::Instrumented,
    },
    NativeBenchmarkPlanItem {
        bucket: NativeBenchmarkBucket::WitnessCommitment,
        unit: NativeBenchmarkUnit::WallTime,
        instrumentation: BenchmarkInstrumentation::Instrumented,
    },
    NativeBenchmarkPlanItem {
        bucket: NativeBenchmarkBucket::RomLookup,
        unit: NativeBenchmarkUnit::WallTime,
        instrumentation: BenchmarkInstrumentation::Instrumented,
    },
    NativeBenchmarkPlanItem {
        bucket: NativeBenchmarkBucket::MutableMemoryProof,
        unit: NativeBenchmarkUnit::WallTime,
        instrumentation: BenchmarkInstrumentation::Instrumented,
    },
    NativeBenchmarkPlanItem {
        bucket: NativeBenchmarkBucket::ContinuityProof,
        unit: NativeBenchmarkUnit::WallTime,
        instrumentation: BenchmarkInstrumentation::Instrumented,
    },
    NativeBenchmarkPlanItem {
        bucket: NativeBenchmarkBucket::ProtocolLogProof,
        unit: NativeBenchmarkUnit::WallTime,
        instrumentation: BenchmarkInstrumentation::Instrumented,
    },
    NativeBenchmarkPlanItem {
        bucket: NativeBenchmarkBucket::Sumcheck,
        unit: NativeBenchmarkUnit::WallTime,
        instrumentation: BenchmarkInstrumentation::Instrumented,
    },
    NativeBenchmarkPlanItem {
        bucket: NativeBenchmarkBucket::Opening,
        unit: NativeBenchmarkUnit::WallTime,
        instrumentation: BenchmarkInstrumentation::Instrumented,
    },
    NativeBenchmarkPlanItem {
        bucket: NativeBenchmarkBucket::Encoding,
        unit: NativeBenchmarkUnit::WallTime,
        instrumentation: BenchmarkInstrumentation::Instrumented,
    },
    NativeBenchmarkPlanItem {
        bucket: NativeBenchmarkBucket::VerifierTime,
        unit: NativeBenchmarkUnit::WallTime,
        instrumentation: BenchmarkInstrumentation::Instrumented,
    },
    NativeBenchmarkPlanItem {
        bucket: NativeBenchmarkBucket::ProofBytes,
        unit: NativeBenchmarkUnit::Bytes,
        instrumentation: BenchmarkInstrumentation::Planned,
    },
];

const PACKED_BLOCK_OBLIGATIONS: [ProofObligationMetadata; 8] = [
    ProofObligationMetadata {
        family: ProofObligationFamily::Cpu,
        evaluation: EvaluationPointBinding::PackedRowSumcheckTerminal,
        carrier: "BlockCpuRelation",
        accumulation_candidate: true,
    },
    ProofObligationMetadata {
        family: ProofObligationFamily::Device,
        evaluation: EvaluationPointBinding::PackedRowSumcheckTerminal,
        carrier: "BlockCpuRelation",
        accumulation_candidate: true,
    },
    ProofObligationMetadata {
        family: ProofObligationFamily::FixedIsaLookup,
        evaluation: EvaluationPointBinding::SharedWitnessOpening,
        carrier: "IsaLookupProof",
        accumulation_candidate: true,
    },
    ProofObligationMetadata {
        family: ProofObligationFamily::ExecutionLookup,
        evaluation: EvaluationPointBinding::SharedWitnessOpening,
        carrier: "ExecutionLookupProof",
        accumulation_candidate: true,
    },
    ProofObligationMetadata {
        family: ProofObligationFamily::ImmutableRomLookup,
        evaluation: EvaluationPointBinding::TableOpening,
        carrier: "RomLookupProof",
        accumulation_candidate: true,
    },
    ProofObligationMetadata {
        family: ProofObligationFamily::MutableMemory,
        evaluation: EvaluationPointBinding::SharedWitnessOpening,
        carrier: "PackedMutableMemoryProof",
        accumulation_candidate: true,
    },
    ProofObligationMetadata {
        family: ProofObligationFamily::Continuity,
        evaluation: EvaluationPointBinding::SegmentBoundaryChallenge,
        carrier: "PackedContinuityProof",
        accumulation_candidate: true,
    },
    ProofObligationMetadata {
        family: ProofObligationFamily::ProtocolLog,
        evaluation: EvaluationPointBinding::ProtocolLogChallenge,
        carrier: "PackedProtocolLogProof",
        accumulation_candidate: true,
    },
];

const AKITA_OPTIMIZATION_ASSESSMENT: [AkitaOptimizationAssessment; 3] = [
    AkitaOptimizationAssessment {
        track: AkitaOptimizationTrack::SeededParameters,
        decision: AkitaOptimizationDecision::RequiresProtocolRevision,
        rationale: "schedule artifacts and commitment encodings are verifier-relevant today",
    },
    AkitaOptimizationAssessment {
        track: AkitaOptimizationTrack::ChunkedCommitment,
        decision: AkitaOptimizationDecision::ProverSideCandidate,
        rationale: "the current adapter already commits fixed groups independently",
    },
    AkitaOptimizationAssessment {
        track: AkitaOptimizationTrack::BinaryColumnFastPath,
        decision: AkitaOptimizationDecision::RequiresUpstreamSupport,
        rationale: "the current Akita API receives field polynomials, not typed binary columns",
    },
];

/// Returns the component benchmark buckets required for native performance claims.
#[must_use]
pub const fn native_benchmark_plan() -> &'static [NativeBenchmarkPlanItem] {
    &BENCHMARK_PLAN
}

/// Returns the family and point metadata for current packed-block obligations.
#[must_use]
pub const fn packed_block_obligation_metadata() -> &'static [ProofObligationMetadata] {
    &PACKED_BLOCK_OBLIGATIONS
}

/// Returns the current Akita-side optimization assessment.
#[must_use]
pub const fn akita_optimization_assessment() -> &'static [AkitaOptimizationAssessment] {
    &AKITA_OPTIMIZATION_ASSESSMENT
}

#[cfg(test)]
mod tests {
    use super::{
        EvaluationPointBinding, NativeBenchmarkBucket, ProofObligationFamily,
        akita_optimization_assessment, native_benchmark_plan, packed_block_obligation_metadata,
    };

    #[test]
    fn benchmark_plan_covers_required_issue_buckets() {
        let plan = native_benchmark_plan();
        for bucket in [
            NativeBenchmarkBucket::WitnessConstruction,
            NativeBenchmarkBucket::PackedRelationEvaluation,
            NativeBenchmarkBucket::WitnessCommitment,
            NativeBenchmarkBucket::RomLookup,
            NativeBenchmarkBucket::MutableMemoryProof,
            NativeBenchmarkBucket::ContinuityProof,
            NativeBenchmarkBucket::ProtocolLogProof,
            NativeBenchmarkBucket::Sumcheck,
            NativeBenchmarkBucket::Opening,
            NativeBenchmarkBucket::Encoding,
            NativeBenchmarkBucket::VerifierTime,
            NativeBenchmarkBucket::ProofBytes,
        ] {
            assert!(plan.iter().any(|item| item.bucket == bucket));
        }
    }

    #[test]
    fn obligation_accumulation_requires_same_family_and_point() -> Result<(), &'static str> {
        let obligations = packed_block_obligation_metadata();
        let cpu = obligations
            .iter()
            .copied()
            .find(|item| item.family == ProofObligationFamily::Cpu)
            .ok_or("CPU obligation metadata exists")?;
        let device = obligations
            .iter()
            .copied()
            .find(|item| item.family == ProofObligationFamily::Device)
            .ok_or("device obligation metadata exists")?;
        assert_eq!(
            cpu.evaluation,
            EvaluationPointBinding::PackedRowSumcheckTerminal
        );
        assert!(!cpu.can_accumulate_with(device));
        assert!(cpu.can_accumulate_with(cpu));
        Ok(())
    }

    #[test]
    fn akita_assessment_has_all_nightstream_tracks() {
        assert_eq!(akita_optimization_assessment().len(), 3);
    }
}
