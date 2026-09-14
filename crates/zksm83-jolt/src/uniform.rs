//! Akita-committed uniform relations for the native SM83 proof pipeline.

mod commitment;
mod composite;
mod encoding;
mod geometry;
mod relation;
#[cfg(test)]
mod scratch_tests;
mod sumcheck;

use akita_config::proof_optimized::fp128;
use akita_pcs::{AkitaError, AkitaTranscript, Ring, Transcript};
use akita_serialization::SerializationError;
use rayon::prelude::*;
use thiserror::Error;

use crate::{AkitaWorkerError, NativeProtocolVersion};
pub use commitment::{CommittedWitness, WitnessCommitments};
use commitment::{
    OpeningProof, commit_columns, prove_opening, prove_selected_opening,
    verify_opening_for_protocol, verify_selected_opening_for_protocol,
};
pub(crate) use composite::{
    CompositeUniformRelationProof, ProjectedRelation, prove_uniform_composite,
    verify_uniform_composite_for_protocol,
};
pub use relation::ConstraintOutput;
use relation::initialize_constraint_output;
#[cfg(test)]
use sumcheck::{combined_relation_with_scratch, parallel_sumcheck_round, sumcheck_round};
use sumcheck::{prove_sumcheck, replay_sumcheck};

/// Scalar field used by the native transparent relation and Akita PCS.
pub type NativeField = fp128::Field;

const OUTER_TRANSCRIPT_DOMAIN_V2: &[u8] = b"zksm83-native-uniform/v2";
pub(crate) use encoding::{push_bytes, push_usize};
pub use geometry::{
    BLOCK_CPU_COMMITMENT_GROUP_COUNT, BLOCK_CPU_OPENING_COUNT, BLOCK_CPU_PADDED_COLUMN_COUNT,
    BLOCK_CPU_PADDING_COLUMN_COUNT, COMMITMENT_GROUP_COLUMNS, NATIVE_TRACE_COMMITMENT_GROUP_COUNT,
    NATIVE_TRACE_OPENING_COUNT, NATIVE_TRACE_PADDED_COLUMN_COUNT,
    NATIVE_TRACE_PADDING_COLUMN_COUNT, UNIFORM_NUM_VARIABLES, UNIFORM_ROW_COUNT,
};

/// A fixed low-degree identity evaluated independently on every active row.
///
/// This M2 surface deliberately has no row-shift operation. Sequential SM83
/// continuity is added by the cycle/increment claim in later milestones.
pub trait UniformRelation: Sync {
    /// Stable, non-empty relation-domain tag.
    fn domain(&self) -> &'static [u8];

    /// Canonical public bytes bound before Fiat-Shamir challenges.
    fn statement_bytes(&self) -> Vec<u8>;

    /// Number of committed witness columns consumed by one row.
    fn column_count(&self) -> usize;

    /// Number of identities returned by [`Self::evaluate`].
    fn constraint_count(&self) -> usize;

    /// Maximum total degree of any returned identity.
    fn max_constraint_degree(&self) -> usize;

    /// Declares whether [`Self::evaluate`] needs a zero-initialized output.
    ///
    /// Implementations should select [`ConstraintOutput::Overwritten`] only
    /// when every declared slot is assigned on every successful call.
    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::ZeroInitialized
    }

    /// Evaluates every identity at one possibly non-Boolean row point.
    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError>;
}

/// In-memory proof of one committed uniform relation.
///
/// This low-level object is not a receipt; the canonical v2 receipt encodes the
/// composed packed relation and its lookup, memory, continuity, and log proofs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniformProof {
    commitments: WitnessCommitments,
    relation: UniformRelationProof,
}

/// Relation proof that borrows its witness identity from external commitments.
///
/// Composite SM83 claims carry this value beside one shared
/// [`WitnessCommitments`] value instead of recommitting the same trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniformRelationProof {
    pub(crate) logical_column_count: usize,
    pub(crate) sumcheck_rounds: Vec<Vec<NativeField>>,
    pub(crate) opened_values: Vec<NativeField>,
    pub(crate) opening: OpeningProof,
}

impl UniformProof {
    /// Returns `log2` of the committed row count.
    #[must_use]
    pub const fn num_variables(&self) -> usize {
        UNIFORM_NUM_VARIABLES
    }

    /// Returns the number of committed witness columns.
    #[must_use]
    pub fn column_count(&self) -> usize {
        self.commitments.column_count()
    }

    /// Returns the number of sumcheck rounds.
    #[must_use]
    pub fn round_count(&self) -> usize {
        self.relation.sumcheck_rounds.len()
    }

    /// Returns the number of fixed-width Akita commitment groups.
    #[must_use]
    pub fn commitment_group_count(&self) -> usize {
        self.commitments.group_count()
    }

    /// Returns the verifier-visible witness commitments.
    #[must_use]
    pub const fn commitments(&self) -> &WitnessCommitments {
        &self.commitments
    }
}

/// Invalid native uniform statement, witness, proof, or backend operation.
#[derive(Debug, Error)]
pub enum UniformError {
    /// The relation has an empty domain, statement, column set, constraint set,
    /// or degree bound.
    #[error("native uniform relation declaration is empty")]
    EmptyRelation,
    /// Witness columns or proof vectors disagree with the declared shape.
    #[error("native uniform relation shape is invalid")]
    Shape,
    /// A concrete Boolean-domain witness row violates one declared constraint.
    #[error("native uniform witness row {row} violates constraint {constraint}")]
    WitnessUnsatisfied {
        /// Zero-based witness row.
        row: usize,
        /// Zero-based constraint slot in the relation's stable evaluation order.
        constraint: usize,
    },
    /// A reduced polynomial identity does not equal its claimed sum.
    #[error("native uniform reduced relation is unsatisfied")]
    Unsatisfied,
    /// A sumcheck message has the wrong degree or does not preserve its claim.
    #[error("native uniform sumcheck rejected a round")]
    Sumcheck,
    /// Opened column values do not satisfy the terminal relation claim.
    #[error("native uniform terminal opening does not satisfy the relation")]
    TerminalMismatch,
    /// A Fiat-Shamir constraint-mixing challenge was zero.
    #[error("native uniform Fiat-Shamir mixing challenge was zero")]
    ZeroChallenge,
    /// A fixed interpolation denominator unexpectedly had no inverse.
    #[error("native uniform interpolation denominator is not invertible")]
    NonInvertibleInterpolation,
    /// Akita rejected setup, commitment, opening construction, or verification.
    #[error("Akita rejected the native uniform proof: {0}")]
    Akita(#[from] AkitaError),
    /// Canonical Akita serialization failed.
    #[error("native uniform proof serialization failed: {0}")]
    Serialization(#[from] SerializationError),
    /// A cached per-layout PCS prover context could not be initialized.
    #[error("native uniform PCS context failed: {0}")]
    PcsContext(String),
    /// The operating system rejected creation of the bounded proof worker.
    #[error("failed to start native uniform proof worker: {0}")]
    WorkerSpawn(#[source] std::io::Error),
    /// The bounded proof worker panicked and its result was rejected.
    #[error("native uniform proof worker terminated unexpectedly")]
    WorkerPanicked,
}

/// Checks a fixed-row witness against a uniform relation without committing or proving it.
///
/// This is the bounded proof-free validation boundary used by trace encoders and profilers before
/// any PCS work is considered.
pub fn validate_uniform_witness(
    relation: &impl UniformRelation,
    columns: &[Vec<u64>],
) -> Result<(), UniformError> {
    let row_count = validate_witness_shape(relation, columns)?;
    ensure_u64_relation_holds(relation, columns, row_count)
}

/// Commits `u64` witness columns and proves one uniform low-degree relation.
///
/// The call executes Akita on an explicitly sized worker stack. It returns no
/// receipt and makes no SM83-completeness or witness-hiding claim by itself.
pub fn prove_uniform(
    relation: &impl UniformRelation,
    columns: &[Vec<u64>],
) -> Result<UniformProof, UniformError> {
    on_worker(|| {
        validate_uniform_witness(relation, columns)?;
        let witness = commit_columns(columns)?;
        let relation_proof = prove_satisfied_uniform_on_worker(relation, &witness)?;
        Ok(UniformProof {
            commitments: witness.into_commitments(),
            relation: relation_proof,
        })
    })
}

/// Verifies a uniform proof without receiving any witness column.
pub fn verify_uniform(
    relation: &impl UniformRelation,
    proof: &UniformProof,
) -> Result<(), UniformError> {
    verify_uniform_committed(relation, &proof.commitments, &proof.relation)
}

/// Commits one fixed-row witness plane for reuse by several native claims.
pub fn commit_witness(columns: &[Vec<u64>]) -> Result<CommittedWitness, UniformError> {
    on_worker(|| commit_columns(columns))
}

/// Proves a uniform relation against an already committed witness plane.
pub fn prove_uniform_committed(
    relation: &impl UniformRelation,
    witness: &CommittedWitness,
) -> Result<UniformRelationProof, UniformError> {
    on_worker(|| prove_uniform_committed_on_worker(relation, witness))
}

/// Verifies a relation proof against caller-supplied shared commitments.
pub fn verify_uniform_committed(
    relation: &impl UniformRelation,
    commitments: &WitnessCommitments,
    proof: &UniformRelationProof,
) -> Result<(), UniformError> {
    verify_uniform_committed_for_protocol(
        NativeProtocolVersion::current(),
        relation,
        commitments,
        proof,
    )
}

pub(crate) fn verify_uniform_committed_for_protocol(
    protocol: NativeProtocolVersion,
    relation: &impl UniformRelation,
    commitments: &WitnessCommitments,
    proof: &UniformRelationProof,
) -> Result<(), UniformError> {
    on_worker(|| verify_uniform_committed_on_worker(protocol, relation, commitments, proof))
}

pub(crate) fn prove_witness_opening(
    witness: &CommittedWitness,
    point: &[NativeField],
    values: &[NativeField],
    descriptor: &[u8],
) -> Result<crate::pcs::OpeningProof, UniformError> {
    prove_opening(witness, point, values, descriptor)
}

pub(crate) fn verify_witness_opening_for_protocol(
    protocol: NativeProtocolVersion,
    commitments: &WitnessCommitments,
    point: &[NativeField],
    values: &[NativeField],
    descriptor: &[u8],
    opening: &crate::pcs::OpeningProof,
) -> Result<(), UniformError> {
    verify_opening_for_protocol(protocol, commitments, point, values, descriptor, opening)
}

pub(crate) fn prove_witness_selected_opening(
    witness: &CommittedWitness,
    point: &[NativeField],
    selected_columns: &[usize],
    descriptor: &[u8],
) -> Result<(Vec<NativeField>, crate::pcs::OpeningProof), UniformError> {
    prove_selected_opening(witness, point, selected_columns, descriptor)
}

pub(crate) fn verify_witness_selected_opening_for_protocol(
    protocol: NativeProtocolVersion,
    commitments: &WitnessCommitments,
    point: &[NativeField],
    values: &[NativeField],
    selected_columns: &[usize],
    descriptor: &[u8],
    opening: &crate::pcs::OpeningProof,
) -> Result<(), UniformError> {
    verify_selected_opening_for_protocol(
        protocol,
        commitments,
        point,
        values,
        selected_columns,
        descriptor,
        opening,
    )
}

fn prove_uniform_committed_on_worker(
    relation: &impl UniformRelation,
    witness: &CommittedWitness,
) -> Result<UniformRelationProof, UniformError> {
    let protocol = NativeProtocolVersion::current();
    validate_committed_relation(protocol, relation, witness.commitments())?;
    let field_columns = witness.field_columns()?;
    ensure_relation_holds(relation, field_columns.as_slice(), UNIFORM_ROW_COUNT)?;
    prove_satisfied_uniform_on_worker(relation, witness)
}

fn prove_satisfied_uniform_on_worker(
    relation: &impl UniformRelation,
    witness: &CommittedWitness,
) -> Result<UniformRelationProof, UniformError> {
    let protocol = NativeProtocolVersion::current();
    validate_committed_relation(protocol, relation, witness.commitments())?;
    let field_columns = witness.field_columns()?;
    let descriptor = relation_instance_descriptor(protocol, relation, witness.commitments())?;
    let mut transcript = outer_transcript(protocol, &descriptor, TranscriptSide::Prover);
    let row_point = sample_point(&mut transcript, UNIFORM_NUM_VARIABLES);
    let constraint_mix = transcript.challenge_scalar(b"constraint-mix");
    if constraint_mix == NativeField::from_u64(0) {
        return Err(UniformError::ZeroChallenge);
    }
    let weights = equality_evaluations(&row_point);
    let (sumcheck_rounds, opening_point, opened_values) = prove_sumcheck(
        relation,
        field_columns.as_slice(),
        weights,
        constraint_mix,
        &mut transcript,
    )?;
    let opening = prove_opening(witness, &opening_point, &opened_values, &descriptor)?;
    Ok(UniformRelationProof {
        logical_column_count: relation.column_count(),
        sumcheck_rounds,
        opened_values,
        opening,
    })
}

fn verify_uniform_committed_on_worker(
    protocol: NativeProtocolVersion,
    relation: &impl UniformRelation,
    commitments: &WitnessCommitments,
    proof: &UniformRelationProof,
) -> Result<(), UniformError> {
    validate_committed_relation(protocol, relation, commitments)?;
    if proof.logical_column_count != relation.column_count()
        || proof.sumcheck_rounds.len() != UNIFORM_NUM_VARIABLES
        || proof.opened_values.len() != relation.column_count()
    {
        return Err(UniformError::Shape);
    }
    let descriptor = relation_instance_descriptor(protocol, relation, commitments)?;
    let mut transcript = outer_transcript(protocol, &descriptor, TranscriptSide::Verifier);
    let row_point = sample_point(&mut transcript, UNIFORM_NUM_VARIABLES);
    let constraint_mix = transcript.challenge_scalar(b"constraint-mix");
    if constraint_mix == NativeField::from_u64(0) {
        return Err(UniformError::ZeroChallenge);
    }
    let opening_point = replay_sumcheck(
        relation,
        &proof.sumcheck_rounds,
        &proof.opened_values,
        &row_point,
        constraint_mix,
        &mut transcript,
    )?;
    verify_opening_for_protocol(
        protocol,
        commitments,
        &opening_point,
        &proof.opened_values,
        &descriptor,
        &proof.opening,
    )
}

fn validate_relation(relation: &impl UniformRelation) -> Result<(), UniformError> {
    if relation.domain().is_empty()
        || relation.statement_bytes().is_empty()
        || relation.column_count() == 0
        || relation.constraint_count() == 0
        || relation.max_constraint_degree() == 0
    {
        return Err(UniformError::EmptyRelation);
    }
    relation
        .max_constraint_degree()
        .checked_add(2)
        .ok_or(UniformError::Shape)?;
    Ok(())
}

fn validate_witness_shape(
    relation: &impl UniformRelation,
    columns: &[Vec<u64>],
) -> Result<usize, UniformError> {
    validate_relation(relation)?;
    if columns.len() != relation.column_count() {
        return Err(UniformError::Shape);
    }
    let row_count = columns.first().map(Vec::len).ok_or(UniformError::Shape)?;
    if row_count != UNIFORM_ROW_COUNT || columns.iter().any(|column| column.len() != row_count) {
        return Err(UniformError::Shape);
    }
    Ok(row_count)
}

fn validate_committed_relation(
    protocol: NativeProtocolVersion,
    relation: &impl UniformRelation,
    commitments: &WitnessCommitments,
) -> Result<(), UniformError> {
    validate_relation(relation)?;
    commitments.validate_for(protocol)?;
    if commitments.column_count() != relation.column_count() {
        return Err(UniformError::Shape);
    }
    Ok(())
}

fn ensure_relation_holds<C>(
    relation: &impl UniformRelation,
    columns: &[C],
    row_count: usize,
) -> Result<(), UniformError>
where
    C: AsRef<[NativeField]> + Sync,
{
    let chunks = validation_chunk_count(row_count)?;
    let rows_per_chunk = row_count.div_ceil(chunks);
    let results = (0..chunks)
        .into_par_iter()
        .map(|chunk| validate_field_chunk(relation, columns, row_count, rows_per_chunk, chunk))
        .collect::<Vec<_>>();
    finish_parallel_validation(results)
}

fn ensure_u64_relation_holds(
    relation: &impl UniformRelation,
    columns: &[Vec<u64>],
    row_count: usize,
) -> Result<(), UniformError> {
    let chunks = validation_chunk_count(row_count)?;
    let rows_per_chunk = row_count.div_ceil(chunks);
    let results = (0..chunks)
        .into_par_iter()
        .map(|chunk| validate_u64_chunk(relation, columns, row_count, rows_per_chunk, chunk))
        .collect::<Vec<_>>();
    finish_parallel_validation(results)
}

fn validate_field_chunk<C>(
    relation: &impl UniformRelation,
    columns: &[C],
    row_count: usize,
    rows_per_chunk: usize,
    chunk: usize,
) -> Result<Option<(usize, usize)>, UniformError>
where
    C: AsRef<[NativeField]>,
{
    let zero = NativeField::from_u64(0);
    let mut row = Vec::with_capacity(columns.len());
    let mut constraints = vec![zero; relation.constraint_count()];
    for row_index in validation_range(row_count, rows_per_chunk, chunk)? {
        row.clear();
        for column in columns {
            row.push(
                column
                    .as_ref()
                    .get(row_index)
                    .copied()
                    .ok_or(UniformError::Shape)?,
            );
        }
        initialize_constraint_output(relation, &mut constraints);
        relation.evaluate(&row, &mut constraints)?;
        if let Some(constraint) = constraints.iter().position(|value| *value != zero) {
            return Ok(Some((row_index, constraint)));
        }
    }
    Ok(None)
}

fn validate_u64_chunk(
    relation: &impl UniformRelation,
    columns: &[Vec<u64>],
    row_count: usize,
    rows_per_chunk: usize,
    chunk: usize,
) -> Result<Option<(usize, usize)>, UniformError> {
    let zero = NativeField::from_u64(0);
    let mut row = Vec::with_capacity(columns.len());
    let mut constraints = vec![zero; relation.constraint_count()];
    for row_index in validation_range(row_count, rows_per_chunk, chunk)? {
        row.clear();
        for column in columns {
            row.push(NativeField::from_u64(
                column.get(row_index).copied().ok_or(UniformError::Shape)?,
            ));
        }
        initialize_constraint_output(relation, &mut constraints);
        relation.evaluate(&row, &mut constraints)?;
        if let Some(constraint) = constraints.iter().position(|value| *value != zero) {
            return Ok(Some((row_index, constraint)));
        }
    }
    Ok(None)
}

fn validation_chunk_count(row_count: usize) -> Result<usize, UniformError> {
    if row_count == 0 {
        return Err(UniformError::Shape);
    }
    Ok(rayon::current_num_threads().clamp(1, row_count))
}

fn validation_range(
    row_count: usize,
    rows_per_chunk: usize,
    chunk: usize,
) -> Result<std::ops::Range<usize>, UniformError> {
    let start = chunk
        .checked_mul(rows_per_chunk)
        .ok_or(UniformError::Shape)?;
    let end = start.saturating_add(rows_per_chunk).min(row_count);
    Ok(start..end)
}

fn finish_parallel_validation(
    results: Vec<Result<Option<(usize, usize)>, UniformError>>,
) -> Result<(), UniformError> {
    for result in results {
        if let Some((row, constraint)) = result? {
            return Err(UniformError::WitnessUnsatisfied { row, constraint });
        }
    }
    Ok(())
}

enum TranscriptSide {
    Prover,
    Verifier,
}

fn outer_transcript(
    protocol: NativeProtocolVersion,
    descriptor: &[u8],
    side: TranscriptSide,
) -> AkitaTranscript<NativeField> {
    let domain = match protocol {
        NativeProtocolVersion::V2 => OUTER_TRANSCRIPT_DOMAIN_V2,
    };
    let mut transcript = match side {
        TranscriptSide::Prover => AkitaTranscript::<NativeField>::unbound_prover(domain),
        TranscriptSide::Verifier => AkitaTranscript::<NativeField>::unbound_verifier(domain),
    };
    transcript.bind_instance_bytes(descriptor);
    transcript
}

fn relation_instance_descriptor(
    protocol: NativeProtocolVersion,
    relation: &impl UniformRelation,
    commitments: &WitnessCommitments,
) -> Result<Vec<u8>, UniformError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, protocol.protocol_id().as_bytes())?;
    push_bytes(&mut descriptor, protocol.trace_schedule_sha256().as_bytes())?;
    push_bytes(&mut descriptor, relation.domain())?;
    push_bytes(&mut descriptor, &relation.statement_bytes())?;
    push_usize(&mut descriptor, UNIFORM_NUM_VARIABLES)?;
    push_usize(&mut descriptor, relation.column_count())?;
    push_usize(&mut descriptor, relation.constraint_count())?;
    push_usize(&mut descriptor, relation.max_constraint_degree())?;
    push_bytes(&mut descriptor, &commitments.canonical_bytes_for(protocol)?)?;
    Ok(descriptor)
}

fn sample_point(
    transcript: &mut AkitaTranscript<NativeField>,
    num_variables: usize,
) -> Vec<NativeField> {
    (0..num_variables)
        .map(|_| transcript.challenge_scalar(b"row-point"))
        .collect()
}

fn equality_evaluations(point: &[NativeField]) -> Vec<NativeField> {
    let one = NativeField::from_u64(1);
    let mut evaluations = vec![one];
    for coordinate in point {
        let complement = one - *coordinate;
        let mut next = Vec::with_capacity(evaluations.len().saturating_mul(2));
        next.extend(evaluations.iter().map(|value| *value * complement));
        next.extend(evaluations.iter().map(|value| *value * *coordinate));
        evaluations = next;
    }
    evaluations
}

fn on_worker<T: Send>(
    operation: impl FnOnce() -> Result<T, UniformError> + Send,
) -> Result<T, UniformError> {
    match crate::on_akita_worker(operation) {
        Ok(result) => result,
        Err(AkitaWorkerError::Spawn(error)) => Err(UniformError::WorkerSpawn(error)),
        Err(AkitaWorkerError::Panicked) => Err(UniformError::WorkerPanicked),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        COMMITMENT_GROUP_COLUMNS, NativeField, UNIFORM_NUM_VARIABLES, UNIFORM_ROW_COUNT,
        UniformError, UniformProof, UniformRelation, commit_witness,
        commitment::{AUXILIARY_SCHEDULE_ARTIFACT, SCHEDULE_ARTIFACT, scheme},
        prove_uniform, prove_uniform_committed, verify_uniform, verify_uniform_committed,
    };
    use akita_pcs::Ring;
    use sha2::{Digest, Sha256};

    struct BooleanColumn;

    struct EdgeEqualityColumns<const N: usize>;

    #[test]
    fn pinned_v2_schedule_has_only_the_frozen_pair_shape() -> Result<(), UniformError> {
        let scheme = scheme()?;
        let shapes = scheme
            .schedules()
            .catalog()
            .rows()
            .map(|row| {
                let profiles = row.profiles();
                (
                    profiles.final_group.group.num_vars(),
                    profiles.final_group.group.num_polynomials(),
                    profiles
                        .precommitteds
                        .iter()
                        .map(|profile| (profile.group.num_vars(), profile.group.num_polynomials()))
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(shapes.len(), 1);
        let (num_variables, num_polynomials, precommitted) =
            shapes.first().ok_or(UniformError::Shape)?;
        assert_eq!(*num_variables, UNIFORM_NUM_VARIABLES);
        assert_eq!(*num_polynomials, COMMITMENT_GROUP_COLUMNS);
        assert_eq!(
            precommitted.as_slice(),
            &[(UNIFORM_NUM_VARIABLES, COMMITMENT_GROUP_COLUMNS)]
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(SCHEDULE_ARTIFACT)),
            crate::AKITA_SCHEDULE_SHA256
        );
        Ok(())
    }

    #[test]
    fn pinned_auxiliary_schedule_digest_matches_backend_identity() {
        assert_eq!(
            format!("{:x}", Sha256::digest(AUXILIARY_SCHEDULE_ARTIFACT)),
            crate::AKITA_AUXILIARY_SCHEDULE_SHA256
        );
    }

    impl UniformRelation for BooleanColumn {
        fn domain(&self) -> &'static [u8] {
            b"zksm83/test/boolean-column/v1"
        }

        fn statement_bytes(&self) -> Vec<u8> {
            b"one committed column is Boolean".to_vec()
        }

        fn column_count(&self) -> usize {
            1
        }

        fn constraint_count(&self) -> usize {
            1
        }

        fn max_constraint_degree(&self) -> usize {
            2
        }

        fn evaluate(
            &self,
            row: &[NativeField],
            constraints: &mut [NativeField],
        ) -> Result<(), UniformError> {
            let value = row.first().copied().ok_or(UniformError::Shape)?;
            let constraint = constraints.first_mut().ok_or(UniformError::Shape)?;
            *constraint = value * (value - NativeField::from_u64(1));
            Ok(())
        }
    }

    impl<const N: usize> UniformRelation for EdgeEqualityColumns<N> {
        fn domain(&self) -> &'static [u8] {
            b"zksm83/test/edge-equality-columns/v1"
        }

        fn statement_bytes(&self) -> Vec<u8> {
            N.to_le_bytes().to_vec()
        }

        fn column_count(&self) -> usize {
            N
        }

        fn constraint_count(&self) -> usize {
            1
        }

        fn max_constraint_degree(&self) -> usize {
            1
        }

        fn evaluate(
            &self,
            row: &[NativeField],
            constraints: &mut [NativeField],
        ) -> Result<(), UniformError> {
            if row.len() != N {
                return Err(UniformError::Shape);
            }
            let constraint = constraints.first_mut().ok_or(UniformError::Shape)?;
            let first = row.first().copied().ok_or(UniformError::Shape)?;
            let last = row.last().copied().ok_or(UniformError::Shape)?;
            *constraint = first - last;
            Ok(())
        }
    }

    #[test]
    #[ignore = "expensive Akita commitment, sumcheck, opening, and verification gate"]
    fn committed_boolean_relation_verifies_and_rejects_tampering() -> Result<(), UniformError> {
        let column = (0..UNIFORM_ROW_COUNT)
            .map(|index| u64::from(index % 3 == 0))
            .collect::<Vec<_>>();
        let witness = commit_witness(&[column])?;
        let commitment_digest = witness.commitments().digest()?;
        let relation_proof = prove_uniform_committed(&BooleanColumn, &witness)?;
        verify_uniform_committed(&BooleanColumn, witness.commitments(), &relation_proof)?;

        let other_column = (0..UNIFORM_ROW_COUNT)
            .map(|index| u64::from(index % 5 == 0))
            .collect::<Vec<_>>();
        let other_witness = commit_witness(&[other_column])?;
        assert_ne!(commitment_digest, other_witness.commitments().digest()?);
        assert!(
            verify_uniform_committed(&BooleanColumn, other_witness.commitments(), &relation_proof,)
                .is_err()
        );

        let proof = UniformProof {
            commitments: witness.into_commitments(),
            relation: relation_proof,
        };
        verify_uniform(&BooleanColumn, &proof)?;

        let mut tampered = proof.clone();
        let first_round = tampered
            .relation
            .sumcheck_rounds
            .first_mut()
            .ok_or(UniformError::Shape)?;
        let first_value = first_round.first_mut().ok_or(UniformError::Shape)?;
        *first_value += NativeField::from_u64(1);
        assert!(verify_uniform(&BooleanColumn, &tampered).is_err());
        assert_eq!(proof.num_variables(), 14);
        assert_eq!(proof.column_count(), 1);
        assert_eq!(proof.commitment_group_count(), 1);
        assert_eq!(proof.round_count(), 14);
        Ok(())
    }

    #[test]
    #[ignore = "expensive two-group Akita opening and ordering gate"]
    fn multiple_commitment_groups_verify_and_reject_reordering() -> Result<(), UniformError> {
        const LOGICAL_COLUMNS: usize = COMMITMENT_GROUP_COLUMNS + 2;
        let mut columns = (0..LOGICAL_COLUMNS)
            .map(|_| vec![0; UNIFORM_ROW_COUNT])
            .collect::<Vec<_>>();
        let shared = (0..UNIFORM_ROW_COUNT)
            .map(|row| u64::from(row % 5 == 0))
            .collect::<Vec<_>>();
        *columns.first_mut().ok_or(UniformError::Shape)? = shared.clone();
        *columns.last_mut().ok_or(UniformError::Shape)? = shared;
        let relation = EdgeEqualityColumns::<LOGICAL_COLUMNS>;
        let proof = prove_uniform(&relation, &columns)?;
        assert_eq!(proof.commitment_group_count(), 2);
        verify_uniform(&relation, &proof)?;

        let mut reordered = proof.clone();
        reordered.commitments.inner.groups.swap(0, 1);
        reordered.relation.opening.groups.swap(0, 1);
        assert!(verify_uniform(&relation, &reordered).is_err());
        Ok(())
    }
}
