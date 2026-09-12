//! Akita-committed uniform relations for the native SM83 proof pipeline.

mod commitment;
mod composite;

use akita_config::proof_optimized::fp128;
use akita_pcs::{AkitaError, AkitaTranscript, Ring, Transcript};
use akita_serialization::SerializationError;
use jolt_field::Field;
use thiserror::Error;

use crate::{AKITA_SCHEDULE_SHA256, AkitaWorkerError, PROTOCOL_ID};
pub use commitment::{CommittedWitness, WitnessCommitments};
use commitment::{OpeningProof, commit_columns, prove_opening, verify_opening};
pub(crate) use composite::{
    CompositeUniformRelationProof, prove_uniform_composite, verify_uniform_composite,
};

/// Scalar field used by the native transparent relation and Akita PCS.
pub type NativeField = fp128::Field;

const OUTER_TRANSCRIPT_DOMAIN: &[u8] = b"zksm83-native-uniform/v1";
/// Number of rows in every native relation segment, including inactive padding.
pub const UNIFORM_ROW_COUNT: usize = 1 << UNIFORM_NUM_VARIABLES;

/// Number of row-address variables in every native relation segment.
pub const UNIFORM_NUM_VARIABLES: usize = 14;

/// Number of polynomials in each independently opened Akita commitment group.
pub const COMMITMENT_GROUP_COLUMNS: usize = 128;

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

    /// Evaluates every identity at one possibly non-Boolean row point.
    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError>;
}

/// In-memory M2 proof of one committed uniform relation.
///
/// The type is intentionally not a public receipt encoding. M6 introduces a
/// versioned canonical byte format after all SM83 claims are integrated.
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

/// Commits `u64` witness columns and proves one uniform low-degree relation.
///
/// The call executes Akita on an explicitly sized worker stack. It returns no
/// receipt and makes no SM83-completeness or witness-hiding claim by itself.
pub fn prove_uniform(
    relation: &impl UniformRelation,
    columns: &[Vec<u64>],
) -> Result<UniformProof, UniformError> {
    on_worker(|| {
        let row_count = validate_witness_shape(relation, columns)?;
        let field_columns = encode_u64_columns(columns);
        ensure_relation_holds(relation, &field_columns, row_count)?;
        let witness = commit_columns(columns)?;
        let relation_proof = prove_uniform_committed_on_worker(relation, &witness)?;
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
    on_worker(|| verify_uniform_committed_on_worker(relation, commitments, proof))
}

pub(crate) fn prove_witness_opening(
    witness: &CommittedWitness,
    point: &[NativeField],
    values: &[NativeField],
    descriptor: &[u8],
) -> Result<crate::pcs::OpeningProof, UniformError> {
    prove_opening(witness, point, values, descriptor)
}

pub(crate) fn verify_witness_opening(
    commitments: &WitnessCommitments,
    point: &[NativeField],
    values: &[NativeField],
    descriptor: &[u8],
    opening: &crate::pcs::OpeningProof,
) -> Result<(), UniformError> {
    verify_opening(commitments, point, values, descriptor, opening)
}

fn prove_uniform_committed_on_worker(
    relation: &impl UniformRelation,
    witness: &CommittedWitness,
) -> Result<UniformRelationProof, UniformError> {
    validate_committed_relation(relation, witness.commitments())?;
    ensure_relation_holds(relation, witness.field_columns(), UNIFORM_ROW_COUNT)?;
    let descriptor = relation_instance_descriptor(relation, witness.commitments())?;
    let mut transcript = outer_transcript(&descriptor, TranscriptSide::Prover);
    let row_point = sample_point(&mut transcript, UNIFORM_NUM_VARIABLES);
    let constraint_mix = transcript.challenge_scalar(b"constraint-mix");
    if constraint_mix == NativeField::from_u64(0) {
        return Err(UniformError::ZeroChallenge);
    }
    let weights = equality_evaluations(&row_point);
    let (sumcheck_rounds, opening_point, opened_values) = prove_sumcheck(
        relation,
        witness.field_columns().to_vec(),
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
    relation: &impl UniformRelation,
    commitments: &WitnessCommitments,
    proof: &UniformRelationProof,
) -> Result<(), UniformError> {
    validate_committed_relation(relation, commitments)?;
    if proof.logical_column_count != relation.column_count()
        || proof.sumcheck_rounds.len() != UNIFORM_NUM_VARIABLES
        || proof.opened_values.len() != relation.column_count()
    {
        return Err(UniformError::Shape);
    }
    let descriptor = relation_instance_descriptor(relation, commitments)?;
    let mut transcript = outer_transcript(&descriptor, TranscriptSide::Verifier);
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
    verify_opening(
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
    relation: &impl UniformRelation,
    commitments: &WitnessCommitments,
) -> Result<(), UniformError> {
    validate_relation(relation)?;
    commitments.validate()?;
    if commitments.column_count() != relation.column_count() {
        return Err(UniformError::Shape);
    }
    Ok(())
}

fn encode_u64_columns(columns: &[Vec<u64>]) -> Vec<Vec<NativeField>> {
    columns
        .iter()
        .map(|column| column.iter().copied().map(NativeField::from_u64).collect())
        .collect()
}

fn ensure_relation_holds(
    relation: &impl UniformRelation,
    columns: &[Vec<NativeField>],
    row_count: usize,
) -> Result<(), UniformError> {
    let zero = NativeField::from_u64(0);
    let mut row = Vec::with_capacity(columns.len());
    let mut constraints = vec![zero; relation.constraint_count()];
    for row_index in 0..row_count {
        row.clear();
        for column in columns {
            row.push(column.get(row_index).copied().ok_or(UniformError::Shape)?);
        }
        constraints.fill(zero);
        relation.evaluate(&row, &mut constraints)?;
        if let Some(constraint) = constraints.iter().position(|value| *value != zero) {
            return Err(UniformError::WitnessUnsatisfied {
                row: row_index,
                constraint,
            });
        }
    }
    Ok(())
}

enum TranscriptSide {
    Prover,
    Verifier,
}

fn outer_transcript(descriptor: &[u8], side: TranscriptSide) -> AkitaTranscript<NativeField> {
    let mut transcript = match side {
        TranscriptSide::Prover => {
            AkitaTranscript::<NativeField>::unbound_prover(OUTER_TRANSCRIPT_DOMAIN)
        }
        TranscriptSide::Verifier => {
            AkitaTranscript::<NativeField>::unbound_verifier(OUTER_TRANSCRIPT_DOMAIN)
        }
    };
    transcript.bind_instance_bytes(descriptor);
    transcript
}

fn relation_instance_descriptor(
    relation: &impl UniformRelation,
    commitments: &WitnessCommitments,
) -> Result<Vec<u8>, UniformError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, PROTOCOL_ID.as_bytes())?;
    push_bytes(&mut descriptor, AKITA_SCHEDULE_SHA256.as_bytes())?;
    push_bytes(&mut descriptor, relation.domain())?;
    push_bytes(&mut descriptor, &relation.statement_bytes())?;
    push_usize(&mut descriptor, UNIFORM_NUM_VARIABLES)?;
    push_usize(&mut descriptor, relation.column_count())?;
    push_usize(&mut descriptor, relation.constraint_count())?;
    push_usize(&mut descriptor, relation.max_constraint_degree())?;
    push_bytes(&mut descriptor, &commitments.canonical_bytes()?)?;
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

type SumcheckOutput = (Vec<Vec<NativeField>>, Vec<NativeField>, Vec<NativeField>);

fn prove_sumcheck(
    relation: &impl UniformRelation,
    mut columns: Vec<Vec<NativeField>>,
    mut weights: Vec<NativeField>,
    constraint_mix: NativeField,
    transcript: &mut AkitaTranscript<NativeField>,
) -> Result<SumcheckOutput, UniformError> {
    let _phase = crate::metrics::start(crate::metrics::Phase::Sumcheck);
    if columns.iter().any(|column| column.len() != weights.len()) {
        return Err(UniformError::Shape);
    }
    let round_evaluations = relation
        .max_constraint_degree()
        .checked_add(2)
        .ok_or(UniformError::Shape)?;
    let mut rounds = Vec::with_capacity(weights.len().ilog2() as usize);
    let mut opening_point = Vec::with_capacity(rounds.capacity());
    let mut claim = NativeField::from_u64(0);
    while weights.len() > 1 {
        let message = sumcheck_round(
            relation,
            &columns,
            &weights,
            constraint_mix,
            round_evaluations,
        )?;
        let at_zero = message.first().copied().ok_or(UniformError::Sumcheck)?;
        let at_one = message.get(1).copied().ok_or(UniformError::Sumcheck)?;
        if at_zero + at_one != claim {
            return Err(UniformError::Unsatisfied);
        }
        absorb_round(transcript, rounds.len(), &message)?;
        let challenge = transcript.challenge_scalar(b"sumcheck-round");
        claim = evaluate_lagrange(&message, challenge)?;
        fold_columns(&mut columns, challenge)?;
        fold_column(&mut weights, challenge)?;
        rounds.push(message);
        opening_point.push(challenge);
    }
    let opened_values = columns
        .iter()
        .map(|column| column.first().copied().ok_or(UniformError::Shape))
        .collect::<Result<Vec<_>, _>>()?;
    let terminal_weight = weights.first().copied().ok_or(UniformError::Shape)?;
    let terminal_relation = combined_relation(relation, &opened_values, constraint_mix)?;
    if claim != terminal_weight * terminal_relation {
        return Err(UniformError::TerminalMismatch);
    }
    Ok((rounds, opening_point, opened_values))
}

fn replay_sumcheck(
    relation: &impl UniformRelation,
    rounds: &[Vec<NativeField>],
    opened_values: &[NativeField],
    row_point: &[NativeField],
    constraint_mix: NativeField,
    transcript: &mut AkitaTranscript<NativeField>,
) -> Result<Vec<NativeField>, UniformError> {
    let expected_message_len = relation
        .max_constraint_degree()
        .checked_add(2)
        .ok_or(UniformError::Shape)?;
    if rounds.len() != row_point.len() || opened_values.len() != relation.column_count() {
        return Err(UniformError::Shape);
    }
    let mut claim = NativeField::from_u64(0);
    let mut opening_point = Vec::with_capacity(rounds.len());
    for (round_index, message) in rounds.iter().enumerate() {
        if message.len() != expected_message_len {
            return Err(UniformError::Sumcheck);
        }
        let at_zero = message.first().copied().ok_or(UniformError::Sumcheck)?;
        let at_one = message.get(1).copied().ok_or(UniformError::Sumcheck)?;
        if at_zero + at_one != claim {
            return Err(UniformError::Sumcheck);
        }
        absorb_round(transcript, round_index, message)?;
        let challenge = transcript.challenge_scalar(b"sumcheck-round");
        claim = evaluate_lagrange(message, challenge)?;
        opening_point.push(challenge);
    }
    let terminal_weight = equality_evaluation(row_point, &opening_point)?;
    let terminal_relation = combined_relation(relation, opened_values, constraint_mix)?;
    if claim != terminal_weight * terminal_relation {
        return Err(UniformError::TerminalMismatch);
    }
    Ok(opening_point)
}

fn sumcheck_round(
    relation: &impl UniformRelation,
    columns: &[Vec<NativeField>],
    weights: &[NativeField],
    constraint_mix: NativeField,
    evaluation_count: usize,
) -> Result<Vec<NativeField>, UniformError> {
    if columns.iter().any(|column| column.len() != weights.len())
        || weights.len() < 2
        || !weights.len().is_multiple_of(2)
    {
        return Err(UniformError::Shape);
    }
    let zero = NativeField::from_u64(0);
    let mut message = vec![zero; evaluation_count];
    for (point_index, evaluation) in message.iter_mut().enumerate() {
        let point =
            NativeField::from_u64(u64::try_from(point_index).map_err(|_| UniformError::Shape)?);
        for pair_index in 0..(weights.len() / 2) {
            let row = interpolate_row(columns, pair_index, point)?;
            let weight = interpolate_pair(weights, pair_index, point)?;
            *evaluation += weight * combined_relation(relation, &row, constraint_mix)?;
        }
    }
    Ok(message)
}

fn interpolate_row(
    columns: &[Vec<NativeField>],
    pair_index: usize,
    point: NativeField,
) -> Result<Vec<NativeField>, UniformError> {
    columns
        .iter()
        .map(|column| interpolate_pair(column, pair_index, point))
        .collect()
}

fn interpolate_pair(
    values: &[NativeField],
    pair_index: usize,
    point: NativeField,
) -> Result<NativeField, UniformError> {
    let start = pair_index.checked_mul(2).ok_or(UniformError::Shape)?;
    let low = values.get(start).copied().ok_or(UniformError::Shape)?;
    let high = values
        .get(start.checked_add(1).ok_or(UniformError::Shape)?)
        .copied()
        .ok_or(UniformError::Shape)?;
    Ok(low + point * (high - low))
}

fn combined_relation(
    relation: &impl UniformRelation,
    row: &[NativeField],
    constraint_mix: NativeField,
) -> Result<NativeField, UniformError> {
    if row.len() != relation.column_count() {
        return Err(UniformError::Shape);
    }
    let zero = NativeField::from_u64(0);
    let mut constraints = vec![zero; relation.constraint_count()];
    relation.evaluate(row, &mut constraints)?;
    let mut power = NativeField::from_u64(1);
    let mut combined = zero;
    for constraint in constraints {
        combined += power * constraint;
        power *= constraint_mix;
    }
    Ok(combined)
}

fn fold_columns(
    columns: &mut [Vec<NativeField>],
    challenge: NativeField,
) -> Result<(), UniformError> {
    for column in columns {
        fold_column(column, challenge)?;
    }
    Ok(())
}

fn fold_column(values: &mut Vec<NativeField>, challenge: NativeField) -> Result<(), UniformError> {
    if values.len() < 2 || !values.len().is_multiple_of(2) {
        return Err(UniformError::Shape);
    }
    let mut folded = Vec::with_capacity(values.len() / 2);
    for pair in values.chunks_exact(2) {
        let [low, high] = pair else {
            return Err(UniformError::Shape);
        };
        folded.push(*low + challenge * (*high - *low));
    }
    *values = folded;
    Ok(())
}

fn evaluate_lagrange(
    evaluations: &[NativeField],
    point: NativeField,
) -> Result<NativeField, UniformError> {
    if evaluations.is_empty() {
        return Err(UniformError::Sumcheck);
    }
    let mut result = NativeField::from_u64(0);
    for (index, evaluation) in evaluations.iter().enumerate() {
        let index_field =
            NativeField::from_u64(u64::try_from(index).map_err(|_| UniformError::Shape)?);
        let mut numerator = NativeField::from_u64(1);
        let mut denominator = NativeField::from_u64(1);
        for other in 0..evaluations.len() {
            if other == index {
                continue;
            }
            let other_field =
                NativeField::from_u64(u64::try_from(other).map_err(|_| UniformError::Shape)?);
            numerator *= point - other_field;
            denominator *= index_field - other_field;
        }
        let inverse = denominator
            .inverse()
            .ok_or(UniformError::NonInvertibleInterpolation)?;
        result += *evaluation * numerator * inverse;
    }
    Ok(result)
}

fn equality_evaluation(
    left: &[NativeField],
    right: &[NativeField],
) -> Result<NativeField, UniformError> {
    if left.len() != right.len() {
        return Err(UniformError::Shape);
    }
    let one = NativeField::from_u64(1);
    Ok(left
        .iter()
        .copied()
        .zip(right.iter().copied())
        .fold(one, |product, (left, right)| {
            product * (left * right + (one - left) * (one - right))
        }))
}

fn absorb_round(
    transcript: &mut AkitaTranscript<NativeField>,
    round_index: usize,
    message: &[NativeField],
) -> Result<(), UniformError> {
    let index = u64::try_from(round_index).map_err(|_| UniformError::Shape)?;
    transcript.append_bytes(b"sumcheck-round-index", &index.to_le_bytes());
    for value in message {
        transcript.append_field(b"sumcheck-round-evaluation", value);
    }
    Ok(())
}

fn push_usize(bytes: &mut Vec<u8>, value: usize) -> Result<(), UniformError> {
    let value = u64::try_from(value).map_err(|_| UniformError::Shape)?;
    bytes.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), UniformError> {
    push_usize(bytes, value.len())?;
    bytes.extend_from_slice(value);
    Ok(())
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
        commitment::{SCHEDULE_ARTIFACT, scheme},
        prove_uniform, prove_uniform_committed, verify_uniform, verify_uniform_committed,
    };
    use akita_pcs::Ring;
    use sha2::{Digest, Sha256};

    struct BooleanColumn;

    struct EdgeEqualityColumns<const N: usize>;

    #[test]
    fn pinned_schedule_has_only_the_frozen_group_shape() -> Result<(), UniformError> {
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
        assert!(precommitted.is_empty());
        assert_eq!(
            format!("{:x}", Sha256::digest(SCHEDULE_ARTIFACT)),
            crate::AKITA_SCHEDULE_SHA256
        );
        Ok(())
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
    fn malformed_or_unsatisfied_witness_fails_before_commitment() -> Result<(), UniformError> {
        assert!(matches!(
            prove_uniform(&BooleanColumn, &[vec![0, 1, 0]]),
            Err(UniformError::Shape)
        ));
        let mut unsatisfied = vec![0; UNIFORM_ROW_COUNT];
        *unsatisfied.get_mut(2).ok_or(UniformError::Shape)? = 2;
        assert!(matches!(
            prove_uniform(&BooleanColumn, &[unsatisfied]),
            Err(UniformError::WitnessUnsatisfied {
                row: 2,
                constraint: 0
            })
        ));
        Ok(())
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
