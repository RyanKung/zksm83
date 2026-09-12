//! Committed row ordering and public semantic-boundary claim.

#[cfg(test)]
mod tests;

use akita_pcs::{AkitaTranscript, Ring, Transcript};
use jolt_field::{CanonicalBytes, Field};
use thiserror::Error;

use crate::{
    AKITA_SCHEDULE_SHA256, AkitaWorkerError, NativeField, NativeStateBoundary, NativeTraceWitness,
    PROTOCOL_ID, STATE_SCALAR_COUNT, TRACE_ACTIVE, TRACE_AFTER_STATE_START,
    TRACE_BEFORE_STATE_START, TRACE_ROW_BIT_COUNT, TRACE_ROW_BITS_START, UNIFORM_NUM_VARIABLES,
    UNIFORM_ROW_COUNT, UniformError, UniformRelation, WitnessCommitments,
    pcs::OpeningProof,
    uniform::{
        CommittedWitness, CompositeUniformRelationProof, prove_uniform_composite,
        prove_witness_opening, verify_uniform_composite, verify_witness_opening,
    },
};

const CLAIM_DOMAIN: &[u8] = b"zksm83/native-execution-claim/v1";
const CHALLENGE_DOMAIN: &[u8] = b"zksm83-native-continuity-challenges/v1";
const SUM_DOMAIN: &[u8] = b"zksm83-native-continuity-sum/v1";
const INVERSE_COLUMN_COUNT: usize = 4;

/// Public semantic claim for one fixed-capacity native trace segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeExecutionClaim {
    active_row_count: u64,
    initial_state: NativeStateBoundary,
    final_state: NativeStateBoundary,
}

/// Transparent proof that active rows form one ordered state-transition chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuityProof {
    pub(crate) inverse_commitments: WitnessCommitments,
    pub(crate) relation: CompositeUniformRelationProof,
    pub(crate) sum: ContinuitySumProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContinuitySumProof {
    pub(crate) values: Vec<NativeField>,
    pub(crate) opening: OpeningProof,
}

#[derive(Clone, Copy)]
struct ContinuityChallenges {
    state_mix: NativeField,
    inverse_point: NativeField,
}

/// Invalid public boundary, discontinuous committed trace, or proof operation.
#[derive(Debug, Error)]
pub enum ContinuityError {
    /// The public row count or a proof vector has an invalid shape.
    #[error("native continuity claim or proof shape is invalid")]
    Shape,
    /// A Fiat-Shamir challenge required by the ordering argument was zero.
    #[error("native continuity Fiat-Shamir challenge is zero")]
    ZeroChallenge,
    /// A compressed state token collided with the inverse evaluation point.
    #[error("native continuity inverse denominator is zero")]
    ZeroDenominator,
    /// The committed rows do not form the claimed ordered boundary chain.
    #[error("native continuity relation is unsatisfied")]
    Unsatisfied,
    /// The shared uniform relation or Akita opening was rejected.
    #[error(transparent)]
    Uniform(#[from] UniformError),
    /// The operating system rejected creation of the bounded opening worker.
    #[error("failed to start native continuity worker: {0}")]
    WorkerSpawn(#[source] std::io::Error),
    /// The bounded opening worker panicked and its result was rejected.
    #[error("native continuity worker terminated unexpectedly")]
    WorkerPanicked,
}

impl NativeExecutionClaim {
    /// Creates a checked public segment claim.
    pub fn new(
        active_row_count: u64,
        initial_state: NativeStateBoundary,
        final_state: NativeStateBoundary,
    ) -> Result<Self, ContinuityError> {
        let claim = Self {
            active_row_count,
            initial_state,
            final_state,
        };
        claim.validate()?;
        Ok(claim)
    }

    /// Derives the exact claim represented by a prover-side trace witness.
    pub fn from_trace(trace: &NativeTraceWitness) -> Result<Self, ContinuityError> {
        Self::new(
            u64::try_from(trace.active_row_count()).map_err(|_| ContinuityError::Shape)?,
            NativeStateBoundary::from_vm_state(trace.initial_state()),
            NativeStateBoundary::from_vm_state(trace.final_state()),
        )
    }

    /// Returns the exact number of non-padding rows.
    #[must_use]
    pub const fn active_row_count(&self) -> u64 {
        self.active_row_count
    }

    /// Returns the claimed first pre-state.
    #[must_use]
    pub const fn initial_state(&self) -> NativeStateBoundary {
        self.initial_state
    }

    /// Returns the claimed last post-state.
    #[must_use]
    pub const fn final_state(&self) -> NativeStateBoundary {
        self.final_state
    }

    /// Returns the canonical protocol encoding of this public claim.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(24 + 16 * STATE_SCALAR_COUNT);
        append_bytes_infallible(&mut bytes, CLAIM_DOMAIN);
        bytes.extend_from_slice(&self.active_row_count.to_le_bytes());
        self.initial_state.append_canonical_bytes(&mut bytes);
        self.final_state.append_canonical_bytes(&mut bytes);
        bytes
    }

    pub(crate) fn validate(&self) -> Result<(), ContinuityError> {
        let capacity = u64::try_from(UNIFORM_ROW_COUNT).map_err(|_| ContinuityError::Shape)?;
        if self.active_row_count == 0 || self.active_row_count > capacity {
            return Err(ContinuityError::Shape);
        }
        Ok(())
    }
}

/// Proves exact initial/final states, active-row prefix, and row adjacency.
pub fn prove_continuity(
    trace: &NativeTraceWitness,
    trace_witness: &CommittedWitness,
    claim: &NativeExecutionClaim,
) -> Result<ContinuityProof, ContinuityError> {
    claim.validate()?;
    let phase_one = phase_one_descriptor(trace_witness.commitments(), claim)?;
    let challenges = challenges(&phase_one)?;
    let inverse_columns = inverse_columns(trace.columns(), challenges)?;
    let inverses = crate::commit_witness(&inverse_columns)?;
    let relation = ContinuityRelation { challenges };
    let relation_proof = prove_uniform_composite(&relation, trace_witness, &inverses)?;
    let full = full_descriptor(&phase_one, inverses.commitments())?;
    let sum = on_worker(|| prove_sum(&inverses, claim, challenges, &full))?;
    Ok(ContinuityProof {
        inverse_commitments: inverses.into_commitments(),
        relation: relation_proof,
        sum,
    })
}

/// Verifies continuity without receiving trace rows or replaying the emulator.
pub fn verify_continuity(
    proof: &ContinuityProof,
    trace: &WitnessCommitments,
    claim: &NativeExecutionClaim,
) -> Result<(), ContinuityError> {
    claim.validate()?;
    let phase_one = phase_one_descriptor(trace, claim)?;
    let challenges = challenges(&phase_one)?;
    let relation = ContinuityRelation { challenges };
    verify_uniform_composite(
        &relation,
        trace,
        &proof.inverse_commitments,
        &proof.relation,
    )?;
    let full = full_descriptor(&phase_one, &proof.inverse_commitments)?;
    on_worker(|| {
        verify_sum(
            &proof.sum,
            &proof.inverse_commitments,
            claim,
            challenges,
            &full,
        )
    })
}

fn on_worker<T: Send>(
    operation: impl FnOnce() -> Result<T, ContinuityError> + Send,
) -> Result<T, ContinuityError> {
    match crate::on_akita_worker(operation) {
        Ok(result) => result,
        Err(AkitaWorkerError::Spawn(error)) => Err(ContinuityError::WorkerSpawn(error)),
        Err(AkitaWorkerError::Panicked) => Err(ContinuityError::WorkerPanicked),
    }
}

struct ContinuityRelation {
    challenges: ContinuityChallenges,
}

impl UniformRelation for ContinuityRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-continuity-inverses/v1"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut bytes = field_bytes(self.challenges.state_mix);
        bytes.extend_from_slice(&field_bytes(self.challenges.inverse_point));
        bytes
    }

    fn column_count(&self) -> usize {
        crate::NATIVE_TRACE_COLUMN_COUNT + INVERSE_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        2
    }

    fn max_constraint_degree(&self) -> usize {
        2
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != self.column_count() || constraints.len() != 2 {
            return Err(UniformError::Shape);
        }
        let active = value(row, TRACE_ACTIVE)?;
        let row_index = packed(row, TRACE_ROW_BITS_START, TRACE_ROW_BIT_COUNT)?;
        let after = state_token_from_row(
            row,
            TRACE_AFTER_STATE_START,
            row_index + NativeField::from_u64(1),
            self.challenges.state_mix,
        )?;
        let before = state_token_from_row(
            row,
            TRACE_BEFORE_STATE_START,
            row_index,
            self.challenges.state_mix,
        )?;
        let after_inverse = inverse_from_row(row, crate::NATIVE_TRACE_COLUMN_COUNT)?;
        let before_inverse = inverse_from_row(row, crate::NATIVE_TRACE_COLUMN_COUNT + 2)?;
        *constraints.get_mut(0).ok_or(UniformError::Shape)? =
            (self.challenges.inverse_point - after) * after_inverse - active;
        *constraints.get_mut(1).ok_or(UniformError::Shape)? =
            (self.challenges.inverse_point - before) * before_inverse - active;
        Ok(())
    }
}

fn inverse_columns(
    trace: &[Vec<u64>],
    challenges: ContinuityChallenges,
) -> Result<Vec<Vec<u64>>, ContinuityError> {
    if trace.len() != crate::NATIVE_TRACE_COLUMN_COUNT {
        return Err(ContinuityError::Shape);
    }
    let mut columns = (0..INVERSE_COLUMN_COUNT)
        .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
        .collect::<Vec<_>>();
    for row in 0..UNIFORM_ROW_COUNT {
        let active = trace_value(trace, TRACE_ACTIVE, row)?;
        let row_tag =
            NativeField::from_u64(u64::try_from(row).map_err(|_| ContinuityError::Shape)?);
        let after = state_token_from_trace(
            trace,
            TRACE_AFTER_STATE_START,
            row,
            row_tag + NativeField::from_u64(1),
            challenges.state_mix,
        )?;
        let before = state_token_from_trace(
            trace,
            TRACE_BEFORE_STATE_START,
            row,
            row_tag,
            challenges.state_mix,
        )?;
        push_inverse(
            &mut columns,
            0,
            selected_inverse(active, after, challenges)?,
        )?;
        push_inverse(
            &mut columns,
            2,
            selected_inverse(active, before, challenges)?,
        )?;
    }
    Ok(columns)
}

fn selected_inverse(
    selector: u64,
    token: NativeField,
    challenges: ContinuityChallenges,
) -> Result<NativeField, ContinuityError> {
    if selector == 0 {
        return Ok(NativeField::from_u64(0));
    }
    let selector = NativeField::from_u64(selector);
    Ok(selector * inverse(challenges.inverse_point - token)?)
}

fn push_inverse(
    columns: &mut [Vec<u64>],
    offset: usize,
    inverse: NativeField,
) -> Result<(), ContinuityError> {
    let [low, high] = split_field(inverse)?;
    columns
        .get_mut(offset)
        .ok_or(ContinuityError::Shape)?
        .push(low);
    columns
        .get_mut(offset + 1)
        .ok_or(ContinuityError::Shape)?
        .push(high);
    Ok(())
}

fn prove_sum(
    inverses: &CommittedWitness,
    claim: &NativeExecutionClaim,
    challenges: ContinuityChallenges,
    full_descriptor: &[u8],
) -> Result<ContinuitySumProof, ContinuityError> {
    let descriptor = sum_descriptor(full_descriptor)?;
    let point = half_point()?;
    let values = inverses
        .field_columns()
        .iter()
        .map(|column| evaluate_field_column(column, &point))
        .collect::<Result<Vec<_>, _>>()?;
    check_sum(&values, claim, challenges)?;
    let opening = prove_witness_opening(inverses, &point, &values, &descriptor)?;
    Ok(ContinuitySumProof { values, opening })
}

fn verify_sum(
    proof: &ContinuitySumProof,
    inverses: &WitnessCommitments,
    claim: &NativeExecutionClaim,
    challenges: ContinuityChallenges,
    full_descriptor: &[u8],
) -> Result<(), ContinuityError> {
    let descriptor = sum_descriptor(full_descriptor)?;
    let point = half_point()?;
    verify_witness_opening(inverses, &point, &proof.values, &descriptor, &proof.opening)?;
    check_sum(&proof.values, claim, challenges)
}

fn check_sum(
    values: &[NativeField],
    claim: &NativeExecutionClaim,
    challenges: ContinuityChallenges,
) -> Result<(), ContinuityError> {
    if values.len() != INVERSE_COLUMN_COUNT {
        return Err(ContinuityError::Shape);
    }
    let after = join_limbs(value(values, 0)?, value(values, 1)?);
    let before = join_limbs(value(values, 2)?, value(values, 3)?);
    let initial = state_token_from_boundary(
        claim.initial_state(),
        NativeField::from_u64(0),
        challenges.state_mix,
    );
    let final_state = state_token_from_boundary(
        claim.final_state(),
        NativeField::from_u64(claim.active_row_count()),
        challenges.state_mix,
    );
    let initial_inverse = inverse(challenges.inverse_point - initial)?;
    let final_inverse = inverse(challenges.inverse_point - final_state)?;
    let rows = NativeField::from_u64(
        u64::try_from(UNIFORM_ROW_COUNT).map_err(|_| ContinuityError::Shape)?,
    );
    if rows * (after - before) + initial_inverse - final_inverse != NativeField::from_u64(0) {
        return Err(ContinuityError::Unsatisfied);
    }
    Ok(())
}

fn state_token_from_boundary(
    boundary: NativeStateBoundary,
    tag: NativeField,
    mix: NativeField,
) -> NativeField {
    boundary
        .scalars()
        .iter()
        .copied()
        .fold((tag, mix), |(token, power), scalar| {
            (token + power * NativeField::from_u64(scalar), power * mix)
        })
        .0
}

fn state_token_from_row(
    row: &[NativeField],
    start: usize,
    tag: NativeField,
    mix: NativeField,
) -> Result<NativeField, UniformError> {
    let mut token = tag;
    let mut power = mix;
    for offset in 0..STATE_SCALAR_COUNT {
        token += power * value(row, start + offset)?;
        power *= mix;
    }
    Ok(token)
}

fn state_token_from_trace(
    trace: &[Vec<u64>],
    start: usize,
    row: usize,
    tag: NativeField,
    mix: NativeField,
) -> Result<NativeField, ContinuityError> {
    let mut token = tag;
    let mut power = mix;
    for offset in 0..STATE_SCALAR_COUNT {
        token += power * NativeField::from_u64(trace_value(trace, start + offset, row)?);
        power *= mix;
    }
    Ok(token)
}

fn phase_one_descriptor(
    trace: &WitnessCommitments,
    claim: &NativeExecutionClaim,
) -> Result<Vec<u8>, ContinuityError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, PROTOCOL_ID.as_bytes())?;
    push_bytes(&mut descriptor, AKITA_SCHEDULE_SHA256.as_bytes())?;
    push_bytes(&mut descriptor, &trace.canonical_bytes()?)?;
    push_bytes(&mut descriptor, &claim.canonical_bytes())?;
    Ok(descriptor)
}

fn full_descriptor(
    phase_one: &[u8],
    inverses: &WitnessCommitments,
) -> Result<Vec<u8>, ContinuityError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, phase_one)?;
    push_bytes(&mut descriptor, &inverses.canonical_bytes()?)?;
    Ok(descriptor)
}

fn challenges(descriptor: &[u8]) -> Result<ContinuityChallenges, ContinuityError> {
    let mut transcript = AkitaTranscript::<NativeField>::unbound_verifier(CHALLENGE_DOMAIN);
    transcript.bind_instance_bytes(descriptor);
    let state_mix = transcript.challenge_scalar(b"state-mix");
    let inverse_point = transcript.challenge_scalar(b"inverse-point");
    if state_mix == NativeField::from_u64(0) {
        return Err(ContinuityError::ZeroChallenge);
    }
    Ok(ContinuityChallenges {
        state_mix,
        inverse_point,
    })
}

fn sum_descriptor(full: &[u8]) -> Result<Vec<u8>, ContinuityError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, SUM_DOMAIN)?;
    push_bytes(&mut descriptor, full)?;
    Ok(descriptor)
}

fn half_point() -> Result<Vec<NativeField>, ContinuityError> {
    let half = NativeField::from_u64(2)
        .inverse()
        .ok_or(ContinuityError::ZeroChallenge)?;
    Ok(vec![half; UNIFORM_NUM_VARIABLES])
}

fn evaluate_field_column(
    values: &[NativeField],
    point: &[NativeField],
) -> Result<NativeField, ContinuityError> {
    if values.len() != 1_usize << point.len() {
        return Err(ContinuityError::Shape);
    }
    let mut folded = values.to_vec();
    for coordinate in point {
        let mut next = Vec::with_capacity(folded.len() / 2);
        for pair in folded.chunks_exact(2) {
            let zero = pair.first().copied().ok_or(ContinuityError::Shape)?;
            let one = pair.get(1).copied().ok_or(ContinuityError::Shape)?;
            next.push(zero + *coordinate * (one - zero));
        }
        folded = next;
    }
    folded.first().copied().ok_or(ContinuityError::Shape)
}

fn trace_value(trace: &[Vec<u64>], column: usize, row: usize) -> Result<u64, ContinuityError> {
    trace
        .get(column)
        .and_then(|values| values.get(row))
        .copied()
        .ok_or(ContinuityError::Shape)
}

fn packed(row: &[NativeField], start: usize, width: usize) -> Result<NativeField, UniformError> {
    let mut packed_value = NativeField::from_u64(0);
    let mut power = NativeField::from_u64(1);
    for bit in 0..width {
        packed_value += power * value(row, start + bit)?;
        power += power;
    }
    Ok(packed_value)
}

fn inverse_from_row(row: &[NativeField], start: usize) -> Result<NativeField, UniformError> {
    Ok(join_limbs(value(row, start)?, value(row, start + 1)?))
}

fn inverse(value: NativeField) -> Result<NativeField, ContinuityError> {
    value.inverse().ok_or(ContinuityError::ZeroDenominator)
}

fn split_field(value: NativeField) -> Result<[u64; 2], ContinuityError> {
    let bytes = value.to_bytes_le_vec();
    let low = <[u8; 8]>::try_from(bytes.get(..8).ok_or(ContinuityError::Shape)?)
        .map_err(|_| ContinuityError::Shape)?;
    let high = <[u8; 8]>::try_from(bytes.get(8..16).ok_or(ContinuityError::Shape)?)
        .map_err(|_| ContinuityError::Shape)?;
    Ok([u64::from_le_bytes(low), u64::from_le_bytes(high)])
}

fn join_limbs(low: NativeField, high: NativeField) -> NativeField {
    low + (NativeField::from_u64(u64::MAX) + NativeField::from_u64(1)) * high
}

fn value(values: &[NativeField], index: usize) -> Result<NativeField, UniformError> {
    values.get(index).copied().ok_or(UniformError::Shape)
}

fn push_bytes(target: &mut Vec<u8>, value: &[u8]) -> Result<(), ContinuityError> {
    let length = u64::try_from(value.len()).map_err(|_| ContinuityError::Shape)?;
    target.extend_from_slice(&length.to_le_bytes());
    target.extend_from_slice(value);
    Ok(())
}

fn append_bytes_infallible(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_le_bytes());
    target.extend_from_slice(value);
}

fn field_bytes(value: NativeField) -> Vec<u8> {
    value.to_bytes_le_vec()
}
