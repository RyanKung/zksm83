//! Committed row ordering and public semantic-boundary claim.

#[cfg(test)]
mod tests;

use akita_pcs::{AkitaTranscript, Ring, Transcript};
use jolt_field::{CanonicalBytes, Field};
use thiserror::Error;
use zksm83_trace::BASIC_BLOCK_INSTRUCTION_BOUND;

use crate::{
    AkitaWorkerError, BLOCK_CPU_COLUMN_COUNT, BLOCK_ROUTING_COLUMN_COUNT, BlockCpuWitness,
    ConstraintOutput, NativeField, NativeProtocolVersion, NativeStateBoundary, STATE_SCALAR_COUNT,
    TRACE_ROW_BIT_COUNT, UNIFORM_NUM_VARIABLES, UNIFORM_ROW_COUNT, UniformError, UniformRelation,
    WitnessCommitments,
    block_boundary::{BLOCK_LOCAL_STATE_SCALAR_COUNT, device_state_column, local_state_column},
    block_memory::BLOCK_MEMORY_ROW_BITS_START,
    field_batch::{FieldBatchError, SelectedDenominator, selected_inverse_columns},
    pcs::OpeningProof,
    uniform::{
        CommittedWitness, CompositeUniformRelationProof, prove_uniform_composite,
        prove_witness_opening, verify_uniform_composite_for_protocol,
        verify_witness_opening_for_protocol,
    },
};

const CLAIM_DOMAIN_V2: &[u8] = b"zksm83/native-execution-claim/v2";
const PACKED_LAYOUT_DOMAIN: &[u8] = b"zksm83/native-block-continuity-layout/v2";
const PACKED_CHALLENGE_DOMAIN: &[u8] = b"zksm83-native-block-continuity-challenges/v2";
const PACKED_SUM_DOMAIN: &[u8] = b"zksm83-native-block-continuity-sum/v2";
const PACKED_INVERSE_COLUMN_COUNT: usize = 5;

/// Public semantic claim for one fixed-capacity native trace segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeExecutionClaim {
    active_row_count: u64,
    transition_count: u64,
    initial_state: NativeStateBoundary,
    final_state: NativeStateBoundary,
}

/// Transparent v2 proof that packed blocks form one ordered state chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackedContinuityProof {
    pub(crate) inverse_commitments: WitnessCommitments,
    pub(crate) relation: CompositeUniformRelationProof,
    pub(crate) sum: ContinuitySumProof,
}

pub(crate) struct PreparedPackedContinuity {
    inverses: CommittedWitness,
    phase_one: Vec<u8>,
    challenges: ContinuityChallenges,
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
        transition_count: u64,
        initial_state: NativeStateBoundary,
        final_state: NativeStateBoundary,
    ) -> Result<Self, ContinuityError> {
        let claim = Self {
            active_row_count,
            transition_count,
            initial_state,
            final_state,
        };
        claim.validate()?;
        Ok(claim)
    }

    /// Derives the exact public claim represented by a packed-block witness.
    pub fn from_packed_trace(trace: &BlockCpuWitness) -> Result<Self, ContinuityError> {
        Self::new(
            u64::try_from(trace.active_block_count()).map_err(|_| ContinuityError::Shape)?,
            u64::try_from(trace.transition_count()).map_err(|_| ContinuityError::Shape)?,
            NativeStateBoundary::from_vm_state(trace.initial_state()),
            NativeStateBoundary::from_vm_state(trace.final_state()),
        )
    }

    /// Returns the exact number of non-padding rows.
    #[must_use]
    pub const fn active_row_count(&self) -> u64 {
        self.active_row_count
    }

    /// Returns the exact number of source machine transitions represented.
    #[must_use]
    pub const fn transition_count(&self) -> u64 {
        self.transition_count
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
        self.canonical_bytes_for(NativeProtocolVersion::current())
    }

    pub(crate) fn canonical_bytes_for(&self, protocol: NativeProtocolVersion) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(24 + 16 * STATE_SCALAR_COUNT);
        let domain = match protocol {
            NativeProtocolVersion::V2 => CLAIM_DOMAIN_V2,
        };
        append_bytes_infallible(&mut bytes, domain);
        bytes.extend_from_slice(&self.active_row_count.to_le_bytes());
        bytes.extend_from_slice(&self.transition_count.to_le_bytes());
        self.initial_state.append_canonical_bytes(&mut bytes);
        self.final_state.append_canonical_bytes(&mut bytes);
        bytes
    }

    pub(crate) fn validate(&self) -> Result<(), ContinuityError> {
        let capacity = u64::try_from(UNIFORM_ROW_COUNT).map_err(|_| ContinuityError::Shape)?;
        let maximum_transitions = self
            .active_row_count
            .checked_mul(BASIC_BLOCK_INSTRUCTION_BOUND as u64)
            .ok_or(ContinuityError::Shape)?;
        if self.active_row_count == 0
            || self.active_row_count > capacity
            || self.transition_count < self.active_row_count
            || self.transition_count > maximum_transitions
        {
            return Err(ContinuityError::Shape);
        }
        Ok(())
    }
}

/// Proves exact packed initial/final states, active prefix, and block adjacency.
pub fn prove_packed_continuity(
    trace: &BlockCpuWitness,
    trace_witness: &CommittedWitness,
    claim: &NativeExecutionClaim,
) -> Result<PackedContinuityProof, ContinuityError> {
    let prepared = prepare_packed_continuity(trace, trace_witness, claim)?;
    prove_prepared_packed_continuity(prepared, trace_witness, claim)
}

pub(crate) fn prepare_packed_continuity(
    trace: &BlockCpuWitness,
    trace_witness: &CommittedWitness,
    claim: &NativeExecutionClaim,
) -> Result<PreparedPackedContinuity, ContinuityError> {
    let protocol = NativeProtocolVersion::current();
    let layout = ContinuityLayout::Packed;
    claim.validate()?;
    let phase_one = phase_one_descriptor(protocol, layout, trace_witness.commitments(), claim)?;
    let challenges = challenges(protocol, layout, &phase_one)?;
    let inverse_columns = inverse_columns(trace.columns(), layout, challenges)?;
    let inverses = crate::commit_witness(&inverse_columns)?;
    Ok(PreparedPackedContinuity {
        inverses,
        phase_one,
        challenges,
    })
}

pub(crate) fn prove_prepared_packed_continuity(
    prepared: PreparedPackedContinuity,
    trace_witness: &CommittedWitness,
    claim: &NativeExecutionClaim,
) -> Result<PackedContinuityProof, ContinuityError> {
    let protocol = NativeProtocolVersion::current();
    let layout = ContinuityLayout::Packed;
    let PreparedPackedContinuity {
        inverses,
        phase_one,
        challenges,
    } = prepared;
    let relation = ContinuityRelation::new(layout, challenges);
    let relation_proof = prove_uniform_composite(&relation, trace_witness, &inverses)?;
    let full = full_descriptor(protocol, &phase_one, inverses.commitments())?;
    let sum = on_worker(|| prove_sum(protocol, layout, &inverses, claim, challenges, &full))?;
    Ok(PackedContinuityProof {
        inverse_commitments: inverses.into_commitments(),
        relation: relation_proof,
        sum,
    })
}

/// Verifies packed-block continuity without receiving rows or replaying execution.
pub fn verify_packed_continuity(
    proof: &PackedContinuityProof,
    trace: &WitnessCommitments,
    claim: &NativeExecutionClaim,
) -> Result<(), ContinuityError> {
    verify_packed_continuity_for_protocol(NativeProtocolVersion::current(), proof, trace, claim)
}

pub(crate) fn verify_packed_continuity_for_protocol(
    protocol: NativeProtocolVersion,
    proof: &PackedContinuityProof,
    trace: &WitnessCommitments,
    claim: &NativeExecutionClaim,
) -> Result<(), ContinuityError> {
    verify_for_layout(
        protocol,
        ContinuityLayout::Packed,
        &proof.inverse_commitments,
        &proof.relation,
        &proof.sum,
        trace,
        claim,
    )
}

fn verify_for_layout(
    protocol: NativeProtocolVersion,
    layout: ContinuityLayout,
    inverse_commitments: &WitnessCommitments,
    relation_proof: &CompositeUniformRelationProof,
    sum: &ContinuitySumProof,
    trace: &WitnessCommitments,
    claim: &NativeExecutionClaim,
) -> Result<(), ContinuityError> {
    claim.validate()?;
    let phase_one = phase_one_descriptor(protocol, layout, trace, claim)?;
    let challenges = challenges(protocol, layout, &phase_one)?;
    let relation = ContinuityRelation::new(layout, challenges);
    verify_uniform_composite_for_protocol(
        protocol,
        &relation,
        trace,
        inverse_commitments,
        relation_proof,
    )?;
    let full = full_descriptor(protocol, &phase_one, inverse_commitments)?;
    on_worker(|| {
        verify_sum(
            protocol,
            layout,
            sum,
            inverse_commitments,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContinuityLayout {
    Packed,
}

impl ContinuityLayout {
    const fn trace_column_count(self) -> usize {
        BLOCK_CPU_COLUMN_COUNT
    }

    const fn active_column(self) -> usize {
        crate::block_metadata::BLOCK_ACTIVE
    }

    const fn inverse_column_count(self) -> usize {
        PACKED_INVERSE_COLUMN_COUNT
    }

    const fn row_bits_start(self) -> usize {
        BLOCK_MEMORY_ROW_BITS_START
    }

    fn state_column(self, after: bool, scalar: usize) -> Option<usize> {
        let relative = if scalar < BLOCK_LOCAL_STATE_SCALAR_COUNT {
            let boundary = if after {
                BASIC_BLOCK_INSTRUCTION_BOUND
            } else {
                0
            };
            local_state_column(boundary, scalar)
        } else {
            device_state_column(after, scalar)
        }?;
        BLOCK_ROUTING_COLUMN_COUNT.checked_add(relative)
    }
}

struct ContinuityRelation {
    layout: ContinuityLayout,
    challenges: ContinuityChallenges,
    state_mix_powers: [NativeField; STATE_SCALAR_COUNT],
}

impl ContinuityRelation {
    fn new(layout: ContinuityLayout, challenges: ContinuityChallenges) -> Self {
        Self {
            layout,
            challenges,
            state_mix_powers: state_mix_powers(challenges.state_mix),
        }
    }
}

impl UniformRelation for ContinuityRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-continuity-inverses/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut bytes = field_bytes(self.challenges.state_mix);
        bytes.extend_from_slice(&field_bytes(self.challenges.inverse_point));
        bytes.extend_from_slice(&(BLOCK_CPU_COLUMN_COUNT as u64).to_le_bytes());
        bytes.extend_from_slice(&(STATE_SCALAR_COUNT as u64).to_le_bytes());
        bytes.extend_from_slice(&(TRACE_ROW_BIT_COUNT as u64).to_le_bytes());
        bytes.extend_from_slice(&(PACKED_INVERSE_COLUMN_COUNT as u64).to_le_bytes());
        bytes.extend_from_slice(&7_u64.to_le_bytes());
        bytes
    }

    fn column_count(&self) -> usize {
        self.layout.trace_column_count() + self.layout.inverse_column_count()
    }

    fn constraint_count(&self) -> usize {
        self.layout.inverse_column_count() - 2
    }

    fn max_constraint_degree(&self) -> usize {
        2
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != self.column_count() || constraints.len() != self.constraint_count() {
            return Err(UniformError::Shape);
        }
        let active = value(row, self.layout.active_column())?;
        let row_index = packed(row, self.layout.row_bits_start(), TRACE_ROW_BIT_COUNT)?;
        let after = state_token_from_layout_row(
            row,
            self.layout,
            true,
            row_index + NativeField::from_u64(1),
            &self.state_mix_powers,
        )?;
        let before = state_token_from_layout_row(
            row,
            self.layout,
            false,
            row_index,
            &self.state_mix_powers,
        )?;
        let trace_columns = self.layout.trace_column_count();
        let after_inverse = inverse_from_row(row, trace_columns)?;
        let before_inverse = inverse_from_row(row, trace_columns + 2)?;
        *constraints.get_mut(0).ok_or(UniformError::Shape)? =
            (self.challenges.inverse_point - after) * after_inverse - active;
        *constraints.get_mut(1).ok_or(UniformError::Shape)? =
            (self.challenges.inverse_point - before) * before_inverse - active;
        let transition = value(row, trace_columns + 4)?;
        let instruction = value(row, crate::block_metadata::INSTRUCTION_BLOCK)?;
        let mut expected = active - instruction;
        for lane in 0..BASIC_BLOCK_INSTRUCTION_BOUND {
            let column = crate::block_metadata::lane_column(lane).ok_or(UniformError::Shape)?;
            expected += value(row, column)?;
        }
        *constraints.get_mut(2).ok_or(UniformError::Shape)? = transition - expected;
        Ok(())
    }
}

fn inverse_columns(
    trace: &[Vec<u64>],
    layout: ContinuityLayout,
    challenges: ContinuityChallenges,
) -> Result<Vec<Vec<u64>>, ContinuityError> {
    if trace.len() != layout.trace_column_count() {
        return Err(ContinuityError::Shape);
    }
    let powers = state_mix_powers(challenges.state_mix);
    if layout.inverse_column_count() != PACKED_INVERSE_COLUMN_COUNT {
        return Err(ContinuityError::Shape);
    }
    selected_inverse_columns(
        UNIFORM_ROW_COUNT,
        |row| continuity_inverse_row(trace, layout, challenges, &powers, row),
        continuity_limb_row,
        map_batch_error,
    )
}

fn continuity_inverse_row(
    trace: &[Vec<u64>],
    layout: ContinuityLayout,
    challenges: ContinuityChallenges,
    powers: &[NativeField; STATE_SCALAR_COUNT],
    row: usize,
) -> Result<([SelectedDenominator; 2], u64), ContinuityError> {
    let active = trace_value(trace, layout.active_column(), row)?;
    let row_tag = NativeField::from_u64(u64::try_from(row).map_err(|_| ContinuityError::Shape)?);
    let after = state_token_from_layout_trace(
        trace,
        layout,
        true,
        row,
        row_tag + NativeField::from_u64(1),
        powers,
    )?;
    let before = state_token_from_layout_trace(trace, layout, false, row, row_tag, powers)?;
    let instruction = trace_value(trace, crate::block_metadata::INSTRUCTION_BLOCK, row)?;
    let lane_count = (0..BASIC_BLOCK_INSTRUCTION_BOUND).try_fold(0_u64, |count, lane| {
        let column = crate::block_metadata::lane_column(lane).ok_or(ContinuityError::Shape)?;
        count
            .checked_add(trace_value(trace, column, row)?)
            .ok_or(ContinuityError::Shape)
    })?;
    let transition = active
        .checked_sub(instruction)
        .and_then(|count| count.checked_add(lane_count))
        .ok_or(ContinuityError::Shape)?;
    let scale = NativeField::from_u64(active);
    Ok((
        [
            SelectedDenominator::new(scale, challenges.inverse_point - after),
            SelectedDenominator::new(scale, challenges.inverse_point - before),
        ],
        transition,
    ))
}

fn continuity_limb_row(
    inverses: [SelectedDenominator; 2],
    transition: u64,
) -> Result<[u64; PACKED_INVERSE_COLUMN_COUNT], ContinuityError> {
    let [after, before] = inverses;
    let [after_low, after_high] = split_field(after.value())?;
    let [before_low, before_high] = split_field(before.value())?;
    Ok([after_low, after_high, before_low, before_high, transition])
}

fn map_batch_error(error: FieldBatchError) -> ContinuityError {
    match error {
        FieldBatchError::Shape => ContinuityError::Shape,
        FieldBatchError::ZeroDenominator => ContinuityError::ZeroDenominator,
    }
}

fn prove_sum(
    protocol: NativeProtocolVersion,
    layout: ContinuityLayout,
    inverses: &CommittedWitness,
    claim: &NativeExecutionClaim,
    challenges: ContinuityChallenges,
    full_descriptor: &[u8],
) -> Result<ContinuitySumProof, ContinuityError> {
    let descriptor = sum_descriptor(protocol, layout, full_descriptor)?;
    let point = half_point()?;
    let columns = inverses.field_columns()?;
    let values = columns
        .as_slice()
        .iter()
        .map(|column| evaluate_field_column(column, &point))
        .collect::<Result<Vec<_>, _>>()?;
    check_sum(layout, &values, claim, challenges)?;
    let opening = prove_witness_opening(inverses, &point, &values, &descriptor)?;
    Ok(ContinuitySumProof { values, opening })
}

fn verify_sum(
    protocol: NativeProtocolVersion,
    layout: ContinuityLayout,
    proof: &ContinuitySumProof,
    inverses: &WitnessCommitments,
    claim: &NativeExecutionClaim,
    challenges: ContinuityChallenges,
    full_descriptor: &[u8],
) -> Result<(), ContinuityError> {
    let descriptor = sum_descriptor(protocol, layout, full_descriptor)?;
    let point = half_point()?;
    verify_witness_opening_for_protocol(
        protocol,
        inverses,
        &point,
        &proof.values,
        &descriptor,
        &proof.opening,
    )?;
    check_sum(layout, &proof.values, claim, challenges)
}

fn check_sum(
    layout: ContinuityLayout,
    values: &[NativeField],
    claim: &NativeExecutionClaim,
    challenges: ContinuityChallenges,
) -> Result<(), ContinuityError> {
    if values.len() != layout.inverse_column_count() {
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
    let proved_transitions = rows * value(values, 4)?;
    if proved_transitions != NativeField::from_u64(claim.transition_count()) {
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

fn state_token_from_layout_row(
    row: &[NativeField],
    layout: ContinuityLayout,
    after: bool,
    tag: NativeField,
    powers: &[NativeField; STATE_SCALAR_COUNT],
) -> Result<NativeField, UniformError> {
    let mut token = tag;
    for (scalar, power) in powers.iter().copied().enumerate() {
        let column = layout
            .state_column(after, scalar)
            .ok_or(UniformError::Shape)?;
        token += power * value(row, column)?;
    }
    Ok(token)
}

fn state_token_from_layout_trace(
    trace: &[Vec<u64>],
    layout: ContinuityLayout,
    after: bool,
    row: usize,
    tag: NativeField,
    powers: &[NativeField; STATE_SCALAR_COUNT],
) -> Result<NativeField, ContinuityError> {
    let mut token = tag;
    for (scalar, power) in powers.iter().copied().enumerate() {
        let column = layout
            .state_column(after, scalar)
            .ok_or(ContinuityError::Shape)?;
        token += power * NativeField::from_u64(trace_value(trace, column, row)?);
    }
    Ok(token)
}

fn state_mix_powers(mix: NativeField) -> [NativeField; STATE_SCALAR_COUNT] {
    let mut power = NativeField::from_u64(1);
    std::array::from_fn(|_| {
        power *= mix;
        power
    })
}

fn phase_one_descriptor(
    protocol: NativeProtocolVersion,
    _layout: ContinuityLayout,
    trace: &WitnessCommitments,
    claim: &NativeExecutionClaim,
) -> Result<Vec<u8>, ContinuityError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, protocol.protocol_id().as_bytes())?;
    push_bytes(
        &mut descriptor,
        crate::AKITA_AUXILIARY_SCHEDULE_SHA256.as_bytes(),
    )?;
    push_bytes(&mut descriptor, &trace.canonical_bytes_for(protocol)?)?;
    push_bytes(&mut descriptor, &claim.canonical_bytes_for(protocol))?;
    push_bytes(&mut descriptor, PACKED_LAYOUT_DOMAIN)?;
    Ok(descriptor)
}

fn full_descriptor(
    protocol: NativeProtocolVersion,
    phase_one: &[u8],
    inverses: &WitnessCommitments,
) -> Result<Vec<u8>, ContinuityError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, phase_one)?;
    push_bytes(&mut descriptor, &inverses.canonical_bytes_for(protocol)?)?;
    Ok(descriptor)
}

fn challenges(
    _protocol: NativeProtocolVersion,
    _layout: ContinuityLayout,
    descriptor: &[u8],
) -> Result<ContinuityChallenges, ContinuityError> {
    let mut transcript = AkitaTranscript::<NativeField>::unbound_verifier(PACKED_CHALLENGE_DOMAIN);
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

fn sum_descriptor(
    _protocol: NativeProtocolVersion,
    _layout: ContinuityLayout,
    full: &[u8],
) -> Result<Vec<u8>, ContinuityError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, PACKED_SUM_DOMAIN)?;
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
    crate::field_fold::evaluate_mle(values, point).map_err(|_| ContinuityError::Shape)
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
