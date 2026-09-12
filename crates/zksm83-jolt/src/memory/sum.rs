use akita_pcs::Ring;
use jolt_field::Field;

use crate::{
    NativeField, NativeProtocolVersion, TRACE_BUS_SLOTS, UNIFORM_NUM_VARIABLES, WitnessCommitments,
    pcs::{ColumnCommitments, OpeningProof, prove_opening, verify_opening},
    uniform::{CommittedWitness, prove_witness_opening, verify_witness_opening_for_protocol},
};

use super::{
    CommittedMemoryColumns, MEMORY_LAYOUT, MEMORY_TABLE_NUM_VARIABLES, MutableMemoryError,
    join_limbs, push_bytes,
};

const SUM_DOMAIN: &[u8] = b"zksm83-native-memory-multiset-sum/v1";
const TRACE_INVERSE_COLUMNS: usize = TRACE_BUS_SLOTS * 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MultisetSumProof {
    pub(crate) trace_values: Vec<NativeField>,
    pub(crate) initial_values: Vec<NativeField>,
    pub(crate) final_values: Vec<NativeField>,
    pub(crate) trace_opening: OpeningProof,
    pub(crate) initial_opening: OpeningProof,
    pub(crate) final_opening: OpeningProof,
}

pub(super) fn prove(
    trace: &CommittedWitness,
    initial: &CommittedMemoryColumns,
    final_memory: &CommittedMemoryColumns,
    full_descriptor: &[u8],
) -> Result<MultisetSumProof, MutableMemoryError> {
    let descriptor = descriptor(full_descriptor)?;
    let trace_point = half_point(UNIFORM_NUM_VARIABLES)?;
    let memory_point = half_point(MEMORY_TABLE_NUM_VARIABLES)?;
    let trace_values = trace
        .field_columns()
        .iter()
        .map(|column| super::evaluate_field_column(column, &trace_point))
        .collect::<Result<Vec<_>, _>>()?;
    let initial_values = evaluate_columns(initial, &memory_point)?;
    let final_values = evaluate_columns(final_memory, &memory_point)?;
    check_equality(&trace_values, &initial_values, &final_values)?;
    let trace_opening = prove_witness_opening(trace, &trace_point, &trace_values, &descriptor)?;
    let initial_opening = prove_opening(
        MEMORY_LAYOUT,
        &initial.inner,
        &memory_point,
        &initial_values,
        &descriptor,
    )?;
    let final_opening = prove_opening(
        MEMORY_LAYOUT,
        &final_memory.inner,
        &memory_point,
        &final_values,
        &descriptor,
    )?;
    Ok(MultisetSumProof {
        trace_values,
        initial_values,
        final_values,
        trace_opening,
        initial_opening,
        final_opening,
    })
}

pub(super) fn verify(
    protocol: NativeProtocolVersion,
    trace: &WitnessCommitments,
    initial: &ColumnCommitments,
    final_memory: &ColumnCommitments,
    full_descriptor: &[u8],
    proof: &MultisetSumProof,
) -> Result<(), MutableMemoryError> {
    let descriptor = descriptor(full_descriptor)?;
    let trace_point = half_point(UNIFORM_NUM_VARIABLES)?;
    let memory_point = half_point(MEMORY_TABLE_NUM_VARIABLES)?;
    verify_witness_opening_for_protocol(
        protocol,
        trace,
        &trace_point,
        &proof.trace_values,
        &descriptor,
        &proof.trace_opening,
    )?;
    verify_opening(
        MEMORY_LAYOUT,
        initial,
        &memory_point,
        &proof.initial_values,
        &descriptor,
        &proof.initial_opening,
    )?;
    verify_opening(
        MEMORY_LAYOUT,
        final_memory,
        &memory_point,
        &proof.final_values,
        &descriptor,
        &proof.final_opening,
    )?;
    check_equality(
        &proof.trace_values,
        &proof.initial_values,
        &proof.final_values,
    )
}

fn check_equality(
    trace: &[NativeField],
    initial: &[NativeField],
    final_memory: &[NativeField],
) -> Result<(), MutableMemoryError> {
    if trace.len() != TRACE_INVERSE_COLUMNS || initial.len() != 2 || final_memory.len() != 2 {
        return Err(MutableMemoryError::Shape);
    }
    let trace_delta = (0..TRACE_BUS_SLOTS).try_fold(NativeField::from_u64(0), |sum, slot| {
        let input = joined_trace(trace, slot)?;
        let output = joined_trace(trace, TRACE_BUS_SLOTS * 2 + slot)?;
        Ok::<_, MutableMemoryError>(sum + output - input)
    })?;
    let initial = join_limbs(
        initial.first().copied().ok_or(MutableMemoryError::Shape)?,
        initial.get(1).copied().ok_or(MutableMemoryError::Shape)?,
    );
    let final_memory = join_limbs(
        final_memory
            .first()
            .copied()
            .ok_or(MutableMemoryError::Shape)?,
        final_memory
            .get(1)
            .copied()
            .ok_or(MutableMemoryError::Shape)?,
    );
    let memory_rows = NativeField::from_u64(1_u64 << MEMORY_TABLE_NUM_VARIABLES);
    let trace_rows = NativeField::from_u64(1_u64 << UNIFORM_NUM_VARIABLES);
    if memory_rows * (initial - final_memory) + trace_rows * trace_delta != NativeField::from_u64(0)
    {
        return Err(MutableMemoryError::Unsatisfied);
    }
    Ok(())
}

fn joined_trace(values: &[NativeField], low: usize) -> Result<NativeField, MutableMemoryError> {
    Ok(join_limbs(
        values.get(low).copied().ok_or(MutableMemoryError::Shape)?,
        values
            .get(low + TRACE_BUS_SLOTS)
            .copied()
            .ok_or(MutableMemoryError::Shape)?,
    ))
}

fn evaluate_columns(
    columns: &CommittedMemoryColumns,
    point: &[NativeField],
) -> Result<Vec<NativeField>, MutableMemoryError> {
    columns
        .inner
        .field_columns()
        .iter()
        .map(|column| super::evaluate_field_column(column, point))
        .collect()
}

fn half_point(count: usize) -> Result<Vec<NativeField>, MutableMemoryError> {
    let half = NativeField::from_u64(2)
        .inverse()
        .ok_or(MutableMemoryError::ZeroChallenge)?;
    Ok(vec![half; count])
}

fn descriptor(full: &[u8]) -> Result<Vec<u8>, MutableMemoryError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, SUM_DOMAIN)?;
    push_bytes(&mut descriptor, full)?;
    Ok(descriptor)
}
