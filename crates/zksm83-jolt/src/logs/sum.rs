use akita_pcs::Ring;
use jolt_field::Field;

use crate::{
    NativeExecutionClaim, NativeField, NativeProtocolVersion, UNIFORM_NUM_VARIABLES,
    UNIFORM_ROW_COUNT, WitnessCommitments,
    pcs::{ColumnCommitments, CommittedColumns, OpeningProof, prove_opening, verify_opening},
    uniform::{CommittedWitness, prove_witness_opening, verify_witness_opening_for_protocol},
};

use super::{
    BUS_START, CommittedLogColumns, INPUT_START, ISA_START, LOG_COLUMN_COUNT, LOG_KIND_COUNT,
    LOG_LAYOUT, OUTPUT_START, PROTOCOL_LOG_NUM_VARIABLES, PROTOCOL_LOG_ROW_COUNT, ProtocolLogError,
    TABLE_INVERSE_COLUMN_COUNT, TRACE_INVERSE_COLUMN_COUNT, TRACE_INVERSE_ENTRY_COUNT,
    evaluate_field_column, expected_counts, join_limbs, push_bytes,
};

const SUM_DOMAIN: &[u8] = b"zksm83-native-protocol-log-multiset-sum/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProtocolLogSumProof {
    pub(crate) trace_values: Vec<NativeField>,
    pub(crate) log_values: Vec<NativeField>,
    pub(crate) table_inverse_values: Vec<NativeField>,
    pub(crate) trace_opening: OpeningProof,
    pub(crate) log_opening: OpeningProof,
    pub(crate) table_inverse_opening: OpeningProof,
}

pub(super) fn prove(
    trace_inverses: &CommittedWitness,
    logs: &CommittedColumns,
    table_inverses: &CommittedLogColumns,
    claim: &NativeExecutionClaim,
    full_descriptor: &[u8],
) -> Result<ProtocolLogSumProof, ProtocolLogError> {
    let descriptor = descriptor(full_descriptor)?;
    let trace_point = half_point(UNIFORM_NUM_VARIABLES)?;
    let log_point = half_point(PROTOCOL_LOG_NUM_VARIABLES)?;
    let trace_values = evaluate_columns(trace_inverses.field_columns(), &trace_point)?;
    let log_values = evaluate_columns(logs.field_columns(), &log_point)?;
    let table_inverse_values = evaluate_columns(table_inverses.inner.field_columns(), &log_point)?;
    check(&trace_values, &log_values, &table_inverse_values, claim)?;
    let trace_opening =
        prove_witness_opening(trace_inverses, &trace_point, &trace_values, &descriptor)?;
    let log_opening = prove_opening(LOG_LAYOUT, logs, &log_point, &log_values, &descriptor)?;
    let table_inverse_opening = prove_opening(
        LOG_LAYOUT,
        &table_inverses.inner,
        &log_point,
        &table_inverse_values,
        &descriptor,
    )?;
    Ok(ProtocolLogSumProof {
        trace_values,
        log_values,
        table_inverse_values,
        trace_opening,
        log_opening,
        table_inverse_opening,
    })
}

pub(super) fn verify(
    protocol: NativeProtocolVersion,
    proof: &ProtocolLogSumProof,
    trace_inverses: &WitnessCommitments,
    logs: &ColumnCommitments,
    table_inverses: &ColumnCommitments,
    claim: &NativeExecutionClaim,
    full_descriptor: &[u8],
) -> Result<(), ProtocolLogError> {
    let descriptor = descriptor(full_descriptor)?;
    let trace_point = half_point(UNIFORM_NUM_VARIABLES)?;
    let log_point = half_point(PROTOCOL_LOG_NUM_VARIABLES)?;
    verify_witness_opening_for_protocol(
        protocol,
        trace_inverses,
        &trace_point,
        &proof.trace_values,
        &descriptor,
        &proof.trace_opening,
    )?;
    verify_opening(
        LOG_LAYOUT,
        logs,
        &log_point,
        &proof.log_values,
        &descriptor,
        &proof.log_opening,
    )?;
    verify_opening(
        LOG_LAYOUT,
        table_inverses,
        &log_point,
        &proof.table_inverse_values,
        &descriptor,
        &proof.table_inverse_opening,
    )?;
    check(
        &proof.trace_values,
        &proof.log_values,
        &proof.table_inverse_values,
        claim,
    )
}

fn check(
    trace: &[NativeField],
    logs: &[NativeField],
    table_inverses: &[NativeField],
    claim: &NativeExecutionClaim,
) -> Result<(), ProtocolLogError> {
    if trace.len() != TRACE_INVERSE_COLUMN_COUNT
        || logs.len() != LOG_COLUMN_COUNT
        || table_inverses.len() != TABLE_INVERSE_COLUMN_COUNT
    {
        return Err(ProtocolLogError::Shape);
    }
    let trace_rows = NativeField::from_u64(
        u64::try_from(UNIFORM_ROW_COUNT).map_err(|_| ProtocolLogError::Shape)?,
    );
    let log_rows = NativeField::from_u64(
        u64::try_from(PROTOCOL_LOG_ROW_COUNT).map_err(|_| ProtocolLogError::Shape)?,
    );
    let entry_ranges = [0..5, 5..10, 10..15, 15..16];
    let selectors = [BUS_START, INPUT_START, OUTPUT_START, ISA_START];
    let counts = expected_counts(claim)?;
    for kind in 0..LOG_KIND_COUNT {
        let mut range = entry_ranges
            .get(kind)
            .ok_or(ProtocolLogError::Shape)?
            .clone();
        let trace_sum = range.try_fold(NativeField::from_u64(0), |sum, entry| {
            Ok::<_, ProtocolLogError>(sum + joined_trace(trace, entry)?)
        })?;
        let table = join_limbs(
            scalar(table_inverses, kind * 2)?,
            scalar(table_inverses, kind * 2 + 1)?,
        );
        if trace_rows * trace_sum != log_rows * table {
            return Err(ProtocolLogError::Unsatisfied);
        }
        let selector = scalar(logs, *selectors.get(kind).ok_or(ProtocolLogError::Shape)?)?;
        if log_rows * selector
            != NativeField::from_u64(*counts.get(kind).ok_or(ProtocolLogError::Shape)?)
        {
            return Err(ProtocolLogError::Unsatisfied);
        }
    }
    Ok(())
}

fn joined_trace(values: &[NativeField], entry: usize) -> Result<NativeField, ProtocolLogError> {
    if entry >= TRACE_INVERSE_ENTRY_COUNT {
        return Err(ProtocolLogError::Shape);
    }
    Ok(join_limbs(
        scalar(values, entry * 2)?,
        scalar(values, entry * 2 + 1)?,
    ))
}

fn evaluate_columns(
    columns: &[Vec<NativeField>],
    point: &[NativeField],
) -> Result<Vec<NativeField>, ProtocolLogError> {
    columns
        .iter()
        .map(|column| evaluate_field_column(column, point))
        .collect()
}

fn half_point(count: usize) -> Result<Vec<NativeField>, ProtocolLogError> {
    let half = NativeField::from_u64(2)
        .inverse()
        .ok_or(ProtocolLogError::ZeroChallenge)?;
    Ok(vec![half; count])
}

fn descriptor(full: &[u8]) -> Result<Vec<u8>, ProtocolLogError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, SUM_DOMAIN)?;
    push_bytes(&mut descriptor, full)?;
    Ok(descriptor)
}

fn scalar(values: &[NativeField], index: usize) -> Result<NativeField, ProtocolLogError> {
    values.get(index).copied().ok_or(ProtocolLogError::Shape)
}
