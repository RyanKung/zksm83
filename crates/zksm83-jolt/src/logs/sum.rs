use akita_pcs::Ring;
use jolt_field::Field;

use crate::{
    NativeField, NativeProtocolVersion, NativeProverBackend, UNIFORM_NUM_VARIABLES,
    UNIFORM_ROW_COUNT, WitnessCommitments,
    pcs::{
        ColumnCommitments, CommittedColumns, OpeningProof, prove_opening_with_backend,
        verify_opening_with_backend,
    },
    uniform::{
        CommittedWitness, prove_witness_opening_with_backend,
        verify_witness_opening_for_protocol_with_backend,
    },
};

use super::{
    BUS_START, CommittedLogColumns, INPUT_START, ISA_START, LOG_COLUMN_COUNT, LOG_KIND_COUNT,
    LOG_LAYOUT, OUTPUT_START, PROTOCOL_LOG_NUM_VARIABLES, PROTOCOL_LOG_ROW_COUNT, ProtocolLogError,
    TABLE_INVERSE_COLUMN_COUNT, TraceLogLayout, evaluate_field_column, join_limbs, push_bytes,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProtocolLogSumProof {
    pub(crate) trace_values: Vec<NativeField>,
    pub(crate) log_values: Vec<NativeField>,
    pub(crate) table_inverse_values: Vec<NativeField>,
    pub(crate) trace_opening: OpeningProof,
    pub(crate) log_opening: OpeningProof,
    pub(crate) table_inverse_opening: OpeningProof,
}

pub(super) struct ProtocolLogSumInputs<'a> {
    pub(super) trace_inverses: &'a WitnessCommitments,
    pub(super) logs: &'a ColumnCommitments,
    pub(super) table_inverses: &'a ColumnCommitments,
    pub(super) full_descriptor: &'a [u8],
}

pub(super) fn prove(
    layout: TraceLogLayout,
    trace_inverses: &CommittedWitness,
    logs: &CommittedColumns,
    table_inverses: &CommittedLogColumns,
    counts: [u64; LOG_KIND_COUNT],
    full_descriptor: &[u8],
    backend: &NativeProverBackend,
) -> Result<ProtocolLogSumProof, ProtocolLogError> {
    let descriptor = descriptor(layout, full_descriptor)?;
    let trace_point = half_point(UNIFORM_NUM_VARIABLES)?;
    let log_point = half_point(PROTOCOL_LOG_NUM_VARIABLES)?;
    let trace_columns = trace_inverses.field_columns()?;
    let log_columns = logs.field_columns()?;
    let table_inverse_columns = table_inverses.inner.field_columns()?;
    let trace_values = evaluate_columns(trace_columns.as_slice(), &trace_point)?;
    let log_values = evaluate_columns(log_columns.as_slice(), &log_point)?;
    let table_inverse_values = evaluate_columns(table_inverse_columns.as_slice(), &log_point)?;
    check(
        layout,
        &trace_values,
        &log_values,
        &table_inverse_values,
        counts,
    )?;
    let trace_opening = prove_witness_opening_with_backend(
        trace_inverses,
        &trace_point,
        &trace_values,
        &descriptor,
        backend,
    )?;
    let log_opening = prove_opening_with_backend(
        LOG_LAYOUT,
        logs,
        &log_point,
        &log_values,
        &descriptor,
        backend,
    )?;
    let table_inverse_opening = prove_opening_with_backend(
        LOG_LAYOUT,
        &table_inverses.inner,
        &log_point,
        &table_inverse_values,
        &descriptor,
        backend,
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
    layout: TraceLogLayout,
    protocol: NativeProtocolVersion,
    proof: &ProtocolLogSumProof,
    counts: [u64; LOG_KIND_COUNT],
    inputs: ProtocolLogSumInputs<'_>,
    backend: &NativeProverBackend,
) -> Result<(), ProtocolLogError> {
    let descriptor = descriptor(layout, inputs.full_descriptor)?;
    let trace_point = half_point(UNIFORM_NUM_VARIABLES)?;
    let log_point = half_point(PROTOCOL_LOG_NUM_VARIABLES)?;
    verify_witness_opening_for_protocol_with_backend(
        protocol,
        inputs.trace_inverses,
        &trace_point,
        &proof.trace_values,
        &descriptor,
        &proof.trace_opening,
        backend,
    )?;
    verify_opening_with_backend(
        LOG_LAYOUT,
        inputs.logs,
        &log_point,
        &proof.log_values,
        &descriptor,
        &proof.log_opening,
        backend,
    )?;
    verify_opening_with_backend(
        LOG_LAYOUT,
        inputs.table_inverses,
        &log_point,
        &proof.table_inverse_values,
        &descriptor,
        &proof.table_inverse_opening,
        backend,
    )?;
    check(
        layout,
        &proof.trace_values,
        &proof.log_values,
        &proof.table_inverse_values,
        counts,
    )
}

fn check(
    layout: TraceLogLayout,
    trace: &[NativeField],
    logs: &[NativeField],
    table_inverses: &[NativeField],
    counts: [u64; LOG_KIND_COUNT],
) -> Result<(), ProtocolLogError> {
    if trace.len() != layout.inverse_column_count()
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
    let entry_ranges = layout.entry_ranges();
    let selectors = [BUS_START, INPUT_START, OUTPUT_START, ISA_START];
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
    let high = entry
        .checked_mul(2)
        .and_then(|index| index.checked_add(1))
        .ok_or(ProtocolLogError::Shape)?;
    if high >= values.len() {
        return Err(ProtocolLogError::Shape);
    }
    Ok(join_limbs(
        scalar(values, entry * 2)?,
        scalar(values, entry * 2 + 1)?,
    ))
}

fn evaluate_columns(
    columns: &[impl AsRef<[NativeField]>],
    point: &[NativeField],
) -> Result<Vec<NativeField>, ProtocolLogError> {
    columns
        .iter()
        .map(|column| evaluate_field_column(column.as_ref(), point))
        .collect()
}

fn half_point(count: usize) -> Result<Vec<NativeField>, ProtocolLogError> {
    let half = NativeField::from_u64(2)
        .inverse()
        .ok_or(ProtocolLogError::ZeroChallenge)?;
    Ok(vec![half; count])
}

fn descriptor(layout: TraceLogLayout, full: &[u8]) -> Result<Vec<u8>, ProtocolLogError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, layout.sum_domain())?;
    push_bytes(&mut descriptor, full)?;
    Ok(descriptor)
}

fn scalar(values: &[NativeField], index: usize) -> Result<NativeField, ProtocolLogError> {
    values.get(index).copied().ok_or(ProtocolLogError::Shape)
}
