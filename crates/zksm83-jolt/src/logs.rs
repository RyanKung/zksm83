//! Native commitments and ordered membership arguments for protocol logs.

mod packed;
mod packed_trace_relation;
pub(crate) mod sum;
pub(crate) mod table_relation;
#[cfg(test)]
mod tests;

use akita_pcs::{AkitaTranscript, Ring, Transcript};
use jolt_field::CanonicalBytes;
use thiserror::Error;

use crate::{
    AkitaWorkerError, FieldFoldError, NativeField, NativeProtocolVersion, UniformError,
    WitnessCommitments,
    pcs::{ColumnCommitments, CommittedColumns, PcsError, PcsLayout, commit_columns},
    sumcheck::ProductSumcheckError,
};

/// Number of address variables in every fixed-capacity segment log table.
pub const PROTOCOL_LOG_NUM_VARIABLES: usize = 17;
/// Maximum entries in each segment-local input, output, bus, or ISA log.
pub const PROTOCOL_LOG_ROW_COUNT: usize = 1 << PROTOCOL_LOG_NUM_VARIABLES;

const LOG_GROUP_COLUMNS: usize = 128;
const LOG_COLUMN_COUNT: usize = 19;
const TABLE_INVERSE_COLUMN_COUNT: usize = LOG_KIND_COUNT * 2;
const PACKED_TRACE_INVERSE_ENTRY_COUNT: usize = crate::TRACE_BUS_SLOTS * 3 + 4;
const PACKED_TRACE_INVERSE_COLUMN_COUNT: usize = PACKED_TRACE_INVERSE_ENTRY_COUNT * 2;
const LOG_KIND_COUNT: usize = 4;
const LOG_SCHEDULE_FILE: &[u8] =
    include_bytes!("../protocol/akita/fp128_dense_bounded_nv17_p128.aks");
const LOG_SCHEDULE_ARTIFACT: &[u8] = LOG_SCHEDULE_FILE.split_at(LOG_SCHEDULE_FILE.len() - 1).0;
const LOG_LAYOUT: PcsLayout = PcsLayout::new(
    PROTOCOL_LOG_NUM_VARIABLES,
    LOG_GROUP_COLUMNS,
    LOG_SCHEDULE_ARTIFACT,
    b"zksm83/native-protocol-logs/v1",
    b"zksm83-native-protocol-log-opening/v1",
);

const BUS_START: usize = 0;
const BUS_WIDTH: usize = 9;
const INPUT_START: usize = BUS_START + BUS_WIDTH;
const BYTE_LOG_WIDTH: usize = 3;
const OUTPUT_START: usize = INPUT_START + BYTE_LOG_WIDTH;
const ISA_START: usize = OUTPUT_START + BYTE_LOG_WIDTH;
const ISA_WIDTH: usize = 4;

const STATE_INPUT_INDEX: usize = 16;
const STATE_OUTPUT_INDEX: usize = 17;
const STATE_BUS_INDEX: usize = 18;
const STATE_ISA_INDEX: usize = 19;

/// Prover-owned canonical segment log tables and their public commitment.
pub struct CommittedProtocolLogs {
    inner: CommittedColumns,
    commitment: ProtocolLogCommitments,
}

/// Verifier-visible Akita commitment to four exact segment-local protocol logs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolLogCommitments {
    pub(crate) inner: ColumnCommitments,
}

struct LogEntries {
    bus: Vec<[u64; BUS_WIDTH - 1]>,
    input: Vec<[u64; BYTE_LOG_WIDTH - 1]>,
    output: Vec<[u64; BYTE_LOG_WIDTH - 1]>,
    isa: Vec<[u64; ISA_WIDTH - 1]>,
}

pub(crate) use packed::verify_packed_protocol_logs_for_protocol;
pub use packed::{
    PackedProtocolLogClaim, PackedProtocolLogProof, commit_packed_protocol_logs,
    prove_packed_protocol_logs, verify_packed_protocol_logs,
};
pub(crate) use packed::{
    prepare_packed_protocol_logs, prove_prepared_packed_protocol_logs_with_backend,
};

/// Invalid log table, cursor claim, proof shape, or backend operation.
#[derive(Debug, Error)]
pub enum ProtocolLogError {
    /// A fixed table, proof vector, cursor range, or column layout is malformed.
    #[error("native protocol-log shape is invalid")]
    Shape,
    /// A segment contains more events than one frozen log table can hold.
    #[error("native protocol log exceeds its fixed segment capacity")]
    Capacity,
    /// A compressed tuple denominator is zero for this Fiat-Shamir transcript.
    #[error("native protocol-log inverse denominator is zero")]
    ZeroDenominator,
    /// A required Fiat-Shamir challenge was zero.
    #[error("native protocol-log Fiat-Shamir challenge is zero")]
    ZeroChallenge,
    /// The committed tables and ordered trace events differ.
    #[error("native protocol-log relation is unsatisfied")]
    Unsatisfied,
    /// A sumcheck transcript was rejected.
    #[error("native protocol-log sumcheck failed")]
    Sumcheck,
    /// The selected prover backend could not fold an evaluation table.
    #[error(transparent)]
    FieldFold(#[from] FieldFoldError),
    /// A trace-side uniform relation or opening was rejected.
    #[error(transparent)]
    Uniform(#[from] UniformError),
    /// Akita rejected a log-table commitment or opening.
    #[error("native protocol-log Akita operation failed: {0}")]
    Pcs(String),
    /// The operating system rejected creation of the bounded proof worker.
    #[error("failed to start native protocol-log worker: {0}")]
    WorkerSpawn(#[source] std::io::Error),
    /// The bounded proof worker panicked and its result was rejected.
    #[error("native protocol-log worker terminated unexpectedly")]
    WorkerPanicked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogKind {
    Bus,
    Input,
    Output,
    Isa,
}

#[derive(Clone, Copy)]
struct LogChallenges {
    tuple_mix: [NativeField; LOG_KIND_COUNT],
    inverse_point: [NativeField; LOG_KIND_COUNT],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TraceLogLayout {
    Packed,
}

impl TraceLogLayout {
    const fn inverse_column_count(self) -> usize {
        PACKED_TRACE_INVERSE_COLUMN_COUNT
    }

    fn entry_ranges(self) -> [std::ops::Range<usize>; LOG_KIND_COUNT] {
        [0..5, 5..10, 10..15, 15..19]
    }

    const fn sum_domain(self) -> &'static [u8] {
        b"zksm83-native-block-protocol-log-multiset-sum/v2"
    }
}

impl LogChallenges {
    fn mix(self, kind: LogKind) -> NativeField {
        let [bus, input, output, isa] = self.tuple_mix;
        match kind {
            LogKind::Bus => bus,
            LogKind::Input => input,
            LogKind::Output => output,
            LogKind::Isa => isa,
        }
    }

    fn point(self, kind: LogKind) -> NativeField {
        let [bus, input, output, isa] = self.inverse_point;
        match kind {
            LogKind::Bus => bus,
            LogKind::Input => input,
            LogKind::Output => output,
            LogKind::Isa => isa,
        }
    }
}

impl From<PcsError> for ProtocolLogError {
    fn from(error: PcsError) -> Self {
        Self::Pcs(error.to_string())
    }
}

impl From<ProductSumcheckError> for ProtocolLogError {
    fn from(error: ProductSumcheckError) -> Self {
        match error {
            ProductSumcheckError::FieldFold(source) => Self::FieldFold(source),
            _ => Self::Sumcheck,
        }
    }
}

impl CommittedProtocolLogs {
    /// Returns the verifier-visible commitment to all four log tables.
    #[must_use]
    pub const fn commitment(&self) -> &ProtocolLogCommitments {
        &self.commitment
    }
}

impl ProtocolLogCommitments {
    /// Returns the canonical protocol encoding of this table commitment.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProtocolLogError> {
        self.inner.canonical_bytes(LOG_LAYOUT).map_err(Into::into)
    }

    /// Returns SHA-256 of the canonical table commitment encoding.
    pub fn digest(&self) -> Result<[u8; 32], ProtocolLogError> {
        self.inner.digest(LOG_LAYOUT).map_err(Into::into)
    }

    fn validate(&self) -> Result<(), ProtocolLogError> {
        self.inner.validate(LOG_LAYOUT).map_err(Into::into)
    }
}

fn append_table<const WIDTH: usize>(
    columns: &mut [Vec<u64>],
    start: usize,
    entries: &[[u64; WIDTH]],
) -> Result<(), ProtocolLogError> {
    if entries.len() > PROTOCOL_LOG_ROW_COUNT {
        return Err(ProtocolLogError::Capacity);
    }
    for row in 0..PROTOCOL_LOG_ROW_COUNT {
        let entry = entries.get(row);
        push_column(columns, start, u64::from(entry.is_some()))?;
        for offset in 0..WIDTH {
            push_column(
                columns,
                start + 1 + offset,
                entry
                    .and_then(|values| values.get(offset))
                    .copied()
                    .unwrap_or(0),
            )?;
        }
    }
    Ok(())
}

fn full_descriptor(
    protocol: NativeProtocolVersion,
    phase_one: &[u8],
    trace_inverses: &WitnessCommitments,
    table_inverses: &ColumnCommitments,
) -> Result<Vec<u8>, ProtocolLogError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, phase_one)?;
    push_bytes(
        &mut descriptor,
        &trace_inverses.canonical_bytes_for(protocol)?,
    )?;
    push_bytes(
        &mut descriptor,
        &table_inverses.canonical_bytes(LOG_LAYOUT)?,
    )?;
    Ok(descriptor)
}

fn challenge_array(
    transcript: &mut AkitaTranscript<NativeField>,
    label: &'static [u8],
) -> Result<[NativeField; LOG_KIND_COUNT], ProtocolLogError> {
    let mut values = [NativeField::from_u64(0); LOG_KIND_COUNT];
    for value in &mut values {
        *value = transcript.challenge_scalar(label);
        if *value == NativeField::from_u64(0) {
            return Err(ProtocolLogError::ZeroChallenge);
        }
    }
    Ok(values)
}

fn scalar_delta(
    before: crate::NativeStateBoundary,
    after: crate::NativeStateBoundary,
    index: usize,
) -> Result<u64, ProtocolLogError> {
    after
        .scalars()
        .get(index)
        .copied()
        .ok_or(ProtocolLogError::Shape)?
        .checked_sub(
            before
                .scalars()
                .get(index)
                .copied()
                .ok_or(ProtocolLogError::Shape)?,
        )
        .ok_or(ProtocolLogError::Shape)
}

fn commit_log_columns(columns: &[Vec<u64>]) -> Result<CommittedLogColumns, ProtocolLogError> {
    if columns.is_empty()
        || columns
            .iter()
            .any(|column| column.len() != PROTOCOL_LOG_ROW_COUNT)
    {
        return Err(ProtocolLogError::Shape);
    }
    on_worker(|| {
        Ok(CommittedLogColumns {
            inner: commit_columns(LOG_LAYOUT, columns)?,
        })
    })
}

struct CommittedLogColumns {
    inner: CommittedColumns,
}

impl CommittedLogColumns {
    fn commitments(&self) -> &ColumnCommitments {
        self.inner.commitments()
    }

    fn into_commitments(self) -> ColumnCommitments {
        self.inner.commitments().clone()
    }
}

fn compress(values: &[NativeField], mix: NativeField) -> NativeField {
    values
        .iter()
        .copied()
        .fold(
            (NativeField::from_u64(0), NativeField::from_u64(1)),
            |(sum, power), value| (sum + power * value, power * mix),
        )
        .0
}

fn split_field(value: NativeField) -> Result<[u64; 2], ProtocolLogError> {
    let bytes = value.to_bytes_le_vec();
    let low = <[u8; 8]>::try_from(bytes.get(..8).ok_or(ProtocolLogError::Shape)?)
        .map_err(|_| ProtocolLogError::Shape)?;
    let high = <[u8; 8]>::try_from(bytes.get(8..16).ok_or(ProtocolLogError::Shape)?)
        .map_err(|_| ProtocolLogError::Shape)?;
    Ok([u64::from_le_bytes(low), u64::from_le_bytes(high)])
}

fn join_limbs(low: NativeField, high: NativeField) -> NativeField {
    low + two_to_64() * high
}

fn two_to_64() -> NativeField {
    NativeField::from_u64(u64::MAX) + NativeField::from_u64(1)
}

fn trace_value(trace: &[Vec<u64>], column: usize, row: usize) -> Result<u64, ProtocolLogError> {
    trace
        .get(column)
        .and_then(|values| values.get(row))
        .copied()
        .ok_or(ProtocolLogError::Shape)
}

fn packed_trace(
    trace: &[Vec<u64>],
    start: usize,
    width: usize,
    row: usize,
) -> Result<u64, ProtocolLogError> {
    let mut packed = 0_u64;
    for bit in 0..width {
        packed |= trace_value(trace, start + bit, row)? << bit;
    }
    Ok(packed)
}

fn push_column(
    columns: &mut [Vec<u64>],
    column: usize,
    value: u64,
) -> Result<(), ProtocolLogError> {
    columns
        .get_mut(column)
        .ok_or(ProtocolLogError::Shape)?
        .push(value);
    Ok(())
}

fn field_column(
    columns: &CommittedColumns,
    index: usize,
) -> Result<&[NativeField], ProtocolLogError> {
    columns.field_column(index).map_err(Into::into)
}

fn evaluate_field_column(
    values: &[NativeField],
    point: &[NativeField],
) -> Result<NativeField, ProtocolLogError> {
    crate::field_fold::evaluate_mle(values, point).map_err(|_| ProtocolLogError::Shape)
}

fn equality_evaluations(point: &[NativeField]) -> Vec<NativeField> {
    let one = NativeField::from_u64(1);
    let mut values = vec![one];
    for coordinate in point {
        let mut next = Vec::with_capacity(values.len().saturating_mul(2));
        next.extend(values.iter().map(|value| *value * (one - *coordinate)));
        next.extend(values.iter().map(|value| *value * *coordinate));
        values = next;
    }
    values
}

fn equality_evaluation(
    left: &[NativeField],
    right: &[NativeField],
) -> Result<NativeField, ProtocolLogError> {
    if left.len() != right.len() {
        return Err(ProtocolLogError::Shape);
    }
    let one = NativeField::from_u64(1);
    Ok(left.iter().zip(right).fold(one, |product, (left, right)| {
        product * (*left * *right + (one - *left) * (one - *right))
    }))
}

fn push_bytes(target: &mut Vec<u8>, value: &[u8]) -> Result<(), ProtocolLogError> {
    let length = u64::try_from(value.len()).map_err(|_| ProtocolLogError::Shape)?;
    target.extend_from_slice(&length.to_le_bytes());
    target.extend_from_slice(value);
    Ok(())
}

fn transcript(domain: &'static [u8], descriptor: &[u8]) -> AkitaTranscript<NativeField> {
    let mut transcript = AkitaTranscript::<NativeField>::unbound_verifier(domain);
    transcript.bind_instance_bytes(descriptor);
    transcript
}

fn on_worker<T: Send>(
    operation: impl FnOnce() -> Result<T, ProtocolLogError> + Send,
) -> Result<T, ProtocolLogError> {
    match crate::on_akita_worker(operation) {
        Ok(result) => result,
        Err(AkitaWorkerError::Spawn(error)) => Err(ProtocolLogError::WorkerSpawn(error)),
        Err(AkitaWorkerError::Panicked) => Err(ProtocolLogError::WorkerPanicked),
    }
}
