//! Native commitments and ordered membership arguments for protocol logs.

pub(crate) mod sum;
pub(crate) mod table_relation;
#[cfg(test)]
mod tests;
mod trace_relation;

use akita_pcs::{AkitaTranscript, Ring, Transcript};
use jolt_field::{CanonicalBytes, Field};
use thiserror::Error;

use crate::{
    AKITA_LOG_SCHEDULE_SHA256, AkitaWorkerError, ISA_PACKED_HIGH, ISA_PACKED_LOW,
    NATIVE_TRACE_COLUMN_COUNT, NativeExecutionClaim, NativeField, NativeProtocolVersion,
    NativeTraceWitness, STATE_SCALAR_COUNT, TRACE_ACTIVE, TRACE_BEFORE_STATE_START,
    TRACE_BUS_KIND_BITS, TRACE_BUS_SLOT_WIDTH, TRACE_BUS_SLOTS, TRACE_BUS_START,
    TRACE_ISA_OUTPUT_START, UNIFORM_ROW_COUNT, UniformError, WitnessCommitments,
    pcs::{ColumnCommitments, CommittedColumns, PcsError, PcsLayout, commit_columns},
    sumcheck::ProductSumcheckError,
    uniform::CommittedWitness,
};

/// Number of address variables in every fixed-capacity segment log table.
pub const PROTOCOL_LOG_NUM_VARIABLES: usize = 17;
/// Maximum entries in each segment-local input, output, bus, or ISA log.
pub const PROTOCOL_LOG_ROW_COUNT: usize = 1 << PROTOCOL_LOG_NUM_VARIABLES;

const LOG_GROUP_COLUMNS: usize = 128;
const LOG_COLUMN_COUNT: usize = 19;
const TABLE_INVERSE_COLUMN_COUNT: usize = LOG_KIND_COUNT * 2;
const TRACE_INVERSE_ENTRY_COUNT: usize = TRACE_BUS_SLOTS * 3 + 1;
const TRACE_INVERSE_COLUMN_COUNT: usize = TRACE_INVERSE_ENTRY_COUNT * 2;
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
const CHALLENGE_DOMAIN: &[u8] = b"zksm83-native-protocol-log-challenges/v1";
const CHALLENGE_DOMAIN_V2: &[u8] = b"zksm83-native-protocol-log-challenges/v2";

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

const BUS_ADDRESS_OFFSET: usize = 1 + TRACE_BUS_KIND_BITS;
const BUS_PHYSICAL_OFFSET: usize = BUS_ADDRESS_OFFSET + 1;
const BUS_BEFORE_OFFSET: usize = BUS_ADDRESS_OFFSET + 2;
const BUS_AUXILIARY_OFFSET: usize = BUS_ADDRESS_OFFSET + 3;
const BUS_VALUE_OFFSET: usize = BUS_ADDRESS_OFFSET + 4;
const BUS_EVENT_INDEX_OFFSET: usize = BUS_ADDRESS_OFFSET + 5;

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

/// Proof that the committed tables equal the ordered events in one trace segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolLogProof {
    pub(crate) trace_inverses: WitnessCommitments,
    pub(crate) table_inverses: ColumnCommitments,
    pub(crate) trace_relation: crate::uniform::CompositeUniformRelationProof,
    pub(crate) table_relation: table_relation::TableRelationProof,
    pub(crate) sum: sum::ProtocolLogSumProof,
}

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
    fn from(_: ProductSumcheckError) -> Self {
        Self::Sumcheck
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

/// Commits deterministic fixed-capacity tables extracted from one native trace.
pub fn commit_protocol_logs(
    trace: &NativeTraceWitness,
) -> Result<CommittedProtocolLogs, ProtocolLogError> {
    let columns = log_columns(trace)?;
    on_worker(|| {
        let inner = commit_columns(LOG_LAYOUT, &columns)?;
        let commitment = ProtocolLogCommitments {
            inner: inner.commitments().clone(),
        };
        Ok(CommittedProtocolLogs { inner, commitment })
    })
}

/// Proves that committed tables contain exactly the trace's ordered log events.
pub fn prove_protocol_logs(
    trace: &NativeTraceWitness,
    trace_witness: &CommittedWitness,
    logs: &CommittedProtocolLogs,
    claim: &NativeExecutionClaim,
) -> Result<ProtocolLogProof, ProtocolLogError> {
    let protocol = NativeProtocolVersion::current();
    claim.validate().map_err(|_| ProtocolLogError::Shape)?;
    logs.commitment.validate()?;
    let phase_one = phase_one_descriptor(
        protocol,
        trace_witness.commitments(),
        &logs.commitment,
        claim,
    )?;
    let challenges = challenges(protocol, &phase_one)?;
    let trace_inverse_values = trace_relation::inverse_columns(trace.columns(), challenges)?;
    let trace_inverses = crate::commit_witness(&trace_inverse_values)?;
    let table_inverse_values = table_relation::inverse_columns(&logs.inner, challenges)?;
    let table_inverses = commit_log_columns(&table_inverse_values)?;
    let trace_relation = trace_relation::prove(trace_witness, &trace_inverses, challenges)?;
    let full = full_descriptor(
        protocol,
        &phase_one,
        trace_inverses.commitments(),
        table_inverses.commitments(),
    )?;
    let table_relation = table_relation::prove(&logs.inner, &table_inverses, challenges, &full)?;
    let sum =
        on_worker(|| sum::prove(&trace_inverses, &logs.inner, &table_inverses, claim, &full))?;
    Ok(ProtocolLogProof {
        trace_inverses: trace_inverses.into_commitments(),
        table_inverses: table_inverses.into_commitments(),
        trace_relation,
        table_relation,
        sum,
    })
}

/// Verifies all four logs without receiving trace rows or emulator state.
pub fn verify_protocol_logs(
    proof: &ProtocolLogProof,
    trace: &WitnessCommitments,
    logs: &ProtocolLogCommitments,
    claim: &NativeExecutionClaim,
) -> Result<(), ProtocolLogError> {
    verify_protocol_logs_for_protocol(NativeProtocolVersion::current(), proof, trace, logs, claim)
}

pub(crate) fn verify_protocol_logs_for_protocol(
    protocol: NativeProtocolVersion,
    proof: &ProtocolLogProof,
    trace: &WitnessCommitments,
    logs: &ProtocolLogCommitments,
    claim: &NativeExecutionClaim,
) -> Result<(), ProtocolLogError> {
    claim.validate().map_err(|_| ProtocolLogError::Shape)?;
    logs.validate()?;
    proof.table_inverses.validate(LOG_LAYOUT)?;
    let phase_one = phase_one_descriptor(protocol, trace, logs, claim)?;
    let challenges = challenges(protocol, &phase_one)?;
    trace_relation::verify(
        protocol,
        trace,
        &proof.trace_inverses,
        challenges,
        &proof.trace_relation,
    )?;
    let full = full_descriptor(
        protocol,
        &phase_one,
        &proof.trace_inverses,
        &proof.table_inverses,
    )?;
    table_relation::verify(
        &logs.inner,
        &proof.table_inverses,
        challenges,
        &full,
        &proof.table_relation,
    )?;
    on_worker(|| {
        sum::verify(
            protocol,
            &proof.sum,
            &proof.trace_inverses,
            &logs.inner,
            &proof.table_inverses,
            claim,
            &full,
        )
    })
}

struct LogEntries {
    bus: Vec<[u64; BUS_WIDTH - 1]>,
    input: Vec<[u64; BYTE_LOG_WIDTH - 1]>,
    output: Vec<[u64; BYTE_LOG_WIDTH - 1]>,
    isa: Vec<[u64; ISA_WIDTH - 1]>,
}

fn log_columns(trace: &NativeTraceWitness) -> Result<Vec<Vec<u64>>, ProtocolLogError> {
    let entries = extract_entries(trace.columns())?;
    let mut columns = (0..LOG_COLUMN_COUNT)
        .map(|_| Vec::with_capacity(PROTOCOL_LOG_ROW_COUNT))
        .collect::<Vec<_>>();
    append_table(&mut columns, BUS_START, &entries.bus)?;
    append_table(&mut columns, INPUT_START, &entries.input)?;
    append_table(&mut columns, OUTPUT_START, &entries.output)?;
    append_table(&mut columns, ISA_START, &entries.isa)?;
    if columns
        .iter()
        .any(|column| column.len() != PROTOCOL_LOG_ROW_COUNT)
    {
        return Err(ProtocolLogError::Shape);
    }
    Ok(columns)
}

fn extract_entries(trace: &[Vec<u64>]) -> Result<LogEntries, ProtocolLogError> {
    if trace.len() != NATIVE_TRACE_COLUMN_COUNT {
        return Err(ProtocolLogError::Shape);
    }
    let mut entries = LogEntries {
        bus: Vec::new(),
        input: Vec::new(),
        output: Vec::new(),
        isa: Vec::new(),
    };
    for row in 0..UNIFORM_ROW_COUNT {
        if trace_value(trace, TRACE_ACTIVE, row)? == 0 {
            continue;
        }
        append_row_entries(trace, row, &mut entries)?;
    }
    Ok(entries)
}

fn append_row_entries(
    trace: &[Vec<u64>],
    row: usize,
    entries: &mut LogEntries,
) -> Result<(), ProtocolLogError> {
    let before_bus = state_value(trace, row, STATE_BUS_INDEX)?;
    let mut ordinal = 0_u64;
    for slot in 0..TRACE_BUS_SLOTS {
        let start = bus_start(slot)?;
        if trace_value(trace, start, row)? == 0 {
            continue;
        }
        let kind = packed_trace(trace, start + 1, TRACE_BUS_KIND_BITS, row)?;
        let tuple = bus_tuple(trace, start, row, before_bus + ordinal, kind)?;
        entries.bus.push(tuple);
        append_byte_entry(trace, start, row, kind, entries)?;
        ordinal = ordinal.checked_add(1).ok_or(ProtocolLogError::Shape)?;
    }
    entries.isa.push([
        state_value(trace, row, STATE_ISA_INDEX)?,
        trace_value(trace, TRACE_ISA_OUTPUT_START + ISA_PACKED_LOW, row)?,
        trace_value(trace, TRACE_ISA_OUTPUT_START + ISA_PACKED_HIGH, row)?,
    ]);
    Ok(())
}

fn bus_tuple(
    trace: &[Vec<u64>],
    start: usize,
    row: usize,
    global_index: u64,
    kind: u64,
) -> Result<[u64; BUS_WIDTH - 1], ProtocolLogError> {
    Ok([
        global_index,
        kind,
        trace_value(trace, start + BUS_ADDRESS_OFFSET, row)?,
        trace_value(trace, start + BUS_PHYSICAL_OFFSET, row)?,
        trace_value(trace, start + BUS_BEFORE_OFFSET, row)?,
        trace_value(trace, start + BUS_AUXILIARY_OFFSET, row)?,
        trace_value(trace, start + BUS_VALUE_OFFSET, row)?,
        trace_value(trace, start + BUS_EVENT_INDEX_OFFSET, row)?,
    ])
}

fn append_byte_entry(
    trace: &[Vec<u64>],
    start: usize,
    row: usize,
    kind: u64,
    entries: &mut LogEntries,
) -> Result<(), ProtocolLogError> {
    let index = trace_value(trace, start + BUS_EVENT_INDEX_OFFSET, row)?;
    if kind == 6 || kind == 13 {
        let offset = if kind == 13 {
            BUS_AUXILIARY_OFFSET
        } else {
            BUS_VALUE_OFFSET
        };
        entries
            .input
            .push([index, trace_value(trace, start + offset, row)?]);
    }
    if kind == 7 {
        entries
            .output
            .push([index, trace_value(trace, start + BUS_VALUE_OFFSET, row)?]);
    }
    Ok(())
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

fn phase_one_descriptor(
    protocol: NativeProtocolVersion,
    trace: &WitnessCommitments,
    logs: &ProtocolLogCommitments,
    claim: &NativeExecutionClaim,
) -> Result<Vec<u8>, ProtocolLogError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, protocol.protocol_id().as_bytes())?;
    push_bytes(&mut descriptor, protocol.trace_schedule_sha256().as_bytes())?;
    push_bytes(&mut descriptor, AKITA_LOG_SCHEDULE_SHA256.as_bytes())?;
    push_bytes(&mut descriptor, &trace.canonical_bytes_for(protocol)?)?;
    push_bytes(&mut descriptor, &logs.canonical_bytes()?)?;
    push_bytes(&mut descriptor, &claim.canonical_bytes_for(protocol))?;
    Ok(descriptor)
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

fn challenges(
    protocol: NativeProtocolVersion,
    descriptor: &[u8],
) -> Result<LogChallenges, ProtocolLogError> {
    let domain = match protocol {
        NativeProtocolVersion::V1 => CHALLENGE_DOMAIN,
        NativeProtocolVersion::V2 => CHALLENGE_DOMAIN_V2,
    };
    let mut transcript = AkitaTranscript::<NativeField>::unbound_verifier(domain);
    transcript.bind_instance_bytes(descriptor);
    let tuple_mix = challenge_array(&mut transcript, b"tuple-mix")?;
    let inverse_point = challenge_array(&mut transcript, b"inverse-point")?;
    Ok(LogChallenges {
        tuple_mix,
        inverse_point,
    })
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

fn expected_counts(
    claim: &NativeExecutionClaim,
) -> Result<[u64; LOG_KIND_COUNT], ProtocolLogError> {
    let before = claim.initial_state();
    let after = claim.final_state();
    Ok([
        scalar_delta(before, after, STATE_BUS_INDEX)?,
        scalar_delta(before, after, STATE_INPUT_INDEX)?,
        scalar_delta(before, after, STATE_OUTPUT_INDEX)?,
        scalar_delta(before, after, STATE_ISA_INDEX)?,
    ])
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

fn selected_inverse(
    selector: u64,
    token: NativeField,
    inverse_point: NativeField,
) -> Result<NativeField, ProtocolLogError> {
    if selector == 0 {
        return Ok(NativeField::from_u64(0));
    }
    Ok(NativeField::from_u64(selector) * inverse(inverse_point - token)?)
}

fn inverse(value: NativeField) -> Result<NativeField, ProtocolLogError> {
    value.inverse().ok_or(ProtocolLogError::ZeroDenominator)
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

fn state_value(trace: &[Vec<u64>], row: usize, scalar: usize) -> Result<u64, ProtocolLogError> {
    if scalar >= STATE_SCALAR_COUNT {
        return Err(ProtocolLogError::Shape);
    }
    trace_value(trace, TRACE_BEFORE_STATE_START + scalar, row)
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

fn bus_start(slot: usize) -> Result<usize, ProtocolLogError> {
    TRACE_BUS_START
        .checked_add(
            slot.checked_mul(TRACE_BUS_SLOT_WIDTH)
                .ok_or(ProtocolLogError::Shape)?,
        )
        .ok_or(ProtocolLogError::Shape)
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

fn push_inverse(
    columns: &mut [Vec<u64>],
    offset: usize,
    value: NativeField,
) -> Result<(), ProtocolLogError> {
    let [low, high] = split_field(value)?;
    push_column(columns, offset, low)?;
    push_column(columns, offset + 1, high)
}

fn field_column(
    columns: &CommittedColumns,
    index: usize,
) -> Result<&[NativeField], ProtocolLogError> {
    columns
        .field_columns()
        .get(index)
        .map(Vec::as_slice)
        .ok_or(ProtocolLogError::Shape)
}

fn evaluate_field_column(
    values: &[NativeField],
    point: &[NativeField],
) -> Result<NativeField, ProtocolLogError> {
    if values.len() != 1_usize << point.len() {
        return Err(ProtocolLogError::Shape);
    }
    let mut folded = values.to_vec();
    for coordinate in point {
        let mut next = Vec::with_capacity(folded.len() / 2);
        for pair in folded.chunks_exact(2) {
            let zero = pair.first().copied().ok_or(ProtocolLogError::Shape)?;
            let one = pair.get(1).copied().ok_or(ProtocolLogError::Shape)?;
            next.push(zero + *coordinate * (one - zero));
        }
        folded = next;
    }
    folded.first().copied().ok_or(ProtocolLogError::Shape)
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
