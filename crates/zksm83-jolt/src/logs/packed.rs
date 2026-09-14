//! Packed-block protocol-log commitments and shared-witness argument.

use akita_pcs::AkitaTranscript;

use crate::{
    AKITA_AUXILIARY_SCHEDULE_SHA256, AKITA_LOG_SCHEDULE_SHA256, BlockCpuWitness,
    NativeExecutionClaim, NativeField, NativeProtocolVersion, TRACE_BUS_SLOTS, WitnessCommitments,
    pcs::{ColumnCommitments, commit_columns},
    uniform::{CommittedWitness, CompositeUniformRelationProof},
};

use super::{CommittedLogColumns, CommittedProtocolLogs, sum::ProtocolLogSumProof};
use super::{
    LOG_KIND_COUNT, LOG_LAYOUT, LogChallenges, ProtocolLogCommitments, ProtocolLogError,
    STATE_BUS_INDEX, STATE_INPUT_INDEX, STATE_ISA_INDEX, STATE_OUTPUT_INDEX, TraceLogLayout,
    challenge_array, commit_log_columns, full_descriptor, on_worker, packed_trace_relation,
    push_bytes, scalar_delta, sum, table_relation,
};

const PACKED_CHALLENGE_DOMAIN: &[u8] = b"zksm83-native-block-protocol-log-challenges/v2";
const PACKED_CLAIM_DOMAIN: &[u8] = b"zksm83/native-block-protocol-log-claim/v2";

/// Exact bus and ISA entry counts for one packed-block segment.
///
/// Input and output counts remain derived from the execution boundary so the
/// same public state claim controls their global stream positions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedProtocolLogClaim {
    bus_event_count: u64,
    instruction_count: u64,
}

/// Proof that one committed table equals the canonical-position packed logs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackedProtocolLogProof {
    pub(crate) trace_inverses: WitnessCommitments,
    pub(crate) table_inverses: ColumnCommitments,
    pub(crate) trace_relation: CompositeUniformRelationProof,
    pub(crate) table_relation: table_relation::TableRelationProof,
    pub(crate) sum: ProtocolLogSumProof,
}

pub(crate) struct PreparedPackedProtocolLogs {
    trace_inverses: CommittedWitness,
    table_inverses: CommittedLogColumns,
    phase_one: Vec<u8>,
    challenges: LogChallenges,
}

impl PackedProtocolLogClaim {
    /// Creates a checked packed-log count claim for one execution boundary.
    pub fn new(
        bus_event_count: u64,
        instruction_count: u64,
        execution: &NativeExecutionClaim,
    ) -> Result<Self, ProtocolLogError> {
        let claim = Self {
            bus_event_count,
            instruction_count,
        };
        claim.validate(execution)?;
        Ok(claim)
    }

    /// Derives exact packed bus and ISA counts from a prover-side witness.
    pub fn from_trace(
        trace: &BlockCpuWitness,
        execution: &NativeExecutionClaim,
    ) -> Result<Self, ProtocolLogError> {
        if execution.active_row_count()
            != u64::try_from(trace.active_block_count()).map_err(|_| ProtocolLogError::Shape)?
        {
            return Err(ProtocolLogError::Shape);
        }
        Self::new(
            u64::try_from(trace.bus_event_count()).map_err(|_| ProtocolLogError::Shape)?,
            u64::try_from(trace.instruction_count()).map_err(|_| ProtocolLogError::Shape)?,
            execution,
        )
    }

    /// Returns the exact number of active shared-bus entries.
    #[must_use]
    pub const fn bus_event_count(self) -> u64 {
        self.bus_event_count
    }

    /// Returns the exact number of active fixed-ISA lane entries.
    #[must_use]
    pub const fn instruction_count(self) -> u64 {
        self.instruction_count
    }

    fn validate(self, execution: &NativeExecutionClaim) -> Result<(), ProtocolLogError> {
        execution.validate().map_err(|_| ProtocolLogError::Shape)?;
        let block_count = execution.active_row_count();
        if self.bus_event_count
            > block_count
                .checked_mul(TRACE_BUS_SLOTS as u64)
                .ok_or(ProtocolLogError::Shape)?
            || self.instruction_count > block_count.checked_mul(4).ok_or(ProtocolLogError::Shape)?
        {
            return Err(ProtocolLogError::Shape);
        }
        let input = scalar_delta(
            execution.initial_state(),
            execution.final_state(),
            STATE_INPUT_INDEX,
        )?;
        let output = scalar_delta(
            execution.initial_state(),
            execution.final_state(),
            STATE_OUTPUT_INDEX,
        )?;
        let bus_cursor = scalar_delta(
            execution.initial_state(),
            execution.final_state(),
            STATE_BUS_INDEX,
        )?;
        let isa_cursor = scalar_delta(
            execution.initial_state(),
            execution.final_state(),
            STATE_ISA_INDEX,
        )?;
        if input
            .checked_add(output)
            .is_none_or(|count| count > self.bus_event_count)
            || bus_cursor != 0
            || isa_cursor != 0
        {
            return Err(ProtocolLogError::Shape);
        }
        Ok(())
    }

    fn counts(
        self,
        execution: &NativeExecutionClaim,
    ) -> Result<[u64; LOG_KIND_COUNT], ProtocolLogError> {
        self.validate(execution)?;
        Ok([
            self.bus_event_count,
            scalar_delta(
                execution.initial_state(),
                execution.final_state(),
                STATE_INPUT_INDEX,
            )?,
            scalar_delta(
                execution.initial_state(),
                execution.final_state(),
                STATE_OUTPUT_INDEX,
            )?,
            self.instruction_count,
        ])
    }

    fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PACKED_CLAIM_DOMAIN.len() + 16);
        bytes.extend_from_slice(PACKED_CLAIM_DOMAIN);
        bytes.extend_from_slice(&self.bus_event_count.to_le_bytes());
        bytes.extend_from_slice(&self.instruction_count.to_le_bytes());
        bytes
    }
}

/// Commits canonical-position bus, input, output, and ISA tables from packed blocks.
pub fn commit_packed_protocol_logs(
    trace: &BlockCpuWitness,
) -> Result<CommittedProtocolLogs, ProtocolLogError> {
    let columns = packed_trace_relation::log_columns(trace)?;
    on_worker(|| {
        let inner = commit_columns(LOG_LAYOUT, &columns)?;
        let commitment = ProtocolLogCommitments {
            inner: inner.commitments().clone(),
        };
        Ok(CommittedProtocolLogs { inner, commitment })
    })
}

/// Proves exact packed logs against the same commitment used by the block relation.
///
/// Bus and ISA tokens use canonical `(row, slot)` positions because lookup-native
/// execution deliberately does not advance the legacy bus/ISA state cursors.
/// Sound use also verifies the packed row relation and packed continuity claim.
pub fn prove_packed_protocol_logs(
    trace: &BlockCpuWitness,
    trace_witness: &CommittedWitness,
    logs: &CommittedProtocolLogs,
    execution: &NativeExecutionClaim,
    claim: PackedProtocolLogClaim,
) -> Result<PackedProtocolLogProof, ProtocolLogError> {
    let prepared = prepare_packed_protocol_logs(trace, trace_witness, logs, execution, claim)?;
    prove_prepared_packed_protocol_logs(prepared, trace_witness, logs, execution, claim)
}

pub(crate) fn prepare_packed_protocol_logs(
    trace: &BlockCpuWitness,
    trace_witness: &CommittedWitness,
    logs: &CommittedProtocolLogs,
    execution: &NativeExecutionClaim,
    claim: PackedProtocolLogClaim,
) -> Result<PreparedPackedProtocolLogs, ProtocolLogError> {
    if PackedProtocolLogClaim::from_trace(trace, execution)? != claim {
        return Err(ProtocolLogError::Shape);
    }
    logs.commitment.validate()?;
    let protocol = NativeProtocolVersion::current();
    let phase_one = phase_one_descriptor(
        protocol,
        trace_witness.commitments(),
        &logs.commitment,
        execution,
        claim,
    )?;
    let challenges = challenges(&phase_one)?;
    let trace_inverse_values = packed_trace_relation::inverse_columns(trace, challenges)?;
    let trace_inverses = crate::commit_witness(&trace_inverse_values)?;
    let table_inverse_values = table_relation::inverse_columns(&logs.inner, challenges)?;
    let table_inverses = commit_log_columns(&table_inverse_values)?;
    Ok(PreparedPackedProtocolLogs {
        trace_inverses,
        table_inverses,
        phase_one,
        challenges,
    })
}

pub(crate) fn prove_prepared_packed_protocol_logs(
    prepared: PreparedPackedProtocolLogs,
    trace_witness: &CommittedWitness,
    logs: &CommittedProtocolLogs,
    execution: &NativeExecutionClaim,
    claim: PackedProtocolLogClaim,
) -> Result<PackedProtocolLogProof, ProtocolLogError> {
    let protocol = NativeProtocolVersion::current();
    let PreparedPackedProtocolLogs {
        trace_inverses,
        table_inverses,
        phase_one,
        challenges,
    } = prepared;
    let trace_relation = packed_trace_relation::prove(trace_witness, &trace_inverses, challenges)?;
    let full = full_descriptor(
        protocol,
        &phase_one,
        trace_inverses.commitments(),
        table_inverses.commitments(),
    )?;
    let table_relation = table_relation::prove(&logs.inner, &table_inverses, challenges, &full)?;
    let counts = claim.counts(execution)?;
    let sum = on_worker(|| {
        sum::prove(
            TraceLogLayout::Packed,
            &trace_inverses,
            &logs.inner,
            &table_inverses,
            counts,
            &full,
        )
    })?;
    Ok(PackedProtocolLogProof {
        trace_inverses: trace_inverses.into_commitments(),
        table_inverses: table_inverses.into_commitments(),
        trace_relation,
        table_relation,
        sum,
    })
}

/// Verifies packed canonical-position logs without receiving trace rows.
pub fn verify_packed_protocol_logs(
    proof: &PackedProtocolLogProof,
    trace: &WitnessCommitments,
    logs: &ProtocolLogCommitments,
    execution: &NativeExecutionClaim,
    claim: PackedProtocolLogClaim,
) -> Result<(), ProtocolLogError> {
    verify_packed_protocol_logs_for_protocol(
        NativeProtocolVersion::current(),
        proof,
        trace,
        logs,
        execution,
        claim,
    )
}

pub(crate) fn verify_packed_protocol_logs_for_protocol(
    protocol: NativeProtocolVersion,
    proof: &PackedProtocolLogProof,
    trace: &WitnessCommitments,
    logs: &ProtocolLogCommitments,
    execution: &NativeExecutionClaim,
    claim: PackedProtocolLogClaim,
) -> Result<(), ProtocolLogError> {
    let counts = claim.counts(execution)?;
    logs.validate()?;
    proof.table_inverses.validate(LOG_LAYOUT)?;
    let phase_one = phase_one_descriptor(protocol, trace, logs, execution, claim)?;
    let challenges = challenges(&phase_one)?;
    packed_trace_relation::verify(
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
            TraceLogLayout::Packed,
            protocol,
            &proof.sum,
            counts,
            sum::ProtocolLogSumInputs {
                trace_inverses: &proof.trace_inverses,
                logs: &logs.inner,
                table_inverses: &proof.table_inverses,
                full_descriptor: &full,
            },
        )
    })
}

fn phase_one_descriptor(
    protocol: NativeProtocolVersion,
    trace: &WitnessCommitments,
    logs: &ProtocolLogCommitments,
    execution: &NativeExecutionClaim,
    claim: PackedProtocolLogClaim,
) -> Result<Vec<u8>, ProtocolLogError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, protocol.protocol_id().as_bytes())?;
    push_bytes(&mut descriptor, AKITA_AUXILIARY_SCHEDULE_SHA256.as_bytes())?;
    push_bytes(&mut descriptor, AKITA_LOG_SCHEDULE_SHA256.as_bytes())?;
    push_bytes(&mut descriptor, &trace.canonical_bytes_for(protocol)?)?;
    push_bytes(&mut descriptor, &logs.canonical_bytes()?)?;
    push_bytes(&mut descriptor, &execution.canonical_bytes_for(protocol))?;
    push_bytes(&mut descriptor, &claim.canonical_bytes())?;
    Ok(descriptor)
}

fn challenges(descriptor: &[u8]) -> Result<LogChallenges, ProtocolLogError> {
    let mut transcript = AkitaTranscript::<NativeField>::unbound_verifier(PACKED_CHALLENGE_DOMAIN);
    transcript.bind_instance_bytes(descriptor);
    let tuple_mix = challenge_array(&mut transcript, b"tuple-mix")?;
    let inverse_point = challenge_array(&mut transcript, b"inverse-point")?;
    Ok(LogChallenges {
        tuple_mix,
        inverse_point,
    })
}
