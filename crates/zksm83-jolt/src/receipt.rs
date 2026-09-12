//! Versioned native-SM83 receipt and witness-free verification boundary.

mod identity;
mod stream;
#[cfg(test)]
mod tests;
mod wire;

use thiserror::Error;

use crate::{
    CommittedMemory, CommittedRom, MemoryCommitment, NativeCpuStructuralError,
    NativeExecutionClaim, NativeMemoryCpuProof, NativeStateBoundary, NativeTraceWitness,
    ProtocolLogCommitments, ProtocolLogError, ROM_IMAGE_BYTES, RomCommitment, UNIFORM_ROW_COUNT,
    commit_protocol_logs, prove_native_memory_cpu, verify_native_memory_cpu,
};

pub use identity::{
    CommitmentIdentity, CommitmentKind, NativeBoundary, ProtocolLogCounts, ProtocolLogIdentities,
    ProtocolLogKind,
};

use self::identity::{backend_digest, checked_delta, direct_memory_identity, direct_rom_identity};
use self::wire::{decode_receipt, decode_statement, encode_receipt, encode_statement};

/// Current canonical native receipt wire version.
pub const NATIVE_RECEIPT_VERSION: u64 = 1;
/// Maximum canonical receipt byte length accepted by the verifier.
pub const MAX_NATIVE_RECEIPT_BYTES: usize = 512 * 1024 * 1024;
/// Maximum canonical expected-statement byte length accepted by the verifier.
pub const MAX_NATIVE_STATEMENT_BYTES: usize = 16 * 1024;
/// Maximum encoded verifier-visible ROM commitment in a receipt stream.
pub const MAX_NATIVE_ROM_COMMITMENT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum encoded proof frame for one fixed-capacity segment.
pub const MAX_NATIVE_SEGMENT_BYTES: usize = 512 * 1024 * 1024;
/// Maximum total receipt file length accepted by the standalone verifier.
pub const MAX_NATIVE_STREAM_RECEIPT_BYTES: u64 = 2 * 1024 * 1024 * 1024 * 1024;
/// Maximum number of fixed-capacity segments in one receipt.
pub const MAX_NATIVE_SEGMENT_COUNT: usize = 4096;

pub use stream::{
    NativeReceiptStreamProver, VerifiedNativeSpool, verify_native_receipt_reader,
    verify_native_spool_reader,
};

/// Prover-side inputs for one contiguous native trace segment.
#[derive(Clone, Copy)]
pub struct NativeSegmentWitness<'a> {
    trace: &'a NativeTraceWitness,
    initial_memory: &'a CommittedMemory,
    final_memory: &'a CommittedMemory,
}

/// Exact public statement authenticated by a native receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeStatement {
    pub(crate) backend_digest: [u8; 32],
    pub(crate) machine_profile: u64,
    pub(crate) rom_byte_length: u64,
    pub(crate) rom: CommitmentIdentity,
    pub(crate) initial: NativeBoundary,
    pub(crate) final_boundary: NativeBoundary,
    pub(crate) segment_count: u64,
    pub(crate) relation_step_count: u64,
    pub(crate) m_cycle_count: u64,
    pub(crate) logs: ProtocolLogCounts,
    pub(crate) statement_id: [u8; 32],
}

/// One fixed-capacity segment and every verifier-visible proof input it needs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeSegmentReceipt {
    pub(crate) segment_index: u64,
    pub(crate) active_row_count: u64,
    pub(crate) padded_row_count: u64,
    pub(crate) initial: NativeBoundary,
    pub(crate) final_boundary: NativeBoundary,
    pub(crate) initial_memory: MemoryCommitment,
    pub(crate) final_memory: MemoryCommitment,
    pub(crate) logs: ProtocolLogCommitments,
    pub(crate) m_cycle_count: u64,
    pub(crate) log_counts: ProtocolLogCounts,
    pub(crate) proof: NativeMemoryCpuProof,
}

/// Canonical versioned transparent receipt for one or more native segments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeReceipt {
    pub(crate) version: u64,
    pub(crate) statement: NativeStatement,
    pub(crate) rom: RomCommitment,
    pub(crate) segments: Vec<NativeSegmentReceipt>,
}

/// Minimal output returned only after independent receipt verification succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedNativeReceipt {
    statement_id: [u8; 32],
    segment_count: u64,
}

/// Invalid statement, segment chain, canonical encoding, or cryptographic proof.
#[derive(Debug, Error)]
pub enum NativeReceiptError {
    /// The receipt or statement encoding is malformed or exceeds a protocol bound.
    #[error("native receipt wire encoding is invalid: {0}")]
    Wire(String),
    /// The receipt version or compiled backend identity is unsupported.
    #[error("native receipt version or backend identity is unsupported")]
    UnsupportedBackend,
    /// The statement fields are internally inconsistent.
    #[error("native receipt public statement is invalid")]
    InvalidStatement,
    /// The supplied expected statement does not exactly match the receipt.
    #[error("native receipt does not match the expected public statement")]
    StatementMismatch,
    /// Segment order, state, memory, or cumulative log boundaries are discontinuous.
    #[error("native receipt segment chain is discontinuous: {0}")]
    SegmentChain(&'static str),
    /// A public count overflowed or regressed.
    #[error("native receipt public counter overflow or regression")]
    Counter,
    /// An input or output stream failed before a canonical receipt was complete.
    #[error("native receipt stream I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The operating system rejected creation of the bounded receipt worker.
    #[error("failed to start native receipt proof worker: {0}")]
    WorkerSpawn(#[source] std::io::Error),
    /// The bounded receipt worker panicked and its result was rejected.
    #[error("native receipt proof worker terminated unexpectedly")]
    WorkerPanicked,
    /// The proof only supports the frozen DMG post-boot MBC3 profile.
    #[error("native receipt machine profile is unsupported")]
    UnsupportedProfile,
    /// Protocol-log commitment construction or identity validation failed.
    #[error(transparent)]
    ProtocolLog(#[from] ProtocolLogError),
    /// A composed CPU, ISA, ROM, memory, continuity, or log proof failed.
    #[error(transparent)]
    Proof(#[from] NativeCpuStructuralError),
}

impl<'a> NativeSegmentWitness<'a> {
    /// Creates one segment input from a canonical trace and exact memory checkpoints.
    #[must_use]
    pub const fn new(
        trace: &'a NativeTraceWitness,
        initial_memory: &'a CommittedMemory,
        final_memory: &'a CommittedMemory,
    ) -> Self {
        Self {
            trace,
            initial_memory,
            final_memory,
        }
    }
}

impl NativeStatement {
    /// Returns the compiled backend digest bound by this statement.
    #[must_use]
    pub const fn backend_digest(&self) -> [u8; 32] {
        self.backend_digest
    }

    /// Returns the stable machine-profile code.
    #[must_use]
    pub const fn machine_profile(&self) -> u64 {
        self.machine_profile
    }

    /// Returns the typed one-MiB ROM identity.
    #[must_use]
    pub const fn rom(&self) -> &CommitmentIdentity {
        &self.rom
    }

    /// Returns the first authenticated execution boundary.
    #[must_use]
    pub const fn initial(&self) -> &NativeBoundary {
        &self.initial
    }

    /// Returns the last authenticated execution boundary.
    #[must_use]
    pub const fn final_boundary(&self) -> &NativeBoundary {
        &self.final_boundary
    }

    /// Returns the exact number of fixed-capacity segments.
    #[must_use]
    pub const fn segment_count(&self) -> u64 {
        self.segment_count
    }

    /// Returns the exact number of active state-transition rows.
    #[must_use]
    pub const fn relation_step_count(&self) -> u64 {
        self.relation_step_count
    }

    /// Returns the exact aggregate machine-cycle delta.
    #[must_use]
    pub const fn m_cycle_count(&self) -> u64 {
        self.m_cycle_count
    }

    /// Returns exact aggregate bus, input, output, and ISA log deltas.
    #[must_use]
    pub const fn log_counts(&self) -> ProtocolLogCounts {
        self.logs
    }

    /// Returns SHA-256 of every preceding canonical statement field.
    #[must_use]
    pub const fn statement_id(&self) -> [u8; 32] {
        self.statement_id
    }

    /// Encodes this statement canonically for out-of-band pinning.
    pub fn to_bytes(&self) -> Result<Vec<u8>, NativeReceiptError> {
        encode_statement(self)
    }

    /// Decodes and validates one canonical expected statement.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NativeReceiptError> {
        let statement = decode_statement(bytes)?;
        statement.validate()?;
        Ok(statement)
    }

    fn new(
        rom: CommitmentIdentity,
        initial: NativeBoundary,
        final_boundary: NativeBoundary,
        segment_count: u64,
        relation_step_count: u64,
    ) -> Result<Self, NativeReceiptError> {
        let machine_profile = initial.machine_profile()?;
        let m_cycle_count = checked_delta(initial.m_cycles(), final_boundary.m_cycles())?;
        let logs = ProtocolLogCounts::between(&initial, &final_boundary)?;
        let mut statement = Self {
            backend_digest: backend_digest(),
            machine_profile,
            rom_byte_length: u64::try_from(ROM_IMAGE_BYTES)
                .map_err(|_| NativeReceiptError::Counter)?,
            rom,
            initial,
            final_boundary,
            segment_count,
            relation_step_count,
            m_cycle_count,
            logs,
            statement_id: [0; 32],
        };
        statement.statement_id = statement.compute_id();
        statement.validate()?;
        Ok(statement)
    }

    fn validate(&self) -> Result<(), NativeReceiptError> {
        let maximum =
            u64::try_from(MAX_NATIVE_SEGMENT_COUNT).map_err(|_| NativeReceiptError::Counter)?;
        if self.backend_digest != backend_digest()
            || self.rom_byte_length
                != u64::try_from(ROM_IMAGE_BYTES).map_err(|_| NativeReceiptError::Counter)?
        {
            return Err(NativeReceiptError::UnsupportedBackend);
        }
        if self.segment_count == 0 || self.segment_count > maximum || self.relation_step_count == 0
        {
            return Err(NativeReceiptError::InvalidStatement);
        }
        self.rom
            .validate(CommitmentKind::Rom, self.rom_byte_length)?;
        self.initial.validate()?;
        self.final_boundary.validate()?;
        if self.machine_profile != self.initial.machine_profile()?
            || self.machine_profile != self.final_boundary.machine_profile()?
            || self.m_cycle_count
                != checked_delta(self.initial.m_cycles(), self.final_boundary.m_cycles())?
            || self.logs != ProtocolLogCounts::between(&self.initial, &self.final_boundary)?
            || self.statement_id != self.compute_id()
        {
            return Err(NativeReceiptError::InvalidStatement);
        }
        Ok(())
    }

    fn compute_id(&self) -> [u8; 32] {
        identity::statement_digest(self)
    }
}

impl NativeSegmentReceipt {
    /// Returns this segment's zero-based index.
    #[must_use]
    pub const fn segment_index(&self) -> u64 {
        self.segment_index
    }

    /// Returns the exact number of active relation rows.
    #[must_use]
    pub const fn active_row_count(&self) -> u64 {
        self.active_row_count
    }

    /// Returns the exact number of canonical padding rows.
    #[must_use]
    pub const fn padded_row_count(&self) -> u64 {
        self.padded_row_count
    }

    /// Returns the segment's initial authenticated boundary.
    #[must_use]
    pub const fn initial(&self) -> &NativeBoundary {
        &self.initial
    }

    /// Returns the segment's final authenticated boundary.
    #[must_use]
    pub const fn final_boundary(&self) -> &NativeBoundary {
        &self.final_boundary
    }
}

impl NativeReceipt {
    /// Returns the canonical wire version.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Returns the exact public statement carried by this receipt.
    #[must_use]
    pub const fn statement(&self) -> &NativeStatement {
        &self.statement
    }

    /// Returns all ordered segment receipts.
    #[must_use]
    pub fn segments(&self) -> &[NativeSegmentReceipt] {
        &self.segments
    }

    /// Encodes this receipt canonically with strict size bounds.
    pub fn to_bytes(&self) -> Result<Vec<u8>, NativeReceiptError> {
        encode_receipt(self)
    }

    /// Decodes a canonical receipt without treating parsing as verification.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NativeReceiptError> {
        decode_receipt(bytes)
    }
}

impl VerifiedNativeReceipt {
    /// Returns the verified statement identifier.
    #[must_use]
    pub const fn statement_id(self) -> [u8; 32] {
        self.statement_id
    }

    /// Returns the verified segment count.
    #[must_use]
    pub const fn segment_count(self) -> u64 {
        self.segment_count
    }
}

fn prove_segment(
    index: usize,
    initial: NativeBoundary,
    witness: NativeSegmentWitness<'_>,
    rom: &CommittedRom,
) -> Result<(NativeSegmentReceipt, NativeBoundary), NativeReceiptError> {
    let claim = NativeExecutionClaim::from_trace(witness.trace)
        .map_err(NativeCpuStructuralError::Continuity)?;
    let expected_initial = NativeStateBoundary::from_vm_state(witness.trace.initial_state());
    let memory_identity = direct_memory_identity(witness.initial_memory.commitment())?;
    if initial.state() != expected_initial || initial.memory() != &memory_identity {
        return Err(NativeReceiptError::SegmentChain(
            "prover witness does not start at the expected boundary",
        ));
    }
    let logs = commit_protocol_logs(witness.trace)?;
    let segment_index = u64::try_from(index).map_err(|_| NativeReceiptError::Counter)?;
    let final_state = NativeStateBoundary::from_vm_state(witness.trace.final_state());
    let final_memory_identity = direct_memory_identity(witness.final_memory.commitment())?;
    let final_boundary = initial.advance(
        final_state,
        final_memory_identity,
        logs.commitment(),
        segment_index,
    )?;
    let proof = prove_native_memory_cpu(
        witness.trace,
        &claim,
        &logs,
        rom,
        witness.initial_memory,
        witness.final_memory,
    )?;
    let capacity = u64::try_from(UNIFORM_ROW_COUNT).map_err(|_| NativeReceiptError::Counter)?;
    let padded_row_count = capacity
        .checked_sub(claim.active_row_count())
        .ok_or(NativeReceiptError::Counter)?;
    let m_cycle_count = checked_delta(initial.m_cycles(), final_boundary.m_cycles())?;
    let log_counts = ProtocolLogCounts::between(&initial, &final_boundary)?;
    let receipt = NativeSegmentReceipt {
        segment_index,
        active_row_count: claim.active_row_count(),
        padded_row_count,
        initial,
        final_boundary: final_boundary.clone(),
        initial_memory: witness.initial_memory.commitment().clone(),
        final_memory: witness.final_memory.commitment().clone(),
        logs: logs.commitment().clone(),
        m_cycle_count,
        log_counts,
        proof,
    };
    Ok((receipt, final_boundary))
}

/// Verifies a parsed receipt against one separately supplied exact statement.
pub fn verify_native_receipt(
    receipt: &NativeReceipt,
    expected: &NativeStatement,
) -> Result<VerifiedNativeReceipt, NativeReceiptError> {
    expected.validate()?;
    receipt.statement.validate()?;
    if receipt.version != NATIVE_RECEIPT_VERSION || receipt.statement != *expected {
        return Err(NativeReceiptError::StatementMismatch);
    }
    verify_receipt_structure(receipt)?;
    Ok(VerifiedNativeReceipt {
        statement_id: expected.statement_id,
        segment_count: expected.segment_count,
    })
}

/// Canonically decodes and independently verifies a receipt without an emulator.
pub fn verify_native_receipt_bytes(
    bytes: &[u8],
    expected: &NativeStatement,
) -> Result<VerifiedNativeReceipt, NativeReceiptError> {
    let receipt = NativeReceipt::from_bytes(bytes)?;
    verify_native_receipt(&receipt, expected)
}

fn verify_receipt_structure(receipt: &NativeReceipt) -> Result<(), NativeReceiptError> {
    let statement = &receipt.statement;
    if direct_rom_identity(&receipt.rom)? != statement.rom
        || receipt.segments.len()
            != usize::try_from(statement.segment_count).map_err(|_| NativeReceiptError::Counter)?
    {
        return Err(NativeReceiptError::StatementMismatch);
    }
    let mut boundary = statement.initial.clone();
    let mut steps = 0_u64;
    let mut previous_memory: Option<&MemoryCommitment> = None;
    for (index, segment) in receipt.segments.iter().enumerate() {
        if let Some(memory) = previous_memory {
            ensure_same_memory(memory, &segment.initial_memory)?;
        }
        verify_segment(index, segment, &boundary, &receipt.rom)?;
        steps = steps
            .checked_add(segment.active_row_count)
            .ok_or(NativeReceiptError::Counter)?;
        boundary = segment.final_boundary.clone();
        previous_memory = Some(&segment.final_memory);
    }
    if boundary != statement.final_boundary || steps != statement.relation_step_count {
        return Err(NativeReceiptError::SegmentChain(
            "final boundary or relation-step count differs from the statement",
        ));
    }
    Ok(())
}

fn ensure_same_memory(
    left: &MemoryCommitment,
    right: &MemoryCommitment,
) -> Result<(), NativeReceiptError> {
    if direct_memory_identity(left)? != direct_memory_identity(right)? {
        return Err(NativeReceiptError::SegmentChain(
            "adjacent mutable-memory commitment identities differ",
        ));
    }
    Ok(())
}

fn verify_segment(
    index: usize,
    segment: &NativeSegmentReceipt,
    expected_initial: &NativeBoundary,
    rom: &RomCommitment,
) -> Result<(), NativeReceiptError> {
    let _phase = crate::metrics::start(crate::metrics::Phase::Verify);
    let expected_index = u64::try_from(index).map_err(|_| NativeReceiptError::Counter)?;
    let capacity = u64::try_from(UNIFORM_ROW_COUNT).map_err(|_| NativeReceiptError::Counter)?;
    if segment.segment_index != expected_index {
        return Err(NativeReceiptError::SegmentChain("segment index differs"));
    }
    if &segment.initial != expected_initial {
        return Err(NativeReceiptError::SegmentChain("initial boundary differs"));
    }
    if segment.active_row_count == 0
        || segment
            .active_row_count
            .checked_add(segment.padded_row_count)
            != Some(capacity)
    {
        return Err(NativeReceiptError::SegmentChain(
            "active and padded row counts are invalid",
        ));
    }
    if direct_memory_identity(&segment.initial_memory)? != segment.initial.memory {
        return Err(NativeReceiptError::SegmentChain(
            "initial memory commitment identity differs",
        ));
    }
    if direct_memory_identity(&segment.final_memory)? != segment.final_boundary.memory {
        return Err(NativeReceiptError::SegmentChain(
            "final memory commitment identity differs",
        ));
    }
    segment.initial.validate()?;
    segment.final_boundary.validate()?;
    let expected_final = segment.initial.advance(
        segment.final_boundary.state,
        segment.final_boundary.memory.clone(),
        &segment.logs,
        segment.segment_index,
    )?;
    if expected_final != segment.final_boundary {
        return Err(NativeReceiptError::SegmentChain(
            "derived final boundary differs",
        ));
    }
    if segment.m_cycle_count
        != checked_delta(
            segment.initial.m_cycles(),
            segment.final_boundary.m_cycles(),
        )?
    {
        return Err(NativeReceiptError::SegmentChain(
            "machine-cycle count differs",
        ));
    }
    if segment.log_counts != ProtocolLogCounts::between(&segment.initial, &segment.final_boundary)?
    {
        return Err(NativeReceiptError::SegmentChain(
            "protocol-log counts differ",
        ));
    }
    let claim = NativeExecutionClaim::new(
        segment.active_row_count,
        segment.initial.state,
        segment.final_boundary.state,
    )
    .map_err(NativeCpuStructuralError::Continuity)?;
    verify_native_memory_cpu(
        &segment.proof,
        &claim,
        &segment.logs,
        rom,
        &segment.initial_memory,
        &segment.final_memory,
    )?;
    Ok(())
}
