//! Typed commitment identities and cumulative protocol-log boundaries.

use sha2::{Digest, Sha256};

use crate::{
    AKITA_LOG_SCHEDULE_SHA256, AKITA_MEMORY_SCHEDULE_SHA256, AKITA_ROM_SCHEDULE_SHA256,
    MEMORY_IMAGE_BYTES, MemoryCommitment, NativeCpuStructuralError, NativeStateBoundary,
    PROTOCOL_ID, ProtocolLogCommitments, ROM_IMAGE_BYTES, RomCommitment, STATE_SCALAR_COUNT,
    backend_identity,
};

use super::{NativeReceiptError, NativeStatement};

const PROFILE_SCALAR: usize = 20;
const M_CYCLE_SCALAR: usize = 12;
const INPUT_CURSOR_SCALAR: usize = 16;
const OUTPUT_CURSOR_SCALAR: usize = 17;
const BUS_CURSOR_SCALAR: usize = 18;
const ISA_CURSOR_SCALAR: usize = 19;
const DMG_POST_BOOT_MBC3_V1: u64 = 1;

const IDENTITY_DOMAIN: &[u8] = b"zksm83/native-commitment-identity/v1";
const LAYOUT_DOMAIN: &[u8] = b"zksm83/native-layout-identity/v1";
const EMPTY_LOG_DOMAIN: &[u8] = b"zksm83/native-empty-log-chain/v1";
const LOG_SEGMENT_DOMAIN: &[u8] = b"zksm83/native-log-segment-identity/v1";
const LOG_CHAIN_DOMAIN: &[u8] = b"zksm83/native-log-chain/v1";
const BACKEND_DOMAIN: &[u8] = b"zksm83/native-backend-identity/v1";
const STATEMENT_DOMAIN: &[u8] = b"zksm83/native-statement/v1";

/// Consensus type of a verifier-visible commitment identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitmentKind {
    /// Statement-scoped immutable cartridge ROM.
    Rom,
    /// Mutable 128-KiB memory checkpoint.
    MutableMemory,
    /// Cumulative ordered input samples.
    InputLog,
    /// Cumulative ordered output bytes.
    OutputLog,
    /// Cumulative ordered bus events.
    BusLog,
    /// Cumulative ordered ISA rows.
    IsaLog,
}

/// One of the four ordered protocol logs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolLogKind {
    /// Canonical bus-event tuples.
    Bus,
    /// Raw input samples consumed by execution.
    Input,
    /// Output bytes emitted by execution.
    Output,
    /// Packed fixed-ISA rows selected by execution.
    Isa,
}

/// Typed digest of one direct commitment or cumulative ordered log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitmentIdentity {
    pub(crate) kind: CommitmentKind,
    pub(crate) layout_digest: [u8; 32],
    pub(crate) committed_length: u64,
    pub(crate) digest: [u8; 32],
}

/// Exact cumulative identities for all four ordered protocol logs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolLogIdentities {
    pub(crate) bus: CommitmentIdentity,
    pub(crate) input: CommitmentIdentity,
    pub(crate) output: CommitmentIdentity,
    pub(crate) isa: CommitmentIdentity,
}

/// Exact event-count deltas for all four ordered protocol logs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolLogCounts {
    pub(crate) bus: u64,
    pub(crate) input: u64,
    pub(crate) output: u64,
    pub(crate) isa: u64,
}

/// Complete authenticated boundary between native trace segments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeBoundary {
    pub(crate) state: NativeStateBoundary,
    pub(crate) memory: CommitmentIdentity,
    pub(crate) logs: ProtocolLogIdentities,
}

impl CommitmentKind {
    pub(crate) const fn code(self) -> u64 {
        match self {
            Self::Rom => 0,
            Self::MutableMemory => 1,
            Self::InputLog => 2,
            Self::OutputLog => 3,
            Self::BusLog => 4,
            Self::IsaLog => 5,
        }
    }

    pub(crate) const fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Self::Rom),
            1 => Some(Self::MutableMemory),
            2 => Some(Self::InputLog),
            3 => Some(Self::OutputLog),
            4 => Some(Self::BusLog),
            5 => Some(Self::IsaLog),
            _ => None,
        }
    }
}

impl ProtocolLogKind {
    /// Returns the stable public type code.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::Bus => 0,
            Self::Input => 1,
            Self::Output => 2,
            Self::Isa => 3,
        }
    }

    pub(crate) const fn commitment_kind(self) -> CommitmentKind {
        match self {
            Self::Bus => CommitmentKind::BusLog,
            Self::Input => CommitmentKind::InputLog,
            Self::Output => CommitmentKind::OutputLog,
            Self::Isa => CommitmentKind::IsaLog,
        }
    }

    pub(crate) const fn cursor_index(self) -> usize {
        match self {
            Self::Bus => BUS_CURSOR_SCALAR,
            Self::Input => INPUT_CURSOR_SCALAR,
            Self::Output => OUTPUT_CURSOR_SCALAR,
            Self::Isa => ISA_CURSOR_SCALAR,
        }
    }
}

impl CommitmentIdentity {
    /// Returns the consensus commitment type.
    #[must_use]
    pub const fn kind(&self) -> CommitmentKind {
        self.kind
    }

    /// Returns the frozen layout digest.
    #[must_use]
    pub const fn layout_digest(&self) -> [u8; 32] {
        self.layout_digest
    }

    /// Returns the exact logical byte or event length.
    #[must_use]
    pub const fn committed_length(&self) -> u64 {
        self.committed_length
    }

    /// Returns the typed commitment digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(crate) fn validate(
        &self,
        expected_kind: CommitmentKind,
        expected_length: u64,
    ) -> Result<(), NativeReceiptError> {
        if self.kind != expected_kind
            || self.committed_length != expected_length
            || self.layout_digest != layout_digest(expected_kind)
        {
            return Err(NativeReceiptError::InvalidStatement);
        }
        Ok(())
    }

    fn append(&self, hash: &mut CanonicalHash) {
        hash.u64(self.kind.code());
        hash.fixed(&self.layout_digest);
        hash.u64(self.committed_length);
        hash.fixed(&self.digest);
    }
}

impl ProtocolLogIdentities {
    /// Returns the cumulative identity for a selected log.
    #[must_use]
    pub const fn get(&self, kind: ProtocolLogKind) -> &CommitmentIdentity {
        match kind {
            ProtocolLogKind::Bus => &self.bus,
            ProtocolLogKind::Input => &self.input,
            ProtocolLogKind::Output => &self.output,
            ProtocolLogKind::Isa => &self.isa,
        }
    }

    pub(super) fn empty() -> Self {
        Self {
            bus: empty_log_identity(ProtocolLogKind::Bus),
            input: empty_log_identity(ProtocolLogKind::Input),
            output: empty_log_identity(ProtocolLogKind::Output),
            isa: empty_log_identity(ProtocolLogKind::Isa),
        }
    }

    fn advance(
        &self,
        initial: NativeStateBoundary,
        final_state: NativeStateBoundary,
        commitment: &ProtocolLogCommitments,
        segment_index: u64,
    ) -> Result<Self, NativeReceiptError> {
        Ok(Self {
            bus: advance_log(
                &self.bus,
                ProtocolLogKind::Bus,
                initial,
                final_state,
                commitment,
                segment_index,
            )?,
            input: advance_log(
                &self.input,
                ProtocolLogKind::Input,
                initial,
                final_state,
                commitment,
                segment_index,
            )?,
            output: advance_log(
                &self.output,
                ProtocolLogKind::Output,
                initial,
                final_state,
                commitment,
                segment_index,
            )?,
            isa: advance_log(
                &self.isa,
                ProtocolLogKind::Isa,
                initial,
                final_state,
                commitment,
                segment_index,
            )?,
        })
    }

    fn append(&self, hash: &mut CanonicalHash) {
        self.bus.append(hash);
        self.input.append(hash);
        self.output.append(hash);
        self.isa.append(hash);
    }
}

impl ProtocolLogCounts {
    /// Returns the bus-event count.
    #[must_use]
    pub const fn bus(self) -> u64 {
        self.bus
    }

    /// Returns the consumed-input count.
    #[must_use]
    pub const fn input(self) -> u64 {
        self.input
    }

    /// Returns the emitted-output count.
    #[must_use]
    pub const fn output(self) -> u64 {
        self.output
    }

    /// Returns the selected-ISA-row count.
    #[must_use]
    pub const fn isa(self) -> u64 {
        self.isa
    }

    pub(crate) fn between(
        initial: &NativeBoundary,
        final_boundary: &NativeBoundary,
    ) -> Result<Self, NativeReceiptError> {
        Ok(Self {
            bus: checked_delta(
                initial.log_cursor(ProtocolLogKind::Bus),
                final_boundary.log_cursor(ProtocolLogKind::Bus),
            )?,
            input: checked_delta(
                initial.log_cursor(ProtocolLogKind::Input),
                final_boundary.log_cursor(ProtocolLogKind::Input),
            )?,
            output: checked_delta(
                initial.log_cursor(ProtocolLogKind::Output),
                final_boundary.log_cursor(ProtocolLogKind::Output),
            )?,
            isa: checked_delta(
                initial.log_cursor(ProtocolLogKind::Isa),
                final_boundary.log_cursor(ProtocolLogKind::Isa),
            )?,
        })
    }

    fn append(self, hash: &mut CanonicalHash) {
        hash.u64(self.bus);
        hash.u64(self.input);
        hash.u64(self.output);
        hash.u64(self.isa);
    }
}

impl NativeBoundary {
    /// Returns the complete public semantic state.
    #[must_use]
    pub const fn state(&self) -> NativeStateBoundary {
        self.state
    }

    /// Returns the typed mutable-memory commitment identity.
    #[must_use]
    pub const fn memory(&self) -> &CommitmentIdentity {
        &self.memory
    }

    /// Returns cumulative ordered-log identities.
    #[must_use]
    pub const fn logs(&self) -> &ProtocolLogIdentities {
        &self.logs
    }

    pub(crate) fn initial(
        state: NativeStateBoundary,
        memory: &MemoryCommitment,
    ) -> Result<Self, NativeReceiptError> {
        let boundary = Self {
            state,
            memory: direct_memory_identity(memory)?,
            logs: ProtocolLogIdentities::empty(),
        };
        if [
            ProtocolLogKind::Bus,
            ProtocolLogKind::Input,
            ProtocolLogKind::Output,
            ProtocolLogKind::Isa,
        ]
        .into_iter()
        .any(|kind| boundary.log_cursor(kind) != 0)
        {
            return Err(NativeReceiptError::SegmentChain(
                "initial protocol-log cursor is nonzero",
            ));
        }
        boundary.validate()?;
        Ok(boundary)
    }

    pub(crate) fn advance(
        &self,
        state: NativeStateBoundary,
        memory: CommitmentIdentity,
        commitment: &ProtocolLogCommitments,
        segment_index: u64,
    ) -> Result<Self, NativeReceiptError> {
        let logs = self
            .logs
            .advance(self.state, state, commitment, segment_index)?;
        let boundary = Self {
            state,
            memory,
            logs,
        };
        boundary.validate()?;
        Ok(boundary)
    }

    pub(crate) fn machine_profile(&self) -> Result<u64, NativeReceiptError> {
        let profile = self.scalar(PROFILE_SCALAR)?;
        if profile != DMG_POST_BOOT_MBC3_V1 {
            return Err(NativeReceiptError::UnsupportedProfile);
        }
        Ok(profile)
    }

    pub(crate) fn m_cycles(&self) -> u64 {
        self.state
            .scalars()
            .get(M_CYCLE_SCALAR)
            .copied()
            .unwrap_or(0)
    }

    pub(crate) fn log_cursor(&self, kind: ProtocolLogKind) -> u64 {
        self.state
            .scalars()
            .get(kind.cursor_index())
            .copied()
            .unwrap_or(0)
    }

    pub(crate) fn validate(&self) -> Result<(), NativeReceiptError> {
        self.machine_profile()?;
        self.memory.validate(
            CommitmentKind::MutableMemory,
            u64::try_from(MEMORY_IMAGE_BYTES).map_err(|_| NativeReceiptError::Counter)?,
        )?;
        for kind in [
            ProtocolLogKind::Bus,
            ProtocolLogKind::Input,
            ProtocolLogKind::Output,
            ProtocolLogKind::Isa,
        ] {
            let cursor = self.log_cursor(kind);
            let identity = self.logs.get(kind);
            identity.validate(kind.commitment_kind(), cursor)?;
            if cursor == 0 && identity != &empty_log_identity(kind) {
                return Err(NativeReceiptError::InvalidStatement);
            }
        }
        Ok(())
    }

    fn scalar(&self, index: usize) -> Result<u64, NativeReceiptError> {
        self.state
            .scalars()
            .get(index)
            .copied()
            .ok_or(NativeReceiptError::InvalidStatement)
    }

    fn append(&self, hash: &mut CanonicalHash) {
        for scalar in self.state.scalars() {
            hash.u64(*scalar);
        }
        self.memory.append(hash);
        self.logs.append(hash);
    }
}

pub(super) fn direct_rom_identity(
    commitment: &RomCommitment,
) -> Result<CommitmentIdentity, NativeReceiptError> {
    direct_identity(
        CommitmentKind::Rom,
        u64::try_from(ROM_IMAGE_BYTES).map_err(|_| NativeReceiptError::Counter)?,
        &commitment
            .canonical_bytes()
            .map_err(NativeCpuErrorMap::rom)?,
    )
}

pub(super) fn direct_memory_identity(
    commitment: &MemoryCommitment,
) -> Result<CommitmentIdentity, NativeReceiptError> {
    direct_identity(
        CommitmentKind::MutableMemory,
        u64::try_from(MEMORY_IMAGE_BYTES).map_err(|_| NativeReceiptError::Counter)?,
        &commitment
            .canonical_bytes()
            .map_err(NativeCpuErrorMap::memory)?,
    )
}

pub(super) fn direct_identity(
    kind: CommitmentKind,
    length: u64,
    commitment: &[u8],
) -> Result<CommitmentIdentity, NativeReceiptError> {
    let layout_digest = layout_digest(kind);
    let mut hash = CanonicalHash::new(IDENTITY_DOMAIN);
    hash.u64(kind.code());
    hash.fixed(&layout_digest);
    hash.u64(length);
    hash.bytes(commitment);
    Ok(CommitmentIdentity {
        kind,
        layout_digest,
        committed_length: length,
        digest: hash.finish(),
    })
}

fn empty_log_identity(kind: ProtocolLogKind) -> CommitmentIdentity {
    let commitment_kind = kind.commitment_kind();
    let layout_digest = layout_digest(commitment_kind);
    let mut hash = CanonicalHash::new(EMPTY_LOG_DOMAIN);
    hash.u64(kind.code());
    hash.fixed(&layout_digest);
    CommitmentIdentity {
        kind: commitment_kind,
        layout_digest,
        committed_length: 0,
        digest: hash.finish(),
    }
}

fn advance_log(
    previous: &CommitmentIdentity,
    kind: ProtocolLogKind,
    initial: NativeStateBoundary,
    final_state: NativeStateBoundary,
    commitment: &ProtocolLogCommitments,
    segment_index: u64,
) -> Result<CommitmentIdentity, NativeReceiptError> {
    let start = scalar(initial, kind.cursor_index())?;
    let end = scalar(final_state, kind.cursor_index())?;
    let count = checked_delta(start, end)?;
    previous.validate(kind.commitment_kind(), start)?;
    if count == 0 {
        return Ok(previous.clone());
    }
    let commitment_bytes = commitment.canonical_bytes()?;
    let mut segment = CanonicalHash::new(LOG_SEGMENT_DOMAIN);
    segment.u64(kind.code());
    segment.u64(count);
    segment.bytes(&commitment_bytes);
    let mut chain = CanonicalHash::new(LOG_CHAIN_DOMAIN);
    previous.append(&mut chain);
    chain.u64(kind.code());
    chain.u64(segment_index);
    chain.u64(start);
    chain.u64(end);
    chain.fixed(&segment.finish());
    Ok(CommitmentIdentity {
        kind: kind.commitment_kind(),
        layout_digest: layout_digest(kind.commitment_kind()),
        committed_length: end,
        digest: chain.finish(),
    })
}

pub(super) fn checked_delta(initial: u64, final_value: u64) -> Result<u64, NativeReceiptError> {
    final_value
        .checked_sub(initial)
        .ok_or(NativeReceiptError::Counter)
}

pub(super) fn backend_digest() -> [u8; 32] {
    let backend = backend_identity();
    let mut hash = CanonicalHash::new(BACKEND_DOMAIN);
    for value in [
        backend.protocol,
        backend.jolt_reference_revision,
        backend.akita_revision,
        backend.jolt_field_revision,
        backend.schedule_sha256,
        backend.isa_table_schedule_sha256,
        backend.rom_schedule_sha256,
        backend.memory_schedule_sha256,
        backend.log_schedule_sha256,
        backend.isa_table_commitment_sha256,
        backend.field,
        backend.transcript,
    ] {
        hash.bytes(value.as_bytes());
    }
    for value in [
        backend.relation_num_variables,
        backend.trace_column_count,
        backend.constraint_count,
        backend.max_constraint_degree,
        backend.commitment_group_columns,
    ] {
        hash.u64(value as u64);
    }
    hash.u64(u64::from(backend.privacy.hides_witness()));
    hash.u64(u64::from(backend.uses_rv64_guest));
    hash.finish()
}

pub(super) fn statement_digest(statement: &NativeStatement) -> [u8; 32] {
    let mut hash = CanonicalHash::new(STATEMENT_DOMAIN);
    hash.fixed(&statement.backend_digest);
    hash.u64(statement.machine_profile);
    hash.u64(statement.rom_byte_length);
    statement.rom.append(&mut hash);
    statement.initial.append(&mut hash);
    statement.final_boundary.append(&mut hash);
    hash.u64(statement.segment_count);
    hash.u64(statement.relation_step_count);
    hash.u64(statement.m_cycle_count);
    statement.logs.append(&mut hash);
    hash.finish()
}

fn layout_digest(kind: CommitmentKind) -> [u8; 32] {
    let mut hash = CanonicalHash::new(LAYOUT_DOMAIN);
    hash.bytes(PROTOCOL_ID.as_bytes());
    hash.u64(kind.code());
    match kind {
        CommitmentKind::Rom => {
            hash.bytes(AKITA_ROM_SCHEDULE_SHA256.as_bytes());
            hash.u64(20);
            hash.u64(1);
        }
        CommitmentKind::MutableMemory => {
            hash.bytes(AKITA_MEMORY_SCHEDULE_SHA256.as_bytes());
            hash.u64(17);
            hash.u64(1);
        }
        CommitmentKind::InputLog
        | CommitmentKind::OutputLog
        | CommitmentKind::BusLog
        | CommitmentKind::IsaLog => {
            hash.bytes(AKITA_LOG_SCHEDULE_SHA256.as_bytes());
            hash.u64(17);
            hash.u64(128);
        }
    }
    hash.finish()
}

fn scalar(state: NativeStateBoundary, index: usize) -> Result<u64, NativeReceiptError> {
    state
        .scalars()
        .get(index)
        .copied()
        .ok_or(NativeReceiptError::InvalidStatement)
}

struct CanonicalHash(Sha256);

impl CanonicalHash {
    fn new(domain: &[u8]) -> Self {
        let mut hash = Sha256::new();
        append_bytes(&mut hash, domain);
        Self(hash)
    }

    fn u64(&mut self, value: u64) {
        self.0.update(value.to_le_bytes());
    }

    fn fixed(&mut self, bytes: &[u8; 32]) {
        self.0.update(bytes);
    }

    fn bytes(&mut self, bytes: &[u8]) {
        append_bytes(&mut self.0, bytes);
    }

    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

fn append_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hash.update(bytes);
}

struct NativeCpuErrorMap;

impl NativeCpuErrorMap {
    fn rom(error: crate::RomLookupError) -> NativeReceiptError {
        NativeReceiptError::Proof(NativeCpuStructuralError::RomLookup(error))
    }

    fn memory(error: crate::MutableMemoryError) -> NativeReceiptError {
        NativeReceiptError::Proof(NativeCpuStructuralError::MutableMemory(error))
    }
}

const _: () = assert!(STATE_SCALAR_COUNT > ISA_CURSOR_SCALAR);
