//! Native SM83 integration boundary for the Jolt protocol and Akita PCS.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod baseline;
mod continuity;
mod cpu;
mod isa;
mod isa_lookup;
mod logs;
mod memory;
mod pcs;
mod receipt;
mod rom_lookup;
mod state;
mod sumcheck;
mod trace;
mod uniform;
mod wire;

// Akita's largest const-generic ring kernels exceed the platform-default stack
// once a trace spans nine commitment groups. This matches the stack size used
// by Akita's own dense/cross-mode proof gates; allocation is virtual and each
// proof boundary maps spawn and join failures into a typed error.
const AKITA_WORKER_STACK_BYTES: usize = 512 * 1024 * 1024;

pub(crate) enum AkitaWorkerError {
    Spawn(std::io::Error),
    Panicked,
}

pub(crate) fn on_large_stack<T: Send>(
    name: &str,
    operation: impl FnOnce() -> T + Send,
) -> Result<T, AkitaWorkerError> {
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name(name.to_owned())
            .stack_size(AKITA_WORKER_STACK_BYTES)
            .spawn_scoped(scope, || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
                    .map_err(|_| AkitaWorkerError::Panicked)
            })
            .map_err(AkitaWorkerError::Spawn)?;
        worker.join().map_err(|_| AkitaWorkerError::Panicked)?
    })
}

pub(crate) fn on_akita_worker<T: Send>(
    operation: impl FnOnce() -> T + Send,
) -> Result<T, AkitaWorkerError> {
    on_large_stack("zksm83-akita-supervisor", || {
        let pool = rayon::ThreadPoolBuilder::new()
            .stack_size(AKITA_WORKER_STACK_BYTES)
            .thread_name(|index| format!("zksm83-akita-{index}"))
            .build()
            .map_err(|error| AkitaWorkerError::Spawn(std::io::Error::other(error.to_string())))?;
        Ok(pool.install(operation))
    })?
}

pub use baseline::{BaselineError, BaselineReport, verify_transparent_opening};
pub use continuity::{
    ContinuityError, ContinuityProof, NativeExecutionClaim, prove_continuity, verify_continuity,
};
pub use cpu::{
    CPU_STRUCTURAL_CONSTRAINT_COUNT, CPU_STRUCTURAL_MAX_DEGREE, CpuStructuralRelation,
    NativeCpuStructuralError, NativeCpuStructuralProof, NativeMemoryCpuProof, NativeRomCpuProof,
    prove_native_cpu_structural, prove_native_memory_cpu, prove_native_rom_cpu,
    verify_native_cpu_structural, verify_native_memory_cpu, verify_native_rom_cpu,
};
pub use isa::{
    ISA_ARGUMENT_ONE_BITS_START, ISA_ARGUMENT_ZERO_BITS_START, ISA_OPERATION_BITS_START,
    ISA_OUTPUT_COUNT, ISA_PACKED_HIGH, ISA_PACKED_LOW, ISA_TABLE_ROW_COUNT, ISA_TAKEN_TIMING,
    ISA_VALID, ISA_WRITE_BITS_START, IsaTableError, IsaTableRow, fixed_isa_table,
    fixed_isa_table_digest,
};
pub use isa_lookup::{
    FIXED_ISA_TABLE_COMMITMENT_SHA256, FixedIsaCommitments, ISA_ADDRESS_BIT_COUNT,
    IsaLookupColumns, IsaLookupError, IsaLookupProof, prove_isa_lookup, verify_isa_lookup,
};
pub use logs::{
    CommittedProtocolLogs, ProtocolLogCommitments, ProtocolLogError, ProtocolLogProof,
    commit_protocol_logs, prove_protocol_logs, verify_protocol_logs,
};
pub use memory::{
    CommittedMemory, MEMORY_IMAGE_BYTES, MEMORY_TABLE_NUM_VARIABLES, MemoryCommitment,
    MutableMemoryError, MutableMemoryProof, commit_memory, prove_mutable_memory,
    verify_mutable_memory,
};
pub use receipt::{
    CommitmentIdentity, CommitmentKind, MAX_NATIVE_RECEIPT_BYTES, MAX_NATIVE_ROM_COMMITMENT_BYTES,
    MAX_NATIVE_SEGMENT_BYTES, MAX_NATIVE_SEGMENT_COUNT, MAX_NATIVE_STATEMENT_BYTES,
    MAX_NATIVE_STREAM_RECEIPT_BYTES, NATIVE_RECEIPT_VERSION, NativeBoundary, NativeReceipt,
    NativeReceiptError, NativeReceiptStreamProver, NativeSegmentReceipt, NativeSegmentWitness,
    NativeStatement, ProtocolLogCounts, ProtocolLogIdentities, ProtocolLogKind,
    VerifiedNativeReceipt, verify_native_receipt, verify_native_receipt_bytes,
    verify_native_receipt_reader,
};
pub use rom_lookup::{
    CommittedRom, ROM_ADDRESS_BIT_COUNT, ROM_IMAGE_BYTES, RomCommitment, RomLookupColumns,
    RomLookupError, RomLookupProof, commit_rom, prove_rom_lookup, verify_rom_lookup,
};
use serde::Serialize;
pub use state::{
    NativeStateBoundary, STATE_SCALAR_COUNT, STATE_SCALAR_NAMES, encode_state_scalars,
};
pub use trace::{
    NATIVE_TRACE_COLUMN_COUNT, NativeTraceError, NativeTraceWitness, TRACE_ACTIVE,
    TRACE_ADDRESS_WRAP, TRACE_AFTER_CPU_BYTE_BITS_START, TRACE_AFTER_DMA_BITS_START,
    TRACE_AFTER_INTERRUPT_ENABLE_BITS_START, TRACE_AFTER_INTERRUPT_REQUEST_BITS_START,
    TRACE_AFTER_PC_BITS_START, TRACE_AFTER_RAM_RTC_BITS_START, TRACE_AFTER_ROM_BANK_BITS_START,
    TRACE_AFTER_SP_BITS_START, TRACE_AFTER_STATE_START, TRACE_ARITHMETIC_CARRY,
    TRACE_ARITHMETIC_HALF_CARRY, TRACE_BEFORE_CPU_BYTE_BITS_START, TRACE_BEFORE_DMA_BITS_START,
    TRACE_BEFORE_INTERRUPT_ENABLE_BITS_START, TRACE_BEFORE_INTERRUPT_REQUEST_BITS_START,
    TRACE_BEFORE_PC_BITS_START, TRACE_BEFORE_RAM_RTC_BITS_START, TRACE_BEFORE_ROM_BANK_BITS_START,
    TRACE_BEFORE_SP_BITS_START, TRACE_BEFORE_STATE_START, TRACE_BRANCH_TAKEN,
    TRACE_BUS_ADDRESS_BITS_START, TRACE_BUS_BEFORE_BITS_START, TRACE_BUS_KIND_BITS,
    TRACE_BUS_PHYSICAL_BITS_START, TRACE_BUS_SLOT_WIDTH, TRACE_BUS_SLOTS, TRACE_BUS_START,
    TRACE_BUS_TUPLE_FIELDS, TRACE_BUS_VALUE_BITS_START, TRACE_CONTROL_OVERFLOW,
    TRACE_CONTROL_UNDERFLOW, TRACE_CYCLE_INCREMENT, TRACE_DAA_ACC_GT_99, TRACE_DAA_HIGH_ADJUST,
    TRACE_DAA_HIGH_EQUALS_NINE, TRACE_DAA_HIGH_GT_NINE, TRACE_DAA_LOW_ADJUST,
    TRACE_DAA_LOW_GT_NINE, TRACE_DAA_WRAP, TRACE_FETCH_ONE_WRAP, TRACE_FETCH_TWO_WRAP,
    TRACE_HALT_BUG, TRACE_IMMEDIATE_HIGH, TRACE_IMMEDIATE_HIGH_BITS_START, TRACE_IMMEDIATE_LOW,
    TRACE_IMMEDIATE_LOW_BITS_START, TRACE_INTERRUPT_COUNT, TRACE_INTERRUPT_START,
    TRACE_ISA_ADDRESS_START, TRACE_ISA_OUTPUT_START, TRACE_MEMORY_AFTER_OFFSET,
    TRACE_MEMORY_BEFORE_OFFSET, TRACE_MEMORY_DELTA_BITS_OFFSET,
    TRACE_MEMORY_PREDECESSOR_BITS_OFFSET, TRACE_MEMORY_SELECTOR_OFFSET, TRACE_MEMORY_SLOT_WIDTH,
    TRACE_MEMORY_START, TRACE_MEMORY_TIMESTAMP_BITS, TRACE_MEMORY_WRITE_SELECTOR_OFFSET,
    TRACE_MODE_COUNT, TRACE_MODE_START, TRACE_OPERAND_BITS_START, TRACE_OPERAND_VALUE,
    TRACE_PC_WRAP, TRACE_PENDING_INTERRUPT, TRACE_POP_FLAGS_LOW_NIBBLE,
    TRACE_POP_FLAGS_LOW_NIBBLE_BITS_START, TRACE_RESULT_BITS_START, TRACE_RESULT_VALUE,
    TRACE_RESULT_ZERO, TRACE_RESULT_ZERO_PRODUCT_COUNT, TRACE_RESULT_ZERO_PRODUCTS_START,
    TRACE_ROM_SELECTOR_START, TRACE_ROM_VALUE_START, TRACE_ROW_BIT_COUNT, TRACE_ROW_BITS_START,
    TRACE_SEQUENTIAL_PC, TRACE_SEQUENTIAL_PC_BITS_START, TRACE_SIGNED_SP_OVERFLOW,
    TRACE_SIGNED_SP_UNDERFLOW, TRACE_STACK_FIRST_WRAP, TRACE_STACK_WRAP, TRACE_SUMMARY_AUX,
    TRACE_WORD_CARRY, TRACE_WORD_HALF_CARRY, TRACE_WORD_WRAP,
};
pub use uniform::{
    COMMITMENT_GROUP_COLUMNS, CommittedWitness, NativeField, UNIFORM_NUM_VARIABLES,
    UNIFORM_ROW_COUNT, UniformError, UniformProof, UniformRelation, UniformRelationProof,
    WitnessCommitments, commit_witness, prove_uniform, prove_uniform_committed, verify_uniform,
    verify_uniform_committed,
};

/// Exact Jolt protocol revision used as the native-SM83 integration reference.
pub const JOLT_REFERENCE_REVISION: &str = "95c898d3d2bbcc178fd8b18603662fce69cfa37d";

/// Exact Akita source revision compiled by this proof backend.
pub const AKITA_REVISION: &str = "69438de6cd8ce8ed7c9ebb21bdf60b813e8fcabc";

/// Exact `jolt-field` source revision selected by pinned Akita.
pub const JOLT_FIELD_REVISION: &str = "72dc6451628d8b1dd794147a1f1cc40be0d77963";

/// SHA-256 of the upstream single-column M0 baseline schedule artifact.
pub const AKITA_BASELINE_SCHEDULE_SHA256: &str =
    "c2098502e4c976a6a6cf687e4f70acfcb818372e2fbd589bff7b18e8decfa9cf";

/// SHA-256 of the generated 14-variable, 128-column relation schedule.
pub const AKITA_SCHEDULE_SHA256: &str =
    "e601bc0bd9d4501220c367b3012901aac09467f145899c8e907b282d30e96646";

/// SHA-256 of the generated 9-variable, 128-column fixed-ISA schedule.
pub const AKITA_ISA_TABLE_SCHEDULE_SHA256: &str =
    "3a8bbab5196d9233434abf33552cd7fc5637c74f0f76cea66cf247eddb8e7287";

/// SHA-256 of the generated 20-variable, one-column ROM schedule.
pub const AKITA_ROM_SCHEDULE_SHA256: &str =
    "141f4ffaf9b1546351a35582352a6337b2855aab3d77cd456bfe30241d4c40af";

/// SHA-256 of the generated 17-variable, one-column mutable-memory schedule.
pub const AKITA_MEMORY_SCHEDULE_SHA256: &str =
    "8292b771966f1e30f7919796f5ebad3b6327686b7be61a4c778cd4972719ef15";

/// SHA-256 of the generated 17-variable, 128-column protocol-log schedule.
pub const AKITA_LOG_SCHEDULE_SHA256: &str =
    "2dba5b6d53ca57eaee58c872ceba3cdf6c7dbfe522162144577e71cadf543a80";

/// Stable protocol identifier for the first native SM83 Akita integration.
pub const PROTOCOL_ID: &str = "zksm83-native-jolt-akita-v1";

/// Privacy guarantee implemented by a proof backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofPrivacy {
    /// The proof is transparent and does not claim witness hiding.
    Transparent,
}

impl ProofPrivacy {
    /// Returns whether this mode cryptographically hides the witness.
    pub const fn hides_witness(self) -> bool {
        match self {
            Self::Transparent => false,
        }
    }
}

/// Consensus-relevant identity of the selected proof backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct BackendIdentity {
    /// Stable ZKSM83 protocol identifier.
    pub protocol: &'static str,
    /// Pinned upstream Jolt protocol reference revision.
    pub jolt_reference_revision: &'static str,
    /// Pinned upstream Akita revision.
    pub akita_revision: &'static str,
    /// Pinned transitive `jolt-field` revision.
    pub jolt_field_revision: &'static str,
    /// Digest of the embedded schedule artifact.
    pub schedule_sha256: &'static str,
    /// Digest of the embedded fixed-ISA table schedule artifact.
    pub isa_table_schedule_sha256: &'static str,
    /// Digest of the embedded one-MiB ROM schedule artifact.
    pub rom_schedule_sha256: &'static str,
    /// Digest of the embedded 128-KiB mutable-memory schedule artifact.
    pub memory_schedule_sha256: &'static str,
    /// Digest of the embedded fixed-capacity protocol-log schedule artifact.
    pub log_schedule_sha256: &'static str,
    /// Digest of the canonical fixed-ISA table commitment.
    pub isa_table_commitment_sha256: &'static str,
    /// Scalar field selected by the Akita adapter.
    pub field: &'static str,
    /// Fiat-Shamir transcript selected for native proofs.
    pub transcript: &'static str,
    /// Number of Boolean row-address variables in one trace segment.
    pub relation_num_variables: usize,
    /// Number of logical trace columns committed by the CPU relation.
    pub trace_column_count: usize,
    /// Number of fixed relation slots, including canonical zero tail slots.
    pub constraint_count: usize,
    /// Maximum CPU/device constraint degree before equality weighting.
    pub max_constraint_degree: usize,
    /// Fixed number of polynomials admitted in one trace commitment group.
    pub commitment_group_columns: usize,
    /// Implemented witness-privacy guarantee.
    pub privacy: ProofPrivacy,
    /// Whether execution passes through a RISC-V guest.
    pub uses_rv64_guest: bool,
}

/// Returns the exact backend identity that receipts must bind.
pub const fn backend_identity() -> BackendIdentity {
    BackendIdentity {
        protocol: PROTOCOL_ID,
        jolt_reference_revision: JOLT_REFERENCE_REVISION,
        akita_revision: AKITA_REVISION,
        jolt_field_revision: JOLT_FIELD_REVISION,
        schedule_sha256: AKITA_SCHEDULE_SHA256,
        isa_table_schedule_sha256: AKITA_ISA_TABLE_SCHEDULE_SHA256,
        rom_schedule_sha256: AKITA_ROM_SCHEDULE_SHA256,
        memory_schedule_sha256: AKITA_MEMORY_SCHEDULE_SHA256,
        log_schedule_sha256: AKITA_LOG_SCHEDULE_SHA256,
        isa_table_commitment_sha256: FIXED_ISA_TABLE_COMMITMENT_SHA256,
        field: "akita-proof-optimized-fp128-dense-bounded",
        transcript: "blake2b-512",
        relation_num_variables: UNIFORM_NUM_VARIABLES,
        trace_column_count: NATIVE_TRACE_COLUMN_COUNT,
        constraint_count: CPU_STRUCTURAL_CONSTRAINT_COUNT,
        max_constraint_degree: CPU_STRUCTURAL_MAX_DEGREE,
        commitment_group_columns: COMMITMENT_GROUP_COLUMNS,
        privacy: ProofPrivacy::Transparent,
        uses_rv64_guest: false,
    }
}

#[cfg(test)]
mod tests {
    use super::{ProofPrivacy, backend_identity};

    #[test]
    fn backend_identity_excludes_rv64_and_witness_hiding() {
        let identity = backend_identity();
        assert!(!identity.uses_rv64_guest);
        assert_eq!(identity.privacy, ProofPrivacy::Transparent);
        assert!(!identity.privacy.hides_witness());
    }
}
