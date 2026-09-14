//! Native SM83 integration boundary for the Jolt protocol and Akita PCS.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod baseline;
mod block_boundary;
mod block_bus;
mod block_control;
mod block_cpu;
mod block_device;
mod block_device_apu;
mod block_device_dma;
mod block_device_joypad;
mod block_device_mmio;
mod block_device_ppu;
mod block_device_ppu_interrupt;
mod block_device_ppu_mmio;
mod block_device_serial;
mod block_device_serial_mmio;
mod block_device_timer;
mod block_device_timer_core;
mod block_device_timer_mmio;
mod block_device_timer_stage;
mod block_flow;
mod block_frontend;
mod block_isa;
mod block_isa_control;
mod block_machine;
mod block_memory;
mod block_metadata;
mod block_proof;
mod block_routing;
#[cfg(test)]
mod block_test_support;
mod continuity;
mod cpu;
mod execution_lookup;
mod field_batch;
mod field_fold;
mod isa;
mod isa_lookup;
mod logs;
mod memory;
mod metrics;
mod optimization;
mod pcs;
mod pcs_batch_gate;
mod prover_backend;
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
pub use block_boundary::{
    BLOCK_BOUNDARY_COLUMN_COUNT, BLOCK_BOUNDARY_CONSTRAINT_COUNT, BLOCK_BOUNDARY_MAX_DEGREE,
    BLOCK_DEVICE_STATE_SCALAR_COUNT, BLOCK_LOCAL_STATE_SCALAR_COUNT, BlockBoundaryError,
    BlockBoundaryRelation, BlockBoundaryWitness,
};
pub use block_bus::{
    BLOCK_BUS_COLUMN_COUNT, BLOCK_BUS_CONSTRAINT_COUNT, BLOCK_BUS_MAX_DEGREE, BlockBusError,
    BlockBusRelation, BlockBusWitness,
};
pub use block_control::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_CONTROL_CONSTRAINT_COUNT, BLOCK_CONTROL_MAX_DEGREE,
    BlockControlError, BlockControlRelation, BlockControlWitness,
};
pub use block_cpu::{
    BLOCK_CPU_COLUMN_COUNT, BLOCK_CPU_CONSTRAINT_COUNT, BLOCK_CPU_MAX_DEGREE, BlockCpuError,
    BlockCpuRelation, BlockCpuWitness, PackedCpuCachedValue, PackedCpuEvaluationHotspot,
    PackedCpuEvaluationProfile,
};
pub use block_device::{
    BLOCK_DEVICE_ENVELOPE_COLUMN_COUNT, BLOCK_DEVICE_ENVELOPE_CONSTRAINT_COUNT,
    BLOCK_DEVICE_ENVELOPE_MAX_DEGREE, BlockDeviceEnvelopeError, BlockDeviceEnvelopeRelation,
    BlockDeviceEnvelopeWitness,
};
pub use block_device_apu::{
    BLOCK_DEVICE_APU_COLUMN_COUNT, BLOCK_DEVICE_APU_CONSTRAINT_COUNT, BLOCK_DEVICE_APU_MAX_DEGREE,
    BlockDeviceApuError, BlockDeviceApuRelation, BlockDeviceApuWitness,
};
pub use block_device_dma::{
    BLOCK_DEVICE_DMA_COLUMN_COUNT, BLOCK_DEVICE_DMA_CONSTRAINT_COUNT, BLOCK_DEVICE_DMA_MAX_DEGREE,
    BlockDeviceDmaError, BlockDeviceDmaRelation, BlockDeviceDmaWitness,
};
pub use block_device_joypad::{
    BLOCK_DEVICE_JOYPAD_COLUMN_COUNT, BLOCK_DEVICE_JOYPAD_CONSTRAINT_COUNT,
    BLOCK_DEVICE_JOYPAD_MAX_DEGREE, BlockDeviceJoypadError, BlockDeviceJoypadRelation,
    BlockDeviceJoypadWitness,
};
pub use block_device_mmio::{
    BLOCK_DEVICE_MMIO_COLUMN_COUNT, BLOCK_DEVICE_MMIO_CONSTRAINT_COUNT,
    BLOCK_DEVICE_MMIO_MAX_DEGREE, BlockDeviceMmioError, BlockDeviceMmioRelation,
    BlockDeviceMmioWitness,
};
pub use block_device_ppu::{
    BLOCK_DEVICE_PPU_COLUMN_COUNT, BLOCK_DEVICE_PPU_CONSTRAINT_COUNT, BLOCK_DEVICE_PPU_MAX_DEGREE,
    BlockDevicePpuError, BlockDevicePpuRelation, BlockDevicePpuWitness,
};
pub use block_device_ppu_interrupt::{
    BLOCK_DEVICE_PPU_INTERRUPT_COLUMN_COUNT, BLOCK_DEVICE_PPU_INTERRUPT_CONSTRAINT_COUNT,
    BLOCK_DEVICE_PPU_INTERRUPT_MAX_DEGREE, BlockDevicePpuInterruptError,
    BlockDevicePpuInterruptRelation, BlockDevicePpuInterruptWitness,
};
pub use block_device_ppu_mmio::{
    BLOCK_DEVICE_PPU_MMIO_COLUMN_COUNT, BLOCK_DEVICE_PPU_MMIO_CONSTRAINT_COUNT,
    BLOCK_DEVICE_PPU_MMIO_MAX_DEGREE, BlockDevicePpuMmioError, BlockDevicePpuMmioRelation,
    BlockDevicePpuMmioWitness,
};
pub use block_device_serial::{
    BLOCK_DEVICE_SERIAL_COLUMN_COUNT, BLOCK_DEVICE_SERIAL_CONSTRAINT_COUNT,
    BLOCK_DEVICE_SERIAL_MAX_DEGREE, BlockDeviceSerialError, BlockDeviceSerialRelation,
    BlockDeviceSerialWitness,
};
pub use block_device_serial_mmio::{
    BLOCK_DEVICE_SERIAL_MMIO_COLUMN_COUNT, BLOCK_DEVICE_SERIAL_MMIO_CONSTRAINT_COUNT,
    BLOCK_DEVICE_SERIAL_MMIO_MAX_DEGREE, BlockDeviceSerialMmioError, BlockDeviceSerialMmioRelation,
    BlockDeviceSerialMmioWitness,
};
pub use block_device_timer::{
    BLOCK_DEVICE_TIMER_COLUMN_COUNT, BLOCK_DEVICE_TIMER_CONSTRAINT_COUNT,
    BLOCK_DEVICE_TIMER_MAX_DEGREE, BlockDeviceTimerError, BlockDeviceTimerRelation,
    BlockDeviceTimerWitness,
};
pub use block_device_timer_core::{
    BLOCK_DEVICE_TIMER_CORE_COLUMN_COUNT, BLOCK_DEVICE_TIMER_CORE_CONSTRAINT_COUNT,
    BLOCK_DEVICE_TIMER_CORE_MAX_DEGREE, BlockDeviceTimerCoreError, BlockDeviceTimerCoreRelation,
    BlockDeviceTimerCoreWitness,
};
pub use block_device_timer_mmio::{
    BLOCK_DEVICE_TIMER_MMIO_COLUMN_COUNT, BLOCK_DEVICE_TIMER_MMIO_CONSTRAINT_COUNT,
    BLOCK_DEVICE_TIMER_MMIO_MAX_DEGREE, BlockDeviceTimerMmioError, BlockDeviceTimerMmioRelation,
    BlockDeviceTimerMmioWitness,
};
pub use block_flow::{
    BLOCK_FLOW_COLUMN_COUNT, BLOCK_FLOW_CONSTRAINT_COUNT, BLOCK_FLOW_MAX_DEGREE, BlockFlowRelation,
};
pub use block_frontend::{
    BLOCK_FRONTEND_COLUMN_COUNT, BLOCK_FRONTEND_CONSTRAINT_COUNT, BLOCK_FRONTEND_MAX_DEGREE,
    BlockFrontendError, BlockFrontendRelation, BlockFrontendWitness,
};
pub use block_isa::{
    BLOCK_ISA_COLUMN_COUNT, BLOCK_ISA_CONSTRAINT_COUNT, BLOCK_ISA_LANE_COLUMN_COUNT,
    BLOCK_ISA_MAX_DEGREE, BlockIsaError, BlockIsaRelation, BlockIsaWitness,
};
pub use block_isa_control::{
    BLOCK_ISA_CONTROL_COLUMN_COUNT, BLOCK_ISA_CONTROL_CONSTRAINT_COUNT,
    BLOCK_ISA_CONTROL_MAX_DEGREE, BlockIsaControlError, BlockIsaControlRelation,
    BlockIsaControlWitness,
};
pub use block_machine::{
    BLOCK_MACHINE_COLUMN_COUNT, BLOCK_MACHINE_CONSTRAINT_COUNT, BLOCK_MACHINE_MAX_DEGREE,
    BlockMachineError, BlockMachineRelation, BlockMachineWitness,
};
pub use block_memory::{
    BLOCK_MEMORY_COLUMN_COUNT, BLOCK_MEMORY_CONSTRAINT_COUNT, BLOCK_MEMORY_MAX_DEGREE,
    BlockMemoryError, BlockMemoryRelation, BlockMemoryWitness,
};
pub use block_proof::{
    PACKED_BLOCK_ISA_LOOKUP_COUNT, PackedBlockProof, PackedBlockProofError,
    prove_packed_block_components, prove_packed_block_components_with_backend,
    verify_packed_block_components,
};
pub use block_routing::{
    BLOCK_ROUTING_COLUMN_COUNT, BLOCK_ROUTING_CONSTRAINT_COUNT, BLOCK_ROUTING_MAX_DEGREE,
    BlockRoutingError, BlockRoutingRelation, BlockRoutingWitness,
};
pub use continuity::{
    ContinuityError, NativeExecutionClaim, PackedContinuityProof, prove_packed_continuity,
    verify_packed_continuity,
};
pub use cpu::{CPU_STRUCTURAL_CONSTRAINT_COUNT, CPU_STRUCTURAL_MAX_DEGREE, CpuStructuralRelation};
pub use execution_lookup::{
    EXECUTION_LOOKUP_ADDRESS_BIT_COUNT, EXECUTION_LOOKUP_COLUMN_COUNT,
    EXECUTION_LOOKUP_INPUT_BIT_COUNT, EXECUTION_LOOKUP_OUTPUT_BIT_COUNT,
    EXECUTION_LOOKUP_WELL_FORMED_CONSTRAINT_COUNT, EXECUTION_LOOKUPS_PER_BLOCK,
    EXECUTION_LOOKUPS_PER_INSTRUCTION, ExecutionLookupColumns, ExecutionLookupProof,
    ExecutionLookupProofError, ExecutionLookupWellFormedRelation, ExecutionLookupWitness,
    ExecutionLookupWitnessError, evaluate_packed_execution_table_entry,
};
pub use field_fold::FieldFoldError;
pub use isa::{
    ISA_ARGUMENT_ONE_BITS_START, ISA_ARGUMENT_ZERO_BITS_START, ISA_BASE_M_CYCLES, ISA_DATA_READS,
    ISA_DATA_WRITES, ISA_IMMEDIATE_READS, ISA_OPCODE_FETCHES, ISA_OPERATION_BITS_START,
    ISA_OUTPUT_COUNT, ISA_PACKED_HIGH, ISA_PACKED_LOW, ISA_PADDING_ADDRESS, ISA_TABLE_ROW_COUNT,
    ISA_TAKEN_DATA_READS, ISA_TAKEN_DATA_WRITES, ISA_TAKEN_M_CYCLES, ISA_TAKEN_TIMING, ISA_VALID,
    ISA_WRITE_BITS_START, IsaTableError, IsaTableRow, fixed_isa_table, fixed_isa_table_digest,
};
pub use isa_lookup::{
    FIXED_ISA_TABLE_COMMITMENT_SHA256, FixedIsaCommitments, ISA_ADDRESS_BIT_COUNT,
    IsaLookupColumns, IsaLookupError, IsaLookupProof, prove_isa_lookup, verify_isa_lookup,
};
pub use logs::{
    CommittedProtocolLogs, PackedProtocolLogClaim, PackedProtocolLogProof, ProtocolLogCommitments,
    ProtocolLogError, commit_packed_protocol_logs, prove_packed_protocol_logs,
    verify_packed_protocol_logs,
};
pub use memory::{
    CommittedMemory, MEMORY_IMAGE_BYTES, MEMORY_TABLE_NUM_VARIABLES, MemoryCommitment,
    MutableMemoryError, PackedMutableMemoryProof, commit_memory, prove_packed_mutable_memory,
    verify_packed_mutable_memory,
};
pub use metrics::{NativeProofPhaseMetrics, native_proof_phase_metrics};
pub use optimization::{
    AkitaOptimizationAssessment, AkitaOptimizationDecision, AkitaOptimizationTrack,
    BenchmarkInstrumentation, EvaluationPointBinding, NativeBenchmarkBucket,
    NativeBenchmarkPlanItem, NativeBenchmarkUnit, ProofObligationFamily, ProofObligationMetadata,
    akita_optimization_assessment, native_benchmark_plan, packed_block_obligation_metadata,
};
pub use pcs_batch_gate::{
    PcsBatchGateError, PcsBatchGateMode, PcsBatchPathReport, PcsBatchTamperReport,
    run_pcs_batch_gate_worker,
};
pub use prover_backend::{NativeProverBackend, NativeProverBackendError, NativeProverBackendKind};
pub use receipt::{
    CommitmentIdentity, CommitmentKind, MAX_NATIVE_RECEIPT_BYTES, MAX_NATIVE_ROM_COMMITMENT_BYTES,
    MAX_NATIVE_SEGMENT_BYTES, MAX_NATIVE_SEGMENT_COUNT, MAX_NATIVE_STATEMENT_BYTES,
    MAX_NATIVE_STREAM_RECEIPT_BYTES, NATIVE_RECEIPT_VERSION, NativeBoundary, NativeReceipt,
    NativeReceiptError, NativeReceiptStreamProver, NativeSegmentReceipt, NativeSegmentWitness,
    NativeStatement, ProtocolLogCounts, ProtocolLogIdentities, ProtocolLogKind,
    VerifiedNativeReceipt, VerifiedNativeSpool, native_backend_digest, verify_native_receipt,
    verify_native_receipt_bytes, verify_native_receipt_reader, verify_native_spool_reader,
};
pub use rom_lookup::{
    CommittedRom, ROM_256KIB_IMAGE_BYTES, ROM_ADDRESS_BIT_COUNT, ROM_IMAGE_BYTES, RomCommitment,
    RomLookupColumns, RomLookupError, RomLookupProof, commit_rom, prove_rom_lookup,
    verify_rom_lookup,
};
use serde::Serialize;
pub use state::{
    NativeStateBoundary, STATE_APU_CONTROL_HIGH_PACK_INDEX, STATE_APU_CONTROL_LOW_PACK_INDEX,
    STATE_APU_MIXER_PACK_INDEX, STATE_APU_WAVE_HIGH_PACK_INDEX, STATE_APU_WAVE_LOW_PACK_INDEX,
    STATE_BUS_NEXT_INDEX, STATE_CPU_M_CYCLES_INDEX, STATE_DMA_PACK_INDEX,
    STATE_DMG_HIGH_REGISTER_PACK_INDEX, STATE_DMG_LOW_REGISTER_PACK_INDEX, STATE_INPUT_NEXT_INDEX,
    STATE_INTERRUPT_ENABLE_INDEX, STATE_INTERRUPT_REQUEST_INDEX, STATE_ISA_NEXT_INDEX,
    STATE_JOYPAD_PACK_INDEX, STATE_MACHINE_PROFILE_INDEX, STATE_OUTPUT_NEXT_INDEX,
    STATE_PPU_DOT_INDEX, STATE_PPU_LINE_INDEX, STATE_SCALAR_COUNT, STATE_SCALAR_NAMES,
    STATE_TIMER_COUNTER_INDEX, STATE_TIMER_DIV_INDEX, STATE_TIMER_EDGE_LATCH_INDEX,
    STATE_TIMER_RELOAD_PHASE_INDEX, encode_state_scalars,
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
    TRACE_SIGNED_SP_UNDERFLOW, TRACE_STACK_FIRST_WRAP, TRACE_STACK_WRAP, TRACE_WORD_CARRY,
    TRACE_WORD_HALF_CARRY, TRACE_WORD_WRAP,
};
pub use uniform::{
    BLOCK_CPU_COMMITMENT_GROUP_COUNT, BLOCK_CPU_OPENING_COUNT, BLOCK_CPU_PADDED_COLUMN_COUNT,
    BLOCK_CPU_PADDING_COLUMN_COUNT, COMMITMENT_GROUP_COLUMNS, CommittedWitness, ConstraintOutput,
    NATIVE_TRACE_COMMITMENT_GROUP_COUNT, NATIVE_TRACE_OPENING_COUNT,
    NATIVE_TRACE_PADDED_COLUMN_COUNT, NATIVE_TRACE_PADDING_COLUMN_COUNT, NativeField,
    UNIFORM_NUM_VARIABLES, UNIFORM_ROW_COUNT, UniformError, UniformProof, UniformRelation,
    UniformRelationProof, WitnessCommitments, commit_witness, prove_uniform,
    prove_uniform_committed, validate_uniform_witness, verify_uniform, verify_uniform_committed,
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

/// SHA-256 of the single-group 14-variable auxiliary relation schedule.
pub const AKITA_AUXILIARY_SCHEDULE_SHA256: &str =
    "e601bc0bd9d4501220c367b3012901aac09467f145899c8e907b282d30e96646";

/// SHA-256 of the version-two paired 14-variable, 128-column relation schedule.
pub const AKITA_SCHEDULE_SHA256_V2: &str =
    "1cd339f09114c2a941abbfb434ab795868866cb15485f83300d81cee7bf46e71";

/// SHA-256 of the current native trace schedule.
pub const AKITA_SCHEDULE_SHA256: &str = AKITA_SCHEDULE_SHA256_V2;

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

/// Stable protocol identifier for canonical version-two receipts.
pub const PROTOCOL_ID_V2: &str = "zksm83-native-jolt-akita-v2";

/// Stable protocol identifier emitted by the current prover.
pub const PROTOCOL_ID: &str = PROTOCOL_ID_V2;

/// Explicit proof/receipt composition revision bound by current backend identities.
pub const PROOF_COMPOSITION_REVISION_V2: &str = "packed-block-jolt-execution-shout-compact20-compact-aux55-isa38-mbc3-profiled-rom-size-rtc-wire-v2";

/// The sole native receipt protocol revision supported by this build.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeProtocolVersion {
    /// Canonical paired-opening receipt emitted by current provers.
    V2,
}

impl NativeProtocolVersion {
    /// Returns the protocol emitted by current provers.
    #[must_use]
    pub const fn current() -> Self {
        Self::V2
    }

    /// Decodes a canonical receipt version number.
    #[must_use]
    pub const fn from_code(code: u64) -> Option<Self> {
        match code {
            2 => Some(Self::V2),
            _ => None,
        }
    }

    /// Returns the canonical receipt version number.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::V2 => 2,
        }
    }

    /// Returns the stable protocol identifier.
    #[must_use]
    pub const fn protocol_id(self) -> &'static str {
        match self {
            Self::V2 => PROTOCOL_ID_V2,
        }
    }

    /// Returns the pinned trace schedule digest.
    #[must_use]
    pub const fn trace_schedule_sha256(self) -> &'static str {
        match self {
            Self::V2 => AKITA_SCHEDULE_SHA256_V2,
        }
    }
}

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
    /// Digest of the single-group schedule used by auxiliary trace planes.
    pub auxiliary_schedule_sha256: &'static str,
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
    /// Exact proof/receipt composition revision, including auxiliary relations and wire fields.
    pub proof_composition_revision: &'static str,
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
}

/// Returns the exact backend identity that receipts must bind.
pub const fn backend_identity() -> BackendIdentity {
    backend_identity_for(NativeProtocolVersion::current())
}

/// Returns the exact backend identity bound by one supported receipt protocol.
#[must_use]
pub const fn backend_identity_for(protocol: NativeProtocolVersion) -> BackendIdentity {
    BackendIdentity {
        protocol: protocol.protocol_id(),
        jolt_reference_revision: JOLT_REFERENCE_REVISION,
        akita_revision: AKITA_REVISION,
        jolt_field_revision: JOLT_FIELD_REVISION,
        schedule_sha256: protocol.trace_schedule_sha256(),
        auxiliary_schedule_sha256: AKITA_AUXILIARY_SCHEDULE_SHA256,
        isa_table_schedule_sha256: AKITA_ISA_TABLE_SCHEDULE_SHA256,
        rom_schedule_sha256: AKITA_ROM_SCHEDULE_SHA256,
        memory_schedule_sha256: AKITA_MEMORY_SCHEDULE_SHA256,
        log_schedule_sha256: AKITA_LOG_SCHEDULE_SHA256,
        isa_table_commitment_sha256: FIXED_ISA_TABLE_COMMITMENT_SHA256,
        field: "akita-proof-optimized-fp128-dense-bounded",
        transcript: "blake2b-512",
        proof_composition_revision: PROOF_COMPOSITION_REVISION_V2,
        relation_num_variables: UNIFORM_NUM_VARIABLES,
        trace_column_count: BLOCK_CPU_COLUMN_COUNT,
        constraint_count: BLOCK_CPU_CONSTRAINT_COUNT,
        max_constraint_degree: BLOCK_CPU_MAX_DEGREE,
        commitment_group_columns: COMMITMENT_GROUP_COLUMNS,
        privacy: ProofPrivacy::Transparent,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BLOCK_CPU_COLUMN_COUNT, BLOCK_CPU_COMMITMENT_GROUP_COUNT, BLOCK_CPU_CONSTRAINT_COUNT,
        BLOCK_CPU_MAX_DEGREE, BLOCK_CPU_OPENING_COUNT, BLOCK_CPU_PADDED_COLUMN_COUNT,
        BLOCK_CPU_PADDING_COLUMN_COUNT, NATIVE_RECEIPT_VERSION, NativeProtocolVersion,
        ProofPrivacy, backend_identity,
    };

    #[test]
    fn backend_identity_exposes_transparent_privacy() {
        let identity = backend_identity();
        assert_eq!(identity.privacy, ProofPrivacy::Transparent);
        assert!(!identity.privacy.hides_witness());
    }

    #[test]
    fn protocol_identity_is_v2_only() {
        assert_eq!(NativeProtocolVersion::from_code(1), None);
        let current = backend_identity();
        assert_eq!(current.trace_column_count, BLOCK_CPU_COLUMN_COUNT);
        assert_eq!(current.constraint_count, BLOCK_CPU_CONSTRAINT_COUNT);
        assert_eq!(current.max_constraint_degree, BLOCK_CPU_MAX_DEGREE);
        assert_eq!(
            current.proof_composition_revision,
            super::PROOF_COMPOSITION_REVISION_V2
        );
        assert_eq!(BLOCK_CPU_COMMITMENT_GROUP_COUNT, 36);
        assert_eq!(BLOCK_CPU_OPENING_COUNT, 18);
        assert_eq!(BLOCK_CPU_PADDED_COLUMN_COUNT, 4_608);
        assert_eq!(BLOCK_CPU_PADDING_COLUMN_COUNT, 4);
        assert_eq!(NativeProtocolVersion::V2.code(), NATIVE_RECEIPT_VERSION);
        assert_eq!(NativeProtocolVersion::current(), NativeProtocolVersion::V2);
    }
}
