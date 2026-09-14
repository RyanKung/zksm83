#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![recursion_limit = "256"]

//! Proof-free execution profiler for generic native-SM83 workloads.

use std::{process::ExitCode, time::Instant};

use clap::Parser;
use serde::Serialize;
use thiserror::Error;
use zksm83_jolt::{
    BLOCK_BOUNDARY_COLUMN_COUNT, BLOCK_BOUNDARY_CONSTRAINT_COUNT, BLOCK_BOUNDARY_MAX_DEGREE,
    BLOCK_BUS_COLUMN_COUNT, BLOCK_BUS_CONSTRAINT_COUNT, BLOCK_BUS_MAX_DEGREE,
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_CONTROL_CONSTRAINT_COUNT, BLOCK_CONTROL_MAX_DEGREE,
    BLOCK_CPU_COLUMN_COUNT, BLOCK_CPU_COMMITMENT_GROUP_COUNT, BLOCK_CPU_CONSTRAINT_COUNT,
    BLOCK_CPU_MAX_DEGREE, BLOCK_CPU_OPENING_COUNT, BLOCK_CPU_PADDED_COLUMN_COUNT,
    BLOCK_CPU_PADDING_COLUMN_COUNT, BLOCK_DEVICE_APU_COLUMN_COUNT,
    BLOCK_DEVICE_APU_CONSTRAINT_COUNT, BLOCK_DEVICE_APU_MAX_DEGREE, BLOCK_DEVICE_DMA_COLUMN_COUNT,
    BLOCK_DEVICE_DMA_CONSTRAINT_COUNT, BLOCK_DEVICE_DMA_MAX_DEGREE,
    BLOCK_DEVICE_ENVELOPE_COLUMN_COUNT, BLOCK_DEVICE_ENVELOPE_CONSTRAINT_COUNT,
    BLOCK_DEVICE_ENVELOPE_MAX_DEGREE, BLOCK_DEVICE_JOYPAD_COLUMN_COUNT,
    BLOCK_DEVICE_JOYPAD_CONSTRAINT_COUNT, BLOCK_DEVICE_JOYPAD_MAX_DEGREE,
    BLOCK_DEVICE_MMIO_COLUMN_COUNT, BLOCK_DEVICE_MMIO_CONSTRAINT_COUNT,
    BLOCK_DEVICE_MMIO_MAX_DEGREE, BLOCK_DEVICE_PPU_COLUMN_COUNT, BLOCK_DEVICE_PPU_CONSTRAINT_COUNT,
    BLOCK_DEVICE_PPU_INTERRUPT_COLUMN_COUNT, BLOCK_DEVICE_PPU_INTERRUPT_CONSTRAINT_COUNT,
    BLOCK_DEVICE_PPU_INTERRUPT_MAX_DEGREE, BLOCK_DEVICE_PPU_MAX_DEGREE,
    BLOCK_DEVICE_PPU_MMIO_COLUMN_COUNT, BLOCK_DEVICE_PPU_MMIO_CONSTRAINT_COUNT,
    BLOCK_DEVICE_PPU_MMIO_MAX_DEGREE, BLOCK_DEVICE_SERIAL_COLUMN_COUNT,
    BLOCK_DEVICE_SERIAL_CONSTRAINT_COUNT, BLOCK_DEVICE_SERIAL_MAX_DEGREE,
    BLOCK_DEVICE_SERIAL_MMIO_COLUMN_COUNT, BLOCK_DEVICE_SERIAL_MMIO_CONSTRAINT_COUNT,
    BLOCK_DEVICE_SERIAL_MMIO_MAX_DEGREE, BLOCK_DEVICE_TIMER_COLUMN_COUNT,
    BLOCK_DEVICE_TIMER_CONSTRAINT_COUNT, BLOCK_DEVICE_TIMER_CORE_COLUMN_COUNT,
    BLOCK_DEVICE_TIMER_CORE_CONSTRAINT_COUNT, BLOCK_DEVICE_TIMER_CORE_MAX_DEGREE,
    BLOCK_DEVICE_TIMER_MAX_DEGREE, BLOCK_DEVICE_TIMER_MMIO_COLUMN_COUNT,
    BLOCK_DEVICE_TIMER_MMIO_CONSTRAINT_COUNT, BLOCK_DEVICE_TIMER_MMIO_MAX_DEGREE,
    BLOCK_FLOW_COLUMN_COUNT, BLOCK_FLOW_CONSTRAINT_COUNT, BLOCK_FLOW_MAX_DEGREE,
    BLOCK_FRONTEND_COLUMN_COUNT, BLOCK_FRONTEND_CONSTRAINT_COUNT, BLOCK_FRONTEND_MAX_DEGREE,
    BLOCK_ISA_COLUMN_COUNT, BLOCK_ISA_CONSTRAINT_COUNT, BLOCK_ISA_CONTROL_COLUMN_COUNT,
    BLOCK_ISA_CONTROL_CONSTRAINT_COUNT, BLOCK_ISA_CONTROL_MAX_DEGREE, BLOCK_ISA_MAX_DEGREE,
    BLOCK_MACHINE_COLUMN_COUNT, BLOCK_MACHINE_CONSTRAINT_COUNT, BLOCK_MACHINE_MAX_DEGREE,
    BLOCK_MEMORY_COLUMN_COUNT, BLOCK_MEMORY_CONSTRAINT_COUNT, BLOCK_MEMORY_MAX_DEGREE,
    BLOCK_ROUTING_COLUMN_COUNT, BLOCK_ROUTING_CONSTRAINT_COUNT, BLOCK_ROUTING_MAX_DEGREE,
    BlockCpuError, BlockCpuRelation, BlockCpuWitness, COMMITMENT_GROUP_COLUMNS,
    MEMORY_TABLE_NUM_VARIABLES, NativeField, NativeStateBoundary, PROOF_COMPOSITION_REVISION_V2,
    PROTOCOL_ID, UNIFORM_ROW_COUNT, UniformError, native_backend_digest, validate_uniform_witness,
};
use zksm83_memory::{MemoryImage, MemoryImageError, RomImage, RomImageError};
use zksm83_trace::{
    BASIC_BLOCK_BUS_EVENT_BOUND, BASIC_BLOCK_INSTRUCTION_BOUND, BASIC_BLOCK_M_CYCLE_BOUND,
    BasicBlockPlanError, ExecutionMetrics, LookupTraceBuilder, LookupTraceBuilderError,
    ProgramCounterCount, pack_witness_basic_blocks,
};

const REPORT_SCHEMA: &str = "zksm83-proof-free-profile/v4";
const DEFAULT_STEPS: u64 = 4_096;
const DEFAULT_REPEATS: usize = 5;
const PROFILED_PROGRAM_COUNTERS: usize = 8;

#[derive(Debug, Parser)]
#[command(about = "Profile generic SM83 witness construction without generating a proof")]
struct Args {
    /// Exact source SM83 transitions executed by each deterministic workload.
    #[arg(long, default_value_t = DEFAULT_STEPS)]
    steps: u64,
    /// Independent samples collected for each workload.
    #[arg(long, default_value_t = DEFAULT_REPEATS)]
    repeats: usize,
    /// Optionally retain, pack, encode, and validate this many stack-workload transitions.
    #[arg(long)]
    packed_trace_steps: Option<u64>,
}

#[derive(Clone, Copy)]
struct Workload {
    name: &'static str,
    program: &'static [u8],
    supplies_input: bool,
}

const WORKLOADS: [Workload; 4] = [
    Workload {
        name: "cpu_branch_loop",
        program: &[0x04, 0x18, 0xfd],
        supplies_input: false,
    },
    Workload {
        name: "wram_read_write_loop",
        program: &[0x21, 0x00, 0xc0, 0x34, 0x7e, 0x18, 0xfc],
        supplies_input: false,
    },
    Workload {
        name: "stack_multi_write_loop",
        program: &[0xc5, 0xc1, 0x18, 0xfc],
        supplies_input: false,
    },
    Workload {
        name: "joypad_input_loop",
        program: &[0xf0, 0x00, 0x18, 0xfc],
        supplies_input: true,
    },
];

#[derive(Debug, Serialize)]
struct ProfileReport {
    schema: &'static str,
    protocol_id: &'static str,
    proof_composition_revision: &'static str,
    backend_digest_sha256: String,
    dimensions: RelationDimensions,
    workloads: Vec<WorkloadReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    packed_trace: Option<PackedTraceReport>,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct RelationDimensions {
    segment_rows: usize,
    trace_columns: usize,
    constraint_slots: usize,
    maximum_constraint_degree: usize,
    commitment_group_columns: usize,
    commitment_groups: usize,
    paired_openings: usize,
    padded_trace_columns: usize,
    padding_trace_columns: usize,
    basic_block_instruction_bound: usize,
    basic_block_m_cycle_bound: usize,
    basic_block_bus_event_bound: usize,
    block_routing_columns: usize,
    block_routing_constraint_slots: usize,
    block_routing_maximum_degree: usize,
    block_boundary_columns: usize,
    block_boundary_constraint_slots: usize,
    block_boundary_maximum_degree: usize,
    block_control_columns: usize,
    block_control_constraint_slots: usize,
    block_control_maximum_degree: usize,
    block_isa_columns: usize,
    block_isa_constraint_slots: usize,
    block_isa_maximum_degree: usize,
    block_isa_control_columns: usize,
    block_isa_control_constraint_slots: usize,
    block_isa_control_maximum_degree: usize,
    block_bus_columns: usize,
    block_bus_constraint_slots: usize,
    block_bus_maximum_degree: usize,
    block_frontend_columns: usize,
    block_frontend_constraint_slots: usize,
    block_frontend_maximum_degree: usize,
    block_flow_columns: usize,
    block_flow_constraint_slots: usize,
    block_flow_maximum_degree: usize,
    block_device_envelope_columns: usize,
    block_device_envelope_constraint_slots: usize,
    block_device_envelope_maximum_degree: usize,
    block_device_ppu_columns: usize,
    block_device_ppu_constraint_slots: usize,
    block_device_ppu_maximum_degree: usize,
    block_device_serial_columns: usize,
    block_device_serial_constraint_slots: usize,
    block_device_serial_maximum_degree: usize,
    block_device_timer_columns: usize,
    block_device_timer_constraint_slots: usize,
    block_device_timer_maximum_degree: usize,
    block_device_timer_core_columns: usize,
    block_device_timer_core_constraint_slots: usize,
    block_device_timer_core_maximum_degree: usize,
    block_device_ppu_interrupt_columns: usize,
    block_device_ppu_interrupt_constraint_slots: usize,
    block_device_ppu_interrupt_maximum_degree: usize,
    block_device_dma_columns: usize,
    block_device_dma_constraint_slots: usize,
    block_device_dma_maximum_degree: usize,
    block_device_mmio_columns: usize,
    block_device_mmio_constraint_slots: usize,
    block_device_mmio_maximum_degree: usize,
    block_device_joypad_columns: usize,
    block_device_joypad_constraint_slots: usize,
    block_device_joypad_maximum_degree: usize,
    block_device_apu_columns: usize,
    block_device_apu_constraint_slots: usize,
    block_device_apu_maximum_degree: usize,
    block_device_serial_mmio_columns: usize,
    block_device_serial_mmio_constraint_slots: usize,
    block_device_serial_mmio_maximum_degree: usize,
    block_device_timer_mmio_columns: usize,
    block_device_timer_mmio_constraint_slots: usize,
    block_device_timer_mmio_maximum_degree: usize,
    block_device_ppu_mmio_columns: usize,
    block_device_ppu_mmio_constraint_slots: usize,
    block_device_ppu_mmio_maximum_degree: usize,
    block_memory_columns: usize,
    block_memory_constraint_slots: usize,
    block_memory_maximum_degree: usize,
    block_cpu_columns: usize,
    block_cpu_constraint_slots: usize,
    block_cpu_maximum_degree: usize,
    block_machine_columns: usize,
    block_machine_constraint_slots: usize,
    block_machine_maximum_degree: usize,
    trace_scalar_cells: usize,
    trace_column_payload_bytes: usize,
    native_field_bytes: usize,
    memory_timestamp_payload_bytes: usize,
}

const RELATION_DIMENSIONS: RelationDimensions = RelationDimensions {
    segment_rows: UNIFORM_ROW_COUNT,
    trace_columns: BLOCK_CPU_COLUMN_COUNT,
    constraint_slots: BLOCK_CPU_CONSTRAINT_COUNT,
    maximum_constraint_degree: BLOCK_CPU_MAX_DEGREE,
    commitment_group_columns: COMMITMENT_GROUP_COLUMNS,
    commitment_groups: BLOCK_CPU_COMMITMENT_GROUP_COUNT,
    paired_openings: BLOCK_CPU_OPENING_COUNT,
    padded_trace_columns: BLOCK_CPU_PADDED_COLUMN_COUNT,
    padding_trace_columns: BLOCK_CPU_PADDING_COLUMN_COUNT,
    basic_block_instruction_bound: BASIC_BLOCK_INSTRUCTION_BOUND,
    basic_block_m_cycle_bound: BASIC_BLOCK_M_CYCLE_BOUND,
    basic_block_bus_event_bound: BASIC_BLOCK_BUS_EVENT_BOUND,
    block_routing_columns: BLOCK_ROUTING_COLUMN_COUNT,
    block_routing_constraint_slots: BLOCK_ROUTING_CONSTRAINT_COUNT,
    block_routing_maximum_degree: BLOCK_ROUTING_MAX_DEGREE,
    block_boundary_columns: BLOCK_BOUNDARY_COLUMN_COUNT,
    block_boundary_constraint_slots: BLOCK_BOUNDARY_CONSTRAINT_COUNT,
    block_boundary_maximum_degree: BLOCK_BOUNDARY_MAX_DEGREE,
    block_control_columns: BLOCK_CONTROL_COLUMN_COUNT,
    block_control_constraint_slots: BLOCK_CONTROL_CONSTRAINT_COUNT,
    block_control_maximum_degree: BLOCK_CONTROL_MAX_DEGREE,
    block_isa_columns: BLOCK_ISA_COLUMN_COUNT,
    block_isa_constraint_slots: BLOCK_ISA_CONSTRAINT_COUNT,
    block_isa_maximum_degree: BLOCK_ISA_MAX_DEGREE,
    block_isa_control_columns: BLOCK_ISA_CONTROL_COLUMN_COUNT,
    block_isa_control_constraint_slots: BLOCK_ISA_CONTROL_CONSTRAINT_COUNT,
    block_isa_control_maximum_degree: BLOCK_ISA_CONTROL_MAX_DEGREE,
    block_bus_columns: BLOCK_BUS_COLUMN_COUNT,
    block_bus_constraint_slots: BLOCK_BUS_CONSTRAINT_COUNT,
    block_bus_maximum_degree: BLOCK_BUS_MAX_DEGREE,
    block_frontend_columns: BLOCK_FRONTEND_COLUMN_COUNT,
    block_frontend_constraint_slots: BLOCK_FRONTEND_CONSTRAINT_COUNT,
    block_frontend_maximum_degree: BLOCK_FRONTEND_MAX_DEGREE,
    block_flow_columns: BLOCK_FLOW_COLUMN_COUNT,
    block_flow_constraint_slots: BLOCK_FLOW_CONSTRAINT_COUNT,
    block_flow_maximum_degree: BLOCK_FLOW_MAX_DEGREE,
    block_device_envelope_columns: BLOCK_DEVICE_ENVELOPE_COLUMN_COUNT,
    block_device_envelope_constraint_slots: BLOCK_DEVICE_ENVELOPE_CONSTRAINT_COUNT,
    block_device_envelope_maximum_degree: BLOCK_DEVICE_ENVELOPE_MAX_DEGREE,
    block_device_ppu_columns: BLOCK_DEVICE_PPU_COLUMN_COUNT,
    block_device_ppu_constraint_slots: BLOCK_DEVICE_PPU_CONSTRAINT_COUNT,
    block_device_ppu_maximum_degree: BLOCK_DEVICE_PPU_MAX_DEGREE,
    block_device_serial_columns: BLOCK_DEVICE_SERIAL_COLUMN_COUNT,
    block_device_serial_constraint_slots: BLOCK_DEVICE_SERIAL_CONSTRAINT_COUNT,
    block_device_serial_maximum_degree: BLOCK_DEVICE_SERIAL_MAX_DEGREE,
    block_device_timer_columns: BLOCK_DEVICE_TIMER_COLUMN_COUNT,
    block_device_timer_constraint_slots: BLOCK_DEVICE_TIMER_CONSTRAINT_COUNT,
    block_device_timer_maximum_degree: BLOCK_DEVICE_TIMER_MAX_DEGREE,
    block_device_timer_core_columns: BLOCK_DEVICE_TIMER_CORE_COLUMN_COUNT,
    block_device_timer_core_constraint_slots: BLOCK_DEVICE_TIMER_CORE_CONSTRAINT_COUNT,
    block_device_timer_core_maximum_degree: BLOCK_DEVICE_TIMER_CORE_MAX_DEGREE,
    block_device_ppu_interrupt_columns: BLOCK_DEVICE_PPU_INTERRUPT_COLUMN_COUNT,
    block_device_ppu_interrupt_constraint_slots: BLOCK_DEVICE_PPU_INTERRUPT_CONSTRAINT_COUNT,
    block_device_ppu_interrupt_maximum_degree: BLOCK_DEVICE_PPU_INTERRUPT_MAX_DEGREE,
    block_device_dma_columns: BLOCK_DEVICE_DMA_COLUMN_COUNT,
    block_device_dma_constraint_slots: BLOCK_DEVICE_DMA_CONSTRAINT_COUNT,
    block_device_dma_maximum_degree: BLOCK_DEVICE_DMA_MAX_DEGREE,
    block_device_mmio_columns: BLOCK_DEVICE_MMIO_COLUMN_COUNT,
    block_device_mmio_constraint_slots: BLOCK_DEVICE_MMIO_CONSTRAINT_COUNT,
    block_device_mmio_maximum_degree: BLOCK_DEVICE_MMIO_MAX_DEGREE,
    block_device_joypad_columns: BLOCK_DEVICE_JOYPAD_COLUMN_COUNT,
    block_device_joypad_constraint_slots: BLOCK_DEVICE_JOYPAD_CONSTRAINT_COUNT,
    block_device_joypad_maximum_degree: BLOCK_DEVICE_JOYPAD_MAX_DEGREE,
    block_device_apu_columns: BLOCK_DEVICE_APU_COLUMN_COUNT,
    block_device_apu_constraint_slots: BLOCK_DEVICE_APU_CONSTRAINT_COUNT,
    block_device_apu_maximum_degree: BLOCK_DEVICE_APU_MAX_DEGREE,
    block_device_serial_mmio_columns: BLOCK_DEVICE_SERIAL_MMIO_COLUMN_COUNT,
    block_device_serial_mmio_constraint_slots: BLOCK_DEVICE_SERIAL_MMIO_CONSTRAINT_COUNT,
    block_device_serial_mmio_maximum_degree: BLOCK_DEVICE_SERIAL_MMIO_MAX_DEGREE,
    block_device_timer_mmio_columns: BLOCK_DEVICE_TIMER_MMIO_COLUMN_COUNT,
    block_device_timer_mmio_constraint_slots: BLOCK_DEVICE_TIMER_MMIO_CONSTRAINT_COUNT,
    block_device_timer_mmio_maximum_degree: BLOCK_DEVICE_TIMER_MMIO_MAX_DEGREE,
    block_device_ppu_mmio_columns: BLOCK_DEVICE_PPU_MMIO_COLUMN_COUNT,
    block_device_ppu_mmio_constraint_slots: BLOCK_DEVICE_PPU_MMIO_CONSTRAINT_COUNT,
    block_device_ppu_mmio_maximum_degree: BLOCK_DEVICE_PPU_MMIO_MAX_DEGREE,
    block_memory_columns: BLOCK_MEMORY_COLUMN_COUNT,
    block_memory_constraint_slots: BLOCK_MEMORY_CONSTRAINT_COUNT,
    block_memory_maximum_degree: BLOCK_MEMORY_MAX_DEGREE,
    block_cpu_columns: BLOCK_CPU_COLUMN_COUNT,
    block_cpu_constraint_slots: BLOCK_CPU_CONSTRAINT_COUNT,
    block_cpu_maximum_degree: BLOCK_CPU_MAX_DEGREE,
    block_machine_columns: BLOCK_MACHINE_COLUMN_COUNT,
    block_machine_constraint_slots: BLOCK_MACHINE_CONSTRAINT_COUNT,
    block_machine_maximum_degree: BLOCK_MACHINE_MAX_DEGREE,
    trace_scalar_cells: BLOCK_CPU_COLUMN_COUNT * UNIFORM_ROW_COUNT,
    trace_column_payload_bytes: BLOCK_CPU_COLUMN_COUNT * UNIFORM_ROW_COUNT * size_of::<u64>(),
    native_field_bytes: size_of::<NativeField>(),
    memory_timestamp_payload_bytes: (1_usize << MEMORY_TABLE_NUM_VARIABLES) * size_of::<u64>(),
};

#[derive(Debug, Serialize)]
struct WorkloadReport {
    name: &'static str,
    steps: u64,
    repeats: usize,
    rom_witness_root: String,
    setup: TimingSummary,
    execution: TimingSummary,
    metrics: ExecutionMetrics,
    top_program_counters: Vec<ProgramCounterCount>,
    final_state_scalars: Vec<u64>,
}

#[derive(Debug, Serialize)]
struct PackedTraceReport {
    workload: &'static str,
    steps: u64,
    setup_microseconds: u128,
    retained_execution_microseconds: u128,
    block_planning_microseconds: u128,
    block_cpu_encoding_microseconds: u128,
    block_cpu_validation_microseconds: u128,
    planned_relation_rows: usize,
    planned_instruction_blocks: usize,
    planned_machine_event_rows: usize,
    maximum_planned_instruction_count: usize,
    maximum_planned_instruction_m_cycles: u64,
    maximum_planned_instruction_bus_events: usize,
    packed_active_rows: usize,
    packed_columns: usize,
    rows_per_column: usize,
    final_state_scalars: Vec<u64>,
}

#[derive(Debug, Serialize)]
struct TimingSummary {
    samples_microseconds: Vec<u128>,
    minimum_microseconds: u128,
    median_microseconds: u128,
    maximum_microseconds: u128,
}

#[derive(Debug, Eq, PartialEq)]
struct WorkloadSemantics {
    rom_witness_root: String,
    metrics: ExecutionMetrics,
    top_program_counters: Vec<ProgramCounterCount>,
    final_state_scalars: Vec<u64>,
}

struct WorkloadSample {
    setup_microseconds: u128,
    execution_microseconds: u128,
    semantics: WorkloadSemantics,
}

#[derive(Debug, Error)]
enum ProfileError {
    #[error("profile step count must be nonzero")]
    ZeroSteps,
    #[error("profile repeat count must be nonzero")]
    ZeroRepeats,
    #[error("profile step count does not fit this platform")]
    StepCountOverflow,
    #[error("packed trace profile step count {actual} exceeds segment capacity {maximum}")]
    PackedTraceStepBound { actual: u64, maximum: u64 },
    #[error("profile relation dimensions overflow this platform")]
    DimensionOverflow,
    #[error("synthetic ROM layout is invalid")]
    RomLayout,
    #[error("timing sample set violated its non-empty invariant")]
    TimingInvariant,
    #[error("repeated execution produced a different semantic result for {workload}")]
    NondeterministicWorkload { workload: &'static str },
    #[error(transparent)]
    Rom(#[from] RomImageError),
    #[error(transparent)]
    Memory(#[from] MemoryImageError),
    #[error(transparent)]
    Trace(#[from] LookupTraceBuilderError),
    #[error(transparent)]
    BasicBlock(#[from] BasicBlockPlanError),
    #[error(transparent)]
    BlockCpu(#[from] BlockCpuError),
    #[error(transparent)]
    Uniform(#[from] UniformError),
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("proof-free profile serialization failed: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("proof-free profile failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<ProfileReport, ProfileError> {
    if args.steps == 0 {
        return Err(ProfileError::ZeroSteps);
    }
    if args.repeats == 0 {
        return Err(ProfileError::ZeroRepeats);
    }
    let packed_trace = args
        .packed_trace_steps
        .map(profile_packed_trace)
        .transpose()?;
    let workloads = WORKLOADS
        .into_iter()
        .map(|workload| profile_workload(workload, args.steps, args.repeats))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ProfileReport {
        schema: REPORT_SCHEMA,
        protocol_id: PROTOCOL_ID,
        proof_composition_revision: PROOF_COMPOSITION_REVISION_V2,
        backend_digest_sha256: hex::encode(native_backend_digest()),
        dimensions: RELATION_DIMENSIONS,
        workloads,
        packed_trace,
    })
}

fn profile_workload(
    workload: Workload,
    steps: u64,
    repeats: usize,
) -> Result<WorkloadReport, ProfileError> {
    let first = profile_sample(workload, steps)?;
    let mut setup_samples = Vec::with_capacity(repeats);
    let mut execution_samples = Vec::with_capacity(repeats);
    setup_samples.push(first.setup_microseconds);
    execution_samples.push(first.execution_microseconds);
    for _ in 1..repeats {
        let sample = profile_sample(workload, steps)?;
        if sample.semantics != first.semantics {
            return Err(ProfileError::NondeterministicWorkload {
                workload: workload.name,
            });
        }
        setup_samples.push(sample.setup_microseconds);
        execution_samples.push(sample.execution_microseconds);
    }
    Ok(WorkloadReport {
        name: workload.name,
        steps,
        repeats,
        rom_witness_root: first.semantics.rom_witness_root,
        setup: TimingSummary::from_samples(setup_samples)?,
        execution: TimingSummary::from_samples(execution_samples)?,
        metrics: first.semantics.metrics,
        top_program_counters: first.semantics.top_program_counters,
        final_state_scalars: first.semantics.final_state_scalars,
    })
}

fn profile_sample(workload: Workload, steps: u64) -> Result<WorkloadSample, ProfileError> {
    let setup_started = Instant::now();
    let (mut builder, rom_witness_root) = prepare_workload(workload, steps)?;
    let setup_microseconds = setup_started.elapsed().as_micros();

    let execution_started = Instant::now();
    let (boundary, profile) = builder.run_exact_boundary_profiled(steps)?;
    let execution_microseconds = execution_started.elapsed().as_micros();
    Ok(WorkloadSample {
        setup_microseconds,
        execution_microseconds,
        semantics: WorkloadSemantics {
            rom_witness_root,
            metrics: boundary.metrics(),
            top_program_counters: profile.top(PROFILED_PROGRAM_COUNTERS),
            final_state_scalars: NativeStateBoundary::from_vm_state(boundary.final_state())
                .scalars()
                .to_vec(),
        },
    })
}

fn prepare_workload(
    workload: Workload,
    steps: u64,
) -> Result<(LookupTraceBuilder, String), ProfileError> {
    let mut rom_bytes = vec![0_u8; 0x100 + workload.program.len()];
    rom_bytes
        .get_mut(0x100..)
        .ok_or(ProfileError::RomLayout)?
        .copy_from_slice(workload.program);
    let rom = RomImage::new(rom_bytes.clone())?;
    let rom_root = rom.root();
    let memory = MemoryImage::zeroed()?;
    let memory_root = memory.root();
    let memory_bytes = memory.checkpoint_bytes();
    let input_length = usize::try_from(steps).map_err(|_| ProfileError::StepCountOverflow)?;
    let private_input = if workload.supplies_input {
        vec![0_u8; input_length]
    } else {
        Vec::new()
    };
    let builder = LookupTraceBuilder::new_dmg_post_boot_mbc3(
        rom_bytes,
        memory_bytes,
        private_input,
        rom_root,
        memory_root,
    )?;
    Ok((builder, hex::encode(rom_root.to_bytes())))
}

fn profile_packed_trace(steps: u64) -> Result<PackedTraceReport, ProfileError> {
    let maximum = u64::try_from(UNIFORM_ROW_COUNT).map_err(|_| ProfileError::DimensionOverflow)?;
    if steps == 0 || steps > maximum {
        return Err(ProfileError::PackedTraceStepBound {
            actual: steps,
            maximum,
        });
    }
    let workload = WORKLOADS.get(2).copied().ok_or(ProfileError::RomLayout)?;
    let setup_started = Instant::now();
    let (mut builder, _rom_witness_root) = prepare_workload(workload, steps)?;
    let setup_microseconds = setup_started.elapsed().as_micros();
    let execution_started = Instant::now();
    let witness = builder.run_exact_steps(steps)?;
    let retained_execution_microseconds = execution_started.elapsed().as_micros();
    let planning_started = Instant::now();
    let blocks = pack_witness_basic_blocks(witness)?;
    let block_planning_microseconds = planning_started.elapsed().as_micros();
    let cpu_started = Instant::now();
    let block_cpu = BlockCpuWitness::from_blocks(&blocks)?;
    let block_cpu_encoding_microseconds = cpu_started.elapsed().as_micros();
    let cpu_validation_started = Instant::now();
    validate_uniform_witness(&BlockCpuRelation, block_cpu.columns())?;
    let block_cpu_validation_microseconds = cpu_validation_started.elapsed().as_micros();
    let planned_instruction_blocks = blocks
        .iter()
        .filter(|span| span.instruction_count() != 0)
        .count();
    let planned_machine_event_rows = blocks
        .iter()
        .filter(|span| span.instruction_count() == 0)
        .count();
    let maximum_planned_instruction_count = blocks
        .iter()
        .map(|span| span.instruction_count())
        .max()
        .unwrap_or(0);
    let maximum_planned_instruction_m_cycles = blocks
        .iter()
        .filter(|span| span.instruction_count() != 0)
        .map(|span| span.m_cycle_count())
        .max()
        .unwrap_or(0);
    let maximum_planned_instruction_bus_events = blocks
        .iter()
        .filter(|span| span.instruction_count() != 0)
        .map(|span| span.bus_event_count())
        .max()
        .unwrap_or(0);
    Ok(PackedTraceReport {
        workload: workload.name,
        steps,
        setup_microseconds,
        retained_execution_microseconds,
        block_planning_microseconds,
        block_cpu_encoding_microseconds,
        block_cpu_validation_microseconds,
        planned_relation_rows: blocks.len(),
        planned_instruction_blocks,
        planned_machine_event_rows,
        maximum_planned_instruction_count,
        maximum_planned_instruction_m_cycles,
        maximum_planned_instruction_bus_events,
        packed_active_rows: block_cpu.active_block_count(),
        packed_columns: block_cpu.columns().len(),
        rows_per_column: UNIFORM_ROW_COUNT,
        final_state_scalars: NativeStateBoundary::from_vm_state(block_cpu.final_state())
            .scalars()
            .to_vec(),
    })
}

impl TimingSummary {
    fn from_samples(mut samples_microseconds: Vec<u128>) -> Result<Self, ProfileError> {
        samples_microseconds.sort_unstable();
        let minimum_microseconds = samples_microseconds
            .first()
            .copied()
            .ok_or(ProfileError::TimingInvariant)?;
        let maximum_microseconds = samples_microseconds
            .last()
            .copied()
            .ok_or(ProfileError::TimingInvariant)?;
        let median_microseconds = samples_microseconds
            .get(samples_microseconds.len() / 2)
            .copied()
            .ok_or(ProfileError::TimingInvariant)?;
        Ok(Self {
            samples_microseconds,
            minimum_microseconds,
            median_microseconds,
            maximum_microseconds,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Args, REPORT_SCHEMA, run};

    #[test]
    fn profile_suite_covers_distinct_generic_workloads() -> Result<(), super::ProfileError> {
        let report = run(Args {
            steps: 12,
            repeats: 2,
            packed_trace_steps: None,
        })?;
        let cpu = report
            .workloads
            .first()
            .ok_or(super::ProfileError::RomLayout)?;
        let memory = report
            .workloads
            .get(1)
            .ok_or(super::ProfileError::RomLayout)?;
        let stack = report
            .workloads
            .get(2)
            .ok_or(super::ProfileError::RomLayout)?;
        let input = report
            .workloads
            .get(3)
            .ok_or(super::ProfileError::RomLayout)?;

        assert_eq!(report.schema, REPORT_SCHEMA);
        assert_eq!(report.workloads.len(), 4);
        assert_eq!(cpu.repeats, 2);
        assert_eq!(cpu.execution.samples_microseconds.len(), 2);
        assert_eq!(cpu.metrics.relation_steps(), 12);
        assert!(memory.metrics.bus_events() > cpu.metrics.bus_events());
        assert!(stack.metrics.memory_writes() > 0);
        assert!(input.metrics.joypad_samples() > 0);
        Ok(())
    }

    #[test]
    fn profile_suite_rejects_zero_steps() {
        assert!(
            run(Args {
                steps: 0,
                repeats: 1,
                packed_trace_steps: None,
            })
            .is_err()
        );
        assert!(
            run(Args {
                steps: 1,
                repeats: 0,
                packed_trace_steps: None,
            })
            .is_err()
        );
    }
}
