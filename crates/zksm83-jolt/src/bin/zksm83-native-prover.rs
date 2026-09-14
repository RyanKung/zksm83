#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Resumable bounded-memory prover for native-SM83 receipt streams.

use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Instant,
};

use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zksm83_core::{
    CpuState, DmgDeviceState, MachineProfile, Mbc3CartridgeProfile, Mbc3RomSize, Mbc3RtcMode,
    Mbc3State, VmState,
};
use zksm83_jolt::{
    AKITA_AUXILIARY_SCHEDULE_SHA256, AKITA_SCHEDULE_SHA256, BlockCpuError, BlockCpuWitness,
    CommittedMemory, MAX_NATIVE_SEGMENT_COUNT, MAX_NATIVE_STATEMENT_BYTES,
    MAX_NATIVE_STREAM_RECEIPT_BYTES, MemoryCommitment, NATIVE_RECEIPT_VERSION, NativeBoundary,
    NativeProverBackend, NativeProverBackendError, NativeProverBackendKind, NativeReceiptError,
    NativeReceiptStreamProver, NativeSegmentWitness, PROOF_COMPOSITION_REVISION_V2, PROTOCOL_ID,
    ROM_256KIB_IMAGE_BYTES, ROM_IMAGE_BYTES, UNIFORM_ROW_COUNT, commit_memory, commit_rom,
    native_backend_digest, native_proof_phase_metrics, verify_native_spool_reader,
};
use zksm83_memory::{
    CommitmentRoot, LogAccumulator, LogKind, MemoryImage, MemoryImageError, RomImage, RomImageError,
};
use zksm83_trace::{
    BASIC_BLOCK_INSTRUCTION_BOUND, BasicBlock, BasicBlockPlanError, TraceBuilder,
    TraceBuilderError, pack_witness_basic_blocks_at,
};

#[path = "zksm83-native-prover/support.rs"]
mod support;

use support::{
    atomic_replace, io_error, load_file_bounded as read_bounded, open_existing, open_new,
    partial_path, require_absent, sha256, sha256_reader, sync_parent_directory, write_new,
};

const EXPECTED_CHECKPOINT_SCHEMA: &str = "zksm83-trace-checkpoint/v7";
const PROGRESS_SCHEMA: &str = "zksm83-native-prover-progress/v5";
const PROGRESS_EVIDENCE_SCHEMA: &str = "zksm83-native-progress-evidence/v5";
const INPUT_SCHEDULE_SCHEMA: &str = "zksm83-input-schedule/v1";
const MAX_ROM_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_INPUT_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CHECKPOINT_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "zksm83-native-prover", version)]
struct Args {
    /// Supported MBC3 ROM image.
    #[arg(long)]
    rom: PathBuf,
    /// Logical ROM profile size.
    #[arg(long, value_enum, default_value_t = RomSizeArg::Auto)]
    rom_size: RomSizeArg,
    /// RTC-capable cartridge profile selection.
    #[arg(long, value_enum, default_value_t = RtcArg::Auto)]
    rtc: RtcArg,
    /// Raw private input or a versioned JSON input schedule.
    #[arg(long)]
    input: PathBuf,
    /// Independently generated full-memory endpoint checkpoint.
    #[arg(long)]
    expected_checkpoint: PathBuf,
    /// Seekable file that stores completed length-delimited proof frames.
    #[arg(long)]
    spool: PathBuf,
    /// Atomic state/memory checkpoint updated after each durable proof frame.
    #[arg(long)]
    progress_checkpoint: PathBuf,
    /// Final canonical receipt stream, created only after the endpoint matches.
    #[arg(long)]
    receipt: PathBuf,
    /// Final separately pinnable public statement.
    #[arg(long)]
    statement: PathBuf,
    /// Verify and resume an existing spool/progress pair.
    #[arg(long)]
    resume: bool,
    /// Stop successfully after this many new segments without finalizing a receipt.
    #[arg(long)]
    segment_limit: Option<u64>,
    /// Prover execution backend. CUDA requires a feature-enabled Linux build.
    #[arg(long, value_enum, default_value_t = ProofBackendArg::Cpu)]
    proof_backend: ProofBackendArg,
    /// Zero-based CUDA device ordinal; valid only with `--proof-backend cuda`.
    #[arg(long)]
    cuda_device: Option<usize>,
    /// Validate identities, endpoint data, and protocol bounds without proving.
    #[arg(long)]
    preflight_only: bool,
    /// Verify an existing progress/spool pair and print read-only JSON evidence.
    #[arg(
        long,
        conflicts_with_all = ["resume", "segment_limit", "preflight_only"]
    )]
    inspect_progress_only: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum RomSizeArg {
    Auto,
    #[value(name = "256k", alias = "256kib")]
    Rom256KiB,
    #[value(name = "1m", alias = "1mib")]
    Rom1MiB,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum RtcArg {
    Auto,
    Off,
    On,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CartridgeSelection {
    profile: Mbc3CartridgeProfile,
    machine_profile: MachineProfile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ProofBackendArg {
    Cpu,
    Cuda,
}

#[derive(Debug, Deserialize)]
struct ExpectedCheckpoint {
    schema: String,
    completed_steps: u64,
    state: ExpectedState,
    memory_hex: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
struct ExpectedState {
    profile: MachineProfile,
    cpu: CpuState,
    mbc3: Mbc3State,
    dmg_devices: DmgDeviceState,
    #[serde(rename = "rom_root")]
    _legacy_rom_root: CommitmentRoot,
    #[serde(rename = "memory_root")]
    _legacy_memory_root: CommitmentRoot,
    input_log: LogAccumulator,
    output_log: LogAccumulator,
}

#[derive(Debug, Deserialize)]
struct InputSchedule {
    schema: String,
    length: usize,
    segments: Vec<InputSegment>,
}

#[derive(Debug, Deserialize)]
struct InputSegment {
    start: usize,
    end: usize,
    value: u8,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProverProgress {
    schema: String,
    receipt_version: u64,
    protocol_id: String,
    proof_composition_revision: String,
    backend_digest_sha256: String,
    trace_schedule_sha256: String,
    auxiliary_schedule_sha256: String,
    rom_sha256: String,
    input_sha256: String,
    expected_checkpoint_sha256: String,
    relation_row_capacity: usize,
    segment_count: u64,
    completed_steps: u64,
    relation_row_count: u64,
    spool_bytes: u64,
    state: VmState,
    memory_hex: String,
}

#[derive(Debug, Serialize)]
struct ProgressEvidence {
    schema: &'static str,
    verified: bool,
    endpoint_complete: bool,
    receipt_version: u64,
    protocol_id: &'static str,
    proof_composition_revision: &'static str,
    backend_digest_sha256: String,
    trace_schedule_sha256: &'static str,
    auxiliary_schedule_sha256: &'static str,
    rom_sha256: String,
    input_sha256: String,
    expected_checkpoint_sha256: String,
    progress_checkpoint_sha256: String,
    spool_sha256: String,
    relation_row_capacity: usize,
    segment_count: u64,
    completed_steps: u64,
    relation_row_count: u64,
    spool_bytes: u64,
    initial_state_scalars: Vec<u64>,
    final_state_scalars: Vec<u64>,
    final_memory_commitment_sha256: String,
}

#[derive(Debug, Error)]
enum CliError {
    #[error("failed to {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("{kind} file {path} exceeds {maximum} bytes")]
    FileTooLarge {
        kind: &'static str,
        path: String,
        maximum: u64,
    },
    #[error("output path already exists: {0}")]
    OutputExists(String),
    #[error("existing final artifact differs from the recovered proof: {0}")]
    FinalArtifactMismatch(&'static str),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("checkpoint memory is invalid hexadecimal: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("unsupported expected checkpoint schema {0}")]
    ExpectedSchema(String),
    #[error("unsupported input schedule schema {0}")]
    InputSchema(String),
    #[error("input schedule length {actual} exceeds {maximum}")]
    InputTooLarge { actual: usize, maximum: usize },
    #[error("input schedule segment {index} has an invalid or overlapping range")]
    InputSegment { index: usize },
    #[error("native prover checkpoint mismatch: {0}")]
    ProgressMismatch(&'static str),
    #[error(
        "native prover checkpoint memory commitment differs from verified spool: spooled={spooled}, checkpoint={checkpoint}"
    )]
    ProgressMemoryCommitment { spooled: String, checkpoint: String },
    #[error("expected execution endpoint mismatch: {0}")]
    EndpointMismatch(&'static str),
    #[error("--cuda-device requires --proof-backend cuda")]
    CudaDeviceWithCpuBackend,
    #[error(transparent)]
    ProverBackend(#[from] NativeProverBackendError),
    #[error(transparent)]
    Receipt(#[from] NativeReceiptError),
    #[error(transparent)]
    BlockCpu(#[from] BlockCpuError),
    #[error(transparent)]
    BlockPlan(#[from] BasicBlockPlanError),
    #[error(transparent)]
    Trace(#[from] TraceBuilderError),
    #[error(transparent)]
    Memory(#[from] MemoryImageError),
    #[error(transparent)]
    Rom(#[from] RomImageError),
    #[error("ROM commitment failed: {0}")]
    RomCommitment(#[from] zksm83_jolt::RomLookupError),
    #[error("memory commitment failed: {0}")]
    MemoryCommitment(#[from] zksm83_jolt::MutableMemoryError),
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("native prover command failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<(), CliError> {
    let rom_bytes = read_bounded(&args.rom, "ROM", MAX_ROM_FILE_BYTES)?;
    let cartridge = resolve_cartridge_selection(&args, &rom_bytes)?;
    let input = load_input(&args.input)?;
    let expected_bytes = read_bounded(
        &args.expected_checkpoint,
        "expected checkpoint",
        MAX_CHECKPOINT_FILE_BYTES,
    )?;
    let expected: ExpectedCheckpoint = serde_json::from_slice(&expected_bytes)?;
    validate_expected_artifact(&expected, &rom_bytes, cartridge)?;
    let identities = InputIdentities {
        rom: sha256(&rom_bytes),
        input: sha256(&input),
        expected: sha256(&expected_bytes),
    };
    if args.preflight_only {
        return preflight(&expected, &rom_bytes, &input, identities, cartridge);
    }
    let committed_rom = commit_rom(&rom_bytes)?;
    if args.inspect_progress_only {
        return inspect_progress(
            &args,
            identities,
            &committed_rom,
            &expected,
            &rom_bytes,
            &input,
        );
    }
    require_absent(&args.receipt)?;
    if !args.resume {
        require_absent(&args.statement)?;
    }
    let backend = initialize_prover_backend(args.proof_backend, args.cuda_device)?;
    let (mut builder, mut initial_memory, completed, mut prover) = if args.resume {
        resume(
            &args,
            &rom_bytes,
            &input,
            identities,
            &committed_rom,
            backend,
        )?
    } else {
        start(
            &args,
            &rom_bytes,
            &input,
            &committed_rom,
            cartridge,
            backend,
        )?
    };
    let completed_steps = prove_segments(
        &args,
        &expected,
        identities,
        &mut builder,
        &mut initial_memory,
        completed,
        &mut prover,
    )?;
    if completed_steps != expected.completed_steps {
        println!(
            "paused proof_backend={} segments={} completed_steps={} relation_rows={} spool_bytes={}",
            prover.backend_kind(),
            prover.segment_count(),
            completed_steps,
            prover.relation_row_count(),
            prover.spooled_bytes()
        );
        return Ok(());
    }
    let final_memory = builder.checkpoint_memory();
    validate_endpoint(
        builder.state(),
        &final_memory,
        &rom_bytes,
        &input,
        &expected,
    )?;
    finalize(&args, prover)?;
    Ok(())
}

fn initialize_prover_backend(
    selection: ProofBackendArg,
    cuda_device: Option<usize>,
) -> Result<NativeProverBackend, CliError> {
    NativeProverBackend::initialize(prover_backend_kind(selection, cuda_device)?)
        .map_err(Into::into)
}

fn prover_backend_kind(
    selection: ProofBackendArg,
    cuda_device: Option<usize>,
) -> Result<NativeProverBackendKind, CliError> {
    match (selection, cuda_device) {
        (ProofBackendArg::Cpu, None) => Ok(NativeProverBackendKind::Cpu),
        (ProofBackendArg::Cpu, Some(_)) => Err(CliError::CudaDeviceWithCpuBackend),
        (ProofBackendArg::Cuda, device_ordinal) => Ok(NativeProverBackendKind::Cuda {
            device_ordinal: device_ordinal.unwrap_or(0),
        }),
    }
}

fn inspect_progress(
    args: &Args,
    identities: InputIdentities,
    committed_rom: &zksm83_jolt::CommittedRom,
    expected: &ExpectedCheckpoint,
    rom_bytes: &[u8],
    input: &[u8],
) -> Result<(), CliError> {
    let progress_bytes = read_bounded(
        &args.progress_checkpoint,
        "progress checkpoint",
        MAX_CHECKPOINT_FILE_BYTES,
    )?;
    let progress: ProverProgress = serde_json::from_slice(&progress_bytes)?;
    validate_progress(&progress, identities)?;
    if progress.completed_steps > expected.completed_steps {
        return Err(CliError::ProgressMismatch(
            "completed steps exceed expected endpoint",
        ));
    }
    let mut spool = File::open(&args.spool)
        .map_err(|source| io_error("open read-only", &args.spool, source))?;
    let verified =
        verify_native_spool_reader(&mut spool, progress.spool_bytes, committed_rom.commitment())?;
    let spool_sha256 = sha256_reader(&mut spool, progress.spool_bytes, &args.spool)?;
    let view = VerifiedProgress {
        segment_count: verified.segment_count(),
        transition_count: verified.transition_count(),
        relation_row_count: verified.relation_row_count(),
        spool_bytes: verified.spool_bytes(),
        final_boundary: verified.final_boundary(),
        final_memory: verified.final_memory(),
    };
    let _checkpoint_memory = validate_verified_progress(&progress, view)?;
    let endpoint_complete = verified.transition_count() == expected.completed_steps;
    if endpoint_complete {
        let memory = hex::decode(&progress.memory_hex)?;
        validate_endpoint(progress.state, &memory, rom_bytes, input, expected)?;
    }
    let evidence = ProgressEvidence {
        schema: PROGRESS_EVIDENCE_SCHEMA,
        verified: true,
        endpoint_complete,
        receipt_version: NATIVE_RECEIPT_VERSION,
        protocol_id: PROTOCOL_ID,
        proof_composition_revision: PROOF_COMPOSITION_REVISION_V2,
        backend_digest_sha256: hex::encode(native_backend_digest()),
        trace_schedule_sha256: AKITA_SCHEDULE_SHA256,
        auxiliary_schedule_sha256: AKITA_AUXILIARY_SCHEDULE_SHA256,
        rom_sha256: hex::encode(identities.rom),
        input_sha256: hex::encode(identities.input),
        expected_checkpoint_sha256: hex::encode(identities.expected),
        progress_checkpoint_sha256: hex::encode(sha256(&progress_bytes)),
        spool_sha256: hex::encode(spool_sha256),
        relation_row_capacity: progress.relation_row_capacity,
        segment_count: verified.segment_count(),
        completed_steps: verified.transition_count(),
        relation_row_count: verified.relation_row_count(),
        spool_bytes: verified.spool_bytes(),
        initial_state_scalars: verified.initial().state().scalars().to_vec(),
        final_state_scalars: verified.final_boundary().state().scalars().to_vec(),
        final_memory_commitment_sha256: hex::encode(verified.final_memory().digest()?),
    };
    println!("{}", serde_json::to_string_pretty(&evidence)?);
    Ok(())
}

fn preflight(
    expected: &ExpectedCheckpoint,
    rom_bytes: &[u8],
    input: &[u8],
    identities: InputIdentities,
    cartridge: CartridgeSelection,
) -> Result<(), CliError> {
    let capacity = u64::try_from(UNIFORM_ROW_COUNT)
        .map_err(|_| CliError::ProgressMismatch("segment capacity overflow"))?;
    let worst_case_segment_count = expected.completed_steps.div_ceil(capacity);
    let maximum = u64::try_from(MAX_NATIVE_SEGMENT_COUNT)
        .map_err(|_| CliError::ProgressMismatch("segment limit overflow"))?;
    if worst_case_segment_count > maximum {
        return Err(CliError::EndpointMismatch(
            "segment count exceeds protocol bound",
        ));
    }
    let input_length = u64::try_from(input.len())
        .map_err(|_| CliError::EndpointMismatch("input length overflow"))?;
    if expected.state.input_log.next_index() > input_length {
        return Err(CliError::EndpointMismatch(
            "input prefix exceeds supplied bytes",
        ));
    }
    let rom_witness_root = RomImage::new(rom_bytes.to_vec())?.root();
    let memory_bytes = hex::decode(&expected.memory_hex)?;
    let memory_witness_root = MemoryImage::from_checkpoint_bytes(memory_bytes)?.root();
    println!(
        "preflight=true receipt_version={} protocol_id={} proof_composition_revision={} backend_digest_sha256={} trace_schedule_sha256={} auxiliary_schedule_sha256={} machine_profile_code={} rom_bytes={} rtc_mode={:?} steps={} relation_row_capacity={} worst_case_segments={} input_bytes={} input_consumed={} rom_sha256={} input_sha256={} expected_checkpoint_sha256={} rom_witness_auth_root_sha256={} endpoint_memory_witness_auth_root_sha256={}",
        NATIVE_RECEIPT_VERSION,
        PROTOCOL_ID,
        PROOF_COMPOSITION_REVISION_V2,
        hex::encode(native_backend_digest()),
        AKITA_SCHEDULE_SHA256,
        AKITA_AUXILIARY_SCHEDULE_SHA256,
        cartridge.machine_profile.code(),
        cartridge.profile.rom_size().byte_length(),
        cartridge.profile.rtc(),
        expected.completed_steps,
        capacity,
        worst_case_segment_count,
        input.len(),
        expected.state.input_log.next_index(),
        hex::encode(identities.rom),
        hex::encode(identities.input),
        hex::encode(identities.expected),
        rom_witness_root,
        memory_witness_root
    );
    Ok(())
}

#[derive(Clone, Copy)]
struct InputIdentities {
    rom: [u8; 32],
    input: [u8; 32],
    expected: [u8; 32],
}

fn resolve_cartridge_selection(
    args: &Args,
    rom_bytes: &[u8],
) -> Result<CartridgeSelection, CliError> {
    let rom_size = resolve_rom_size(args.rom_size, rom_bytes.len())?;
    let rtc = resolve_rtc_mode(args.rtc, rom_bytes);
    let profile = Mbc3CartridgeProfile::new(rom_size, rtc);
    Ok(CartridgeSelection {
        profile,
        machine_profile: MachineProfile::dmg_post_boot_for_cartridge(profile),
    })
}

fn resolve_rom_size(selection: RomSizeArg, byte_length: usize) -> Result<Mbc3RomSize, CliError> {
    match selection {
        RomSizeArg::Auto => match byte_length {
            ROM_256KIB_IMAGE_BYTES => Ok(Mbc3RomSize::Rom256KiB),
            ROM_IMAGE_BYTES => Ok(Mbc3RomSize::Rom1MiB),
            _ => Err(CliError::EndpointMismatch("unsupported ROM byte length")),
        },
        RomSizeArg::Rom256KiB if byte_length == ROM_256KIB_IMAGE_BYTES => {
            Ok(Mbc3RomSize::Rom256KiB)
        }
        RomSizeArg::Rom1MiB if byte_length == ROM_IMAGE_BYTES => Ok(Mbc3RomSize::Rom1MiB),
        RomSizeArg::Rom256KiB | RomSizeArg::Rom1MiB => Err(CliError::EndpointMismatch(
            "ROM byte length does not match --rom-size",
        )),
    }
}

fn resolve_rtc_mode(selection: RtcArg, rom_bytes: &[u8]) -> Mbc3RtcMode {
    match selection {
        RtcArg::Auto => header_rtc_mode(rom_bytes).unwrap_or(Mbc3RtcMode::NoRtc),
        RtcArg::Off => Mbc3RtcMode::NoRtc,
        RtcArg::On => Mbc3RtcMode::RtcCapable,
    }
}

fn header_rtc_mode(rom_bytes: &[u8]) -> Option<Mbc3RtcMode> {
    let cartridge_type = *rom_bytes.get(0x0147)?;
    match cartridge_type {
        0x0f | 0x10 => Some(Mbc3RtcMode::RtcCapable),
        0x11..=0x13 => Some(Mbc3RtcMode::NoRtc),
        _ => None,
    }
}

type FileProver<'a> = NativeReceiptStreamProver<'a, File>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SpoolRecovery {
    Exact,
    DiscardUncheckpointedTail,
}

#[derive(Clone, Copy)]
struct VerifiedProgress<'a> {
    segment_count: u64,
    transition_count: u64,
    relation_row_count: u64,
    spool_bytes: u64,
    final_boundary: &'a NativeBoundary,
    final_memory: &'a MemoryCommitment,
}

struct PackedSegment {
    blocks: Vec<BasicBlock>,
    completed_steps: u64,
}

fn spool_recovery(actual: u64, checkpointed: u64) -> Result<SpoolRecovery, CliError> {
    if actual < checkpointed {
        return Err(CliError::ProgressMismatch(
            "spool is shorter than checkpoint",
        ));
    }
    if actual == checkpointed {
        Ok(SpoolRecovery::Exact)
    } else {
        Ok(SpoolRecovery::DiscardUncheckpointedTail)
    }
}

fn start<'a>(
    args: &Args,
    rom_bytes: &[u8],
    input: &[u8],
    committed_rom: &'a zksm83_jolt::CommittedRom,
    cartridge: CartridgeSelection,
    backend: NativeProverBackend,
) -> Result<(TraceBuilder, CommittedMemory, u64, FileProver<'a>), CliError> {
    require_absent(&args.spool)?;
    require_absent(&args.progress_checkpoint)?;
    let memory = MemoryImage::zeroed()?;
    let memory_bytes = memory.checkpoint_bytes();
    let initial_memory = commit_memory(&memory_bytes)?;
    let builder = TraceBuilder::new_dmg_post_boot_mbc3_profile(
        RomImage::new(rom_bytes.to_vec())?,
        memory,
        input.to_vec(),
        cartridge.machine_profile,
    )?;
    let spool = open_new(&args.spool)?;
    let prover = NativeReceiptStreamProver::new_with_backend(committed_rom, spool, backend)?;
    Ok((builder, initial_memory, 0, prover))
}

fn resume<'a>(
    args: &Args,
    rom_bytes: &[u8],
    input: &[u8],
    identities: InputIdentities,
    committed_rom: &'a zksm83_jolt::CommittedRom,
    backend: NativeProverBackend,
) -> Result<(TraceBuilder, CommittedMemory, u64, FileProver<'a>), CliError> {
    let progress_bytes = read_bounded(
        &args.progress_checkpoint,
        "progress checkpoint",
        MAX_CHECKPOINT_FILE_BYTES,
    )?;
    let progress: ProverProgress = serde_json::from_slice(&progress_bytes)?;
    validate_progress(&progress, identities)?;
    let spool = open_existing(&args.spool)?;
    let actual_length = spool
        .metadata()
        .map_err(|source| io_error("inspect", &args.spool, source))?
        .len();
    if spool_recovery(actual_length, progress.spool_bytes)?
        == SpoolRecovery::DiscardUncheckpointedTail
    {
        spool
            .set_len(progress.spool_bytes)
            .map_err(|source| io_error("truncate uncheckpointed tail of", &args.spool, source))?;
        spool
            .sync_all()
            .map_err(|source| io_error("sync", &args.spool, source))?;
    }
    let prover = NativeReceiptStreamProver::resume_with_backend(committed_rom, spool, backend)?;
    let final_boundary = prover.current_boundary().ok_or(CliError::ProgressMismatch(
        "verified spool has no final boundary",
    ))?;
    let final_memory = prover
        .current_memory_commitment()
        .ok_or(CliError::ProgressMismatch("verified spool has no memory"))?;
    let initial_memory = validate_verified_progress(
        &progress,
        VerifiedProgress {
            segment_count: prover.segment_count(),
            transition_count: prover.transition_count(),
            relation_row_count: prover.relation_row_count(),
            spool_bytes: prover.spooled_bytes(),
            final_boundary,
            final_memory,
        },
    )?;
    let memory_bytes = hex::decode(&progress.memory_hex)?;
    let memory = MemoryImage::from_checkpoint_bytes(memory_bytes)?;
    let builder = TraceBuilder::resume(
        RomImage::new(rom_bytes.to_vec())?,
        memory,
        input.to_vec(),
        progress.state,
    )?;
    Ok((builder, initial_memory, progress.completed_steps, prover))
}

fn validate_verified_progress(
    progress: &ProverProgress,
    verified: VerifiedProgress<'_>,
) -> Result<CommittedMemory, CliError> {
    validate_verified_counters(
        progress,
        verified.segment_count,
        verified.transition_count,
        verified.relation_row_count,
        verified.spool_bytes,
    )?;
    let checkpoint_state = zksm83_jolt::NativeStateBoundary::from_vm_state(progress.state);
    if verified.final_boundary.state() != checkpoint_state {
        return Err(CliError::ProgressMismatch(
            "verified spool state differs from checkpoint",
        ));
    }
    let memory_bytes = hex::decode(&progress.memory_hex)?;
    let checkpoint_memory = commit_memory(&memory_bytes)?;
    if verified.final_memory.canonical_bytes()?
        != checkpoint_memory.commitment().canonical_bytes()?
    {
        return Err(CliError::ProgressMemoryCommitment {
            spooled: hex::encode(verified.final_memory.digest()?),
            checkpoint: hex::encode(checkpoint_memory.commitment().digest()?),
        });
    }
    Ok(checkpoint_memory)
}

fn validate_verified_counters(
    progress: &ProverProgress,
    segment_count: u64,
    transition_count: u64,
    relation_row_count: u64,
    spool_bytes: u64,
) -> Result<(), CliError> {
    if segment_count != progress.segment_count
        || transition_count != progress.completed_steps
        || relation_row_count != progress.relation_row_count
        || spool_bytes != progress.spool_bytes
    {
        return Err(CliError::ProgressMismatch("verified spool counters differ"));
    }
    Ok(())
}

fn prove_segments(
    args: &Args,
    expected: &ExpectedCheckpoint,
    identities: InputIdentities,
    builder: &mut TraceBuilder,
    initial_memory: &mut CommittedMemory,
    completed: u64,
    prover: &mut FileProver<'_>,
) -> Result<u64, CliError> {
    if completed != prover.transition_count() {
        return Err(CliError::ProgressMismatch(
            "completed-step cursor differs from verified spool",
        ));
    }
    if completed > expected.completed_steps {
        return Err(CliError::ProgressMismatch(
            "completed-step cursor is invalid",
        ));
    }
    let mut new_segments = 0_u64;
    let mut completed_steps = completed;
    while completed_steps < expected.completed_steps {
        if args
            .segment_limit
            .is_some_and(|limit| new_segments >= limit)
        {
            break;
        }
        let remaining = expected.completed_steps - completed_steps;
        let started = Instant::now();
        let phases_before = native_proof_phase_metrics();
        let PackedSegment {
            blocks,
            completed_steps: segment_steps,
        } = fill_packed_segment(builder, remaining)?;
        let packed_trace = BlockCpuWitness::from_blocks(&blocks)?;
        drop(blocks);
        if u64::try_from(packed_trace.transition_count())
            .map_err(|_| CliError::ProgressMismatch("packed transition count overflow"))?
            != segment_steps
        {
            return Err(CliError::ProgressMismatch(
                "packed transition count differs from emulator cursor",
            ));
        }
        let segment_relation_rows = packed_trace.active_block_count();
        let final_bytes = builder.checkpoint_memory();
        let final_memory = commit_memory(&final_bytes)?;
        prover.append(NativeSegmentWitness::new(
            packed_trace,
            initial_memory,
            &final_memory,
        ))?;
        let authenticated_steps = prover.transition_count();
        let expected_steps = completed_steps
            .checked_add(segment_steps)
            .ok_or(CliError::ProgressMismatch("completed-step cursor overflow"))?;
        if authenticated_steps != expected_steps {
            return Err(CliError::ProgressMismatch(
                "proved transition count differs from emulator cursor",
            ));
        }
        prover.sync_spool()?;
        *initial_memory = final_memory;
        completed_steps = authenticated_steps;
        new_segments = new_segments
            .checked_add(1)
            .ok_or(CliError::ProgressMismatch("segment counter overflow"))?;
        write_progress(args, identities, builder, prover)?;
        let phases = native_proof_phase_metrics().since(phases_before);
        println!(
            "proof_backend={} segment={} steps={} segment_relation_rows={} completed_steps={} relation_rows={} spool_bytes={} elapsed_seconds={:.3} setup_seconds={:.3} relation_eval_seconds={:.3} commit_seconds={:.3} rom_lookup_seconds={:.3} mutable_memory_seconds={:.3} continuity_seconds={:.3} protocol_log_seconds={:.3} sumcheck_seconds={:.3} opening_seconds={:.3} encode_seconds={:.3}",
            prover.backend_kind(),
            prover.segment_count() - 1,
            segment_steps,
            segment_relation_rows,
            completed_steps,
            prover.relation_row_count(),
            prover.spooled_bytes(),
            started.elapsed().as_secs_f64(),
            phases.setup().as_secs_f64(),
            phases.packed_relation_evaluation().as_secs_f64(),
            phases.commit().as_secs_f64(),
            phases.rom_lookup().as_secs_f64(),
            phases.mutable_memory().as_secs_f64(),
            phases.continuity().as_secs_f64(),
            phases.protocol_log().as_secs_f64(),
            phases.sumcheck().as_secs_f64(),
            phases.opening().as_secs_f64(),
            phases.encode().as_secs_f64()
        );
    }
    Ok(completed_steps)
}

fn fill_packed_segment(
    builder: &mut TraceBuilder,
    maximum_steps: u64,
) -> Result<PackedSegment, CliError> {
    fill_packed_segment_with_capacity(builder, maximum_steps, UNIFORM_ROW_COUNT)
}

fn fill_packed_segment_with_capacity(
    builder: &mut TraceBuilder,
    maximum_steps: u64,
    relation_row_capacity: usize,
) -> Result<PackedSegment, CliError> {
    if maximum_steps == 0 || relation_row_capacity == 0 {
        return Err(CliError::ProgressMismatch("zero packed-segment bound"));
    }
    let mut blocks = Vec::with_capacity(relation_row_capacity);
    let mut completed_steps = 0_u64;
    while completed_steps < maximum_steps && blocks.len() < relation_row_capacity {
        let remaining_rows = relation_row_capacity - blocks.len();
        let chunk_bound = u64::try_from(remaining_rows)
            .map_err(|_| CliError::ProgressMismatch("relation-row capacity overflow"))?;
        let remaining_steps = maximum_steps - completed_steps;
        let chunk_steps = remaining_steps.min(chunk_bound);
        let source_row_offset = usize::try_from(completed_steps)
            .map_err(|_| CliError::ProgressMismatch("segment source-row offset overflow"))?;
        let witness = builder.run_exact_steps(chunk_steps)?;
        let mut chunk = pack_witness_basic_blocks_at(witness, source_row_offset)?;
        if chunk.is_empty() || chunk.len() > remaining_rows {
            return Err(CliError::ProgressMismatch(
                "packed chunk exceeded relation-row capacity",
            ));
        }
        completed_steps = completed_steps
            .checked_add(chunk_steps)
            .ok_or(CliError::ProgressMismatch("completed-step cursor overflow"))?;
        blocks.append(&mut chunk);
    }
    if blocks.is_empty() || completed_steps == 0 {
        return Err(CliError::ProgressMismatch("packed segment is empty"));
    }
    Ok(PackedSegment {
        blocks,
        completed_steps,
    })
}

fn write_progress(
    args: &Args,
    identities: InputIdentities,
    builder: &TraceBuilder,
    prover: &FileProver<'_>,
) -> Result<(), CliError> {
    let progress = ProverProgress {
        schema: PROGRESS_SCHEMA.to_owned(),
        receipt_version: NATIVE_RECEIPT_VERSION,
        protocol_id: PROTOCOL_ID.to_owned(),
        proof_composition_revision: PROOF_COMPOSITION_REVISION_V2.to_owned(),
        backend_digest_sha256: hex::encode(native_backend_digest()),
        trace_schedule_sha256: AKITA_SCHEDULE_SHA256.to_owned(),
        auxiliary_schedule_sha256: AKITA_AUXILIARY_SCHEDULE_SHA256.to_owned(),
        rom_sha256: hex::encode(identities.rom),
        input_sha256: hex::encode(identities.input),
        expected_checkpoint_sha256: hex::encode(identities.expected),
        relation_row_capacity: UNIFORM_ROW_COUNT,
        segment_count: prover.segment_count(),
        completed_steps: prover.transition_count(),
        relation_row_count: prover.relation_row_count(),
        spool_bytes: prover.spooled_bytes(),
        state: builder.state(),
        memory_hex: hex::encode(builder.checkpoint_memory()),
    };
    let bytes = serde_json::to_vec_pretty(&progress)?;
    atomic_replace(&args.progress_checkpoint, &bytes)
}

fn finalize(args: &Args, prover: FileProver<'_>) -> Result<(), CliError> {
    let receipt_partial = partial_path(&args.receipt);
    require_absent(&receipt_partial)?;
    let receipt = open_new(&receipt_partial)?;
    let mut receipt = BufWriter::new(receipt);
    let statement = prover.finish(&mut receipt)?;
    receipt
        .flush()
        .map_err(|source| io_error("flush", &receipt_partial, source))?;
    let receipt = receipt
        .into_inner()
        .map_err(|error| io_error("flush", &receipt_partial, error.into_error()))?;
    receipt
        .sync_all()
        .map_err(|source| io_error("sync", &receipt_partial, source))?;
    let statement_bytes = statement.to_bytes()?;
    if args.statement.exists() {
        let existing = read_bounded(
            &args.statement,
            "existing statement",
            u64::try_from(MAX_NATIVE_STATEMENT_BYTES)
                .map_err(|_| CliError::FinalArtifactMismatch("statement size bound"))?,
        )?;
        if existing != statement_bytes {
            return Err(CliError::FinalArtifactMismatch("statement"));
        }
    } else {
        write_new(&args.statement, &statement_bytes)?;
    }
    require_absent(&args.receipt)?;
    fs::rename(&receipt_partial, &args.receipt)
        .map_err(|source| io_error("publish", &args.receipt, source))?;
    sync_parent_directory(&args.receipt)?;
    println!(
        "complete receipt_version={} protocol_id={} proof_composition_revision={} statement_id={} segments={} transitions={} relation_rows={}",
        statement.protocol().code(),
        PROTOCOL_ID,
        PROOF_COMPOSITION_REVISION_V2,
        hex::encode(statement.statement_id()),
        statement.segment_count(),
        statement.transition_count(),
        statement.relation_row_count()
    );
    Ok(())
}

fn validate_expected_artifact(
    expected: &ExpectedCheckpoint,
    rom_bytes: &[u8],
    cartridge: CartridgeSelection,
) -> Result<(), CliError> {
    if expected.schema != EXPECTED_CHECKPOINT_SCHEMA {
        return Err(CliError::ExpectedSchema(expected.schema.clone()));
    }
    if expected.completed_steps == 0 {
        return Err(CliError::EndpointMismatch("zero relation steps"));
    }
    if rom_bytes.len() != cartridge.profile.rom_size().byte_length() {
        return Err(CliError::EndpointMismatch("ROM byte length"));
    }
    if expected.state.profile != cartridge.machine_profile {
        return Err(CliError::EndpointMismatch(
            "expected checkpoint machine profile",
        ));
    }
    Mbc3State::from_profile_parts(
        cartridge.profile,
        expected.state.mbc3.ram_enabled(),
        expected.state.mbc3.rom_bank(),
        expected.state.mbc3.ram_rtc_select(),
    )
    .map_err(|_| CliError::EndpointMismatch("expected MBC3 state profile"))?;
    let rom = RomImage::new(rom_bytes.to_vec())?;
    let _rom_witness_auth_root = rom.root();
    let memory_bytes = hex::decode(&expected.memory_hex)?;
    let memory = MemoryImage::from_checkpoint_bytes(memory_bytes)?;
    let _memory_witness_auth_root = memory.root();
    Ok(())
}

fn validate_endpoint(
    actual: VmState,
    memory: &[u8],
    rom_bytes: &[u8],
    input: &[u8],
    expected: &ExpectedCheckpoint,
) -> Result<(), CliError> {
    let expected_memory = hex::decode(&expected.memory_hex)?;
    if memory != expected_memory {
        return Err(CliError::EndpointMismatch("exact mutable memory image"));
    }
    let rom_root = RomImage::new(rom_bytes.to_vec())?.root();
    let memory_root = MemoryImage::from_checkpoint_bytes(expected_memory)?.root();
    let state = expected.state;
    let input_length = usize::try_from(state.input_log.next_index())
        .map_err(|_| CliError::EndpointMismatch("input prefix length overflow"))?;
    let input_prefix = input.get(..input_length).ok_or(CliError::EndpointMismatch(
        "input prefix exceeds supplied bytes",
    ))?;
    let input_log = LogAccumulator::commit(LogKind::Input, input_prefix)
        .map_err(|_| CliError::EndpointMismatch("input log index overflow"))?;
    if state.output_log.next_index() != 0 {
        return Err(CliError::EndpointMismatch(
            "nonempty output endpoint unsupported",
        ));
    }
    let matches = actual.profile() == state.profile
        && actual.cpu() == state.cpu
        && actual.mbc3() == state.mbc3
        && actual.dmg_devices() == state.dmg_devices
        && actual.rom_root() == rom_root
        && actual.memory_root() == memory_root
        && actual.input_log() == input_log
        && actual.output_log() == LogAccumulator::empty(LogKind::Output);
    if !matches {
        return Err(CliError::EndpointMismatch("typed final VM state"));
    }
    Ok(())
}

fn validate_progress(
    progress: &ProverProgress,
    identities: InputIdentities,
) -> Result<(), CliError> {
    if progress.schema != PROGRESS_SCHEMA {
        return Err(CliError::ProgressMismatch("schema"));
    }
    if progress.receipt_version != NATIVE_RECEIPT_VERSION
        || progress.protocol_id != PROTOCOL_ID
        || progress.proof_composition_revision != PROOF_COMPOSITION_REVISION_V2
        || progress.backend_digest_sha256 != hex::encode(native_backend_digest())
        || progress.trace_schedule_sha256 != AKITA_SCHEDULE_SHA256
        || progress.auxiliary_schedule_sha256 != AKITA_AUXILIARY_SCHEDULE_SHA256
    {
        return Err(CliError::ProgressMismatch("protocol identity"));
    }
    if progress.relation_row_capacity != UNIFORM_ROW_COUNT {
        return Err(CliError::ProgressMismatch("relation-row capacity"));
    }
    let maximum_segments = u64::try_from(MAX_NATIVE_SEGMENT_COUNT)
        .map_err(|_| CliError::ProgressMismatch("segment limit overflow"))?;
    let row_capacity = u64::try_from(UNIFORM_ROW_COUNT)
        .map_err(|_| CliError::ProgressMismatch("relation-row capacity overflow"))?;
    let maximum_rows = progress
        .segment_count
        .checked_mul(row_capacity)
        .ok_or(CliError::ProgressMismatch("relation-row count overflow"))?;
    let maximum_transitions = progress
        .relation_row_count
        .checked_mul(
            u64::try_from(BASIC_BLOCK_INSTRUCTION_BOUND)
                .map_err(|_| CliError::ProgressMismatch("transition bound overflow"))?,
        )
        .ok_or(CliError::ProgressMismatch("transition count overflow"))?;
    if progress.segment_count == 0
        || progress.segment_count > maximum_segments
        || progress.relation_row_count == 0
        || progress.completed_steps == 0
        || progress.segment_count > progress.relation_row_count
        || progress.relation_row_count > maximum_rows
        || progress.relation_row_count > progress.completed_steps
        || progress.completed_steps > maximum_transitions
        || progress.spool_bytes == 0
        || progress.spool_bytes > MAX_NATIVE_STREAM_RECEIPT_BYTES
    {
        return Err(CliError::ProgressMismatch("progress counters"));
    }
    if progress.rom_sha256 != hex::encode(identities.rom)
        || progress.input_sha256 != hex::encode(identities.input)
        || progress.expected_checkpoint_sha256 != hex::encode(identities.expected)
    {
        return Err(CliError::ProgressMismatch("input identity"));
    }
    Ok(())
}

fn load_input(path: &Path) -> Result<Vec<u8>, CliError> {
    let raw = read_bounded(path, "input", MAX_INPUT_FILE_BYTES)?;
    if path.extension() != Some(OsStr::new("json")) {
        return Ok(raw);
    }
    let schedule: InputSchedule = serde_json::from_slice(&raw)?;
    expand_schedule(schedule)
}

fn expand_schedule(schedule: InputSchedule) -> Result<Vec<u8>, CliError> {
    if schedule.schema != INPUT_SCHEDULE_SCHEMA {
        return Err(CliError::InputSchema(schedule.schema));
    }
    if schedule.length > MAX_INPUT_BYTES {
        return Err(CliError::InputTooLarge {
            actual: schedule.length,
            maximum: MAX_INPUT_BYTES,
        });
    }
    let mut bytes = vec![0_u8; schedule.length];
    let mut assigned = vec![false; schedule.length];
    for (index, segment) in schedule.segments.into_iter().enumerate() {
        let range = segment.start..segment.end;
        let flags = assigned
            .get_mut(range.clone())
            .ok_or(CliError::InputSegment { index })?;
        if segment.start >= segment.end || flags.iter().any(|flag| *flag) {
            return Err(CliError::InputSegment { index });
        }
        flags.fill(true);
        bytes
            .get_mut(range)
            .ok_or(CliError::InputSegment { index })?
            .fill(segment.value);
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "zksm83-native-prover/tests.rs"]
mod tests;
