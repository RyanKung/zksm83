#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Resumable bounded-memory prover for native-SM83 receipt streams.

use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Instant,
};

use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zksm83_core::{CpuState, DmgDeviceState, MachineProfile, Mbc3State, VmState};
use zksm83_jolt::{
    CommittedMemory, MAX_NATIVE_SEGMENT_COUNT, NativeReceiptError, NativeReceiptStreamProver,
    NativeSegmentWitness, NativeTraceError, NativeTraceWitness, UNIFORM_ROW_COUNT, commit_memory,
    commit_rom,
};
use zksm83_memory::{
    CommitmentRoot, LogAccumulator, LogKind, MemoryImage, MemoryImageError, RomImage, RomImageError,
};
use zksm83_trace::{TraceBuilder, TraceBuilderError};

const EXPECTED_CHECKPOINT_SCHEMA: &str = "zksm83-trace-checkpoint/v7";
const PROGRESS_SCHEMA: &str = "zksm83-native-prover-progress/v1";
const INPUT_SCHEDULE_SCHEMA: &str = "zksm83-input-schedule/v1";
const ROM_BYTE_LENGTH: usize = 1 << 20;
const MAX_ROM_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_INPUT_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CHECKPOINT_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "zksm83-native-prover", version)]
struct Args {
    /// Exact one-MiB no-RTC MBC3 ROM image.
    #[arg(long)]
    rom: PathBuf,
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
    /// Validate identities, endpoint data, and protocol bounds without proving.
    #[arg(long)]
    preflight_only: bool,
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
struct ProverProgress {
    schema: String,
    rom_sha256: String,
    input_sha256: String,
    expected_checkpoint_sha256: String,
    segment_capacity: usize,
    segment_count: u64,
    relation_step_count: u64,
    spool_bytes: u64,
    state: VmState,
    memory_hex: String,
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
    #[error("expected Blue endpoint mismatch: {0}")]
    EndpointMismatch(&'static str),
    #[error(transparent)]
    Receipt(#[from] NativeReceiptError),
    #[error(transparent)]
    NativeTrace(#[from] NativeTraceError),
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
            eprintln!("native proving failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<(), CliError> {
    require_absent(&args.receipt)?;
    require_absent(&args.statement)?;
    let rom_bytes = read_bounded(&args.rom, "ROM", MAX_ROM_FILE_BYTES)?;
    let input = load_input(&args.input)?;
    let expected_bytes = read_bounded(
        &args.expected_checkpoint,
        "expected checkpoint",
        MAX_CHECKPOINT_FILE_BYTES,
    )?;
    let expected: ExpectedCheckpoint = serde_json::from_slice(&expected_bytes)?;
    validate_expected_artifact(&expected, &rom_bytes)?;
    let identities = InputIdentities {
        rom: sha256(&rom_bytes),
        input: sha256(&input),
        expected: sha256(&expected_bytes),
    };
    if args.preflight_only {
        return preflight(&expected, &rom_bytes, &input, identities);
    }
    let committed_rom = commit_rom(&rom_bytes)?;
    let (mut builder, mut initial_memory, completed, mut prover) = if args.resume {
        resume(&args, &rom_bytes, &input, identities, &committed_rom)?
    } else {
        start(&args, &rom_bytes, &input, &committed_rom)?
    };
    prove_segments(
        &args,
        &expected,
        identities,
        &mut builder,
        &mut initial_memory,
        completed,
        &mut prover,
    )?;
    if prover.relation_step_count() != expected.completed_steps {
        println!(
            "paused segments={} steps={} spool_bytes={}",
            prover.segment_count(),
            prover.relation_step_count(),
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

fn preflight(
    expected: &ExpectedCheckpoint,
    rom_bytes: &[u8],
    input: &[u8],
    identities: InputIdentities,
) -> Result<(), CliError> {
    let capacity = u64::try_from(UNIFORM_ROW_COUNT)
        .map_err(|_| CliError::ProgressMismatch("segment capacity overflow"))?;
    let segment_count = expected.completed_steps.div_ceil(capacity);
    let maximum = u64::try_from(MAX_NATIVE_SEGMENT_COUNT)
        .map_err(|_| CliError::ProgressMismatch("segment limit overflow"))?;
    if segment_count > maximum {
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
        "preflight=true steps={} segment_capacity={} segments={} input_bytes={} input_consumed={} rom_sha256={} input_sha256={} expected_checkpoint_sha256={} rom_witness_auth_root_sha256={} endpoint_memory_witness_auth_root_sha256={}",
        expected.completed_steps,
        capacity,
        segment_count,
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

type FileProver<'a> = NativeReceiptStreamProver<'a, File>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SpoolRecovery {
    Exact,
    DiscardUncheckpointedTail,
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
) -> Result<(TraceBuilder, CommittedMemory, u64, FileProver<'a>), CliError> {
    require_absent(&args.spool)?;
    require_absent(&args.progress_checkpoint)?;
    let memory = MemoryImage::zeroed()?;
    let memory_bytes = memory.checkpoint_bytes();
    let initial_memory = commit_memory(&memory_bytes)?;
    let builder = TraceBuilder::new_dmg_post_boot_mbc3(
        RomImage::new(rom_bytes.to_vec())?,
        memory,
        input.to_vec(),
    );
    let spool = open_new(&args.spool)?;
    let prover = NativeReceiptStreamProver::new(committed_rom, spool)?;
    Ok((builder, initial_memory, 0, prover))
}

fn resume<'a>(
    args: &Args,
    rom_bytes: &[u8],
    input: &[u8],
    identities: InputIdentities,
    committed_rom: &'a zksm83_jolt::CommittedRom,
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
            .sync_data()
            .map_err(|source| io_error("sync", &args.spool, source))?;
    }
    let prover = NativeReceiptStreamProver::resume(committed_rom, spool)?;
    if prover.segment_count() != progress.segment_count
        || prover.relation_step_count() != progress.relation_step_count
        || prover.spooled_bytes() != progress.spool_bytes
    {
        return Err(CliError::ProgressMismatch("verified spool counters differ"));
    }
    let checkpoint_state = zksm83_jolt::NativeStateBoundary::from_vm_state(progress.state);
    if prover.current_boundary().map(|boundary| boundary.state()) != Some(checkpoint_state) {
        return Err(CliError::ProgressMismatch(
            "verified spool state differs from checkpoint",
        ));
    }
    let memory_bytes = hex::decode(&progress.memory_hex)?;
    let initial_memory = commit_memory(&memory_bytes)?;
    let spooled_memory = prover
        .current_memory_commitment()
        .ok_or(CliError::ProgressMismatch("verified spool has no memory"))?;
    if spooled_memory.canonical_bytes()? != initial_memory.commitment().canonical_bytes()? {
        return Err(CliError::ProgressMemoryCommitment {
            spooled: hex::encode(spooled_memory.digest()?),
            checkpoint: hex::encode(initial_memory.commitment().digest()?),
        });
    }
    let memory = MemoryImage::from_checkpoint_bytes(memory_bytes)?;
    let builder = TraceBuilder::resume(
        RomImage::new(rom_bytes.to_vec())?,
        memory,
        input.to_vec(),
        progress.state,
    )?;
    Ok((
        builder,
        initial_memory,
        progress.relation_step_count,
        prover,
    ))
}

fn prove_segments(
    args: &Args,
    expected: &ExpectedCheckpoint,
    identities: InputIdentities,
    builder: &mut TraceBuilder,
    initial_memory: &mut CommittedMemory,
    completed: u64,
    prover: &mut FileProver<'_>,
) -> Result<(), CliError> {
    if completed != prover.relation_step_count() || completed > expected.completed_steps {
        return Err(CliError::ProgressMismatch(
            "relation-step cursor is invalid",
        ));
    }
    let capacity = u64::try_from(UNIFORM_ROW_COUNT)
        .map_err(|_| CliError::ProgressMismatch("segment capacity overflow"))?;
    let mut new_segments = 0_u64;
    while prover.relation_step_count() < expected.completed_steps {
        if args
            .segment_limit
            .is_some_and(|limit| new_segments >= limit)
        {
            break;
        }
        let remaining = expected.completed_steps - prover.relation_step_count();
        let segment_steps = remaining.min(capacity);
        let started = Instant::now();
        let witness = builder.run_exact_steps(segment_steps)?;
        let native_trace = NativeTraceWitness::from_witness(&witness)?;
        let final_bytes = builder.checkpoint_memory();
        let final_memory = commit_memory(&final_bytes)?;
        prover.append(NativeSegmentWitness::new(
            &native_trace,
            initial_memory,
            &final_memory,
        ))?;
        prover.sync_spool()?;
        *initial_memory = final_memory;
        new_segments = new_segments
            .checked_add(1)
            .ok_or(CliError::ProgressMismatch("segment counter overflow"))?;
        write_progress(args, identities, builder, prover)?;
        println!(
            "segment={} steps={} total_steps={} spool_bytes={} elapsed_seconds={:.3}",
            prover.segment_count() - 1,
            segment_steps,
            prover.relation_step_count(),
            prover.spooled_bytes(),
            started.elapsed().as_secs_f64()
        );
    }
    Ok(())
}

fn write_progress(
    args: &Args,
    identities: InputIdentities,
    builder: &TraceBuilder,
    prover: &FileProver<'_>,
) -> Result<(), CliError> {
    let progress = ProverProgress {
        schema: PROGRESS_SCHEMA.to_owned(),
        rom_sha256: hex::encode(identities.rom),
        input_sha256: hex::encode(identities.input),
        expected_checkpoint_sha256: hex::encode(identities.expected),
        segment_capacity: UNIFORM_ROW_COUNT,
        segment_count: prover.segment_count(),
        relation_step_count: prover.relation_step_count(),
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
    fs::rename(&receipt_partial, &args.receipt)
        .map_err(|source| io_error("publish", &args.receipt, source))?;
    write_new(&args.statement, &statement.to_bytes()?)?;
    println!(
        "complete statement_id={} segments={} steps={}",
        hex::encode(statement.statement_id()),
        statement.segment_count(),
        statement.relation_step_count()
    );
    Ok(())
}

fn validate_expected_artifact(
    expected: &ExpectedCheckpoint,
    rom_bytes: &[u8],
) -> Result<(), CliError> {
    if expected.schema != EXPECTED_CHECKPOINT_SCHEMA {
        return Err(CliError::ExpectedSchema(expected.schema.clone()));
    }
    if expected.completed_steps == 0 {
        return Err(CliError::EndpointMismatch("zero relation steps"));
    }
    if rom_bytes.len() != ROM_BYTE_LENGTH {
        return Err(CliError::EndpointMismatch("ROM byte length"));
    }
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
    if progress.segment_capacity != UNIFORM_ROW_COUNT {
        return Err(CliError::ProgressMismatch("segment capacity"));
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

fn read_bounded(path: &Path, kind: &'static str, maximum: u64) -> Result<Vec<u8>, CliError> {
    let metadata = fs::metadata(path).map_err(|source| io_error("inspect", path, source))?;
    if metadata.len() > maximum {
        return Err(CliError::FileTooLarge {
            kind,
            path: path.display().to_string(),
            maximum,
        });
    }
    fs::read(path).map_err(|source| io_error("read", path, source))
}

fn open_new(path: &Path) -> Result<File, CliError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error("create", path, source))
}

fn open_existing(path: &Path) -> Result<File, CliError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|source| io_error("open", path, source))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut file = open_new(path)?;
    file.write_all(bytes)
        .map_err(|source| io_error("write", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync", path, source))
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let temporary = partial_path(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)
        .map_err(|source| io_error("create", &temporary, source))?;
    file.write_all(bytes)
        .map_err(|source| io_error("write", &temporary, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync", &temporary, source))?;
    fs::rename(&temporary, path).map_err(|source| io_error("publish", path, source))
}

fn require_absent(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        Err(CliError::OutputExists(path.display().to_string()))
    } else {
        Ok(())
    }
}

fn partial_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".partial");
    PathBuf::from(value)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> CliError {
    CliError::Io {
        operation,
        path: path.display().to_string(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CliError, EXPECTED_CHECKPOINT_SCHEMA, ExpectedCheckpoint, ExpectedState, ROM_BYTE_LENGTH,
        SpoolRecovery, spool_recovery, validate_endpoint, validate_expected_artifact,
    };
    use zksm83_core::{
        CpuState, DmgDeviceState, MachineContext, MachineProfile, Mbc3State, VmState,
    };
    use zksm83_memory::{CommitmentRoot, LogAccumulator, LogKind, MemoryImage, RomImage};

    #[test]
    fn legacy_roots_do_not_override_exact_native_endpoint_checks()
    -> Result<(), Box<dyn std::error::Error>> {
        let (expected, actual, memory, rom, input) = fixture()?;
        validate_endpoint(actual, &memory, &rom, &input, &expected)?;

        let mut changed_memory = memory.clone();
        let byte = changed_memory
            .get_mut(0)
            .ok_or_else(|| std::io::Error::other("missing memory byte"))?;
        *byte ^= 1;
        assert!(validate_endpoint(actual, &changed_memory, &rom, &input, &expected).is_err());

        let changed_input = [8_u8];
        assert!(validate_endpoint(actual, &memory, &rom, &changed_input, &expected).is_err());
        Ok(())
    }

    #[test]
    fn preflight_rejects_a_short_rom() -> Result<(), Box<dyn std::error::Error>> {
        let (expected, _, _, _, _) = fixture()?;
        assert!(validate_expected_artifact(&expected, &[0]).is_err());
        Ok(())
    }

    #[test]
    fn spool_length_policy_rejects_loss_and_discards_only_uncheckpointed_tail() {
        assert!(matches!(spool_recovery(8, 8), Ok(SpoolRecovery::Exact)));
        assert!(matches!(
            spool_recovery(9, 8),
            Ok(SpoolRecovery::DiscardUncheckpointedTail)
        ));
        assert!(matches!(
            spool_recovery(7, 8),
            Err(CliError::ProgressMismatch(
                "spool is shorter than checkpoint"
            ))
        ));
    }

    fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
        let rom = vec![0_u8; ROM_BYTE_LENGTH];
        let rom_root = RomImage::new(rom.clone())?.root();
        let memory_image = MemoryImage::zeroed()?;
        let memory = memory_image.checkpoint_bytes();
        let input = vec![7_u8];
        let input_log = LogAccumulator::commit(LogKind::Input, &input)?;
        let output_log = LogAccumulator::empty(LogKind::Output);
        let cpu = CpuState::dmg_post_boot_initial();
        let devices = DmgDeviceState::dmg_post_boot();
        let actual = VmState::from_profile_parts(
            MachineContext::new(MachineProfile::DmgPostBootMbc3V1, devices),
            cpu,
            Mbc3State::profile_initial(),
            rom_root,
            memory_image.root(),
            input_log,
            output_log,
        )?;
        let expected = ExpectedCheckpoint {
            schema: EXPECTED_CHECKPOINT_SCHEMA.to_owned(),
            completed_steps: 1,
            state: ExpectedState {
                profile: MachineProfile::DmgPostBootMbc3V1,
                cpu,
                mbc3: Mbc3State::profile_initial(),
                dmg_devices: devices,
                _legacy_rom_root: CommitmentRoot::zero(),
                _legacy_memory_root: CommitmentRoot::zero(),
                input_log,
                output_log,
            },
            memory_hex: hex::encode(&memory),
        };
        Ok((expected, actual, memory, rom, input))
    }

    type Fixture = (ExpectedCheckpoint, VmState, Vec<u8>, Vec<u8>, Vec<u8>);
}
