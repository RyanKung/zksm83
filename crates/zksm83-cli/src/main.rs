#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Command-line adapters for proving, verification, benchmarks, and trace inspection.

use std::{
    ffi::OsStr,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::Instant,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zksm83_core::{MachineProfile, VmState};
use zksm83_memory::{MemoryImage, RomImage};
use zksm83_receipt::{Receipt, ReceiptError};
use zksm83_trace::{
    ExecutionMetrics, ProgramCounterCount, TraceBuilder, TraceBuilderError, Witness,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ExecutionProfile {
    CleanCoreV1,
    DmgPostBootMbc3V1,
}

#[derive(Debug, Parser)]
#[command(name = "zksm83", version, about = "Clean native SM83 zkVM")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Execute a ROM and write a reference Halo2 V2 receipt.
    Prove(ProveArgs),
    /// Verify a reference Halo2 V2 receipt.
    Verify(VerifyArgs),
    /// Execute and serialize the fully validated trace witness.
    InspectTrace(InspectArgs),
    /// Measure the reference Halo2 V2 stages as JSON.
    Bench(BenchArgs),
}

#[derive(Debug, Args)]
struct ExecutionArgs {
    /// Raw ROM path, or lowercase/whitespace-tolerant hexadecimal when extension is `.hex`.
    #[arg(long)]
    rom: PathBuf,
    /// Optional raw private-input byte file.
    #[arg(long)]
    input: Option<PathBuf>,
    /// Maximum relation rows before a still-running execution fails closed.
    #[arg(long, default_value_t = 10_000)]
    max_steps: u64,
    /// Machine boundary used for address ownership and initial CPU state.
    #[arg(long, value_enum, default_value_t = ExecutionProfile::CleanCoreV1)]
    profile: ExecutionProfile,
    /// Execute exactly `max_steps` and allow a still-running final state.
    #[arg(long)]
    exact_steps: bool,
    /// Resume from a previously validated full-memory trace checkpoint.
    #[arg(long)]
    checkpoint_in: Option<PathBuf>,
    /// Optional exact 32-KiB four-bank MBC3 battery SRAM image.
    #[arg(long)]
    save_in: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ProveArgs {
    #[command(flatten)]
    execution: ExecutionArgs,
    /// Destination JSON receipt.
    #[arg(long)]
    receipt: PathBuf,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    /// JSON receipt to verify.
    #[arg(long)]
    receipt: PathBuf,
    /// Optional verification-report path; stdout is used when omitted.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct InspectArgs {
    #[command(flatten)]
    execution: ExecutionArgs,
    /// Optional output path; stdout is used when omitted.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Emit only public boundaries and construction cost, not every private row.
    #[arg(long)]
    summary_only: bool,
    /// Persist the final state and full committed memory for deterministic resumption.
    #[arg(long)]
    checkpoint_out: Option<PathBuf>,
    /// Write the final four-bank MBC3 battery SRAM to a new `.sav` path.
    #[arg(long)]
    save_out: Option<PathBuf>,
    /// Stop after the selected distinct arrival whose final PC matches this value.
    #[arg(long, value_parser = parse_u16_number)]
    stop_pc: Option<u16>,
    /// Also require this selected MBC3 ROM bank at the PC milestone.
    #[arg(long, value_parser = parse_u8_number)]
    stop_rom_bank: Option<u8>,
    /// Stop on this distinct arrival at the selected PC milestone.
    #[arg(long, default_value_t = 1)]
    stop_occurrence: u64,
    /// Include the N hottest instruction PCs in a summary-only exact-prefix run.
    #[arg(long)]
    pc_profile_limit: Option<usize>,
}

#[derive(Debug, Args)]
struct BenchArgs {
    #[command(flatten)]
    execution: ExecutionArgs,
    /// Destination machine-readable benchmark report.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Error)]
enum CliError {
    #[error("filesystem operation for {path} failed: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("hexadecimal ROM {path} is invalid: {source}")]
    HexRom {
        path: PathBuf,
        source: hex::FromHexError,
    },
    #[error("hexadecimal input {path} is invalid: {source}")]
    HexInput {
        path: PathBuf,
        source: hex::FromHexError,
    },
    #[error("JSON input schedule {path} is invalid: {source}")]
    InputScheduleJson {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("unsupported input schedule schema {schema}")]
    UnsupportedInputScheduleSchema { schema: String },
    #[error("input schedule length {actual} exceeds limit {maximum}")]
    InputScheduleTooLarge { actual: usize, maximum: usize },
    #[error("input schedule segment {index} has invalid range {start}..{end} for length {length}")]
    InvalidInputScheduleSegment {
        index: usize,
        start: usize,
        end: usize,
        length: usize,
    },
    #[error("input schedule segment {index} overlaps an earlier segment")]
    OverlappingInputScheduleSegment { index: usize },
    #[error("checkpoint memory in {path} is invalid hexadecimal: {source}")]
    HexCheckpoint {
        path: PathBuf,
        source: hex::FromHexError,
    },
    #[error(transparent)]
    Rom(#[from] zksm83_memory::RomImageError),
    #[error(transparent)]
    Memory(#[from] zksm83_memory::MemoryImageError),
    #[error(transparent)]
    Trace(#[from] TraceBuilderError),
    #[error(transparent)]
    Receipt(#[from] ReceiptError),
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("resident-memory probe returned invalid output")]
    MemoryProbe,
    #[error("trace summary requires --exact-steps")]
    TraceSummaryRequiresExactSteps,
    #[error("trace checkpoint output requires --summary-only and --exact-steps")]
    TraceCheckpointRequiresSummary,
    #[error("battery SRAM output requires --summary-only and --exact-steps")]
    SaveOutputRequiresSummary,
    #[error("--save-in cannot be combined with --checkpoint-in")]
    SaveInputCheckpointConflict,
    #[error("--stop-rom-bank requires --stop-pc")]
    StopRomBankRequiresPc,
    #[error("--stop-occurrence requires --stop-pc when it differs from 1")]
    StopOccurrenceRequiresPc,
    #[error("--stop-occurrence must be at least 1")]
    ZeroStopOccurrence,
    #[error("--pc-profile-limit requires --summary-only and --exact-steps")]
    PcProfileRequiresSummary,
    #[error("unsupported trace checkpoint schema {schema}")]
    UnsupportedTraceCheckpointSchema { schema: String },
    #[error("checkpoint profile does not match the selected execution profile")]
    TraceCheckpointProfileMismatch,
    #[error("checkpoint relation-step count overflow")]
    TraceCheckpointStepOverflow,
    #[error("validated trace cycle counter regressed")]
    TraceCycleRegression,
    #[error(
        "Game Boy cartridge header is missing byte 0x{required_offset:03x}; file has {actual} bytes"
    )]
    CartridgeHeaderTooShort {
        required_offset: usize,
        actual: usize,
    },
    #[error("cartridge type 0x{cartridge_type:02x} is not a supported no-RTC MBC3 type")]
    UnsupportedCartridgeType { cartridge_type: u8 },
    #[error("cartridge ROM-size code 0x{rom_size:02x} exceeds the one-MiB MBC3 profile")]
    UnsupportedCartridgeRomSize { rom_size: u8 },
    #[error("cartridge RAM-size code 0x{ram_size:02x} exceeds the 32-KiB MBC3 profile")]
    UnsupportedCartridgeRamSize { ram_size: u8 },
}

#[derive(Serialize)]
struct VerificationReport {
    schema: &'static str,
    verified: bool,
    receipt_id: String,
    k: u32,
    step_count: u64,
    cycle_count: u64,
    public_output_root: String,
}

#[derive(Serialize)]
struct BenchmarkReport {
    schema: &'static str,
    platform: &'static str,
    architecture: &'static str,
    backend: &'static str,
    rom_bytes: usize,
    private_input_bytes: usize,
    step_count: u64,
    cycle_count: u64,
    k: u32,
    proof_bytes: usize,
    trace_milliseconds: u128,
    prove_milliseconds: u128,
    verify_milliseconds: u128,
    resident_kib_after_trace: u64,
    resident_kib_after_prove: u64,
    resident_kib_after_verify: u64,
    verified: bool,
    receipt_id: String,
}

#[derive(Serialize)]
struct TraceSummary {
    schema: &'static str,
    rom_bytes: usize,
    private_input_bytes: usize,
    step_count: u64,
    metrics: ExecutionMetrics,
    m_cycle_count: u64,
    trace_milliseconds: u128,
    milestone: Option<TraceMilestone>,
    pc_profile: Option<Vec<ProgramCounterCount>>,
    initial_state: VmState,
    final_state: VmState,
}

#[derive(Clone, Copy, Serialize)]
struct TraceMilestone {
    pc: u16,
    rom_bank: Option<u8>,
    occurrence: u64,
}

#[derive(Deserialize, Serialize)]
struct TraceCheckpoint {
    schema: String,
    completed_steps: u64,
    state: VmState,
    memory_hex: String,
}

#[derive(Deserialize)]
struct InputSchedule {
    schema: String,
    length: usize,
    segments: Vec<InputSegment>,
}

#[derive(Deserialize)]
struct InputSegment {
    start: usize,
    end: usize,
    value: u8,
}

const TRACE_CHECKPOINT_V7: &str = "zksm83-trace-checkpoint/v7";
const INPUT_SCHEDULE_V1: &str = "zksm83-input-schedule/v1";
const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("zksm83: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Commands::Prove(args) => prove_command(args),
        Commands::Verify(args) => verify_command(args),
        Commands::InspectTrace(args) => inspect_command(args),
        Commands::Bench(args) => bench_command(args),
    }
}

fn prove_command(args: ProveArgs) -> Result<(), CliError> {
    let (_, _, witness) = build_witness(&args.execution)?;
    let receipt = Receipt::prove(&witness)?;
    let encoded = receipt.to_json_pretty()?;
    write_file(&args.receipt, encoded.as_bytes())?;
    let verified = receipt.verify()?;
    println!(
        "receipt_id={} verified=true steps={} cycles={} proof_bytes={}",
        verified.receipt_id.to_hex(),
        verified.step_count,
        verified.cycle_count,
        receipt.proof.len()
    );
    Ok(())
}

fn verify_command(args: VerifyArgs) -> Result<(), CliError> {
    let encoded = read_file(&args.receipt)?;
    let text = std::str::from_utf8(&encoded).map_err(|source| CliError::Io {
        path: args.receipt.clone(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
    })?;
    let verified = Receipt::from_json(text)?.verify()?;
    let report = VerificationReport {
        schema: "zksm83-verification/v2",
        verified: true,
        receipt_id: verified.receipt_id.to_hex(),
        k: verified.k,
        step_count: verified.step_count,
        cycle_count: verified.cycle_count,
        public_output_root: verified.public_output_root.to_hex(),
    };
    let report_json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = args.output {
        write_file(&path, report_json.as_bytes())
    } else {
        println!("{report_json}");
        Ok(())
    }
}

fn inspect_command(args: InspectArgs) -> Result<(), CliError> {
    let started = Instant::now();
    let encoded = if args.summary_only {
        if !args.execution.exact_steps {
            return Err(CliError::TraceSummaryRequiresExactSteps);
        }
        if args.stop_pc.is_none() && args.stop_rom_bank.is_some() {
            return Err(CliError::StopRomBankRequiresPc);
        }
        if args.stop_occurrence == 0 {
            return Err(CliError::ZeroStopOccurrence);
        }
        if args.stop_pc.is_none() && args.stop_occurrence != 1 {
            return Err(CliError::StopOccurrenceRequiresPc);
        }
        let milestone = args.stop_pc.map(|pc| TraceMilestone {
            pc,
            rom_bank: args.stop_rom_bank,
            occurrence: args.stop_occurrence,
        });
        let (rom_bytes, input_bytes, prior_steps, mut builder) =
            build_trace_builder(&args.execution)?;
        let (boundary_result, pc_profile) = match (milestone, args.pc_profile_limit) {
            (None, Some(limit)) => {
                match builder.run_exact_boundary_profiled(args.execution.max_steps) {
                    Ok((boundary, profile)) => (Ok(boundary), Some(profile.top(limit))),
                    Err(error) => (Err(error), None),
                }
            }
            (None, None) => (builder.run_exact_boundary(args.execution.max_steps), None),
            (Some(target), limit) => {
                let mut arrivals = 0_u64;
                let mut previously_at_target = false;
                let reached = |state: VmState| {
                    let at_target = state.cpu().pc() == target.pc
                        && target
                            .rom_bank
                            .is_none_or(|bank| state.mbc3().rom_bank() == bank);
                    if at_target && !previously_at_target {
                        arrivals = arrivals.saturating_add(1);
                    }
                    previously_at_target = at_target;
                    arrivals == target.occurrence
                };
                match limit {
                    Some(limit) => match builder
                        .run_until_boundary_profiled(args.execution.max_steps, reached)
                    {
                        Ok((boundary, profile)) => (Ok(boundary), Some(profile.top(limit))),
                        Err(error) => (Err(error), None),
                    },
                    None => (
                        builder.run_until_boundary(args.execution.max_steps, reached),
                        None,
                    ),
                }
            }
        };
        let boundary = match boundary_result {
            Ok(boundary) => boundary,
            Err(error) => {
                if let (Some(path), Some(completed)) =
                    (&args.checkpoint_out, error.completed_exact_steps())
                {
                    let completed_steps = prior_steps
                        .checked_add(completed)
                        .ok_or(CliError::TraceCheckpointStepOverflow)?;
                    write_trace_checkpoint(path, completed_steps, &builder)?;
                    eprintln!(
                        "zksm83: preserved the last accepted boundary after {completed} rows in {}",
                        path.display()
                    );
                }
                return Err(CliError::Trace(error));
            }
        };
        if let Some(path) = &args.checkpoint_out {
            let completed_steps = prior_steps
                .checked_add(boundary.step_count())
                .ok_or(CliError::TraceCheckpointStepOverflow)?;
            write_trace_checkpoint(path, completed_steps, &builder)?;
        }
        if let Some(path) = &args.save_out {
            write_new_file(path, &builder.battery_sram()?)?;
        }
        serde_json::to_string_pretty(&TraceSummary {
            schema: "zksm83-trace-summary/v9",
            rom_bytes,
            private_input_bytes: input_bytes,
            step_count: boundary.step_count(),
            metrics: boundary.metrics(),
            m_cycle_count: boundary
                .final_state()
                .cpu()
                .m_cycles()
                .checked_sub(boundary.initial_state().cpu().m_cycles())
                .ok_or(CliError::TraceCycleRegression)?,
            trace_milliseconds: started.elapsed().as_millis(),
            milestone,
            pc_profile,
            initial_state: boundary.initial_state(),
            final_state: boundary.final_state(),
        })?
    } else {
        if args.pc_profile_limit.is_some() {
            return Err(CliError::PcProfileRequiresSummary);
        }
        if args.checkpoint_out.is_some() {
            return Err(CliError::TraceCheckpointRequiresSummary);
        }
        if args.save_out.is_some() {
            return Err(CliError::SaveOutputRequiresSummary);
        }
        let (_, _, witness) = build_witness(&args.execution)?;
        serde_json::to_string_pretty(&witness)?
    };
    if let Some(path) = args.output {
        write_file(&path, encoded.as_bytes())
    } else {
        println!("{encoded}");
        Ok(())
    }
}

fn bench_command(args: BenchArgs) -> Result<(), CliError> {
    let trace_started = Instant::now();
    let (rom_bytes, input_bytes, witness) = build_witness(&args.execution)?;
    let trace_milliseconds = trace_started.elapsed().as_millis();
    let resident_kib_after_trace = resident_kib()?;
    let prove_started = Instant::now();
    let receipt = Receipt::prove(&witness)?;
    let prove_milliseconds = prove_started.elapsed().as_millis();
    let resident_kib_after_prove = resident_kib()?;
    let verify_started = Instant::now();
    let verified = receipt.verify()?;
    let verify_milliseconds = verify_started.elapsed().as_millis();
    let report = BenchmarkReport {
        schema: "zksm83-benchmark/v2",
        platform: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        backend: "halo2-ipa-pasta-poseidon-v2",
        rom_bytes,
        private_input_bytes: input_bytes,
        step_count: verified.step_count,
        cycle_count: verified.cycle_count,
        k: verified.k,
        proof_bytes: receipt.proof.len(),
        trace_milliseconds,
        prove_milliseconds,
        verify_milliseconds,
        resident_kib_after_trace,
        resident_kib_after_prove,
        resident_kib_after_verify: resident_kib()?,
        verified: true,
        receipt_id: verified.receipt_id.to_hex(),
    };
    write_file(
        &args.output,
        serde_json::to_string_pretty(&report)?.as_bytes(),
    )
}

fn build_witness(args: &ExecutionArgs) -> Result<(usize, usize, Witness), CliError> {
    let (rom_len, input_len, _, mut builder) = build_trace_builder(args)?;
    let witness = if args.exact_steps {
        builder.run_exact_steps(args.max_steps)?
    } else {
        builder.run(args.max_steps)?
    };
    Ok((rom_len, input_len, witness))
}

fn build_trace_builder(
    args: &ExecutionArgs,
) -> Result<(usize, usize, u64, TraceBuilder), CliError> {
    let rom_bytes = load_rom(&args.rom)?;
    let input = args
        .input
        .as_ref()
        .map_or(Ok(Vec::new()), |path| load_input(path))?;
    let rom_len = rom_bytes.len();
    let input_len = input.len();
    let rom = RomImage::new(rom_bytes)?;
    if args.checkpoint_in.is_some() && args.save_in.is_some() {
        return Err(CliError::SaveInputCheckpointConflict);
    }
    let (completed_steps, builder) = match &args.checkpoint_in {
        Some(path) => {
            let checkpoint = read_trace_checkpoint(path)?;
            if checkpoint.state.profile() != args.profile.machine_profile() {
                return Err(CliError::TraceCheckpointProfileMismatch);
            }
            let memory_bytes =
                hex::decode(&checkpoint.memory_hex).map_err(|source| CliError::HexCheckpoint {
                    path: path.clone(),
                    source,
                })?;
            let memory = MemoryImage::from_checkpoint_bytes(memory_bytes)?;
            let builder = TraceBuilder::resume(rom, memory, input, checkpoint.state)?;
            (checkpoint.completed_steps, builder)
        }
        None => {
            let memory = match &args.save_in {
                Some(path) => MemoryImage::with_battery_sram(read_file(path)?)?,
                None => MemoryImage::zeroed()?,
            };
            let builder = match args.profile {
                ExecutionProfile::CleanCoreV1 => TraceBuilder::new(rom, memory, input),
                ExecutionProfile::DmgPostBootMbc3V1 => {
                    TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, input)
                }
            };
            (0, builder)
        }
    };
    Ok((rom_len, input_len, completed_steps, builder))
}

impl ExecutionProfile {
    const fn machine_profile(self) -> MachineProfile {
        match self {
            Self::CleanCoreV1 => MachineProfile::CleanCoreV1,
            Self::DmgPostBootMbc3V1 => MachineProfile::DmgPostBootMbc3V1,
        }
    }
}

fn read_trace_checkpoint(path: &Path) -> Result<TraceCheckpoint, CliError> {
    let encoded = read_file(path)?;
    let checkpoint: TraceCheckpoint = serde_json::from_slice(&encoded)?;
    if checkpoint.schema != TRACE_CHECKPOINT_V7 {
        return Err(CliError::UnsupportedTraceCheckpointSchema {
            schema: checkpoint.schema,
        });
    }
    Ok(checkpoint)
}

fn write_trace_checkpoint(
    path: &Path,
    completed_steps: u64,
    builder: &TraceBuilder,
) -> Result<(), CliError> {
    let checkpoint = TraceCheckpoint {
        schema: TRACE_CHECKPOINT_V7.to_owned(),
        completed_steps,
        state: builder.state(),
        memory_hex: hex::encode(builder.checkpoint_memory()),
    };
    write_file(path, serde_json::to_string_pretty(&checkpoint)?.as_bytes())
}

fn load_input(path: &Path) -> Result<Vec<u8>, CliError> {
    let raw = read_file(path)?;
    if path.extension() == Some(OsStr::new("json")) {
        let schedule: InputSchedule =
            serde_json::from_slice(&raw).map_err(|source| CliError::InputScheduleJson {
                path: path.to_path_buf(),
                source,
            })?;
        return expand_input_schedule(schedule);
    }
    if path.extension() != Some(OsStr::new("hex")) {
        return Ok(raw);
    }
    let compact = raw
        .into_iter()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    hex::decode(compact).map_err(|source| CliError::HexInput {
        path: path.to_path_buf(),
        source,
    })
}

fn expand_input_schedule(schedule: InputSchedule) -> Result<Vec<u8>, CliError> {
    if schedule.schema != INPUT_SCHEDULE_V1 {
        return Err(CliError::UnsupportedInputScheduleSchema {
            schema: schedule.schema,
        });
    }
    if schedule.length > MAX_INPUT_BYTES {
        return Err(CliError::InputScheduleTooLarge {
            actual: schedule.length,
            maximum: MAX_INPUT_BYTES,
        });
    }
    let mut bytes = vec![0_u8; schedule.length];
    let mut assigned = vec![false; schedule.length];
    for (index, segment) in schedule.segments.into_iter().enumerate() {
        if segment.start >= segment.end || segment.end > schedule.length {
            return Err(CliError::InvalidInputScheduleSegment {
                index,
                start: segment.start,
                end: segment.end,
                length: schedule.length,
            });
        }
        let claimed = assigned.get_mut(segment.start..segment.end).ok_or(
            CliError::InvalidInputScheduleSegment {
                index,
                start: segment.start,
                end: segment.end,
                length: schedule.length,
            },
        )?;
        if claimed.iter().any(|value| *value) {
            return Err(CliError::OverlappingInputScheduleSegment { index });
        }
        claimed.fill(true);
        bytes
            .get_mut(segment.start..segment.end)
            .ok_or(CliError::InvalidInputScheduleSegment {
                index,
                start: segment.start,
                end: segment.end,
                length: schedule.length,
            })?
            .fill(segment.value);
    }
    Ok(bytes)
}

fn parse_u16_number(value: &str) -> Result<u16, String> {
    let (digits, radix) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or((value, 10), |digits| (digits, 16));
    u16::from_str_radix(digits, radix).map_err(|error| format!("invalid 16-bit value: {error}"))
}

fn parse_u8_number(value: &str) -> Result<u8, String> {
    let parsed = parse_u16_number(value)?;
    u8::try_from(parsed).map_err(|_| format!("value {parsed} exceeds 8 bits"))
}

fn load_rom(path: &Path) -> Result<Vec<u8>, CliError> {
    let raw = read_file(path)?;
    if path.extension() == Some(OsStr::new("hex")) {
        let compact = raw
            .into_iter()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        hex::decode(compact).map_err(|source| CliError::HexRom {
            path: path.to_path_buf(),
            source,
        })
    } else {
        if matches!(path.extension(), Some(extension) if extension == OsStr::new("gb") || extension == OsStr::new("gbc"))
        {
            validate_mbc3_cartridge(&raw)?;
        }
        Ok(raw)
    }
}

fn validate_mbc3_cartridge(bytes: &[u8]) -> Result<(), CliError> {
    let cartridge_type = cartridge_header_byte(bytes, 0x147)?;
    if !matches!(cartridge_type, 0x11..=0x13) {
        return Err(CliError::UnsupportedCartridgeType { cartridge_type });
    }
    let rom_size = cartridge_header_byte(bytes, 0x148)?;
    if rom_size > 0x05 {
        return Err(CliError::UnsupportedCartridgeRomSize { rom_size });
    }
    let ram_size = cartridge_header_byte(bytes, 0x149)?;
    if !matches!(ram_size, 0x00 | 0x02 | 0x03) {
        return Err(CliError::UnsupportedCartridgeRamSize { ram_size });
    }
    Ok(())
}

fn cartridge_header_byte(bytes: &[u8], offset: usize) -> Result<u8, CliError> {
    bytes
        .get(offset)
        .copied()
        .ok_or(CliError::CartridgeHeaderTooShort {
            required_offset: offset,
            actual: bytes.len(),
        })
}

fn read_file(path: &Path) -> Result<Vec<u8>, CliError> {
    fs::read(path).map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn write_file(path: &Path, contents: &[u8]) -> Result<(), CliError> {
    fs::write(path, contents).map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn write_new_file(path: &Path, contents: &[u8]) -> Result<(), CliError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| CliError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    file.write_all(contents).map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn resident_kib() -> Result<u64, CliError> {
    let pid = std::process::id().to_string();
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .map_err(|source| CliError::Io {
            path: PathBuf::from("ps"),
            source,
        })?;
    let encoded = String::from_utf8(output.stdout).map_err(|_| CliError::MemoryProbe)?;
    encoded.trim().parse().map_err(|_| CliError::MemoryProbe)
}

#[cfg(test)]
mod tests {
    use super::{
        CliError, InputSchedule, InputSegment, expand_input_schedule, parse_u8_number,
        parse_u16_number, validate_mbc3_cartridge,
    };

    #[test]
    fn accepts_blue_header_and_rejects_mbc5() -> Result<(), Box<dyn std::error::Error>> {
        let mut header = vec![0_u8; 0x150];
        set_header_byte(&mut header, 0x147, 0x13)?;
        set_header_byte(&mut header, 0x148, 0x05)?;
        set_header_byte(&mut header, 0x149, 0x03)?;
        validate_mbc3_cartridge(&header)?;

        set_header_byte(&mut header, 0x147, 0x1b)?;
        assert!(matches!(
            validate_mbc3_cartridge(&header),
            Err(CliError::UnsupportedCartridgeType {
                cartridge_type: 0x1b
            })
        ));
        Ok(())
    }

    #[test]
    fn parses_decimal_and_hexadecimal_milestones() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(parse_u16_number("0x1311")?, 0x1311);
        assert_eq!(parse_u16_number("4881")?, 0x1311);
        assert_eq!(parse_u8_number("0x1c")?, 0x1c);
        assert!(parse_u8_number("0x100").is_err());
        Ok(())
    }

    #[test]
    fn expands_non_overlapping_input_schedule_and_rejects_overlap()
    -> Result<(), Box<dyn std::error::Error>> {
        let schedule = InputSchedule {
            schema: "zksm83-input-schedule/v1".to_owned(),
            length: 8,
            segments: vec![
                InputSegment {
                    start: 1,
                    end: 3,
                    value: 0x80,
                },
                InputSegment {
                    start: 5,
                    end: 6,
                    value: 0x10,
                },
            ],
        };
        assert_eq!(
            expand_input_schedule(schedule)?,
            vec![0, 0x80, 0x80, 0, 0, 0x10, 0, 0]
        );

        let overlapping = InputSchedule {
            schema: "zksm83-input-schedule/v1".to_owned(),
            length: 4,
            segments: vec![
                InputSegment {
                    start: 0,
                    end: 2,
                    value: 1,
                },
                InputSegment {
                    start: 1,
                    end: 3,
                    value: 2,
                },
            ],
        };
        assert!(matches!(
            expand_input_schedule(overlapping),
            Err(CliError::OverlappingInputScheduleSegment { index: 1 })
        ));
        Ok(())
    }

    fn set_header_byte(header: &mut [u8], offset: usize, value: u8) -> Result<(), std::io::Error> {
        let byte = header
            .get_mut(offset)
            .ok_or_else(|| std::io::Error::other("missing cartridge header byte"))?;
        *byte = value;
        Ok(())
    }
}
