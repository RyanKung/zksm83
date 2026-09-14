//! Measures lookup-backed cartridge execution without per-access Merkle paths.

use std::{env, error::Error, ffi::OsString, fs, io, path::PathBuf, time::Instant};

use serde::{Deserialize, Serialize};
use zksm83_core::{CpuState, DmgDeviceState, MachineProfile, Mbc3State, VmState};
use zksm83_memory::{CommitmentRoot, LogAccumulator, LogKind, MemoryImage, RomImage};
use zksm83_trace::{ExecutionMetrics, LookupTraceBuilder, ProgramCounterCount};

const INPUT_SCHEDULE_V1: &str = "zksm83-input-schedule/v1";

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

#[derive(Deserialize)]
struct TraceCheckpoint {
    state: ExpectedState,
    memory_hex: String,
}

#[derive(Deserialize)]
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

#[derive(Serialize)]
struct LookupProfileReport {
    schema: &'static str,
    steps: u64,
    lookup_execution_milliseconds: u128,
    metrics: ExecutionMetrics,
    top_program_counters: Vec<ProgramCounterCount>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os().skip(1);
    let rom_path = arguments.next().map(PathBuf::from).ok_or_else(|| {
        io::Error::other(
            "usage: lookup_rom_prefix ROM STEPS [INPUT_JSON] [CHECKPOINT_JSON] [PROFILE_JSON] [PROFILE_LIMIT]",
        )
    })?;
    let steps = arguments
        .next()
        .ok_or_else(|| {
            io::Error::other(
                "usage: lookup_rom_prefix ROM STEPS [INPUT_JSON] [CHECKPOINT_JSON] [PROFILE_JSON] [PROFILE_LIMIT]",
            )
        })?
        .into_string()
        .map_err(|_| io::Error::other("step count is not UTF-8"))?
        .parse::<u64>()?;
    let input_path = arguments.next().map(PathBuf::from);
    let checkpoint_path = arguments.next().map(PathBuf::from);
    let profile_path = arguments.next().map(PathBuf::from);
    let profile_limit = parse_profile_limit(arguments.next())?;
    if arguments.next().is_some() {
        return Err(io::Error::other(
            "usage: lookup_rom_prefix ROM STEPS [INPUT_JSON] [CHECKPOINT_JSON] [PROFILE_JSON] [PROFILE_LIMIT]",
        )
        .into());
    }

    let rom_bytes = fs::read(rom_path)?;
    let roots_started = Instant::now();
    let rom_root = RomImage::new(rom_bytes.clone())?.root();
    let memory = MemoryImage::zeroed()?;
    let memory_root = memory.root();
    let memory_bytes = memory.checkpoint_bytes();
    let root_setup_milliseconds = roots_started.elapsed().as_millis();

    let private_input = input_path
        .map(load_input_schedule)
        .transpose()?
        .unwrap_or_default();
    let execution_started = Instant::now();
    let mut builder = LookupTraceBuilder::new_dmg_post_boot_mbc3(
        rom_bytes,
        memory_bytes,
        private_input.clone(),
        rom_root,
        memory_root,
    )?;
    let (boundary, profile) = if profile_path.is_some() {
        let (boundary, profile) = builder.run_exact_boundary_profiled(steps)?;
        (boundary, Some(profile))
    } else {
        (builder.run_exact_boundary(steps)?, None)
    };
    let execution_milliseconds = execution_started.elapsed().as_millis();

    let final_root_started = Instant::now();
    let final_memory_root = MemoryImage::from_checkpoint_bytes(builder.checkpoint_memory())?.root();
    let final_root_milliseconds = final_root_started.elapsed().as_millis();
    let checkpoint_matches = checkpoint_path
        .map(|path| {
            validate_checkpoint(
                &path,
                boundary.final_state(),
                builder.checkpoint_memory(),
                rom_root,
                &private_input,
            )
        })
        .transpose()?
        .unwrap_or(false);
    if let (Some(path), Some(profile)) = (profile_path, profile) {
        let report = LookupProfileReport {
            schema: "zksm83-lookup-pc-profile/v1",
            steps: boundary.step_count(),
            lookup_execution_milliseconds: execution_milliseconds,
            metrics: boundary.metrics(),
            top_program_counters: profile.top(profile_limit),
        };
        fs::write(path, serde_json::to_vec_pretty(&report)?)?;
    }
    println!(
        "steps={} bus_events={} root_setup_ms={} lookup_execution_ms={} final_root_ms={} final_pc=0x{:04x} final_memory_root={} checkpoint_matches={}",
        boundary.step_count(),
        boundary.metrics().bus_events(),
        root_setup_milliseconds,
        execution_milliseconds,
        final_root_milliseconds,
        boundary.final_state().cpu().pc(),
        final_memory_root,
        checkpoint_matches,
    );
    Ok(())
}

fn parse_profile_limit(value: Option<OsString>) -> Result<usize, Box<dyn Error>> {
    value
        .map(|value| {
            value
                .into_string()
                .map_err(|_| io::Error::other("profile limit is not UTF-8"))?
                .parse::<usize>()
                .map_err(|error| io::Error::other(error.to_string()))
        })
        .transpose()
        .map(|value| value.unwrap_or(100))
        .map_err(Into::into)
}

fn load_input_schedule(path: PathBuf) -> Result<Vec<u8>, Box<dyn Error>> {
    let schedule: InputSchedule = serde_json::from_slice(&fs::read(path)?)?;
    if schedule.schema != INPUT_SCHEDULE_V1 {
        return Err(io::Error::other("unsupported input schedule schema").into());
    }
    let mut input = vec![0_u8; schedule.length];
    let mut assigned = vec![false; schedule.length];
    for segment in schedule.segments {
        if segment.start >= segment.end || segment.end > input.len() {
            return Err(io::Error::other("invalid input schedule segment").into());
        }
        let claimed = assigned
            .get_mut(segment.start..segment.end)
            .ok_or_else(|| io::Error::other("input segment out of bounds"))?;
        if claimed.iter().any(|value| *value) {
            return Err(io::Error::other("overlapping input schedule segment").into());
        }
        claimed.fill(true);
        input
            .get_mut(segment.start..segment.end)
            .ok_or_else(|| io::Error::other("input segment out of bounds"))?
            .fill(segment.value);
    }
    Ok(input)
}

fn validate_checkpoint(
    path: &PathBuf,
    actual: VmState,
    actual_memory: Vec<u8>,
    rom_root: CommitmentRoot,
    input: &[u8],
) -> Result<bool, Box<dyn Error>> {
    let expected: TraceCheckpoint = serde_json::from_slice(&fs::read(path)?)?;
    let expected_memory = hex::decode(expected.memory_hex)?;
    let actual_memory_root = MemoryImage::from_checkpoint_bytes(actual_memory.clone())?.root();
    let input_length = usize::try_from(expected.state.input_log.next_index())?;
    let Some(input_prefix) = input.get(..input_length) else {
        return Ok(false);
    };
    let input_log = LogAccumulator::commit(LogKind::Input, input_prefix)?;
    let logical_state_matches = actual.profile() == expected.state.profile
        && actual.cpu() == expected.state.cpu
        && actual.mbc3() == expected.state.mbc3
        && actual.dmg_devices() == expected.state.dmg_devices
        && actual.rom_root() == rom_root
        && actual.memory_root() == actual_memory_root
        && actual.input_log() == input_log
        && expected.state.output_log.next_index() == 0
        && actual.output_log() == LogAccumulator::empty(LogKind::Output);
    Ok(logical_state_matches && actual_memory == expected_memory)
}
