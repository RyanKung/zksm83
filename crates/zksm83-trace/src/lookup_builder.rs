//! Plain-byte witness construction for an enclosing lookup-memory proof.

use thiserror::Error;
use zksm83_core::{
    BusEvent, BusWitness, LookupStepRelation, MachineProfile, RunState, StepError, StepInput,
    VmState, WitnessRequest,
};
use zksm83_memory::{
    CommitmentRoot, LogAccumulator, LogError, LogKind, MemoryRead, MemoryWrite, MerklePath, RomRead,
};

use crate::{
    ExecutionBoundary, ExecutionMetrics, ProgramCounterProfile, TraceError, TraceRow, Witness,
};

const ROM_BYTES: usize = 1 << 20;
const MEMORY_BYTES: usize = 1 << 17;
const BATTERY_SRAM_START: usize = 1 << 16;
const BATTERY_SRAM_BYTES: usize = 1 << 15;
const MAX_WITNESSES_PER_STEP: usize = 5;

/// Deterministic byte-array executor for a separately proven lookup argument.
///
/// The CPU, mapper, timing, device, input, and transcript relations are the
/// same typed core transition used by `TraceBuilder`. ROM and mutable-memory
/// values come from these arrays, while their Merkle roots stay fixed anchors;
/// callers must place every emitted access under an independent lookup-memory
/// proof before treating the result as authenticated.
pub struct LookupTraceBuilder {
    rom: Vec<u8>,
    memory: Vec<u8>,
    private_input: Vec<u8>,
    state: VmState,
}

impl LookupTraceBuilder {
    /// Starts the DMG/MBC3 relation from explicit externally authenticated roots.
    pub fn new_dmg_post_boot_mbc3(
        mut rom: Vec<u8>,
        memory: Vec<u8>,
        private_input: Vec<u8>,
        rom_root: CommitmentRoot,
        memory_root_anchor: CommitmentRoot,
    ) -> Result<Self, LookupTraceBuilderError> {
        if rom.is_empty() {
            return Err(LookupTraceBuilderError::EmptyRom);
        }
        if rom.len() > ROM_BYTES {
            return Err(LookupTraceBuilderError::RomTooLarge {
                actual: rom.len(),
                maximum: ROM_BYTES,
            });
        }
        if memory.len() != MEMORY_BYTES {
            return Err(LookupTraceBuilderError::MemoryLength {
                actual: memory.len(),
                expected: MEMORY_BYTES,
            });
        }
        rom.resize(ROM_BYTES, 0);
        Ok(Self {
            rom,
            memory,
            private_input,
            state: VmState::dmg_post_boot_mbc3_initial(rom_root, memory_root_anchor),
        })
    }

    /// Restores a lookup-backed boundary without rebuilding Merkle paths.
    ///
    /// The enclosing proof must authenticate `rom`, `memory`, and the state's
    /// fixed root anchors. This constructor checks structural dimensions,
    /// lookup-mode transcript invariants, and the already-consumed input prefix.
    pub fn resume_dmg_post_boot_mbc3(
        mut rom: Vec<u8>,
        memory: Vec<u8>,
        private_input: Vec<u8>,
        state: VmState,
    ) -> Result<Self, LookupTraceBuilderError> {
        if rom.is_empty() {
            return Err(LookupTraceBuilderError::EmptyRom);
        }
        if rom.len() > ROM_BYTES {
            return Err(LookupTraceBuilderError::RomTooLarge {
                actual: rom.len(),
                maximum: ROM_BYTES,
            });
        }
        if memory.len() != MEMORY_BYTES {
            return Err(LookupTraceBuilderError::MemoryLength {
                actual: memory.len(),
                expected: MEMORY_BYTES,
            });
        }
        if state.profile() != MachineProfile::DmgPostBootMbc3V1 {
            return Err(LookupTraceBuilderError::CheckpointProfileMismatch);
        }
        if state.bus_transcript().next_index() != 0 || state.isa_transcript().next_index() != 0 {
            return Err(LookupTraceBuilderError::CheckpointTranscriptNotEmpty);
        }
        validate_input_prefix(&private_input, state)?;
        rom.resize(ROM_BYTES, 0);
        Ok(Self {
            rom,
            memory,
            private_input,
            state,
        })
    }

    /// Returns the current lookup-backed VM boundary.
    #[must_use]
    pub const fn state(&self) -> VmState {
        self.state
    }

    /// Copies the complete 128-KiB mutable lookup table.
    #[must_use]
    pub fn checkpoint_memory(&self) -> Vec<u8> {
        self.memory.clone()
    }

    /// Copies the four physical MBC3 battery-SRAM banks in `.sav` order.
    pub fn battery_sram(&self) -> Result<Vec<u8>, LookupTraceBuilderError> {
        let end = BATTERY_SRAM_START
            .checked_add(BATTERY_SRAM_BYTES)
            .ok_or(LookupTraceBuilderError::AddressOverflow)?;
        self.memory
            .get(BATTERY_SRAM_START..end)
            .map(<[u8]>::to_vec)
            .ok_or(LookupTraceBuilderError::AddressOverflow)
    }

    /// Constructs and applies one lookup-backed relation row.
    pub fn step(&mut self) -> Result<TraceRow, LookupTraceBuilderError> {
        let before = self.state;
        let mut plan = Vec::with_capacity(MAX_WITNESSES_PER_STEP);
        loop {
            let input = self.materialize(&plan)?;
            match LookupStepRelation::apply(before, input) {
                Ok((after, effects)) => {
                    self.apply_memory_effects(&effects)?;
                    self.state = after;
                    return Ok(TraceRow::from_accepted(before, after, effects));
                }
                Err(StepError::MissingWitness { request }) => {
                    if plan.len() >= MAX_WITNESSES_PER_STEP {
                        return Err(LookupTraceBuilderError::WitnessBoundExceeded {
                            maximum: MAX_WITNESSES_PER_STEP,
                        });
                    }
                    plan.push(self.plan(request, &plan)?);
                }
                Err(error) => return Err(LookupTraceBuilderError::Step(error)),
            }
        }
    }

    /// Executes exactly `step_count` rows and retains their compact effects.
    pub fn run_exact_steps(&mut self, step_count: u64) -> Result<Witness, LookupTraceBuilderError> {
        let capacity =
            usize::try_from(step_count).map_err(|_| LookupTraceBuilderError::StepCountOverflow)?;
        let mut rows = Vec::with_capacity(capacity);
        let _boundary = self.execute_exact(step_count, |row| {
            rows.push(row);
            Ok(())
        })?;
        Witness::from_rows(rows).map_err(LookupTraceBuilderError::Trace)
    }

    /// Executes an exact prefix while retaining only its public state boundary.
    ///
    /// The returned state deliberately retains fixed lookup root anchors. The
    /// enclosing proof must separately bind the final `checkpoint_memory()`.
    pub fn run_exact_boundary(
        &mut self,
        step_count: u64,
    ) -> Result<ExecutionBoundary, LookupTraceBuilderError> {
        self.execute_exact(step_count, |_| Ok(()))
    }

    /// Executes an exact prefix while also accumulating a bounded PC histogram.
    pub fn run_exact_boundary_profiled(
        &mut self,
        step_count: u64,
    ) -> Result<(ExecutionBoundary, ProgramCounterProfile), LookupTraceBuilderError> {
        let mut profile = ProgramCounterProfile::default();
        let boundary = self.execute_exact(step_count, |row| {
            profile.record(&row).map_err(LookupTraceBuilderError::Trace)
        })?;
        Ok((boundary, profile))
    }

    /// Executes through the first accepted row satisfying a semantic milestone.
    pub fn run_until_boundary(
        &mut self,
        step_bound: u64,
        reached: impl FnMut(VmState) -> bool,
    ) -> Result<ExecutionBoundary, LookupTraceBuilderError> {
        self.execute_until(step_bound, reached, |_| Ok(()))
    }

    /// Executes to a milestone while retaining only a PC histogram and boundary.
    pub fn run_until_boundary_profiled(
        &mut self,
        step_bound: u64,
        reached: impl FnMut(VmState) -> bool,
    ) -> Result<(ExecutionBoundary, ProgramCounterProfile), LookupTraceBuilderError> {
        let mut profile = ProgramCounterProfile::default();
        let boundary = self.execute_until(step_bound, reached, |row| {
            profile.record(&row).map_err(LookupTraceBuilderError::Trace)
        })?;
        Ok((boundary, profile))
    }

    fn execute_exact(
        &mut self,
        step_count: u64,
        mut accept: impl FnMut(TraceRow) -> Result<(), LookupTraceBuilderError>,
    ) -> Result<ExecutionBoundary, LookupTraceBuilderError> {
        if step_count == 0 {
            return Err(LookupTraceBuilderError::ZeroStepChunk);
        }
        let initial_state = self.state;
        let mut metrics = ExecutionMetrics::default();
        for completed in 0..step_count {
            self.require_exact_row(completed, step_count)?;
            let row = self.exact_step(completed)?;
            metrics.record(&row)?;
            accept(row)?;
        }
        Ok(ExecutionBoundary::from_exact(
            initial_state,
            self.state,
            metrics,
        ))
    }

    fn execute_until(
        &mut self,
        step_bound: u64,
        mut reached: impl FnMut(VmState) -> bool,
        mut accept: impl FnMut(TraceRow) -> Result<(), LookupTraceBuilderError>,
    ) -> Result<ExecutionBoundary, LookupTraceBuilderError> {
        if step_bound == 0 {
            return Err(LookupTraceBuilderError::ZeroStepChunk);
        }
        let initial_state = self.state;
        let mut metrics = ExecutionMetrics::default();
        for completed in 0..step_bound {
            self.require_exact_row(completed, step_bound)?;
            let row = self.exact_step(completed)?;
            metrics.record(&row)?;
            accept(row)?;
            if reached(self.state) {
                return Ok(ExecutionBoundary::from_exact(
                    initial_state,
                    self.state,
                    metrics,
                ));
            }
        }
        Err(LookupTraceBuilderError::MilestoneNotReached {
            completed: step_bound,
        })
    }

    fn exact_step(&mut self, completed: u64) -> Result<TraceRow, LookupTraceBuilderError> {
        let pc = self.state.cpu().pc();
        self.step()
            .map_err(|source| LookupTraceBuilderError::ExactStepFailed {
                completed,
                pc,
                source: Box::new(source),
            })
    }

    fn require_exact_row(
        &self,
        completed: u64,
        requested: u64,
    ) -> Result<(), LookupTraceBuilderError> {
        let run_state = self.state.cpu().run_state();
        if run_state.can_execute_instruction() || run_state == RunState::Halted {
            return Ok(());
        }
        Err(LookupTraceBuilderError::TerminatedBeforeExactSteps {
            completed,
            requested,
            run_state,
        })
    }

    fn materialize(&self, plan: &[PlannedWitness]) -> Result<StepInput, LookupTraceBuilderError> {
        let mut witnesses = Vec::with_capacity(plan.len());
        for (index, planned) in plan.iter().enumerate() {
            let preceding = plan
                .get(..index)
                .ok_or(LookupTraceBuilderError::WitnessPlanInvariant)?;
            let witness = match *planned {
                PlannedWitness::Rom(address, physical_address) => BusWitness::Rom(RomRead {
                    address,
                    physical_address,
                    value: self.rom_byte(physical_address)?,
                    path: MerklePath::lookup_placeholder(),
                }),
                PlannedWitness::MemoryRead(address, physical_address) => {
                    let value = self.planned_memory_byte(preceding, physical_address)?;
                    BusWitness::MemoryRead(MemoryRead {
                        address,
                        physical_address,
                        value,
                        path: MerklePath::lookup_placeholder(),
                    })
                }
                PlannedWitness::MemoryWrite(address, physical_address, value) => {
                    let before = self.planned_memory_byte(preceding, physical_address)?;
                    BusWitness::MemoryWrite(MemoryWrite {
                        address,
                        physical_address,
                        before,
                        after: value,
                        path: MerklePath::lookup_placeholder(),
                    })
                }
                PlannedWitness::InputByte(value) => BusWitness::InputByte(value),
            };
            witnesses.push(witness);
        }
        Ok(StepInput::new(witnesses))
    }

    fn planned_memory_byte(
        &self,
        preceding: &[PlannedWitness],
        physical_address: u32,
    ) -> Result<u8, LookupTraceBuilderError> {
        preceding
            .iter()
            .rev()
            .find_map(|planned| match *planned {
                PlannedWitness::MemoryWrite(_, address, value) if address == physical_address => {
                    Some(value)
                }
                PlannedWitness::Rom(..)
                | PlannedWitness::MemoryRead(..)
                | PlannedWitness::MemoryWrite(..)
                | PlannedWitness::InputByte(_) => None,
            })
            .map_or_else(|| self.memory_byte(physical_address), Ok)
    }

    fn plan(
        &self,
        request: WitnessRequest,
        existing: &[PlannedWitness],
    ) -> Result<PlannedWitness, LookupTraceBuilderError> {
        match request {
            WitnessRequest::Rom {
                address,
                physical_address,
                ..
            } => Ok(PlannedWitness::Rom(address, physical_address)),
            WitnessRequest::MemoryRead {
                address,
                physical_address,
            } => Ok(PlannedWitness::MemoryRead(address, physical_address)),
            WitnessRequest::MemoryWrite {
                address,
                physical_address,
                value,
            } => Ok(PlannedWitness::MemoryWrite(
                address,
                physical_address,
                value,
            )),
            WitnessRequest::InputByte => {
                let prior_in_step = existing
                    .iter()
                    .filter(|planned| matches!(planned, PlannedWitness::InputByte(_)))
                    .count();
                let prior = u64::try_from(prior_in_step)
                    .map_err(|_| LookupTraceBuilderError::InputIndexOverflow)?;
                let index = self
                    .state
                    .input_log()
                    .next_index()
                    .checked_add(prior)
                    .ok_or(LookupTraceBuilderError::InputIndexOverflow)?;
                let position = usize::try_from(index)
                    .map_err(|_| LookupTraceBuilderError::InputIndexOverflow)?;
                let value = self
                    .private_input
                    .get(position)
                    .copied()
                    .ok_or(LookupTraceBuilderError::InputExhausted { index })?;
                Ok(PlannedWitness::InputByte(value))
            }
        }
    }

    fn apply_memory_effects(
        &mut self,
        effects: &zksm83_core::StepEffects,
    ) -> Result<(), LookupTraceBuilderError> {
        for event in effects.bus_events() {
            if let BusEvent::MemoryWrite(write) | BusEvent::DmgDmaWrite(write) = event {
                let before = self.memory_byte(write.physical_address)?;
                if before != write.before {
                    return Err(LookupTraceBuilderError::MemoryEffectDivergence);
                }
                set_byte(&mut self.memory, write.physical_address, write.after)?;
            }
        }
        Ok(())
    }

    fn rom_byte(&self, physical_address: u32) -> Result<u8, LookupTraceBuilderError> {
        byte(&self.rom, physical_address)
    }

    fn memory_byte(&self, physical_address: u32) -> Result<u8, LookupTraceBuilderError> {
        byte(&self.memory, physical_address)
    }
}

fn validate_input_prefix(
    private_input: &[u8],
    state: VmState,
) -> Result<(), LookupTraceBuilderError> {
    let provided = u64::try_from(private_input.len())
        .map_err(|_| LookupTraceBuilderError::InputIndexOverflow)?;
    let consumed = state.input_log().next_index();
    if consumed > provided {
        return Err(LookupTraceBuilderError::CheckpointInputTooShort { consumed, provided });
    }
    let consumed_length =
        usize::try_from(consumed).map_err(|_| LookupTraceBuilderError::InputIndexOverflow)?;
    let consumed_prefix = private_input
        .get(..consumed_length)
        .ok_or(LookupTraceBuilderError::CheckpointInputTooShort { consumed, provided })?;
    if LogAccumulator::commit(LogKind::Input, consumed_prefix)? != state.input_log() {
        return Err(LookupTraceBuilderError::CheckpointInputRootMismatch);
    }
    Ok(())
}

fn byte(bytes: &[u8], address: u32) -> Result<u8, LookupTraceBuilderError> {
    let index = usize::try_from(address).map_err(|_| LookupTraceBuilderError::AddressOverflow)?;
    bytes
        .get(index)
        .copied()
        .ok_or(LookupTraceBuilderError::PhysicalAddressOutOfRange { address })
}

fn set_byte(bytes: &mut [u8], address: u32, value: u8) -> Result<(), LookupTraceBuilderError> {
    let index = usize::try_from(address).map_err(|_| LookupTraceBuilderError::AddressOverflow)?;
    let target = bytes
        .get_mut(index)
        .ok_or(LookupTraceBuilderError::PhysicalAddressOutOfRange { address })?;
    *target = value;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlannedWitness {
    Rom(u16, u32),
    MemoryRead(u16, u32),
    MemoryWrite(u16, u32, u8),
    InputByte(u8),
}

/// Failure to execute the separately authenticated lookup-backed relation.
#[derive(Debug, Error)]
pub enum LookupTraceBuilderError {
    /// The immutable ROM cannot be empty.
    #[error("lookup ROM is empty")]
    EmptyRom,
    /// The ROM exceeds the fixed one-MiB MBC3 table.
    #[error("lookup ROM has {actual} bytes; maximum is {maximum}")]
    RomTooLarge {
        /// Supplied bytes.
        actual: usize,
        /// Fixed table maximum.
        maximum: usize,
    },
    /// Mutable memory must be the complete 128-KiB lookup table.
    #[error("lookup memory has {actual} bytes; expected {expected}")]
    MemoryLength {
        /// Supplied bytes.
        actual: usize,
        /// Fixed table length.
        expected: usize,
    },
    /// A physical ROM or memory address fell outside its table.
    #[error("lookup physical address 0x{address:05x} is outside its table")]
    PhysicalAddressOutOfRange {
        /// Rejected physical address.
        address: u32,
    },
    /// A host integer could not represent an address or step count.
    #[error("lookup execution integer conversion overflow")]
    AddressOverflow,
    /// The relation requested an input byte beyond the supplied schedule.
    #[error("lookup private input exhausted at index {index}")]
    InputExhausted {
        /// Missing zero-based input index.
        index: u64,
    },
    /// The input cursor could not advance safely.
    #[error("lookup private-input index overflow")]
    InputIndexOverflow,
    /// One row exceeded the fixed witness plan.
    #[error("lookup instruction exceeded maximum witness count {maximum}")]
    WitnessBoundExceeded {
        /// Fixed per-row witness maximum.
        maximum: usize,
    },
    /// An internal witness-plan prefix was not representable.
    #[error("lookup witness plan violated its bounded prefix invariant")]
    WitnessPlanInvariant,
    /// The pure transition relation rejected the byte-array witness.
    #[error(transparent)]
    Step(#[from] StepError),
    /// An accepted write disagreed with the backing byte array.
    #[error("lookup memory effect diverged from its backing table")]
    MemoryEffectDivergence,
    /// An exact chunk cannot be empty.
    #[error("lookup exact-step chunk cannot be empty")]
    ZeroStepChunk,
    /// The exact row count does not fit this platform.
    #[error("lookup exact-step count does not fit this platform")]
    StepCountOverflow,
    /// Restored state does not use the DMG post-boot/MBC3 profile.
    #[error("lookup checkpoint does not use the DMG post-boot MBC3 profile")]
    CheckpointProfileMismatch,
    /// Lookup-backed state must not carry legacy per-access transcripts.
    #[error("lookup checkpoint carries a non-empty legacy bus or ISA transcript")]
    CheckpointTranscriptNotEmpty,
    /// Checkpoint consumed more private input than the supplied log contains.
    #[error("checkpoint consumed {consumed} private-input bytes but only {provided} were supplied")]
    CheckpointInputTooShort {
        /// Input bytes already committed by the state.
        consumed: u64,
        /// Total input bytes available to resumed execution.
        provided: u64,
    },
    /// Supplied input prefix does not reproduce the checkpoint commitment.
    #[error("private-input prefix does not match the lookup checkpoint commitment")]
    CheckpointInputRootMismatch,
    /// Input-prefix commitment construction failed.
    #[error(transparent)]
    InputCommitment(#[from] LogError),
    /// STOP or another terminal state occurred before an exact boundary.
    #[error("VM became {run_state:?} after {completed} steps; exact chunk requested {requested}")]
    TerminatedBeforeExactSteps {
        /// Successfully completed relation rows.
        completed: u64,
        /// Requested relation rows.
        requested: u64,
        /// Terminal CPU state.
        run_state: RunState,
    },
    /// A bounded milestone was not reached.
    #[error("semantic lookup milestone was not reached after {completed} accepted rows")]
    MilestoneNotReached {
        /// Accepted relation-row count.
        completed: u64,
    },
    /// An exact row failed with its boundary attached.
    #[error("lookup exact chunk failed at step {completed}, PC 0x{pc:04x}: {source}")]
    ExactStepFailed {
        /// Successfully completed rows.
        completed: u64,
        /// Program counter before the failed row.
        pc: u16,
        /// Typed underlying construction failure.
        #[source]
        source: Box<LookupTraceBuilderError>,
    },
    /// Compact witness assembly failed.
    #[error(transparent)]
    Trace(#[from] TraceError),
}
