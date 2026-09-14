//! Prover adapter that answers core witness requests from committed images.

use thiserror::Error;
use zksm83_core::{
    BusEvent, BusWitness, MachineProfile, RunState, StepError, StepInput, StepRelation, VmState,
    WitnessRequest,
};
use zksm83_memory::{
    LogAccumulator, LogError, LogKind, MemoryImage, MemoryImageError, RomImage, RomImageError,
};

use crate::{
    ExecutionBoundary, ExecutionMetrics, ProgramCounterProfile, TraceError, TraceRow, Witness,
};

const MAX_WITNESSES_PER_STEP: usize = 5;

/// Deterministic witness constructor around the pure core relation.
pub struct TraceBuilder {
    rom: RomImage,
    memory: MemoryImage,
    private_input: Vec<u8>,
    state: VmState,
}

impl TraceBuilder {
    /// Starts execution at the fixed v1 initial CPU state.
    #[must_use]
    pub fn new(rom: RomImage, memory: MemoryImage, private_input: Vec<u8>) -> Self {
        let state = VmState::profile_initial(rom.root(), memory.root());
        Self {
            rom,
            memory,
            private_input,
            state,
        }
    }

    /// Starts execution at the canonical DMG post-boot MBC3 state.
    #[must_use]
    pub fn new_dmg_post_boot_mbc3(
        rom: RomImage,
        memory: MemoryImage,
        private_input: Vec<u8>,
    ) -> Self {
        let state = VmState::dmg_post_boot_mbc3_initial(rom.root(), memory.root());
        Self {
            rom,
            memory,
            private_input,
            state,
        }
    }

    /// Restores a validated trace boundary from committed ROM and memory images.
    pub fn resume(
        rom: RomImage,
        memory: MemoryImage,
        private_input: Vec<u8>,
        state: VmState,
    ) -> Result<Self, TraceBuilderError> {
        if state.rom_root() != rom.root() {
            return Err(TraceBuilderError::CheckpointRomRootMismatch);
        }
        if state.memory_root() != memory.root() {
            return Err(TraceBuilderError::CheckpointMemoryRootMismatch);
        }
        let provided = u64::try_from(private_input.len())
            .map_err(|_| TraceBuilderError::InputIndexOverflow)?;
        let consumed = state.input_log().next_index();
        if consumed > provided {
            return Err(TraceBuilderError::CheckpointInputTooShort { consumed, provided });
        }
        let consumed_length =
            usize::try_from(consumed).map_err(|_| TraceBuilderError::InputIndexOverflow)?;
        let consumed_prefix = private_input
            .get(..consumed_length)
            .ok_or(TraceBuilderError::CheckpointInputTooShort { consumed, provided })?;
        let committed_prefix = LogAccumulator::commit(LogKind::Input, consumed_prefix)?;
        if committed_prefix != state.input_log() {
            return Err(TraceBuilderError::CheckpointInputRootMismatch);
        }
        Ok(Self {
            rom,
            memory,
            private_input,
            state,
        })
    }

    /// Returns the current VM state.
    #[must_use]
    pub const fn state(&self) -> VmState {
        self.state
    }

    /// Copies the complete mutable image needed to resume from `state`.
    #[must_use]
    pub fn checkpoint_memory(&self) -> Vec<u8> {
        self.memory.checkpoint_bytes()
    }

    /// Copies all four physical MBC3 battery SRAM banks for an explicit save artifact.
    pub fn battery_sram(&self) -> Result<Vec<u8>, TraceBuilderError> {
        self.memory
            .battery_sram_bytes()
            .map_err(TraceBuilderError::Memory)
    }

    /// Constructs, validates, and applies one trace row.
    pub fn step(&mut self) -> Result<TraceRow, TraceBuilderError> {
        let before = self.state;
        let mut plan = Vec::with_capacity(MAX_WITNESSES_PER_STEP);
        loop {
            let input = self.materialize(&plan)?;
            match StepRelation::apply(before, input) {
                Ok((after, effects)) => {
                    self.apply_image_effects(&effects, after.memory_root())?;
                    self.state = after;
                    return Ok(TraceRow::from_accepted(before, after, effects));
                }
                Err(StepError::MissingWitness { request }) => {
                    if plan.len() >= MAX_WITNESSES_PER_STEP {
                        return Err(TraceBuilderError::WitnessBoundExceeded {
                            maximum: MAX_WITNESSES_PER_STEP,
                        });
                    }
                    plan.push(self.plan(request, &plan)?);
                }
                Err(error) => return Err(TraceBuilderError::Step(error)),
            }
        }
    }

    /// Executes until HALT or STOP, rejecting a still-running exact step bound.
    pub fn run(self, step_bound: u64) -> Result<Witness, TraceBuilderError> {
        let mut builder = self;
        let mut rows = Vec::new();
        for _ in 0..step_bound {
            if !builder.state.cpu().run_state().can_execute_instruction() {
                break;
            }
            rows.push(builder.step()?);
        }
        if builder.state.cpu().run_state() == RunState::Running {
            return Err(TraceBuilderError::StepBoundReached { step_bound });
        }
        let consumed = builder.state.input_log().next_index();
        let provided = u64::try_from(builder.private_input.len())
            .map_err(|_| TraceBuilderError::InputIndexOverflow)?;
        if consumed != provided {
            return Err(TraceBuilderError::UnconsumedInput { consumed, provided });
        }
        Witness::from_rows(rows).map_err(TraceBuilderError::Trace)
    }

    /// Executes exactly `step_count` instructions and permits a running final state.
    ///
    /// This is the chunk boundary used by IVC gameplay execution. It never
    /// treats reaching the requested prefix as a terminal-machine claim.
    pub fn run_exact_steps(&mut self, step_count: u64) -> Result<Witness, TraceBuilderError> {
        let mut rows = Vec::new();
        let _boundary = self.execute_exact(step_count, |row| {
            rows.push(row);
            Ok(())
        })?;
        Witness::from_rows(rows).map_err(TraceBuilderError::Trace)
    }

    /// Executes an exact prefix while retaining only its public boundary.
    ///
    /// Every row is still authenticated and accepted by the pure relation. The
    /// private row value is dropped immediately and therefore cannot later be
    /// used to construct a proof.
    pub fn run_exact_boundary(
        &mut self,
        step_count: u64,
    ) -> Result<ExecutionBoundary, TraceBuilderError> {
        self.execute_exact(step_count, |_| Ok(()))
    }

    /// Executes an exact prefix while retaining only its boundary and PC histogram.
    pub fn run_exact_boundary_profiled(
        &mut self,
        step_count: u64,
    ) -> Result<(ExecutionBoundary, ProgramCounterProfile), TraceBuilderError> {
        let mut profile = ProgramCounterProfile::default();
        let boundary = self.execute_exact(step_count, |row| {
            profile.record(&row).map_err(TraceBuilderError::Trace)
        })?;
        Ok((boundary, profile))
    }

    /// Executes until an accepted row reaches a semantic state milestone.
    ///
    /// `step_bound` is an explicit fail-closed upper bound. The predicate is
    /// evaluated only after a complete row has been authenticated and applied,
    /// so a returned boundary never represents a partial instruction or device
    /// transition.
    pub fn run_until_boundary(
        &mut self,
        step_bound: u64,
        reached: impl FnMut(VmState) -> bool,
    ) -> Result<ExecutionBoundary, TraceBuilderError> {
        self.execute_until(step_bound, reached, |_| Ok(()))
    }

    /// Executes to a semantic milestone while retaining its boundary and PC histogram.
    pub fn run_until_boundary_profiled(
        &mut self,
        step_bound: u64,
        reached: impl FnMut(VmState) -> bool,
    ) -> Result<(ExecutionBoundary, ProgramCounterProfile), TraceBuilderError> {
        let mut profile = ProgramCounterProfile::default();
        let boundary = self.execute_until(step_bound, reached, |row| {
            profile.record(&row).map_err(TraceBuilderError::Trace)
        })?;
        Ok((boundary, profile))
    }

    fn execute_until(
        &mut self,
        step_bound: u64,
        mut reached: impl FnMut(VmState) -> bool,
        mut accept: impl FnMut(TraceRow) -> Result<(), TraceBuilderError>,
    ) -> Result<ExecutionBoundary, TraceBuilderError> {
        if step_bound == 0 {
            return Err(TraceBuilderError::ZeroStepChunk);
        }
        let initial_state = self.state;
        let mut metrics = ExecutionMetrics::default();
        for completed in 0..step_bound {
            let run_state = self.state.cpu().run_state();
            self.require_exact_row(run_state, completed, step_bound)?;
            let pc = self.state.cpu().pc();
            let row = self
                .step()
                .map_err(|source| TraceBuilderError::ExactStepFailed {
                    completed,
                    pc,
                    source: Box::new(source),
                })?;
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
        Err(TraceBuilderError::MilestoneNotReached {
            completed: step_bound,
        })
    }

    fn execute_exact(
        &mut self,
        step_count: u64,
        mut accept: impl FnMut(TraceRow) -> Result<(), TraceBuilderError>,
    ) -> Result<ExecutionBoundary, TraceBuilderError> {
        if step_count == 0 {
            return Err(TraceBuilderError::ZeroStepChunk);
        }
        let initial_state = self.state;
        let mut metrics = ExecutionMetrics::default();
        for completed in 0..step_count {
            let run_state = self.state.cpu().run_state();
            self.require_exact_row(run_state, completed, step_count)?;
            let pc = self.state.cpu().pc();
            let row = self
                .step()
                .map_err(|source| TraceBuilderError::ExactStepFailed {
                    completed,
                    pc,
                    source: Box::new(source),
                })?;
            metrics.record(&row)?;
            accept(row)?;
        }
        Ok(ExecutionBoundary::from_exact(
            initial_state,
            self.state,
            metrics,
        ))
    }

    fn require_exact_row(
        &self,
        run_state: RunState,
        completed: u64,
        requested: u64,
    ) -> Result<(), TraceBuilderError> {
        if run_state.can_execute_instruction()
            || (self.state.profile() == MachineProfile::DmgPostBootMbc3V1
                && run_state == RunState::Halted)
        {
            return Ok(());
        }
        Err(TraceBuilderError::TerminatedBeforeExactSteps {
            completed,
            requested,
            run_state,
        })
    }

    fn materialize(&self, plan: &[PlannedWitness]) -> Result<StepInput, TraceBuilderError> {
        let mut fork = requires_memory_fork(plan).then(|| self.memory.fork());
        let mut witnesses = Vec::with_capacity(plan.len());
        for planned in plan {
            let witness = match *planned {
                PlannedWitness::Rom(address, physical_address) => {
                    BusWitness::Rom(self.rom.read_mapped(address, physical_address)?)
                }
                PlannedWitness::MemoryRead(address, physical_address) => {
                    let read = match fork.as_ref() {
                        Some(memory) => memory.read_mapped(address, physical_address)?,
                        None => self.memory.read_mapped(address, physical_address)?,
                    };
                    BusWitness::MemoryRead(read)
                }
                PlannedWitness::MemoryWrite(address, physical_address, value) => {
                    let write = match fork.as_mut() {
                        Some(memory) => memory.write_mapped(address, physical_address, value)?,
                        None => {
                            self.memory
                                .preview_write_mapped(address, physical_address, value)?
                        }
                    };
                    BusWitness::MemoryWrite(write)
                }
                PlannedWitness::InputByte(value) => BusWitness::InputByte(value),
            };
            witnesses.push(witness);
        }
        Ok(StepInput::new(witnesses))
    }

    fn plan(
        &self,
        request: WitnessRequest,
        existing: &[PlannedWitness],
    ) -> Result<PlannedWitness, TraceBuilderError> {
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
                    .map_err(|_| TraceBuilderError::InputIndexOverflow)?;
                let index = self
                    .state
                    .input_log()
                    .next_index()
                    .checked_add(prior)
                    .ok_or(TraceBuilderError::InputIndexOverflow)?;
                let position =
                    usize::try_from(index).map_err(|_| TraceBuilderError::InputIndexOverflow)?;
                let value = self
                    .private_input
                    .get(position)
                    .copied()
                    .ok_or(TraceBuilderError::InputExhausted { index })?;
                Ok(PlannedWitness::InputByte(value))
            }
        }
    }

    fn apply_image_effects(
        &mut self,
        effects: &zksm83_core::StepEffects,
        expected_root: zksm83_memory::CommitmentRoot,
    ) -> Result<(), TraceBuilderError> {
        for event in effects.bus_events() {
            if let BusEvent::MemoryWrite(expected) | BusEvent::DmgDmaWrite(expected) = event {
                let actual = self.memory.write_mapped(
                    expected.address,
                    expected.physical_address,
                    expected.after,
                )?;
                if &actual != expected {
                    return Err(TraceBuilderError::MemoryEffectDivergence);
                }
            }
        }
        if self.memory.root() != expected_root {
            return Err(TraceBuilderError::MemoryEffectDivergence);
        }
        Ok(())
    }
}

impl TraceBuilderError {
    /// Returns the number of rows accepted before an exact-prefix failure.
    #[must_use]
    pub const fn completed_exact_steps(&self) -> Option<u64> {
        match self {
            Self::TerminatedBeforeExactSteps { completed, .. }
            | Self::ExactStepFailed { completed, .. }
            | Self::MilestoneNotReached { completed } => Some(*completed),
            _ => None,
        }
    }
}

fn requires_memory_fork(plan: &[PlannedWitness]) -> bool {
    let mut write_seen = false;
    for planned in plan {
        match planned {
            PlannedWitness::MemoryWrite(..) if write_seen => return true,
            PlannedWitness::MemoryWrite(..) => write_seen = true,
            PlannedWitness::MemoryRead(..) if write_seen => return true,
            PlannedWitness::Rom(..)
            | PlannedWitness::MemoryRead(..)
            | PlannedWitness::InputByte(_) => {}
        }
    }
    false
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlannedWitness {
    Rom(u16, u32),
    MemoryRead(u16, u32),
    MemoryWrite(u16, u32, u8),
    InputByte(u8),
}

/// Failure to build a validated trace from committed images.
#[derive(Debug, Error)]
pub enum TraceBuilderError {
    /// The pure transition rejected a fully materialized step.
    #[error(transparent)]
    Step(#[from] StepError),
    /// ROM image could not produce a requested authentication witness.
    #[error(transparent)]
    Rom(#[from] RomImageError),
    /// Mutable image could not produce or apply a requested authentication witness.
    #[error(transparent)]
    Memory(#[from] MemoryImageError),
    /// Validated trace assembly failed.
    #[error(transparent)]
    Trace(#[from] TraceError),
    /// Execution remained running after the declared exact upper bound.
    #[error("VM remained running after step bound {step_bound}")]
    StepBoundReached {
        /// Exhausted step bound.
        step_bound: u64,
    },
    /// A non-empty witness is required for one IVC chunk.
    #[error("exact-step trace chunk cannot be empty")]
    ZeroStepChunk,
    /// HALT or STOP occurred before the requested exact chunk boundary.
    #[error("VM became {run_state:?} after {completed} steps; exact chunk requested {requested}")]
    TerminatedBeforeExactSteps {
        /// Successfully completed relation-row count.
        completed: u64,
        /// Requested exact relation-row count.
        requested: u64,
        /// Terminal CPU state encountered.
        run_state: RunState,
    },
    /// One exact-prefix relation row failed with its zero-based position attached.
    #[error("exact chunk failed at step {completed}, PC 0x{pc:04x}: {source}")]
    ExactStepFailed {
        /// Successfully completed relation-row count.
        completed: u64,
        /// PC before the failed relation row.
        pc: u16,
        /// Typed underlying construction failure.
        #[source]
        source: Box<TraceBuilderError>,
    },
    /// The accepted prefix exhausted its bound without reaching the predicate.
    #[error("semantic trace milestone was not reached after {completed} accepted rows")]
    MilestoneNotReached {
        /// Successfully completed relation-row count.
        completed: u64,
    },
    /// The private input log has no byte at the requested index.
    #[error("private input exhausted at index {index}")]
    InputExhausted {
        /// Missing zero-based input index.
        index: u64,
    },
    /// Input index cannot be represented or advanced safely.
    #[error("private input index overflow")]
    InputIndexOverflow,
    /// Checkpoint state does not bind the supplied ROM image.
    #[error("checkpoint ROM root does not match the supplied ROM")]
    CheckpointRomRootMismatch,
    /// Checkpoint state does not bind the supplied mutable-memory image.
    #[error("checkpoint memory root does not match its restored memory image")]
    CheckpointMemoryRootMismatch,
    /// Checkpoint consumed more private input than the supplied log contains.
    #[error("checkpoint consumed {consumed} private-input bytes but only {provided} were supplied")]
    CheckpointInputTooShort {
        /// Input bytes already committed by the checkpoint state.
        consumed: u64,
        /// Total private input bytes supplied for resumed execution.
        provided: u64,
    },
    /// Supplied private-input prefix does not reproduce the checkpoint input root.
    #[error("private-input prefix does not match the checkpoint input commitment")]
    CheckpointInputRootMismatch,
    /// Recomputing a checkpoint input prefix commitment failed.
    #[error(transparent)]
    CheckpointInputCommitment(#[from] LogError),
    /// Execution halted before consuming the complete declared private input.
    #[error("execution consumed {consumed} private-input bytes but {provided} were declared")]
    UnconsumedInput {
        /// Consumed prefix length.
        consumed: u64,
        /// Declared input length.
        provided: u64,
    },
    /// Instruction exceeded the model's bounded bus witness count.
    #[error("instruction exceeded maximum witness count {maximum}")]
    WitnessBoundExceeded {
        /// Fixed per-step witness maximum.
        maximum: usize,
    },
    /// Applying accepted write effects produced a different memory image.
    #[error("accepted memory write diverged from the prover image")]
    MemoryEffectDivergence,
}
