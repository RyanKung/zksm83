//! Validated trace rows, chunks, and complete witnesses.

use serde::Serialize;
use thiserror::Error;
use zksm83_core::{
    BLUE_SOUND_WAIT_ROM_ROOT, BusEvent, MachineProfile, RunState, StepEffects, StepError,
    StepInput, StepKind, StepRelation, VmState,
};

/// One instruction or zero-time machine transition validated by the pure relation.
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct TraceRow {
    before: VmState,
    after: VmState,
    effects: StepEffects,
}

impl TraceRow {
    /// Executes and records one validated instruction row.
    pub fn execute(before: VmState, input: StepInput) -> Result<Self, TraceError> {
        let (after, effects) = StepRelation::apply(before, input)?;
        Ok(Self {
            before,
            after,
            effects,
        })
    }

    pub(crate) const fn from_accepted(
        before: VmState,
        after: VmState,
        effects: StepEffects,
    ) -> Self {
        Self {
            before,
            after,
            effects,
        }
    }

    /// Returns the complete state before this instruction.
    #[must_use]
    pub const fn before(&self) -> VmState {
        self.before
    }

    /// Returns the complete state after this instruction.
    #[must_use]
    pub const fn after(&self) -> VmState {
        self.after
    }

    /// Returns decoded instruction and ordered bus effects.
    #[must_use]
    pub const fn effects(&self) -> &StepEffects {
        &self.effects
    }
}

/// Non-empty contiguous sequence of trace rows.
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct TraceChunk {
    rows: Vec<TraceRow>,
}

impl TraceChunk {
    /// Validates non-emptiness and exact state continuity.
    pub fn new(rows: Vec<TraceRow>) -> Result<Self, TraceError> {
        if rows.is_empty() {
            return Err(TraceError::EmptyChunk);
        }
        for (index, pair) in rows.windows(2).enumerate() {
            let before = pair.first().ok_or(TraceError::ChunkShapeInvariant)?;
            let after = pair.last().ok_or(TraceError::ChunkShapeInvariant)?;
            if before.after != after.before {
                return Err(TraceError::DiscontinuousRow { index });
            }
        }
        Ok(Self { rows })
    }

    /// Returns the first state in the chunk.
    pub fn initial_state(&self) -> Result<VmState, TraceError> {
        self.rows
            .first()
            .map(TraceRow::before)
            .ok_or(TraceError::EmptyChunk)
    }

    /// Returns the final state in the chunk.
    pub fn final_state(&self) -> Result<VmState, TraceError> {
        self.rows
            .last()
            .map(TraceRow::after)
            .ok_or(TraceError::EmptyChunk)
    }

    /// Returns rows in execution order.
    pub fn rows(&self) -> impl ExactSizeIterator<Item = &TraceRow> {
        self.rows.iter()
    }

    /// Returns row count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Returns whether the chunk is empty, which is always false for validated values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// Non-empty contiguous execution witness.
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct Witness {
    chunks: Vec<TraceChunk>,
    initial_state: VmState,
    final_state: VmState,
    step_count: u64,
}

/// Public boundary of an exact validated execution prefix without retained rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ExecutionBoundary {
    initial_state: VmState,
    final_state: VmState,
    step_count: u64,
    metrics: ExecutionMetrics,
}

/// Exact transition-family and selected-bus counts for one constructed prefix.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ExecutionMetrics {
    relation_steps: u64,
    instructions: u64,
    halt_idle_steps: u64,
    halt_idle_m_cycles: u64,
    halt_until_vblank_steps: u64,
    halt_until_vblank_m_cycles: u64,
    blue_sound_wait_steps: u64,
    blue_sound_wait_m_cycles: u64,
    blue_delay_loop_steps: u64,
    blue_delay_loop_iterations: u64,
    blue_delay_loop_m_cycles: u64,
    blue_dma_wait_steps: u64,
    blue_dma_wait_m_cycles: u64,
    blue_rom_block_steps: u64,
    blue_rom_block_instructions: u64,
    blue_rom_block_saved_rows: u64,
    #[serde(skip)]
    blue_rom_block_pending: u8,
    #[serde(skip)]
    blue_rom_block_pending_events: u8,
    #[serde(skip)]
    blue_rom_block_pending_m_cycles: u8,
    halt_wake_steps: u64,
    interrupt_dispatches: u64,
    dma_byte_steps: u64,
    bus_events: u64,
    joypad_samples: u64,
    battery_sram_writes: u64,
    dma_starts: u64,
    blue_quiet_boundary_violations: u64,
}

/// One instruction-address frequency in a profiled execution prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ProgramCounterCount {
    /// CPU program counter before the instruction.
    pub pc: u16,
    /// Selected ROM bank for cartridge code, or `None` for mutable execution space.
    pub rom_bank: Option<u8>,
    /// Physical ROM byte index, or `0x100000 + pc` for mutable execution space.
    pub physical_pc: u32,
    /// Number of accepted instruction rows at this address.
    pub count: u64,
}

/// Bounded 16-bit instruction-address histogram collected without retaining rows.
#[derive(Debug, Eq, PartialEq)]
pub struct ProgramCounterProfile {
    counts: Box<[u64]>,
}

impl Default for ProgramCounterProfile {
    fn default() -> Self {
        Self {
            counts: vec![0; (1_usize << 20) + (1_usize << 16)].into_boxed_slice(),
        }
    }
}

impl ProgramCounterProfile {
    pub(crate) fn record(&mut self, row: &TraceRow) -> Result<(), TraceError> {
        if row.effects().kind() != StepKind::Instruction {
            return Ok(());
        }
        let state = row.before();
        let pc = state.cpu().pc();
        let physical_pc = match pc {
            0x0000..=0x3fff => u32::from(pc),
            0x4000..=0x7fff => u32::from(state.mbc3().rom_bank()) * 0x4000 + u32::from(pc - 0x4000),
            0x8000..=0xffff => (1_u32 << 20) + u32::from(pc),
        };
        let index =
            usize::try_from(physical_pc).map_err(|_| TraceError::ProgramCounterProfileInvariant)?;
        let count = self
            .counts
            .get_mut(index)
            .ok_or(TraceError::ProgramCounterProfileInvariant)?;
        increment(count)
    }

    /// Returns the most frequent instruction addresses, ordered by count then PC.
    #[must_use]
    pub fn top(&self, limit: usize) -> Vec<ProgramCounterCount> {
        let mut counts = self
            .counts
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, count)| *count != 0)
            .filter_map(|(physical_pc, count)| {
                let physical_pc = u32::try_from(physical_pc).ok()?;
                if physical_pc < 1_u32 << 20 {
                    let bank = u8::try_from(physical_pc / 0x4000).ok()?;
                    let offset = u16::try_from(physical_pc % 0x4000).ok()?;
                    let pc = if bank == 0 { offset } else { 0x4000 + offset };
                    Some(ProgramCounterCount {
                        pc,
                        rom_bank: Some(bank),
                        physical_pc,
                        count,
                    })
                } else {
                    let pc = u16::try_from(physical_pc - (1_u32 << 20)).ok()?;
                    Some(ProgramCounterCount {
                        pc,
                        rom_bank: None,
                        physical_pc,
                        count,
                    })
                }
            })
            .collect::<Vec<_>>();
        counts.sort_unstable_by(|left, right| {
            right
                .count
                .cmp(&left.count)
                .then_with(|| left.physical_pc.cmp(&right.physical_pc))
        });
        counts.truncate(limit);
        counts
    }
}

impl ExecutionBoundary {
    pub(crate) const fn from_exact(
        initial_state: VmState,
        final_state: VmState,
        metrics: ExecutionMetrics,
    ) -> Self {
        Self {
            initial_state,
            final_state,
            step_count: metrics.relation_steps,
            metrics,
        }
    }

    /// Returns the state before the exact prefix.
    #[must_use]
    pub const fn initial_state(self) -> VmState {
        self.initial_state
    }

    /// Returns the state after the exact prefix.
    #[must_use]
    pub const fn final_state(self) -> VmState {
        self.final_state
    }

    /// Returns the number of validated relation rows in the prefix.
    #[must_use]
    pub const fn step_count(self) -> u64 {
        self.step_count
    }

    /// Returns exact row-family and selected-bus counts for the prefix.
    #[must_use]
    pub const fn metrics(self) -> ExecutionMetrics {
        self.metrics
    }
}

impl ExecutionMetrics {
    pub(crate) fn record(&mut self, row: &TraceRow) -> Result<(), TraceError> {
        increment(&mut self.relation_steps)?;
        self.record_blue_rom_block(row)?;
        if !blue_quiet_state(row.before()) || !blue_quiet_state(row.after()) {
            increment(&mut self.blue_quiet_boundary_violations)?;
        }
        match row.effects().kind() {
            StepKind::Instruction => increment(&mut self.instructions)?,
            StepKind::HaltIdle => {
                increment(&mut self.halt_idle_steps)?;
                let elapsed = row
                    .after()
                    .cpu()
                    .m_cycles()
                    .checked_sub(row.before().cpu().m_cycles())
                    .ok_or(TraceError::CycleRegression)?;
                self.halt_idle_m_cycles = self
                    .halt_idle_m_cycles
                    .checked_add(elapsed)
                    .ok_or(TraceError::MetricOverflow)?;
            }
            StepKind::HaltUntilVBlank => {
                increment(&mut self.halt_until_vblank_steps)?;
                let elapsed = row
                    .after()
                    .cpu()
                    .m_cycles()
                    .checked_sub(row.before().cpu().m_cycles())
                    .ok_or(TraceError::CycleRegression)?;
                self.halt_until_vblank_m_cycles = self
                    .halt_until_vblank_m_cycles
                    .checked_add(elapsed)
                    .ok_or(TraceError::MetricOverflow)?;
            }
            StepKind::BlueSoundWait => {
                increment(&mut self.blue_sound_wait_steps)?;
                let elapsed = row
                    .after()
                    .cpu()
                    .m_cycles()
                    .checked_sub(row.before().cpu().m_cycles())
                    .ok_or(TraceError::CycleRegression)?;
                self.blue_sound_wait_m_cycles = self
                    .blue_sound_wait_m_cycles
                    .checked_add(elapsed)
                    .ok_or(TraceError::MetricOverflow)?;
            }
            StepKind::BlueDelayLoop => {
                increment(&mut self.blue_delay_loop_steps)?;
                let before = row.before().cpu().registers();
                let after = row.after().cpu().registers();
                let iterations = u16::from_be_bytes([before.d, before.e])
                    .checked_sub(u16::from_be_bytes([after.d, after.e]))
                    .ok_or(TraceError::DelayIterationRegression)?;
                self.blue_delay_loop_iterations = self
                    .blue_delay_loop_iterations
                    .checked_add(u64::from(iterations))
                    .ok_or(TraceError::MetricOverflow)?;
                let elapsed = row
                    .after()
                    .cpu()
                    .m_cycles()
                    .checked_sub(row.before().cpu().m_cycles())
                    .ok_or(TraceError::CycleRegression)?;
                self.blue_delay_loop_m_cycles = self
                    .blue_delay_loop_m_cycles
                    .checked_add(elapsed)
                    .ok_or(TraceError::MetricOverflow)?;
            }
            StepKind::BlueDmaWait => {
                increment(&mut self.blue_dma_wait_steps)?;
                let elapsed = row
                    .after()
                    .cpu()
                    .m_cycles()
                    .checked_sub(row.before().cpu().m_cycles())
                    .ok_or(TraceError::CycleRegression)?;
                self.blue_dma_wait_m_cycles = self
                    .blue_dma_wait_m_cycles
                    .checked_add(elapsed)
                    .ok_or(TraceError::MetricOverflow)?;
            }
            StepKind::HaltWake => increment(&mut self.halt_wake_steps)?,
            StepKind::InterruptDispatch(_) => increment(&mut self.interrupt_dispatches)?,
            StepKind::DmaByte => increment(&mut self.dma_byte_steps)?,
        }
        for event in row.effects().bus_events() {
            increment(&mut self.bus_events)?;
            match event {
                BusEvent::DmgJoypadRead { .. } => increment(&mut self.joypad_samples)?,
                BusEvent::MemoryWrite(write)
                    if (0x1_0000..=0x1_7fff).contains(&write.physical_address) =>
                {
                    increment(&mut self.battery_sram_writes)?;
                }
                BusEvent::DmgMmioWrite {
                    address: 0xff46, ..
                } => {
                    increment(&mut self.dma_starts)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn record_blue_rom_block(&mut self, row: &TraceRow) -> Result<(), TraceError> {
        let Some(cost) = blue_rom_block_cost(row) else {
            self.reset_blue_rom_block_pending();
            return Ok(());
        };
        let can_append = self.blue_rom_block_pending < BLUE_ROM_BLOCK_MAX_INSTRUCTIONS
            && self
                .blue_rom_block_pending_events
                .checked_add(cost.events())
                .is_some_and(|events| events <= BLUE_ROM_BLOCK_MAX_EVENTS)
            && self
                .blue_rom_block_pending_m_cycles
                .checked_add(cost.m_cycles())
                .is_some_and(|cycles| cycles <= BLUE_ROM_BLOCK_MAX_M_CYCLES);
        if self.blue_rom_block_pending == 0 || !can_append {
            self.blue_rom_block_pending = 1;
            self.blue_rom_block_pending_events = cost.events();
            self.blue_rom_block_pending_m_cycles = cost.m_cycles();
            return Ok(());
        }
        self.blue_rom_block_pending = self
            .blue_rom_block_pending
            .checked_add(1)
            .ok_or(TraceError::MetricOverflow)?;
        self.blue_rom_block_pending_events = self
            .blue_rom_block_pending_events
            .checked_add(cost.events())
            .ok_or(TraceError::MetricOverflow)?;
        self.blue_rom_block_pending_m_cycles = self
            .blue_rom_block_pending_m_cycles
            .checked_add(cost.m_cycles())
            .ok_or(TraceError::MetricOverflow)?;
        if self.blue_rom_block_pending == 2 {
            increment(&mut self.blue_rom_block_steps)?;
            self.blue_rom_block_instructions = self
                .blue_rom_block_instructions
                .checked_add(2)
                .ok_or(TraceError::MetricOverflow)?;
            increment(&mut self.blue_rom_block_saved_rows)?;
        } else if self.blue_rom_block_pending <= BLUE_ROM_BLOCK_MAX_INSTRUCTIONS {
            increment(&mut self.blue_rom_block_instructions)?;
            increment(&mut self.blue_rom_block_saved_rows)?;
            if self.blue_rom_block_pending == BLUE_ROM_BLOCK_MAX_INSTRUCTIONS {
                self.reset_blue_rom_block_pending();
            }
        } else {
            return Err(TraceError::ProgramCounterProfileInvariant);
        }
        Ok(())
    }

    fn reset_blue_rom_block_pending(&mut self) {
        self.blue_rom_block_pending = 0;
        self.blue_rom_block_pending_events = 0;
        self.blue_rom_block_pending_m_cycles = 0;
    }

    /// Returns total native/circuit relation rows.
    #[must_use]
    pub const fn relation_steps(self) -> u64 {
        self.relation_steps
    }

    /// Returns decoded CPU instruction rows.
    #[must_use]
    pub const fn instructions(self) -> u64 {
        self.instructions
    }

    /// Returns ROM-bound Pokémon Blue sound-wait summary rows.
    #[must_use]
    pub const fn blue_sound_wait_steps(self) -> u64 {
        self.blue_sound_wait_steps
    }

    /// Returns M-cycles represented by Pokémon Blue sound-wait summaries.
    #[must_use]
    pub const fn blue_sound_wait_m_cycles(self) -> u64 {
        self.blue_sound_wait_m_cycles
    }

    /// Returns ROM-bound Pokémon Blue pure-delay summary rows.
    #[must_use]
    pub const fn blue_delay_loop_steps(self) -> u64 {
        self.blue_delay_loop_steps
    }

    /// Returns DE-loop iterations represented by Pokémon Blue delay summaries.
    #[must_use]
    pub const fn blue_delay_loop_iterations(self) -> u64 {
        self.blue_delay_loop_iterations
    }

    /// Returns M-cycles represented by Pokémon Blue delay summaries.
    #[must_use]
    pub const fn blue_delay_loop_m_cycles(self) -> u64 {
        self.blue_delay_loop_m_cycles
    }

    /// Returns authenticated Pokémon Blue HRAM DMA-wait summary rows.
    #[must_use]
    pub const fn blue_dma_wait_steps(self) -> u64 {
        self.blue_dma_wait_steps
    }

    /// Returns M-cycles represented by Pokémon Blue HRAM DMA-wait summaries.
    #[must_use]
    pub const fn blue_dma_wait_m_cycles(self) -> u64 {
        self.blue_dma_wait_m_cycles
    }

    /// Returns rows that each summarize two to five consecutive Blue ROM instructions.
    #[must_use]
    pub const fn blue_rom_block_steps(self) -> u64 {
        self.blue_rom_block_steps
    }

    /// Returns native instructions covered by safe Blue ROM micro-blocks.
    #[must_use]
    pub const fn blue_rom_block_instructions(self) -> u64 {
        self.blue_rom_block_instructions
    }

    /// Returns native relation rows removed by greedy two-to-five instruction packing.
    #[must_use]
    pub const fn blue_rom_block_saved_rows(self) -> u64 {
        self.blue_rom_block_saved_rows
    }

    /// Returns authenticated zero-time OAM DMA byte rows.
    #[must_use]
    pub const fn dma_byte_steps(self) -> u64 {
        self.dma_byte_steps
    }

    /// Returns all ordered bus events emitted by the accepted rows.
    #[must_use]
    pub const fn bus_events(self) -> u64 {
        self.bus_events
    }

    /// Returns committed P1 samples.
    #[must_use]
    pub const fn joypad_samples(self) -> u64 {
        self.joypad_samples
    }

    /// Returns authenticated writes into the four physical battery SRAM banks.
    #[must_use]
    pub const fn battery_sram_writes(self) -> u64 {
        self.battery_sram_writes
    }

    /// Returns rows whose before or after boundary cannot use BlueQuiet timing.
    #[must_use]
    pub const fn blue_quiet_boundary_violations(self) -> u64 {
        self.blue_quiet_boundary_violations
    }
}

/// Maximum number of native instructions represented by one Blue ROM micro-block.
pub const BLUE_ROM_BLOCK_MAX_INSTRUCTIONS: u8 = 5;
/// Maximum immutable fetch and safe read events authenticated by one Blue ROM micro-block.
pub const BLUE_ROM_BLOCK_MAX_EVENTS: u8 = 5;
/// Maximum aggregate M-cycles advanced by one Blue ROM micro-block.
pub const BLUE_ROM_BLOCK_MAX_M_CYCLES: u8 = 6;

/// Resource use of one native instruction eligible for Blue ROM micro-block packing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlueRomBlockCost {
    fetches: u8,
    data_reads: u8,
    events: u8,
    m_cycles: u8,
}

impl BlueRomBlockCost {
    /// Returns authenticated immutable-ROM fetches consumed by this instruction.
    #[must_use]
    pub const fn fetches(self) -> u8 {
        self.fetches
    }

    /// Returns authenticated ROM or timing-insensitive mutable-memory data reads.
    #[must_use]
    pub const fn data_reads(self) -> u8 {
        self.data_reads
    }

    /// Returns the total authenticated bus slots consumed by this instruction.
    #[must_use]
    pub const fn events(self) -> u8 {
        self.events
    }

    /// Returns M-cycles consumed by this instruction.
    #[must_use]
    pub const fn m_cycles(self) -> u8 {
        self.m_cycles
    }
}

/// Returns the bounded fetch and timing cost of an atomic Blue ROM micro-block candidate.
///
/// Candidates execute entirely from immutable ROM and may read only immutable ROM or
/// timing-insensitive WRAM, battery SRAM, or HRAM. They keep IME and the running state unchanged
/// and do not raise an interrupt. A block may contain at most five such instructions while
/// consuming at most five authenticated events and six M-cycles. MMIO, mapper, input, write,
/// VRAM, and OAM effects remain atomic rows so timing is additive and no hidden device boundary
/// is lost between packed rows.
#[must_use]
pub fn blue_rom_block_cost(row: &TraceRow) -> Option<BlueRomBlockCost> {
    let before = row.before();
    let after = row.after();
    let elapsed = u8::try_from(
        after
            .cpu()
            .m_cycles()
            .checked_sub(before.cpu().m_cycles())?,
    )
    .ok()?;
    let events = row.effects().bus_events();
    let event_count = u8::try_from(events.len()).ok()?;
    let mut fetches = 0_u8;
    let mut data_reads = 0_u8;
    let mut saw_data = false;
    let mut allowed_events = true;
    for event in events {
        match event {
            BusEvent::OpcodeFetch(_) | BusEvent::ImmediateRead(_) if !saw_data => {
                fetches = fetches.checked_add(1)?;
            }
            BusEvent::RomRead(_) => {
                saw_data = true;
                data_reads = data_reads.checked_add(1)?;
            }
            BusEvent::MemoryRead(read) if blue_rom_block_memory_read(read.address) => {
                saw_data = true;
                data_reads = data_reads.checked_add(1)?;
            }
            _ => allowed_events = false,
        }
    }
    let first_is_opcode = matches!(
        row.effects().bus_events().next(),
        Some(BusEvent::OpcodeFetch(_))
    );
    let eligible = row.effects().kind() == StepKind::Instruction
        && fetches == row.effects().instruction().byte_len()
        && first_is_opcode
        && allowed_events
        && blue_rom_block_state(before)
        && blue_rom_block_state(after)
        && before.cpu().run_state() == RunState::Running
        && after.cpu().run_state() == RunState::Running
        && before.cpu().ime() == after.cpu().ime()
        && before.dmg_devices().interrupt_request() == after.dmg_devices().interrupt_request()
        && (1..=BLUE_ROM_BLOCK_MAX_EVENTS).contains(&event_count)
        && (1..=BLUE_ROM_BLOCK_MAX_M_CYCLES).contains(&elapsed);
    eligible.then_some(BlueRomBlockCost {
        fetches,
        data_reads,
        events: event_count,
        m_cycles: elapsed,
    })
}

fn blue_rom_block_memory_read(address: u16) -> bool {
    matches!(address, 0xa000..=0xdfff | 0xff80..=0xfffe)
}

/// Returns whether an atomic Blue instruction can share a bounded summary row with adjacent rows.
#[must_use]
pub fn blue_rom_block_candidate(row: &TraceRow) -> bool {
    blue_rom_block_cost(row).is_some()
}

fn blue_rom_block_state(state: VmState) -> bool {
    state.profile() == MachineProfile::DmgPostBootMbc3V1
        && state.dmg_devices().blue_quiet_proof_compatible()
}

fn blue_quiet_state(state: VmState) -> bool {
    state.profile() == MachineProfile::DmgPostBootMbc3V1
        && state.rom_root().to_bytes() == BLUE_SOUND_WAIT_ROM_ROOT
        && state.dmg_devices().blue_quiet_proof_compatible()
}

fn increment(value: &mut u64) -> Result<(), TraceError> {
    *value = value.checked_add(1).ok_or(TraceError::MetricOverflow)?;
    Ok(())
}

impl Witness {
    /// Validates chunk continuity and checked total step count.
    pub fn new(chunks: Vec<TraceChunk>) -> Result<Self, TraceError> {
        let first = chunks.first().ok_or(TraceError::EmptyWitness)?;
        let last = chunks.last().ok_or(TraceError::EmptyWitness)?;
        for (index, pair) in chunks.windows(2).enumerate() {
            let before = pair.first().ok_or(TraceError::WitnessShapeInvariant)?;
            let after = pair.last().ok_or(TraceError::WitnessShapeInvariant)?;
            if before.final_state()? != after.initial_state()? {
                return Err(TraceError::DiscontinuousChunk { index });
            }
        }
        let step_count = chunks.iter().try_fold(0_u64, |total, chunk| {
            let chunk_len =
                u64::try_from(chunk.len()).map_err(|_| TraceError::StepCountOverflow)?;
            total
                .checked_add(chunk_len)
                .ok_or(TraceError::StepCountOverflow)
        })?;
        Ok(Self {
            initial_state: first.initial_state()?,
            final_state: last.final_state()?,
            chunks,
            step_count,
        })
    }

    /// Wraps a row sequence in one validated chunk and witness.
    pub fn from_rows(rows: Vec<TraceRow>) -> Result<Self, TraceError> {
        Self::new(vec![TraceChunk::new(rows)?])
    }

    /// Returns the first VM state.
    #[must_use]
    pub const fn initial_state(&self) -> VmState {
        self.initial_state
    }

    /// Returns the final VM state.
    #[must_use]
    pub const fn final_state(&self) -> VmState {
        self.final_state
    }

    /// Returns exact relation-row count.
    #[must_use]
    pub const fn step_count(&self) -> u64 {
        self.step_count
    }

    /// Iterates over every row in execution order.
    pub fn rows(&self) -> impl Iterator<Item = &TraceRow> {
        self.chunks.iter().flat_map(TraceChunk::rows)
    }

    /// Returns validated chunks.
    pub fn chunks(&self) -> impl ExactSizeIterator<Item = &TraceChunk> {
        self.chunks.iter()
    }
}

/// Failure to construct a validated trace object.
#[derive(Debug, Error)]
pub enum TraceError {
    /// The pure instruction relation rejected a row.
    #[error(transparent)]
    Step(#[from] StepError),
    /// A trace chunk must contain at least one row.
    #[error("trace chunk is empty")]
    EmptyChunk,
    /// Adjacent rows do not share an identical boundary state.
    #[error("trace rows around index {index} are discontinuous")]
    DiscontinuousRow {
        /// Index of the first row in the rejected pair.
        index: usize,
    },
    /// A non-empty row window violated its fixed two-element shape.
    #[error("trace row window violated its fixed shape")]
    ChunkShapeInvariant,
    /// A witness must contain at least one chunk.
    #[error("execution witness is empty")]
    EmptyWitness,
    /// Adjacent chunks do not share an identical boundary state.
    #[error("trace chunks around index {index} are discontinuous")]
    DiscontinuousChunk {
        /// Index of the first chunk in the rejected pair.
        index: usize,
    },
    /// A non-empty chunk window violated its fixed two-element shape.
    #[error("trace chunk window violated its fixed shape")]
    WitnessShapeInvariant,
    /// Total relation-step count overflowed `u64`.
    #[error("trace step count overflow")]
    StepCountOverflow,
    /// An exact execution metric exceeded the `u64` representation.
    #[error("execution metric overflow")]
    MetricOverflow,
    /// The fixed 16-bit PC histogram did not contain a valid CPU address.
    #[error("program-counter profile violated its 16-bit shape")]
    ProgramCounterProfileInvariant,
    /// A validated row unexpectedly moved the hardware clock backwards.
    #[error("validated trace cycle count regressed")]
    CycleRegression,
    /// A Blue delay summary increased its remaining DE iteration count.
    #[error("validated Blue delay summary iteration count regressed")]
    DelayIterationRegression,
}
