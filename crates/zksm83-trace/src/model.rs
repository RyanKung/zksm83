//! Validated trace rows, chunks, and complete witnesses.

use std::collections::BTreeMap;

use serde::Serialize;
use thiserror::Error;
use zksm83_core::{BusEvent, StepEffects, StepError, StepInput, StepKind, StepRelation, VmState};

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
    halt_until_serial_steps: u64,
    halt_until_serial_m_cycles: u64,
    halt_until_timer_steps: u64,
    halt_until_timer_m_cycles: u64,
    halt_wake_steps: u64,
    interrupt_dispatches: u64,
    dma_byte_steps: u64,
    bus_events: u64,
    rom_reads: u64,
    memory_reads: u64,
    memory_writes: u64,
    input_events: u64,
    output_events: u64,
    isa_rows: u64,
    joypad_samples: u64,
    battery_sram_writes: u64,
    dma_starts: u64,
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
#[derive(Debug, Default, Eq, PartialEq)]
pub struct ProgramCounterProfile {
    counts: BTreeMap<u32, u64>,
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
        let count = self.counts.entry(physical_pc).or_insert(0);
        increment(count)
    }

    /// Returns the most frequent instruction addresses, ordered by count then PC.
    #[must_use]
    pub fn top(&self, limit: usize) -> Vec<ProgramCounterCount> {
        let mut counts = self
            .counts
            .iter()
            .filter_map(|(&physical_pc, &count)| {
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
        increment(&mut self.isa_rows)?;
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
            StepKind::HaltUntilSerial => {
                increment(&mut self.halt_until_serial_steps)?;
                let elapsed = row
                    .after()
                    .cpu()
                    .m_cycles()
                    .checked_sub(row.before().cpu().m_cycles())
                    .ok_or(TraceError::CycleRegression)?;
                self.halt_until_serial_m_cycles = self
                    .halt_until_serial_m_cycles
                    .checked_add(elapsed)
                    .ok_or(TraceError::MetricOverflow)?;
            }
            StepKind::HaltUntilTimer => {
                increment(&mut self.halt_until_timer_steps)?;
                let elapsed = row
                    .after()
                    .cpu()
                    .m_cycles()
                    .checked_sub(row.before().cpu().m_cycles())
                    .ok_or(TraceError::CycleRegression)?;
                self.halt_until_timer_m_cycles = self
                    .halt_until_timer_m_cycles
                    .checked_add(elapsed)
                    .ok_or(TraceError::MetricOverflow)?;
            }
            StepKind::HaltWake => increment(&mut self.halt_wake_steps)?,
            StepKind::InterruptDispatch(_) => increment(&mut self.interrupt_dispatches)?,
            StepKind::DmaByte => increment(&mut self.dma_byte_steps)?,
        }
        self.record_bus_events(row)
    }

    fn record_bus_events(&mut self, row: &TraceRow) -> Result<(), TraceError> {
        for event in row.effects().bus_events() {
            increment(&mut self.bus_events)?;
            match event {
                BusEvent::OpcodeFetch(_)
                | BusEvent::ImmediateRead(_)
                | BusEvent::RomRead(_)
                | BusEvent::DmgDmaRomRead(_) => increment(&mut self.rom_reads)?,
                BusEvent::MemoryOpcodeFetch(_)
                | BusEvent::MemoryImmediateRead(_)
                | BusEvent::MemoryRead(_)
                | BusEvent::DmgDmaMemoryRead(_) => increment(&mut self.memory_reads)?,
                BusEvent::MemoryWrite(_) | BusEvent::DmgDmaWrite(_) => {
                    increment(&mut self.memory_writes)?
                }
                BusEvent::InputRead { .. } | BusEvent::DmgJoypadRead { .. } => {
                    increment(&mut self.input_events)?
                }
                BusEvent::OutputWrite { .. } => increment(&mut self.output_events)?,
                BusEvent::Mbc3ControlWrite { .. }
                | BusEvent::Mbc3OpenBusRead { .. }
                | BusEvent::Mbc3IgnoredWrite { .. }
                | BusEvent::DmgMmioRead { .. }
                | BusEvent::DmgMmioWrite { .. } => {}
            }
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

    /// Returns guarded long-HALT rows ending at serial completion.
    #[must_use]
    pub const fn halt_until_serial_steps(self) -> u64 {
        self.halt_until_serial_steps
    }

    /// Returns M-cycles compressed by guarded serial-completion HALT rows.
    #[must_use]
    pub const fn halt_until_serial_m_cycles(self) -> u64 {
        self.halt_until_serial_m_cycles
    }

    /// Returns guarded long-HALT rows ending at a timer reload interrupt.
    #[must_use]
    pub const fn halt_until_timer_steps(self) -> u64 {
        self.halt_until_timer_steps
    }

    /// Returns M-cycles compressed by guarded timer-interrupt HALT rows.
    #[must_use]
    pub const fn halt_until_timer_m_cycles(self) -> u64 {
        self.halt_until_timer_m_cycles
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

    /// Returns authenticated immutable-ROM reads, including instruction fetches.
    #[must_use]
    pub const fn rom_reads(self) -> u64 {
        self.rom_reads
    }

    /// Returns authenticated mutable-memory reads, including executable memory and DMA.
    #[must_use]
    pub const fn memory_reads(self) -> u64 {
        self.memory_reads
    }

    /// Returns authenticated mutable-memory writes, including DMA destinations.
    #[must_use]
    pub const fn memory_writes(self) -> u64 {
        self.memory_writes
    }

    /// Returns ordered private-input events, including joypad samples.
    #[must_use]
    pub const fn input_events(self) -> u64 {
        self.input_events
    }

    /// Returns ordered public-output events.
    #[must_use]
    pub const fn output_events(self) -> u64 {
        self.output_events
    }

    /// Returns fixed-ISA rows selected by active execution rows.
    #[must_use]
    pub const fn isa_rows(self) -> u64 {
        self.isa_rows
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

    pub(crate) fn into_rows(self) -> Vec<TraceRow> {
        let mut rows = Vec::new();
        for chunk in self.chunks {
            rows.extend(chunk.rows);
        }
        rows
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
    /// A validated row unexpectedly moved the hardware clock backwards.
    #[error("validated trace cycle count regressed")]
    CycleRegression,
}
