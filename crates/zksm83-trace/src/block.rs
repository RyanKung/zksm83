//! Generic planning for bounded packed-instruction relation rows.

use serde::Serialize;
use thiserror::Error;
use zksm83_core::{BusEventKind, ImeState, StepKind, VmState};
use zksm83_isa::Operation;

use crate::{TraceRow, Witness};

/// Universal maximum number of decoded instructions admitted to one planned block.
pub const BASIC_BLOCK_INSTRUCTION_BOUND: usize = 4;

/// Maximum aggregate machine cycles admitted to one planned instruction block.
pub const BASIC_BLOCK_M_CYCLE_BOUND: usize = 6;

/// Maximum aggregate ordered bus events admitted to one planned instruction block.
pub const BASIC_BLOCK_BUS_EVENT_BOUND: usize = 5;

/// Auditable reason that a planned block cannot absorb the following trace row.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum BasicBlockCut {
    /// The universal instruction-lane bound was reached.
    InstructionBound,
    /// Adding the next instruction would exceed the shared device-step cycle budget.
    CycleBound,
    /// Adding the next instruction would exceed the shared ordered-bus-slot budget.
    BusEventBound,
    /// The validated input trace ended.
    EndOfTrace,
    /// A jump, call, return, restart, or other PC-changing operation ended the block.
    ControlFlow,
    /// HALT or STOP changed the CPU run state.
    LowPower,
    /// An instruction changed interrupt-master-enable semantics.
    InterruptControl,
    /// An enabled interrupt is pending before the next row.
    InterruptPending,
    /// A typed timer, PPU, serial, APU, joypad, or DMA-control register was accessed.
    DeviceIo,
    /// A VRAM or OAM access depends on the PPU mode at this instruction boundary.
    PpuSensitiveMemory,
    /// A private-input or public-output port was accessed.
    ProtocolIo,
    /// Cartridge mapper state changed.
    MapperChange,
    /// An opcode or immediate was fetched from mutable executable memory.
    MutableExecution,
    /// An explicit interrupt, HALT-idle, long-event, wake, or DMA row forms its own span.
    MachineEvent,
}

/// One contiguous span in a generic basic-block plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct BasicBlockSpan {
    row_start: usize,
    row_count: usize,
    instruction_count: usize,
    m_cycle_count: u64,
    bus_event_count: usize,
    cut: BasicBlockCut,
}

/// Owned, non-empty group of accepted rows prepared for one future packed relation row.
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct BasicBlock {
    source_row_start: usize,
    rows: Vec<TraceRow>,
    instruction_count: usize,
    m_cycle_count: u64,
    bus_event_count: usize,
    cut: BasicBlockCut,
    initial_state: VmState,
    final_state: VmState,
    lanes: [BasicBlockLane; BASIC_BLOCK_INSTRUCTION_BOUND],
    m_cycle_owners: [BasicBlockResourceOwner; BASIC_BLOCK_M_CYCLE_BOUND],
    bus_event_owners: [BasicBlockResourceOwner; BASIC_BLOCK_BUS_EVENT_BOUND],
}

/// One canonical instruction lane or explicit inactive padding lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum BasicBlockLane {
    /// No instruction occupies this suffix lane.
    Padding,
    /// One accepted instruction occupies this lane.
    Instruction(BasicBlockLaneDescriptor),
}

/// Exact source, cycle, and shared-bus interval assigned to one instruction lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct BasicBlockLaneDescriptor {
    source_row_index: usize,
    m_cycle_start: u64,
    m_cycle_count: u64,
    bus_event_start: usize,
    bus_event_count: usize,
}

/// Typed zero-based index of one of the four instruction lanes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum BasicBlockLaneIndex {
    /// First instruction lane.
    Lane0,
    /// Second instruction lane.
    Lane1,
    /// Third instruction lane.
    Lane2,
    /// Fourth instruction lane.
    Lane3,
}

/// Canonical owner of one shared cycle or bus-event resource slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum BasicBlockResourceOwner {
    /// Unused canonical suffix slot.
    Padding,
    /// Slot consumed by one instruction lane.
    Instruction(BasicBlockLaneIndex),
}

struct BasicBlockRouting {
    lanes: [BasicBlockLane; BASIC_BLOCK_INSTRUCTION_BOUND],
    m_cycle_owners: [BasicBlockResourceOwner; BASIC_BLOCK_M_CYCLE_BOUND],
    bus_event_owners: [BasicBlockResourceOwner; BASIC_BLOCK_BUS_EVENT_BOUND],
}

impl BasicBlockLaneIndex {
    const fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(Self::Lane0),
            1 => Some(Self::Lane1),
            2 => Some(Self::Lane2),
            3 => Some(Self::Lane3),
            _ => None,
        }
    }

    /// Returns the stable zero-based lane index.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Lane0 => 0,
            Self::Lane1 => 1,
            Self::Lane2 => 2,
            Self::Lane3 => 3,
        }
    }
}

impl BasicBlockLane {
    /// Returns whether this lane contains an accepted instruction.
    #[must_use]
    pub const fn is_instruction(self) -> bool {
        matches!(self, Self::Instruction(_))
    }

    /// Returns the instruction descriptor, or `None` for canonical padding.
    #[must_use]
    pub const fn descriptor(self) -> Option<BasicBlockLaneDescriptor> {
        match self {
            Self::Padding => None,
            Self::Instruction(descriptor) => Some(descriptor),
        }
    }
}

impl BasicBlockLaneDescriptor {
    /// Returns the source trace-row index assigned to this lane.
    #[must_use]
    pub const fn source_row_index(self) -> usize {
        self.source_row_index
    }

    /// Returns the first shared device M-cycle assigned to this lane.
    #[must_use]
    pub const fn m_cycle_start(self) -> u64 {
        self.m_cycle_start
    }

    /// Returns the number of shared device M-cycles assigned to this lane.
    #[must_use]
    pub const fn m_cycle_count(self) -> u64 {
        self.m_cycle_count
    }

    /// Returns the first shared ordered bus-event slot assigned to this lane.
    #[must_use]
    pub const fn bus_event_start(self) -> usize {
        self.bus_event_start
    }

    /// Returns the number of shared ordered bus-event slots assigned to this lane.
    #[must_use]
    pub const fn bus_event_count(self) -> usize {
        self.bus_event_count
    }
}
impl BasicBlock {
    /// Returns the first source trace-row index.
    #[must_use]
    pub const fn source_row_start(&self) -> usize {
        self.source_row_start
    }

    /// Returns accepted source rows in execution order.
    pub fn rows(&self) -> impl ExactSizeIterator<Item = &TraceRow> {
        self.rows.iter()
    }

    /// Returns the number of accepted source rows.
    #[must_use]
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Returns decoded instructions; explicit machine-event blocks return zero.
    #[must_use]
    pub const fn instruction_count(&self) -> usize {
        self.instruction_count
    }

    /// Returns the exact aggregate machine-cycle delta.
    #[must_use]
    pub const fn m_cycle_count(&self) -> u64 {
        self.m_cycle_count
    }

    /// Returns the exact aggregate ordered bus-event count.
    #[must_use]
    pub const fn bus_event_count(&self) -> usize {
        self.bus_event_count
    }

    /// Returns why the block ended.
    #[must_use]
    pub const fn cut(&self) -> BasicBlockCut {
        self.cut
    }

    /// Returns the exact state before the first source row.
    #[must_use]
    pub const fn initial_state(&self) -> VmState {
        self.initial_state
    }

    /// Returns the exact state after the last source row.
    #[must_use]
    pub const fn final_state(&self) -> VmState {
        self.final_state
    }

    /// Returns the fixed four-lane schedule, including canonical suffix padding.
    #[must_use]
    pub const fn lanes(&self) -> &[BasicBlockLane; BASIC_BLOCK_INSTRUCTION_BOUND] {
        &self.lanes
    }

    /// Returns the fixed ownership of all six shared instruction M-cycle slots.
    #[must_use]
    pub const fn m_cycle_owners(&self) -> &[BasicBlockResourceOwner; BASIC_BLOCK_M_CYCLE_BOUND] {
        &self.m_cycle_owners
    }

    /// Returns the fixed ownership of all five shared ordered bus-event slots.
    #[must_use]
    pub const fn bus_event_owners(
        &self,
    ) -> &[BasicBlockResourceOwner; BASIC_BLOCK_BUS_EVENT_BOUND] {
        &self.bus_event_owners
    }
}

impl BasicBlockSpan {
    /// Returns the first source trace-row index.
    #[must_use]
    pub const fn row_start(self) -> usize {
        self.row_start
    }

    /// Returns the number of source rows covered by this span.
    #[must_use]
    pub const fn row_count(self) -> usize {
        self.row_count
    }

    /// Returns decoded instructions in this span; machine-event spans return zero.
    #[must_use]
    pub const fn instruction_count(self) -> usize {
        self.instruction_count
    }

    /// Returns the exact aggregate machine-cycle delta covered by this span.
    #[must_use]
    pub const fn m_cycle_count(self) -> u64 {
        self.m_cycle_count
    }

    /// Returns the exact aggregate ordered bus-event count covered by this span.
    #[must_use]
    pub const fn bus_event_count(self) -> usize {
        self.bus_event_count
    }

    /// Returns why the span ended.
    #[must_use]
    pub const fn cut(self) -> BasicBlockCut {
        self.cut
    }
}

/// A supplied row slice is not a contiguous accepted execution.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BasicBlockPlanError {
    /// Adjacent rows disagree on their exact semantic boundary.
    #[error("basic-block input is discontinuous after row {index}")]
    Discontinuous {
        /// Index of the row before the broken boundary.
        index: usize,
    },
    /// A validated row regressed or overflowed an execution resource counter.
    #[error("basic-block resource accounting failed at row {index}")]
    ResourceAccounting {
        /// Index of the row with inconsistent resource accounting.
        index: usize,
    },
    /// An internally generated span did not partition the consumed witness exactly.
    #[error("basic-block owned partition violated its span invariant")]
    PartitionInvariant,
}

/// Partitions validated rows into universal bounded instruction spans and explicit machine rows.
///
/// This planner does not replace proof rows. It establishes the deterministic cut policy that a
/// later packed-lane relation must enforce while preserving every source transition.
pub fn plan_basic_blocks(rows: &[TraceRow]) -> Result<Vec<BasicBlockSpan>, BasicBlockPlanError> {
    plan_indexed(rows.len(), |index| rows.get(index))
}

/// Plans every row in a validated witness, including boundaries between its chunks.
///
/// This proof-free convenience path retains only row references while planning;
/// it does not clone state, effects, or bus events.
pub fn plan_witness_basic_blocks(
    witness: &Witness,
) -> Result<Vec<BasicBlockSpan>, BasicBlockPlanError> {
    let rows = witness.rows().collect::<Vec<_>>();
    plan_indexed(rows.len(), |index| rows.get(index).copied())
}

/// Consumes a validated witness and moves its rows into owned bounded blocks.
///
/// No row, state, bus event, or authentication path is cloned. This is the
/// proof-free ownership boundary intended for a future packed trace encoder.
pub fn pack_witness_basic_blocks(witness: Witness) -> Result<Vec<BasicBlock>, BasicBlockPlanError> {
    pack_witness_basic_blocks_at(witness, 0)
}

/// Consumes a validated witness and rebases its diagnostic source-row indices.
///
/// This is used when one packed segment is filled from several bounded witness
/// chunks. The offset does not affect relation semantics, but preserves exact
/// source-row provenance across chunk boundaries.
pub fn pack_witness_basic_blocks_at(
    witness: Witness,
    source_row_offset: usize,
) -> Result<Vec<BasicBlock>, BasicBlockPlanError> {
    let spans = plan_witness_basic_blocks(&witness)?;
    let mut rows = witness.into_rows().into_iter();
    let mut blocks = Vec::with_capacity(spans.len());
    for span in spans {
        let block_rows = rows.by_ref().take(span.row_count()).collect::<Vec<_>>();
        let first = block_rows
            .first()
            .ok_or(BasicBlockPlanError::PartitionInvariant)?;
        let last = block_rows
            .last()
            .ok_or(BasicBlockPlanError::PartitionInvariant)?;
        if block_rows.len() != span.row_count() {
            return Err(BasicBlockPlanError::PartitionInvariant);
        }
        let routing = block_routing(&block_rows, span, source_row_offset)?;
        let source_row_start = source_row_offset
            .checked_add(span.row_start())
            .ok_or(BasicBlockPlanError::PartitionInvariant)?;
        blocks.push(BasicBlock {
            source_row_start,
            instruction_count: span.instruction_count(),
            m_cycle_count: span.m_cycle_count(),
            bus_event_count: span.bus_event_count(),
            cut: span.cut(),
            initial_state: first.before(),
            final_state: last.after(),
            lanes: routing.lanes,
            m_cycle_owners: routing.m_cycle_owners,
            bus_event_owners: routing.bus_event_owners,
            rows: block_rows,
        });
    }
    if rows.next().is_some() {
        return Err(BasicBlockPlanError::PartitionInvariant);
    }
    Ok(blocks)
}

fn block_routing(
    rows: &[TraceRow],
    span: BasicBlockSpan,
    source_row_offset: usize,
) -> Result<BasicBlockRouting, BasicBlockPlanError> {
    let mut lanes = [BasicBlockLane::Padding; BASIC_BLOCK_INSTRUCTION_BOUND];
    let mut m_cycle_owners = [BasicBlockResourceOwner::Padding; BASIC_BLOCK_M_CYCLE_BOUND];
    let mut bus_event_owners = [BasicBlockResourceOwner::Padding; BASIC_BLOCK_BUS_EVENT_BOUND];
    if span.instruction_count() == 0 {
        if rows.len() != 1
            || rows
                .first()
                .is_none_or(|row| row.effects().kind() == StepKind::Instruction)
        {
            return Err(BasicBlockPlanError::PartitionInvariant);
        }
        return Ok(BasicBlockRouting {
            lanes,
            m_cycle_owners,
            bus_event_owners,
        });
    }
    if rows.len() != span.instruction_count() || rows.len() > BASIC_BLOCK_INSTRUCTION_BOUND {
        return Err(BasicBlockPlanError::PartitionInvariant);
    }
    let mut m_cycle_start = 0_u64;
    let mut bus_event_start = 0_usize;
    for (lane_index, row) in rows.iter().enumerate() {
        if row.effects().kind() != StepKind::Instruction {
            return Err(BasicBlockPlanError::PartitionInvariant);
        }
        let source_row_index = span
            .row_start()
            .checked_add(lane_index)
            .and_then(|index| source_row_offset.checked_add(index))
            .ok_or(BasicBlockPlanError::PartitionInvariant)?;
        let (m_cycle_count, bus_event_count) = row_resources(row, source_row_index)?;
        let typed_lane = BasicBlockLaneIndex::from_index(lane_index)
            .ok_or(BasicBlockPlanError::PartitionInvariant)?;
        let lane = lanes
            .get_mut(lane_index)
            .ok_or(BasicBlockPlanError::PartitionInvariant)?;
        *lane = BasicBlockLane::Instruction(BasicBlockLaneDescriptor {
            source_row_index,
            m_cycle_start,
            m_cycle_count,
            bus_event_start,
            bus_event_count,
        });
        let cycle_start =
            usize::try_from(m_cycle_start).map_err(|_| BasicBlockPlanError::PartitionInvariant)?;
        let cycle_count =
            usize::try_from(m_cycle_count).map_err(|_| BasicBlockPlanError::PartitionInvariant)?;
        let cycle_end = cycle_start
            .checked_add(cycle_count)
            .ok_or(BasicBlockPlanError::PartitionInvariant)?;
        m_cycle_owners
            .get_mut(cycle_start..cycle_end)
            .ok_or(BasicBlockPlanError::PartitionInvariant)?
            .fill(BasicBlockResourceOwner::Instruction(typed_lane));
        let bus_event_end = bus_event_start
            .checked_add(bus_event_count)
            .ok_or(BasicBlockPlanError::PartitionInvariant)?;
        bus_event_owners
            .get_mut(bus_event_start..bus_event_end)
            .ok_or(BasicBlockPlanError::PartitionInvariant)?
            .fill(BasicBlockResourceOwner::Instruction(typed_lane));
        m_cycle_start = m_cycle_start
            .checked_add(m_cycle_count)
            .ok_or(BasicBlockPlanError::PartitionInvariant)?;
        bus_event_start = bus_event_start
            .checked_add(bus_event_count)
            .ok_or(BasicBlockPlanError::PartitionInvariant)?;
    }
    if m_cycle_start != span.m_cycle_count() || bus_event_start != span.bus_event_count() {
        return Err(BasicBlockPlanError::PartitionInvariant);
    }
    Ok(BasicBlockRouting {
        lanes,
        m_cycle_owners,
        bus_event_owners,
    })
}

fn plan_indexed<'a>(
    row_count: usize,
    row_at: impl Copy + Fn(usize) -> Option<&'a TraceRow>,
) -> Result<Vec<BasicBlockSpan>, BasicBlockPlanError> {
    ensure_contiguous(row_count, row_at)?;
    let m_cycle_bound = u64::try_from(BASIC_BLOCK_M_CYCLE_BOUND)
        .map_err(|_| BasicBlockPlanError::PartitionInvariant)?;
    let mut spans = Vec::new();
    let mut cursor = 0;
    while cursor < row_count {
        let row = row_at(cursor).ok_or(BasicBlockPlanError::Discontinuous { index: cursor })?;
        if row.effects().kind() != StepKind::Instruction {
            let (m_cycle_count, bus_event_count) = row_resources(row, cursor)?;
            spans.push(BasicBlockSpan {
                row_start: cursor,
                row_count: 1,
                instruction_count: 0,
                m_cycle_count,
                bus_event_count,
                cut: BasicBlockCut::MachineEvent,
            });
            cursor += 1;
            continue;
        }
        let start = cursor;
        let mut m_cycle_count = 0_u64;
        let mut bus_event_count = 0_usize;
        let cut = loop {
            let current =
                row_at(cursor).ok_or(BasicBlockPlanError::Discontinuous { index: cursor })?;
            if cursor != start
                && let Some(cut) = standalone_cut(current)
            {
                break cut;
            }
            let (next_m_cycles, next_bus_events) = row_resources(current, cursor)?;
            let candidate_m_cycles = m_cycle_count
                .checked_add(next_m_cycles)
                .ok_or(BasicBlockPlanError::ResourceAccounting { index: cursor })?;
            let candidate_bus_events = bus_event_count
                .checked_add(next_bus_events)
                .ok_or(BasicBlockPlanError::ResourceAccounting { index: cursor })?;
            if cursor != start && candidate_m_cycles > m_cycle_bound {
                break BasicBlockCut::CycleBound;
            }
            if cursor != start && candidate_bus_events > BASIC_BLOCK_BUS_EVENT_BOUND {
                break BasicBlockCut::BusEventBound;
            }
            if candidate_m_cycles > m_cycle_bound
                || candidate_bus_events > BASIC_BLOCK_BUS_EVENT_BOUND
            {
                return Err(BasicBlockPlanError::ResourceAccounting { index: cursor });
            }
            m_cycle_count = candidate_m_cycles;
            bus_event_count = candidate_bus_events;
            cursor += 1;
            if let Some(cut) = semantic_cut(current) {
                break cut;
            }
            if cursor - start == BASIC_BLOCK_INSTRUCTION_BOUND {
                break BasicBlockCut::InstructionBound;
            }
            let Some(next) = row_at(cursor) else {
                break BasicBlockCut::EndOfTrace;
            };
            if next.effects().kind() != StepKind::Instruction {
                break BasicBlockCut::MachineEvent;
            }
        };
        spans.push(BasicBlockSpan {
            row_start: start,
            row_count: cursor - start,
            instruction_count: cursor - start,
            m_cycle_count,
            bus_event_count,
            cut,
        });
    }
    Ok(spans)
}

fn row_resources(row: &TraceRow, index: usize) -> Result<(u64, usize), BasicBlockPlanError> {
    let m_cycle_count = row
        .after()
        .cpu()
        .m_cycles()
        .checked_sub(row.before().cpu().m_cycles())
        .ok_or(BasicBlockPlanError::ResourceAccounting { index })?;
    Ok((m_cycle_count, row.effects().ordered_bus_events().len()))
}

fn ensure_contiguous<'a>(
    row_count: usize,
    row_at: impl Fn(usize) -> Option<&'a TraceRow>,
) -> Result<(), BasicBlockPlanError> {
    for index in 0..row_count.saturating_sub(1) {
        let before = row_at(index).ok_or(BasicBlockPlanError::Discontinuous { index })?;
        let after = row_at(index + 1).ok_or(BasicBlockPlanError::Discontinuous { index })?;
        if before.after() != after.before() {
            return Err(BasicBlockPlanError::Discontinuous { index });
        }
    }
    Ok(())
}

fn semantic_cut(row: &TraceRow) -> Option<BasicBlockCut> {
    let operation = row.effects().instruction().operation();
    if matches!(operation, Operation::Halt | Operation::Stop) {
        return Some(BasicBlockCut::LowPower);
    }
    if matches!(
        operation,
        Operation::DisableInterrupts | Operation::EnableInterrupts | Operation::ReturnFromInterrupt
    ) {
        return Some(BasicBlockCut::InterruptControl);
    }
    if matches!(
        operation,
        Operation::RelativeJump(_)
            | Operation::Return(_)
            | Operation::JumpHl
            | Operation::Jump(_)
            | Operation::Call(_)
            | Operation::Restart(_)
    ) {
        return Some(BasicBlockCut::ControlFlow);
    }
    if let Some(cut) = standalone_cut(row) {
        return Some(cut);
    }
    for event in row.effects().ordered_bus_events() {
        let cut = match event.kind() {
            BusEventKind::InputRead | BusEventKind::OutputWrite | BusEventKind::DmgJoypadRead => {
                Some(BasicBlockCut::ProtocolIo)
            }
            BusEventKind::Mbc3ControlWrite => Some(BasicBlockCut::MapperChange),
            BusEventKind::MemoryOpcodeFetch | BusEventKind::MemoryImmediateRead => {
                Some(BasicBlockCut::MutableExecution)
            }
            BusEventKind::Unused
            | BusEventKind::OpcodeFetch
            | BusEventKind::ImmediateRead
            | BusEventKind::RomRead
            | BusEventKind::MemoryRead
            | BusEventKind::MemoryWrite
            | BusEventKind::Mbc3OpenBusRead
            | BusEventKind::Mbc3IgnoredWrite
            | BusEventKind::DmgMmioRead
            | BusEventKind::DmgMmioWrite
            | BusEventKind::DmgDmaRomRead
            | BusEventKind::DmgDmaMemoryRead
            | BusEventKind::DmgDmaWrite => None,
        };
        if cut.is_some() {
            return cut;
        }
    }
    if row.after().cpu().ime() == ImeState::Enabled
        && row.after().dmg_devices().pending_interrupt().is_some()
    {
        return Some(BasicBlockCut::InterruptPending);
    }
    None
}

fn standalone_cut(row: &TraceRow) -> Option<BasicBlockCut> {
    for event in row.effects().ordered_bus_events() {
        if matches!(
            event.kind(),
            BusEventKind::DmgMmioRead | BusEventKind::DmgMmioWrite | BusEventKind::DmgJoypadRead
        ) {
            return Some(BasicBlockCut::DeviceIo);
        }
        let address = event.transcript_event().address;
        if matches!(
            event.kind(),
            BusEventKind::MemoryRead
                | BusEventKind::MemoryWrite
                | BusEventKind::MemoryOpcodeFetch
                | BusEventKind::MemoryImmediateRead
        ) && ((0x8000..=0x9fff).contains(&address) || (0xfe00..=0xfe9f).contains(&address))
        {
            return Some(BasicBlockCut::PpuSensitiveMemory);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use zksm83_memory::{MemoryImage, RomImage};

    use crate::{LookupTraceBuilder, TraceBuilder};

    use super::*;

    #[test]
    fn planner_applies_universal_bound_and_control_cut() -> Result<(), Box<dyn std::error::Error>> {
        let rom = RomImage::new(vec![0x00, 0x00, 0x00, 0x00, 0xc3, 0x00, 0x00])?;
        let memory = MemoryImage::zeroed()?;
        let mut builder = TraceBuilder::new(rom, memory, Vec::new());
        let mut rows = Vec::new();
        for _ in 0..5 {
            rows.push(builder.step()?);
        }
        let spans = plan_basic_blocks(&rows)?;
        assert_eq!(spans.len(), 2);
        let first = spans.first().ok_or("missing bounded span")?;
        assert_eq!(first.row_count(), BASIC_BLOCK_INSTRUCTION_BOUND);
        assert_eq!(first.m_cycle_count(), BASIC_BLOCK_INSTRUCTION_BOUND as u64);
        assert_eq!(first.bus_event_count(), BASIC_BLOCK_INSTRUCTION_BOUND);
        assert_eq!(first.cut(), BasicBlockCut::InstructionBound);
        let second = spans.get(1).ok_or("missing control span")?;
        assert_eq!(second.row_start(), BASIC_BLOCK_INSTRUCTION_BOUND);
        assert_eq!(second.cut(), BasicBlockCut::ControlFlow);
        Ok(())
    }

    #[test]
    fn planner_cuts_before_exceeding_shared_cycle_budget() -> Result<(), Box<dyn std::error::Error>>
    {
        let rom = RomImage::new(vec![0x03; 4])?;
        let memory = MemoryImage::zeroed()?;
        let mut builder = TraceBuilder::new(rom, memory, Vec::new());
        let rows = vec![
            builder.step()?,
            builder.step()?,
            builder.step()?,
            builder.step()?,
        ];
        let spans = plan_basic_blocks(&rows)?;
        assert_eq!(spans.len(), 2);
        let first = spans.first().ok_or("missing cycle-bounded span")?;
        let second = spans.get(1).ok_or("missing cycle remainder span")?;
        assert_eq!(first.cut(), BasicBlockCut::CycleBound);
        assert_eq!(first.m_cycle_count(), 6);
        assert_eq!(first.bus_event_count(), 3);
        assert_eq!(second.m_cycle_count(), 2);
        Ok(())
    }

    #[test]
    fn planner_cuts_before_exceeding_shared_bus_budget() -> Result<(), Box<dyn std::error::Error>> {
        let rom = RomImage::new(vec![0xcb, 0x00, 0xcb, 0x00, 0xcb, 0x00])?;
        let memory = MemoryImage::zeroed()?;
        let mut builder = TraceBuilder::new(rom, memory, Vec::new());
        let rows = vec![builder.step()?, builder.step()?, builder.step()?];
        let spans = plan_basic_blocks(&rows)?;
        assert_eq!(spans.len(), 2);
        let first = spans.first().ok_or("missing bus-bounded span")?;
        assert_eq!(first.cut(), BasicBlockCut::BusEventBound);
        assert_eq!(first.m_cycle_count(), 4);
        assert_eq!(first.bus_event_count(), 4);
        Ok(())
    }

    #[test]
    fn planner_cuts_typed_device_io() -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes = vec![0_u8; 0x104];
        bytes
            .get_mut(0x100..0x104)
            .ok_or("missing device fixture")?
            .copy_from_slice(&[0x3e, 0x00, 0xe0, 0x40]);
        let rom = RomImage::new(bytes)?;
        let memory = MemoryImage::zeroed()?;
        let mut builder = TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, Vec::new());
        let first = builder.step()?;
        let second = builder.step()?;
        let spans = plan_basic_blocks(&[first, second])?;
        assert_eq!(spans.len(), 2);
        let prefix = spans.first().ok_or("missing pre-device span")?;
        let device = spans.get(1).ok_or("missing device span")?;
        assert_eq!(prefix.row_count(), 1);
        assert_eq!(prefix.cut(), BasicBlockCut::DeviceIo);
        assert_eq!(device.row_count(), 1);
        assert_eq!(device.cut(), BasicBlockCut::DeviceIo);
        Ok(())
    }

    #[test]
    fn planner_isolates_ppu_timing_sensitive_memory() -> Result<(), Box<dyn std::error::Error>> {
        let rom = RomImage::new(vec![0xfa, 0x00, 0x80, 0x00])?;
        let memory = MemoryImage::zeroed()?;
        let mut builder = TraceBuilder::new(rom, memory, Vec::new());
        let rows = vec![builder.step()?, builder.step()?];
        let spans = plan_basic_blocks(&rows)?;
        assert_eq!(spans.len(), 2);
        let memory = spans.first().ok_or("missing PPU-sensitive span")?;
        let suffix = spans.get(1).ok_or("missing post-memory span")?;
        assert_eq!(memory.row_count(), 1);
        assert_eq!(memory.cut(), BasicBlockCut::PpuSensitiveMemory);
        assert_eq!(suffix.row_count(), 1);
        Ok(())
    }

    #[test]
    fn planner_never_absorbs_mutable_instruction_fetches() -> Result<(), Box<dyn std::error::Error>>
    {
        let rom = RomImage::new(vec![0xc3, 0x00, 0xc0])?;
        let mut memory_bytes = vec![0_u8; 0x4001];
        *memory_bytes
            .get_mut(0x4000)
            .ok_or("missing mutable instruction byte")? = 0x00;
        let memory = MemoryImage::new(memory_bytes)?;
        let mut builder = TraceBuilder::new(rom, memory, Vec::new());
        let jump = builder.step()?;
        let mutable_instruction = builder.step()?;
        let spans = plan_basic_blocks(&[jump, mutable_instruction])?;
        assert_eq!(spans.len(), 2);
        let jump = spans.first().ok_or("missing jump span")?;
        let mutable = spans.get(1).ok_or("missing mutable span")?;
        assert_eq!(jump.cut(), BasicBlockCut::ControlFlow);
        assert_eq!(mutable.cut(), BasicBlockCut::MutableExecution);
        Ok(())
    }

    #[test]
    fn witness_planner_preserves_chunk_boundaries() -> Result<(), Box<dyn std::error::Error>> {
        let rom = RomImage::new(vec![0x00; BASIC_BLOCK_INSTRUCTION_BOUND + 1])?;
        let memory = MemoryImage::zeroed()?;
        let mut builder = TraceBuilder::new(rom, memory, Vec::new());
        let mut rows = (0..=BASIC_BLOCK_INSTRUCTION_BOUND)
            .map(|_| builder.step())
            .collect::<Result<Vec<_>, _>>()?;
        let second_rows = rows.split_off(2);
        let witness = Witness::new(vec![
            crate::TraceChunk::new(rows)?,
            crate::TraceChunk::new(second_rows)?,
        ])?;
        let blocks = pack_witness_basic_blocks(witness)?;
        assert_eq!(blocks.len(), 2);
        let first = blocks.first().ok_or("missing first witness block")?;
        let second = blocks.get(1).ok_or("missing second witness block")?;
        assert_eq!(first.row_count(), BASIC_BLOCK_INSTRUCTION_BOUND);
        assert_eq!(second.row_count(), 1);
        assert_eq!(first.source_row_start(), 0);
        assert_eq!(second.source_row_start(), BASIC_BLOCK_INSTRUCTION_BOUND);
        assert_eq!(first.final_state(), second.initial_state());
        assert_eq!(first.rows().len(), first.row_count());
        for (lane_index, lane) in first.lanes().iter().copied().enumerate() {
            let descriptor = lane.descriptor().ok_or("missing active lane descriptor")?;
            let offset = u64::try_from(lane_index)?;
            assert_eq!(descriptor.source_row_index(), lane_index);
            assert_eq!(descriptor.m_cycle_start(), offset);
            assert_eq!(descriptor.m_cycle_count(), 1);
            assert_eq!(descriptor.bus_event_start(), lane_index);
            assert_eq!(descriptor.bus_event_count(), 1);
        }
        for (slot, owner) in first.m_cycle_owners().iter().copied().enumerate() {
            let expected = BasicBlockLaneIndex::from_index(slot).map_or(
                BasicBlockResourceOwner::Padding,
                BasicBlockResourceOwner::Instruction,
            );
            assert_eq!(owner, expected);
        }
        for (slot, owner) in first.bus_event_owners().iter().copied().enumerate() {
            let expected = BasicBlockLaneIndex::from_index(slot).map_or(
                BasicBlockResourceOwner::Padding,
                BasicBlockResourceOwner::Instruction,
            );
            assert_eq!(owner, expected);
        }
        assert_eq!(
            second
                .lanes()
                .iter()
                .filter(|lane| lane.is_instruction())
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn machine_event_block_has_only_padding_instruction_lanes()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes = vec![0_u8; 0x101];
        *bytes.get_mut(0x100).ok_or("missing HALT byte")? = 0x76;
        let rom = RomImage::new(bytes)?;
        let memory = MemoryImage::zeroed()?;
        let mut builder = TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, Vec::new());
        let witness = Witness::from_rows(vec![builder.step()?, builder.step()?])?;
        let blocks = pack_witness_basic_blocks(witness)?;
        let machine = blocks.get(1).ok_or("missing machine-event block")?;
        assert_eq!(machine.instruction_count(), 0);
        assert_eq!(machine.cut(), BasicBlockCut::MachineEvent);
        assert!(machine.lanes().iter().all(|lane| !lane.is_instruction()));
        assert!(
            machine
                .m_cycle_owners()
                .iter()
                .all(|owner| *owner == BasicBlockResourceOwner::Padding)
        );
        assert!(
            machine
                .bus_event_owners()
                .iter()
                .all(|owner| *owner == BasicBlockResourceOwner::Padding)
        );
        Ok(())
    }

    #[test]
    fn lookup_blocks_keep_legacy_transcript_cursors_empty() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut rom_bytes = vec![0_u8; 0x104];
        let program = rom_bytes.get_mut(0x100..).ok_or("synthetic ROM layout")?;
        program.copy_from_slice(&[0x00; 4]);
        let rom = RomImage::new(rom_bytes.clone())?;
        let memory = MemoryImage::zeroed()?;
        let mut builder = LookupTraceBuilder::new_dmg_post_boot_mbc3(
            rom_bytes,
            memory.checkpoint_bytes(),
            Vec::new(),
            rom.root(),
            memory.root(),
        )?;
        let witness = builder.run_exact_steps(4)?;
        for row in witness.rows() {
            assert_eq!(row.before().bus_transcript().next_index(), 0);
            assert_eq!(row.after().bus_transcript().next_index(), 0);
            assert_eq!(row.before().isa_transcript().next_index(), 0);
            assert_eq!(row.after().isa_transcript().next_index(), 0);
        }
        let blocks = pack_witness_basic_blocks(witness)?;
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks.first().map(BasicBlock::instruction_count), Some(4));
        Ok(())
    }
}
