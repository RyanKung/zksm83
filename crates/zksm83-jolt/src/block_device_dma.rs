//! Shared quiet-instruction DMA scheduling and serialized DMA-byte transition.

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_core::StepKind;
use zksm83_trace::{BASIC_BLOCK_BUS_EVENT_BOUND, BASIC_BLOCK_INSTRUCTION_BOUND, BasicBlock};

use crate::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_DEVICE_PPU_INTERRUPT_COLUMN_COUNT,
    BLOCK_DEVICE_PPU_INTERRUPT_CONSTRAINT_COUNT, BLOCK_DEVICE_PPU_INTERRUPT_MAX_DEGREE,
    BLOCK_FRONTEND_COLUMN_COUNT, BLOCK_ISA_CONTROL_COLUMN_COUNT, BLOCK_ROUTING_COLUMN_COUNT,
    BlockDevicePpuInterruptError, BlockDevicePpuInterruptRelation, BlockDevicePpuInterruptWitness,
    ConstraintOutput, NativeField, STATE_CPU_M_CYCLES_INDEX, STATE_DMA_PACK_INDEX,
    UNIFORM_ROW_COUNT, UniformError, UniformRelation,
    block_boundary::{device_state_value, local_state_value},
    block_bus::{slot_active_value, slot_address_value, slot_kind_selector, slot_value_value},
    block_device::{device_clocked_block, device_io_selector_value},
    block_machine::{
        device_clocked_value, halt_until_serial_value, halt_until_timer_value,
        halt_until_vblank_value,
    },
    block_metadata,
};

const DMA_AUX_START: usize = BLOCK_DEVICE_PPU_INTERRUPT_COLUMN_COUNT;
const BEFORE_PACK_BITS_START: usize = 0;
const AFTER_PACK_BITS_START: usize = BEFORE_PACK_BITS_START + 32;
const BEFORE_INDEX_SLACK_BITS_START: usize = AFTER_PACK_BITS_START + 32;
const AFTER_INDEX_SLACK_BITS_START: usize = BEFORE_INDEX_SLACK_BITS_START + 8;
const BEFORE_OWED_SLACK_BITS_START: usize = AFTER_INDEX_SLACK_BITS_START + 8;
const AFTER_OWED_SLACK_BITS_START: usize = BEFORE_OWED_SLACK_BITS_START + 3;
const BEFORE_INDEX_ZERO_PREFIX_START: usize = AFTER_OWED_SLACK_BITS_START + 3;
const AFTER_INDEX_ZERO_PREFIX_START: usize = BEFORE_INDEX_ZERO_PREFIX_START + 8;
const NEAR_END: usize = AFTER_INDEX_ZERO_PREFIX_START + 8;
const NEAR_END_GAP_BITS_START: usize = NEAR_END + 1;
const DMA_BYTE_SELECTOR: usize = NEAR_END_GAP_BITS_START + 8;
const DMA_AUX_COLUMN_COUNT: usize = DMA_BYTE_SELECTOR + 1;
const DMA_ADDITIONAL_CONSTRAINT_COUNT: usize = 286;
const DMA_LENGTH: u64 = 160;
const DMA_MAX_OWED: u64 = 6;
const DMA_SOURCE_KIND_ROM: u8 = 16;
const DMA_SOURCE_KIND_MEMORY: u8 = 17;
const DMA_WRITE_KIND: u8 = 18;

/// Logical columns in the PPU-interrupt relation plus bounded DMA state.
pub const BLOCK_DEVICE_DMA_COLUMN_COUNT: usize =
    BLOCK_DEVICE_PPU_INTERRUPT_COLUMN_COUNT + DMA_AUX_COLUMN_COUNT;
/// Identities in the shared bounded-DMA relation.
pub const BLOCK_DEVICE_DMA_CONSTRAINT_COUNT: usize =
    BLOCK_DEVICE_PPU_INTERRUPT_CONSTRAINT_COUNT + DMA_ADDITIONAL_CONSTRAINT_COUNT;
/// Maximum total degree in the shared bounded-DMA relation.
pub const BLOCK_DEVICE_DMA_MAX_DEGREE: usize = BLOCK_DEVICE_PPU_INTERRUPT_MAX_DEGREE;

const _: () = assert!(BASIC_BLOCK_INSTRUCTION_BOUND == 4);
const _: () = assert!(BASIC_BLOCK_BUS_EVENT_BOUND == 5);
const _: () = assert!(DMA_AUX_COLUMN_COUNT == 112);
const _: () = assert!(BLOCK_DEVICE_DMA_COLUMN_COUNT == 2_474);
const _: () = assert!(BLOCK_DEVICE_DMA_CONSTRAINT_COUNT == 5_352);
const _: () = assert!(BLOCK_DEVICE_DMA_MAX_DEGREE == 7);

/// Fixed-row witness carrying bounded clock scheduling and DMA-byte consumption.
#[derive(Debug)]
pub struct BlockDeviceDmaWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to construct the shared packed-block DMA witness.
#[derive(Debug, Error)]
pub enum BlockDeviceDmaError {
    /// PPU-interrupt witness construction failed.
    #[error("packed-block PPU-interrupt construction failed: {0}")]
    PpuInterrupt(#[from] BlockDevicePpuInterruptError),
    /// A validated block exposed an inconsistent DMA state transition.
    #[error("packed block {block} has an inconsistent DMA transition")]
    InvalidTransition {
        /// Zero-based packed-block row.
        block: usize,
    },
    /// DMA auxiliary columns violated their fixed layout.
    #[error("packed-block DMA witness violated its typed layout")]
    Layout,
}

/// PPU-interrupt relation plus bounded DMA scheduling and byte-consumption semantics.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockDeviceDmaRelation;

impl BlockDeviceDmaWitness {
    /// Derives one shared DMA witness from each validated packed block.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockDeviceDmaError> {
        let ppu_interrupt = BlockDevicePpuInterruptWitness::from_blocks(blocks)?;
        let active_block_count = ppu_interrupt.active_block_count();
        let mut auxiliary = (0..DMA_AUX_COLUMN_COUNT)
            .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
            .collect::<Vec<_>>();
        for (block_index, block) in blocks.iter().enumerate() {
            let mut row = [0_u64; DMA_AUX_COLUMN_COUNT];
            append_dma_row(&mut row, block, block_index)?;
            for (column, value) in auxiliary.iter_mut().zip(row) {
                column.push(value);
            }
        }
        for column in &mut auxiliary {
            column.resize(UNIFORM_ROW_COUNT, 0);
        }
        let mut columns = ppu_interrupt.into_columns();
        columns.extend(auxiliary);
        if columns.len() != BLOCK_DEVICE_DMA_COLUMN_COUNT {
            return Err(BlockDeviceDmaError::Layout);
        }
        Ok(Self {
            columns,
            active_block_count,
        })
    }

    /// Returns every logical column in PPU-interrupt-then-DMA order.
    #[must_use]
    pub fn columns(&self) -> &[Vec<u64>] {
        &self.columns
    }

    /// Returns the number of non-padding packed-block rows.
    #[must_use]
    pub const fn active_block_count(&self) -> usize {
        self.active_block_count
    }

    pub(crate) fn into_columns(self) -> Vec<Vec<u64>> {
        self.columns
    }
}

impl UniformRelation for BlockDeviceDmaRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-device-dma/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [2_362_u64, 5_066, 112, 160, 2_474, 5_352, 3] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_DEVICE_DMA_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_DEVICE_DMA_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_DEVICE_DMA_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_DEVICE_DMA_COLUMN_COUNT
            || constraints.len() != BLOCK_DEVICE_DMA_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let ppu_interrupt = row
            .get(..BLOCK_DEVICE_PPU_INTERRUPT_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let auxiliary = row
            .get(DMA_AUX_START..BLOCK_DEVICE_DMA_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let (ppu_interrupt_constraints, dma_constraints) =
            constraints.split_at_mut(BLOCK_DEVICE_PPU_INTERRUPT_CONSTRAINT_COUNT);
        BlockDevicePpuInterruptRelation.evaluate(ppu_interrupt, ppu_interrupt_constraints)?;
        constrain_dma(ppu_interrupt, auxiliary, dma_constraints)
    }
}

fn append_dma_row(
    row: &mut [u64],
    block: &BasicBlock,
    block_index: usize,
) -> Result<(), BlockDeviceDmaError> {
    let before = DmaState::from_pack(block.initial_state().dmg_devices().dma_pack(), block_index)?;
    let after = DmaState::from_pack(block.final_state().dmg_devices().dma_pack(), block_index)?;
    append_dma_state(row, false, before)?;
    append_dma_state(row, true, after)?;
    let quiet = quiet_instruction_block(block)?;
    if quiet {
        append_quiet_schedule(row, block, before, after, block_index)?;
    }
    let dma_byte = dma_byte_block(block);
    set(row, DMA_BYTE_SELECTOR, u64::from(dma_byte))?;
    if dma_byte {
        validate_dma_byte(before, after, block_index)?;
    }
    Ok(())
}

fn quiet_instruction_block(block: &BasicBlock) -> Result<bool, BlockDeviceDmaError> {
    device_clocked_block(block).map_err(|_| BlockDeviceDmaError::Layout)
}

fn dma_byte_block(block: &BasicBlock) -> bool {
    block.row_count() == 1
        && block
            .rows()
            .next()
            .is_some_and(|row| row.effects().kind() == StepKind::DmaByte)
}

fn append_dma_state(
    row: &mut [u64],
    after: bool,
    state: DmaState,
) -> Result<(), BlockDeviceDmaError> {
    append_bits(row, pack_start(after), u64::from(state.pack()), 32)?;
    let index_slack = DMA_LENGTH
        .checked_sub(u64::from(state.index))
        .ok_or(BlockDeviceDmaError::Layout)?;
    let owed_slack = DMA_MAX_OWED
        .checked_sub(u64::from(state.owed))
        .ok_or(BlockDeviceDmaError::Layout)?;
    append_bits(row, index_slack_start(after), index_slack, 8)?;
    append_bits(row, owed_slack_start(after), owed_slack, 3)?;
    let mut zero_prefix = true;
    for bit in 0..8 {
        zero_prefix &= index_slack >> bit & 1 == 0;
        set(
            row,
            checked_add(index_zero_prefix_start(after), bit)?,
            u64::from(zero_prefix),
        )?;
    }
    Ok(())
}

fn append_quiet_schedule(
    row: &mut [u64],
    block: &BasicBlock,
    before: DmaState,
    after: DmaState,
    block_index: usize,
) -> Result<(), BlockDeviceDmaError> {
    let cycles = block.m_cycle_count();
    let remaining = DMA_LENGTH
        .checked_sub(u64::from(before.index))
        .ok_or(BlockDeviceDmaError::Layout)?;
    let expected_owed = if before.active {
        cycles.min(remaining)
    } else {
        0
    };
    if before.owed != 0
        || after.source_high != before.source_high
        || after.index != before.index
        || after.active != before.active
        || u64::from(after.owed) != expected_owed
    {
        return Err(BlockDeviceDmaError::InvalidTransition { block: block_index });
    }
    if before.active {
        let (near_end, gap) = comparison_witness(cycles, remaining)?;
        set(row, NEAR_END, u64::from(near_end))?;
        append_bits(row, NEAR_END_GAP_BITS_START, gap, 8)?;
    }
    Ok(())
}

fn validate_dma_byte(
    before: DmaState,
    after: DmaState,
    block: usize,
) -> Result<(), BlockDeviceDmaError> {
    let expected_index = before
        .index
        .checked_add(1)
        .ok_or(BlockDeviceDmaError::InvalidTransition { block })?;
    let expected_owed = before
        .owed
        .checked_sub(1)
        .ok_or(BlockDeviceDmaError::InvalidTransition { block })?;
    if !before.active
        || before.owed == 0
        || after.source_high != before.source_high
        || after.index != expected_index
        || after.owed != expected_owed
        || after.active != (expected_index < DMA_LENGTH as u8)
    {
        return Err(BlockDeviceDmaError::InvalidTransition { block });
    }
    Ok(())
}

fn comparison_witness(elapsed: u64, distance: u64) -> Result<(bool, u64), BlockDeviceDmaError> {
    if elapsed >= distance {
        Ok((
            true,
            elapsed
                .checked_sub(distance)
                .ok_or(BlockDeviceDmaError::Layout)?,
        ))
    } else {
        Ok((
            false,
            distance
                .checked_sub(elapsed)
                .and_then(|value| value.checked_sub(1))
                .ok_or(BlockDeviceDmaError::Layout)?,
        ))
    }
}

fn constrain_dma(
    ppu_interrupt: &[NativeField],
    auxiliary: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if auxiliary.len() != DMA_AUX_COLUMN_COUNT
        || constraints.len() != DMA_ADDITIONAL_CONSTRAINT_COUNT
    {
        return Err(UniformError::Shape);
    }
    let block_active = block_metadata::block_active_value(ppu_interrupt)?;
    let one = NativeField::from_u64(1);
    let mut sink = ConstraintSink::new(constraints);
    for state in auxiliary.iter().copied() {
        sink.push(state * (state - one))?;
        sink.push((one - block_active) * state)?;
    }
    let frontend = ppu_interrupt
        .get(..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let boundary = frontend
        .get(BLOCK_ROUTING_COLUMN_COUNT..BLOCK_CONTROL_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let bus = frontend
        .get(BLOCK_ISA_CONTROL_COLUMN_COUNT..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    constrain_dma_state(boundary, auxiliary, false, block_active, &mut sink)?;
    constrain_dma_state(boundary, auxiliary, true, block_active, &mut sink)?;
    constrain_dma_selector(frontend, bus, auxiliary, &mut sink)?;
    constrain_quiet_schedule(ppu_interrupt, boundary, auxiliary, &mut sink)?;
    constrain_dma_byte(bus, auxiliary, &mut sink)?;
    sink.finish()
}

fn constrain_dma_state(
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    after: bool,
    block_active: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let packed = packed_bits(auxiliary, pack_start(after), 32)?;
    sink.push(device_state_value(boundary, after, STATE_DMA_PACK_INDEX)? - packed)?;
    let index = state_byte(auxiliary, after, 1)?;
    let owed = state_byte(auxiliary, after, 3)?;
    let index_slack = packed_bits(auxiliary, index_slack_start(after), 8)?;
    let owed_slack = packed_bits(auxiliary, owed_slack_start(after), 3)?;
    sink.push(index + index_slack - NativeField::from_u64(DMA_LENGTH) * block_active)?;
    sink.push(owed + owed_slack - NativeField::from_u64(DMA_MAX_OWED) * block_active)?;
    for bit in 1..8 {
        sink.push(state_bit(auxiliary, after, 2, bit)?)?;
    }
    let mut prefix = block_active;
    for bit in 0..8 {
        let next = value(auxiliary, index_zero_prefix_start(after) + bit)?;
        let slack_bit = value(auxiliary, index_slack_start(after) + bit)?;
        sink.push(next - prefix * (one - slack_bit))?;
        prefix = next;
    }
    sink.push(state_bit(auxiliary, after, 2, 0)? * prefix)
}

fn constrain_dma_selector(
    frontend: &[NativeField],
    bus: &[NativeField],
    auxiliary: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let dma = value(auxiliary, DMA_BYTE_SELECTOR)?;
    let source = slot_kind_selector(bus, 0, DMA_SOURCE_KIND_ROM)?
        + slot_kind_selector(bus, 0, DMA_SOURCE_KIND_MEMORY)?;
    sink.push(dma - source)?;
    sink.push(dma - slot_kind_selector(bus, 1, DMA_WRITE_KIND)?)?;
    for slot in 2..BASIC_BLOCK_BUS_EVENT_BOUND {
        sink.push(dma * slot_active_value(bus, slot)?)?;
    }
    sink.push(dma * block_metadata::instruction_value(frontend)?)
}

fn constrain_quiet_schedule(
    ppu_interrupt: &[NativeField],
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let device_io = device_io_selector_value(ppu_interrupt)?;
    let quiet = device_clocked_value(ppu_interrupt)? * (NativeField::from_u64(1) - device_io);
    let before_active = state_bit(auxiliary, false, 2, 0)?;
    let before_owed = state_byte(auxiliary, false, 3)?;
    let long = halt_until_vblank_value(ppu_interrupt)?
        + halt_until_serial_value(ppu_interrupt)?
        + halt_until_timer_value(ppu_interrupt)?;
    sink.push(long * before_active)?;
    sink.push(quiet * before_owed)?;
    for byte in 0..3 {
        sink.push(
            quiet * (state_byte(auxiliary, true, byte)? - state_byte(auxiliary, false, byte)?),
        )?;
    }
    let cycles = local_state_value(
        boundary,
        BASIC_BLOCK_INSTRUCTION_BOUND,
        STATE_CPU_M_CYCLES_INDEX,
    )? - local_state_value(boundary, 0, STATE_CPU_M_CYCLES_INDEX)?;
    let remaining = packed_bits(auxiliary, BEFORE_INDEX_SLACK_BITS_START, 8)?;
    let active = quiet * before_active;
    constrain_comparison(
        auxiliary,
        ComparisonSpec {
            active,
            elapsed: cycles,
            distance: remaining,
            event_index: NEAR_END,
            gap_start: NEAR_END_GAP_BITS_START,
            gap_width: 8,
        },
        sink,
    )?;
    let near_end = value(auxiliary, NEAR_END)?;
    let expected_owed = before_active * (cycles - near_end * (cycles - remaining));
    sink.push(quiet * (state_byte(auxiliary, true, 3)? - expected_owed))
}

fn constrain_dma_byte(
    bus: &[NativeField],
    auxiliary: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let dma = value(auxiliary, DMA_BYTE_SELECTOR)?;
    let before_active = state_bit(auxiliary, false, 2, 0)?;
    let before_owed = state_byte(auxiliary, false, 3)?;
    let after_completion = value(auxiliary, AFTER_INDEX_ZERO_PREFIX_START + 7)?;
    sink.push(dma * (before_active - one))?;
    let owed_zero = (one - state_bit(auxiliary, false, 3, 0)?)
        * (one - state_bit(auxiliary, false, 3, 1)?)
        * (one - state_bit(auxiliary, false, 3, 2)?);
    sink.push(dma * owed_zero)?;
    sink.push(dma * (state_byte(auxiliary, true, 0)? - state_byte(auxiliary, false, 0)?))?;
    sink.push(dma * (state_byte(auxiliary, true, 1)? - state_byte(auxiliary, false, 1)? - one))?;
    sink.push(dma * (state_byte(auxiliary, true, 3)? - before_owed + one))?;
    sink.push(dma * (state_bit(auxiliary, true, 2, 0)? - before_active + after_completion))?;
    let source_address = NativeField::from_u64(256) * state_byte(auxiliary, false, 0)?
        + state_byte(auxiliary, false, 1)?;
    let destination_address = NativeField::from_u64(0xfe00) + state_byte(auxiliary, false, 1)?;
    sink.push(dma * (slot_address_value(bus, 0)? - source_address))?;
    sink.push(dma * (slot_address_value(bus, 1)? - destination_address))?;
    sink.push(dma * (slot_value_value(bus, 1)? - slot_value_value(bus, 0)?))
}

fn constrain_comparison(
    auxiliary: &[NativeField],
    spec: ComparisonSpec,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let event = value(auxiliary, spec.event_index)?;
    let gap = packed_bits(auxiliary, spec.gap_start, spec.gap_width)?;
    let crossed_gap = spec.elapsed - spec.distance;
    let before_gap = spec.distance - spec.elapsed - one;
    sink.push(spec.active * (gap - event * crossed_gap - (one - event) * before_gap))?;
    sink.push((one - spec.active) * event)?;
    sink.push((one - spec.active) * gap)
}

const fn pack_start(after: bool) -> usize {
    if after {
        AFTER_PACK_BITS_START
    } else {
        BEFORE_PACK_BITS_START
    }
}

const fn index_slack_start(after: bool) -> usize {
    if after {
        AFTER_INDEX_SLACK_BITS_START
    } else {
        BEFORE_INDEX_SLACK_BITS_START
    }
}

const fn owed_slack_start(after: bool) -> usize {
    if after {
        AFTER_OWED_SLACK_BITS_START
    } else {
        BEFORE_OWED_SLACK_BITS_START
    }
}

const fn index_zero_prefix_start(after: bool) -> usize {
    if after {
        AFTER_INDEX_ZERO_PREFIX_START
    } else {
        BEFORE_INDEX_ZERO_PREFIX_START
    }
}

fn state_byte(row: &[NativeField], after: bool, byte: usize) -> Result<NativeField, UniformError> {
    let offset = byte.checked_mul(8).ok_or(UniformError::Shape)?;
    let start = pack_start(after)
        .checked_add(offset)
        .ok_or(UniformError::Shape)?;
    packed_bits(row, start, 8)
}

pub(crate) fn dma_state_byte_value(
    row: &[NativeField],
    after: bool,
    byte: usize,
) -> Result<NativeField, UniformError> {
    if row.len() < BLOCK_DEVICE_DMA_COLUMN_COUNT || byte >= 4 {
        return Err(UniformError::Shape);
    }
    let auxiliary = row
        .get(DMA_AUX_START..BLOCK_DEVICE_DMA_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    state_byte(auxiliary, after, byte)
}

fn state_bit(
    row: &[NativeField],
    after: bool,
    byte: usize,
    bit: usize,
) -> Result<NativeField, UniformError> {
    let offset = byte
        .checked_mul(8)
        .and_then(|value| value.checked_add(bit))
        .ok_or(UniformError::Shape)?;
    value(
        row,
        pack_start(after)
            .checked_add(offset)
            .ok_or(UniformError::Shape)?,
    )
}

fn packed_bits(
    row: &[NativeField],
    start: usize,
    width: usize,
) -> Result<NativeField, UniformError> {
    let mut packed = NativeField::from_u64(0);
    let mut power = NativeField::from_u64(1);
    for bit in 0..width {
        packed += power * value(row, start.checked_add(bit).ok_or(UniformError::Shape)?)?;
        power += power;
    }
    Ok(packed)
}

fn value(row: &[NativeField], index: usize) -> Result<NativeField, UniformError> {
    row.get(index).copied().ok_or(UniformError::Shape)
}

fn append_bits(
    row: &mut [u64],
    start: usize,
    value: u64,
    width: usize,
) -> Result<(), BlockDeviceDmaError> {
    for bit in 0..width {
        set(row, checked_add(start, bit)?, value >> bit & 1)?;
    }
    Ok(())
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), BlockDeviceDmaError> {
    *row.get_mut(index).ok_or(BlockDeviceDmaError::Layout)? = value;
    Ok(())
}

fn checked_add(start: usize, offset: usize) -> Result<usize, BlockDeviceDmaError> {
    start.checked_add(offset).ok_or(BlockDeviceDmaError::Layout)
}

#[derive(Clone, Copy)]
struct DmaState {
    source_high: u8,
    index: u8,
    active: bool,
    owed: u8,
}

impl DmaState {
    fn from_pack(pack: u32, block: usize) -> Result<Self, BlockDeviceDmaError> {
        let [source_high, index, active, owed] = pack.to_le_bytes();
        if active > 1 || index > DMA_LENGTH as u8 || owed > DMA_MAX_OWED as u8 {
            return Err(BlockDeviceDmaError::InvalidTransition { block });
        }
        let active = active == 1;
        if active && index == DMA_LENGTH as u8 {
            return Err(BlockDeviceDmaError::InvalidTransition { block });
        }
        Ok(Self {
            source_high,
            index,
            active,
            owed,
        })
    }

    const fn pack(self) -> u32 {
        u32::from_le_bytes([self.source_high, self.index, self.active as u8, self.owed])
    }
}

#[derive(Clone, Copy)]
struct ComparisonSpec {
    active: NativeField,
    elapsed: NativeField,
    distance: NativeField,
    event_index: usize,
    gap_start: usize,
    gap_width: usize,
}

struct ConstraintSink<'a> {
    constraints: &'a mut [NativeField],
    next: usize,
}

impl<'a> ConstraintSink<'a> {
    const fn new(constraints: &'a mut [NativeField]) -> Self {
        Self {
            constraints,
            next: 0,
        }
    }

    fn push(&mut self, value: NativeField) -> Result<(), UniformError> {
        *self
            .constraints
            .get_mut(self.next)
            .ok_or(UniformError::Shape)? = value;
        self.next = self.next.checked_add(1).ok_or(UniformError::Shape)?;
        Ok(())
    }

    fn finish(self) -> Result<(), UniformError> {
        if self.next == self.constraints.len() {
            Ok(())
        } else {
            Err(UniformError::Shape)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        block_test_support::{
            MachineEventFixture, flip_witness_bit, lookup_blocks, machine_event_block,
        },
        validate_uniform_witness,
    };

    #[test]
    fn inactive_dma_is_stable_across_a_quiet_block() -> Result<(), Box<dyn std::error::Error>> {
        let blocks = lookup_blocks(
            &[0x00; BASIC_BLOCK_INSTRUCTION_BOUND],
            BASIC_BLOCK_INSTRUCTION_BOUND,
        )?;
        let witness = BlockDeviceDmaWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockDeviceDmaRelation, witness.columns())?;
        let mut mutated = witness.columns().to_vec();
        flip_witness_bit(&mut mutated, DMA_AUX_START + BEFORE_PACK_BITS_START, 0)?;
        assert!(validate_uniform_witness(&BlockDeviceDmaRelation, &mutated).is_err());
        Ok(())
    }

    #[test]
    fn dma_byte_event_binds_serialized_transfer() -> Result<(), Box<dyn std::error::Error>> {
        let blocks = machine_event_block(MachineEventFixture::DmaByte)?;
        let witness = BlockDeviceDmaWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockDeviceDmaRelation, witness.columns())?;
        let mut mutated = witness.columns().to_vec();
        flip_witness_bit(&mut mutated, DMA_AUX_START + DMA_BYTE_SELECTOR, 0)?;
        assert!(validate_uniform_witness(&BlockDeviceDmaRelation, &mutated).is_err());
        Ok(())
    }
}
