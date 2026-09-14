//! Packed-block mutable-memory selectors and strict event chronology.

#[cfg(test)]
mod tests;

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_core::{BusEventKind, VmState};
use zksm83_trace::{BASIC_BLOCK_BUS_EVENT_BOUND, BasicBlock, BasicBlockLaneIndex};

use crate::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_DEVICE_PPU_MMIO_COLUMN_COUNT,
    BLOCK_DEVICE_PPU_MMIO_CONSTRAINT_COUNT, BLOCK_DEVICE_PPU_MMIO_MAX_DEGREE,
    BLOCK_FRONTEND_COLUMN_COUNT, BLOCK_ISA_CONTROL_COLUMN_COUNT, BLOCK_ROUTING_COLUMN_COUNT,
    BlockDevicePpuMmioError, BlockDevicePpuMmioRelation, BlockDevicePpuMmioWitness,
    BlockFrontendError, BlockFrontendWitness, ConstraintOutput, ISA_ADDRESS_BIT_COUNT,
    ISA_OUTPUT_COUNT, IsaLookupColumns, MEMORY_IMAGE_BYTES, NativeField, ROM_ADDRESS_BIT_COUNT,
    RomLookupColumns, STATE_INPUT_NEXT_INDEX, STATE_OUTPUT_NEXT_INDEX, TRACE_MEMORY_TIMESTAMP_BITS,
    UNIFORM_NUM_VARIABLES, UNIFORM_ROW_COUNT, UniformError, UniformRelation,
    block_boundary::local_state_value,
    block_bus::{slot_kind_selector, slot_physical_address_bit},
};

const MEMORY_KIND_CODES: [u8; 6] = [4, 5, 14, 15, 17, 18];
const MEMORY_WRITE_KIND_CODES: [u8; 2] = [5, 18];
const ROW_BITS_START: usize = 0;
const SLOT_START: usize = ROW_BITS_START + UNIFORM_NUM_VARIABLES;
const SLOT_SELECTOR_OFFSET: usize = 0;
const SLOT_WRITE_SELECTOR_OFFSET: usize = 1;
const SLOT_PREDECESSOR_BITS_OFFSET: usize = 2;
const SLOT_DELTA_BITS_OFFSET: usize = SLOT_PREDECESSOR_BITS_OFFSET + TRACE_MEMORY_TIMESTAMP_BITS;
const SLOT_WIDTH: usize = SLOT_DELTA_BITS_OFFSET + TRACE_MEMORY_TIMESTAMP_BITS;
const LOG_SELECTOR_START: usize = SLOT_START + BASIC_BLOCK_BUS_EVENT_BOUND * SLOT_WIDTH;
const LOG_SELECTOR_WIDTH: usize = 2;
const LOG_INPUT_SELECTOR_OFFSET: usize = 0;
const LOG_OUTPUT_SELECTOR_OFFSET: usize = 1;
const BLOCK_MEMORY_AUX_COLUMN_COUNT: usize =
    LOG_SELECTOR_START + BASIC_BLOCK_BUS_EVENT_BOUND * LOG_SELECTOR_WIDTH;
const BLOCK_MEMORY_ADDITIONAL_CONSTRAINT_COUNT: usize =
    UNIFORM_NUM_VARIABLES + BASIC_BLOCK_BUS_EVENT_BOUND * 48;
const MEMORY_PHYSICAL_ADDRESS_BITS: usize = TRACE_MEMORY_TIMESTAMP_BITS;
const INPUT_KIND_CODES: [u8; 2] = [
    BusEventKind::InputRead.code(),
    BusEventKind::DmgJoypadRead.code(),
];
const OUTPUT_KIND_CODES: [u8; 1] = [BusEventKind::OutputWrite.code()];

/// Logical columns in PPU-MMIO plus packed mutable-memory chronology.
pub const BLOCK_MEMORY_COLUMN_COUNT: usize =
    BLOCK_DEVICE_PPU_MMIO_COLUMN_COUNT + BLOCK_MEMORY_AUX_COLUMN_COUNT;
/// Identities in the packed mutable-memory chronology relation.
pub const BLOCK_MEMORY_CONSTRAINT_COUNT: usize =
    BLOCK_DEVICE_PPU_MMIO_CONSTRAINT_COUNT + BLOCK_MEMORY_ADDITIONAL_CONSTRAINT_COUNT;
/// Maximum total degree in the packed mutable-memory chronology relation.
pub const BLOCK_MEMORY_MAX_DEGREE: usize = BLOCK_DEVICE_PPU_MMIO_MAX_DEGREE;

const BLOCK_MEMORY_AUX_START: usize = BLOCK_DEVICE_PPU_MMIO_COLUMN_COUNT;
pub(crate) const BLOCK_MEMORY_ROW_BITS_START: usize = BLOCK_MEMORY_AUX_START + ROW_BITS_START;

const _: () = assert!(BASIC_BLOCK_BUS_EVENT_BOUND == 5);
const _: () = assert!(ISA_ADDRESS_BIT_COUNT == 9);
const _: () = assert!(ISA_OUTPUT_COUNT == 38);
const _: () = assert!(UNIFORM_NUM_VARIABLES == 14);
const _: () = assert!(TRACE_MEMORY_TIMESTAMP_BITS == 17);
const _: () = assert!(ROM_ADDRESS_BIT_COUNT == 20);
const _: () = assert!(MEMORY_IMAGE_BYTES == 1 << TRACE_MEMORY_TIMESTAMP_BITS);
const _: () = assert!(SLOT_WIDTH == 36);
const _: () = assert!(BLOCK_MEMORY_AUX_COLUMN_COUNT == 204);
const _: () = assert!(BLOCK_MEMORY_ADDITIONAL_CONSTRAINT_COUNT == 254);
const _: () = assert!(BLOCK_MEMORY_COLUMN_COUNT == 3_542);
const _: () = assert!(BLOCK_MEMORY_CONSTRAINT_COUNT == 8_257);
const _: () = assert!(BLOCK_MEMORY_MAX_DEGREE == 15);

/// Fixed-row packed-block witness carrying ordered mutable-memory timestamps.
#[derive(Debug)]
pub struct BlockMemoryWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
    bus_event_count: usize,
    instruction_count: usize,
    initial_state: VmState,
    final_state: VmState,
    final_memory_timestamps: Vec<u64>,
}

/// Failure to construct the packed mutable-memory chronology witness.
#[derive(Debug, Error)]
pub enum BlockMemoryError {
    /// PPU-MMIO relation construction failed.
    #[error("packed-block PPU-MMIO construction failed: {0}")]
    PpuMmio(#[from] BlockDevicePpuMmioError),
    /// A mutable-memory event selected an address outside the 17-bit table.
    #[error("packed mutable-memory address 0x{physical_address:05x} exceeds 17 bits")]
    PhysicalAddressOutOfRange {
        /// Rejected physical byte address.
        physical_address: u32,
    },
    /// A row or event timestamp exceeded the fixed 17-bit chronology.
    #[error("packed mutable-memory timestamp exceeds 17 bits")]
    TimestampOverflow,
    /// Packed mutable-memory columns violated their fixed layout.
    #[error("packed mutable-memory witness violated its typed layout")]
    Layout,
}

/// PPU-MMIO relation plus strict packed mutable-memory event chronology.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockMemoryRelation;

impl BlockMemoryWitness {
    /// Encodes all packed memory events and the final per-address timestamps.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockMemoryError> {
        let ppu = BlockDevicePpuMmioWitness::from_blocks(blocks)?;
        let active_block_count = ppu.active_block_count();
        let bus_event_count = blocks.iter().try_fold(0_usize, |count, block| {
            count
                .checked_add(block.bus_event_count())
                .ok_or(BlockMemoryError::Layout)
        })?;
        let instruction_count = blocks.iter().try_fold(0_usize, |count, block| {
            count
                .checked_add(block.instruction_count())
                .ok_or(BlockMemoryError::Layout)
        })?;
        let initial_state = blocks
            .first()
            .map(BasicBlock::initial_state)
            .ok_or(BlockMemoryError::Layout)?;
        let final_state = blocks
            .last()
            .map(BasicBlock::final_state)
            .ok_or(BlockMemoryError::Layout)?;
        let mut auxiliary = (0..BLOCK_MEMORY_AUX_COLUMN_COUNT)
            .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
            .collect::<Vec<_>>();
        let mut timestamps = vec![0_u64; MEMORY_IMAGE_BYTES];
        for row_index in 0..UNIFORM_ROW_COUNT {
            let mut row = [0_u64; BLOCK_MEMORY_AUX_COLUMN_COUNT];
            append_bits(
                &mut row,
                ROW_BITS_START,
                u64::try_from(row_index).map_err(|_| BlockMemoryError::TimestampOverflow)?,
                UNIFORM_NUM_VARIABLES,
            )?;
            if let Some(block) = blocks.get(row_index) {
                append_block_events(&mut row, block, row_index, &mut timestamps)?;
            }
            for (column, value) in auxiliary.iter_mut().zip(row) {
                column.push(value);
            }
        }
        let mut columns = ppu.into_columns();
        columns.extend(auxiliary);
        if columns.len() != BLOCK_MEMORY_COLUMN_COUNT {
            return Err(BlockMemoryError::Layout);
        }
        Ok(Self {
            columns,
            active_block_count,
            bus_event_count,
            instruction_count,
            initial_state,
            final_state,
            final_memory_timestamps: timestamps,
        })
    }

    /// Returns every logical column in PPU-MMIO-then-memory order.
    #[must_use]
    pub fn columns(&self) -> &[Vec<u64>] {
        &self.columns
    }

    /// Returns the number of non-padding packed-block rows.
    #[must_use]
    pub const fn active_block_count(&self) -> usize {
        self.active_block_count
    }

    /// Returns the exact number of active shared-bus slots.
    #[must_use]
    pub const fn bus_event_count(&self) -> usize {
        self.bus_event_count
    }

    /// Returns the exact number of active fixed-ISA lanes.
    #[must_use]
    pub const fn instruction_count(&self) -> usize {
        self.instruction_count
    }

    /// Returns the exact VM boundary before the first packed block.
    #[must_use]
    pub const fn initial_state(&self) -> VmState {
        self.initial_state
    }

    /// Returns the exact VM boundary after the final packed block.
    #[must_use]
    pub const fn final_state(&self) -> VmState {
        self.final_state
    }

    /// Returns the last packed event timestamp for every mutable byte.
    #[must_use]
    pub fn final_memory_timestamps(&self) -> &[u64] {
        &self.final_memory_timestamps
    }

    /// Returns one lane's fixed-ISA lookup layout in the full packed-memory plane.
    pub fn lane_isa_lookup_columns(
        lane: BasicBlockLaneIndex,
    ) -> Result<IsaLookupColumns, BlockFrontendError> {
        BlockFrontendWitness::lane_lookup_columns(lane)
    }

    /// Returns the immutable-ROM lookup layout in the full packed-memory plane.
    pub fn rom_lookup_columns() -> Result<RomLookupColumns, BlockFrontendError> {
        BlockFrontendWitness::rom_lookup_columns()
    }

    pub(crate) fn into_columns_and_timestamps(self) -> (Vec<Vec<u64>>, Vec<u64>) {
        (self.columns, self.final_memory_timestamps)
    }
}

impl UniformRelation for BlockMemoryRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-memory-chronology/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [3_338_u64, 8_003, 204, 254, 5, 17, 14, 3_542, 8_257, 4] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_MEMORY_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_MEMORY_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_MEMORY_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_MEMORY_COLUMN_COUNT
            || constraints.len() != BLOCK_MEMORY_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let ppu = row
            .get(..BLOCK_DEVICE_PPU_MMIO_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let auxiliary = row
            .get(BLOCK_MEMORY_AUX_START..BLOCK_MEMORY_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let (ppu_constraints, memory_constraints) =
            constraints.split_at_mut(BLOCK_DEVICE_PPU_MMIO_CONSTRAINT_COUNT);
        BlockDevicePpuMmioRelation.evaluate(ppu, ppu_constraints)?;
        constrain_memory(ppu, auxiliary, memory_constraints)
    }
}

fn append_block_events(
    row: &mut [u64],
    block: &BasicBlock,
    row_index: usize,
    timestamps: &mut [u64],
) -> Result<(), BlockMemoryError> {
    let mut slot = 0_usize;
    for source in block.rows() {
        for event in source.effects().ordered_bus_events() {
            if slot >= BASIC_BLOCK_BUS_EVENT_BOUND {
                return Err(BlockMemoryError::Layout);
            }
            append_log_selectors(row, slot, event.kind())?;
            let event = event.transcript_event();
            if MEMORY_KIND_CODES.contains(&event.kind) {
                append_memory_event(row, row_index, slot, event, timestamps)?;
            }
            slot = slot.checked_add(1).ok_or(BlockMemoryError::Layout)?;
        }
    }
    if slot != block.bus_event_count() {
        return Err(BlockMemoryError::Layout);
    }
    Ok(())
}

fn append_log_selectors(
    row: &mut [u64],
    slot: usize,
    kind: BusEventKind,
) -> Result<(), BlockMemoryError> {
    let start = log_selector_start(slot)?;
    set(
        row,
        start + LOG_INPUT_SELECTOR_OFFSET,
        u64::from(matches!(
            kind,
            BusEventKind::InputRead | BusEventKind::DmgJoypadRead
        )),
    )?;
    set(
        row,
        start + LOG_OUTPUT_SELECTOR_OFFSET,
        u64::from(kind == BusEventKind::OutputWrite),
    )
}

fn append_memory_event(
    row: &mut [u64],
    row_index: usize,
    slot: usize,
    event: zksm83_memory::BusTranscriptEvent,
    timestamps: &mut [u64],
) -> Result<(), BlockMemoryError> {
    let address = usize::try_from(event.physical_address).map_err(|_| {
        BlockMemoryError::PhysicalAddressOutOfRange {
            physical_address: event.physical_address,
        }
    })?;
    let predecessor =
        timestamps
            .get(address)
            .copied()
            .ok_or(BlockMemoryError::PhysicalAddressOutOfRange {
                physical_address: event.physical_address,
            })?;
    let current = current_timestamp(row_index, slot)?;
    let delta = current
        .checked_sub(predecessor)
        .and_then(|value| value.checked_sub(1))
        .ok_or(BlockMemoryError::TimestampOverflow)?;
    *timestamps
        .get_mut(address)
        .ok_or(BlockMemoryError::PhysicalAddressOutOfRange {
            physical_address: event.physical_address,
        })? = current;
    let start = slot_start(slot)?;
    set(row, start + SLOT_SELECTOR_OFFSET, 1)?;
    set(
        row,
        start + SLOT_WRITE_SELECTOR_OFFSET,
        u64::from(MEMORY_WRITE_KIND_CODES.contains(&event.kind)),
    )?;
    append_bits(
        row,
        start + SLOT_PREDECESSOR_BITS_OFFSET,
        predecessor,
        TRACE_MEMORY_TIMESTAMP_BITS,
    )?;
    append_bits(
        row,
        start + SLOT_DELTA_BITS_OFFSET,
        delta,
        TRACE_MEMORY_TIMESTAMP_BITS,
    )
}

fn current_timestamp(row: usize, slot: usize) -> Result<u64, BlockMemoryError> {
    let timestamp = row
        .checked_mul(BASIC_BLOCK_BUS_EVENT_BOUND)
        .and_then(|value| value.checked_add(slot))
        .and_then(|value| value.checked_add(1))
        .ok_or(BlockMemoryError::TimestampOverflow)?;
    if timestamp >= MEMORY_IMAGE_BYTES {
        return Err(BlockMemoryError::TimestampOverflow);
    }
    u64::try_from(timestamp).map_err(|_| BlockMemoryError::TimestampOverflow)
}

fn constrain_memory(
    ppu: &[NativeField],
    auxiliary: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if auxiliary.len() != BLOCK_MEMORY_AUX_COLUMN_COUNT
        || constraints.len() != BLOCK_MEMORY_ADDITIONAL_CONSTRAINT_COUNT
    {
        return Err(UniformError::Shape);
    }
    let bus = ppu
        .get(BLOCK_ISA_CONTROL_COLUMN_COUNT..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let boundary = ppu
        .get(BLOCK_ROUTING_COLUMN_COUNT..BLOCK_CONTROL_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let mut sink = ConstraintSink::new(constraints);
    for bit in 0..UNIFORM_NUM_VARIABLES {
        sink.push(boolean(value(auxiliary, ROW_BITS_START + bit)?))?;
    }
    let row_index = packed_bits(auxiliary, ROW_BITS_START, UNIFORM_NUM_VARIABLES)?;
    let initial_input = local_state_value(boundary, 0, STATE_INPUT_NEXT_INDEX)?;
    let initial_output = local_state_value(boundary, 0, STATE_OUTPUT_NEXT_INDEX)?;
    let mut prior_input = NativeField::from_u64(0);
    let mut prior_output = NativeField::from_u64(0);
    for slot in 0..BASIC_BLOCK_BUS_EVENT_BOUND {
        constrain_memory_slot(bus, auxiliary, row_index, slot, &mut sink)?;
        let (input, output) = constrain_log_slot(
            bus,
            auxiliary,
            initial_input + prior_input,
            initial_output + prior_output,
            slot,
            &mut sink,
        )?;
        prior_input += input;
        prior_output += output;
    }
    sink.finish()
}

fn constrain_memory_slot(
    bus: &[NativeField],
    auxiliary: &[NativeField],
    row_index: NativeField,
    slot: usize,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let start = slot_start_uniform(slot)?;
    let selected = value(auxiliary, start + SLOT_SELECTOR_OFFSET)?;
    let write = value(auxiliary, start + SLOT_WRITE_SELECTOR_OFFSET)?;
    sink.push(boolean(selected))?;
    sink.push(boolean(write))?;
    sink.push(selected - kind_selector_sum(bus, slot, &MEMORY_KIND_CODES)?)?;
    sink.push(write - kind_selector_sum(bus, slot, &MEMORY_WRITE_KIND_CODES)?)?;
    for bit in 0..TRACE_MEMORY_TIMESTAMP_BITS {
        sink.push(
            (one - selected) * value(auxiliary, start + SLOT_PREDECESSOR_BITS_OFFSET + bit)?,
        )?;
        sink.push((one - selected) * value(auxiliary, start + SLOT_DELTA_BITS_OFFSET + bit)?)?;
    }
    let predecessor = packed_bits(
        auxiliary,
        start + SLOT_PREDECESSOR_BITS_OFFSET,
        TRACE_MEMORY_TIMESTAMP_BITS,
    )?;
    let delta = packed_bits(
        auxiliary,
        start + SLOT_DELTA_BITS_OFFSET,
        TRACE_MEMORY_TIMESTAMP_BITS,
    )?;
    let slot_number = u64::try_from(slot).map_err(|_| UniformError::Shape)?;
    let current = row_index * NativeField::from_u64(BASIC_BLOCK_BUS_EVENT_BOUND as u64)
        + NativeField::from_u64(slot_number + 1);
    sink.push(selected * (current - predecessor - delta - one))?;
    for bit in MEMORY_PHYSICAL_ADDRESS_BITS..ROM_ADDRESS_BIT_COUNT {
        sink.push(selected * slot_physical_address_bit(bus, slot, bit)?)?;
    }
    Ok(())
}

fn constrain_log_slot(
    bus: &[NativeField],
    auxiliary: &[NativeField],
    expected_input: NativeField,
    expected_output: NativeField,
    slot: usize,
    sink: &mut ConstraintSink<'_>,
) -> Result<(NativeField, NativeField), UniformError> {
    let start = log_selector_start_uniform(slot)?;
    let input = value(auxiliary, start + LOG_INPUT_SELECTOR_OFFSET)?;
    let output = value(auxiliary, start + LOG_OUTPUT_SELECTOR_OFFSET)?;
    sink.push(boolean(input))?;
    sink.push(boolean(output))?;
    sink.push(input - kind_selector_sum(bus, slot, &INPUT_KIND_CODES)?)?;
    sink.push(output - kind_selector_sum(bus, slot, &OUTPUT_KIND_CODES)?)?;
    let event_index = crate::block_bus::slot_index_value(bus, slot)?;
    sink.push(input * (event_index - expected_input))?;
    sink.push(output * (event_index - expected_output))?;
    Ok((input, output))
}

fn kind_selector_sum(
    row: &[NativeField],
    slot: usize,
    codes: &[u8],
) -> Result<NativeField, UniformError> {
    codes
        .iter()
        .copied()
        .try_fold(NativeField::from_u64(0), |sum, code| {
            Ok(sum + slot_kind_selector(row, slot, code)?)
        })
}

fn slot_start(slot: usize) -> Result<usize, BlockMemoryError> {
    SLOT_START
        .checked_add(
            slot.checked_mul(SLOT_WIDTH)
                .ok_or(BlockMemoryError::Layout)?,
        )
        .ok_or(BlockMemoryError::Layout)
}

fn slot_start_uniform(slot: usize) -> Result<usize, UniformError> {
    SLOT_START
        .checked_add(slot.checked_mul(SLOT_WIDTH).ok_or(UniformError::Shape)?)
        .ok_or(UniformError::Shape)
}

fn log_selector_start(slot: usize) -> Result<usize, BlockMemoryError> {
    LOG_SELECTOR_START
        .checked_add(
            slot.checked_mul(LOG_SELECTOR_WIDTH)
                .ok_or(BlockMemoryError::Layout)?,
        )
        .ok_or(BlockMemoryError::Layout)
}

fn log_selector_start_uniform(slot: usize) -> Result<usize, UniformError> {
    LOG_SELECTOR_START
        .checked_add(
            slot.checked_mul(LOG_SELECTOR_WIDTH)
                .ok_or(UniformError::Shape)?,
        )
        .ok_or(UniformError::Shape)
}

fn append_bits(
    row: &mut [u64],
    start: usize,
    packed: u64,
    width: usize,
) -> Result<(), BlockMemoryError> {
    for bit in 0..width {
        set(
            row,
            start.checked_add(bit).ok_or(BlockMemoryError::Layout)?,
            packed >> bit & 1,
        )?;
    }
    Ok(())
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), BlockMemoryError> {
    *row.get_mut(index).ok_or(BlockMemoryError::Layout)? = value;
    Ok(())
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

fn boolean(value: NativeField) -> NativeField {
    value * (value - NativeField::from_u64(1))
}

fn value(row: &[NativeField], index: usize) -> Result<NativeField, UniformError> {
    row.get(index).copied().ok_or(UniformError::Shape)
}

pub(crate) fn memory_row_index_value(row: &[NativeField]) -> Result<NativeField, UniformError> {
    if row.len() < BLOCK_MEMORY_COLUMN_COUNT {
        return Err(UniformError::Shape);
    }
    packed_bits(row, BLOCK_MEMORY_ROW_BITS_START, UNIFORM_NUM_VARIABLES)
}

pub(crate) fn memory_selector_value(
    row: &[NativeField],
    slot: usize,
) -> Result<NativeField, UniformError> {
    memory_auxiliary_value(row, slot_start_uniform(slot)? + SLOT_SELECTOR_OFFSET)
}

pub(crate) fn memory_write_selector_value(
    row: &[NativeField],
    slot: usize,
) -> Result<NativeField, UniformError> {
    memory_auxiliary_value(row, slot_start_uniform(slot)? + SLOT_WRITE_SELECTOR_OFFSET)
}

pub(crate) fn memory_predecessor_value(
    row: &[NativeField],
    slot: usize,
) -> Result<NativeField, UniformError> {
    let start = BLOCK_MEMORY_AUX_START
        .checked_add(slot_start_uniform(slot)?)
        .and_then(|value| value.checked_add(SLOT_PREDECESSOR_BITS_OFFSET))
        .ok_or(UniformError::Shape)?;
    packed_bits(row, start, TRACE_MEMORY_TIMESTAMP_BITS)
}

pub(crate) fn memory_selector_column(slot: usize) -> Result<usize, UniformError> {
    memory_column_index(slot, SLOT_SELECTOR_OFFSET)
}

pub(crate) fn memory_write_selector_column(slot: usize) -> Result<usize, UniformError> {
    memory_column_index(slot, SLOT_WRITE_SELECTOR_OFFSET)
}

pub(crate) fn memory_predecessor_bit_column(
    slot: usize,
    bit: usize,
) -> Result<usize, UniformError> {
    if bit >= TRACE_MEMORY_TIMESTAMP_BITS {
        return Err(UniformError::Shape);
    }
    memory_column_index(
        slot,
        SLOT_PREDECESSOR_BITS_OFFSET
            .checked_add(bit)
            .ok_or(UniformError::Shape)?,
    )
}

fn memory_column_index(slot: usize, relative: usize) -> Result<usize, UniformError> {
    BLOCK_MEMORY_AUX_START
        .checked_add(slot_start_uniform(slot)?)
        .and_then(|value| value.checked_add(relative))
        .ok_or(UniformError::Shape)
}

fn memory_auxiliary_value(
    row: &[NativeField],
    relative: usize,
) -> Result<NativeField, UniformError> {
    if row.len() < BLOCK_MEMORY_COLUMN_COUNT {
        return Err(UniformError::Shape);
    }
    let index = BLOCK_MEMORY_AUX_START
        .checked_add(relative)
        .ok_or(UniformError::Shape)?;
    value(row, index)
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

    fn push(&mut self, constraint: NativeField) -> Result<(), UniformError> {
        *self
            .constraints
            .get_mut(self.next)
            .ok_or(UniformError::Shape)? = constraint;
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
