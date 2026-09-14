//! Shared ordered-bus plane for bounded packed SM83 blocks.

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_trace::{BASIC_BLOCK_BUS_EVENT_BOUND, BasicBlock};

use crate::{
    ConstraintOutput, NativeField, ROM_ADDRESS_BIT_COUNT, RomLookupColumns, RomLookupError,
    TRACE_BUS_KIND_BITS, TRACE_BUS_SLOT_WIDTH, UNIFORM_ROW_COUNT, UniformError, UniformRelation,
    block_metadata::{
        self, BLOCK_METADATA_COLUMN_COUNT, BLOCK_METADATA_CONSTRAINT_COUNT, BlockMetadata,
    },
};

/// Logical columns in the shared packed-block bus plane.
pub const BLOCK_BUS_COLUMN_COUNT: usize = 336;
/// Identities in the shared packed-block bus relation.
pub const BLOCK_BUS_CONSTRAINT_COUNT: usize = 380;
/// Maximum total degree of a shared packed-block bus identity.
pub const BLOCK_BUS_MAX_DEGREE: usize = 5;

const BUS_START: usize = BLOCK_METADATA_COLUMN_COUNT;
const ADDRESS_BITS_START: usize = BUS_START + BASIC_BLOCK_BUS_EVENT_BOUND * TRACE_BUS_SLOT_WIDTH;
const PHYSICAL_BITS_START: usize = ADDRESS_BITS_START + BASIC_BLOCK_BUS_EVENT_BOUND * 16;
const VALUE_BITS_START: usize =
    PHYSICAL_BITS_START + BASIC_BLOCK_BUS_EVENT_BOUND * ROM_ADDRESS_BIT_COUNT;
const BEFORE_BITS_START: usize = VALUE_BITS_START + BASIC_BLOCK_BUS_EVENT_BOUND * 8;
const ROM_SELECTOR_START: usize = BEFORE_BITS_START + BASIC_BLOCK_BUS_EVENT_BOUND * 8;
const ROM_VALUE_START: usize = ROM_SELECTOR_START + BASIC_BLOCK_BUS_EVENT_BOUND;
const COLUMN_END: usize = ROM_VALUE_START + BASIC_BLOCK_BUS_EVENT_BOUND;

const BUS_ADDRESS_OFFSET: usize = 1 + TRACE_BUS_KIND_BITS;
const BUS_PHYSICAL_OFFSET: usize = BUS_ADDRESS_OFFSET + 1;
const BUS_BEFORE_OFFSET: usize = BUS_ADDRESS_OFFSET + 2;
const BUS_AUXILIARY_OFFSET: usize = BUS_ADDRESS_OFFSET + 3;
const BUS_VALUE_OFFSET: usize = BUS_ADDRESS_OFFSET + 4;
const BUS_INDEX_OFFSET: usize = BUS_ADDRESS_OFFSET + 5;
const BUS_TUPLE_FIELDS: usize = 6;

const _: () = assert!(BASIC_BLOCK_BUS_EVENT_BOUND == 5);
const _: () = assert!(TRACE_BUS_KIND_BITS == 5);
const _: () = assert!(TRACE_BUS_SLOT_WIDTH == 12);
const _: () = assert!(ROM_ADDRESS_BIT_COUNT == 20);
const _: () = assert!(COLUMN_END == BLOCK_BUS_COLUMN_COUNT);
const _: () = assert!(BLOCK_BUS_CONSTRAINT_COUNT == 380);

/// Fixed-row shared bus witness derived from validated owned blocks.
#[derive(Debug)]
pub struct BlockBusWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to encode or describe the shared packed-block bus witness.
#[derive(Debug, Error)]
pub enum BlockBusError {
    /// At least one validated block is required.
    #[error("packed-block bus witness is empty")]
    Empty,
    /// The block count exceeds the fixed relation row capacity.
    #[error("packed-block bus witness has {actual} rows, maximum is {maximum}")]
    TooManyBlocks {
        /// Supplied block count.
        actual: usize,
        /// Fixed relation capacity.
        maximum: usize,
    },
    /// One block contains more ordered bus events than the universal shared bound.
    #[error("packed block {block} has {actual} bus events, maximum is {maximum}")]
    TooManyBusEvents {
        /// Zero-based packed-block row.
        block: usize,
        /// Supplied ordered event count.
        actual: usize,
        /// Universal shared event bound.
        maximum: usize,
    },
    /// A block exposed an inconsistent event or column layout.
    #[error("packed-block bus witness violated its typed layout")]
    Layout,
    /// Construction of the shared ROM lookup descriptor failed.
    #[error(transparent)]
    RomLookup(#[from] RomLookupError),
}

/// Low-degree relation for canonical shared bus tuples and decompositions.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockBusRelation;

impl BlockBusWitness {
    /// Encodes every block's ordered bus events and appends all-zero padding rows.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockBusError> {
        if blocks.is_empty() {
            return Err(BlockBusError::Empty);
        }
        if blocks.len() > UNIFORM_ROW_COUNT {
            return Err(BlockBusError::TooManyBlocks {
                actual: blocks.len(),
                maximum: UNIFORM_ROW_COUNT,
            });
        }
        let mut columns = (0..BLOCK_BUS_COLUMN_COUNT)
            .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
            .collect::<Vec<_>>();
        for (block_index, block) in blocks.iter().enumerate() {
            append_block(&mut columns, block, block_index)?;
        }
        for column in &mut columns {
            column.resize(UNIFORM_ROW_COUNT, 0);
        }
        Ok(Self {
            columns,
            active_block_count: blocks.len(),
        })
    }

    /// Returns every logical column in metadata-then-bus order.
    #[must_use]
    pub fn columns(&self) -> &[Vec<u64>] {
        &self.columns
    }

    /// Returns the number of non-padding block rows.
    #[must_use]
    pub const fn active_block_count(&self) -> usize {
        self.active_block_count
    }

    /// Returns the five-slot immutable-ROM lookup layout in this bus plane.
    pub fn rom_lookup_columns() -> Result<RomLookupColumns, BlockBusError> {
        let mut selectors = [0_usize; BASIC_BLOCK_BUS_EVENT_BOUND];
        let mut values = [0_usize; BASIC_BLOCK_BUS_EVENT_BOUND];
        let mut address_bits = [[0_usize; ROM_ADDRESS_BIT_COUNT]; BASIC_BLOCK_BUS_EVENT_BOUND];
        for slot in 0..BASIC_BLOCK_BUS_EVENT_BOUND {
            *selectors.get_mut(slot).ok_or(BlockBusError::Layout)? =
                checked_index(ROM_SELECTOR_START, slot)?;
            *values.get_mut(slot).ok_or(BlockBusError::Layout)? =
                checked_index(ROM_VALUE_START, slot)?;
            for bit in 0..ROM_ADDRESS_BIT_COUNT {
                let offset = slot
                    .checked_mul(ROM_ADDRESS_BIT_COUNT)
                    .and_then(|value| value.checked_add(bit))
                    .ok_or(BlockBusError::Layout)?;
                *address_bits
                    .get_mut(slot)
                    .and_then(|bits| bits.get_mut(bit))
                    .ok_or(BlockBusError::Layout)? = checked_index(PHYSICAL_BITS_START, offset)?;
            }
        }
        RomLookupColumns::new(selectors, address_bits, values).map_err(Into::into)
    }

    pub(crate) fn into_columns(self) -> Vec<Vec<u64>> {
        self.columns
    }
}

impl UniformRelation for BlockBusRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-bus/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [5_u64, 5, 12, 20, 336, 380] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_BUS_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_BUS_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_BUS_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_BUS_COLUMN_COUNT || constraints.len() != BLOCK_BUS_CONSTRAINT_COUNT {
            return Err(UniformError::Shape);
        }
        let (metadata_constraints, bus_constraints) =
            constraints.split_at_mut(BLOCK_METADATA_CONSTRAINT_COUNT);
        block_metadata::evaluate(row, metadata_constraints)?;
        let mut sink = ConstraintSink::new(bus_constraints);
        constrain_bus(row, &mut sink)?;
        sink.finish()
    }
}

fn append_block(
    columns: &mut [Vec<u64>],
    block: &BasicBlock,
    block_index: usize,
) -> Result<(), BlockBusError> {
    let mut row = [0_u64; BLOCK_BUS_COLUMN_COUNT];
    BlockMetadata::from_block(block)
        .and_then(|metadata| metadata.write_to(&mut row))
        .ok_or(BlockBusError::Layout)?;
    let event_count = block
        .rows()
        .try_fold(0_usize, |count, source| {
            count.checked_add(source.effects().ordered_bus_events().len())
        })
        .ok_or(BlockBusError::Layout)?;
    if event_count > BASIC_BLOCK_BUS_EVENT_BOUND {
        return Err(BlockBusError::TooManyBusEvents {
            block: block_index,
            actual: event_count,
            maximum: BASIC_BLOCK_BUS_EVENT_BOUND,
        });
    }
    let mut slot = 0_usize;
    for source in block.rows() {
        for event in source.effects().ordered_bus_events() {
            append_event(&mut row, slot, event)?;
            slot = slot.checked_add(1).ok_or(BlockBusError::Layout)?;
        }
    }
    if slot != event_count {
        return Err(BlockBusError::Layout);
    }
    for (column, value) in columns.iter_mut().zip(row) {
        column.push(value);
    }
    Ok(())
}

fn append_event(
    row: &mut [u64],
    slot: usize,
    event: &zksm83_core::BusEvent,
) -> Result<(), BlockBusError> {
    let start = slot_start(slot).ok_or(BlockBusError::Layout)?;
    set(row, start, 1)?;
    let code = event.kind().code();
    append_bits(
        row,
        checked_index(start, 1)?,
        u64::from(code),
        TRACE_BUS_KIND_BITS,
    )?;
    let event = event.transcript_event();
    for (offset, value) in [
        u64::from(event.address),
        u64::from(event.physical_address),
        u64::from(event.before),
        u64::from(event.auxiliary),
        u64::from(event.value),
        event.index,
    ]
    .into_iter()
    .enumerate()
    {
        set(
            row,
            checked_index(start, 1 + TRACE_BUS_KIND_BITS + offset)?,
            value,
        )?;
    }
    append_slot_bits(row, slot, event)?;
    let rom = matches!(code, 1 | 2 | 3 | 16);
    set(
        row,
        checked_index(ROM_SELECTOR_START, slot)?,
        u64::from(rom),
    )?;
    set(
        row,
        checked_index(ROM_VALUE_START, slot)?,
        u64::from(rom) * u64::from(event.value),
    )
}

fn append_slot_bits(
    row: &mut [u64],
    slot: usize,
    event: zksm83_memory::BusTranscriptEvent,
) -> Result<(), BlockBusError> {
    append_bits(
        row,
        slot_bit_start(ADDRESS_BITS_START, slot, 16)?,
        u64::from(event.address),
        16,
    )?;
    append_bits(
        row,
        slot_bit_start(PHYSICAL_BITS_START, slot, ROM_ADDRESS_BIT_COUNT)?,
        u64::from(event.physical_address),
        ROM_ADDRESS_BIT_COUNT,
    )?;
    append_bits(
        row,
        slot_bit_start(VALUE_BITS_START, slot, 8)?,
        u64::from(event.value),
        8,
    )?;
    append_bits(
        row,
        slot_bit_start(BEFORE_BITS_START, slot, 8)?,
        u64::from(event.before),
        8,
    )
}

fn append_bits(
    row: &mut [u64],
    start: usize,
    value: u64,
    width: usize,
) -> Result<(), BlockBusError> {
    for bit in 0..width {
        set(row, checked_index(start, bit)?, (value >> bit) & 1)?;
    }
    Ok(())
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), BlockBusError> {
    *row.get_mut(index).ok_or(BlockBusError::Layout)? = value;
    Ok(())
}

fn constrain_bus(row: &[NativeField], sink: &mut ConstraintSink<'_>) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let mut active = [NativeField::from_u64(0); BASIC_BLOCK_BUS_EVENT_BOUND];
    for slot in 0..BASIC_BLOCK_BUS_EVENT_BOUND {
        let slot_active = slot_active_value(row, slot)?;
        let kind_bits = slot_kind_bits(row, slot)?;
        sink.push(boolean(slot_active))?;
        for bit in kind_bits {
            sink.push(boolean(*bit))?;
        }
        let mut valid = NativeField::from_u64(0);
        for code in 0..=18 {
            valid += bit_selector(kind_bits, code)?;
        }
        sink.push(valid - one)?;
        sink.push(slot_active - (one - bit_selector(kind_bits, 0)?))?;
        let start = slot_start(slot).ok_or(UniformError::Shape)?;
        for offset in BUS_ADDRESS_OFFSET..BUS_ADDRESS_OFFSET + BUS_TUPLE_FIELDS {
            sink.push((one - slot_active) * value(row, checked_add(start, offset)?)?)?;
        }
        constrain_slot_decompositions(row, sink, slot, start)?;
        let rom = value(row, checked_add(ROM_SELECTOR_START, slot)?)?;
        let expected_rom = [1_u8, 2, 3, 16]
            .into_iter()
            .try_fold(NativeField::from_u64(0), |sum, code| {
                Ok::<_, UniformError>(sum + bit_selector(kind_bits, code)?)
            })?;
        sink.push(boolean(rom))?;
        sink.push(rom - expected_rom)?;
        sink.push(
            value(row, checked_add(ROM_VALUE_START, slot)?)?
                - rom * value(row, checked_add(start, BUS_VALUE_OFFSET)?)?,
        )?;
        *active.get_mut(slot).ok_or(UniformError::Shape)? = slot_active;
    }
    for pair in active.windows(2) {
        let prior = pair.first().copied().ok_or(UniformError::Shape)?;
        let next = pair.get(1).copied().ok_or(UniformError::Shape)?;
        sink.push(next * (one - prior))?;
    }
    Ok(())
}

fn constrain_slot_decompositions(
    row: &[NativeField],
    sink: &mut ConstraintSink<'_>,
    slot: usize,
    tuple_start: usize,
) -> Result<(), UniformError> {
    for (bits_start, width, tuple_offset) in [
        (ADDRESS_BITS_START, 16, BUS_ADDRESS_OFFSET),
        (
            PHYSICAL_BITS_START,
            ROM_ADDRESS_BIT_COUNT,
            BUS_PHYSICAL_OFFSET,
        ),
        (VALUE_BITS_START, 8, BUS_VALUE_OFFSET),
        (BEFORE_BITS_START, 8, BUS_BEFORE_OFFSET),
    ] {
        let start = slot_bit_start_uniform(bits_start, slot, width)?;
        let bits = values(row, start, width)?;
        for bit in bits {
            sink.push(boolean(*bit))?;
        }
        sink.push(value(row, checked_add(tuple_start, tuple_offset)?)? - packed_bits(bits))?;
    }
    Ok(())
}

pub(crate) fn slot_active_value(
    row: &[NativeField],
    slot: usize,
) -> Result<NativeField, UniformError> {
    value(row, slot_start(slot).ok_or(UniformError::Shape)?)
}

pub(crate) fn slot_field_value(
    row: &[NativeField],
    slot: usize,
    offset: usize,
) -> Result<NativeField, UniformError> {
    if offset >= TRACE_BUS_SLOT_WIDTH {
        return Err(UniformError::Shape);
    }
    let start = slot_start(slot).ok_or(UniformError::Shape)?;
    value(row, checked_add(start, offset)?)
}

pub(crate) fn slot_active_column(slot: usize) -> Result<usize, UniformError> {
    slot_start(slot).ok_or(UniformError::Shape)
}

pub(crate) fn slot_kind_selector(
    row: &[NativeField],
    slot: usize,
    code: u8,
) -> Result<NativeField, UniformError> {
    bit_selector(slot_kind_bits(row, slot)?, code)
}

pub(crate) fn slot_kind_bit_column(slot: usize, bit: usize) -> Result<usize, UniformError> {
    if bit >= TRACE_BUS_KIND_BITS {
        return Err(UniformError::Shape);
    }
    let start = slot_start(slot)
        .and_then(|value| value.checked_add(1))
        .ok_or(UniformError::Shape)?;
    checked_add(start, bit)
}

pub(crate) fn slot_address_value(
    row: &[NativeField],
    slot: usize,
) -> Result<NativeField, UniformError> {
    let start = slot_start(slot).ok_or(UniformError::Shape)?;
    value(row, checked_add(start, BUS_ADDRESS_OFFSET)?)
}

pub(crate) fn slot_address_column(slot: usize) -> Result<usize, UniformError> {
    let start = slot_start(slot).ok_or(UniformError::Shape)?;
    checked_add(start, BUS_ADDRESS_OFFSET)
}

pub(crate) fn slot_value_value(
    row: &[NativeField],
    slot: usize,
) -> Result<NativeField, UniformError> {
    value(row, slot_value_column(slot)?)
}

pub(crate) fn slot_before_value(
    row: &[NativeField],
    slot: usize,
) -> Result<NativeField, UniformError> {
    value(row, slot_before_column(slot)?)
}

pub(crate) fn slot_physical_address_value(
    row: &[NativeField],
    slot: usize,
) -> Result<NativeField, UniformError> {
    value(row, slot_physical_address_column(slot)?)
}

pub(crate) fn slot_value_column(slot: usize) -> Result<usize, UniformError> {
    let start = slot_start(slot).ok_or(UniformError::Shape)?;
    checked_add(start, BUS_VALUE_OFFSET)
}

pub(crate) fn slot_before_column(slot: usize) -> Result<usize, UniformError> {
    let start = slot_start(slot).ok_or(UniformError::Shape)?;
    checked_add(start, BUS_BEFORE_OFFSET)
}

pub(crate) fn slot_physical_address_column(slot: usize) -> Result<usize, UniformError> {
    let start = slot_start(slot).ok_or(UniformError::Shape)?;
    checked_add(start, BUS_PHYSICAL_OFFSET)
}

pub(crate) fn slot_index_column(slot: usize) -> Result<usize, UniformError> {
    let start = slot_start(slot).ok_or(UniformError::Shape)?;
    checked_add(start, BUS_INDEX_OFFSET)
}

pub(crate) fn slot_physical_address_bit(
    row: &[NativeField],
    slot: usize,
    bit: usize,
) -> Result<NativeField, UniformError> {
    if slot >= BASIC_BLOCK_BUS_EVENT_BOUND || bit >= ROM_ADDRESS_BIT_COUNT {
        return Err(UniformError::Shape);
    }
    let start = slot_bit_start_uniform(PHYSICAL_BITS_START, slot, ROM_ADDRESS_BIT_COUNT)?;
    value(row, checked_add(start, bit)?)
}

pub(crate) fn slot_address_bit(
    row: &[NativeField],
    slot: usize,
    bit: usize,
) -> Result<NativeField, UniformError> {
    slot_bit_value(row, ADDRESS_BITS_START, slot, bit, 16)
}

pub(crate) fn slot_value_bit(
    row: &[NativeField],
    slot: usize,
    bit: usize,
) -> Result<NativeField, UniformError> {
    slot_bit_value(row, VALUE_BITS_START, slot, bit, 8)
}

pub(crate) fn slot_before_bit(
    row: &[NativeField],
    slot: usize,
    bit: usize,
) -> Result<NativeField, UniformError> {
    slot_bit_value(row, BEFORE_BITS_START, slot, bit, 8)
}

pub(crate) fn slot_rom_selector_value(
    row: &[NativeField],
    slot: usize,
) -> Result<NativeField, UniformError> {
    value(row, checked_add(ROM_SELECTOR_START, slot)?)
}

pub(crate) fn slot_rom_value_value(
    row: &[NativeField],
    slot: usize,
) -> Result<NativeField, UniformError> {
    value(row, checked_add(ROM_VALUE_START, slot)?)
}

pub(crate) fn slot_auxiliary_value(
    row: &[NativeField],
    slot: usize,
) -> Result<NativeField, UniformError> {
    let start = slot_start(slot).ok_or(UniformError::Shape)?;
    value(row, checked_add(start, BUS_AUXILIARY_OFFSET)?)
}

pub(crate) fn slot_auxiliary_column(slot: usize) -> Result<usize, UniformError> {
    let start = slot_start(slot).ok_or(UniformError::Shape)?;
    checked_add(start, BUS_AUXILIARY_OFFSET)
}

pub(crate) fn slot_index_value(
    row: &[NativeField],
    slot: usize,
) -> Result<NativeField, UniformError> {
    value(row, slot_index_column(slot)?)
}

fn slot_bit_value(
    row: &[NativeField],
    start: usize,
    slot: usize,
    bit: usize,
    width: usize,
) -> Result<NativeField, UniformError> {
    if slot >= BASIC_BLOCK_BUS_EVENT_BOUND || bit >= width {
        return Err(UniformError::Shape);
    }
    let start = slot_bit_start_uniform(start, slot, width)?;
    value(row, checked_add(start, bit)?)
}

fn slot_kind_bits(row: &[NativeField], slot: usize) -> Result<&[NativeField], UniformError> {
    let start = slot_start(slot)
        .and_then(|value| value.checked_add(1))
        .ok_or(UniformError::Shape)?;
    values(row, start, TRACE_BUS_KIND_BITS)
}

fn bit_selector(bits: &[NativeField], code: u8) -> Result<NativeField, UniformError> {
    if bits.is_empty() || bits.len() > 8 {
        return Err(UniformError::Shape);
    }
    let one = NativeField::from_u64(1);
    Ok(bits
        .iter()
        .copied()
        .enumerate()
        .fold(one, |selector, (bit, value)| {
            if (code >> bit) & 1 == 1 {
                selector * value
            } else {
                selector * (one - value)
            }
        }))
}

fn packed_bits(bits: &[NativeField]) -> NativeField {
    let mut power = NativeField::from_u64(1);
    let mut packed = NativeField::from_u64(0);
    for bit in bits {
        packed += power * *bit;
        power += power;
    }
    packed
}

fn slot_start(slot: usize) -> Option<usize> {
    slot.checked_mul(TRACE_BUS_SLOT_WIDTH)
        .and_then(|offset| BUS_START.checked_add(offset))
        .filter(|start| {
            start
                .checked_add(TRACE_BUS_SLOT_WIDTH)
                .is_some_and(|end| end <= ADDRESS_BITS_START)
        })
}

fn slot_bit_start(start: usize, slot: usize, width: usize) -> Result<usize, BlockBusError> {
    slot.checked_mul(width)
        .and_then(|offset| start.checked_add(offset))
        .ok_or(BlockBusError::Layout)
}

fn slot_bit_start_uniform(start: usize, slot: usize, width: usize) -> Result<usize, UniformError> {
    slot.checked_mul(width)
        .and_then(|offset| start.checked_add(offset))
        .ok_or(UniformError::Shape)
}

fn checked_index(start: usize, offset: usize) -> Result<usize, BlockBusError> {
    start.checked_add(offset).ok_or(BlockBusError::Layout)
}

fn checked_add(start: usize, offset: usize) -> Result<usize, UniformError> {
    start.checked_add(offset).ok_or(UniformError::Shape)
}

fn values(row: &[NativeField], start: usize, count: usize) -> Result<&[NativeField], UniformError> {
    let end = start.checked_add(count).ok_or(UniformError::Shape)?;
    row.get(start..end).ok_or(UniformError::Shape)
}

fn value(row: &[NativeField], index: usize) -> Result<NativeField, UniformError> {
    row.get(index).copied().ok_or(UniformError::Shape)
}

fn boolean(value: NativeField) -> NativeField {
    value * (value - NativeField::from_u64(1))
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
    use zksm83_memory::{MemoryImage, RomImage};
    use zksm83_trace::{TraceBuilder, Witness, pack_witness_basic_blocks};

    use super::*;
    use crate::{block_test_support::flip_witness_bit, validate_uniform_witness};

    #[test]
    fn shared_bus_plane_preserves_order_and_satisfies_canonical_blocks()
    -> Result<(), Box<dyn std::error::Error>> {
        let rom = RomImage::new(vec![0xcb, 0x00, 0xcb, 0x00])?;
        let memory = MemoryImage::zeroed()?;
        let mut builder = TraceBuilder::new(rom, memory, Vec::new());
        let rows = vec![builder.step()?, builder.step()?];
        let blocks = pack_witness_basic_blocks(Witness::from_rows(rows)?)?;
        let witness = BlockBusWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockBusRelation, witness.columns())?;
        let layout = BlockBusWitness::rom_lookup_columns()?;
        assert!(
            layout
                .selectors()
                .iter()
                .all(|column| *column < BLOCK_BUS_COLUMN_COUNT)
        );
        let mut mutated = witness.columns().to_vec();
        flip_witness_bit(&mut mutated, ADDRESS_BITS_START, 0)?;
        assert!(validate_uniform_witness(&BlockBusRelation, &mutated).is_err());
        Ok(())
    }
}
