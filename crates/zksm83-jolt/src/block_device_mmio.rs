//! Typed DMG MMIO address classification and device-register transitions.

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_core::BusEventKind;
use zksm83_trace::{BASIC_BLOCK_BUS_EVENT_BOUND, BasicBlock};

use crate::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_DEVICE_DMA_COLUMN_COUNT, BLOCK_DEVICE_DMA_CONSTRAINT_COUNT,
    BLOCK_DEVICE_DMA_MAX_DEGREE, BLOCK_FRONTEND_COLUMN_COUNT, BLOCK_ISA_CONTROL_COLUMN_COUNT,
    BLOCK_ROUTING_COLUMN_COUNT, BlockDeviceDmaError, BlockDeviceDmaRelation, BlockDeviceDmaWitness,
    ConstraintOutput, NativeField, STATE_INTERRUPT_ENABLE_INDEX, STATE_INTERRUPT_REQUEST_INDEX,
    STATE_PPU_LINE_INDEX, UNIFORM_ROW_COUNT, UniformError, UniformRelation,
    block_boundary::device_state_value,
    block_bus::{
        slot_address_value, slot_auxiliary_value, slot_before_value, slot_index_value,
        slot_kind_selector, slot_physical_address_value, slot_value_value,
    },
    block_device::device_io_selector_value,
    block_device_dma::dma_state_byte_value,
    block_device_ppu::low_pack_bit_value,
    block_device_serial::high_pack_bit_value,
    block_device_timer::timer_div_bit_value,
};

const MMIO_LOW_ADDRESSES: [u8; 69] = [
    0x00, 0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0xff,
];
const MMIO_AUX_START: usize = BLOCK_DEVICE_DMA_COLUMN_COUNT;
const ADDRESS_BITS_START: usize = 0;
const ADDRESS_BIT_COUNT: usize = 8;
const IO_VALUE: usize = ADDRESS_BITS_START + ADDRESS_BIT_COUNT;
const IO_BEFORE: usize = IO_VALUE + 1;
const IO_AUXILIARY: usize = IO_BEFORE + 1;
const IO_INDEX: usize = IO_AUXILIARY + 1;
const IO_VALUE_BITS_START: usize = IO_INDEX + 1;
const BEFORE_IE_BITS_START: usize = IO_VALUE_BITS_START + 8;
const AFTER_IE_BITS_START: usize = BEFORE_IE_BITS_START + 5;
const MMIO_AUX_COLUMN_COUNT: usize = AFTER_IE_BITS_START + 5;
const MMIO_ADDITIONAL_CONSTRAINT_COUNT: usize = 118;
const MMIO_READ_KIND: u8 = 11;
const MMIO_WRITE_KIND: u8 = 12;
const JOYPAD_READ_KIND: u8 = 13;

/// Logical columns in the DMA relation plus typed MMIO classification.
pub const BLOCK_DEVICE_MMIO_COLUMN_COUNT: usize =
    BLOCK_DEVICE_DMA_COLUMN_COUNT + MMIO_AUX_COLUMN_COUNT;
/// Identities in the typed DMG MMIO relation.
pub const BLOCK_DEVICE_MMIO_CONSTRAINT_COUNT: usize =
    BLOCK_DEVICE_DMA_CONSTRAINT_COUNT + MMIO_ADDITIONAL_CONSTRAINT_COUNT;
/// Maximum total degree in the typed DMG MMIO relation.
pub const BLOCK_DEVICE_MMIO_MAX_DEGREE: usize = 14;

const _: () = assert!(BASIC_BLOCK_BUS_EVENT_BOUND == 5);
const _: () = assert!(BLOCK_DEVICE_DMA_MAX_DEGREE == 7);
const _: () = assert!(MMIO_AUX_COLUMN_COUNT == 30);
const _: () = assert!(BLOCK_DEVICE_MMIO_COLUMN_COUNT == 2_460);
const _: () = assert!(BLOCK_DEVICE_MMIO_CONSTRAINT_COUNT == 5_426);
const _: () = assert!(BLOCK_DEVICE_MMIO_MAX_DEGREE == 14);

/// Fixed-row witness classifying the one typed DMG device access in a block.
#[derive(Debug)]
pub struct BlockDeviceMmioWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to construct the typed packed-block MMIO witness.
#[derive(Debug, Error)]
pub enum BlockDeviceMmioError {
    /// DMA witness construction failed.
    #[error("packed-block DMA construction failed: {0}")]
    Dma(#[from] BlockDeviceDmaError),
    /// A typed event used an address or operation outside the generic DMG register map.
    #[error("packed block {block} has unsupported device event kind {kind} at {address:#06x}")]
    UnsupportedEvent {
        /// Zero-based packed-block row.
        block: usize,
        /// Stable bus-event kind code.
        kind: u8,
        /// CPU-visible address.
        address: u16,
    },
    /// MMIO auxiliary columns violated their fixed layout.
    #[error("packed-block MMIO witness violated its typed layout")]
    Layout,
}

/// DMA relation plus generic MMIO classification and implemented transitions.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockDeviceMmioRelation;

impl BlockDeviceMmioWitness {
    /// Derives typed address and tuple columns from validated packed blocks.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockDeviceMmioError> {
        let dma = BlockDeviceDmaWitness::from_blocks(blocks)?;
        let active_block_count = dma.active_block_count();
        let mut auxiliary = (0..MMIO_AUX_COLUMN_COUNT)
            .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
            .collect::<Vec<_>>();
        for (block_index, block) in blocks.iter().enumerate() {
            let mut row = [0_u64; MMIO_AUX_COLUMN_COUNT];
            append_mmio_row(&mut row, block, block_index)?;
            for (column, value) in auxiliary.iter_mut().zip(row) {
                column.push(value);
            }
        }
        for column in &mut auxiliary {
            column.resize(UNIFORM_ROW_COUNT, 0);
        }
        let mut columns = dma.into_columns();
        columns.extend(auxiliary);
        if columns.len() != BLOCK_DEVICE_MMIO_COLUMN_COUNT {
            return Err(BlockDeviceMmioError::Layout);
        }
        Ok(Self {
            columns,
            active_block_count,
        })
    }

    /// Returns every logical column in DMA-then-MMIO order.
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

impl UniformRelation for BlockDeviceMmioRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-device-mmio/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [2_430_u64, 5_308, 69, 8, 30, 118, 2_460, 5_426, 14] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_DEVICE_MMIO_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_DEVICE_MMIO_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_DEVICE_MMIO_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_DEVICE_MMIO_COLUMN_COUNT
            || constraints.len() != BLOCK_DEVICE_MMIO_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let dma = row
            .get(..BLOCK_DEVICE_DMA_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let auxiliary = row
            .get(MMIO_AUX_START..BLOCK_DEVICE_MMIO_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let (dma_constraints, mmio_constraints) =
            constraints.split_at_mut(BLOCK_DEVICE_DMA_CONSTRAINT_COUNT);
        BlockDeviceDmaRelation.evaluate(dma, dma_constraints)?;
        constrain_mmio(dma, auxiliary, mmio_constraints)
    }
}

fn append_mmio_row(
    row: &mut [u64],
    block: &BasicBlock,
    block_index: usize,
) -> Result<(), BlockDeviceMmioError> {
    for source in block.rows() {
        for event in source.effects().ordered_bus_events() {
            if !matches!(
                event.kind(),
                BusEventKind::DmgMmioRead
                    | BusEventKind::DmgMmioWrite
                    | BusEventKind::DmgJoypadRead
            ) {
                continue;
            }
            let tuple = event.transcript_event();
            let kind = event.kind().code();
            let Some(low) = u8::try_from(tuple.address & 0x00ff).ok() else {
                return Err(BlockDeviceMmioError::Layout);
            };
            MMIO_LOW_ADDRESSES
                .contains(&low)
                .then_some(())
                .filter(|_| tuple.address >> 8 == 0xff)
                .filter(|_| kind != MMIO_READ_KIND || low != 0x00)
                .filter(|_| kind != JOYPAD_READ_KIND || low == 0x00)
                .ok_or(BlockDeviceMmioError::UnsupportedEvent {
                    block: block_index,
                    kind,
                    address: tuple.address,
                })?;
            append_bits(row, ADDRESS_BITS_START, u64::from(low), ADDRESS_BIT_COUNT)?;
            set(row, IO_VALUE, u64::from(tuple.value))?;
            set(row, IO_BEFORE, u64::from(tuple.before))?;
            set(row, IO_AUXILIARY, u64::from(tuple.auxiliary))?;
            set(row, IO_INDEX, tuple.index)?;
            append_bits(row, IO_VALUE_BITS_START, u64::from(tuple.value), 8)?;
            append_bits(
                row,
                BEFORE_IE_BITS_START,
                u64::from(block.initial_state().dmg_devices().interrupt_enable()),
                5,
            )?;
            append_bits(
                row,
                AFTER_IE_BITS_START,
                u64::from(block.final_state().dmg_devices().interrupt_enable()),
                5,
            )?;
        }
    }
    Ok(())
}

fn constrain_mmio(
    dma: &[NativeField],
    auxiliary: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if auxiliary.len() != MMIO_AUX_COLUMN_COUNT
        || constraints.len() != MMIO_ADDITIONAL_CONSTRAINT_COUNT
    {
        return Err(UniformError::Shape);
    }
    let one = NativeField::from_u64(1);
    let device_io = device_io_selector_value(dma)?;
    let mut sink = ConstraintSink::new(constraints);
    for bit in 0..ADDRESS_BIT_COUNT {
        let address_bit = value(auxiliary, ADDRESS_BITS_START + bit)?;
        sink.push(address_bit * (address_bit - one))?;
    }
    let low_address = packed_bits(auxiliary, ADDRESS_BITS_START, ADDRESS_BIT_COUNT)?;
    let supported_address_sum = supported_address_selector_sum(auxiliary)?;
    sink.push(device_io * (supported_address_sum - one))?;
    let io_value = value(auxiliary, IO_VALUE)?;
    let io_before = value(auxiliary, IO_BEFORE)?;
    let io_auxiliary = value(auxiliary, IO_AUXILIARY)?;
    let io_index = value(auxiliary, IO_INDEX)?;
    sink.push((one - device_io) * io_value)?;
    sink.push((one - device_io) * io_before)?;
    sink.push((one - device_io) * io_auxiliary)?;
    sink.push((one - device_io) * io_index)?;
    constrain_value_and_ie_bits(dma, auxiliary, device_io, io_value, &mut sink)?;
    let classified_address = NativeField::from_u64(0xff00) * device_io + low_address;
    let events = selected_events(dma)?;
    sink.push(classified_address - events.address)?;
    sink.push(io_value - events.value)?;
    sink.push(io_before - events.before)?;
    sink.push(io_auxiliary - events.auxiliary)?;
    sink.push(io_index - events.index)?;
    let address_zero = address_selector(auxiliary, 0x00)?;
    sink.push(events.joypad * (one - address_zero))?;
    sink.push(address_zero * events.read)?;
    sink.push(events.read * io_before)?;
    sink.push(events.physical)?;
    sink.push(events.plain_auxiliary)?;
    sink.push(events.plain_index)?;
    constrain_dma_start(
        dma, auxiliary, device_io, io_value, io_before, events, &mut sink,
    )?;
    constrain_interrupt_enable(auxiliary, device_io, io_value, io_before, events, &mut sink)?;
    constrain_direct_register_tuples(dma, auxiliary, io_value, io_before, events, &mut sink)?;
    constrain_packed_register_tuples(dma, auxiliary, io_value, io_before, events, &mut sink)?;
    constrain_stable_packed_registers(dma, auxiliary, device_io, events.write, &mut sink)?;
    sink.finish()
}

fn constrain_value_and_ie_bits(
    dma: &[NativeField],
    auxiliary: &[NativeField],
    device_io: NativeField,
    io_value: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    for start in [
        IO_VALUE_BITS_START,
        BEFORE_IE_BITS_START,
        AFTER_IE_BITS_START,
    ] {
        let width = if start == IO_VALUE_BITS_START { 8 } else { 5 };
        for bit in 0..width {
            let bit_value = value(auxiliary, start + bit)?;
            sink.push(bit_value * (bit_value - one))?;
            sink.push((one - device_io) * bit_value)?;
        }
    }
    sink.push(io_value - packed_bits(auxiliary, IO_VALUE_BITS_START, 8)?)?;
    let frontend = dma
        .get(..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let boundary = frontend
        .get(BLOCK_ROUTING_COLUMN_COUNT..BLOCK_CONTROL_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    sink.push(
        device_io
            * (device_state_value(boundary, false, STATE_INTERRUPT_ENABLE_INDEX)?
                - packed_bits(auxiliary, BEFORE_IE_BITS_START, 5)?),
    )?;
    sink.push(
        device_io
            * (device_state_value(boundary, true, STATE_INTERRUPT_ENABLE_INDEX)?
                - packed_bits(auxiliary, AFTER_IE_BITS_START, 5)?),
    )
}

fn selected_events(dma: &[NativeField]) -> Result<SelectedEvents, UniformError> {
    let frontend = dma
        .get(..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let bus = frontend
        .get(BLOCK_ISA_CONTROL_COLUMN_COUNT..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let mut selected = SelectedEvents::default();
    for slot in 0..BASIC_BLOCK_BUS_EVENT_BOUND {
        let read = slot_kind_selector(bus, slot, MMIO_READ_KIND)?;
        let write = slot_kind_selector(bus, slot, MMIO_WRITE_KIND)?;
        let joypad = slot_kind_selector(bus, slot, JOYPAD_READ_KIND)?;
        let device = read + write + joypad;
        selected.read += read;
        selected.write += write;
        selected.joypad += joypad;
        selected.address += device * slot_address_value(bus, slot)?;
        selected.value += device * slot_value_value(bus, slot)?;
        selected.before += device * slot_before_value(bus, slot)?;
        selected.physical += device * slot_physical_address_value(bus, slot)?;
        selected.auxiliary += device * slot_auxiliary_value(bus, slot)?;
        selected.index += device * slot_index_value(bus, slot)?;
        selected.plain_auxiliary += (read + write) * slot_auxiliary_value(bus, slot)?;
        selected.plain_index += (read + write) * slot_index_value(bus, slot)?;
    }
    Ok(selected)
}

pub(crate) fn mmio_address_selector_value(
    row: &[NativeField],
    low_address: u8,
) -> Result<NativeField, UniformError> {
    if !MMIO_LOW_ADDRESSES.contains(&low_address) {
        return Err(UniformError::Shape);
    }
    let auxiliary = mmio_auxiliary(row)?;
    address_selector(auxiliary, low_address)
}

pub(crate) fn mmio_io_value(row: &[NativeField]) -> Result<NativeField, UniformError> {
    mmio_auxiliary_value(row, IO_VALUE)
}

pub(crate) fn mmio_io_before_value(row: &[NativeField]) -> Result<NativeField, UniformError> {
    mmio_auxiliary_value(row, IO_BEFORE)
}

pub(crate) fn mmio_io_auxiliary_value(row: &[NativeField]) -> Result<NativeField, UniformError> {
    mmio_auxiliary_value(row, IO_AUXILIARY)
}

pub(crate) fn mmio_io_index_value(row: &[NativeField]) -> Result<NativeField, UniformError> {
    mmio_auxiliary_value(row, IO_INDEX)
}

pub(crate) fn mmio_io_value_bit(
    row: &[NativeField],
    bit: usize,
) -> Result<NativeField, UniformError> {
    if bit >= 8 {
        return Err(UniformError::Shape);
    }
    mmio_auxiliary_value(
        row,
        IO_VALUE_BITS_START
            .checked_add(bit)
            .ok_or(UniformError::Shape)?,
    )
}

pub(crate) fn mmio_write_selector_value(row: &[NativeField]) -> Result<NativeField, UniformError> {
    Ok(selected_events(row)?.write)
}

pub(crate) fn mmio_read_selector_value(row: &[NativeField]) -> Result<NativeField, UniformError> {
    Ok(selected_events(row)?.read)
}

pub(crate) fn mmio_joypad_selector_value(row: &[NativeField]) -> Result<NativeField, UniformError> {
    Ok(selected_events(row)?.joypad)
}

fn mmio_auxiliary_value(row: &[NativeField], index: usize) -> Result<NativeField, UniformError> {
    value(mmio_auxiliary(row)?, index)
}

fn mmio_auxiliary(row: &[NativeField]) -> Result<&[NativeField], UniformError> {
    if row.len() < BLOCK_DEVICE_MMIO_COLUMN_COUNT {
        return Err(UniformError::Shape);
    }
    row.get(MMIO_AUX_START..BLOCK_DEVICE_MMIO_COLUMN_COUNT)
        .ok_or(UniformError::Shape)
}

fn constrain_dma_start(
    dma: &[NativeField],
    auxiliary: &[NativeField],
    device_io: NativeField,
    io_value: NativeField,
    io_before: NativeField,
    events: SelectedEvents,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let address = address_selector(auxiliary, 0x46)?;
    let ff46_read = address * events.read;
    let ff46 = address * events.write;
    let before_source = dma_state_byte_value(dma, false, 0)?;
    sink.push(device_io * dma_state_byte_value(dma, false, 2)?)?;
    sink.push(ff46_read * (io_value - before_source))?;
    sink.push(ff46 * (io_before - before_source))?;
    for (byte, target) in [
        (0, io_value),
        (1, NativeField::from_u64(0)),
        (2, NativeField::from_u64(1)),
        (3, NativeField::from_u64(0)),
    ] {
        let prior = dma_state_byte_value(dma, false, byte)?;
        let next = dma_state_byte_value(dma, true, byte)?;
        sink.push(device_io * (next - prior) - ff46 * (target - prior))?;
    }
    Ok(())
}

fn constrain_interrupt_enable(
    auxiliary: &[NativeField],
    device_io: NativeField,
    io_value: NativeField,
    io_before: NativeField,
    events: SelectedEvents,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let address = address_selector(auxiliary, 0xff)?;
    let read = address * events.read;
    let write = address * events.write;
    let before = packed_bits(auxiliary, BEFORE_IE_BITS_START, 5)?;
    let after = packed_bits(auxiliary, AFTER_IE_BITS_START, 5)?;
    let written = packed_bits(auxiliary, IO_VALUE_BITS_START, 5)?;
    sink.push(read * (io_value - before))?;
    sink.push(write * (io_before - before))?;
    sink.push(device_io * (after - before) - write * (written - before))?;
    Ok(())
}

fn constrain_direct_register_tuples(
    dma: &[NativeField],
    auxiliary: &[NativeField],
    io_value: NativeField,
    io_before: NativeField,
    events: SelectedEvents,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let frontend = dma
        .get(..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let boundary = frontend
        .get(BLOCK_ROUTING_COLUMN_COUNT..BLOCK_CONTROL_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    for (address, scalar, visible_high) in [
        (0x0f, STATE_INTERRUPT_REQUEST_INDEX, 0xe0),
        (0x44, STATE_PPU_LINE_INDEX, 0),
    ] {
        let address = address_selector(auxiliary, address)?;
        let visible =
            device_state_value(boundary, false, scalar)? + NativeField::from_u64(visible_high);
        sink.push(address * events.read * (io_value - visible))?;
        sink.push(address * events.write * (io_before - visible))?;
    }
    let div_address = address_selector(auxiliary, 0x04)?;
    let div = timer_div_high_byte(dma)?;
    sink.push(div_address * events.read * (io_value - div))?;
    sink.push(div_address * events.write * (io_before - div))?;
    Ok(())
}

fn timer_div_high_byte(row: &[NativeField]) -> Result<NativeField, UniformError> {
    let mut packed = NativeField::from_u64(0);
    let mut power = NativeField::from_u64(1);
    for bit in 8..16 {
        packed += power * timer_div_bit_value(row, false, bit)?;
        power += power;
    }
    Ok(packed)
}

fn constrain_packed_register_tuples(
    dma: &[NativeField],
    auxiliary: &[NativeField],
    io_value: NativeField,
    io_before: NativeField,
    events: SelectedEvents,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for (address, high_pack, byte, visible_high) in [
        (0x01, false, 0, 0_u64),
        (0x02, false, 1, 0),
        (0x05, false, 2, 0),
        (0x06, false, 3, 0xf8),
        (0x40, false, 4, 0),
        (0x42, false, 6, 0),
        (0x43, false, 7, 0),
        (0x45, true, 5, 0),
        (0x47, true, 0, 0),
        (0x48, true, 1, 0),
        (0x49, true, 2, 0),
        (0x4a, true, 3, 0),
        (0x4b, true, 4, 0),
    ] {
        let address = address_selector(auxiliary, address)?;
        let visible =
            packed_register_byte(dma, high_pack, byte)? + NativeField::from_u64(visible_high);
        sink.push(address * events.read * (io_value - visible))?;
        sink.push(address * events.write * (io_before - visible))?;
    }
    Ok(())
}

fn packed_register_byte(
    row: &[NativeField],
    high_pack: bool,
    byte: usize,
) -> Result<NativeField, UniformError> {
    if byte >= 8 {
        return Err(UniformError::Shape);
    }
    let start = byte.checked_mul(8).ok_or(UniformError::Shape)?;
    let mut packed = NativeField::from_u64(0);
    let mut power = NativeField::from_u64(1);
    for bit in 0..8 {
        let index = start.checked_add(bit).ok_or(UniformError::Shape)?;
        let value = if high_pack {
            high_pack_bit_value(row, false, index)?
        } else {
            low_pack_bit_value(row, false, index)?
        };
        packed += power * value;
        power += power;
    }
    Ok(packed)
}

fn constrain_stable_packed_registers(
    dma: &[NativeField],
    auxiliary: &[NativeField],
    device_io: NativeField,
    write: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for (address, high_pack, byte, write_mask) in [
        (0x02, false, 1, 0xff_u8),
        (0x05, false, 2, 0xff),
        (0x06, false, 3, 0x07),
        (0x40, false, 4, 0xff),
        (0x41, false, 5, 0x78),
        (0x42, false, 6, 0xff),
        (0x43, false, 7, 0xff),
        (0x45, true, 5, 0xff),
        (0x47, true, 0, 0xff),
        (0x48, true, 1, 0xff),
        (0x49, true, 2, 0xff),
        (0x4a, true, 3, 0xff),
        (0x4b, true, 4, 0xff),
    ] {
        let before = packed_register_byte(dma, high_pack, byte)?;
        let after = packed_register_byte_after(dma, high_pack, byte)?;
        let selected = address_selector(auxiliary, address)? * write;
        let written = masked_io_value(auxiliary, write_mask)?;
        sink.push(device_io * (after - before) - selected * (written - before))?;
    }
    Ok(())
}

fn packed_register_byte_after(
    row: &[NativeField],
    high_pack: bool,
    byte: usize,
) -> Result<NativeField, UniformError> {
    if byte >= 8 {
        return Err(UniformError::Shape);
    }
    let start = byte.checked_mul(8).ok_or(UniformError::Shape)?;
    let mut packed = NativeField::from_u64(0);
    let mut power = NativeField::from_u64(1);
    for bit in 0..8 {
        let index = start.checked_add(bit).ok_or(UniformError::Shape)?;
        let value = if high_pack {
            high_pack_bit_value(row, true, index)?
        } else {
            low_pack_bit_value(row, true, index)?
        };
        packed += power * value;
        power += power;
    }
    Ok(packed)
}

fn masked_io_value(auxiliary: &[NativeField], mask: u8) -> Result<NativeField, UniformError> {
    let mut packed = NativeField::from_u64(0);
    let mut power = NativeField::from_u64(1);
    for bit in 0..8 {
        if mask >> bit & 1 == 1 {
            packed += power * value(auxiliary, IO_VALUE_BITS_START + bit)?;
        }
        power += power;
    }
    Ok(packed)
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

fn address_selector(
    auxiliary: &[NativeField],
    low_address: u8,
) -> Result<NativeField, UniformError> {
    let one = NativeField::from_u64(1);
    (0..ADDRESS_BIT_COUNT).try_fold(one, |selector, bit| {
        let address_bit = value(auxiliary, ADDRESS_BITS_START + bit)?;
        let expected = low_address >> bit & 1;
        Ok(selector
            * if expected == 1 {
                address_bit
            } else {
                one - address_bit
            })
    })
}

fn supported_address_selector_sum(auxiliary: &[NativeField]) -> Result<NativeField, UniformError> {
    MMIO_LOW_ADDRESSES
        .iter()
        .copied()
        .try_fold(NativeField::from_u64(0), |sum, address| {
            Ok(sum + address_selector(auxiliary, address)?)
        })
}

fn append_bits(
    row: &mut [u64],
    start: usize,
    packed: u64,
    width: usize,
) -> Result<(), BlockDeviceMmioError> {
    for bit in 0..width {
        let index = start.checked_add(bit).ok_or(BlockDeviceMmioError::Layout)?;
        set(row, index, packed >> bit & 1)?;
    }
    Ok(())
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), BlockDeviceMmioError> {
    *row.get_mut(index).ok_or(BlockDeviceMmioError::Layout)? = value;
    Ok(())
}

fn value(row: &[NativeField], index: usize) -> Result<NativeField, UniformError> {
    row.get(index).copied().ok_or(UniformError::Shape)
}

#[derive(Clone, Copy, Default)]
struct SelectedEvents {
    read: NativeField,
    write: NativeField,
    joypad: NativeField,
    address: NativeField,
    value: NativeField,
    before: NativeField,
    physical: NativeField,
    auxiliary: NativeField,
    index: NativeField,
    plain_auxiliary: NativeField,
    plain_index: NativeField,
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
        block_test_support::{first_device_io_block_index, flip_witness_bit, lookup_blocks},
        validate_uniform_witness,
    };

    fn address_auxiliary(low_address: u8) -> Result<Vec<NativeField>, UniformError> {
        let mut auxiliary = vec![NativeField::from_u64(0); MMIO_AUX_COLUMN_COUNT];
        for bit in 0..ADDRESS_BIT_COUNT {
            *auxiliary
                .get_mut(ADDRESS_BITS_START + bit)
                .ok_or(UniformError::Shape)? =
                NativeField::from_u64(u64::from(low_address >> bit & 1));
        }
        Ok(auxiliary)
    }

    #[test]
    fn compressed_address_bits_select_exactly_the_supported_mmio_set() -> Result<(), UniformError> {
        for low_address in MMIO_LOW_ADDRESSES {
            let auxiliary = address_auxiliary(low_address)?;
            assert_eq!(
                supported_address_selector_sum(&auxiliary)?,
                NativeField::from_u64(1),
                "supported address {low_address:#04x}",
            );
        }
        for low_address in [0x03, 0x08, 0x4c, 0xfe] {
            let auxiliary = address_auxiliary(low_address)?;
            assert_eq!(
                supported_address_selector_sum(&auxiliary)?,
                NativeField::from_u64(0),
                "unsupported address {low_address:#04x}",
            );
        }
        Ok(())
    }

    #[test]
    fn ff46_write_is_admitted_by_typed_mmio_relation() -> Result<(), Box<dyn std::error::Error>> {
        let blocks = lookup_blocks(&[0x3e, 0xc0, 0xea, 0x46, 0xff], 2)?;
        let witness = BlockDeviceMmioWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockDeviceMmioRelation, witness.columns())?;
        let device_row = first_device_io_block_index(&blocks)?;
        let mut mutated = witness.columns().to_vec();
        flip_witness_bit(
            &mut mutated,
            MMIO_AUX_START + ADDRESS_BITS_START,
            device_row,
        )?;
        assert!(validate_uniform_witness(&BlockDeviceMmioRelation, &mutated).is_err());
        Ok(())
    }
}
