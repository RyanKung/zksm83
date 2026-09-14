//! Typed MMIO write-before-clock semantics for the DMG serial engine.

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_core::{BusEventKind, DmgDeviceState};
use zksm83_trace::BasicBlock;

use crate::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_DEVICE_APU_COLUMN_COUNT, BLOCK_DEVICE_APU_CONSTRAINT_COUNT,
    BLOCK_DEVICE_APU_MAX_DEGREE, BLOCK_FRONTEND_COLUMN_COUNT, BLOCK_ROUTING_COLUMN_COUNT,
    BlockDeviceApuError, BlockDeviceApuRelation, BlockDeviceApuWitness, ConstraintOutput,
    NativeField, STATE_CPU_M_CYCLES_INDEX, UNIFORM_ROW_COUNT, UniformError, UniformRelation,
    block_boundary::local_state_value,
    block_device::device_io_selector_value,
    block_device_mmio::{
        mmio_address_selector_value, mmio_io_value, mmio_io_value_bit, mmio_write_selector_value,
    },
    block_device_ppu::low_pack_bit_value,
    block_device_serial::{
        high_pack_bit_value, interrupt_request_bit_value, serial_countdown_zero_value,
    },
};

const SERIAL_MMIO_AUX_START: usize = BLOCK_DEVICE_APU_COLUMN_COUNT;
const POST_DATA_BITS_START: usize = 0;
const POST_CONTROL_BITS_START: usize = POST_DATA_BITS_START + 8;
const POST_COUNTDOWN_BITS_START: usize = POST_CONTROL_BITS_START + 8;
const POST_ZERO_PRODUCTS_START: usize = POST_COUNTDOWN_BITS_START + 13;
const COMPLETED: usize = POST_ZERO_PRODUCTS_START + 12;
const COMPLETION_GAP_BITS_START: usize = COMPLETED + 1;
const FF01_WRITE: usize = COMPLETION_GAP_BITS_START + 5;
const FF02_WRITE: usize = FF01_WRITE + 1;
const POST_IF_THREE: usize = FF02_WRITE + 1;
const SERIAL_MMIO_AUX_COLUMN_COUNT: usize = POST_IF_THREE + 1;
const SERIAL_MMIO_ADDITIONAL_CONSTRAINT_COUNT: usize = 157;
const COUNTDOWN_WIDTH: usize = 13;
const COUNTDOWN_MAXIMUM: u64 = 4_096;

/// Logical columns in the APU relation plus serial write-before-clock semantics.
pub const BLOCK_DEVICE_SERIAL_MMIO_COLUMN_COUNT: usize =
    BLOCK_DEVICE_APU_COLUMN_COUNT + SERIAL_MMIO_AUX_COLUMN_COUNT;
/// Identities in the typed serial-MMIO relation.
pub const BLOCK_DEVICE_SERIAL_MMIO_CONSTRAINT_COUNT: usize =
    BLOCK_DEVICE_APU_CONSTRAINT_COUNT + SERIAL_MMIO_ADDITIONAL_CONSTRAINT_COUNT;
/// Maximum total degree in the typed serial-MMIO relation.
pub const BLOCK_DEVICE_SERIAL_MMIO_MAX_DEGREE: usize = BLOCK_DEVICE_APU_MAX_DEGREE;

const _: () = assert!(SERIAL_MMIO_AUX_COLUMN_COUNT == 50);
const _: () = assert!(BLOCK_DEVICE_SERIAL_MMIO_COLUMN_COUNT == 3_214);
const _: () = assert!(BLOCK_DEVICE_SERIAL_MMIO_CONSTRAINT_COUNT == 7_378);
const _: () = assert!(BLOCK_DEVICE_SERIAL_MMIO_MAX_DEGREE == 14);

/// Fixed-row witness for the serial state immediately after MMIO and after clocking.
#[derive(Debug)]
pub struct BlockDeviceSerialMmioWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to construct the typed serial-MMIO witness.
#[derive(Debug, Error)]
pub enum BlockDeviceSerialMmioError {
    /// APU relation construction failed.
    #[error("packed-block APU construction failed: {0}")]
    Apu(#[from] BlockDeviceApuError),
    /// A validated device-I/O row exposed an inconsistent serial transition.
    #[error("packed block {block} has an inconsistent serial-MMIO transition")]
    InvalidTransition {
        /// Zero-based packed-block row.
        block: usize,
    },
    /// Serial-MMIO auxiliary columns violated their fixed layout.
    #[error("packed-block serial-MMIO witness violated its typed layout")]
    Layout,
}

/// APU relation plus exact FF01/FF02 post-write serial clocking.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockDeviceSerialMmioRelation;

impl BlockDeviceSerialMmioWitness {
    /// Derives the serial post-write state for every typed device-I/O block.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockDeviceSerialMmioError> {
        let apu = BlockDeviceApuWitness::from_blocks(blocks)?;
        let active_block_count = apu.active_block_count();
        let mut auxiliary = (0..SERIAL_MMIO_AUX_COLUMN_COUNT)
            .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
            .collect::<Vec<_>>();
        for (block_index, block) in blocks.iter().enumerate() {
            let mut row = [0_u64; SERIAL_MMIO_AUX_COLUMN_COUNT];
            append_serial_mmio_row(&mut row, block, block_index)?;
            for (column, value) in auxiliary.iter_mut().zip(row) {
                column.push(value);
            }
        }
        for column in &mut auxiliary {
            column.resize(UNIFORM_ROW_COUNT, 0);
        }
        let mut columns = apu.into_columns();
        columns.extend(auxiliary);
        if columns.len() != BLOCK_DEVICE_SERIAL_MMIO_COLUMN_COUNT {
            return Err(BlockDeviceSerialMmioError::Layout);
        }
        Ok(Self {
            columns,
            active_block_count,
        })
    }

    /// Returns every logical column in APU-then-serial-MMIO order.
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

impl UniformRelation for BlockDeviceSerialMmioRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-device-serial-mmio/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [3_164_u64, 7_221, 50, 157, 3_214, 7_378, 5] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_DEVICE_SERIAL_MMIO_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_DEVICE_SERIAL_MMIO_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_DEVICE_SERIAL_MMIO_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_DEVICE_SERIAL_MMIO_COLUMN_COUNT
            || constraints.len() != BLOCK_DEVICE_SERIAL_MMIO_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let apu = row
            .get(..BLOCK_DEVICE_APU_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let auxiliary = row
            .get(SERIAL_MMIO_AUX_START..BLOCK_DEVICE_SERIAL_MMIO_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let (apu_constraints, serial_constraints) =
            constraints.split_at_mut(BLOCK_DEVICE_APU_CONSTRAINT_COUNT);
        BlockDeviceApuRelation.evaluate(apu, apu_constraints)?;
        constrain_serial_mmio(apu, auxiliary, serial_constraints)
    }
}

fn append_serial_mmio_row(
    row: &mut [u64],
    block: &BasicBlock,
    block_index: usize,
) -> Result<(), BlockDeviceSerialMmioError> {
    let Some((kind, tuple)) = typed_device_event(block, block_index)? else {
        return Ok(());
    };
    let before_device = block.initial_state().dmg_devices();
    let after_device = block.final_state().dmg_devices();
    let before = SerialState::from_device(before_device)?;
    let after = SerialState::from_device(after_device)?;
    let mut post = before;
    let ff01_write = kind == BusEventKind::DmgMmioWrite && tuple.address == 0xff01;
    let ff02_write = kind == BusEventKind::DmgMmioWrite && tuple.address == 0xff02;
    if ff01_write {
        post.data = tuple.value;
    }
    if ff02_write {
        post.control = tuple.value;
        post.countdown = if tuple.value & 0x81 == 0x81 {
            COUNTDOWN_MAXIMUM
        } else {
            0
        };
    }
    let ticks = block
        .m_cycle_count()
        .checked_mul(4)
        .ok_or(BlockDeviceSerialMmioError::InvalidTransition { block: block_index })?;
    let expected_countdown = post.countdown.saturating_sub(ticks);
    let completed = post.countdown != 0 && expected_countdown == 0;
    let expected = SerialState {
        data: if completed { 0xff } else { post.data },
        control: if completed {
            post.control & 0x7f
        } else {
            post.control
        },
        countdown: expected_countdown,
    };
    let mut post_if = before_device.interrupt_request() & 0x08 != 0;
    if kind == BusEventKind::DmgMmioWrite && tuple.address == 0xff0f {
        post_if = tuple.value & 0x08 != 0;
    }
    let expected_if = post_if || completed;
    let after_if = after_device.interrupt_request() & 0x08 != 0;
    if expected != after || expected_if != after_if {
        return Err(BlockDeviceSerialMmioError::InvalidTransition { block: block_index });
    }
    append_bits(row, POST_DATA_BITS_START, u64::from(post.data), 8)?;
    append_bits(row, POST_CONTROL_BITS_START, u64::from(post.control), 8)?;
    append_bits(
        row,
        POST_COUNTDOWN_BITS_START,
        post.countdown,
        COUNTDOWN_WIDTH,
    )?;
    append_zero_products(row, POST_ZERO_PRODUCTS_START, post.countdown)?;
    set(row, COMPLETED, u64::from(completed))?;
    let gap = if completed {
        ticks
            .checked_sub(post.countdown)
            .ok_or(BlockDeviceSerialMmioError::InvalidTransition { block: block_index })?
    } else {
        0
    };
    append_bits(row, COMPLETION_GAP_BITS_START, gap, 5)?;
    set(row, FF01_WRITE, u64::from(ff01_write))?;
    set(row, FF02_WRITE, u64::from(ff02_write))?;
    set(row, POST_IF_THREE, u64::from(post_if))
}

fn typed_device_event(
    block: &BasicBlock,
    block_index: usize,
) -> Result<Option<(BusEventKind, zksm83_memory::BusTranscriptEvent)>, BlockDeviceSerialMmioError> {
    let mut selected = None;
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
            if selected.is_some() {
                return Err(BlockDeviceSerialMmioError::InvalidTransition { block: block_index });
            }
            selected = Some((event.kind(), event.transcript_event()));
        }
    }
    Ok(selected)
}

fn constrain_serial_mmio(
    apu: &[NativeField],
    auxiliary: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if auxiliary.len() != SERIAL_MMIO_AUX_COLUMN_COUNT
        || constraints.len() != SERIAL_MMIO_ADDITIONAL_CONSTRAINT_COUNT
    {
        return Err(UniformError::Shape);
    }
    let one = NativeField::from_u64(1);
    let device_io = device_io_selector_value(apu)?;
    let mut sink = ConstraintSink::new(constraints);
    for column in auxiliary.iter().copied() {
        sink.push(column * (column - one))?;
        sink.push((one - device_io) * column)?;
    }
    let frontend = apu
        .get(..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let boundary = frontend
        .get(BLOCK_ROUTING_COLUMN_COUNT..BLOCK_CONTROL_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let write = mmio_write_selector_value(apu)?;
    let ff01 = value(auxiliary, FF01_WRITE)?;
    let ff02 = value(auxiliary, FF02_WRITE)?;
    sink.push(ff01 - mmio_address_selector_value(apu, 0x01)? * write)?;
    sink.push(ff02 - mmio_address_selector_value(apu, 0x02)? * write)?;
    constrain_post_write_state(apu, auxiliary, device_io, ff01, ff02, &mut sink)?;
    constrain_post_countdown(auxiliary, device_io, &mut sink)?;
    let completed = constrain_countdown_transition(apu, boundary, auxiliary, device_io, &mut sink)?;
    constrain_register_completion(apu, auxiliary, device_io, completed, &mut sink)?;
    constrain_serial_interrupt(apu, auxiliary, device_io, completed, write, &mut sink)?;
    sink.finish()
}

fn constrain_post_write_state(
    apu: &[NativeField],
    auxiliary: &[NativeField],
    device_io: NativeField,
    ff01: NativeField,
    ff02: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let before_data = packed_low_byte(apu, false, 0)?;
    let post_data = packed_bits(auxiliary, POST_DATA_BITS_START, 8)?;
    sink.push(device_io * (post_data - before_data) - ff01 * (mmio_io_value(apu)? - before_data))?;
    let before_control = packed_low_byte(apu, false, 1)?;
    let post_control = packed_bits(auxiliary, POST_CONTROL_BITS_START, 8)?;
    sink.push(
        device_io * (post_control - before_control) - ff02 * (mmio_io_value(apu)? - before_control),
    )?;
    let before_countdown = serial_countdown(apu, false)?;
    let post_countdown = packed_bits(auxiliary, POST_COUNTDOWN_BITS_START, COUNTDOWN_WIDTH)?;
    let start = NativeField::from_u64(COUNTDOWN_MAXIMUM)
        * mmio_io_value_bit(apu, 0)?
        * mmio_io_value_bit(apu, 7)?;
    sink.push(device_io * (post_countdown - before_countdown) - ff02 * (start - before_countdown))
}

fn constrain_post_countdown(
    auxiliary: &[NativeField],
    device_io: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let first = (one - value(auxiliary, POST_COUNTDOWN_BITS_START)?)
        * (one - value(auxiliary, POST_COUNTDOWN_BITS_START + 1)?);
    sink.push(device_io * (value(auxiliary, POST_ZERO_PRODUCTS_START)? - first))?;
    for bit in 2..COUNTDOWN_WIDTH {
        let prior = value(auxiliary, POST_ZERO_PRODUCTS_START + bit - 2)?;
        let next = value(auxiliary, POST_ZERO_PRODUCTS_START + bit - 1)?;
        sink.push(
            device_io * (next - prior * (one - value(auxiliary, POST_COUNTDOWN_BITS_START + bit)?)),
        )?;
    }
    let high = value(auxiliary, POST_COUNTDOWN_BITS_START + 12)?;
    for bit in 0..12 {
        sink.push(device_io * high * value(auxiliary, POST_COUNTDOWN_BITS_START + bit)?)?;
    }
    Ok(())
}

fn constrain_countdown_transition(
    apu: &[NativeField],
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    device_io: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<NativeField, UniformError> {
    let one = NativeField::from_u64(1);
    let post_zero = value(auxiliary, POST_ZERO_PRODUCTS_START + 11)?;
    let after_zero = serial_countdown_zero_value(apu, true)?;
    let active = device_io * (one - post_zero);
    let completed = value(auxiliary, COMPLETED)?;
    sink.push(completed - active * after_zero)?;
    let post = packed_bits(auxiliary, POST_COUNTDOWN_BITS_START, COUNTDOWN_WIDTH)?;
    let after = serial_countdown(apu, true)?;
    let ticks = NativeField::from_u64(4)
        * (local_state_value(
            boundary,
            zksm83_trace::BASIC_BLOCK_INSTRUCTION_BOUND,
            STATE_CPU_M_CYCLES_INDEX,
        )? - local_state_value(boundary, 0, STATE_CPU_M_CYCLES_INDEX)?);
    sink.push(device_io * (after - post) + active * (one - completed) * ticks + completed * post)?;
    for bit in 0..5 {
        sink.push(
            device_io * (one - completed) * value(auxiliary, COMPLETION_GAP_BITS_START + bit)?,
        )?;
    }
    let gap = packed_bits(auxiliary, COMPLETION_GAP_BITS_START, 5)?;
    sink.push(completed * (gap - ticks + post))?;
    sink.push(active * (value(auxiliary, POST_CONTROL_BITS_START)? - one))?;
    sink.push(active * (value(auxiliary, POST_CONTROL_BITS_START + 7)? - one))?;
    Ok(completed)
}

fn constrain_register_completion(
    apu: &[NativeField],
    auxiliary: &[NativeField],
    device_io: NativeField,
    completed: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    for bit in 0..8 {
        let post = value(auxiliary, POST_DATA_BITS_START + bit)?;
        sink.push(
            device_io * (low_pack_bit_value(apu, true, bit)? - post) - completed * (one - post),
        )?;
    }
    for bit in 0..7 {
        sink.push(
            device_io
                * (low_pack_bit_value(apu, true, 8 + bit)?
                    - value(auxiliary, POST_CONTROL_BITS_START + bit)?),
        )?;
    }
    let post_seven = value(auxiliary, POST_CONTROL_BITS_START + 7)?;
    sink.push(
        device_io * (low_pack_bit_value(apu, true, 15)? - post_seven) + completed * post_seven,
    )
}

fn constrain_serial_interrupt(
    apu: &[NativeField],
    auxiliary: &[NativeField],
    device_io: NativeField,
    completed: NativeField,
    write: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let before = interrupt_request_bit_value(apu, false, 3)?;
    let post = value(auxiliary, POST_IF_THREE)?;
    let ff0f = mmio_address_selector_value(apu, 0x0f)? * write;
    sink.push(post - device_io * before - ff0f * (mmio_io_value_bit(apu, 3)? - before))?;
    sink.push(
        device_io * (interrupt_request_bit_value(apu, true, 3)? - post) - completed * (one - post),
    )
}

fn serial_countdown(row: &[NativeField], after: bool) -> Result<NativeField, UniformError> {
    let mut packed = NativeField::from_u64(0);
    let mut power = NativeField::from_u64(1);
    for bit in 0..COUNTDOWN_WIDTH {
        packed += power * high_pack_bit_value(row, after, 48 + bit)?;
        power += power;
    }
    Ok(packed)
}

fn packed_low_byte(
    row: &[NativeField],
    after: bool,
    byte: usize,
) -> Result<NativeField, UniformError> {
    if byte >= 8 {
        return Err(UniformError::Shape);
    }
    let start = byte.checked_mul(8).ok_or(UniformError::Shape)?;
    let mut packed = NativeField::from_u64(0);
    let mut power = NativeField::from_u64(1);
    for bit in 0..8 {
        packed += power * low_pack_bit_value(row, after, start + bit)?;
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

fn append_zero_products(
    row: &mut [u64],
    start: usize,
    packed: u64,
) -> Result<(), BlockDeviceSerialMmioError> {
    let mut product = (1 - (packed & 1)) * (1 - ((packed >> 1) & 1));
    set(row, start, product)?;
    for bit in 2..COUNTDOWN_WIDTH {
        product *= 1 - ((packed >> bit) & 1);
        set(
            row,
            start
                .checked_add(bit - 1)
                .ok_or(BlockDeviceSerialMmioError::Layout)?,
            product,
        )?;
    }
    Ok(())
}

fn append_bits(
    row: &mut [u64],
    start: usize,
    packed: u64,
    width: usize,
) -> Result<(), BlockDeviceSerialMmioError> {
    for bit in 0..width {
        set(
            row,
            start
                .checked_add(bit)
                .ok_or(BlockDeviceSerialMmioError::Layout)?,
            packed >> bit & 1,
        )?;
    }
    Ok(())
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), BlockDeviceSerialMmioError> {
    *row.get_mut(index)
        .ok_or(BlockDeviceSerialMmioError::Layout)? = value;
    Ok(())
}

fn value(row: &[NativeField], index: usize) -> Result<NativeField, UniformError> {
    row.get(index).copied().ok_or(UniformError::Shape)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SerialState {
    data: u8,
    control: u8,
    countdown: u64,
}

impl SerialState {
    fn from_device(device: DmgDeviceState) -> Result<Self, BlockDeviceSerialMmioError> {
        let data = device
            .read_mmio(0xff01)
            .ok_or(BlockDeviceSerialMmioError::Layout)?;
        let control = device
            .read_mmio(0xff02)
            .ok_or(BlockDeviceSerialMmioError::Layout)?;
        let countdown = device.high_register_pack() >> 48;
        if countdown > COUNTDOWN_MAXIMUM {
            return Err(BlockDeviceSerialMmioError::Layout);
        }
        Ok(Self {
            data,
            control,
            countdown,
        })
    }
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
    use zksm83_trace::{LookupTraceBuilder, pack_witness_basic_blocks};

    use super::*;
    use crate::{
        block_test_support::{first_device_io_block_index, flip_witness_bit},
        validate_uniform_witness,
    };

    #[test]
    fn ff02_write_starts_then_clocks_the_internal_transfer()
    -> Result<(), Box<dyn std::error::Error>> {
        let program = [0x3e, 0x81, 0xea, 0x02, 0xff];
        let blocks = fixture(&program, 2)?;
        let witness = BlockDeviceSerialMmioWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockDeviceSerialMmioRelation, witness.columns())?;
        let device_row = first_device_io_block_index(&blocks)?;
        let mut mutated = witness.columns().to_vec();
        flip_witness_bit(&mut mutated, SERIAL_MMIO_AUX_START + FF02_WRITE, device_row)?;
        assert!(validate_uniform_witness(&BlockDeviceSerialMmioRelation, &mutated).is_err());
        Ok(())
    }

    fn fixture(program: &[u8], steps: u64) -> Result<Vec<BasicBlock>, Box<dyn std::error::Error>> {
        let mut bytes = vec![0_u8; 0x100 + program.len()];
        bytes
            .get_mut(0x100..)
            .ok_or(UniformError::Shape)?
            .copy_from_slice(program);
        let rom = RomImage::new(bytes.clone())?;
        let memory = MemoryImage::zeroed()?;
        let mut builder = LookupTraceBuilder::new_dmg_post_boot_mbc3(
            bytes,
            memory.checkpoint_bytes(),
            Vec::new(),
            rom.root(),
            memory.root(),
        )?;
        Ok(pack_witness_basic_blocks(builder.run_exact_steps(steps)?)?)
    }
}
