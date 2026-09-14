//! Shared serial countdown and completion for bounded device-clocked packed blocks.

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_trace::{BASIC_BLOCK_INSTRUCTION_BOUND, BasicBlock};

use crate::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_DEVICE_PPU_COLUMN_COUNT, BLOCK_DEVICE_PPU_CONSTRAINT_COUNT,
    BLOCK_DEVICE_PPU_MAX_DEGREE, BLOCK_FRONTEND_COLUMN_COUNT, BLOCK_ROUTING_COLUMN_COUNT,
    BlockDevicePpuError, BlockDevicePpuRelation, BlockDevicePpuWitness, ConstraintOutput,
    NativeField, STATE_CPU_M_CYCLES_INDEX, STATE_DMG_HIGH_REGISTER_PACK_INDEX,
    STATE_INTERRUPT_REQUEST_INDEX, UNIFORM_ROW_COUNT, UniformError, UniformRelation,
    block_boundary::{device_state_value, local_state_value},
    block_device::{device_clocked_block, device_io_selector_value, interrupt_source_bit},
    block_device_ppu::low_pack_bit_value,
    block_machine::{
        device_clocked_value, halt_until_serial_value, halt_until_timer_value,
        halt_until_vblank_value, interrupt_source_value,
    },
    block_metadata,
};

const SERIAL_AUX_START: usize = BLOCK_DEVICE_PPU_COLUMN_COUNT;
const BEFORE_HIGH_BITS_START: usize = 0;
const AFTER_HIGH_BITS_START: usize = BEFORE_HIGH_BITS_START + 64;
const BEFORE_ZERO_PRODUCTS_START: usize = AFTER_HIGH_BITS_START + 64;
const AFTER_ZERO_PRODUCTS_START: usize = BEFORE_ZERO_PRODUCTS_START + 12;
const SERIAL_COMPLETED: usize = AFTER_ZERO_PRODUCTS_START + 12;
const COMPLETION_GAP_BITS_START: usize = SERIAL_COMPLETED + 1;
const BEFORE_IF_BITS_START: usize = COMPLETION_GAP_BITS_START + 5;
const AFTER_IF_BITS_START: usize = BEFORE_IF_BITS_START + 5;
const SERIAL_AUX_COLUMN_COUNT: usize = AFTER_IF_BITS_START + 5;

const SERIAL_COUNTDOWN_BITS_START: usize = 48;
const SERIAL_COUNTDOWN_WIDTH: usize = 13;
const SERIAL_COUNTDOWN_MAXIMUM: u64 = 4_096;
const SERIAL_CONTROL_BIT_ZERO: usize = 8;
const SERIAL_CONTROL_BIT_SEVEN: usize = 15;

/// Logical columns in the shared PPU relation plus the serial witness.
pub const BLOCK_DEVICE_SERIAL_COLUMN_COUNT: usize =
    BLOCK_DEVICE_PPU_COLUMN_COUNT + SERIAL_AUX_COLUMN_COUNT;
/// Identities in the shared serial relation.
pub const BLOCK_DEVICE_SERIAL_CONSTRAINT_COUNT: usize =
    BLOCK_DEVICE_PPU_CONSTRAINT_COUNT + SERIAL_AUX_COLUMN_COUNT * 2 + 139;
/// Maximum total degree in the shared serial relation.
pub const BLOCK_DEVICE_SERIAL_MAX_DEGREE: usize = BLOCK_DEVICE_PPU_MAX_DEGREE;

const _: () = assert!(BASIC_BLOCK_INSTRUCTION_BOUND == 4);
const _: () = assert!(SERIAL_AUX_COLUMN_COUNT == 168);
const _: () = assert!(BLOCK_DEVICE_SERIAL_COLUMN_COUNT == 1_162);
const _: () = assert!(BLOCK_DEVICE_SERIAL_CONSTRAINT_COUNT == 2_299);
const _: () = assert!(BLOCK_DEVICE_SERIAL_MAX_DEGREE == 7);

/// Fixed-row packed witness carrying one serial transition per quiet block.
#[derive(Debug)]
pub struct BlockDeviceSerialWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to construct the shared packed-block serial witness.
#[derive(Debug, Error)]
pub enum BlockDeviceSerialError {
    /// Shared PPU witness construction failed.
    #[error("packed-block PPU construction failed: {0}")]
    Ppu(#[from] BlockDevicePpuError),
    /// A validated block exposed an inconsistent serial transition.
    #[error("packed block {block} has an inconsistent quiet serial transition")]
    InvalidTransition {
        /// Zero-based packed-block row.
        block: usize,
    },
    /// Serial auxiliary columns violated their fixed layout.
    #[error("packed-block serial witness violated its typed layout")]
    Layout,
}

/// Shared PPU relation plus serial countdown, completion, register, and IF semantics.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockDeviceSerialRelation;

impl BlockDeviceSerialWitness {
    /// Derives one compact serial witness for every bounded device-clocked block.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockDeviceSerialError> {
        let ppu = BlockDevicePpuWitness::from_blocks(blocks)?;
        let active_block_count = ppu.active_block_count();
        let mut auxiliary = (0..SERIAL_AUX_COLUMN_COUNT)
            .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
            .collect::<Vec<_>>();
        for (block_index, block) in blocks.iter().enumerate() {
            let mut row = [0_u64; SERIAL_AUX_COLUMN_COUNT];
            let quiet = device_clocked_block(block).map_err(BlockDevicePpuError::from)?;
            append_serial_row(&mut row, block, block_index, quiet)?;
            for (column, value) in auxiliary.iter_mut().zip(row) {
                column.push(value);
            }
        }
        for column in &mut auxiliary {
            column.resize(UNIFORM_ROW_COUNT, 0);
        }
        let mut columns = ppu.into_columns();
        columns.extend(auxiliary);
        if columns.len() != BLOCK_DEVICE_SERIAL_COLUMN_COUNT {
            return Err(BlockDeviceSerialError::Layout);
        }
        Ok(Self {
            columns,
            active_block_count,
        })
    }

    /// Returns every logical column in PPU-then-serial order.
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

impl UniformRelation for BlockDeviceSerialRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-device-serial/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [994_u64, 1_824, 168, 4_096, 1_162, 2_299, 3] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_DEVICE_SERIAL_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_DEVICE_SERIAL_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_DEVICE_SERIAL_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_DEVICE_SERIAL_COLUMN_COUNT
            || constraints.len() != BLOCK_DEVICE_SERIAL_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let ppu = row
            .get(..BLOCK_DEVICE_PPU_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let auxiliary = row
            .get(SERIAL_AUX_START..BLOCK_DEVICE_SERIAL_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let (ppu_constraints, serial_constraints) =
            constraints.split_at_mut(BLOCK_DEVICE_PPU_CONSTRAINT_COUNT);
        BlockDevicePpuRelation.evaluate(ppu, ppu_constraints)?;
        constrain_serial(ppu, auxiliary, serial_constraints)
    }
}

fn append_serial_row(
    row: &mut [u64],
    block: &BasicBlock,
    block_index: usize,
    quiet: bool,
) -> Result<(), BlockDeviceSerialError> {
    let before = block.initial_state().dmg_devices();
    let after = block.final_state().dmg_devices();
    let before_high = before.high_register_pack();
    let after_high = after.high_register_pack();
    let before_countdown = before_high >> SERIAL_COUNTDOWN_BITS_START;
    let after_countdown = after_high >> SERIAL_COUNTDOWN_BITS_START;
    append_bits(row, BEFORE_HIGH_BITS_START, before_high, 64)?;
    append_bits(row, AFTER_HIGH_BITS_START, after_high, 64)?;
    append_bits(
        row,
        BEFORE_IF_BITS_START,
        u64::from(before.interrupt_request()),
        5,
    )?;
    append_bits(
        row,
        AFTER_IF_BITS_START,
        u64::from(after.interrupt_request()),
        5,
    )?;
    append_zero_products(row, BEFORE_ZERO_PRODUCTS_START, before_countdown)?;
    append_zero_products(row, AFTER_ZERO_PRODUCTS_START, after_countdown)?;
    if !quiet {
        return Ok(());
    }
    let ticks = block
        .m_cycle_count()
        .checked_mul(4)
        .ok_or(BlockDeviceSerialError::InvalidTransition { block: block_index })?;
    validate_serial_transition(
        block_index,
        SerialTransition {
            before_low: before.low_register_pack(),
            after_low: after.low_register_pack(),
            before_high,
            after_high,
            before_countdown,
            after_countdown,
            ticks,
            before_if: before.interrupt_request(),
            after_if: after.interrupt_request(),
            acknowledged: interrupt_source_bit(block, 3),
        },
    )?;
    let completed = before_countdown != 0 && after_countdown == 0;
    set(row, SERIAL_COMPLETED, u64::from(completed))?;
    let gap = if completed {
        ticks
            .checked_sub(before_countdown)
            .ok_or(BlockDeviceSerialError::InvalidTransition { block: block_index })?
    } else {
        0
    };
    append_bits(row, COMPLETION_GAP_BITS_START, gap, 5)
}

fn validate_serial_transition(
    block: usize,
    transition: SerialTransition,
) -> Result<(), BlockDeviceSerialError> {
    if transition.before_countdown > SERIAL_COUNTDOWN_MAXIMUM
        || transition.after_countdown > SERIAL_COUNTDOWN_MAXIMUM
    {
        return Err(BlockDeviceSerialError::InvalidTransition { block });
    }
    let expected_countdown = transition.before_countdown.saturating_sub(transition.ticks);
    let completed = transition.before_countdown != 0 && expected_countdown == 0;
    let mut expected_low = transition.before_low;
    if completed {
        expected_low = (expected_low | 0xff) & !(1_u64 << SERIAL_CONTROL_BIT_SEVEN);
    }
    let expected_high = (transition.before_high & ((1_u64 << 48) - 1))
        | expected_countdown << SERIAL_COUNTDOWN_BITS_START;
    let post_ack_if_three =
        ((transition.before_if >> 3) & 1) * (1 - u8::from(transition.acknowledged));
    let expected_if_three = post_ack_if_three | u8::from(completed);
    let before_control = (transition.before_low >> 8) & 0xff;
    if transition.after_countdown != expected_countdown
        || transition.after_low != expected_low
        || transition.after_high != expected_high
        || (transition.after_if >> 3) & 1 != expected_if_three
        || (transition.before_countdown != 0 && before_control & 0x81 != 0x81)
    {
        return Err(BlockDeviceSerialError::InvalidTransition { block });
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct SerialTransition {
    before_low: u64,
    after_low: u64,
    before_high: u64,
    after_high: u64,
    before_countdown: u64,
    after_countdown: u64,
    ticks: u64,
    before_if: u8,
    after_if: u8,
    acknowledged: bool,
}

fn append_zero_products(
    row: &mut [u64],
    start: usize,
    value: u64,
) -> Result<(), BlockDeviceSerialError> {
    let bit_zero = 1 - (value & 1);
    let bit_one = 1 - ((value >> 1) & 1);
    let mut product = bit_zero * bit_one;
    set(row, start, product)?;
    for bit in 2..SERIAL_COUNTDOWN_WIDTH {
        product *= 1 - ((value >> bit) & 1);
        set(
            row,
            start
                .checked_add(bit - 1)
                .ok_or(BlockDeviceSerialError::Layout)?,
            product,
        )?;
    }
    Ok(())
}

fn append_bits(
    row: &mut [u64],
    start: usize,
    value: u64,
    width: usize,
) -> Result<(), BlockDeviceSerialError> {
    for bit in 0..width {
        set(
            row,
            start
                .checked_add(bit)
                .ok_or(BlockDeviceSerialError::Layout)?,
            (value >> bit) & 1,
        )?;
    }
    Ok(())
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), BlockDeviceSerialError> {
    *row.get_mut(index).ok_or(BlockDeviceSerialError::Layout)? = value;
    Ok(())
}

fn constrain_serial(
    ppu: &[NativeField],
    auxiliary: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if auxiliary.len() != SERIAL_AUX_COLUMN_COUNT
        || constraints.len() != SERIAL_AUX_COLUMN_COUNT * 2 + 139
    {
        return Err(UniformError::Shape);
    }
    let frontend = ppu
        .get(..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let device_io = device_io_selector_value(ppu)?;
    let one = NativeField::from_u64(1);
    let quiet = device_clocked_value(ppu)? * (one - device_io);
    let block_active = block_metadata::block_active_value(ppu)?;
    let boundary = frontend
        .get(BLOCK_ROUTING_COLUMN_COUNT..BLOCK_CONTROL_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let mut sink = ConstraintSink::new(constraints);
    constrain_auxiliary_canonical(auxiliary, block_active, quiet, &mut sink)?;
    constrain_high_packs(boundary, auxiliary, block_active, quiet, &mut sink)?;
    constrain_countdown(ppu, boundary, auxiliary, block_active, quiet, &mut sink)?;
    constrain_serial_registers(ppu, auxiliary, quiet, &mut sink)?;
    constrain_serial_interrupt(ppu, boundary, auxiliary, block_active, quiet, &mut sink)?;
    constrain_long_modes(ppu, auxiliary, &mut sink)?;
    sink.finish()
}

fn constrain_long_modes(
    ppu: &[NativeField],
    auxiliary: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let serial = halt_until_serial_value(ppu)?;
    sink.push(serial * (value(auxiliary, SERIAL_COMPLETED)? - one))?;
    sink.push(serial * packed_bits(auxiliary, COMPLETION_GAP_BITS_START, 5)?)?;
    let vblank = halt_until_vblank_value(ppu)?;
    sink.push(
        vblank
            * packed_bits(
                auxiliary,
                BEFORE_HIGH_BITS_START + SERIAL_COUNTDOWN_BITS_START,
                SERIAL_COUNTDOWN_WIDTH,
            )?,
    )?;
    sink.push(vblank * low_pack_bit_value(ppu, false, SERIAL_CONTROL_BIT_SEVEN)?)?;
    let timer = halt_until_timer_value(ppu)?;
    sink.push(
        timer
            * packed_bits(
                auxiliary,
                BEFORE_HIGH_BITS_START + SERIAL_COUNTDOWN_BITS_START,
                SERIAL_COUNTDOWN_WIDTH,
            )?,
    )?;
    sink.push(timer * low_pack_bit_value(ppu, false, SERIAL_CONTROL_BIT_SEVEN)?)
}

fn constrain_auxiliary_canonical(
    auxiliary: &[NativeField],
    block_active: NativeField,
    quiet: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    for (index, value) in auxiliary.iter().copied().enumerate() {
        let transition_only = (SERIAL_COMPLETED..BEFORE_IF_BITS_START).contains(&index);
        let boundary = !transition_only;
        let owner = if boundary { block_active } else { quiet };
        sink.push(value * (value - one))?;
        sink.push((one - owner) * value)?;
    }
    Ok(())
}

fn constrain_high_packs(
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    block_active: NativeField,
    quiet: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for (after, start) in [
        (false, BEFORE_HIGH_BITS_START),
        (true, AFTER_HIGH_BITS_START),
    ] {
        let state = device_state_value(boundary, after, STATE_DMG_HIGH_REGISTER_PACK_INDEX)?;
        sink.push(block_active * (state - packed_bits(auxiliary, start, 64)?))?;
    }
    for bit in 0..48 {
        sink.push(
            quiet
                * (value(auxiliary, BEFORE_HIGH_BITS_START + bit)?
                    - value(auxiliary, AFTER_HIGH_BITS_START + bit)?),
        )?;
    }
    constrain_countdown_range(auxiliary, BEFORE_HIGH_BITS_START, block_active, sink)?;
    constrain_countdown_range(auxiliary, AFTER_HIGH_BITS_START, block_active, sink)
}

fn constrain_countdown_range(
    auxiliary: &[NativeField],
    high_start: usize,
    quiet: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let countdown = high_start
        .checked_add(SERIAL_COUNTDOWN_BITS_START)
        .ok_or(UniformError::Shape)?;
    for bit in 13..16 {
        sink.push(quiet * value(auxiliary, countdown + bit)?)?;
    }
    let high = value(auxiliary, countdown + 12)?;
    for bit in 0..12 {
        sink.push(quiet * high * value(auxiliary, countdown + bit)?)?;
    }
    Ok(())
}

fn constrain_countdown(
    ppu: &[NativeField],
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    block_active: NativeField,
    quiet: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_zero_products(
        auxiliary,
        BEFORE_HIGH_BITS_START + SERIAL_COUNTDOWN_BITS_START,
        BEFORE_ZERO_PRODUCTS_START,
        block_active,
        sink,
    )?;
    constrain_zero_products(
        auxiliary,
        AFTER_HIGH_BITS_START + SERIAL_COUNTDOWN_BITS_START,
        AFTER_ZERO_PRODUCTS_START,
        block_active,
        sink,
    )?;
    let one = NativeField::from_u64(1);
    let before_zero = value(auxiliary, BEFORE_ZERO_PRODUCTS_START + 11)?;
    let after_zero = value(auxiliary, AFTER_ZERO_PRODUCTS_START + 11)?;
    let active = one - before_zero;
    let completed = value(auxiliary, SERIAL_COMPLETED)?;
    sink.push(quiet * (completed - active * after_zero))?;
    let before = packed_bits(
        auxiliary,
        BEFORE_HIGH_BITS_START + SERIAL_COUNTDOWN_BITS_START,
        SERIAL_COUNTDOWN_WIDTH,
    )?;
    let after = packed_bits(
        auxiliary,
        AFTER_HIGH_BITS_START + SERIAL_COUNTDOWN_BITS_START,
        SERIAL_COUNTDOWN_WIDTH,
    )?;
    let cycles = local_state_value(
        boundary,
        BASIC_BLOCK_INSTRUCTION_BOUND,
        STATE_CPU_M_CYCLES_INDEX,
    )? - local_state_value(boundary, 0, STATE_CPU_M_CYCLES_INDEX)?;
    let ticks = NativeField::from_u64(4) * cycles;
    sink.push(quiet * (after - before + active * (one - completed) * ticks + completed * before))?;
    constrain_completion_gap(auxiliary, quiet, completed, before, ticks, sink)?;
    sink.push(quiet * active * (low_pack_bit_value(ppu, false, SERIAL_CONTROL_BIT_ZERO)? - one))?;
    sink.push(quiet * active * (low_pack_bit_value(ppu, false, SERIAL_CONTROL_BIT_SEVEN)? - one))
}

fn constrain_zero_products(
    auxiliary: &[NativeField],
    bits_start: usize,
    products_start: usize,
    quiet: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let first = (one - value(auxiliary, bits_start)?) * (one - value(auxiliary, bits_start + 1)?);
    sink.push(quiet * (value(auxiliary, products_start)? - first))?;
    for bit in 2..SERIAL_COUNTDOWN_WIDTH {
        let prior = value(auxiliary, products_start + bit - 2)?;
        let next = value(auxiliary, products_start + bit - 1)?;
        sink.push(quiet * (next - prior * (one - value(auxiliary, bits_start + bit)?)))?;
    }
    Ok(())
}

fn constrain_completion_gap(
    auxiliary: &[NativeField],
    quiet: NativeField,
    completed: NativeField,
    before: NativeField,
    ticks: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    for bit in 0..5 {
        sink.push(quiet * (one - completed) * value(auxiliary, COMPLETION_GAP_BITS_START + bit)?)?;
    }
    let gap = packed_bits(auxiliary, COMPLETION_GAP_BITS_START, 5)?;
    sink.push(quiet * completed * (gap - ticks + before))
}

fn constrain_serial_registers(
    ppu: &[NativeField],
    auxiliary: &[NativeField],
    quiet: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let completed = value(auxiliary, SERIAL_COMPLETED)?;
    for bit in 0..8 {
        let before = low_pack_bit_value(ppu, false, bit)?;
        let after = low_pack_bit_value(ppu, true, bit)?;
        sink.push(quiet * (after - before - completed * (one - before)))?;
    }
    for bit in 8..15 {
        sink.push(
            quiet * (low_pack_bit_value(ppu, true, bit)? - low_pack_bit_value(ppu, false, bit)?),
        )?;
    }
    let before_control = low_pack_bit_value(ppu, false, SERIAL_CONTROL_BIT_SEVEN)?;
    let after_control = low_pack_bit_value(ppu, true, SERIAL_CONTROL_BIT_SEVEN)?;
    sink.push(quiet * (after_control - before_control * (one - completed)))
}

fn constrain_serial_interrupt(
    ppu: &[NativeField],
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    block_active: NativeField,
    quiet: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for (after, start) in [(false, BEFORE_IF_BITS_START), (true, AFTER_IF_BITS_START)] {
        let state = device_state_value(boundary, after, STATE_INTERRUPT_REQUEST_INDEX)?;
        sink.push(block_active * (state - packed_bits(auxiliary, start, 5)?))?;
    }
    let one = NativeField::from_u64(1);
    let before =
        value(auxiliary, BEFORE_IF_BITS_START + 3)? * (one - interrupt_source_value(ppu, 3)?);
    let after = value(auxiliary, AFTER_IF_BITS_START + 3)?;
    let completed = value(auxiliary, SERIAL_COMPLETED)?;
    sink.push(quiet * (after - before - (one - before) * completed))
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

pub(crate) fn interrupt_request_bit_value(
    row: &[NativeField],
    after: bool,
    bit: usize,
) -> Result<NativeField, UniformError> {
    if bit >= 5 || row.len() < BLOCK_DEVICE_SERIAL_COLUMN_COUNT {
        return Err(UniformError::Shape);
    }
    let relative_start = if after {
        AFTER_IF_BITS_START
    } else {
        BEFORE_IF_BITS_START
    };
    let index = SERIAL_AUX_START
        .checked_add(relative_start)
        .and_then(|value| value.checked_add(bit))
        .ok_or(UniformError::Shape)?;
    value(row, index)
}

pub(crate) fn serial_completed_value(row: &[NativeField]) -> Result<NativeField, UniformError> {
    if row.len() < BLOCK_DEVICE_SERIAL_COLUMN_COUNT {
        return Err(UniformError::Shape);
    }
    value(row, SERIAL_AUX_START + SERIAL_COMPLETED)
}

pub(crate) fn serial_countdown_zero_value(
    row: &[NativeField],
    after: bool,
) -> Result<NativeField, UniformError> {
    if row.len() < BLOCK_DEVICE_SERIAL_COLUMN_COUNT {
        return Err(UniformError::Shape);
    }
    let relative_start = if after {
        AFTER_ZERO_PRODUCTS_START
    } else {
        BEFORE_ZERO_PRODUCTS_START
    };
    value(row, SERIAL_AUX_START + relative_start + 11)
}

pub(crate) fn serial_completion_gap_bit_value(
    row: &[NativeField],
    bit: usize,
) -> Result<NativeField, UniformError> {
    if row.len() < BLOCK_DEVICE_SERIAL_COLUMN_COUNT || bit >= 5 {
        return Err(UniformError::Shape);
    }
    value(row, SERIAL_AUX_START + COMPLETION_GAP_BITS_START + bit)
}

pub(crate) fn high_pack_bit_value(
    row: &[NativeField],
    after: bool,
    bit: usize,
) -> Result<NativeField, UniformError> {
    if bit >= 64 || row.len() < BLOCK_DEVICE_SERIAL_COLUMN_COUNT {
        return Err(UniformError::Shape);
    }
    let relative_start = if after {
        AFTER_HIGH_BITS_START
    } else {
        BEFORE_HIGH_BITS_START
    };
    let index = SERIAL_AUX_START
        .checked_add(relative_start)
        .and_then(|value| value.checked_add(bit))
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
    fn quiet_block_advances_one_shared_serial_countdown() -> Result<(), Box<dyn std::error::Error>>
    {
        let blocks = lookup_blocks(
            &[0x00; BASIC_BLOCK_INSTRUCTION_BOUND],
            BASIC_BLOCK_INSTRUCTION_BOUND,
        )?;
        let witness = BlockDeviceSerialWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockDeviceSerialRelation, witness.columns())?;
        let mut mutated = witness.columns().to_vec();
        flip_witness_bit(&mut mutated, SERIAL_AUX_START + BEFORE_HIGH_BITS_START, 0)?;
        assert!(validate_uniform_witness(&BlockDeviceSerialRelation, &mutated).is_err());
        Ok(())
    }

    #[test]
    fn long_serial_event_binds_exact_completion() -> Result<(), Box<dyn std::error::Error>> {
        let blocks = machine_event_block(MachineEventFixture::HaltUntilSerial)?;
        let witness = BlockDeviceSerialWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockDeviceSerialRelation, witness.columns())?;
        let mut mutated = witness.columns().to_vec();
        flip_witness_bit(
            &mut mutated,
            SERIAL_AUX_START + COMPLETION_GAP_BITS_START,
            0,
        )?;
        assert!(validate_uniform_witness(&BlockDeviceSerialRelation, &mutated).is_err());
        Ok(())
    }
}
