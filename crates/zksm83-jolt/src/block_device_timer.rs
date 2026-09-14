//! Shared timer-divider advancement for bounded device-clocked packed blocks.

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_trace::{BASIC_BLOCK_INSTRUCTION_BOUND, BasicBlock};

use crate::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_DEVICE_SERIAL_COLUMN_COUNT,
    BLOCK_DEVICE_SERIAL_CONSTRAINT_COUNT, BLOCK_DEVICE_SERIAL_MAX_DEGREE,
    BLOCK_FRONTEND_COLUMN_COUNT, BLOCK_ROUTING_COLUMN_COUNT, BlockDevicePpuError,
    BlockDeviceSerialError, BlockDeviceSerialRelation, BlockDeviceSerialWitness, ConstraintOutput,
    NativeField, STATE_CPU_M_CYCLES_INDEX, STATE_TIMER_DIV_INDEX, UNIFORM_ROW_COUNT, UniformError,
    UniformRelation,
    block_boundary::{device_state_value, local_state_value},
    block_device::{device_clocked_block, device_io_selector_value},
    block_machine::device_clocked_value,
    block_metadata,
};

const TIMER_AUX_START: usize = BLOCK_DEVICE_SERIAL_COLUMN_COUNT;
const BEFORE_DIV_BITS_START: usize = 0;
const AFTER_DIV_BITS_START: usize = BEFORE_DIV_BITS_START + 16;
const DIV_QUOTIENT_BITS_START: usize = AFTER_DIV_BITS_START + 16;
const DIV_QUOTIENT_WIDTH: usize = 5;
const TIMER_AUX_COLUMN_COUNT: usize = DIV_QUOTIENT_BITS_START + DIV_QUOTIENT_WIDTH;
const TIMER_DIV_MODULUS: u64 = 1 << 16;

/// Logical columns in the shared serial relation plus timer-divider witness.
pub const BLOCK_DEVICE_TIMER_COLUMN_COUNT: usize =
    BLOCK_DEVICE_SERIAL_COLUMN_COUNT + TIMER_AUX_COLUMN_COUNT;
/// Identities in the shared timer-divider relation.
pub const BLOCK_DEVICE_TIMER_CONSTRAINT_COUNT: usize =
    BLOCK_DEVICE_SERIAL_CONSTRAINT_COUNT + TIMER_AUX_COLUMN_COUNT * 2 + 3;
/// Maximum total degree in the shared timer-divider relation.
pub const BLOCK_DEVICE_TIMER_MAX_DEGREE: usize = BLOCK_DEVICE_SERIAL_MAX_DEGREE;

const _: () = assert!(BASIC_BLOCK_INSTRUCTION_BOUND == 4);
const _: () = assert!(TIMER_AUX_COLUMN_COUNT == 37);
const _: () = assert!(BLOCK_DEVICE_TIMER_COLUMN_COUNT == 1_243);
const _: () = assert!(BLOCK_DEVICE_TIMER_CONSTRAINT_COUNT == 2_420);
const _: () = assert!(BLOCK_DEVICE_TIMER_MAX_DEGREE == 7);

/// Fixed-row packed witness carrying one timer-divider transition per quiet block.
#[derive(Debug)]
pub struct BlockDeviceTimerWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to construct the shared packed-block timer witness.
#[derive(Debug, Error)]
pub enum BlockDeviceTimerError {
    /// Shared serial witness construction failed.
    #[error("packed-block serial construction failed: {0}")]
    Serial(#[from] BlockDeviceSerialError),
    /// A validated block exposed an inconsistent timer-divider transition.
    #[error("packed block {block} has an inconsistent quiet timer-divider transition")]
    InvalidTransition {
        /// Zero-based packed-block row.
        block: usize,
    },
    /// Timer auxiliary columns violated their fixed layout.
    #[error("packed-block timer witness violated its typed layout")]
    Layout,
}

/// Shared serial relation plus exact 16-bit timer-divider advancement.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockDeviceTimerRelation;

impl BlockDeviceTimerWitness {
    /// Derives one timer-divider witness for every bounded device-clocked block.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockDeviceTimerError> {
        let serial = BlockDeviceSerialWitness::from_blocks(blocks)?;
        let active_block_count = serial.active_block_count();
        let mut auxiliary = (0..TIMER_AUX_COLUMN_COUNT)
            .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
            .collect::<Vec<_>>();
        for (block_index, block) in blocks.iter().enumerate() {
            let mut row = [0_u64; TIMER_AUX_COLUMN_COUNT];
            let quiet = device_clocked_block(block)
                .map_err(BlockDevicePpuError::from)
                .map_err(BlockDeviceSerialError::from)?;
            append_timer_row(&mut row, block, block_index, quiet)?;
            for (column, value) in auxiliary.iter_mut().zip(row) {
                column.push(value);
            }
        }
        for column in &mut auxiliary {
            column.resize(UNIFORM_ROW_COUNT, 0);
        }
        let mut columns = serial.into_columns();
        columns.extend(auxiliary);
        if columns.len() != BLOCK_DEVICE_TIMER_COLUMN_COUNT {
            return Err(BlockDeviceTimerError::Layout);
        }
        Ok(Self {
            columns,
            active_block_count,
        })
    }

    /// Returns every logical column in serial-then-timer order.
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

impl UniformRelation for BlockDeviceTimerRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-device-timer/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [1_206_u64, 2_343, 37, 65_536, 1_243, 2_420, 2] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_DEVICE_TIMER_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_DEVICE_TIMER_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_DEVICE_TIMER_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_DEVICE_TIMER_COLUMN_COUNT
            || constraints.len() != BLOCK_DEVICE_TIMER_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let serial = row
            .get(..BLOCK_DEVICE_SERIAL_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let auxiliary = row
            .get(TIMER_AUX_START..BLOCK_DEVICE_TIMER_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let (serial_constraints, timer_constraints) =
            constraints.split_at_mut(BLOCK_DEVICE_SERIAL_CONSTRAINT_COUNT);
        BlockDeviceSerialRelation.evaluate(serial, serial_constraints)?;
        constrain_timer(serial, auxiliary, timer_constraints)
    }
}

fn append_timer_row(
    row: &mut [u64],
    block: &BasicBlock,
    block_index: usize,
    quiet: bool,
) -> Result<(), BlockDeviceTimerError> {
    let before = u64::from(block.initial_state().dmg_devices().timer().raw_div());
    let after = u64::from(block.final_state().dmg_devices().timer().raw_div());
    append_bits(row, BEFORE_DIV_BITS_START, before, 16)?;
    append_bits(row, AFTER_DIV_BITS_START, after, 16)?;
    if !quiet {
        return Ok(());
    }
    let ticks = block
        .m_cycle_count()
        .checked_mul(4)
        .ok_or(BlockDeviceTimerError::InvalidTransition { block: block_index })?;
    let total = before
        .checked_add(ticks)
        .ok_or(BlockDeviceTimerError::InvalidTransition { block: block_index })?;
    if after != total % TIMER_DIV_MODULUS {
        return Err(BlockDeviceTimerError::InvalidTransition { block: block_index });
    }
    let quotient = total / TIMER_DIV_MODULUS;
    if quotient >= 1_u64 << DIV_QUOTIENT_WIDTH {
        return Err(BlockDeviceTimerError::InvalidTransition { block: block_index });
    }
    append_bits(row, DIV_QUOTIENT_BITS_START, quotient, DIV_QUOTIENT_WIDTH)
}

fn append_bits(
    row: &mut [u64],
    start: usize,
    value: u64,
    width: usize,
) -> Result<(), BlockDeviceTimerError> {
    for bit in 0..width {
        set(
            row,
            start
                .checked_add(bit)
                .ok_or(BlockDeviceTimerError::Layout)?,
            (value >> bit) & 1,
        )?;
    }
    Ok(())
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), BlockDeviceTimerError> {
    *row.get_mut(index).ok_or(BlockDeviceTimerError::Layout)? = value;
    Ok(())
}

fn constrain_timer(
    serial: &[NativeField],
    auxiliary: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if auxiliary.len() != TIMER_AUX_COLUMN_COUNT
        || constraints.len() != TIMER_AUX_COLUMN_COUNT * 2 + 3
    {
        return Err(UniformError::Shape);
    }
    let frontend = serial
        .get(..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let device_io = device_io_selector_value(serial)?;
    let one = NativeField::from_u64(1);
    let quiet = device_clocked_value(serial)? * (one - device_io);
    let block_active = block_metadata::block_active_value(serial)?;
    let boundary = frontend
        .get(BLOCK_ROUTING_COLUMN_COUNT..BLOCK_CONTROL_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let mut sink = ConstraintSink::new(constraints);
    for (index, value) in auxiliary.iter().copied().enumerate() {
        let owner = if index < DIV_QUOTIENT_BITS_START {
            block_active
        } else {
            quiet
        };
        sink.push(value * (value - one))?;
        sink.push((one - owner) * value)?;
    }
    let before = device_state_value(boundary, false, STATE_TIMER_DIV_INDEX)?;
    let after = device_state_value(boundary, true, STATE_TIMER_DIV_INDEX)?;
    sink.push(block_active * (before - packed_bits(auxiliary, BEFORE_DIV_BITS_START, 16)?))?;
    sink.push(block_active * (after - packed_bits(auxiliary, AFTER_DIV_BITS_START, 16)?))?;
    let cycles = local_state_value(
        boundary,
        BASIC_BLOCK_INSTRUCTION_BOUND,
        STATE_CPU_M_CYCLES_INDEX,
    )? - local_state_value(boundary, 0, STATE_CPU_M_CYCLES_INDEX)?;
    sink.push(
        quiet
            * (after - before - NativeField::from_u64(4) * cycles
                + NativeField::from_u64(TIMER_DIV_MODULUS)
                    * packed_bits(auxiliary, DIV_QUOTIENT_BITS_START, DIV_QUOTIENT_WIDTH)?),
    )?;
    sink.finish()
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

pub(crate) fn timer_div_bit_value(
    row: &[NativeField],
    after: bool,
    bit: usize,
) -> Result<NativeField, UniformError> {
    if bit >= 16 || row.len() < BLOCK_DEVICE_TIMER_COLUMN_COUNT {
        return Err(UniformError::Shape);
    }
    let relative_start = if after {
        AFTER_DIV_BITS_START
    } else {
        BEFORE_DIV_BITS_START
    };
    let index = TIMER_AUX_START
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
        block_test_support::{flip_witness_bit, lookup_blocks},
        validate_uniform_witness,
    };

    #[test]
    fn quiet_block_advances_one_shared_timer_divider() -> Result<(), Box<dyn std::error::Error>> {
        let blocks = lookup_blocks(
            &[0x00; BASIC_BLOCK_INSTRUCTION_BOUND],
            BASIC_BLOCK_INSTRUCTION_BOUND,
        )?;
        let witness = BlockDeviceTimerWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockDeviceTimerRelation, witness.columns())?;
        let mut mutated = witness.columns().to_vec();
        flip_witness_bit(&mut mutated, TIMER_AUX_START + BEFORE_DIV_BITS_START, 0)?;
        assert!(validate_uniform_witness(&BlockDeviceTimerRelation, &mutated).is_err());
        Ok(())
    }
}
