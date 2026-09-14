//! Shared PPU position advancement for bounded device-clocked packed blocks.

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_trace::{BASIC_BLOCK_INSTRUCTION_BOUND, BasicBlock};

use crate::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_DEVICE_ENVELOPE_COLUMN_COUNT,
    BLOCK_DEVICE_ENVELOPE_CONSTRAINT_COUNT, BLOCK_DEVICE_ENVELOPE_MAX_DEGREE,
    BLOCK_FRONTEND_COLUMN_COUNT, BLOCK_ROUTING_COLUMN_COUNT, BlockDeviceEnvelopeError,
    BlockDeviceEnvelopeRelation, BlockDeviceEnvelopeWitness, ConstraintOutput, NativeField,
    STATE_CPU_M_CYCLES_INDEX, STATE_DMG_LOW_REGISTER_PACK_INDEX, STATE_PPU_DOT_INDEX,
    STATE_PPU_LINE_INDEX, UNIFORM_ROW_COUNT, UniformError, UniformRelation,
    block_boundary::{device_state_value, local_state_value},
    block_device::{device_clocked_block, device_io_selector_value},
    block_machine::{
        device_clocked_value, halt_until_serial_value, halt_until_timer_value,
        halt_until_vblank_value,
    },
    block_metadata,
};

const PPU_LINE_MAXIMUM: u64 = 153;
const PPU_DOT_MAXIMUM: u64 = 455;
const PPU_FRAME_T_CYCLES: u64 = 154 * 456;
const LCD_ENABLE_LOW_PACK_BIT: usize = 39;

const PPU_AUX_START: usize = BLOCK_DEVICE_ENVELOPE_COLUMN_COUNT;
const BEFORE_LOW_PACK_BITS_START: usize = 0;
const AFTER_LOW_PACK_BITS_START: usize = BEFORE_LOW_PACK_BITS_START + 64;
const BEFORE_LINE_BITS_START: usize = AFTER_LOW_PACK_BITS_START + 64;
const BEFORE_DOT_BITS_START: usize = BEFORE_LINE_BITS_START + 8;
const AFTER_LINE_BITS_START: usize = BEFORE_DOT_BITS_START + 9;
const AFTER_DOT_BITS_START: usize = AFTER_LINE_BITS_START + 8;
const BEFORE_LINE_SLACK_BITS_START: usize = AFTER_DOT_BITS_START + 9;
const BEFORE_DOT_SLACK_BITS_START: usize = BEFORE_LINE_SLACK_BITS_START + 8;
const AFTER_LINE_SLACK_BITS_START: usize = BEFORE_DOT_SLACK_BITS_START + 9;
const AFTER_DOT_SLACK_BITS_START: usize = AFTER_LINE_SLACK_BITS_START + 8;
const FRAME_WRAP: usize = AFTER_DOT_SLACK_BITS_START + 9;
const PPU_AUX_COLUMN_COUNT: usize = FRAME_WRAP + 1;

/// Logical columns in the device envelope plus one compact shared PPU witness.
pub const BLOCK_DEVICE_PPU_COLUMN_COUNT: usize =
    BLOCK_DEVICE_ENVELOPE_COLUMN_COUNT + PPU_AUX_COLUMN_COUNT;
/// Identities in the shared PPU relation.
pub const BLOCK_DEVICE_PPU_CONSTRAINT_COUNT: usize =
    BLOCK_DEVICE_ENVELOPE_CONSTRAINT_COUNT + PPU_AUX_COLUMN_COUNT * 2 + 68;
/// Maximum total degree in the shared PPU relation.
pub const BLOCK_DEVICE_PPU_MAX_DEGREE: usize = BLOCK_DEVICE_ENVELOPE_MAX_DEGREE;

const _: () = assert!(BASIC_BLOCK_INSTRUCTION_BOUND == 4);
const _: () = assert!(PPU_AUX_COLUMN_COUNT == 197);
const _: () = assert!(BLOCK_DEVICE_PPU_COLUMN_COUNT == 1_038);
const _: () = assert!(BLOCK_DEVICE_PPU_CONSTRAINT_COUNT == 1_868);
const _: () = assert!(BLOCK_DEVICE_PPU_MAX_DEGREE == 7);

/// Fixed-row packed witness carrying one PPU transition per device-quiet block.
#[derive(Debug)]
pub struct BlockDevicePpuWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to construct the shared packed-block PPU witness.
#[derive(Debug, Error)]
pub enum BlockDevicePpuError {
    /// Shared-device envelope construction failed.
    #[error("packed-block device envelope construction failed: {0}")]
    Envelope(#[from] BlockDeviceEnvelopeError),
    /// A validated block exposed an invalid or inconsistent PPU position transition.
    #[error("packed block {block} has an inconsistent quiet PPU transition")]
    InvalidTransition {
        /// Zero-based packed-block row.
        block: usize,
    },
    /// PPU auxiliary columns violated their fixed layout.
    #[error("packed-block PPU witness violated its typed layout")]
    Layout,
}

/// Device envelope plus shared PPU position advancement.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockDevicePpuRelation;

impl BlockDevicePpuWitness {
    /// Derives one compact PPU witness for every bounded device-clocked block.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockDevicePpuError> {
        let envelope = BlockDeviceEnvelopeWitness::from_blocks(blocks)?;
        let active_block_count = envelope.active_block_count();
        let mut auxiliary = (0..PPU_AUX_COLUMN_COUNT)
            .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
            .collect::<Vec<_>>();
        for (block_index, block) in blocks.iter().enumerate() {
            let mut row = [0_u64; PPU_AUX_COLUMN_COUNT];
            let quiet = device_clocked_block(block)?;
            append_ppu_row(&mut row, block, block_index, quiet)?;
            for (column, value) in auxiliary.iter_mut().zip(row) {
                column.push(value);
            }
        }
        for column in &mut auxiliary {
            column.resize(UNIFORM_ROW_COUNT, 0);
        }
        let mut columns = envelope.into_columns();
        columns.extend(auxiliary);
        if columns.len() != BLOCK_DEVICE_PPU_COLUMN_COUNT {
            return Err(BlockDevicePpuError::Layout);
        }
        Ok(Self {
            columns,
            active_block_count,
        })
    }

    /// Returns every logical column in envelope-then-PPU order.
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

impl UniformRelation for BlockDevicePpuRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-device-ppu/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [841_u64, 1_406, 197, 70_224, 1_038, 1_868, 2] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_DEVICE_PPU_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_DEVICE_PPU_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_DEVICE_PPU_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_DEVICE_PPU_COLUMN_COUNT
            || constraints.len() != BLOCK_DEVICE_PPU_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let envelope = row
            .get(..BLOCK_DEVICE_ENVELOPE_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let auxiliary = row
            .get(PPU_AUX_START..BLOCK_DEVICE_PPU_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let (envelope_constraints, ppu_constraints) =
            constraints.split_at_mut(BLOCK_DEVICE_ENVELOPE_CONSTRAINT_COUNT);
        BlockDeviceEnvelopeRelation.evaluate(envelope, envelope_constraints)?;
        constrain_ppu(envelope, auxiliary, ppu_constraints)
    }
}

fn append_ppu_row(
    row: &mut [u64],
    block: &BasicBlock,
    block_index: usize,
    quiet: bool,
) -> Result<(), BlockDevicePpuError> {
    let before = block.initial_state().dmg_devices();
    let after = block.final_state().dmg_devices();
    let before_line = u64::from(before.ppu_line());
    let before_dot = u64::from(before.ppu_dot());
    let after_line = u64::from(after.ppu_line());
    let after_dot = u64::from(after.ppu_dot());
    let before_low_pack = before.low_register_pack();
    let after_low_pack = after.low_register_pack();
    append_bits(row, BEFORE_LOW_PACK_BITS_START, before_low_pack, 64)?;
    append_bits(row, AFTER_LOW_PACK_BITS_START, after_low_pack, 64)?;
    append_ranged_position(
        row,
        BEFORE_LINE_BITS_START,
        before_line,
        8,
        PPU_LINE_MAXIMUM,
    )?;
    append_ranged_position(row, BEFORE_DOT_BITS_START, before_dot, 9, PPU_DOT_MAXIMUM)?;
    append_ranged_position(row, AFTER_LINE_BITS_START, after_line, 8, PPU_LINE_MAXIMUM)?;
    append_ranged_position(row, AFTER_DOT_BITS_START, after_dot, 9, PPU_DOT_MAXIMUM)?;
    if !quiet {
        return Ok(());
    }
    let enabled = before_low_pack & (1_u64 << LCD_ENABLE_LOW_PACK_BIT) != 0;
    let increment = block
        .m_cycle_count()
        .checked_mul(4)
        .ok_or(BlockDevicePpuError::InvalidTransition { block: block_index })?;
    let before_position = ppu_position(before_line, before_dot, block_index)?;
    let after_position = ppu_position(after_line, after_dot, block_index)?;
    let total = before_position
        .checked_add(increment)
        .ok_or(BlockDevicePpuError::InvalidTransition { block: block_index })?;
    let expected = if enabled {
        total % PPU_FRAME_T_CYCLES
    } else {
        0
    };
    if after_position != expected {
        return Err(BlockDevicePpuError::InvalidTransition { block: block_index });
    }
    set(
        row,
        FRAME_WRAP,
        u64::from(enabled && total >= PPU_FRAME_T_CYCLES),
    )
}

fn append_ranged_position(
    row: &mut [u64],
    bits_start: usize,
    value: u64,
    width: usize,
    maximum: u64,
) -> Result<(), BlockDevicePpuError> {
    let slack_start = match bits_start {
        BEFORE_LINE_BITS_START => BEFORE_LINE_SLACK_BITS_START,
        BEFORE_DOT_BITS_START => BEFORE_DOT_SLACK_BITS_START,
        AFTER_LINE_BITS_START => AFTER_LINE_SLACK_BITS_START,
        AFTER_DOT_BITS_START => AFTER_DOT_SLACK_BITS_START,
        _ => return Err(BlockDevicePpuError::Layout),
    };
    let slack = maximum
        .checked_sub(value)
        .ok_or(BlockDevicePpuError::Layout)?;
    append_bits(row, bits_start, value, width)?;
    append_bits(row, slack_start, slack, width)
}

fn ppu_position(line: u64, dot: u64, block: usize) -> Result<u64, BlockDevicePpuError> {
    if line > PPU_LINE_MAXIMUM || dot > PPU_DOT_MAXIMUM {
        return Err(BlockDevicePpuError::InvalidTransition { block });
    }
    line.checked_mul(PPU_DOT_MAXIMUM + 1)
        .and_then(|position| position.checked_add(dot))
        .ok_or(BlockDevicePpuError::InvalidTransition { block })
}

fn append_bits(
    row: &mut [u64],
    start: usize,
    value: u64,
    width: usize,
) -> Result<(), BlockDevicePpuError> {
    for bit in 0..width {
        set(
            row,
            start.checked_add(bit).ok_or(BlockDevicePpuError::Layout)?,
            (value >> bit) & 1,
        )?;
    }
    Ok(())
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), BlockDevicePpuError> {
    *row.get_mut(index).ok_or(BlockDevicePpuError::Layout)? = value;
    Ok(())
}

fn constrain_ppu(
    envelope: &[NativeField],
    auxiliary: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if auxiliary.len() != PPU_AUX_COLUMN_COUNT || constraints.len() != PPU_AUX_COLUMN_COUNT * 2 + 68
    {
        return Err(UniformError::Shape);
    }
    let frontend = envelope
        .get(..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let device_io = device_io_selector_value(envelope)?;
    let one = NativeField::from_u64(1);
    let quiet = device_clocked_value(envelope)? * (one - device_io);
    let block_active = block_metadata::block_active_value(envelope)?;
    let mut sink = ConstraintSink::new(constraints);
    constrain_auxiliary_canonical(auxiliary, block_active, quiet, &mut sink)?;
    constrain_ppu_transition(frontend, auxiliary, block_active, quiet, &mut sink)?;
    constrain_long_mode_preconditions(envelope, auxiliary, &mut sink)?;
    sink.finish()
}

fn constrain_long_mode_preconditions(
    envelope: &[NativeField],
    auxiliary: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let lcd_enabled = value(
        auxiliary,
        BEFORE_LOW_PACK_BITS_START + LCD_ENABLE_LOW_PACK_BIT,
    )?;
    let vblank = halt_until_vblank_value(envelope)?;
    sink.push(vblank * (lcd_enabled - one))?;
    sink.push(halt_until_serial_value(envelope)? * lcd_enabled)?;
    sink.push(halt_until_timer_value(envelope)? * lcd_enabled)?;
    sink.push(vblank * packed_bits(auxiliary, BEFORE_LOW_PACK_BITS_START + 40, 8)?)
}

fn constrain_auxiliary_canonical(
    auxiliary: &[NativeField],
    block_active: NativeField,
    quiet: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    for (index, value) in auxiliary.iter().copied().enumerate() {
        let owner = if index == FRAME_WRAP {
            quiet
        } else {
            block_active
        };
        sink.push(value * (value - one))?;
        sink.push((one - owner) * value)?;
    }
    Ok(())
}

fn constrain_ppu_transition(
    frontend: &[NativeField],
    auxiliary: &[NativeField],
    block_active: NativeField,
    quiet: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let boundary = frontend
        .get(BLOCK_ROUTING_COLUMN_COUNT..BLOCK_CONTROL_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let before_line = device_state_value(boundary, false, STATE_PPU_LINE_INDEX)?;
    let before_dot = device_state_value(boundary, false, STATE_PPU_DOT_INDEX)?;
    let after_line = device_state_value(boundary, true, STATE_PPU_LINE_INDEX)?;
    let after_dot = device_state_value(boundary, true, STATE_PPU_DOT_INDEX)?;
    let before_low = device_state_value(boundary, false, STATE_DMG_LOW_REGISTER_PACK_INDEX)?;
    let after_low = device_state_value(boundary, true, STATE_DMG_LOW_REGISTER_PACK_INDEX)?;
    sink.push(
        block_active * (before_low - packed_bits(auxiliary, BEFORE_LOW_PACK_BITS_START, 64)?),
    )?;
    sink.push(block_active * (after_low - packed_bits(auxiliary, AFTER_LOW_PACK_BITS_START, 64)?))?;
    for bit in 16..64 {
        sink.push(
            quiet
                * (value(auxiliary, BEFORE_LOW_PACK_BITS_START + bit)?
                    - value(auxiliary, AFTER_LOW_PACK_BITS_START + bit)?),
        )?;
    }
    for (state, bits, slack, width, maximum) in [
        (
            before_line,
            BEFORE_LINE_BITS_START,
            BEFORE_LINE_SLACK_BITS_START,
            8,
            PPU_LINE_MAXIMUM,
        ),
        (
            before_dot,
            BEFORE_DOT_BITS_START,
            BEFORE_DOT_SLACK_BITS_START,
            9,
            PPU_DOT_MAXIMUM,
        ),
        (
            after_line,
            AFTER_LINE_BITS_START,
            AFTER_LINE_SLACK_BITS_START,
            8,
            PPU_LINE_MAXIMUM,
        ),
        (
            after_dot,
            AFTER_DOT_BITS_START,
            AFTER_DOT_SLACK_BITS_START,
            9,
            PPU_DOT_MAXIMUM,
        ),
    ] {
        sink.push(block_active * (state - packed_bits(auxiliary, bits, width)?))?;
        sink.push(
            block_active
                * (state + packed_bits(auxiliary, slack, width)? - NativeField::from_u64(maximum)),
        )?;
    }
    constrain_position_advance(
        boundary,
        auxiliary,
        quiet,
        PpuPositions {
            before_line,
            before_dot,
            after_line,
            after_dot,
        },
        sink,
    )
}

fn constrain_position_advance(
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    quiet: NativeField,
    positions: PpuPositions,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let enabled = value(
        auxiliary,
        BEFORE_LOW_PACK_BITS_START + LCD_ENABLE_LOW_PACK_BIT,
    )?;
    let disabled = one - enabled;
    for state in [
        positions.before_line,
        positions.before_dot,
        positions.after_line,
        positions.after_dot,
    ] {
        sink.push(quiet * disabled * state)?;
    }
    let before_position = positions.before_line * NativeField::from_u64(456) + positions.before_dot;
    let after_position = positions.after_line * NativeField::from_u64(456) + positions.after_dot;
    let cycles = local_state_value(
        boundary,
        BASIC_BLOCK_INSTRUCTION_BOUND,
        STATE_CPU_M_CYCLES_INDEX,
    )? - local_state_value(boundary, 0, STATE_CPU_M_CYCLES_INDEX)?;
    let wrap = value(auxiliary, FRAME_WRAP)?;
    sink.push(
        quiet
            * enabled
            * (after_position - before_position - NativeField::from_u64(4) * cycles
                + NativeField::from_u64(PPU_FRAME_T_CYCLES) * wrap),
    )?;
    sink.push(quiet * disabled * wrap)
}

#[derive(Clone, Copy)]
struct PpuPositions {
    before_line: NativeField,
    before_dot: NativeField,
    after_line: NativeField,
    after_dot: NativeField,
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

pub(crate) fn low_pack_bit_value(
    row: &[NativeField],
    after: bool,
    bit: usize,
) -> Result<NativeField, UniformError> {
    if bit >= 64 || row.len() < BLOCK_DEVICE_PPU_COLUMN_COUNT {
        return Err(UniformError::Shape);
    }
    let relative_start = if after {
        AFTER_LOW_PACK_BITS_START
    } else {
        BEFORE_LOW_PACK_BITS_START
    };
    let index = PPU_AUX_START
        .checked_add(relative_start)
        .and_then(|value| value.checked_add(bit))
        .ok_or(UniformError::Shape)?;
    value(row, index)
}

pub(crate) fn ppu_line_bit_value(
    row: &[NativeField],
    after: bool,
    bit: usize,
) -> Result<NativeField, UniformError> {
    if bit >= 8 || row.len() < BLOCK_DEVICE_PPU_COLUMN_COUNT {
        return Err(UniformError::Shape);
    }
    let relative_start = if after {
        AFTER_LINE_BITS_START
    } else {
        BEFORE_LINE_BITS_START
    };
    let index = PPU_AUX_START
        .checked_add(relative_start)
        .and_then(|value| value.checked_add(bit))
        .ok_or(UniformError::Shape)?;
    value(row, index)
}

pub(crate) fn ppu_dot_bit_value(
    row: &[NativeField],
    after: bool,
    bit: usize,
) -> Result<NativeField, UniformError> {
    if bit >= 9 || row.len() < BLOCK_DEVICE_PPU_COLUMN_COUNT {
        return Err(UniformError::Shape);
    }
    let relative_start = if after {
        AFTER_DOT_BITS_START
    } else {
        BEFORE_DOT_BITS_START
    };
    let index = PPU_AUX_START
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
    fn quiet_block_advances_one_shared_ppu_position() -> Result<(), Box<dyn std::error::Error>> {
        let blocks = lookup_blocks(
            &[0x00; BASIC_BLOCK_INSTRUCTION_BOUND],
            BASIC_BLOCK_INSTRUCTION_BOUND,
        )?;
        let witness = BlockDevicePpuWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockDevicePpuRelation, witness.columns())?;
        let mut mutated = witness.columns().to_vec();
        flip_witness_bit(
            &mut mutated,
            PPU_AUX_START + BEFORE_LOW_PACK_BITS_START + LCD_ENABLE_LOW_PACK_BIT,
            0,
        )?;
        assert!(validate_uniform_witness(&BlockDevicePpuRelation, &mutated).is_err());
        Ok(())
    }
}
