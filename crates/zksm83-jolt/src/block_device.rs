//! Shared-device invariants over packed SM83 instruction and machine blocks.

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_core::{BusEventKind, StepKind};
use zksm83_trace::{BASIC_BLOCK_BUS_EVENT_BOUND, BasicBlock};

use crate::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_FRONTEND_COLUMN_COUNT, BLOCK_ISA_CONTROL_COLUMN_COUNT,
    BLOCK_MACHINE_COLUMN_COUNT, BLOCK_MACHINE_CONSTRAINT_COUNT, BLOCK_MACHINE_MAX_DEGREE,
    BLOCK_ROUTING_COLUMN_COUNT, BlockMachineError, BlockMachineRelation, BlockMachineWitness,
    ConstraintOutput, NativeField, STATE_APU_CONTROL_HIGH_PACK_INDEX,
    STATE_APU_CONTROL_LOW_PACK_INDEX, STATE_APU_MIXER_PACK_INDEX, STATE_APU_WAVE_HIGH_PACK_INDEX,
    STATE_APU_WAVE_LOW_PACK_INDEX, STATE_INTERRUPT_ENABLE_INDEX, STATE_JOYPAD_PACK_INDEX,
    UNIFORM_ROW_COUNT, UniformError, UniformRelation, block_boundary::device_state_value,
    block_bus::slot_kind_selector, block_metadata,
};

/// Logical columns in the packed machine relation plus its device-I/O selector.
pub const BLOCK_DEVICE_ENVELOPE_COLUMN_COUNT: usize = BLOCK_MACHINE_COLUMN_COUNT + 1;
/// Identities in the packed machine relation plus shared-device envelope checks.
pub const BLOCK_DEVICE_ENVELOPE_CONSTRAINT_COUNT: usize = BLOCK_MACHINE_CONSTRAINT_COUNT + 9;
/// Maximum total degree in the shared-device envelope relation.
pub const BLOCK_DEVICE_ENVELOPE_MAX_DEGREE: usize = BLOCK_MACHINE_MAX_DEGREE;

const DEVICE_IO_SELECTOR: usize = BLOCK_MACHINE_COLUMN_COUNT;
const DEVICE_IO_CODES: [u8; 3] = [11, 12, 13];
const QUIET_DEVICE_INVARIANTS: [usize; 7] = [
    STATE_INTERRUPT_ENABLE_INDEX,
    STATE_APU_CONTROL_LOW_PACK_INDEX,
    STATE_APU_CONTROL_HIGH_PACK_INDEX,
    STATE_APU_MIXER_PACK_INDEX,
    STATE_APU_WAVE_LOW_PACK_INDEX,
    STATE_APU_WAVE_HIGH_PACK_INDEX,
    STATE_JOYPAD_PACK_INDEX,
];

const _: () = assert!(BASIC_BLOCK_BUS_EVENT_BOUND == 5);
const _: () = assert!(BLOCK_DEVICE_ENVELOPE_COLUMN_COUNT == 797);
const _: () = assert!(BLOCK_DEVICE_ENVELOPE_CONSTRAINT_COUNT == 1_362);
const _: () = assert!(BLOCK_DEVICE_ENVELOPE_MAX_DEGREE == 7);

/// Fixed-row packed witness with one explicit device-I/O selector per block.
#[derive(Debug)]
pub struct BlockDeviceEnvelopeWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to construct a shared-device envelope witness.
#[derive(Debug, Error)]
pub enum BlockDeviceEnvelopeError {
    /// Packed machine construction failed.
    #[error("packed-block machine construction failed: {0}")]
    Machine(#[from] BlockMachineError),
    /// A block contains more than one typed device-I/O event.
    #[error("packed block {block} has {actual} device-I/O events, maximum is one")]
    TooManyDeviceEvents {
        /// Zero-based packed-block row.
        block: usize,
        /// Number of typed device-I/O events found in the block.
        actual: usize,
    },
    /// The independently derived columns violated the fixed-row layout.
    #[error("packed-block device envelope violated its typed layout")]
    Layout,
}

/// Machine relation plus device-I/O classification and quiet-device invariants.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockDeviceEnvelopeRelation;

impl BlockDeviceEnvelopeWitness {
    /// Derives the packed front end and one bounded device-I/O selector per block.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockDeviceEnvelopeError> {
        let machine = BlockMachineWitness::from_blocks(blocks)?;
        let active_block_count = machine.active_block_count();
        let mut device_io = Vec::with_capacity(UNIFORM_ROW_COUNT);
        for (block_index, block) in blocks.iter().enumerate() {
            let count = device_io_count(block)?;
            if count > 1 {
                return Err(BlockDeviceEnvelopeError::TooManyDeviceEvents {
                    block: block_index,
                    actual: count,
                });
            }
            device_io.push(u64::from(count == 1));
        }
        device_io.resize(UNIFORM_ROW_COUNT, 0);
        let mut columns = machine.into_columns();
        columns.push(device_io);
        if columns.len() != BLOCK_DEVICE_ENVELOPE_COLUMN_COUNT {
            return Err(BlockDeviceEnvelopeError::Layout);
        }
        Ok(Self {
            columns,
            active_block_count,
        })
    }

    /// Returns every logical column in machine-then-device-selector order.
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

impl UniformRelation for BlockDeviceEnvelopeRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-device-envelope/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [796_u64, 1_353, 3, 7, 797, 1_362, 1] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_DEVICE_ENVELOPE_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_DEVICE_ENVELOPE_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_DEVICE_ENVELOPE_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_DEVICE_ENVELOPE_COLUMN_COUNT
            || constraints.len() != BLOCK_DEVICE_ENVELOPE_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let machine = row
            .get(..BLOCK_MACHINE_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let (machine_constraints, device_constraints) =
            constraints.split_at_mut(BLOCK_MACHINE_CONSTRAINT_COUNT);
        BlockMachineRelation.evaluate(machine, machine_constraints)?;
        let frontend = machine
            .get(..BLOCK_FRONTEND_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        constrain_device_envelope(frontend, row, device_constraints)
    }
}

pub(crate) fn device_io_count(block: &BasicBlock) -> Result<usize, BlockDeviceEnvelopeError> {
    block
        .rows()
        .try_fold(0_usize, |count, row| {
            row.effects()
                .ordered_bus_events()
                .iter()
                .filter(|event| {
                    matches!(
                        event.kind(),
                        BusEventKind::DmgMmioRead
                            | BusEventKind::DmgMmioWrite
                            | BusEventKind::DmgJoypadRead
                    )
                })
                .try_fold(count, |count, _event| count.checked_add(1))
        })
        .ok_or(BlockDeviceEnvelopeError::Layout)
}

pub(crate) fn device_clocked_block(block: &BasicBlock) -> Result<bool, BlockDeviceEnvelopeError> {
    if device_io_count(block)? != 0 {
        return Ok(false);
    }
    if block.instruction_count() != 0 {
        return Ok(true);
    }
    Ok(block.row_count() == 1
        && block.rows().next().is_some_and(|row| {
            matches!(
                row.effects().kind(),
                StepKind::HaltIdle
                    | StepKind::InterruptDispatch(_)
                    | StepKind::HaltUntilVBlank
                    | StepKind::HaltUntilSerial
                    | StepKind::HaltUntilTimer
            )
        }))
}

pub(crate) fn short_device_clocked_block(
    block: &BasicBlock,
) -> Result<bool, BlockDeviceEnvelopeError> {
    if device_io_count(block)? != 0 {
        return Ok(false);
    }
    if block.instruction_count() != 0 {
        return Ok(true);
    }
    Ok(block.row_count() == 1
        && block.rows().next().is_some_and(|row| {
            matches!(
                row.effects().kind(),
                StepKind::HaltIdle | StepKind::InterruptDispatch(_)
            )
        }))
}

pub(crate) fn interrupt_source_bit(block: &BasicBlock, bit: u8) -> bool {
    interrupt_acknowledged_mask(block) >> bit & 1 == 1
}

pub(crate) fn interrupt_acknowledged_mask(block: &BasicBlock) -> u8 {
    if block.row_count() != 1 {
        return 0;
    }
    block.rows().next().map_or(0, |row| {
        if let StepKind::InterruptDispatch(interrupt) = row.effects().kind() {
            1_u8 << interrupt.bit()
        } else {
            0
        }
    })
}

pub(crate) fn device_io_selector_value(row: &[NativeField]) -> Result<NativeField, UniformError> {
    row.get(DEVICE_IO_SELECTOR)
        .copied()
        .ok_or(UniformError::Shape)
}

fn constrain_device_envelope(
    frontend: &[NativeField],
    row: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if constraints.len() != 9 {
        return Err(UniformError::Shape);
    }
    let device_io = row
        .get(DEVICE_IO_SELECTOR)
        .copied()
        .ok_or(UniformError::Shape)?;
    let one = NativeField::from_u64(1);
    let block_active = block_metadata::block_active_value(frontend)?;
    let bus = frontend
        .get(BLOCK_ISA_CONTROL_COLUMN_COUNT..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let boundary = frontend
        .get(BLOCK_ROUTING_COLUMN_COUNT..BLOCK_CONTROL_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let mut sink = ConstraintSink::new(constraints);
    sink.push(device_io * (device_io - one))?;
    sink.push(device_io - typed_device_io_count(bus)?)?;
    let quiet = block_active * (one - device_io);
    for scalar in QUIET_DEVICE_INVARIANTS {
        let before = device_state_value(boundary, false, scalar)?;
        let after = device_state_value(boundary, true, scalar)?;
        sink.push(quiet * (after - before))?;
    }
    sink.finish()
}

fn typed_device_io_count(bus: &[NativeField]) -> Result<NativeField, UniformError> {
    let mut count = NativeField::from_u64(0);
    for slot in 0..BASIC_BLOCK_BUS_EVENT_BOUND {
        for code in DEVICE_IO_CODES {
            count += slot_kind_selector(bus, slot, code)?;
        }
    }
    Ok(count)
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
    use zksm83_trace::BASIC_BLOCK_INSTRUCTION_BOUND;

    use super::*;
    use crate::{
        STATE_APU_CONTROL_LOW_PACK_INDEX, block_boundary::device_state_column,
        block_test_support::lookup_blocks, validate_uniform_witness,
    };

    #[test]
    fn quiet_instruction_block_cannot_mutate_static_device_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let blocks = lookup_blocks(
            &[0x00; BASIC_BLOCK_INSTRUCTION_BOUND],
            BASIC_BLOCK_INSTRUCTION_BOUND,
        )?;
        let witness = BlockDeviceEnvelopeWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockDeviceEnvelopeRelation, witness.columns())?;

        let mut mutated = witness.columns().to_vec();
        let boundary_column = device_state_column(true, STATE_APU_CONTROL_LOW_PACK_INDEX)
            .and_then(|column| column.checked_add(BLOCK_ROUTING_COLUMN_COUNT))
            .ok_or(UniformError::Shape)?;
        let value = mutated
            .get_mut(boundary_column)
            .and_then(|column| column.first_mut())
            .ok_or(UniformError::Shape)?;
        *value = value.checked_add(1).ok_or(UniformError::Shape)?;
        assert!(validate_uniform_witness(&BlockDeviceEnvelopeRelation, &mutated).is_err());
        Ok(())
    }
}
