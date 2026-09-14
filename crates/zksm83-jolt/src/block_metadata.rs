//! Shared activity metadata for every packed-block witness plane.

use akita_pcs::Ring;
use zksm83_trace::{BASIC_BLOCK_INSTRUCTION_BOUND, BasicBlock};

use crate::{NativeField, UniformError};

pub(crate) const BLOCK_METADATA_COLUMN_COUNT: usize = 6;
pub(crate) const BLOCK_METADATA_CONSTRAINT_COUNT: usize = 11;
pub(crate) const BLOCK_ACTIVE: usize = 0;
pub(crate) const INSTRUCTION_BLOCK: usize = BLOCK_ACTIVE + 1;
pub(crate) const LANE_ACTIVE_START: usize = INSTRUCTION_BLOCK + 1;

const _: () = assert!(BASIC_BLOCK_INSTRUCTION_BOUND == 4);
const _: () = assert!(LANE_ACTIVE_START + BASIC_BLOCK_INSTRUCTION_BOUND == 6);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlockMetadata {
    values: [u64; BLOCK_METADATA_COLUMN_COUNT],
}

impl BlockMetadata {
    pub(crate) fn from_block(block: &BasicBlock) -> Option<Self> {
        if block.instruction_count() > BASIC_BLOCK_INSTRUCTION_BOUND {
            return None;
        }
        let mut values = [0_u64; BLOCK_METADATA_COLUMN_COUNT];
        *values.get_mut(BLOCK_ACTIVE)? = 1;
        *values.get_mut(INSTRUCTION_BLOCK)? = u64::from(block.instruction_count() != 0);
        let mut active_lanes = 0_usize;
        for (lane, descriptor) in block.lanes().iter().copied().enumerate() {
            let active = descriptor.is_instruction();
            *values.get_mut(lane_column(lane)?)? = u64::from(active);
            active_lanes = active_lanes.checked_add(usize::from(active))?;
        }
        if active_lanes != block.instruction_count() {
            return None;
        }
        Some(Self { values })
    }

    pub(crate) fn write_to(self, row: &mut [u64]) -> Option<()> {
        row.get_mut(..BLOCK_METADATA_COLUMN_COUNT)?
            .copy_from_slice(&self.values);
        Some(())
    }
}

pub(crate) fn evaluate(
    row: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if constraints.len() != BLOCK_METADATA_CONSTRAINT_COUNT {
        return Err(UniformError::Shape);
    }
    let one = NativeField::from_u64(1);
    let block_active = value(row, BLOCK_ACTIVE)?;
    let instruction = value(row, INSTRUCTION_BLOCK)?;
    let mut sink = ConstraintSink::new(constraints);
    sink.push(boolean(block_active))?;
    sink.push(boolean(instruction))?;
    sink.push(instruction * (one - block_active))?;
    for lane in 0..BASIC_BLOCK_INSTRUCTION_BOUND {
        sink.push(boolean(value(
            row,
            lane_column(lane).ok_or(UniformError::Shape)?,
        )?))?;
    }
    for lane in 1..BASIC_BLOCK_INSTRUCTION_BOUND {
        let active = value(row, lane_column(lane).ok_or(UniformError::Shape)?)?;
        let previous = value(row, lane_column(lane - 1).ok_or(UniformError::Shape)?)?;
        sink.push(active * (one - previous))?;
    }
    sink.push(value(row, lane_column(0).ok_or(UniformError::Shape)?)? - instruction)?;
    sink.finish()
}

pub(crate) fn instruction_value(row: &[NativeField]) -> Result<NativeField, UniformError> {
    value(row, INSTRUCTION_BLOCK)
}

pub(crate) fn block_active_value(row: &[NativeField]) -> Result<NativeField, UniformError> {
    value(row, BLOCK_ACTIVE)
}

pub(crate) fn lane_value(row: &[NativeField], lane: usize) -> Result<NativeField, UniformError> {
    value(row, lane_column(lane).ok_or(UniformError::Shape)?)
}

pub(crate) fn lane_column(lane: usize) -> Option<usize> {
    LANE_ACTIVE_START
        .checked_add(lane)
        .filter(|index| *index < BLOCK_METADATA_COLUMN_COUNT)
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

    #[test]
    fn metadata_encodes_a_prefix_of_active_lanes() -> Result<(), Box<dyn std::error::Error>> {
        let rom = RomImage::new(vec![0x00; BASIC_BLOCK_INSTRUCTION_BOUND])?;
        let memory = MemoryImage::zeroed()?;
        let mut builder = TraceBuilder::new(rom, memory, Vec::new());
        let rows = (0..BASIC_BLOCK_INSTRUCTION_BOUND)
            .map(|_| builder.step())
            .collect::<Result<Vec<_>, _>>()?;
        let blocks = pack_witness_basic_blocks(Witness::from_rows(rows)?)?;
        let block = blocks.first().ok_or(UniformError::Shape)?;
        let metadata = BlockMetadata::from_block(block).ok_or(UniformError::Shape)?;
        assert_eq!(metadata.values, [1, 1, 1, 1, 1, 1]);
        Ok(())
    }
}
