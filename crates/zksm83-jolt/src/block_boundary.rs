//! Canonical outer and intermediate state boundaries for packed SM83 blocks.

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_trace::{BASIC_BLOCK_INSTRUCTION_BOUND, BasicBlock};

use crate::{
    ConstraintOutput, NativeField, STATE_SCALAR_COUNT, UNIFORM_ROW_COUNT, UniformError,
    UniformRelation,
    block_metadata::{
        self, BLOCK_METADATA_COLUMN_COUNT, BLOCK_METADATA_CONSTRAINT_COUNT, BlockMetadata,
    },
    encode_state_scalars,
};

/// Non-device state limbs carried across packed instruction lanes.
///
/// This prefix contains CPU state, mapper state, ordered-log cursors, and the machine profile.
pub const BLOCK_LOCAL_STATE_SCALAR_COUNT: usize = 21;
/// Device state limbs advanced once by the shared block-level device relation.
pub const BLOCK_DEVICE_STATE_SCALAR_COUNT: usize =
    STATE_SCALAR_COUNT - BLOCK_LOCAL_STATE_SCALAR_COUNT;
/// Logical columns in the packed-block boundary witness.
pub const BLOCK_BOUNDARY_COLUMN_COUNT: usize = 145;
/// Identities in the packed-block boundary relation.
pub const BLOCK_BOUNDARY_CONSTRAINT_COUNT: usize = 297;
/// Maximum total degree of a packed-block boundary identity.
pub const BLOCK_BOUNDARY_MAX_DEGREE: usize = 3;

const LOCAL_BOUNDARY_COUNT: usize = BASIC_BLOCK_INSTRUCTION_BOUND + 1;
const LOCAL_BOUNDARY_START: usize = BLOCK_METADATA_COLUMN_COUNT;
const DEVICE_BEFORE_START: usize =
    LOCAL_BOUNDARY_START + LOCAL_BOUNDARY_COUNT * BLOCK_LOCAL_STATE_SCALAR_COUNT;
const DEVICE_AFTER_START: usize = DEVICE_BEFORE_START + BLOCK_DEVICE_STATE_SCALAR_COUNT;
const COLUMN_END: usize = DEVICE_AFTER_START + BLOCK_DEVICE_STATE_SCALAR_COUNT;

const _: () = assert!(STATE_SCALAR_COUNT == 38);
const _: () = assert!(BASIC_BLOCK_INSTRUCTION_BOUND == 4);
const _: () = assert!(BLOCK_LOCAL_STATE_SCALAR_COUNT == 21);
const _: () = assert!(BLOCK_DEVICE_STATE_SCALAR_COUNT == 17);
const _: () = assert!(COLUMN_END == BLOCK_BOUNDARY_COLUMN_COUNT);
const _: () = assert!(BLOCK_BOUNDARY_COLUMN_COUNT == 145);
const _: () = assert!(BLOCK_BOUNDARY_CONSTRAINT_COUNT == 297);

/// Fixed-row boundary witness derived from validated owned basic blocks.
#[derive(Debug)]
pub struct BlockBoundaryWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to encode a canonical packed-block boundary witness.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BlockBoundaryError {
    /// At least one validated block is required.
    #[error("packed-block boundary witness is empty")]
    Empty,
    /// The block count exceeds the fixed relation row capacity.
    #[error("packed-block boundary witness has {actual} rows, maximum is {maximum}")]
    TooManyBlocks {
        /// Supplied block count.
        actual: usize,
        /// Fixed relation capacity.
        maximum: usize,
    },
    /// A block exposed an inconsistent lane or state-boundary layout.
    #[error("packed-block boundary witness violated its typed layout")]
    Layout,
}

/// Low-degree relation for packed lane boundaries and shared outer device state.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockBoundaryRelation;

impl BlockBoundaryWitness {
    /// Encodes typed blocks and appends canonical all-zero padding rows.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockBoundaryError> {
        if blocks.is_empty() {
            return Err(BlockBoundaryError::Empty);
        }
        if blocks.len() > UNIFORM_ROW_COUNT {
            return Err(BlockBoundaryError::TooManyBlocks {
                actual: blocks.len(),
                maximum: UNIFORM_ROW_COUNT,
            });
        }
        let mut columns = (0..BLOCK_BOUNDARY_COLUMN_COUNT)
            .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
            .collect::<Vec<_>>();
        for block in blocks {
            append_block(&mut columns, block)?;
        }
        for column in &mut columns {
            column.resize(UNIFORM_ROW_COUNT, 0);
        }
        Ok(Self {
            columns,
            active_block_count: blocks.len(),
        })
    }

    /// Returns every logical column in canonical order.
    #[must_use]
    pub fn columns(&self) -> &[Vec<u64>] {
        &self.columns
    }

    /// Returns the number of non-padding block rows.
    #[must_use]
    pub const fn active_block_count(&self) -> usize {
        self.active_block_count
    }

    pub(crate) fn into_columns(self) -> Vec<Vec<u64>> {
        self.columns
    }
}

impl UniformRelation for BlockBoundaryRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-boundary/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [4_u64, 21, 17, 145, 297] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_BOUNDARY_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_BOUNDARY_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_BOUNDARY_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_BOUNDARY_COLUMN_COUNT
            || constraints.len() != BLOCK_BOUNDARY_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let (metadata_constraints, boundary_constraints) =
            constraints.split_at_mut(BLOCK_METADATA_CONSTRAINT_COUNT);
        block_metadata::evaluate(row, metadata_constraints)?;
        let mut sink = ConstraintSink::new(boundary_constraints);
        constrain_boundaries(row, &mut sink)?;
        sink.finish()
    }
}

fn append_block(columns: &mut [Vec<u64>], block: &BasicBlock) -> Result<(), BlockBoundaryError> {
    let mut row = [0_u64; BLOCK_BOUNDARY_COLUMN_COUNT];
    BlockMetadata::from_block(block)
        .and_then(|metadata| metadata.write_to(&mut row))
        .ok_or(BlockBoundaryError::Layout)?;
    let instruction_block = block.instruction_count() != 0;
    let before = encode_state_scalars(block.initial_state());
    let after = encode_state_scalars(block.final_state());
    append_local_boundary(&mut row, 0, &before)?;
    append_device_boundary(&mut row, DEVICE_BEFORE_START, &before)?;
    append_device_boundary(&mut row, DEVICE_AFTER_START, &after)?;
    if instruction_block {
        append_instruction_boundaries(&mut row, block, &after)?;
    } else {
        append_local_boundary(&mut row, BASIC_BLOCK_INSTRUCTION_BOUND, &after)?;
    }
    for (column, value) in columns.iter_mut().zip(row) {
        column.push(value);
    }
    Ok(())
}

fn append_instruction_boundaries(
    row: &mut [u64],
    block: &BasicBlock,
    final_state: &[u64; STATE_SCALAR_COUNT],
) -> Result<(), BlockBoundaryError> {
    if block.row_count() != block.instruction_count()
        || block.instruction_count() > BASIC_BLOCK_INSTRUCTION_BOUND
    {
        return Err(BlockBoundaryError::Layout);
    }
    for (lane, source) in block.rows().enumerate() {
        let state = encode_state_scalars(source.after());
        let boundary = lane.checked_add(1).ok_or(BlockBoundaryError::Layout)?;
        append_local_boundary(row, boundary, &state)?;
    }
    let first_padding = block
        .instruction_count()
        .checked_add(1)
        .ok_or(BlockBoundaryError::Layout)?;
    for boundary in first_padding..LOCAL_BOUNDARY_COUNT {
        append_local_boundary(row, boundary, final_state)?;
    }
    Ok(())
}

fn append_local_boundary(
    row: &mut [u64],
    boundary: usize,
    state: &[u64; STATE_SCALAR_COUNT],
) -> Result<(), BlockBoundaryError> {
    for scalar in 0..BLOCK_LOCAL_STATE_SCALAR_COUNT {
        let index = grid_index(
            LOCAL_BOUNDARY_START,
            boundary,
            BLOCK_LOCAL_STATE_SCALAR_COUNT,
            scalar,
        )
        .ok_or(BlockBoundaryError::Layout)?;
        let value = state
            .get(scalar)
            .copied()
            .ok_or(BlockBoundaryError::Layout)?;
        set(row, index, value)?;
    }
    Ok(())
}

fn append_device_boundary(
    row: &mut [u64],
    start: usize,
    state: &[u64; STATE_SCALAR_COUNT],
) -> Result<(), BlockBoundaryError> {
    for device_scalar in 0..BLOCK_DEVICE_STATE_SCALAR_COUNT {
        let state_index = BLOCK_LOCAL_STATE_SCALAR_COUNT
            .checked_add(device_scalar)
            .ok_or(BlockBoundaryError::Layout)?;
        let column = start
            .checked_add(device_scalar)
            .ok_or(BlockBoundaryError::Layout)?;
        let value = state
            .get(state_index)
            .copied()
            .ok_or(BlockBoundaryError::Layout)?;
        set(row, column, value)?;
    }
    Ok(())
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), BlockBoundaryError> {
    *row.get_mut(index).ok_or(BlockBoundaryError::Layout)? = value;
    Ok(())
}

fn constrain_boundaries(
    row: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let block_active = block_metadata::block_active_value(row)?;
    let instruction = block_metadata::instruction_value(row)?;

    let padding = one - block_active;
    for column in LOCAL_BOUNDARY_START..COLUMN_END {
        sink.push(padding * value(row, column)?)?;
    }
    let machine = block_active - instruction;
    for boundary in 1..BASIC_BLOCK_INSTRUCTION_BOUND {
        for scalar in 0..BLOCK_LOCAL_STATE_SCALAR_COUNT {
            sink.push(machine * local_state_value(row, boundary, scalar)?)?;
        }
    }
    for lane in 0..BASIC_BLOCK_INSTRUCTION_BOUND {
        let inactive = one - block_metadata::lane_value(row, lane)?;
        for scalar in 0..BLOCK_LOCAL_STATE_SCALAR_COUNT {
            let before = local_state_value(row, lane, scalar)?;
            let after = local_state_value(row, lane + 1, scalar)?;
            sink.push(instruction * inactive * (after - before))?;
        }
    }
    Ok(())
}

pub(crate) fn local_state_value(
    row: &[NativeField],
    boundary: usize,
    scalar: usize,
) -> Result<NativeField, UniformError> {
    let index = local_state_column(boundary, scalar).ok_or(UniformError::Shape)?;
    value(row, index)
}

pub(crate) fn local_state_column(boundary: usize, scalar: usize) -> Option<usize> {
    if boundary >= LOCAL_BOUNDARY_COUNT || scalar >= BLOCK_LOCAL_STATE_SCALAR_COUNT {
        return None;
    }
    grid_index(
        LOCAL_BOUNDARY_START,
        boundary,
        BLOCK_LOCAL_STATE_SCALAR_COUNT,
        scalar,
    )
}

pub(crate) fn device_state_value(
    row: &[NativeField],
    after: bool,
    scalar: usize,
) -> Result<NativeField, UniformError> {
    let index = device_state_column(after, scalar).ok_or(UniformError::Shape)?;
    value(row, index)
}

pub(crate) fn device_state_column(after: bool, scalar: usize) -> Option<usize> {
    let device_scalar = scalar.checked_sub(BLOCK_LOCAL_STATE_SCALAR_COUNT)?;
    if device_scalar >= BLOCK_DEVICE_STATE_SCALAR_COUNT {
        return None;
    }
    let start = if after {
        DEVICE_AFTER_START
    } else {
        DEVICE_BEFORE_START
    };
    start.checked_add(device_scalar)
}

fn grid_index(start: usize, outer: usize, width: usize, inner: usize) -> Option<usize> {
    outer
        .checked_mul(width)
        .and_then(|offset| offset.checked_add(inner))
        .and_then(|offset| start.checked_add(offset))
}

fn value(row: &[NativeField], index: usize) -> Result<NativeField, UniformError> {
    row.get(index).copied().ok_or(UniformError::Shape)
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
    use crate::validate_uniform_witness;

    #[test]
    fn canonical_boundaries_satisfy_and_padding_mutation_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let rom = RomImage::new(vec![0x00; BASIC_BLOCK_INSTRUCTION_BOUND])?;
        let memory = MemoryImage::zeroed()?;
        let mut builder = TraceBuilder::new(rom, memory, Vec::new());
        let rows = (0..BASIC_BLOCK_INSTRUCTION_BOUND)
            .map(|_| builder.step())
            .collect::<Result<Vec<_>, _>>()?;
        let blocks = pack_witness_basic_blocks(Witness::from_rows(rows)?)?;
        let witness = BlockBoundaryWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockBoundaryRelation, witness.columns())?;

        let mut columns = witness.columns().to_vec();
        let padding_row = blocks.len();
        let value = columns
            .get_mut(LOCAL_BOUNDARY_START)
            .and_then(|column| column.get_mut(padding_row))
            .ok_or(UniformError::Shape)?;
        *value = 1;
        assert!(validate_uniform_witness(&BlockBoundaryRelation, &columns).is_err());
        Ok(())
    }
}
