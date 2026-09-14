//! Composed packed-block control and lane-local fixed-ISA plane.

use thiserror::Error;
use zksm83_trace::{BasicBlock, BasicBlockLaneIndex};

use crate::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_CONTROL_CONSTRAINT_COUNT, BLOCK_CONTROL_MAX_DEGREE,
    BLOCK_ISA_COLUMN_COUNT, BLOCK_ISA_CONSTRAINT_COUNT, BLOCK_ISA_MAX_DEGREE, BlockControlError,
    BlockControlRelation, BlockControlWitness, BlockIsaError, BlockIsaRelation, BlockIsaWitness,
    ConstraintOutput, ISA_ADDRESS_BIT_COUNT, ISA_OUTPUT_COUNT, IsaLookupColumns, NativeField,
    UniformError, UniformRelation, block_metadata::BLOCK_METADATA_COLUMN_COUNT,
};

/// Logical columns in the composed block-control and four-lane ISA witness.
pub const BLOCK_ISA_CONTROL_COLUMN_COUNT: usize =
    BLOCK_CONTROL_COLUMN_COUNT + BLOCK_ISA_COLUMN_COUNT;
/// Identities in the composed block-control and four-lane ISA relation.
pub const BLOCK_ISA_CONTROL_CONSTRAINT_COUNT: usize =
    BLOCK_CONTROL_CONSTRAINT_COUNT + BLOCK_ISA_CONSTRAINT_COUNT + BLOCK_METADATA_COLUMN_COUNT;
/// Maximum total degree in the composed block-control and ISA relation.
pub const BLOCK_ISA_CONTROL_MAX_DEGREE: usize = if BLOCK_CONTROL_MAX_DEGREE > BLOCK_ISA_MAX_DEGREE {
    BLOCK_CONTROL_MAX_DEGREE
} else {
    BLOCK_ISA_MAX_DEGREE
};

const _: () = assert!(BLOCK_METADATA_COLUMN_COUNT == 6);
const _: () = assert!(BLOCK_ISA_CONTROL_COLUMN_COUNT == 437);
const _: () = assert!(BLOCK_ISA_CONTROL_CONSTRAINT_COUNT == 729);
const _: () = assert!(BLOCK_ISA_CONTROL_MAX_DEGREE == 7);

/// Fixed-row witness composing packed control metadata with four fixed-ISA query lanes.
#[derive(Debug)]
pub struct BlockIsaControlWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to construct or describe the composed block ISA control witness.
#[derive(Debug, Error)]
pub enum BlockIsaControlError {
    /// Routing and boundary control construction failed.
    #[error("packed-block control construction failed: {0}")]
    Control(#[from] BlockControlError),
    /// Lane-local ISA construction failed.
    #[error("packed-block ISA construction failed: {0}")]
    Isa(#[from] BlockIsaError),
    /// Independently derived planes disagreed on their fixed-row shape.
    #[error("packed-block ISA control planes have inconsistent shapes")]
    Shape,
}

/// Low-degree composition of block routing, boundaries, and lane-local ISA metadata.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockIsaControlRelation;

impl BlockIsaControlWitness {
    /// Derives the control and ISA planes from the same validated owned blocks.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockIsaControlError> {
        let control = BlockControlWitness::from_blocks(blocks)?;
        let isa = BlockIsaWitness::from_blocks(blocks)?;
        if control.active_block_count() != isa.active_block_count() {
            return Err(BlockIsaControlError::Shape);
        }
        let active_block_count = control.active_block_count();
        let mut columns = control.into_columns();
        columns.extend(isa.into_columns());
        if columns.len() != BLOCK_ISA_CONTROL_COLUMN_COUNT {
            return Err(BlockIsaControlError::Shape);
        }
        Ok(Self {
            columns,
            active_block_count,
        })
    }

    /// Returns all columns in control-then-ISA order.
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

    /// Returns one lane's absolute fixed-ISA lookup layout in this composed plane.
    pub fn lane_lookup_columns(
        lane: BasicBlockLaneIndex,
    ) -> Result<IsaLookupColumns, BlockIsaControlError> {
        let relative = BlockIsaWitness::lane_lookup_columns(lane)?;
        let address_bits = shift_indices(relative.address_bits(), BLOCK_CONTROL_COLUMN_COUNT)?;
        let outputs = shift_indices(relative.outputs(), BLOCK_CONTROL_COLUMN_COUNT)?;
        IsaLookupColumns::new(address_bits, outputs)
            .map_err(BlockIsaError::from)
            .map_err(Into::into)
    }
}

impl UniformRelation for BlockIsaControlRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-isa-control/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [195_u64, 432, 242, 291, 6, 437, 729] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_ISA_CONTROL_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_ISA_CONTROL_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_ISA_CONTROL_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_ISA_CONTROL_COLUMN_COUNT
            || constraints.len() != BLOCK_ISA_CONTROL_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let (control_row, isa_row) = row.split_at(BLOCK_CONTROL_COLUMN_COUNT);
        let (control_constraints, remainder) =
            constraints.split_at_mut(BLOCK_CONTROL_CONSTRAINT_COUNT);
        let (isa_constraints, metadata_constraints) =
            remainder.split_at_mut(BLOCK_ISA_CONSTRAINT_COUNT);
        BlockControlRelation.evaluate(control_row, control_constraints)?;
        BlockIsaRelation.evaluate(isa_row, isa_constraints)?;
        constrain_shared_metadata(control_row, isa_row, metadata_constraints)
    }
}

fn constrain_shared_metadata(
    control: &[NativeField],
    isa: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if constraints.len() != BLOCK_METADATA_COLUMN_COUNT {
        return Err(UniformError::Shape);
    }
    for (column, constraint) in constraints.iter_mut().enumerate() {
        let control_value = control.get(column).copied().ok_or(UniformError::Shape)?;
        let isa_value = isa.get(column).copied().ok_or(UniformError::Shape)?;
        *constraint = control_value - isa_value;
    }
    Ok(())
}

fn shift_indices<const N: usize>(
    indices: [usize; N],
    offset: usize,
) -> Result<[usize; N], BlockIsaControlError> {
    let mut shifted = [0_usize; N];
    for (source, target) in indices.into_iter().zip(shifted.iter_mut()) {
        *target = source
            .checked_add(offset)
            .ok_or(BlockIsaControlError::Shape)?;
    }
    Ok(shifted)
}

const _: () = assert!(ISA_ADDRESS_BIT_COUNT == 9);
const _: () = assert!(ISA_OUTPUT_COUNT == 49);

#[cfg(test)]
mod tests {
    use zksm83_memory::{MemoryImage, RomImage};
    use zksm83_trace::{
        BASIC_BLOCK_INSTRUCTION_BOUND, TraceBuilder, Witness, pack_witness_basic_blocks,
    };

    use super::*;
    use crate::{block_metadata, block_test_support::flip_witness_bit, validate_uniform_witness};

    #[test]
    fn composed_isa_control_satisfies_and_layouts_fit_the_plane()
    -> Result<(), Box<dyn std::error::Error>> {
        let rom = RomImage::new(vec![0x00; BASIC_BLOCK_INSTRUCTION_BOUND])?;
        let memory = MemoryImage::zeroed()?;
        let mut builder = TraceBuilder::new(rom, memory, Vec::new());
        let rows = (0..BASIC_BLOCK_INSTRUCTION_BOUND)
            .map(|_| builder.step())
            .collect::<Result<Vec<_>, _>>()?;
        let blocks = pack_witness_basic_blocks(Witness::from_rows(rows)?)?;
        let witness = BlockIsaControlWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockIsaControlRelation, witness.columns())?;
        for lane in [
            BasicBlockLaneIndex::Lane0,
            BasicBlockLaneIndex::Lane1,
            BasicBlockLaneIndex::Lane2,
            BasicBlockLaneIndex::Lane3,
        ] {
            let layout = BlockIsaControlWitness::lane_lookup_columns(lane)?;
            assert!(
                layout
                    .outputs()
                    .iter()
                    .all(|column| *column < BLOCK_ISA_CONTROL_COLUMN_COUNT)
            );
        }
        let mut mutated = witness.columns().to_vec();
        flip_witness_bit(
            &mut mutated,
            BLOCK_CONTROL_COLUMN_COUNT + block_metadata::BLOCK_ACTIVE,
            0,
        )?;
        assert!(validate_uniform_witness(&BlockIsaControlRelation, &mutated).is_err());
        Ok(())
    }
}
