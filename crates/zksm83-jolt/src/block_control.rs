//! Composed routing and state-boundary control plane for packed SM83 blocks.

use thiserror::Error;
use zksm83_trace::BasicBlock;

use crate::{
    BLOCK_BOUNDARY_COLUMN_COUNT, BLOCK_BOUNDARY_CONSTRAINT_COUNT, BLOCK_BOUNDARY_MAX_DEGREE,
    BLOCK_ROUTING_COLUMN_COUNT, BLOCK_ROUTING_CONSTRAINT_COUNT, BLOCK_ROUTING_MAX_DEGREE,
    BlockBoundaryError, BlockBoundaryRelation, BlockBoundaryWitness, BlockRoutingError,
    BlockRoutingRelation, BlockRoutingWitness, ConstraintOutput, NativeField, UniformError,
    UniformRelation, block_metadata::BLOCK_METADATA_COLUMN_COUNT,
};

/// Logical columns in the composed packed-block control witness.
pub const BLOCK_CONTROL_COLUMN_COUNT: usize =
    BLOCK_ROUTING_COLUMN_COUNT + BLOCK_BOUNDARY_COLUMN_COUNT;
/// Identities in the composed packed-block control relation.
pub const BLOCK_CONTROL_CONSTRAINT_COUNT: usize =
    BLOCK_ROUTING_CONSTRAINT_COUNT + BLOCK_BOUNDARY_CONSTRAINT_COUNT + BLOCK_METADATA_COLUMN_COUNT;
/// Maximum total degree of a packed-block control identity.
pub const BLOCK_CONTROL_MAX_DEGREE: usize = if BLOCK_ROUTING_MAX_DEGREE > BLOCK_BOUNDARY_MAX_DEGREE
{
    BLOCK_ROUTING_MAX_DEGREE
} else {
    BLOCK_BOUNDARY_MAX_DEGREE
};

const _: () = assert!(BLOCK_METADATA_COLUMN_COUNT == 6);
const _: () = assert!(BLOCK_CONTROL_COLUMN_COUNT == 195);
const _: () = assert!(BLOCK_CONTROL_CONSTRAINT_COUNT == 432);
const _: () = assert!(BLOCK_CONTROL_MAX_DEGREE == 7);

/// Fixed-row composed control witness for packed blocks.
#[derive(Debug)]
pub struct BlockControlWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to construct a composed packed-block control witness.
#[derive(Debug, Error)]
pub enum BlockControlError {
    /// Routing witness construction failed.
    #[error("packed-block routing construction failed: {0}")]
    Routing(#[from] BlockRoutingError),
    /// Boundary witness construction failed.
    #[error("packed-block boundary construction failed: {0}")]
    Boundary(#[from] BlockBoundaryError),
    /// The independently derived planes disagreed on their fixed-row shape.
    #[error("packed-block control planes have inconsistent shapes")]
    Shape,
}

/// One low-degree relation composing routing, boundaries, and shared selectors.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockControlRelation;

impl BlockControlWitness {
    /// Derives both control planes from the same validated owned blocks.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockControlError> {
        let routing = BlockRoutingWitness::from_blocks(blocks)?;
        let boundary = BlockBoundaryWitness::from_blocks(blocks)?;
        if routing.active_block_count() != boundary.active_block_count() {
            return Err(BlockControlError::Shape);
        }
        let active_block_count = routing.active_block_count();
        let mut columns = routing.into_columns();
        columns.extend(boundary.into_columns());
        if columns.len() != BLOCK_CONTROL_COLUMN_COUNT {
            return Err(BlockControlError::Shape);
        }
        Ok(Self {
            columns,
            active_block_count,
        })
    }

    /// Returns every logical column in canonical routing-then-boundary order.
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

impl UniformRelation for BlockControlRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-control/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [50_u64, 129, 145, 297, 6, 195, 432] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_CONTROL_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_CONTROL_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_CONTROL_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_CONTROL_COLUMN_COUNT
            || constraints.len() != BLOCK_CONTROL_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let (routing_row, boundary_row) = row.split_at(BLOCK_ROUTING_COLUMN_COUNT);
        let (routing_constraints, remainder) =
            constraints.split_at_mut(BLOCK_ROUTING_CONSTRAINT_COUNT);
        let (boundary_constraints, selector_constraints) =
            remainder.split_at_mut(BLOCK_BOUNDARY_CONSTRAINT_COUNT);
        BlockRoutingRelation.evaluate(routing_row, routing_constraints)?;
        BlockBoundaryRelation.evaluate(boundary_row, boundary_constraints)?;
        constrain_shared_selectors(routing_row, boundary_row, selector_constraints)
    }
}

fn constrain_shared_selectors(
    routing: &[NativeField],
    boundary: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if constraints.len() != BLOCK_METADATA_COLUMN_COUNT {
        return Err(UniformError::Shape);
    }
    for (column, constraint) in constraints.iter_mut().enumerate() {
        let routing_value = routing.get(column).copied().ok_or(UniformError::Shape)?;
        let boundary_value = boundary.get(column).copied().ok_or(UniformError::Shape)?;
        *constraint = routing_value - boundary_value;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use zksm83_memory::{MemoryImage, RomImage};
    use zksm83_trace::{
        BASIC_BLOCK_INSTRUCTION_BOUND, TraceBuilder, Witness, pack_witness_basic_blocks,
    };

    use super::*;
    use crate::{block_metadata, block_test_support::flip_witness_bit, validate_uniform_witness};

    #[test]
    fn composed_control_plane_binds_shared_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let rom = RomImage::new(vec![0x00; BASIC_BLOCK_INSTRUCTION_BOUND])?;
        let memory = MemoryImage::zeroed()?;
        let mut builder = TraceBuilder::new(rom, memory, Vec::new());
        let rows = (0..BASIC_BLOCK_INSTRUCTION_BOUND)
            .map(|_| builder.step())
            .collect::<Result<Vec<_>, _>>()?;
        let blocks = pack_witness_basic_blocks(Witness::from_rows(rows)?)?;
        let witness = BlockControlWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockControlRelation, witness.columns())?;
        let mut mutated = witness.columns().to_vec();
        flip_witness_bit(
            &mut mutated,
            BLOCK_ROUTING_COLUMN_COUNT + block_metadata::BLOCK_ACTIVE,
            0,
        )?;
        assert!(validate_uniform_witness(&BlockControlRelation, &mutated).is_err());
        Ok(())
    }
}
