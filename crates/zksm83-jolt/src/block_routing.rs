//! Algebraic routing relation for bounded packed SM83 instruction blocks.

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_trace::{
    BASIC_BLOCK_BUS_EVENT_BOUND, BASIC_BLOCK_INSTRUCTION_BOUND, BASIC_BLOCK_M_CYCLE_BOUND,
    BasicBlock, BasicBlockResourceOwner,
};

use crate::{
    ConstraintOutput, NativeField, UNIFORM_ROW_COUNT, UniformError, UniformRelation,
    block_metadata::{
        self, BLOCK_METADATA_COLUMN_COUNT, BLOCK_METADATA_CONSTRAINT_COUNT, BlockMetadata,
    },
};

/// Logical columns in the packed-block routing witness.
pub const BLOCK_ROUTING_COLUMN_COUNT: usize = 50;
/// Identities in the packed-block routing relation.
pub const BLOCK_ROUTING_CONSTRAINT_COUNT: usize = 129;
/// Maximum total degree of a packed-block routing identity.
pub const BLOCK_ROUTING_MAX_DEGREE: usize = 7;

const CYCLE_OWNER_START: usize = BLOCK_METADATA_COLUMN_COUNT;
const BUS_OWNER_START: usize =
    CYCLE_OWNER_START + BASIC_BLOCK_M_CYCLE_BOUND * BASIC_BLOCK_INSTRUCTION_BOUND;
const COLUMN_END: usize =
    BUS_OWNER_START + BASIC_BLOCK_BUS_EVENT_BOUND * BASIC_BLOCK_INSTRUCTION_BOUND;

const _: () = assert!(COLUMN_END == BLOCK_ROUTING_COLUMN_COUNT);
const _: () = assert!(BASIC_BLOCK_INSTRUCTION_BOUND == 4);
const _: () = assert!(BASIC_BLOCK_M_CYCLE_BOUND == 6);
const _: () = assert!(BASIC_BLOCK_BUS_EVENT_BOUND == 5);
const _: () = assert!(BLOCK_ROUTING_COLUMN_COUNT == 50);
const _: () = assert!(BLOCK_ROUTING_CONSTRAINT_COUNT == 129);

/// Fixed-row routing witness derived only from validated owned basic blocks.
#[derive(Debug)]
pub struct BlockRoutingWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to encode a canonical packed-block routing witness.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BlockRoutingError {
    /// At least one validated block is required.
    #[error("packed-block routing witness is empty")]
    Empty,
    /// The block count exceeds the fixed relation row capacity.
    #[error("packed-block routing witness has {actual} rows, maximum is {maximum}")]
    TooManyBlocks {
        /// Supplied block count.
        actual: usize,
        /// Fixed relation capacity.
        maximum: usize,
    },
    /// A block exposed an inconsistent lane or resource route.
    #[error("packed-block routing witness violated its typed layout")]
    Layout,
}

/// Pure low-degree relation for lane activity and shared-resource ownership.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockRoutingRelation;

impl BlockRoutingWitness {
    /// Encodes typed blocks and appends canonical all-zero padding rows.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockRoutingError> {
        if blocks.is_empty() {
            return Err(BlockRoutingError::Empty);
        }
        if blocks.len() > UNIFORM_ROW_COUNT {
            return Err(BlockRoutingError::TooManyBlocks {
                actual: blocks.len(),
                maximum: UNIFORM_ROW_COUNT,
            });
        }
        let mut columns = (0..BLOCK_ROUTING_COLUMN_COUNT)
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

impl UniformRelation for BlockRoutingRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-routing/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [4_u64, 6, 5, 50, 129] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_ROUTING_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_ROUTING_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_ROUTING_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_ROUTING_COLUMN_COUNT
            || constraints.len() != BLOCK_ROUTING_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let (metadata_constraints, resource_constraints) =
            constraints.split_at_mut(BLOCK_METADATA_CONSTRAINT_COUNT);
        block_metadata::evaluate(row, metadata_constraints)?;
        let instruction = block_metadata::instruction_value(row)?;
        let mut sink = ConstraintSink::new(resource_constraints);
        constrain_resource::<BASIC_BLOCK_M_CYCLE_BOUND>(
            row,
            &mut sink,
            CYCLE_OWNER_START,
            instruction,
        )?;
        constrain_resource::<BASIC_BLOCK_BUS_EVENT_BOUND>(
            row,
            &mut sink,
            BUS_OWNER_START,
            instruction,
        )?;
        sink.finish()
    }
}

fn append_block(columns: &mut [Vec<u64>], block: &BasicBlock) -> Result<(), BlockRoutingError> {
    let mut row = [0_u64; BLOCK_ROUTING_COLUMN_COUNT];
    BlockMetadata::from_block(block)
        .and_then(|metadata| metadata.write_to(&mut row))
        .ok_or(BlockRoutingError::Layout)?;
    append_owners(&mut row, CYCLE_OWNER_START, block.m_cycle_owners())?;
    append_owners(&mut row, BUS_OWNER_START, block.bus_event_owners())?;
    for (column, value) in columns.iter_mut().zip(row) {
        column.push(value);
    }
    Ok(())
}

fn append_owners<const N: usize>(
    row: &mut [u64],
    start: usize,
    owners: &[BasicBlockResourceOwner; N],
) -> Result<(), BlockRoutingError> {
    for (slot, owner) in owners.iter().copied().enumerate() {
        if let BasicBlockResourceOwner::Instruction(lane) = owner {
            let offset = slot
                .checked_mul(BASIC_BLOCK_INSTRUCTION_BOUND)
                .and_then(|value| value.checked_add(lane.index()))
                .and_then(|value| start.checked_add(value))
                .ok_or(BlockRoutingError::Layout)?;
            set(row, offset, 1)?;
        }
    }
    Ok(())
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), BlockRoutingError> {
    *row.get_mut(index).ok_or(BlockRoutingError::Layout)? = value;
    Ok(())
}

fn constrain_resource<const SLOTS: usize>(
    row: &[NativeField],
    sink: &mut ConstraintSink<'_>,
    start: usize,
    instruction: NativeField,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    for slot in 0..SLOTS {
        let mut sum = NativeField::from_u64(0);
        for lane in 0..BASIC_BLOCK_INSTRUCTION_BOUND {
            let owner = owner(row, start, slot, lane)?;
            sink.push(boolean(owner))?;
            sum += owner;
        }
        sink.push(boolean(sum))?;
    }
    for lane in 0..BASIC_BLOCK_INSTRUCTION_BOUND {
        let active = block_metadata::lane_value(row, lane)?;
        let mut count = NativeField::from_u64(0);
        for slot in 0..SLOTS {
            count += owner(row, start, slot, lane)?;
        }
        sink.push((one - active) * count)?;
        let mut valid_nonzero_count = one;
        for allowed in 1..=SLOTS {
            let allowed = u64::try_from(allowed).map_err(|_| UniformError::Shape)?;
            valid_nonzero_count *= count - NativeField::from_u64(allowed);
        }
        sink.push(active * valid_nonzero_count)?;
    }
    sink.push(owner(row, start, 0, 0)? - instruction)?;
    for slot in 0..SLOTS.saturating_sub(1) {
        constrain_resource_transition(row, sink, start, slot)?;
    }
    Ok(())
}

fn constrain_resource_transition(
    row: &[NativeField],
    sink: &mut ConstraintSink<'_>,
    start: usize,
    slot: usize,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let mut current_sum = NativeField::from_u64(0);
    let mut next_sum = NativeField::from_u64(0);
    for lane in 0..BASIC_BLOCK_INSTRUCTION_BOUND {
        current_sum += owner(row, start, slot, lane)?;
        next_sum += owner(row, start, slot + 1, lane)?;
    }
    sink.push((one - current_sum) * next_sum)?;
    for lane in 0..BASIC_BLOCK_INSTRUCTION_BOUND {
        let mut invalid_next = NativeField::from_u64(0);
        for next_lane in 0..BASIC_BLOCK_INSTRUCTION_BOUND {
            if next_lane < lane || next_lane > lane + 1 {
                invalid_next += owner(row, start, slot + 1, next_lane)?;
            }
        }
        sink.push(owner(row, start, slot, lane)? * invalid_next)?;
    }
    Ok(())
}

fn owner(
    row: &[NativeField],
    start: usize,
    slot: usize,
    lane: usize,
) -> Result<NativeField, UniformError> {
    let index = slot
        .checked_mul(BASIC_BLOCK_INSTRUCTION_BOUND)
        .and_then(|value| value.checked_add(lane))
        .and_then(|value| start.checked_add(value))
        .ok_or(UniformError::Shape)?;
    value(row, index)
}

pub(crate) fn bus_owner_value(
    row: &[NativeField],
    slot: usize,
    lane: usize,
) -> Result<NativeField, UniformError> {
    owner(row, BUS_OWNER_START, slot, lane)
}

pub(crate) fn cycle_owner_value(
    row: &[NativeField],
    slot: usize,
    lane: usize,
) -> Result<NativeField, UniformError> {
    owner(row, CYCLE_OWNER_START, slot, lane)
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
    fn canonical_routing_satisfies_and_owner_mutation_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let rom = RomImage::new(vec![0x00; BASIC_BLOCK_INSTRUCTION_BOUND])?;
        let memory = MemoryImage::zeroed()?;
        let mut builder = TraceBuilder::new(rom, memory, Vec::new());
        let rows = (0..BASIC_BLOCK_INSTRUCTION_BOUND)
            .map(|_| builder.step())
            .collect::<Result<Vec<_>, _>>()?;
        let blocks = pack_witness_basic_blocks(Witness::from_rows(rows)?)?;
        let witness = BlockRoutingWitness::from_blocks(&blocks)?;
        let canonical = field_row(&witness, 0)?;
        assert_satisfied(&canonical)?;

        let mut mutated = canonical;
        let owner = mutated
            .get_mut(CYCLE_OWNER_START)
            .ok_or(UniformError::Shape)?;
        *owner = NativeField::from_u64(0);
        assert!(assert_satisfied(&mutated).is_err());
        Ok(())
    }

    #[test]
    fn padding_row_is_canonical_zero_routing() -> Result<(), Box<dyn std::error::Error>> {
        let row = vec![NativeField::from_u64(0); BLOCK_ROUTING_COLUMN_COUNT];
        assert_satisfied(&row)?;
        Ok(())
    }

    #[test]
    fn machine_block_is_active_but_has_no_instruction_lane()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes = vec![0_u8; 0x101];
        *bytes.get_mut(0x100).ok_or(UniformError::Shape)? = 0x76;
        let rom = RomImage::new(bytes)?;
        let memory = MemoryImage::zeroed()?;
        let mut builder = TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, Vec::new());
        let blocks =
            pack_witness_basic_blocks(Witness::from_rows(vec![builder.step()?, builder.step()?])?)?;
        let witness = BlockRoutingWitness::from_blocks(&blocks)?;
        let machine_row = 1;
        assert_eq!(
            column_value(&witness, block_metadata::BLOCK_ACTIVE, machine_row)?,
            1
        );
        assert_eq!(
            column_value(&witness, block_metadata::INSTRUCTION_BLOCK, machine_row,)?,
            0
        );
        assert_eq!(
            column_value(
                &witness,
                block_metadata::BLOCK_ACTIVE,
                witness.active_block_count(),
            )?,
            0
        );
        Ok(())
    }

    fn column_value(
        witness: &BlockRoutingWitness,
        column: usize,
        row: usize,
    ) -> Result<u64, UniformError> {
        witness
            .columns()
            .get(column)
            .and_then(|values| values.get(row))
            .copied()
            .ok_or(UniformError::Shape)
    }

    fn field_row(
        witness: &BlockRoutingWitness,
        index: usize,
    ) -> Result<Vec<NativeField>, UniformError> {
        witness
            .columns()
            .iter()
            .map(|column| {
                column
                    .get(index)
                    .copied()
                    .map(NativeField::from_u64)
                    .ok_or(UniformError::Shape)
            })
            .collect()
    }

    fn assert_satisfied(row: &[NativeField]) -> Result<(), UniformError> {
        let mut constraints = vec![NativeField::from_u64(0); BLOCK_ROUTING_CONSTRAINT_COUNT];
        BlockRoutingRelation.evaluate(row, &mut constraints)?;
        if constraints
            .iter()
            .all(|value| *value == NativeField::from_u64(0))
        {
            Ok(())
        } else {
            Err(UniformError::WitnessUnsatisfied {
                row: 0,
                constraint: 0,
            })
        }
    }
}
