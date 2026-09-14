//! Lane-local fixed-ISA queries for packed SM83 instruction blocks.

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_core::StepKind;
use zksm83_isa::AlignedInstruction;
use zksm83_trace::{BASIC_BLOCK_INSTRUCTION_BOUND, BasicBlock, BasicBlockLaneIndex};

use crate::{
    ConstraintOutput, ISA_ADDRESS_BIT_COUNT, ISA_OUTPUT_COUNT, ISA_PADDING_ADDRESS,
    ISA_TABLE_ROW_COUNT, ISA_VALID, IsaLookupColumns, IsaLookupError, IsaTableError, NativeField,
    UNIFORM_ROW_COUNT, UniformError, UniformRelation,
    block_metadata::{
        self, BLOCK_METADATA_COLUMN_COUNT, BLOCK_METADATA_CONSTRAINT_COUNT, BlockMetadata,
    },
    fixed_isa_table,
};

/// Columns in one lane-local fixed-ISA query plus its branch decision.
pub const BLOCK_ISA_LANE_COLUMN_COUNT: usize = ISA_ADDRESS_BIT_COUNT + ISA_OUTPUT_COUNT + 1;
/// Logical columns in the four-lane fixed-ISA witness.
pub const BLOCK_ISA_COLUMN_COUNT: usize =
    BLOCK_METADATA_COLUMN_COUNT + BASIC_BLOCK_INSTRUCTION_BOUND * BLOCK_ISA_LANE_COLUMN_COUNT;
/// Identities in the four-lane fixed-ISA relation.
pub const BLOCK_ISA_CONSTRAINT_COUNT: usize = BLOCK_METADATA_CONSTRAINT_COUNT
    + BASIC_BLOCK_INSTRUCTION_BOUND * (ISA_ADDRESS_BIT_COUNT + BLOCK_ISA_LANE_COLUMN_COUNT + 2);
/// Maximum total degree of a lane-local fixed-ISA identity.
pub const BLOCK_ISA_MAX_DEGREE: usize = 2;

const LANE_START: usize = BLOCK_METADATA_COLUMN_COUNT;
const LANE_BRANCH_OFFSET: usize = ISA_ADDRESS_BIT_COUNT + ISA_OUTPUT_COUNT;
const COLUMN_END: usize = LANE_START + BASIC_BLOCK_INSTRUCTION_BOUND * BLOCK_ISA_LANE_COLUMN_COUNT;

const _: () = assert!(BASIC_BLOCK_INSTRUCTION_BOUND == 4);
const _: () = assert!(ISA_ADDRESS_BIT_COUNT == 9);
const _: () = assert!(ISA_OUTPUT_COUNT == 38);
const _: () = assert!(ISA_TABLE_ROW_COUNT == 512);
const _: () = assert!(BLOCK_ISA_LANE_COLUMN_COUNT == 48);
const _: () = assert!(COLUMN_END == BLOCK_ISA_COLUMN_COUNT);
const _: () = assert!(BLOCK_ISA_COLUMN_COUNT == 198);
const _: () = assert!(BLOCK_ISA_CONSTRAINT_COUNT == 247);

/// Fixed-row lane-local ISA witness derived from validated owned blocks.
#[derive(Debug)]
pub struct BlockIsaWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to encode or describe the lane-local fixed-ISA witness.
#[derive(Debug, Error)]
pub enum BlockIsaError {
    /// At least one validated block is required.
    #[error("packed-block ISA witness is empty")]
    Empty,
    /// The block count exceeds the fixed relation row capacity.
    #[error("packed-block ISA witness has {actual} rows, maximum is {maximum}")]
    TooManyBlocks {
        /// Supplied block count.
        actual: usize,
        /// Fixed relation capacity.
        maximum: usize,
    },
    /// A block exposed an inconsistent lane or instruction layout.
    #[error("packed-block ISA witness violated its typed layout")]
    Layout,
    /// Construction of the verifier-fixed ISA table failed.
    #[error(transparent)]
    IsaTable(#[from] IsaTableError),
    /// Construction of one lane's shared-commitment lookup descriptor failed.
    #[error(transparent)]
    IsaLookup(#[from] IsaLookupError),
}

/// Low-degree relation for lane occupancy and canonical inactive ISA queries.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockIsaRelation;

impl BlockIsaWitness {
    /// Encodes every active instruction lane and pads every unused row canonically.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockIsaError> {
        if blocks.is_empty() {
            return Err(BlockIsaError::Empty);
        }
        if blocks.len() > UNIFORM_ROW_COUNT {
            return Err(BlockIsaError::TooManyBlocks {
                actual: blocks.len(),
                maximum: UNIFORM_ROW_COUNT,
            });
        }
        let table = fixed_isa_table()?;
        let padding = canonical_padding_row(&table)?;
        let mut columns = (0..BLOCK_ISA_COLUMN_COUNT)
            .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
            .collect::<Vec<_>>();
        for block in blocks {
            append_block(&mut columns, block, &table, padding)?;
        }
        for (column_index, column) in columns.iter_mut().enumerate() {
            let value = padding
                .get(column_index)
                .copied()
                .ok_or(BlockIsaError::Layout)?;
            column.resize(UNIFORM_ROW_COUNT, value);
        }
        Ok(Self {
            columns,
            active_block_count: blocks.len(),
        })
    }

    /// Returns every logical column in metadata-then-lane order.
    #[must_use]
    pub fn columns(&self) -> &[Vec<u64>] {
        &self.columns
    }

    /// Returns the number of non-padding block rows.
    #[must_use]
    pub const fn active_block_count(&self) -> usize {
        self.active_block_count
    }

    /// Returns the fixed-ISA lookup layout for one typed instruction lane.
    pub fn lane_lookup_columns(
        lane: BasicBlockLaneIndex,
    ) -> Result<IsaLookupColumns, BlockIsaError> {
        let start = lane_start(lane.index()).ok_or(BlockIsaError::Layout)?;
        let mut address_bits = [0_usize; ISA_ADDRESS_BIT_COUNT];
        for (bit, column) in address_bits.iter_mut().enumerate() {
            *column = start.checked_add(bit).ok_or(BlockIsaError::Layout)?;
        }
        let output_start = start
            .checked_add(ISA_ADDRESS_BIT_COUNT)
            .ok_or(BlockIsaError::Layout)?;
        let mut outputs = [0_usize; ISA_OUTPUT_COUNT];
        for (offset, column) in outputs.iter_mut().enumerate() {
            *column = output_start
                .checked_add(offset)
                .ok_or(BlockIsaError::Layout)?;
        }
        IsaLookupColumns::new(address_bits, outputs).map_err(Into::into)
    }

    pub(crate) fn into_columns(self) -> Vec<Vec<u64>> {
        self.columns
    }
}

impl UniformRelation for BlockIsaRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-isa/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [4_u64, 9, 38, 48, 198, 247, u64::from(ISA_PADDING_ADDRESS)] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_ISA_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_ISA_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_ISA_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_ISA_COLUMN_COUNT || constraints.len() != BLOCK_ISA_CONSTRAINT_COUNT {
            return Err(UniformError::Shape);
        }
        let (metadata_constraints, lane_constraints) =
            constraints.split_at_mut(BLOCK_METADATA_CONSTRAINT_COUNT);
        block_metadata::evaluate(row, metadata_constraints)?;
        let mut sink = ConstraintSink::new(lane_constraints);
        constrain_lanes(row, &mut sink)?;
        sink.finish()
    }
}

fn canonical_padding_row(
    table: &[crate::IsaTableRow],
) -> Result<[u64; BLOCK_ISA_COLUMN_COUNT], BlockIsaError> {
    let mut row = [0_u64; BLOCK_ISA_COLUMN_COUNT];
    let table_row = table
        .get(usize::from(ISA_PADDING_ADDRESS))
        .copied()
        .ok_or(BlockIsaError::Layout)?;
    if table_row.is_defined() || table_row.outputs().iter().any(|value| *value != 0) {
        return Err(BlockIsaError::Layout);
    }
    for lane in 0..BASIC_BLOCK_INSTRUCTION_BOUND {
        write_lane(
            &mut row,
            lane,
            ISA_PADDING_ADDRESS,
            table_row.outputs(),
            false,
        )?;
    }
    Ok(row)
}

fn append_block(
    columns: &mut [Vec<u64>],
    block: &BasicBlock,
    table: &[crate::IsaTableRow],
    mut row: [u64; BLOCK_ISA_COLUMN_COUNT],
) -> Result<(), BlockIsaError> {
    BlockMetadata::from_block(block)
        .and_then(|metadata| metadata.write_to(&mut row))
        .ok_or(BlockIsaError::Layout)?;
    if block.instruction_count() == 0 {
        if block.row_count() != 1
            || block
                .rows()
                .any(|source| source.effects().kind() == StepKind::Instruction)
        {
            return Err(BlockIsaError::Layout);
        }
        append_row(columns, row);
        return Ok(());
    }
    if block.instruction_count() != block.row_count() {
        return Err(BlockIsaError::Layout);
    }
    for (lane, source) in block.rows().enumerate() {
        if source.effects().kind() != StepKind::Instruction {
            return Err(BlockIsaError::Layout);
        }
        let aligned = AlignedInstruction::from_decoded(source.effects().instruction());
        let address = u16::from(aligned.key.prefix)
            .checked_mul(256)
            .and_then(|prefix| prefix.checked_add(u16::from(aligned.key.opcode)))
            .ok_or(BlockIsaError::Layout)?;
        let table_row = table
            .get(usize::from(address))
            .copied()
            .filter(|entry| entry.is_defined())
            .ok_or(BlockIsaError::Layout)?;
        write_lane(
            &mut row,
            lane,
            address,
            table_row.outputs(),
            source.effects().branch_taken(),
        )?;
    }
    append_row(columns, row);
    Ok(())
}

fn append_row(columns: &mut [Vec<u64>], row: [u64; BLOCK_ISA_COLUMN_COUNT]) {
    for (column, value) in columns.iter_mut().zip(row) {
        column.push(value);
    }
}

fn write_lane(
    row: &mut [u64],
    lane: usize,
    address: u16,
    outputs: [u64; ISA_OUTPUT_COUNT],
    branch_taken: bool,
) -> Result<(), BlockIsaError> {
    let start = lane_start(lane).ok_or(BlockIsaError::Layout)?;
    for bit in 0..ISA_ADDRESS_BIT_COUNT {
        set(
            row,
            start.checked_add(bit).ok_or(BlockIsaError::Layout)?,
            u64::from((address >> bit) & 1),
        )?;
    }
    let output_start = start
        .checked_add(ISA_ADDRESS_BIT_COUNT)
        .ok_or(BlockIsaError::Layout)?;
    for (offset, value) in outputs.into_iter().enumerate() {
        set(
            row,
            output_start
                .checked_add(offset)
                .ok_or(BlockIsaError::Layout)?,
            value,
        )?;
    }
    set(
        row,
        start
            .checked_add(LANE_BRANCH_OFFSET)
            .ok_or(BlockIsaError::Layout)?,
        u64::from(branch_taken),
    )?;
    Ok(())
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), BlockIsaError> {
    *row.get_mut(index).ok_or(BlockIsaError::Layout)? = value;
    Ok(())
}

fn constrain_lanes(row: &[NativeField], sink: &mut ConstraintSink<'_>) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    for lane in 0..BASIC_BLOCK_INSTRUCTION_BOUND {
        let start = lane_start(lane).ok_or(UniformError::Shape)?;
        let active = block_metadata::lane_value(row, lane)?;
        for bit in 0..ISA_ADDRESS_BIT_COUNT {
            sink.push(boolean(value(row, checked_add(start, bit)?)?))?;
        }
        sink.push(boolean(value(
            row,
            checked_add(start, LANE_BRANCH_OFFSET)?,
        )?))?;
        for offset in 0..BLOCK_ISA_LANE_COLUMN_COUNT {
            let expected = inactive_value(offset)?;
            sink.push((one - active) * (value(row, checked_add(start, offset)?)? - expected))?;
        }
        let valid_column = start
            .checked_add(ISA_ADDRESS_BIT_COUNT)
            .and_then(|index| index.checked_add(ISA_VALID))
            .ok_or(UniformError::Shape)?;
        sink.push(active * (value(row, valid_column)? - one))?;
    }
    Ok(())
}

fn inactive_value(offset: usize) -> Result<NativeField, UniformError> {
    if offset < ISA_ADDRESS_BIT_COUNT {
        let bit = u32::try_from(offset).map_err(|_| UniformError::Shape)?;
        Ok(NativeField::from_u64(u64::from(
            (ISA_PADDING_ADDRESS >> bit) & 1,
        )))
    } else {
        Ok(NativeField::from_u64(0))
    }
}

pub(crate) fn lane_output_value(
    row: &[NativeField],
    lane: usize,
    output: usize,
) -> Result<NativeField, UniformError> {
    if output >= ISA_OUTPUT_COUNT {
        return Err(UniformError::Shape);
    }
    let start = lane_start(lane).ok_or(UniformError::Shape)?;
    let index = start
        .checked_add(ISA_ADDRESS_BIT_COUNT)
        .and_then(|value| value.checked_add(output))
        .ok_or(UniformError::Shape)?;
    value(row, index)
}

pub(crate) fn lane_output_values(
    row: &[NativeField],
    lane: usize,
    output: usize,
    count: usize,
) -> Result<&[NativeField], UniformError> {
    let end = output.checked_add(count).ok_or(UniformError::Shape)?;
    if end > ISA_OUTPUT_COUNT {
        return Err(UniformError::Shape);
    }
    let start = lane_start(lane)
        .and_then(|value| value.checked_add(ISA_ADDRESS_BIT_COUNT))
        .and_then(|value| value.checked_add(output))
        .ok_or(UniformError::Shape)?;
    let end = start.checked_add(count).ok_or(UniformError::Shape)?;
    row.get(start..end).ok_or(UniformError::Shape)
}

pub(crate) fn lane_address_bit_value(
    row: &[NativeField],
    lane: usize,
    bit: usize,
) -> Result<NativeField, UniformError> {
    if bit >= ISA_ADDRESS_BIT_COUNT {
        return Err(UniformError::Shape);
    }
    let start = lane_start(lane).ok_or(UniformError::Shape)?;
    value(row, checked_add(start, bit)?)
}

pub(crate) fn lane_branch_value(
    row: &[NativeField],
    lane: usize,
) -> Result<NativeField, UniformError> {
    let start = lane_start(lane).ok_or(UniformError::Shape)?;
    value(row, checked_add(start, LANE_BRANCH_OFFSET)?)
}

fn lane_start(lane: usize) -> Option<usize> {
    lane.checked_mul(BLOCK_ISA_LANE_COLUMN_COUNT)
        .and_then(|offset| LANE_START.checked_add(offset))
        .filter(|start| {
            start
                .checked_add(BLOCK_ISA_LANE_COLUMN_COUNT)
                .is_some_and(|end| end <= COLUMN_END)
        })
}

fn checked_add(left: usize, right: usize) -> Result<usize, UniformError> {
    left.checked_add(right).ok_or(UniformError::Shape)
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
    use crate::{block_test_support::flip_witness_bit, validate_uniform_witness};

    #[test]
    fn canonical_lane_queries_satisfy_and_expose_disjoint_layouts()
    -> Result<(), Box<dyn std::error::Error>> {
        let rom = RomImage::new(vec![0x00; BASIC_BLOCK_INSTRUCTION_BOUND])?;
        let memory = MemoryImage::zeroed()?;
        let mut builder = TraceBuilder::new(rom, memory, Vec::new());
        let rows = (0..BASIC_BLOCK_INSTRUCTION_BOUND)
            .map(|_| builder.step())
            .collect::<Result<Vec<_>, _>>()?;
        let blocks = pack_witness_basic_blocks(Witness::from_rows(rows)?)?;
        let witness = BlockIsaWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockIsaRelation, witness.columns())?;

        let first = BlockIsaWitness::lane_lookup_columns(BasicBlockLaneIndex::Lane0)?;
        let last = BlockIsaWitness::lane_lookup_columns(BasicBlockLaneIndex::Lane3)?;
        assert!(
            first
                .outputs()
                .iter()
                .all(|column| !last.outputs().contains(column))
        );
        let valid_column = first
            .outputs()
            .get(ISA_VALID)
            .copied()
            .ok_or(UniformError::Shape)?;
        let mut mutated = witness.columns().to_vec();
        flip_witness_bit(&mut mutated, valid_column, 0)?;
        assert!(validate_uniform_witness(&BlockIsaRelation, &mutated).is_err());
        Ok(())
    }
}
