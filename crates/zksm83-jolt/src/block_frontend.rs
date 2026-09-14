//! Composed packed-block control, fixed-ISA, and shared ordered-bus front end.

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_trace::{
    BASIC_BLOCK_BUS_EVENT_BOUND, BASIC_BLOCK_INSTRUCTION_BOUND, BasicBlock, BasicBlockLaneIndex,
};

use crate::{
    BLOCK_BUS_COLUMN_COUNT, BLOCK_BUS_CONSTRAINT_COUNT, BLOCK_BUS_MAX_DEGREE,
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_ISA_CONTROL_COLUMN_COUNT, BLOCK_ISA_CONTROL_CONSTRAINT_COUNT,
    BLOCK_ISA_CONTROL_MAX_DEGREE, BlockBusError, BlockBusRelation, BlockBusWitness,
    BlockIsaControlError, BlockIsaControlRelation, BlockIsaControlWitness, ConstraintOutput,
    ISA_DATA_READS, ISA_DATA_WRITES, ISA_IMMEDIATE_READS, ISA_OPCODE_FETCHES, ISA_TAKEN_DATA_READS,
    ISA_TAKEN_DATA_WRITES, IsaLookupColumns, NativeField, ROM_ADDRESS_BIT_COUNT, RomLookupColumns,
    UniformError, UniformRelation,
    block_bus::{slot_active_value, slot_kind_selector},
    block_isa::{lane_branch_value, lane_output_value},
    block_metadata::{self, BLOCK_METADATA_COLUMN_COUNT},
    block_routing::bus_owner_value,
};

/// Logical columns in the packed-block control, ISA, and shared-bus front end.
pub const BLOCK_FRONTEND_COLUMN_COUNT: usize =
    BLOCK_ISA_CONTROL_COLUMN_COUNT + BLOCK_BUS_COLUMN_COUNT;
/// Identities in the packed-block front-end relation.
pub const BLOCK_FRONTEND_CONSTRAINT_COUNT: usize = BLOCK_ISA_CONTROL_CONSTRAINT_COUNT
    + BLOCK_BUS_CONSTRAINT_COUNT
    + BLOCK_METADATA_COLUMN_COUNT
    + BASIC_BLOCK_BUS_EVENT_BOUND
    + BASIC_BLOCK_INSTRUCTION_BOUND * 5;
/// Maximum total degree in the packed-block front-end relation.
pub const BLOCK_FRONTEND_MAX_DEGREE: usize = if BLOCK_ISA_CONTROL_MAX_DEGREE > BLOCK_BUS_MAX_DEGREE
{
    BLOCK_ISA_CONTROL_MAX_DEGREE
} else {
    BLOCK_BUS_MAX_DEGREE
};

const _: () = assert!(BLOCK_METADATA_COLUMN_COUNT == 6);
const _: () = assert!(BASIC_BLOCK_BUS_EVENT_BOUND == 5);
const _: () = assert!(BASIC_BLOCK_INSTRUCTION_BOUND == 4);
const _: () = assert!(BLOCK_FRONTEND_COLUMN_COUNT == 729);
const _: () = assert!(BLOCK_FRONTEND_CONSTRAINT_COUNT == 1_096);
const _: () = assert!(BLOCK_FRONTEND_MAX_DEGREE == 7);

/// Fixed-row witness for the proof-free packed instruction front end.
#[derive(Debug)]
pub struct BlockFrontendWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to construct or describe the packed instruction front end.
#[derive(Debug, Error)]
pub enum BlockFrontendError {
    /// Control and lane-local ISA construction failed.
    #[error("packed-block ISA control construction failed: {0}")]
    IsaControl(#[from] BlockIsaControlError),
    /// Shared ordered-bus construction failed.
    #[error("packed-block bus construction failed: {0}")]
    Bus(#[from] BlockBusError),
    /// Independently derived planes disagreed on their fixed-row shape.
    #[error("packed-block front-end planes have inconsistent shapes")]
    Shape,
}

/// Low-degree composition of block control, ISA metadata, and shared bus routing.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockFrontendRelation;

impl BlockFrontendWitness {
    /// Derives every front-end plane from the same validated owned blocks.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockFrontendError> {
        let isa_control = BlockIsaControlWitness::from_blocks(blocks)?;
        let bus = BlockBusWitness::from_blocks(blocks)?;
        if isa_control.active_block_count() != bus.active_block_count() {
            return Err(BlockFrontendError::Shape);
        }
        let active_block_count = isa_control.active_block_count();
        let mut columns = isa_control.into_columns();
        columns.extend(bus.into_columns());
        if columns.len() != BLOCK_FRONTEND_COLUMN_COUNT {
            return Err(BlockFrontendError::Shape);
        }
        Ok(Self {
            columns,
            active_block_count,
        })
    }

    /// Returns all columns in ISA-control-then-bus order.
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

    /// Returns one lane's absolute fixed-ISA lookup layout in this front-end plane.
    pub fn lane_lookup_columns(
        lane: BasicBlockLaneIndex,
    ) -> Result<IsaLookupColumns, BlockFrontendError> {
        BlockIsaControlWitness::lane_lookup_columns(lane).map_err(Into::into)
    }

    /// Returns the absolute five-slot immutable-ROM lookup layout in this front-end plane.
    pub fn rom_lookup_columns() -> Result<RomLookupColumns, BlockFrontendError> {
        let relative = BlockBusWitness::rom_lookup_columns()?;
        let selectors = shift_indices(relative.selectors(), BLOCK_ISA_CONTROL_COLUMN_COUNT)?;
        let values = shift_indices(relative.values(), BLOCK_ISA_CONTROL_COLUMN_COUNT)?;
        let address_bits = shift_matrix(relative.address_bits(), BLOCK_ISA_CONTROL_COLUMN_COUNT)?;
        RomLookupColumns::new(selectors, address_bits, values)
            .map_err(BlockBusError::from)
            .map_err(Into::into)
    }
}

impl UniformRelation for BlockFrontendRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-frontend/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [393_u64, 685, 336, 380, 6, 5, 20, 729, 1_096] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_FRONTEND_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_FRONTEND_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_FRONTEND_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_FRONTEND_COLUMN_COUNT
            || constraints.len() != BLOCK_FRONTEND_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let (isa_control_row, bus_row) = row.split_at(BLOCK_ISA_CONTROL_COLUMN_COUNT);
        let (isa_control_constraints, remainder) =
            constraints.split_at_mut(BLOCK_ISA_CONTROL_CONSTRAINT_COUNT);
        let (bus_constraints, composition_constraints) =
            remainder.split_at_mut(BLOCK_BUS_CONSTRAINT_COUNT);
        BlockIsaControlRelation.evaluate(isa_control_row, isa_control_constraints)?;
        BlockBusRelation.evaluate(bus_row, bus_constraints)?;
        constrain_composition(isa_control_row, bus_row, composition_constraints)
    }
}

fn constrain_composition(
    isa_control: &[NativeField],
    bus: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    let expected = BLOCK_METADATA_COLUMN_COUNT
        .checked_add(BASIC_BLOCK_BUS_EVENT_BOUND)
        .and_then(|value| value.checked_add(BASIC_BLOCK_INSTRUCTION_BOUND * 5))
        .ok_or(UniformError::Shape)?;
    if constraints.len() != expected {
        return Err(UniformError::Shape);
    }
    let mut sink = ConstraintSink::new(constraints);
    constrain_shared_metadata(isa_control, bus, &mut sink)?;
    constrain_instruction_slot_activity(isa_control, bus, &mut sink)?;
    constrain_lane_event_counts(isa_control, bus, &mut sink)?;
    sink.finish()
}

fn constrain_shared_metadata(
    isa_control: &[NativeField],
    bus: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for column in 0..BLOCK_METADATA_COLUMN_COUNT {
        let left = isa_control
            .get(column)
            .copied()
            .ok_or(UniformError::Shape)?;
        let right = bus.get(column).copied().ok_or(UniformError::Shape)?;
        sink.push(left - right)?;
    }
    Ok(())
}

fn constrain_instruction_slot_activity(
    isa_control: &[NativeField],
    bus: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let instruction = block_metadata::instruction_value(isa_control)?;
    for slot in 0..BASIC_BLOCK_BUS_EVENT_BOUND {
        let owner_sum = (0..BASIC_BLOCK_INSTRUCTION_BOUND)
            .try_fold(NativeField::from_u64(0), |sum, lane| {
                Ok::<_, UniformError>(sum + bus_owner_value(isa_control, slot, lane)?)
            })?;
        sink.push(instruction * (slot_active_value(bus, slot)? - owner_sum))?;
    }
    Ok(())
}

fn constrain_lane_event_counts(
    isa_control: &[NativeField],
    bus: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let isa = isa_control
        .get(BLOCK_CONTROL_COLUMN_COUNT..BLOCK_ISA_CONTROL_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    for lane in 0..BASIC_BLOCK_INSTRUCTION_BOUND {
        let event_count = lane_bus_owner_count(isa_control, lane)?;
        let opcode = owned_bus_category(isa_control, bus, lane, &[1, 14])?;
        let immediate = owned_bus_category(isa_control, bus, lane, &[2, 15])?;
        let data_read = owned_bus_category(isa_control, bus, lane, &[3, 4, 6, 9, 11, 13])?;
        let data_write = owned_bus_category(isa_control, bus, lane, &[5, 7, 8, 10, 12])?;
        let branch = lane_branch_value(isa, lane)?;
        let base_count = lane_output_value(isa, lane, ISA_OPCODE_FETCHES)?
            + lane_output_value(isa, lane, ISA_IMMEDIATE_READS)?
            + lane_output_value(isa, lane, ISA_DATA_READS)?
            + lane_output_value(isa, lane, ISA_DATA_WRITES)?;
        let taken_count = lane_output_value(isa, lane, ISA_TAKEN_DATA_READS)?
            + lane_output_value(isa, lane, ISA_TAKEN_DATA_WRITES)?;
        sink.push(event_count - base_count - branch * taken_count)?;
        sink.push(opcode - lane_output_value(isa, lane, ISA_OPCODE_FETCHES)?)?;
        sink.push(immediate - lane_output_value(isa, lane, ISA_IMMEDIATE_READS)?)?;
        sink.push(
            data_read
                - lane_output_value(isa, lane, ISA_DATA_READS)?
                - branch * lane_output_value(isa, lane, ISA_TAKEN_DATA_READS)?,
        )?;
        sink.push(
            data_write
                - lane_output_value(isa, lane, ISA_DATA_WRITES)?
                - branch * lane_output_value(isa, lane, ISA_TAKEN_DATA_WRITES)?,
        )?;
    }
    Ok(())
}

pub(crate) fn lane_bus_owner_count(
    isa_control: &[NativeField],
    lane: usize,
) -> Result<NativeField, UniformError> {
    (0..BASIC_BLOCK_BUS_EVENT_BOUND).try_fold(NativeField::from_u64(0), |sum, slot| {
        Ok(sum + bus_owner_value(isa_control, slot, lane)?)
    })
}

pub(crate) fn owned_bus_category(
    isa_control: &[NativeField],
    bus: &[NativeField],
    lane: usize,
    codes: &[u8],
) -> Result<NativeField, UniformError> {
    let mut count = NativeField::from_u64(0);
    for slot in 0..BASIC_BLOCK_BUS_EVENT_BOUND {
        let owner = bus_owner_value(isa_control, slot, lane)?;
        for code in codes {
            count += owner * slot_kind_selector(bus, slot, *code)?;
        }
    }
    Ok(count)
}

fn shift_indices<const N: usize>(
    indices: [usize; N],
    offset: usize,
) -> Result<[usize; N], BlockFrontendError> {
    let mut shifted = [0_usize; N];
    for (source, target) in indices.into_iter().zip(shifted.iter_mut()) {
        *target = source
            .checked_add(offset)
            .ok_or(BlockFrontendError::Shape)?;
    }
    Ok(shifted)
}

fn shift_matrix<const OUTER: usize, const INNER: usize>(
    indices: [[usize; INNER]; OUTER],
    offset: usize,
) -> Result<[[usize; INNER]; OUTER], BlockFrontendError> {
    let mut shifted = [[0_usize; INNER]; OUTER];
    for (source_row, target_row) in indices.into_iter().zip(shifted.iter_mut()) {
        *target_row = shift_indices(source_row, offset)?;
    }
    Ok(shifted)
}

const _: () = assert!(ROM_ADDRESS_BIT_COUNT == 20);

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
    fn packed_frontend_binds_lane_owners_to_isa_event_counts()
    -> Result<(), Box<dyn std::error::Error>> {
        let rom = RomImage::new(vec![0xcb, 0x00, 0x00, 0x00])?;
        let memory = MemoryImage::zeroed()?;
        let mut builder = TraceBuilder::new(rom, memory, Vec::new());
        let rows = vec![builder.step()?, builder.step()?, builder.step()?];
        let blocks = pack_witness_basic_blocks(Witness::from_rows(rows)?)?;
        let witness = BlockFrontendWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockFrontendRelation, witness.columns())?;
        for lane in [
            BasicBlockLaneIndex::Lane0,
            BasicBlockLaneIndex::Lane1,
            BasicBlockLaneIndex::Lane2,
            BasicBlockLaneIndex::Lane3,
        ] {
            BlockFrontendWitness::lane_lookup_columns(lane)?;
        }
        BlockFrontendWitness::rom_lookup_columns()?;

        let mut mutated = witness.columns().to_vec();
        let lane_zero = BlockFrontendWitness::lane_lookup_columns(BasicBlockLaneIndex::Lane0)?;
        let count_column = lane_zero
            .outputs()
            .get(ISA_OPCODE_FETCHES)
            .copied()
            .ok_or(UniformError::Shape)?;
        let value = mutated
            .get_mut(count_column)
            .and_then(|column| column.first_mut())
            .ok_or(UniformError::Shape)?;
        *value = value.checked_add(1).ok_or(UniformError::Shape)?;
        assert!(validate_uniform_witness(&BlockFrontendRelation, &mutated).is_err());
        Ok(())
    }
}
