//! Lane-local cycle and transcript-flow constraints over the packed block front end.

use akita_pcs::Ring;
use zksm83_trace::{BASIC_BLOCK_INSTRUCTION_BOUND, BASIC_BLOCK_M_CYCLE_BOUND};

use crate::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_FRONTEND_COLUMN_COUNT, BLOCK_FRONTEND_CONSTRAINT_COUNT,
    BLOCK_FRONTEND_MAX_DEGREE, BLOCK_ISA_CONTROL_COLUMN_COUNT, BLOCK_ROUTING_COLUMN_COUNT,
    BlockFrontendRelation, ConstraintOutput, ISA_BASE_M_CYCLES, ISA_TAKEN_M_CYCLES,
    ISA_TAKEN_TIMING, NativeField, STATE_BUS_NEXT_INDEX, STATE_CPU_M_CYCLES_INDEX,
    STATE_INPUT_NEXT_INDEX, STATE_ISA_NEXT_INDEX, STATE_MACHINE_PROFILE_INDEX,
    STATE_OUTPUT_NEXT_INDEX, UniformError, UniformRelation,
    block_boundary::local_state_value,
    block_frontend::owned_bus_category,
    block_isa::{lane_branch_value, lane_output_value},
    block_metadata::{self, lane_value},
    block_routing::cycle_owner_value,
};

/// Logical columns consumed by the packed lane-flow relation.
pub const BLOCK_FLOW_COLUMN_COUNT: usize = BLOCK_FRONTEND_COLUMN_COUNT;
/// Identities in the packed lane-flow relation.
pub const BLOCK_FLOW_CONSTRAINT_COUNT: usize =
    BLOCK_FRONTEND_CONSTRAINT_COUNT + BASIC_BLOCK_INSTRUCTION_BOUND * 7;
/// Maximum total degree in the packed lane-flow relation.
pub const BLOCK_FLOW_MAX_DEGREE: usize = BLOCK_FRONTEND_MAX_DEGREE;

const _: () = assert!(BASIC_BLOCK_INSTRUCTION_BOUND == 4);
const _: () = assert!(BASIC_BLOCK_M_CYCLE_BOUND == 6);
const _: () = assert!(ISA_BASE_M_CYCLES == 3);
const _: () = assert!(ISA_TAKEN_M_CYCLES == 4);
const _: () = assert!(STATE_CPU_M_CYCLES_INDEX == 12);
const _: () = assert!(STATE_INPUT_NEXT_INDEX == 16);
const _: () = assert!(STATE_OUTPUT_NEXT_INDEX == 17);
const _: () = assert!(STATE_BUS_NEXT_INDEX == 18);
const _: () = assert!(STATE_ISA_NEXT_INDEX == 19);
const _: () = assert!(STATE_MACHINE_PROFILE_INDEX == 20);
const _: () = assert!(BLOCK_FLOW_COLUMN_COUNT == 729);
const _: () = assert!(BLOCK_FLOW_CONSTRAINT_COUNT == 1_124);
const _: () = assert!(BLOCK_FLOW_MAX_DEGREE == 7);

/// Low-degree front-end relation plus per-lane cycle and ordered-cursor flow.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockFlowRelation;

impl UniformRelation for BlockFlowRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-flow/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [729_u64, 1_096, 4, 7, 1_124, 12, 16, 17, 18, 19, 20, 1] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_FLOW_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_FLOW_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_FLOW_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_FLOW_COLUMN_COUNT || constraints.len() != BLOCK_FLOW_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let (frontend_constraints, flow_constraints) =
            constraints.split_at_mut(BLOCK_FRONTEND_CONSTRAINT_COUNT);
        BlockFrontendRelation.evaluate(row, frontend_constraints)?;
        constrain_lane_flow(row, flow_constraints)
    }
}

fn constrain_lane_flow(
    row: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if constraints.len() != BASIC_BLOCK_INSTRUCTION_BOUND * 7 {
        return Err(UniformError::Shape);
    }
    let boundary = row
        .get(BLOCK_ROUTING_COLUMN_COUNT..BLOCK_CONTROL_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let isa = row
        .get(BLOCK_CONTROL_COLUMN_COUNT..BLOCK_ISA_CONTROL_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let bus = row
        .get(BLOCK_ISA_CONTROL_COLUMN_COUNT..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let instruction = block_metadata::instruction_value(row)?;
    let mut sink = ConstraintSink::new(constraints);
    for lane in 0..BASIC_BLOCK_INSTRUCTION_BOUND {
        constrain_lane(row, boundary, isa, bus, lane, instruction, &mut sink)?;
    }
    sink.finish()
}

fn constrain_lane(
    routing: &[NativeField],
    boundary: &[NativeField],
    isa: &[NativeField],
    bus: &[NativeField],
    lane: usize,
    instruction: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let active = lane_value(routing, lane)?;
    let branch = lane_branch_value(isa, lane)?;
    let base_cycles = lane_output_value(isa, lane, ISA_BASE_M_CYCLES)?;
    let taken_cycles = lane_output_value(isa, lane, ISA_TAKEN_M_CYCLES)?;
    let taken_timing = lane_output_value(isa, lane, ISA_TAKEN_TIMING)?;
    let expected_cycles =
        active * (base_cycles + branch * taken_timing * (taken_cycles - base_cycles));
    sink.push(
        instruction * (state_delta(boundary, lane, STATE_CPU_M_CYCLES_INDEX)? - expected_cycles),
    )?;
    sink.push(instruction * (cycle_owner_count(routing, lane)? - expected_cycles))?;
    sink.push(instruction * state_delta(boundary, lane, STATE_ISA_NEXT_INDEX)?)?;
    sink.push(instruction * state_delta(boundary, lane, STATE_BUS_NEXT_INDEX)?)?;
    sink.push(
        instruction
            * (state_delta(boundary, lane, STATE_INPUT_NEXT_INDEX)?
                - owned_bus_category(routing, bus, lane, &[6, 13])?),
    )?;
    sink.push(
        instruction
            * (state_delta(boundary, lane, STATE_OUTPUT_NEXT_INDEX)?
                - owned_bus_category(routing, bus, lane, &[7])?),
    )?;
    sink.push(instruction * state_delta(boundary, lane, STATE_MACHINE_PROFILE_INDEX)?)
}

fn state_delta(
    boundary: &[NativeField],
    lane: usize,
    scalar: usize,
) -> Result<NativeField, UniformError> {
    let next = lane.checked_add(1).ok_or(UniformError::Shape)?;
    Ok(local_state_value(boundary, next, scalar)? - local_state_value(boundary, lane, scalar)?)
}

fn cycle_owner_count(routing: &[NativeField], lane: usize) -> Result<NativeField, UniformError> {
    (0..BASIC_BLOCK_M_CYCLE_BOUND).try_fold(NativeField::from_u64(0), |sum, slot| {
        Ok(sum + cycle_owner_value(routing, slot, lane)?)
    })
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
        BlockFrontendWitness,
        block_boundary::local_state_column,
        block_test_support::{increment_witness_cell, lookup_blocks},
        validate_uniform_witness,
    };

    #[test]
    fn lane_flow_binds_cycles_and_all_ordered_cursors() -> Result<(), Box<dyn std::error::Error>> {
        let blocks = lookup_blocks(&[0xcb, 0x00, 0x00, 0x00], 3)?;
        let witness = BlockFrontendWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockFlowRelation, witness.columns())?;
        let cycle_column = BLOCK_ROUTING_COLUMN_COUNT
            .checked_add(
                local_state_column(1, STATE_CPU_M_CYCLES_INDEX).ok_or(UniformError::Shape)?,
            )
            .ok_or(UniformError::Shape)?;
        let mut mutated = witness.columns().to_vec();
        increment_witness_cell(&mut mutated, cycle_column, 0)?;
        validate_uniform_witness(&BlockFrontendRelation, &mutated)?;
        assert!(validate_uniform_witness(&BlockFlowRelation, &mutated).is_err());
        Ok(())
    }

    #[test]
    fn taken_branch_uses_total_taken_cycle_count() -> Result<(), Box<dyn std::error::Error>> {
        let blocks = lookup_blocks(&[0x28, 0x00, 0x00], 1)?;
        let witness = BlockFrontendWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockFlowRelation, witness.columns())?;
        Ok(())
    }
}
