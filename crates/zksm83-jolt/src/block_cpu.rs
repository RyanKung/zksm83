//! Compact lane-local SM83 instruction semantics over the packed v2 witness.

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_core::{StepKind, VmState};
use zksm83_trace::{
    BASIC_BLOCK_BUS_EVENT_BOUND, BASIC_BLOCK_INSTRUCTION_BOUND, BasicBlock, BasicBlockLaneIndex,
};

use crate::{
    BLOCK_MEMORY_COLUMN_COUNT, BLOCK_MEMORY_CONSTRAINT_COUNT, BlockFrontendError, BlockMemoryError,
    BlockMemoryRelation, BlockMemoryWitness, ConstraintOutput, IsaLookupColumns, NativeField,
    NativeTraceError, RomLookupColumns, UNIFORM_ROW_COUNT, UniformError, UniformRelation,
    block_metadata,
    cpu::packed::{
        PACKED_CPU_BOUNDARY_CONSTRAINT_COUNT, PACKED_CPU_BUS_MATCH_CONSTRAINT_COUNT,
        PACKED_CPU_LANE_RANGE_CONSTRAINT_COUNT, PACKED_CPU_SHARED_BOUNDARY_CONSTRAINT_COUNT,
        constrain_bus_matches, constrain_instruction_lane,
    },
    execution_lookup::{
        EXECUTION_LOOKUP_COLUMN_COUNT, EXECUTION_LOOKUP_WELL_FORMED_CONSTRAINT_COUNT,
        ExecutionLookupColumns, ExecutionLookupWitness, ExecutionLookupWitnessError,
        constrain_execution_lookup_well_formed,
    },
    trace::{
        CPU_BOUNDARY_AUX_COLUMN_COUNT, CPU_LANE_AUX_COLUMN_COUNT, CPU_SEMANTIC_AUX_COLUMN_COUNT,
        CpuSemanticAuxEncoder, PACKED_CPU_AUX_COLUMN_COUNT, PACKED_CPU_BUS_MATCH_COLUMN_COUNT,
        PACKED_CPU_DERIVED_SCALAR_COUNT, PACKED_CPU_SEMANTIC_AUX_COLUMN_COUNT,
        cpu_semantic_legacy_column, is_omitted_cpu_lane_legacy_column, packed_cpu_aux_offset,
        packed_cpu_bus_match_offset, packed_cpu_derived_scalar,
    },
};

const PACKED_CPU_LANE_CONSTRAINT_COUNT: usize = 317;
const PACKED_CPU_SEMANTIC_CONSTRAINT_COUNT: usize = PACKED_CPU_SEMANTIC_AUX_COLUMN_COUNT
    + PACKED_CPU_BUS_MATCH_CONSTRAINT_COUNT
    + PACKED_CPU_SHARED_BOUNDARY_CONSTRAINT_COUNT
    + BASIC_BLOCK_INSTRUCTION_BOUND * PACKED_CPU_LANE_CONSTRAINT_COUNT;
const PACKED_CPU_ADDITIONAL_CONSTRAINT_COUNT: usize =
    PACKED_CPU_SEMANTIC_CONSTRAINT_COUNT + EXECUTION_LOOKUP_WELL_FORMED_CONSTRAINT_COUNT;

/// Logical columns in the packed memory plane plus four compact CPU helper lanes.
pub const BLOCK_CPU_COLUMN_COUNT: usize =
    BLOCK_MEMORY_COLUMN_COUNT + PACKED_CPU_AUX_COLUMN_COUNT + EXECUTION_LOOKUP_COLUMN_COUNT;
/// Identities in the packed memory and lane-local CPU semantic relation.
pub const BLOCK_CPU_CONSTRAINT_COUNT: usize =
    BLOCK_MEMORY_CONSTRAINT_COUNT + PACKED_CPU_ADDITIONAL_CONSTRAINT_COUNT;
/// Conservative degree bound after projecting shared bus slots through committed matches.
pub const BLOCK_CPU_MAX_DEGREE: usize = 23;

const _: () = assert!(BASIC_BLOCK_INSTRUCTION_BOUND == 4);
const _: () = assert!(BLOCK_CPU_COLUMN_COUNT == 4_604);
const _: () = assert!(BLOCK_CPU_CONSTRAINT_COUNT == 11_483);

/// Repeated packed-CPU computation that should be isolated before benchmarking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackedCpuEvaluationHotspot {
    /// Mapping one shared packed row into each lane-local SM83 view.
    LaneProjection,
    /// Reconstructing packed byte, word, address, and state scalars from bits.
    BitReconstruction,
    /// Building selector polynomials from fixed-ISA and bus-kind bits.
    SelectorConstruction,
    /// Reconstructing lane-local bus slots from committed bus-match columns.
    LocalBusProjection,
    /// Checking committed bus-match helper columns against routing ownership.
    BusMatchReconstruction,
    /// Binding byte-operation queries to the fixed execution lookup table.
    ExecutionLookupGlue,
}

/// Cached value family used by the current packed CPU evaluator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackedCpuCachedValue {
    /// Lane-local projected bus tuple fields.
    LocalBusTupleFields,
    /// Lane-local bus address, physical-address, value, and before bit planes.
    LocalBusBitPlanes,
    /// Lane-local ROM selector and value projections.
    LocalRomProjection,
    /// Derived byte or word scalars reconstructed once per lane.
    DerivedScalars,
    /// Committed helper columns for local-to-shared bus-slot matching.
    BusMatchWitness,
}

/// Static profile of the packed CPU evaluator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedCpuEvaluationProfile {
    /// Number of packed instruction lanes per row.
    pub lane_count: usize,
    /// Maximum lane-local bus slots per packed row.
    pub local_bus_slot_count: usize,
    /// Hot computations to benchmark before protocol-level claims.
    pub hotspots: &'static [PackedCpuEvaluationHotspot],
    /// Computations currently cached or materialized as witness helpers.
    pub cached_values: &'static [PackedCpuCachedValue],
}

const PACKED_CPU_EVALUATION_HOTSPOTS: [PackedCpuEvaluationHotspot; 6] = [
    PackedCpuEvaluationHotspot::LaneProjection,
    PackedCpuEvaluationHotspot::BitReconstruction,
    PackedCpuEvaluationHotspot::SelectorConstruction,
    PackedCpuEvaluationHotspot::LocalBusProjection,
    PackedCpuEvaluationHotspot::BusMatchReconstruction,
    PackedCpuEvaluationHotspot::ExecutionLookupGlue,
];

const PACKED_CPU_CACHED_VALUES: [PackedCpuCachedValue; 5] = [
    PackedCpuCachedValue::LocalBusTupleFields,
    PackedCpuCachedValue::LocalBusBitPlanes,
    PackedCpuCachedValue::LocalRomProjection,
    PackedCpuCachedValue::DerivedScalars,
    PackedCpuCachedValue::BusMatchWitness,
];

/// Fixed-row packed witness with compact helpers for every instruction lane.
#[derive(Debug)]
pub struct BlockCpuWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
    bus_event_count: usize,
    instruction_count: usize,
    execution_lookup_count: usize,
    transition_count: usize,
    initial_state: VmState,
    final_state: VmState,
    final_memory_timestamps: Vec<u64>,
}

/// Failure to build the compact packed CPU semantic witness.
#[derive(Debug, Error)]
pub enum BlockCpuError {
    /// Construction of the packed memory prefix failed.
    #[error(transparent)]
    Memory(#[from] BlockMemoryError),
    /// Construction of one lane's compact CPU helper values failed.
    #[error(transparent)]
    Trace(#[from] NativeTraceError),
    /// Construction of the fixed execution-lookup projection failed.
    #[error(transparent)]
    ExecutionLookup(#[from] ExecutionLookupWitnessError),
    /// A block or auxiliary column violated the fixed packed layout.
    #[error("packed CPU witness violated its typed layout")]
    Layout,
}

/// Deepest proof-free packed relation, including all ordinary instruction families.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockCpuRelation;

impl BlockCpuRelation {
    /// Returns the current packed CPU evaluator's hotspot and cache profile.
    #[must_use]
    pub const fn evaluation_profile() -> PackedCpuEvaluationProfile {
        PackedCpuEvaluationProfile {
            lane_count: BASIC_BLOCK_INSTRUCTION_BOUND,
            local_bus_slot_count: BASIC_BLOCK_BUS_EVENT_BOUND,
            hotspots: &PACKED_CPU_EVALUATION_HOTSPOTS,
            cached_values: &PACKED_CPU_CACHED_VALUES,
        }
    }
}

impl BlockCpuWitness {
    /// Derives the shared packed prefix and all lane-local semantic helpers.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockCpuError> {
        let memory = BlockMemoryWitness::from_blocks(blocks)?;
        let execution = ExecutionLookupWitness::from_blocks(blocks)?;
        let active_block_count = memory.active_block_count();
        if execution.active_block_count() != active_block_count {
            return Err(BlockCpuError::Layout);
        }
        let bus_event_count = memory.bus_event_count();
        let instruction_count = memory.instruction_count();
        let execution_lookup_count = execution.lookup_count();
        let transition_count = blocks
            .iter()
            .try_fold(0_usize, |count, block| count.checked_add(block.row_count()));
        let transition_count = transition_count.ok_or(BlockCpuError::Layout)?;
        let initial_state = memory.initial_state();
        let final_state = memory.final_state();
        let mut auxiliary = (0..PACKED_CPU_AUX_COLUMN_COUNT)
            .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
            .collect::<Vec<_>>();
        let mut encoder = CpuSemanticAuxEncoder::new();
        for block in blocks {
            append_block(&mut auxiliary, &mut encoder, block)?;
        }
        for column in &mut auxiliary {
            column.resize(UNIFORM_ROW_COUNT, 0);
        }
        let (mut columns, final_memory_timestamps) = memory.into_columns_and_timestamps();
        columns.reserve_exact(PACKED_CPU_AUX_COLUMN_COUNT);
        columns.extend(auxiliary);
        columns.extend(execution.into_columns());
        if columns.len() != BLOCK_CPU_COLUMN_COUNT {
            return Err(BlockCpuError::Layout);
        }
        Ok(Self {
            columns,
            active_block_count,
            bus_event_count,
            instruction_count,
            execution_lookup_count,
            transition_count,
            initial_state,
            final_state,
            final_memory_timestamps,
        })
    }

    /// Returns every packed prefix and lane-helper column in canonical order.
    #[must_use]
    pub fn columns(&self) -> &[Vec<u64>] {
        &self.columns
    }

    /// Returns the number of non-padding packed-block rows.
    #[must_use]
    pub const fn active_block_count(&self) -> usize {
        self.active_block_count
    }

    /// Returns the exact number of active shared-bus slots.
    #[must_use]
    pub const fn bus_event_count(&self) -> usize {
        self.bus_event_count
    }

    /// Returns the exact number of active fixed-ISA lanes.
    #[must_use]
    pub const fn instruction_count(&self) -> usize {
        self.instruction_count
    }

    /// Returns the exact number of active execution-table queries.
    #[must_use]
    pub const fn execution_lookup_count(&self) -> usize {
        self.execution_lookup_count
    }

    /// Returns the exact number of source machine transitions represented.
    #[must_use]
    pub const fn transition_count(&self) -> usize {
        self.transition_count
    }

    /// Returns the VM boundary before the first packed block.
    #[must_use]
    pub const fn initial_state(&self) -> VmState {
        self.initial_state
    }

    /// Returns the VM boundary after the final packed block.
    #[must_use]
    pub const fn final_state(&self) -> VmState {
        self.final_state
    }

    /// Returns the last packed event timestamp for every mutable byte.
    #[must_use]
    pub fn final_memory_timestamps(&self) -> &[u64] {
        &self.final_memory_timestamps
    }

    /// Returns one lane's fixed-ISA lookup layout in the shared packed prefix.
    pub fn lane_isa_lookup_columns(
        lane: BasicBlockLaneIndex,
    ) -> Result<IsaLookupColumns, BlockFrontendError> {
        BlockMemoryWitness::lane_isa_lookup_columns(lane)
    }

    /// Returns the immutable-ROM lookup layout in the shared packed prefix.
    pub fn rom_lookup_columns() -> Result<RomLookupColumns, BlockFrontendError> {
        BlockMemoryWitness::rom_lookup_columns()
    }

    /// Returns one packed execution-lookup slot on the shared commitment plane.
    pub fn execution_lookup_columns(
        lane: usize,
        query: usize,
    ) -> Result<ExecutionLookupColumns, ExecutionLookupWitnessError> {
        let start = BLOCK_MEMORY_COLUMN_COUNT
            .checked_add(PACKED_CPU_AUX_COLUMN_COUNT)
            .ok_or(ExecutionLookupWitnessError::Layout)?;
        ExecutionLookupWitness::lookup_columns_at(start, lane, query)
    }
}

impl UniformRelation for BlockCpuRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-cpu/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [
            BLOCK_MEMORY_COLUMN_COUNT as u64,
            BLOCK_MEMORY_CONSTRAINT_COUNT as u64,
            CPU_BOUNDARY_AUX_COLUMN_COUNT as u64,
            CPU_LANE_AUX_COLUMN_COUNT as u64,
            PACKED_CPU_DERIVED_SCALAR_COUNT as u64,
            PACKED_CPU_SEMANTIC_AUX_COLUMN_COUNT as u64,
            PACKED_CPU_BUS_MATCH_COLUMN_COUNT as u64,
            BASIC_BLOCK_INSTRUCTION_BOUND as u64,
            PACKED_CPU_AUX_COLUMN_COUNT as u64,
            PACKED_CPU_BUS_MATCH_CONSTRAINT_COUNT as u64,
            PACKED_CPU_SHARED_BOUNDARY_CONSTRAINT_COUNT as u64,
            PACKED_CPU_LANE_CONSTRAINT_COUNT as u64,
            EXECUTION_LOOKUP_COLUMN_COUNT as u64,
            EXECUTION_LOOKUP_WELL_FORMED_CONSTRAINT_COUNT as u64,
            BLOCK_CPU_COLUMN_COUNT as u64,
            BLOCK_CPU_CONSTRAINT_COUNT as u64,
            BLOCK_CPU_MAX_DEGREE as u64,
            6,
        ] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_CPU_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_CPU_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_CPU_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_CPU_COLUMN_COUNT || constraints.len() != BLOCK_CPU_CONSTRAINT_COUNT {
            return Err(UniformError::Shape);
        }
        let (memory_constraints, cpu_constraints) =
            constraints.split_at_mut(BLOCK_MEMORY_CONSTRAINT_COUNT);
        BlockMemoryRelation.evaluate(
            row.get(..BLOCK_MEMORY_COLUMN_COUNT)
                .ok_or(UniformError::Shape)?,
            memory_constraints,
        )?;
        constrain_cpu(row, cpu_constraints)
    }
}

fn append_block(
    columns: &mut [Vec<u64>],
    encoder: &mut CpuSemanticAuxEncoder,
    block: &BasicBlock,
) -> Result<(), BlockCpuError> {
    if columns.len() != PACKED_CPU_AUX_COLUMN_COUNT {
        return Err(BlockCpuError::Layout);
    }
    let instruction_count = block.instruction_count();
    if instruction_count > BASIC_BLOCK_INSTRUCTION_BOUND
        || (instruction_count != 0 && block.row_count() != instruction_count)
    {
        return Err(BlockCpuError::Layout);
    }
    if instruction_count == 0 {
        for column in columns {
            column.push(0);
        }
        return Ok(());
    }
    let mut packed = [0_u64; PACKED_CPU_AUX_COLUMN_COUNT];
    let mut written = [false; PACKED_CPU_AUX_COLUMN_COUNT];
    let mut rows = block.rows();
    for lane in 0..BASIC_BLOCK_INSTRUCTION_BOUND {
        let values = match rows.next() {
            Some(row) if lane < instruction_count => {
                if row.effects().kind() != StepKind::Instruction {
                    return Err(BlockCpuError::Layout);
                }
                encoder.encode_instruction(row)?
            }
            None if lane >= instruction_count => encoder.encode_inactive(block.final_state())?,
            Some(_) | None => return Err(BlockCpuError::Layout),
        };
        write_packed_lane(&mut packed, &mut written, lane, values)?;
    }
    if rows.next().is_some() {
        return Err(BlockCpuError::Layout);
    }
    write_bus_matches(&mut packed, &mut written, block)?;
    if written.iter().any(|value| !value) {
        return Err(BlockCpuError::Layout);
    }
    for (column, value) in columns.iter_mut().zip(packed) {
        column.push(value);
    }
    Ok(())
}

fn write_bus_matches(
    packed: &mut [u64; PACKED_CPU_AUX_COLUMN_COUNT],
    written: &mut [bool; PACKED_CPU_AUX_COLUMN_COUNT],
    block: &BasicBlock,
) -> Result<(), BlockCpuError> {
    for (lane, lane_value) in block.lanes().iter().copied().enumerate() {
        let descriptor = lane_value.descriptor();
        for local_slot in 0..BASIC_BLOCK_BUS_EVENT_BOUND {
            let expected_shared = match descriptor {
                Some(value) if local_slot < value.bus_event_count() => Some(
                    value
                        .bus_event_start()
                        .checked_add(local_slot)
                        .ok_or(BlockCpuError::Layout)?,
                ),
                Some(_) | None => None,
            };
            for shared_slot in local_slot..BASIC_BLOCK_BUS_EVENT_BOUND {
                let target = packed_cpu_bus_match_offset(lane, local_slot, shared_slot)
                    .ok_or(BlockCpuError::Layout)?;
                *packed.get_mut(target).ok_or(BlockCpuError::Layout)? =
                    u64::from(expected_shared == Some(shared_slot));
                *written.get_mut(target).ok_or(BlockCpuError::Layout)? = true;
            }
        }
    }
    Ok(())
}

fn write_packed_lane(
    packed: &mut [u64; PACKED_CPU_AUX_COLUMN_COUNT],
    written: &mut [bool; PACKED_CPU_AUX_COLUMN_COUNT],
    lane: usize,
    values: &[u64],
) -> Result<(), BlockCpuError> {
    if lane >= BASIC_BLOCK_INSTRUCTION_BOUND || values.len() != CPU_SEMANTIC_AUX_COLUMN_COUNT {
        return Err(BlockCpuError::Layout);
    }
    for (source_offset, value) in values.iter().copied().enumerate() {
        let legacy_column =
            cpu_semantic_legacy_column(source_offset).ok_or(BlockCpuError::Layout)?;
        let Some(target) = packed_cpu_aux_offset(legacy_column, lane) else {
            if packed_cpu_derived_scalar(legacy_column).is_some()
                || is_omitted_cpu_lane_legacy_column(legacy_column)
            {
                continue;
            }
            return Err(BlockCpuError::Layout);
        };
        let target_value = packed.get_mut(target).ok_or(BlockCpuError::Layout)?;
        let target_written = written.get_mut(target).ok_or(BlockCpuError::Layout)?;
        // Invariant: lane i after-state and lane i + 1 before-state encode one boundary.
        if *target_written && *target_value != value {
            return Err(BlockCpuError::Layout);
        }
        *target_value = value;
        *target_written = true;
    }
    Ok(())
}

fn constrain_cpu(row: &[NativeField], constraints: &mut [NativeField]) -> Result<(), UniformError> {
    if constraints.len() != PACKED_CPU_ADDITIONAL_CONSTRAINT_COUNT {
        return Err(UniformError::Shape);
    }
    let (semantic_constraints, lookup_constraints) =
        constraints.split_at_mut(PACKED_CPU_SEMANTIC_CONSTRAINT_COUNT);
    let instruction_block = block_metadata::instruction_value(row)?;
    let canonical_auxiliary = NativeField::from_u64(1) - instruction_block;
    let (padding_constraints, remaining_constraints) =
        semantic_constraints.split_at_mut(PACKED_CPU_SEMANTIC_AUX_COLUMN_COUNT);
    for (offset, constraint) in padding_constraints.iter_mut().enumerate() {
        let value = row
            .get(
                BLOCK_MEMORY_COLUMN_COUNT
                    .checked_add(offset)
                    .ok_or(UniformError::Shape)?,
            )
            .copied()
            .ok_or(UniformError::Shape)?;
        *constraint = canonical_auxiliary * value;
    }
    let (bus_match_constraints, remaining_constraints) =
        remaining_constraints.split_at_mut(PACKED_CPU_BUS_MATCH_CONSTRAINT_COUNT);
    constrain_bus_matches(row, bus_match_constraints)?;
    let (boundary_constraints, lane_constraints) =
        remaining_constraints.split_at_mut(PACKED_CPU_SHARED_BOUNDARY_CONSTRAINT_COUNT);
    let mut boundary_start = 0_usize;
    for lane in 0..BASIC_BLOCK_INSTRUCTION_BOUND {
        let boundary_count = if lane == 0 {
            PACKED_CPU_LANE_RANGE_CONSTRAINT_COUNT
        } else {
            PACKED_CPU_BOUNDARY_CONSTRAINT_COUNT
        };
        let boundary_end = boundary_start
            .checked_add(boundary_count)
            .ok_or(UniformError::Shape)?;
        let boundary_output = boundary_constraints
            .get_mut(boundary_start..boundary_end)
            .ok_or(UniformError::Shape)?;
        let start = lane
            .checked_mul(PACKED_CPU_LANE_CONSTRAINT_COUNT)
            .ok_or(UniformError::Shape)?;
        let end = start
            .checked_add(PACKED_CPU_LANE_CONSTRAINT_COUNT)
            .ok_or(UniformError::Shape)?;
        let output = lane_constraints
            .get_mut(start..end)
            .ok_or(UniformError::Shape)?;
        let used = constrain_instruction_lane(row, lane, boundary_output, output)?;
        if used > PACKED_CPU_LANE_CONSTRAINT_COUNT {
            return Err(UniformError::Shape);
        }
        for constraint in boundary_output {
            *constraint *= instruction_block;
        }
        for constraint in output {
            *constraint *= instruction_block;
        }
        boundary_start = boundary_end;
    }
    if boundary_start != PACKED_CPU_SHARED_BOUNDARY_CONSTRAINT_COUNT {
        return Err(UniformError::Shape);
    }
    constrain_execution_lookup_well_formed(row, lookup_constraints)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BLOCK_ROUTING_COLUMN_COUNT, TRACE_AFTER_CPU_BYTE_BITS_START,
        TRACE_BEFORE_CPU_BYTE_BITS_START, TRACE_RESULT_BITS_START, TRACE_RESULT_VALUE,
        block_boundary::local_state_column,
        block_test_support::lookup_blocks,
        trace::{packed_cpu_aux_offset, packed_cpu_bus_match_offset},
        validate_uniform_witness,
    };

    #[test]
    fn evaluation_profile_identifies_cached_hot_paths() {
        let profile = BlockCpuRelation::evaluation_profile();
        assert_eq!(profile.lane_count, BASIC_BLOCK_INSTRUCTION_BOUND);
        assert_eq!(profile.local_bus_slot_count, BASIC_BLOCK_BUS_EVENT_BOUND);
        assert!(
            profile
                .hotspots
                .contains(&PackedCpuEvaluationHotspot::LocalBusProjection)
        );
        assert!(
            profile
                .cached_values
                .contains(&PackedCpuCachedValue::LocalBusTupleFields)
        );
        assert!(
            profile
                .cached_values
                .contains(&PackedCpuCachedValue::LocalBusBitPlanes)
        );
    }

    #[test]
    fn compact_cpu_relation_accepts_active_and_padding_rows()
    -> Result<(), Box<dyn std::error::Error>> {
        for program in [
            [0x04, 0x00, 0x00, 0x00],
            [0x06, 0x2a, 0x00, 0x00],
            [0xcb, 0x00, 0x00, 0x00],
            [0xc7, 0x00, 0x00, 0x00],
        ] {
            let blocks = lookup_blocks(&program, 1)?;
            let witness = BlockCpuWitness::from_blocks(&blocks)?;
            assert_cpu_row_satisfies(&witness, 0)?;
        }
        let blocks = lookup_blocks(&[0x04, 0x00, 0x00, 0x00], 1)?;
        let witness = BlockCpuWitness::from_blocks(&blocks)?;
        assert_cpu_row_satisfies(&witness, UNIFORM_ROW_COUNT - 1)
    }

    fn assert_cpu_row_satisfies(
        witness: &BlockCpuWitness,
        row_index: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let row = witness
            .columns()
            .iter()
            .map(|column| {
                column
                    .get(row_index)
                    .copied()
                    .map(NativeField::from_u64)
                    .ok_or(UniformError::Shape)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut constraints = vec![NativeField::from_u64(0); BLOCK_CPU_CONSTRAINT_COUNT];
        let mut memory_constraints = vec![NativeField::from_u64(0); BLOCK_MEMORY_CONSTRAINT_COUNT];
        let memory_result = BlockMemoryRelation.evaluate(
            row.get(..BLOCK_MEMORY_COLUMN_COUNT)
                .ok_or(UniformError::Shape)?,
            &mut memory_constraints,
        );
        assert!(memory_result.is_ok(), "memory prefix: {memory_result:?}");
        let cpu_result = BlockCpuRelation.evaluate(&row, &mut constraints);
        assert!(cpu_result.is_ok(), "CPU relation: {cpu_result:?}");
        let violated = constraints
            .iter()
            .position(|value| *value != NativeField::from_u64(0));
        assert_eq!(violated, None, "row {row_index}");
        Ok(())
    }

    #[test]
    fn representative_instruction_families_satisfy_packed_cpu_semantics()
    -> Result<(), Box<dyn std::error::Error>> {
        for program in [
            [0x04, 0x00, 0x00, 0x00],
            [0x06, 0x2a, 0x00, 0x00],
            [0x03, 0x00, 0x00, 0x00],
            [0x18, 0x00, 0x00, 0x00],
            [0xc5, 0x00, 0x00, 0x00],
            [0xcb, 0x00, 0x00, 0x00],
            [0x27, 0x00, 0x00, 0x00],
        ] {
            let blocks = lookup_blocks(&program, 1)?;
            let witness = BlockCpuWitness::from_blocks(&blocks)?;
            validate_uniform_witness(&BlockCpuRelation, witness.columns())?;
        }
        Ok(())
    }

    #[test]
    fn register_and_helper_mutations_are_rejected_only_by_cpu_layer()
    -> Result<(), Box<dyn std::error::Error>> {
        let blocks = lookup_blocks(&[0x04, 0x00, 0x00, 0x00], 1)?;
        let witness = BlockCpuWitness::from_blocks(&blocks)?;

        let mut register_mutation = witness.columns().to_vec();
        for boundary in 1..=BASIC_BLOCK_INSTRUCTION_BOUND {
            let after_b = BLOCK_ROUTING_COLUMN_COUNT
                .checked_add(local_state_column(boundary, 1).ok_or(UniformError::Shape)?)
                .ok_or(UniformError::Shape)?;
            *register_mutation
                .get_mut(after_b)
                .and_then(|column| column.first_mut())
                .ok_or(UniformError::Shape)? ^= 1;
        }
        let memory_prefix = register_mutation
            .get(..BLOCK_MEMORY_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        validate_uniform_witness(&BlockMemoryRelation, memory_prefix)?;
        assert!(validate_uniform_witness(&BlockCpuRelation, &register_mutation).is_err());

        let mut boundary_bit_mutation = witness.columns().to_vec();
        let lane_zero_after =
            packed_cpu_aux_offset(TRACE_AFTER_CPU_BYTE_BITS_START, 0).ok_or(UniformError::Shape)?;
        let lane_one_before = packed_cpu_aux_offset(TRACE_BEFORE_CPU_BYTE_BITS_START, 1)
            .ok_or(UniformError::Shape)?;
        assert_eq!(lane_zero_after, lane_one_before);
        let shared_b_bit = BLOCK_MEMORY_COLUMN_COUNT
            .checked_add(lane_zero_after)
            .ok_or(UniformError::Shape)?;
        *boundary_bit_mutation
            .get_mut(shared_b_bit)
            .and_then(|column| column.first_mut())
            .ok_or(UniformError::Shape)? ^= 1;
        let memory_prefix = boundary_bit_mutation
            .get(..BLOCK_MEMORY_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        validate_uniform_witness(&BlockMemoryRelation, memory_prefix)?;
        assert!(validate_uniform_witness(&BlockCpuRelation, &boundary_bit_mutation).is_err());

        let mut lookup_mutation = witness.columns().to_vec();
        assert!(packed_cpu_aux_offset(TRACE_RESULT_VALUE, 0).is_none());
        assert!(packed_cpu_aux_offset(TRACE_RESULT_BITS_START, 0).is_none());
        let result_bit = BlockCpuWitness::execution_lookup_columns(0, 0)?
            .output_bits()
            .first()
            .copied()
            .ok_or(UniformError::Shape)?;
        *lookup_mutation
            .get_mut(result_bit)
            .and_then(|column| column.first_mut())
            .ok_or(UniformError::Shape)? ^= 1;
        assert!(validate_uniform_witness(&BlockCpuRelation, &lookup_mutation).is_err());

        let mut bus_match_mutation = witness.columns().to_vec();
        let first_bus_match = BLOCK_MEMORY_COLUMN_COUNT
            .checked_add(packed_cpu_bus_match_offset(0, 0, 0).ok_or(UniformError::Shape)?)
            .ok_or(UniformError::Shape)?;
        *bus_match_mutation
            .get_mut(first_bus_match)
            .and_then(|column| column.first_mut())
            .ok_or(UniformError::Shape)? ^= 1;
        let memory_prefix = bus_match_mutation
            .get(..BLOCK_MEMORY_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        validate_uniform_witness(&BlockMemoryRelation, memory_prefix)?;
        assert!(validate_uniform_witness(&BlockCpuRelation, &bus_match_mutation).is_err());
        Ok(())
    }
}
