//! Compact single-row helper projection for packed instruction lanes.

use zksm83_core::{StepKind, VmState};
use zksm83_trace::{BASIC_BLOCK_BUS_EVENT_BOUND, BASIC_BLOCK_INSTRUCTION_BOUND, TraceRow};

use super::{
    ArithmeticWitness, NativeTraceError, TRACE_AFTER_CPU_BYTE_BITS_START,
    TRACE_AFTER_RAM_RTC_BITS_START, TRACE_BEFORE_CPU_BYTE_BITS_START,
    TRACE_BEFORE_ROM_BANK_BITS_START, TRACE_BUS_ADDRESS_BITS_START, TRACE_IMMEDIATE_HIGH,
    TRACE_IMMEDIATE_HIGH_BITS_START, TRACE_IMMEDIATE_LOW, TRACE_IMMEDIATE_LOW_BITS_START,
    TRACE_OPERAND_BITS_START, TRACE_OPERAND_VALUE, TRACE_POP_FLAGS_LOW_NIBBLE,
    TRACE_POP_FLAGS_LOW_NIBBLE_BITS_START, TRACE_RESULT_BITS_START, TRACE_RESULT_VALUE,
    TRACE_SEQUENTIAL_PC, TRACE_SEQUENTIAL_PC_BITS_START, append_arithmetic_witness,
    append_cpu_range_bits, append_empty_instruction_witness, append_instruction_witness,
    append_mapper_bits, append_operation_witness, daa, word,
};

const CPU_SEMANTIC_LOCAL_START: usize = TRACE_BEFORE_CPU_BYTE_BITS_START;
const CPU_SEMANTIC_LOCAL_END: usize = TRACE_BUS_ADDRESS_BITS_START;
const CPU_SEMANTIC_MAPPER_START: usize = TRACE_BEFORE_ROM_BANK_BITS_START;
const CPU_SEMANTIC_MAPPER_END: usize = TRACE_AFTER_RAM_RTC_BITS_START + 4;
const CPU_BYTE_STATE_BIT_COUNT: usize = 8 * 8;
const CPU_WORD_STATE_BIT_COUNT: usize = 16;
const CPU_BOUNDARY_STATE_BIT_COUNT: usize = CPU_BYTE_STATE_BIT_COUNT + CPU_WORD_STATE_BIT_COUNT * 2;
const CPU_BOUNDARY_MAPPER_BIT_COUNT: usize = 6 + 4;
const CPU_SHARED_BOUNDARY_COUNT: usize = BASIC_BLOCK_INSTRUCTION_BOUND + 1;
pub(crate) const PACKED_CPU_DERIVED_SCALAR_COUNT: usize = 5;
const PACKED_CPU_DERIVED_SCALARS: [(usize, usize, usize); PACKED_CPU_DERIVED_SCALAR_COUNT] = [
    (TRACE_OPERAND_VALUE, TRACE_OPERAND_BITS_START, 8),
    (TRACE_IMMEDIATE_LOW, TRACE_IMMEDIATE_LOW_BITS_START, 8),
    (TRACE_IMMEDIATE_HIGH, TRACE_IMMEDIATE_HIGH_BITS_START, 8),
    (TRACE_SEQUENTIAL_PC, TRACE_SEQUENTIAL_PC_BITS_START, 16),
    (
        TRACE_POP_FLAGS_LOW_NIBBLE,
        TRACE_POP_FLAGS_LOW_NIBBLE_BITS_START,
        4,
    ),
];
pub(crate) const CPU_SEMANTIC_AUX_COLUMN_COUNT: usize =
    CPU_SEMANTIC_LOCAL_END - CPU_SEMANTIC_LOCAL_START + CPU_SEMANTIC_MAPPER_END
        - CPU_SEMANTIC_MAPPER_START;
pub(crate) const CPU_BOUNDARY_AUX_COLUMN_COUNT: usize =
    CPU_BOUNDARY_STATE_BIT_COUNT + CPU_BOUNDARY_MAPPER_BIT_COUNT;
pub(crate) const CPU_LANE_AUX_COLUMN_COUNT: usize = 54;
const CPU_LANE_OMITTED_COLUMN_COUNT: usize = 29;
pub(crate) const PACKED_CPU_SEMANTIC_AUX_COLUMN_COUNT: usize = CPU_SHARED_BOUNDARY_COUNT
    * CPU_BOUNDARY_AUX_COLUMN_COUNT
    + BASIC_BLOCK_INSTRUCTION_BOUND * CPU_LANE_AUX_COLUMN_COUNT;
const PACKED_CPU_BUS_MATCH_COLUMNS_PER_LANE: usize =
    BASIC_BLOCK_BUS_EVENT_BOUND * (BASIC_BLOCK_BUS_EVENT_BOUND + 1) / 2;
pub(crate) const PACKED_CPU_BUS_MATCH_COLUMN_COUNT: usize =
    BASIC_BLOCK_INSTRUCTION_BOUND * PACKED_CPU_BUS_MATCH_COLUMNS_PER_LANE;
pub(crate) const PACKED_CPU_AUX_COLUMN_COUNT: usize =
    PACKED_CPU_SEMANTIC_AUX_COLUMN_COUNT + PACKED_CPU_BUS_MATCH_COLUMN_COUNT;

const _: () = assert!(CPU_SEMANTIC_AUX_COLUMN_COUNT == 300);
const _: () = assert!(CPU_BOUNDARY_AUX_COLUMN_COUNT == 106);
const _: () = assert!(
    CPU_LANE_AUX_COLUMN_COUNT + CPU_LANE_OMITTED_COLUMN_COUNT + PACKED_CPU_DERIVED_SCALAR_COUNT
        == CPU_SEMANTIC_LOCAL_END - TRACE_OPERAND_VALUE
);
const _: () = assert!(PACKED_CPU_SEMANTIC_AUX_COLUMN_COUNT == 746);
const _: () = assert!(PACKED_CPU_BUS_MATCH_COLUMNS_PER_LANE == 15);
const _: () = assert!(PACKED_CPU_BUS_MATCH_COLUMN_COUNT == 60);
const _: () = assert!(PACKED_CPU_AUX_COLUMN_COUNT == 806);

/// Reusable single-row encoder for the compact packed-lane CPU helper plane.
pub(crate) struct CpuSemanticAuxEncoder {
    scratch: Vec<Vec<u64>>,
    projected: [u64; CPU_SEMANTIC_AUX_COLUMN_COUNT],
}

impl CpuSemanticAuxEncoder {
    pub(crate) fn new() -> Self {
        Self {
            scratch: vec![Vec::new(); CPU_SEMANTIC_MAPPER_END],
            projected: [0; CPU_SEMANTIC_AUX_COLUMN_COUNT],
        }
    }

    pub(crate) fn encode_instruction(
        &mut self,
        row: &TraceRow,
    ) -> Result<&[u64; CPU_SEMANTIC_AUX_COLUMN_COUNT], NativeTraceError> {
        if row.effects().kind() != StepKind::Instruction {
            return Err(NativeTraceError::Layout);
        }
        self.reset();
        append_cpu_range_bits(&mut self.scratch, row.before(), row.after())?;
        append_mapper_bits(&mut self.scratch, row.before(), row.after())?;
        append_operation_witness(&mut self.scratch, row)?;
        append_instruction_witness(&mut self.scratch, row)?;
        word::append_word_witness(&mut self.scratch, row)?;
        daa::append_daa_witness(&mut self.scratch, row)?;
        self.project()
    }

    pub(crate) fn encode_inactive(
        &mut self,
        state: VmState,
    ) -> Result<&[u64; CPU_SEMANTIC_AUX_COLUMN_COUNT], NativeTraceError> {
        self.reset();
        append_cpu_range_bits(&mut self.scratch, state, state)?;
        append_mapper_bits(&mut self.scratch, state, state)?;
        append_arithmetic_witness(&mut self.scratch, ArithmeticWitness::default())?;
        append_empty_instruction_witness(&mut self.scratch)?;
        word::append_empty_word_witness(&mut self.scratch)?;
        daa::append_empty_daa_witness(&mut self.scratch)?;
        self.project()
    }

    fn reset(&mut self) {
        for index in CPU_SEMANTIC_LOCAL_START..CPU_SEMANTIC_LOCAL_END {
            if let Some(column) = self.scratch.get_mut(index) {
                column.clear();
            }
        }
        for index in CPU_SEMANTIC_MAPPER_START..CPU_SEMANTIC_MAPPER_END {
            if let Some(column) = self.scratch.get_mut(index) {
                column.clear();
            }
        }
    }

    fn project(&mut self) -> Result<&[u64; CPU_SEMANTIC_AUX_COLUMN_COUNT], NativeTraceError> {
        let mut target = 0_usize;
        for index in CPU_SEMANTIC_LOCAL_START..CPU_SEMANTIC_LOCAL_END {
            let value = single_value(&self.scratch, index)?;
            *self
                .projected
                .get_mut(target)
                .ok_or(NativeTraceError::Layout)? = value;
            target = target.checked_add(1).ok_or(NativeTraceError::Layout)?;
        }
        for index in CPU_SEMANTIC_MAPPER_START..CPU_SEMANTIC_MAPPER_END {
            let value = single_value(&self.scratch, index)?;
            *self
                .projected
                .get_mut(target)
                .ok_or(NativeTraceError::Layout)? = value;
            target = target.checked_add(1).ok_or(NativeTraceError::Layout)?;
        }
        if target != CPU_SEMANTIC_AUX_COLUMN_COUNT {
            return Err(NativeTraceError::Layout);
        }
        Ok(&self.projected)
    }
}

pub(crate) fn cpu_semantic_legacy_column(offset: usize) -> Option<usize> {
    let local_count = CPU_SEMANTIC_LOCAL_END.checked_sub(CPU_SEMANTIC_LOCAL_START)?;
    if offset < local_count {
        return CPU_SEMANTIC_LOCAL_START.checked_add(offset);
    }
    offset
        .checked_sub(local_count)
        .filter(|mapper_offset| {
            *mapper_offset < CPU_SEMANTIC_MAPPER_END - CPU_SEMANTIC_MAPPER_START
        })
        .and_then(|mapper_offset| CPU_SEMANTIC_MAPPER_START.checked_add(mapper_offset))
}

pub(crate) fn packed_cpu_aux_offset(legacy_column: usize, lane: usize) -> Option<usize> {
    if lane >= BASIC_BLOCK_INSTRUCTION_BOUND {
        return None;
    }
    let after_boundary = lane.checked_add(1)?;
    let mapped = packed_boundary_aux_offset(
        legacy_column,
        TRACE_BEFORE_CPU_BYTE_BITS_START,
        CPU_BYTE_STATE_BIT_COUNT,
        lane,
        0,
    )
    .or_else(|| {
        packed_boundary_aux_offset(
            legacy_column,
            TRACE_AFTER_CPU_BYTE_BITS_START,
            CPU_BYTE_STATE_BIT_COUNT,
            after_boundary,
            0,
        )
    })
    .or_else(|| packed_pc_aux_offset(legacy_column, lane, after_boundary))
    .or_else(|| packed_sp_aux_offset(legacy_column, lane, after_boundary))
    .or_else(|| packed_mapper_aux_offset(legacy_column, lane, after_boundary));
    if mapped.is_some() {
        return mapped;
    }
    if packed_cpu_derived_scalar(legacy_column).is_some() {
        return None;
    }
    if let Some(lane_column) = packed_lane_aux_index(legacy_column) {
        return CPU_SHARED_BOUNDARY_COUNT
            .checked_mul(CPU_BOUNDARY_AUX_COLUMN_COUNT)
            .and_then(|offset| {
                lane.checked_mul(CPU_LANE_AUX_COLUMN_COUNT)
                    .and_then(|lane_offset| offset.checked_add(lane_offset))
            })
            .and_then(|offset| offset.checked_add(lane_column));
    }
    None
}

fn packed_lane_aux_index(legacy_column: usize) -> Option<usize> {
    let ranged = |start: usize, width: usize, packed_start: usize| {
        legacy_column
            .checked_sub(start)
            .filter(|offset| *offset < width)
            .and_then(|offset| packed_start.checked_add(offset))
    };
    ranged(TRACE_OPERAND_BITS_START, 8, 0)
        .or_else(|| ranged(TRACE_IMMEDIATE_LOW_BITS_START, 8, 8))
        .or_else(|| ranged(TRACE_IMMEDIATE_HIGH_BITS_START, 8, 16))
        .or_else(|| ranged(TRACE_SEQUENTIAL_PC_BITS_START, 16, 24))
        .or_else(|| ranged(super::TRACE_PC_WRAP, 5, 40))
        .or_else(|| ranged(super::TRACE_STACK_WRAP, 2, 45))
        .or_else(|| ranged(TRACE_POP_FLAGS_LOW_NIBBLE_BITS_START, 4, 47))
        .or_else(|| ranged(super::TRACE_ADDRESS_WRAP, 3, 51))
}

pub(crate) fn is_omitted_cpu_lane_legacy_column(legacy_column: usize) -> bool {
    legacy_column == TRACE_RESULT_VALUE
        || (TRACE_RESULT_BITS_START..TRACE_IMMEDIATE_LOW).contains(&legacy_column)
        || (super::TRACE_WORD_CARRY..=super::TRACE_SIGNED_SP_OVERFLOW).contains(&legacy_column)
        || (super::TRACE_DAA_LOW_GT_NINE..=super::TRACE_DAA_WRAP).contains(&legacy_column)
}

pub(crate) fn packed_cpu_bus_match_offset(
    lane: usize,
    local_slot: usize,
    shared_slot: usize,
) -> Option<usize> {
    if lane >= BASIC_BLOCK_INSTRUCTION_BOUND
        || local_slot >= BASIC_BLOCK_BUS_EVENT_BOUND
        || shared_slot < local_slot
        || shared_slot >= BASIC_BLOCK_BUS_EVENT_BOUND
    {
        return None;
    }
    let preceding = local_slot
        .checked_mul(BASIC_BLOCK_BUS_EVENT_BOUND)?
        .checked_sub(local_slot.checked_mul(local_slot.saturating_sub(1))? / 2)?;
    PACKED_CPU_SEMANTIC_AUX_COLUMN_COUNT
        .checked_add(lane.checked_mul(PACKED_CPU_BUS_MATCH_COLUMNS_PER_LANE)?)
        .and_then(|offset| offset.checked_add(preceding))
        .and_then(|offset| offset.checked_add(shared_slot - local_slot))
}

fn packed_pc_aux_offset(
    legacy_column: usize,
    before_boundary: usize,
    after_boundary: usize,
) -> Option<usize> {
    packed_boundary_aux_offset(
        legacy_column,
        super::TRACE_BEFORE_PC_BITS_START,
        CPU_WORD_STATE_BIT_COUNT,
        before_boundary,
        CPU_BYTE_STATE_BIT_COUNT,
    )
    .or_else(|| {
        packed_boundary_aux_offset(
            legacy_column,
            super::TRACE_AFTER_PC_BITS_START,
            CPU_WORD_STATE_BIT_COUNT,
            after_boundary,
            CPU_BYTE_STATE_BIT_COUNT,
        )
    })
}

fn packed_sp_aux_offset(
    legacy_column: usize,
    before_boundary: usize,
    after_boundary: usize,
) -> Option<usize> {
    let offset = CPU_BYTE_STATE_BIT_COUNT + CPU_WORD_STATE_BIT_COUNT;
    packed_boundary_aux_offset(
        legacy_column,
        super::TRACE_BEFORE_SP_BITS_START,
        CPU_WORD_STATE_BIT_COUNT,
        before_boundary,
        offset,
    )
    .or_else(|| {
        packed_boundary_aux_offset(
            legacy_column,
            super::TRACE_AFTER_SP_BITS_START,
            CPU_WORD_STATE_BIT_COUNT,
            after_boundary,
            offset,
        )
    })
}

fn packed_mapper_aux_offset(
    legacy_column: usize,
    before_boundary: usize,
    after_boundary: usize,
) -> Option<usize> {
    packed_boundary_aux_offset(
        legacy_column,
        TRACE_BEFORE_ROM_BANK_BITS_START,
        6,
        before_boundary,
        CPU_BOUNDARY_STATE_BIT_COUNT,
    )
    .or_else(|| {
        packed_boundary_aux_offset(
            legacy_column,
            super::TRACE_AFTER_ROM_BANK_BITS_START,
            6,
            after_boundary,
            CPU_BOUNDARY_STATE_BIT_COUNT,
        )
    })
    .or_else(|| {
        packed_boundary_aux_offset(
            legacy_column,
            super::TRACE_BEFORE_RAM_RTC_BITS_START,
            4,
            before_boundary,
            CPU_BOUNDARY_STATE_BIT_COUNT + 6,
        )
    })
    .or_else(|| {
        packed_boundary_aux_offset(
            legacy_column,
            TRACE_AFTER_RAM_RTC_BITS_START,
            4,
            after_boundary,
            CPU_BOUNDARY_STATE_BIT_COUNT + 6,
        )
    })
}

fn packed_boundary_aux_offset(
    legacy_column: usize,
    start: usize,
    width: usize,
    boundary: usize,
    boundary_offset: usize,
) -> Option<usize> {
    let relative = legacy_column.checked_sub(start)?;
    if relative >= width {
        return None;
    }
    boundary
        .checked_mul(CPU_BOUNDARY_AUX_COLUMN_COUNT)
        .and_then(|offset| offset.checked_add(boundary_offset))
        .and_then(|offset| offset.checked_add(relative))
}

pub(crate) fn packed_cpu_derived_scalar(legacy_column: usize) -> Option<(usize, usize, usize)> {
    PACKED_CPU_DERIVED_SCALARS
        .into_iter()
        .enumerate()
        .find_map(|(index, (scalar, bits, width))| {
            (scalar == legacy_column).then_some((index, bits, width))
        })
}

pub(crate) fn packed_cpu_derived_scalar_at(index: usize) -> Option<(usize, usize, usize)> {
    PACKED_CPU_DERIVED_SCALARS.get(index).copied()
}

fn single_value(columns: &[Vec<u64>], index: usize) -> Result<u64, NativeTraceError> {
    let values = columns.get(index).ok_or(NativeTraceError::Layout)?;
    if values.len() != 1 {
        return Err(NativeTraceError::Layout);
    }
    values.first().copied().ok_or(NativeTraceError::Layout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_lane_layout_is_a_total_disjoint_partition() {
        let mut packed = Vec::new();
        let mut derived = 0_usize;
        let mut omitted = 0_usize;
        for legacy_column in TRACE_OPERAND_VALUE..CPU_SEMANTIC_LOCAL_END {
            let packed_column = packed_lane_aux_index(legacy_column);
            let is_derived = packed_cpu_derived_scalar(legacy_column).is_some();
            let is_omitted = is_omitted_cpu_lane_legacy_column(legacy_column);
            assert_eq!(
                usize::from(packed_column.is_some())
                    + usize::from(is_derived)
                    + usize::from(is_omitted),
                1
            );
            if let Some(column) = packed_column {
                packed.push(column);
            }
            derived += usize::from(is_derived);
            omitted += usize::from(is_omitted);
        }
        assert_eq!(packed, (0..CPU_LANE_AUX_COLUMN_COUNT).collect::<Vec<_>>());
        assert_eq!(derived, PACKED_CPU_DERIVED_SCALAR_COUNT);
        assert_eq!(omitted, CPU_LANE_OMITTED_COLUMN_COUNT);
    }
}
