use akita_pcs::Ring;

use crate::{
    BLOCK_CPU_COLUMN_COUNT, BLOCK_FRONTEND_COLUMN_COUNT, BLOCK_ISA_CONTROL_COLUMN_COUNT,
    BlockCpuWitness, ConstraintOutput, NativeField, TRACE_MEMORY_TIMESTAMP_BITS,
    UNIFORM_NUM_VARIABLES, UNIFORM_ROW_COUNT, UniformError, UniformRelation,
    block_bus::{
        slot_before_column, slot_before_value, slot_physical_address_column,
        slot_physical_address_value, slot_value_column, slot_value_value,
    },
    block_memory::{
        BLOCK_MEMORY_ROW_BITS_START, memory_predecessor_bit_column, memory_predecessor_value,
        memory_row_index_value, memory_selector_column, memory_selector_value,
        memory_write_selector_column, memory_write_selector_value,
    },
    field_batch::{FieldBatchError, SelectedDenominator, selected_inverse_columns},
};

use super::{MemoryChallenges, MutableMemoryError, field_bytes, join_limbs, split_field};

const BUS_SLOTS: usize = 5;
const INVERSE_ENTRY_COUNT: usize = BUS_SLOTS * 2;
const INVERSE_COLUMN_COUNT: usize = BUS_SLOTS * 4;
const CONSTRAINT_COUNT: usize = BUS_SLOTS * 2;

pub(super) struct BlockMemoryEventRelation {
    challenges: MemoryChallenges,
    alpha_squared: NativeField,
}

impl BlockMemoryEventRelation {
    pub(super) fn new(challenges: MemoryChallenges) -> Self {
        Self {
            challenges,
            alpha_squared: challenges.alpha * challenges.alpha,
        }
    }
}

impl UniformRelation for BlockMemoryEventRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-memory-event-inverses/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut bytes = field_bytes(self.challenges.alpha);
        bytes.extend_from_slice(&field_bytes(self.challenges.beta));
        for value in [
            BLOCK_CPU_COLUMN_COUNT as u64,
            BUS_SLOTS as u64,
            TRACE_MEMORY_TIMESTAMP_BITS as u64,
            7,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    fn column_count(&self) -> usize {
        BLOCK_CPU_COLUMN_COUNT + INVERSE_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        3
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != self.column_count() || constraints.len() != CONSTRAINT_COUNT {
            return Err(UniformError::Shape);
        }
        let bus = row
            .get(BLOCK_ISA_CONTROL_COLUMN_COUNT..BLOCK_FRONTEND_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let row_index = memory_row_index_value(row)?;
        for slot in 0..BUS_SLOTS {
            let selected = memory_selector_value(row, slot)?;
            let write = memory_write_selector_value(row, slot)?;
            let address = slot_physical_address_value(bus, slot)?;
            let before = slot_before_value(bus, slot)?;
            let after = slot_value_value(bus, slot)?;
            let predecessor = memory_predecessor_value(row, slot)?;
            let current = row_index * NativeField::from_u64(BUS_SLOTS as u64)
                + NativeField::from_u64(
                    u64::try_from(slot)
                        .map_err(|_| UniformError::Shape)?
                        .checked_add(1)
                        .ok_or(UniformError::Shape)?,
                );
            let input_value = write * before + (selected - write) * after;
            let input =
                address + self.challenges.alpha * input_value + self.alpha_squared * predecessor;
            let output = address + self.challenges.alpha * after + self.alpha_squared * current;
            let input_inverse = inverse_value(row, slot)?;
            let output_inverse = inverse_value(row, BUS_SLOTS * 2 + slot)?;
            *constraints.get_mut(slot).ok_or(UniformError::Shape)? =
                (self.challenges.beta - input) * input_inverse - selected;
            *constraints
                .get_mut(BUS_SLOTS + slot)
                .ok_or(UniformError::Shape)? =
                (self.challenges.beta - output) * output_inverse - selected;
        }
        Ok(())
    }
}

pub(super) fn inverse_columns(
    trace: &BlockCpuWitness,
    challenges: MemoryChallenges,
) -> Result<Vec<Vec<u64>>, MutableMemoryError> {
    if trace.columns().len() != BLOCK_CPU_COLUMN_COUNT {
        return Err(MutableMemoryError::Shape);
    }
    let alpha_squared = challenges.alpha * challenges.alpha;
    selected_inverse_columns(
        UNIFORM_ROW_COUNT,
        |row| Ok((inverse_row(trace, row, challenges, alpha_squared)?, ())),
        |inverses, ()| inverse_limb_row(inverses),
        map_batch_error,
    )
}

fn inverse_row(
    trace: &BlockCpuWitness,
    row: usize,
    challenges: MemoryChallenges,
    alpha_squared: NativeField,
) -> Result<[SelectedDenominator; INVERSE_ENTRY_COUNT], MutableMemoryError> {
    let row_index = packed_trace_bits(
        trace,
        BLOCK_MEMORY_ROW_BITS_START,
        UNIFORM_NUM_VARIABLES,
        row,
    )?;
    let zero = NativeField::from_u64(0);
    let mut entries = [SelectedDenominator::new(zero, zero); INVERSE_ENTRY_COUNT];
    for slot in 0..BUS_SLOTS {
        let selected = trace_value(trace, memory_selector_column(slot)?, row)?;
        let write = trace_value(trace, memory_write_selector_column(slot)?, row)?;
        let address = trace_value(
            trace,
            packed_bus_column(slot_physical_address_column(slot)?)?,
            row,
        )?;
        let before = trace_value(trace, packed_bus_column(slot_before_column(slot)?)?, row)?;
        let after = trace_value(trace, packed_bus_column(slot_value_column(slot)?)?, row)?;
        let predecessor = packed_predecessor(trace, slot, row)?;
        let slot_number = u64::try_from(slot).map_err(|_| MutableMemoryError::Shape)?;
        let current = row_index
            .checked_mul(BUS_SLOTS as u64)
            .and_then(|value| value.checked_add(slot_number + 1))
            .ok_or(MutableMemoryError::Shape)?;
        let input_value = write
            .checked_mul(before)
            .and_then(|value| {
                selected
                    .checked_sub(write)
                    .and_then(|read| read.checked_mul(after))
                    .and_then(|read_value| value.checked_add(read_value))
            })
            .ok_or(MutableMemoryError::Shape)?;
        let input = NativeField::from_u64(address)
            + challenges.alpha * NativeField::from_u64(input_value)
            + alpha_squared * NativeField::from_u64(predecessor);
        let output = NativeField::from_u64(address)
            + challenges.alpha * NativeField::from_u64(after)
            + alpha_squared * NativeField::from_u64(current);
        let scale = NativeField::from_u64(selected);
        *entries.get_mut(slot).ok_or(MutableMemoryError::Shape)? =
            SelectedDenominator::new(scale, challenges.beta - input);
        *entries
            .get_mut(BUS_SLOTS + slot)
            .ok_or(MutableMemoryError::Shape)? =
            SelectedDenominator::new(scale, challenges.beta - output);
    }
    Ok(entries)
}

fn inverse_limb_row(
    inverses: [SelectedDenominator; INVERSE_ENTRY_COUNT],
) -> Result<[u64; INVERSE_COLUMN_COUNT], MutableMemoryError> {
    let mut limbs = [0_u64; INVERSE_COLUMN_COUNT];
    for (entry, inverse) in inverses.into_iter().enumerate() {
        let [low, high] = split_field(inverse.value())?;
        let low_column = if entry < BUS_SLOTS {
            entry
        } else {
            entry
                .checked_add(BUS_SLOTS)
                .ok_or(MutableMemoryError::Shape)?
        };
        *limbs.get_mut(low_column).ok_or(MutableMemoryError::Shape)? = low;
        *limbs
            .get_mut(low_column + BUS_SLOTS)
            .ok_or(MutableMemoryError::Shape)? = high;
    }
    Ok(limbs)
}

fn map_batch_error(error: FieldBatchError) -> MutableMemoryError {
    match error {
        FieldBatchError::Shape => MutableMemoryError::Shape,
        FieldBatchError::ZeroDenominator => MutableMemoryError::ZeroDenominator,
    }
}

fn packed_bus_column(relative: usize) -> Result<usize, MutableMemoryError> {
    BLOCK_ISA_CONTROL_COLUMN_COUNT
        .checked_add(relative)
        .ok_or(MutableMemoryError::Shape)
}

fn packed_predecessor(
    trace: &BlockCpuWitness,
    slot: usize,
    row: usize,
) -> Result<u64, MutableMemoryError> {
    let mut packed = 0_u64;
    for bit in 0..TRACE_MEMORY_TIMESTAMP_BITS {
        packed |= trace_value(trace, memory_predecessor_bit_column(slot, bit)?, row)? << bit;
    }
    Ok(packed)
}

fn packed_trace_bits(
    trace: &BlockCpuWitness,
    start: usize,
    width: usize,
    row: usize,
) -> Result<u64, MutableMemoryError> {
    let mut packed = 0_u64;
    for bit in 0..width {
        packed |= trace_value(
            trace,
            start.checked_add(bit).ok_or(MutableMemoryError::Shape)?,
            row,
        )? << bit;
    }
    Ok(packed)
}

fn trace_value(
    trace: &BlockCpuWitness,
    column: usize,
    row: usize,
) -> Result<u64, MutableMemoryError> {
    trace
        .columns()
        .get(column)
        .and_then(|values| values.get(row))
        .copied()
        .ok_or(MutableMemoryError::Shape)
}

fn inverse_value(row: &[NativeField], low_column: usize) -> Result<NativeField, UniformError> {
    let start = BLOCK_CPU_COLUMN_COUNT
        .checked_add(low_column)
        .ok_or(UniformError::Shape)?;
    Ok(join_limbs(
        row.get(start).copied().ok_or(UniformError::Shape)?,
        row.get(start + BUS_SLOTS)
            .copied()
            .ok_or(UniformError::Shape)?,
    ))
}
