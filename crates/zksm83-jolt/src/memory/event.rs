use akita_pcs::Ring;

use crate::{
    NATIVE_TRACE_COLUMN_COUNT, NativeField, NativeTraceWitness, ROM_ADDRESS_BIT_COUNT,
    TRACE_BUS_PHYSICAL_BITS_START, TRACE_BUS_SLOTS, TRACE_MEMORY_AFTER_OFFSET,
    TRACE_MEMORY_BEFORE_OFFSET, TRACE_MEMORY_PREDECESSOR_BITS_OFFSET, TRACE_MEMORY_SELECTOR_OFFSET,
    TRACE_MEMORY_SLOT_WIDTH, TRACE_MEMORY_START, TRACE_MEMORY_TIMESTAMP_BITS, TRACE_ROW_BIT_COUNT,
    TRACE_ROW_BITS_START, UNIFORM_ROW_COUNT, UniformError, UniformRelation,
};

use super::{MemoryChallenges, MutableMemoryError, field_bytes, inverse, join_limbs, split_field};

const INVERSE_COLUMN_COUNT: usize = TRACE_BUS_SLOTS * 4;

pub(super) struct MemoryEventRelation {
    challenges: MemoryChallenges,
}

impl MemoryEventRelation {
    pub(super) const fn new(challenges: MemoryChallenges) -> Self {
        Self { challenges }
    }
}

impl UniformRelation for MemoryEventRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-memory-event-inverses/v1"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut bytes = field_bytes(self.challenges.alpha);
        bytes.extend_from_slice(&field_bytes(self.challenges.beta));
        bytes.extend_from_slice(&(NATIVE_TRACE_COLUMN_COUNT as u64).to_le_bytes());
        bytes
    }

    fn column_count(&self) -> usize {
        NATIVE_TRACE_COLUMN_COUNT + INVERSE_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        INVERSE_COLUMN_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        2
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != self.column_count() || constraints.len() != self.constraint_count() {
            return Err(UniformError::Shape);
        }
        let row_index = packed(row, TRACE_ROW_BITS_START, TRACE_ROW_BIT_COUNT)?;
        let alpha_squared = self.challenges.alpha * self.challenges.alpha;
        for slot in 0..TRACE_BUS_SLOTS {
            let start = memory_slot_start(slot)?;
            let selector = value(row, start + TRACE_MEMORY_SELECTOR_OFFSET)?;
            let address = packed(
                row,
                TRACE_BUS_PHYSICAL_BITS_START + slot * ROM_ADDRESS_BIT_COUNT,
                ROM_ADDRESS_BIT_COUNT,
            )?;
            let predecessor = packed(
                row,
                start + TRACE_MEMORY_PREDECESSOR_BITS_OFFSET,
                TRACE_MEMORY_TIMESTAMP_BITS,
            )?;
            let slot_number = u64::try_from(slot).map_err(|_| UniformError::Shape)?;
            let current = row_index * NativeField::from_u64(TRACE_BUS_SLOTS as u64)
                + NativeField::from_u64(slot_number + 1);
            let input = address
                + self.challenges.alpha * value(row, start + TRACE_MEMORY_BEFORE_OFFSET)?
                + alpha_squared * predecessor;
            let output = address
                + self.challenges.alpha * value(row, start + TRACE_MEMORY_AFTER_OFFSET)?
                + alpha_squared * current;
            let input_inverse = join_limbs(
                value(row, NATIVE_TRACE_COLUMN_COUNT + slot)?,
                value(row, NATIVE_TRACE_COLUMN_COUNT + TRACE_BUS_SLOTS + slot)?,
            );
            let output_inverse = join_limbs(
                value(row, NATIVE_TRACE_COLUMN_COUNT + TRACE_BUS_SLOTS * 2 + slot)?,
                value(row, NATIVE_TRACE_COLUMN_COUNT + TRACE_BUS_SLOTS * 3 + slot)?,
            );
            *constraints.get_mut(slot).ok_or(UniformError::Shape)? =
                (self.challenges.beta - input) * input_inverse - selector;
            *constraints
                .get_mut(TRACE_BUS_SLOTS + slot)
                .ok_or(UniformError::Shape)? =
                (self.challenges.beta - output) * output_inverse - selector;
        }
        Ok(())
    }
}

pub(super) fn inverse_columns(
    trace: &NativeTraceWitness,
    challenges: MemoryChallenges,
) -> Result<Vec<Vec<u64>>, MutableMemoryError> {
    if trace.columns().len() != NATIVE_TRACE_COLUMN_COUNT {
        return Err(MutableMemoryError::Shape);
    }
    let mut columns = (0..INVERSE_COLUMN_COUNT)
        .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
        .collect::<Vec<_>>();
    let alpha_squared = challenges.alpha * challenges.alpha;
    for row in 0..UNIFORM_ROW_COUNT {
        for slot in 0..TRACE_BUS_SLOTS {
            let start = memory_slot_start(slot).map_err(|_| MutableMemoryError::Shape)?;
            let selector = trace_value(trace, start + TRACE_MEMORY_SELECTOR_OFFSET, row)?;
            let address = trace_packed(
                trace,
                TRACE_BUS_PHYSICAL_BITS_START + slot * ROM_ADDRESS_BIT_COUNT,
                ROM_ADDRESS_BIT_COUNT,
                row,
            )?;
            let predecessor = trace_packed(
                trace,
                start + TRACE_MEMORY_PREDECESSOR_BITS_OFFSET,
                TRACE_MEMORY_TIMESTAMP_BITS,
                row,
            )?;
            let current = row
                .checked_mul(TRACE_BUS_SLOTS)
                .and_then(|value| value.checked_add(slot + 1))
                .ok_or(MutableMemoryError::Shape)?;
            let input = NativeField::from_u64(address)
                + challenges.alpha
                    * NativeField::from_u64(trace_value(
                        trace,
                        start + TRACE_MEMORY_BEFORE_OFFSET,
                        row,
                    )?)
                + alpha_squared * NativeField::from_u64(predecessor);
            let output = NativeField::from_u64(address)
                + challenges.alpha
                    * NativeField::from_u64(trace_value(
                        trace,
                        start + TRACE_MEMORY_AFTER_OFFSET,
                        row,
                    )?)
                + alpha_squared
                    * NativeField::from_u64(
                        u64::try_from(current).map_err(|_| MutableMemoryError::Shape)?,
                    );
            let selected = NativeField::from_u64(selector);
            let input_inverse = if selector == 0 {
                NativeField::from_u64(0)
            } else {
                selected * inverse(challenges.beta - input)?
            };
            let output_inverse = if selector == 0 {
                NativeField::from_u64(0)
            } else {
                selected * inverse(challenges.beta - output)?
            };
            let [input_low, input_high] = split_field(input_inverse)?;
            let [output_low, output_high] = split_field(output_inverse)?;
            for (column, limb) in [
                (slot, input_low),
                (TRACE_BUS_SLOTS + slot, input_high),
                (TRACE_BUS_SLOTS * 2 + slot, output_low),
                (TRACE_BUS_SLOTS * 3 + slot, output_high),
            ] {
                columns
                    .get_mut(column)
                    .ok_or(MutableMemoryError::Shape)?
                    .push(limb);
            }
        }
    }
    Ok(columns)
}

fn trace_value(
    trace: &NativeTraceWitness,
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

fn trace_packed(
    trace: &NativeTraceWitness,
    start: usize,
    width: usize,
    row: usize,
) -> Result<u64, MutableMemoryError> {
    let mut value = 0_u64;
    for bit in 0..width {
        value |= trace_value(trace, start + bit, row)? << bit;
    }
    Ok(value)
}

fn packed(row: &[NativeField], start: usize, width: usize) -> Result<NativeField, UniformError> {
    let mut packed_value = NativeField::from_u64(0);
    let mut power = NativeField::from_u64(1);
    for bit in 0..width {
        packed_value += power * value(row, start + bit)?;
        power += power;
    }
    Ok(packed_value)
}

fn value(row: &[NativeField], index: usize) -> Result<NativeField, UniformError> {
    row.get(index).copied().ok_or(UniformError::Shape)
}

fn memory_slot_start(slot: usize) -> Result<usize, UniformError> {
    TRACE_MEMORY_START
        .checked_add(
            slot.checked_mul(TRACE_MEMORY_SLOT_WIDTH)
                .ok_or(UniformError::Shape)?,
        )
        .ok_or(UniformError::Shape)
}
