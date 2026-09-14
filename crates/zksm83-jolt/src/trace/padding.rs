use zksm83_core::VmState;

use crate::{IsaTableRow, UNIFORM_ROW_COUNT};

use super::{NativeTraceError, TRACE_ROW_BIT_COUNT, TRACE_ROW_BITS_START, encode_padding_row};

pub(super) fn append_rows(
    columns: &mut [Vec<u64>],
    final_state: VmState,
    active_row_count: usize,
    table: &[IsaTableRow],
) -> Result<(), NativeTraceError> {
    if active_row_count == UNIFORM_ROW_COUNT {
        return Ok(());
    }
    encode_padding_row(columns, final_state, active_row_count, table)?;
    let remaining_start = active_row_count
        .checked_add(1)
        .ok_or(NativeTraceError::Layout)?;
    let row_bits_end = TRACE_ROW_BITS_START
        .checked_add(TRACE_ROW_BIT_COUNT)
        .ok_or(NativeTraceError::Layout)?;
    // Invariant: canonical padding depends on the row index only in the fixed
    // row-bit range; every other column repeats the first encoded padding value.
    for (column_index, column) in columns.iter_mut().enumerate() {
        if (TRACE_ROW_BITS_START..row_bits_end).contains(&column_index) {
            append_remaining_row_bits(column, column_index, remaining_start)?;
        } else {
            let value = column.last().copied().ok_or(NativeTraceError::Layout)?;
            column.resize(UNIFORM_ROW_COUNT, value);
        }
    }
    Ok(())
}

fn append_remaining_row_bits(
    column: &mut Vec<u64>,
    column_index: usize,
    remaining_start: usize,
) -> Result<(), NativeTraceError> {
    let bit = column_index
        .checked_sub(TRACE_ROW_BITS_START)
        .ok_or(NativeTraceError::Layout)?;
    for row_index in remaining_start..UNIFORM_ROW_COUNT {
        column.push(u64::from(((row_index >> bit) & 1) != 0));
    }
    Ok(())
}
