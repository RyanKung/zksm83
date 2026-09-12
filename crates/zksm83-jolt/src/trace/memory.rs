use crate::{
    TRACE_MEMORY_AFTER_OFFSET, TRACE_MEMORY_BEFORE_OFFSET, TRACE_MEMORY_DELTA_BITS_OFFSET,
    TRACE_MEMORY_PREDECESSOR_BITS_OFFSET, TRACE_MEMORY_SELECTOR_OFFSET, TRACE_MEMORY_SLOT_WIDTH,
    TRACE_MEMORY_START, TRACE_MEMORY_TIMESTAMP_BITS, TRACE_MEMORY_WRITE_SELECTOR_OFFSET,
    TRACE_ROW_BIT_COUNT, TRACE_ROW_BITS_START,
};

use super::{NativeTraceError, append, append_bits};

const MEMORY_ROW_COUNT: usize = 1 << TRACE_MEMORY_TIMESTAMP_BITS;

pub(super) struct MemoryOrderTracker {
    timestamps: Vec<u64>,
}

pub(super) struct MemoryEventFields {
    pub(super) code: u8,
    pub(super) physical_address: u32,
    pub(super) before: u8,
    pub(super) after: u8,
}

impl MemoryOrderTracker {
    pub(super) fn new() -> Self {
        Self {
            timestamps: vec![0; MEMORY_ROW_COUNT],
        }
    }

    pub(super) fn append_event(
        &mut self,
        columns: &mut [Vec<u64>],
        row: usize,
        slot: usize,
        event: MemoryEventFields,
    ) -> Result<(), NativeTraceError> {
        let selected = matches!(event.code, 4 | 5 | 14 | 15 | 17 | 18);
        if !selected {
            return append_empty_event(columns, slot);
        }
        let address = usize::try_from(event.physical_address).map_err(|_| {
            NativeTraceError::MemoryPhysicalAddressOutOfRange {
                physical_address: event.physical_address,
            }
        })?;
        let predecessor = self.timestamps.get(address).copied().ok_or(
            NativeTraceError::MemoryPhysicalAddressOutOfRange {
                physical_address: event.physical_address,
            },
        )?;
        let current = current_timestamp(row, slot)?;
        let delta = current
            .checked_sub(predecessor)
            .and_then(|difference| difference.checked_sub(1))
            .ok_or(NativeTraceError::MemoryTimestampOverflow)?;
        let timestamp = self.timestamps.get_mut(address).ok_or(
            NativeTraceError::MemoryPhysicalAddressOutOfRange {
                physical_address: event.physical_address,
            },
        )?;
        *timestamp = current;
        let write = matches!(event.code, 5 | 18);
        let before = if write { event.before } else { event.after };
        let start = slot_start(slot)?;
        append(columns, start + TRACE_MEMORY_SELECTOR_OFFSET, 1)?;
        append(
            columns,
            start + TRACE_MEMORY_WRITE_SELECTOR_OFFSET,
            u64::from(write),
        )?;
        append(
            columns,
            start + TRACE_MEMORY_BEFORE_OFFSET,
            u64::from(before),
        )?;
        append(
            columns,
            start + TRACE_MEMORY_AFTER_OFFSET,
            u64::from(event.after),
        )?;
        append_bits(
            columns,
            start + TRACE_MEMORY_PREDECESSOR_BITS_OFFSET,
            predecessor,
            TRACE_MEMORY_TIMESTAMP_BITS,
        )?;
        append_bits(
            columns,
            start + TRACE_MEMORY_DELTA_BITS_OFFSET,
            delta,
            TRACE_MEMORY_TIMESTAMP_BITS,
        )
    }

    pub(super) fn into_timestamps(self) -> Vec<u64> {
        self.timestamps
    }
}

pub(super) fn append_row_bits(
    columns: &mut [Vec<u64>],
    row: usize,
) -> Result<(), NativeTraceError> {
    let row = u64::try_from(row).map_err(|_| NativeTraceError::MemoryTimestampOverflow)?;
    append_bits(columns, TRACE_ROW_BITS_START, row, TRACE_ROW_BIT_COUNT)
}

pub(super) fn append_empty_event(
    columns: &mut [Vec<u64>],
    slot: usize,
) -> Result<(), NativeTraceError> {
    let start = slot_start(slot)?;
    for offset in 0..TRACE_MEMORY_SLOT_WIDTH {
        append(columns, start + offset, 0)?;
    }
    Ok(())
}

fn current_timestamp(row: usize, slot: usize) -> Result<u64, NativeTraceError> {
    let timestamp = row
        .checked_mul(crate::TRACE_BUS_SLOTS)
        .and_then(|value| value.checked_add(slot))
        .and_then(|value| value.checked_add(1))
        .ok_or(NativeTraceError::MemoryTimestampOverflow)?;
    if timestamp >= MEMORY_ROW_COUNT {
        return Err(NativeTraceError::MemoryTimestampOverflow);
    }
    u64::try_from(timestamp).map_err(|_| NativeTraceError::MemoryTimestampOverflow)
}

fn slot_start(slot: usize) -> Result<usize, NativeTraceError> {
    TRACE_MEMORY_START
        .checked_add(
            slot.checked_mul(TRACE_MEMORY_SLOT_WIDTH)
                .ok_or(NativeTraceError::Layout)?,
        )
        .ok_or(NativeTraceError::Layout)
}
