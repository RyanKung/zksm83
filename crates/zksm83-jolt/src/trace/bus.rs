use zksm83_core::BusEvent;
use zksm83_trace::TraceRow;

use crate::{
    ROM_ADDRESS_BIT_COUNT, TRACE_BUS_ADDRESS_BITS_START, TRACE_BUS_BEFORE_BITS_START,
    TRACE_BUS_KIND_BITS, TRACE_BUS_PHYSICAL_BITS_START, TRACE_BUS_SLOT_WIDTH, TRACE_BUS_SLOTS,
    TRACE_BUS_START, TRACE_BUS_VALUE_BITS_START, TRACE_ROM_SELECTOR_START, TRACE_ROM_VALUE_START,
};

use super::{
    NativeTraceError, append, append_bits,
    memory::{MemoryEventFields, MemoryOrderTracker},
};

pub(super) fn append_bus(
    columns: &mut [Vec<u64>],
    row: &TraceRow,
    row_index: usize,
    memory_order: &mut MemoryOrderTracker,
) -> Result<(), NativeTraceError> {
    let events = row.effects().bus_events().collect::<Vec<_>>();
    if events.len() > TRACE_BUS_SLOTS {
        return Err(NativeTraceError::TooManyBusEvents { index: row_index });
    }
    for slot in 0..TRACE_BUS_SLOTS {
        match events.get(slot).copied() {
            Some(event) => append_bus_event(columns, slot, row_index, event, memory_order)?,
            None => append_empty_bus_slot(columns, slot)?,
        }
    }
    Ok(())
}

fn append_bus_event(
    columns: &mut [Vec<u64>],
    slot: usize,
    row_index: usize,
    event: &BusEvent,
    memory_order: &mut MemoryOrderTracker,
) -> Result<(), NativeTraceError> {
    let start = bus_slot_start(slot)?;
    append(columns, start, 1)?;
    let code = event.kind().code();
    for bit in 0..TRACE_BUS_KIND_BITS {
        append(columns, start + 1 + bit, u64::from((code >> bit) & 1))?;
    }
    let event = event.transcript_event();
    append_bits(
        columns,
        TRACE_BUS_ADDRESS_BITS_START + slot * 16,
        u64::from(event.address),
        16,
    )?;
    append_bits(
        columns,
        TRACE_BUS_PHYSICAL_BITS_START + slot * ROM_ADDRESS_BIT_COUNT,
        u64::from(event.physical_address),
        ROM_ADDRESS_BIT_COUNT,
    )?;
    append_bits(
        columns,
        TRACE_BUS_VALUE_BITS_START + slot * 8,
        u64::from(event.value),
        8,
    )?;
    append_bits(
        columns,
        TRACE_BUS_BEFORE_BITS_START + slot * 8,
        u64::from(event.before),
        8,
    )?;
    let rom_selector = matches!(code, 1 | 2 | 3 | 16);
    append(
        columns,
        TRACE_ROM_SELECTOR_START + slot,
        u64::from(rom_selector),
    )?;
    append(
        columns,
        TRACE_ROM_VALUE_START + slot,
        u64::from(rom_selector) * u64::from(event.value),
    )?;
    for (offset, value) in [
        u64::from(event.address),
        u64::from(event.physical_address),
        u64::from(event.before),
        u64::from(event.auxiliary),
        u64::from(event.value),
        event.index,
    ]
    .into_iter()
    .enumerate()
    {
        append(columns, start + 1 + TRACE_BUS_KIND_BITS + offset, value)?;
    }
    memory_order.append_event(
        columns,
        row_index,
        slot,
        MemoryEventFields {
            code,
            physical_address: event.physical_address,
            before: event.before,
            after: event.value,
        },
    )
}

pub(super) fn append_empty_bus(columns: &mut [Vec<u64>]) -> Result<(), NativeTraceError> {
    for slot in 0..TRACE_BUS_SLOTS {
        append_empty_bus_slot(columns, slot)?;
    }
    Ok(())
}

fn append_empty_bus_slot(columns: &mut [Vec<u64>], slot: usize) -> Result<(), NativeTraceError> {
    let start = bus_slot_start(slot)?;
    for offset in 0..TRACE_BUS_SLOT_WIDTH {
        append(columns, start + offset, 0)?;
    }
    for bit in 0..ROM_ADDRESS_BIT_COUNT {
        append(
            columns,
            TRACE_BUS_PHYSICAL_BITS_START + slot * ROM_ADDRESS_BIT_COUNT + bit,
            0,
        )?;
    }
    for bit in 0..16 {
        append(columns, TRACE_BUS_ADDRESS_BITS_START + slot * 16 + bit, 0)?;
    }
    for bit in 0..8 {
        append(columns, TRACE_BUS_VALUE_BITS_START + slot * 8 + bit, 0)?;
        append(columns, TRACE_BUS_BEFORE_BITS_START + slot * 8 + bit, 0)?;
    }
    append(columns, TRACE_ROM_SELECTOR_START + slot, 0)?;
    append(columns, TRACE_ROM_VALUE_START + slot, 0)?;
    super::memory::append_empty_event(columns, slot)
}

fn bus_slot_start(slot: usize) -> Result<usize, NativeTraceError> {
    TRACE_BUS_START
        .checked_add(
            slot.checked_mul(TRACE_BUS_SLOT_WIDTH)
                .ok_or(NativeTraceError::Layout)?,
        )
        .ok_or(NativeTraceError::Layout)
}
