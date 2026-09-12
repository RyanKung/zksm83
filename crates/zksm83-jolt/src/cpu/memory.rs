use akita_pcs::Ring;

use crate::{
    NativeField, ROM_ADDRESS_BIT_COUNT, TRACE_BUS_ADDRESS_BITS_START,
    TRACE_BUS_PHYSICAL_BITS_START, TRACE_BUS_SLOTS, TRACE_MEMORY_AFTER_OFFSET,
    TRACE_MEMORY_BEFORE_OFFSET, TRACE_MEMORY_DELTA_BITS_OFFSET,
    TRACE_MEMORY_PREDECESSOR_BITS_OFFSET, TRACE_MEMORY_SELECTOR_OFFSET, TRACE_MEMORY_SLOT_WIDTH,
    TRACE_MEMORY_START, TRACE_MEMORY_TIMESTAMP_BITS, TRACE_MEMORY_WRITE_SELECTOR_OFFSET,
    TRACE_ROW_BIT_COUNT, TRACE_ROW_BITS_START, UniformError,
};

use super::{
    BUS_BEFORE_OFFSET, BUS_VALUE_OFFSET, ConstraintSink, RowView, STATE_MBC3_RAM_ENABLED,
    bit_selector, boolean, bus_field, bus_kind_bits, packed_bits,
};

pub(super) fn constrain_memory_events(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_row_bits(view, sink)?;
    let row = packed_bits(view, TRACE_ROW_BITS_START, TRACE_ROW_BIT_COUNT)?;
    for slot in 0..TRACE_BUS_SLOTS {
        constrain_slot(view, sink, row, slot)?;
    }
    Ok(())
}

fn constrain_row_bits(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for bit in 0..TRACE_ROW_BIT_COUNT {
        sink.push(boolean(view.value(TRACE_ROW_BITS_START + bit)?))?;
    }
    Ok(())
}

fn constrain_slot(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    row: NativeField,
    slot: usize,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let start = memory_slot_start(slot)?;
    let selected = view.value(start + TRACE_MEMORY_SELECTOR_OFFSET)?;
    let write = view.value(start + TRACE_MEMORY_WRITE_SELECTOR_OFFSET)?;
    let kinds = bus_kind_bits(view, slot)?;
    let read = selector_sum(kinds, &[4, 14, 15, 17])?;
    let expected_write = selector_sum(kinds, &[5, 18])?;
    sink.push(boolean(selected))?;
    sink.push(boolean(write))?;
    sink.push(selected - read - expected_write)?;
    sink.push(write - expected_write)?;
    sink.push(
        view.value(start + TRACE_MEMORY_BEFORE_OFFSET)?
            - write * bus_field(view, slot, BUS_BEFORE_OFFSET)?
            - read * bus_field(view, slot, BUS_VALUE_OFFSET)?,
    )?;
    sink.push(
        view.value(start + TRACE_MEMORY_AFTER_OFFSET)?
            - selected * bus_field(view, slot, BUS_VALUE_OFFSET)?,
    )?;
    let predecessor = constrain_selected_bits(
        view,
        sink,
        selected,
        start + TRACE_MEMORY_PREDECESSOR_BITS_OFFSET,
    )?;
    let delta =
        constrain_selected_bits(view, sink, selected, start + TRACE_MEMORY_DELTA_BITS_OFFSET)?;
    let slot_number = u64::try_from(slot).map_err(|_| UniformError::Shape)?;
    let slots = u64::try_from(TRACE_BUS_SLOTS).map_err(|_| UniformError::Shape)?;
    let current = row * NativeField::from_u64(slots) + NativeField::from_u64(slot_number + 1);
    sink.push(selected * (predecessor + delta + one - current))?;
    constrain_physical_mapping(view, sink, selected, slot)
}

fn constrain_selected_bits(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    selected: NativeField,
    start: usize,
) -> Result<NativeField, UniformError> {
    let one = NativeField::from_u64(1);
    for bit in 0..TRACE_MEMORY_TIMESTAMP_BITS {
        let value = view.value(start + bit)?;
        sink.push(boolean(value))?;
        sink.push((one - selected) * value)?;
    }
    packed_bits(view, start, TRACE_MEMORY_TIMESTAMP_BITS)
}

fn constrain_physical_mapping(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    selected: NativeField,
    slot: usize,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let address_start = TRACE_BUS_ADDRESS_BITS_START + slot * 16;
    let physical_start = TRACE_BUS_PHYSICAL_BITS_START + slot * ROM_ADDRESS_BIT_COUNT;
    let address = packed_bits(view, address_start, 16)?;
    let physical = packed_bits(view, physical_start, ROM_ADDRESS_BIT_COUNT)?;
    let external = view.value(address_start + 15)?
        * (one - view.value(address_start + 14)?)
        * view.value(address_start + 13)?;
    let bank_start = crate::TRACE_BEFORE_RAM_RTC_BITS_START;
    let bank = packed_bits(view, bank_start, 4)?;
    sink.push(selected * external * (one - view.before(STATE_MBC3_RAM_ENABLED)?))?;
    sink.push(selected * external * view.value(bank_start + 2)?)?;
    sink.push(selected * external * view.value(bank_start + 3)?)?;
    let mapped =
        address + external * (NativeField::from_u64(0x6000) + bank * NativeField::from_u64(0x2000));
    sink.push(selected * (physical - mapped))?;
    for bit in 17..ROM_ADDRESS_BIT_COUNT {
        sink.push(selected * view.value(physical_start + bit)?)?;
    }
    Ok(())
}

fn selector_sum(bits: &[NativeField], codes: &[u8]) -> Result<NativeField, UniformError> {
    codes
        .iter()
        .copied()
        .try_fold(NativeField::from_u64(0), |sum, code| {
            Ok::<_, UniformError>(sum + bit_selector(bits, code)?)
        })
}

fn memory_slot_start(slot: usize) -> Result<usize, UniformError> {
    TRACE_MEMORY_START
        .checked_add(
            slot.checked_mul(TRACE_MEMORY_SLOT_WIDTH)
                .ok_or(UniformError::Shape)?,
        )
        .ok_or(UniformError::Shape)
}
