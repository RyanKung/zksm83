use akita_pcs::Ring;

use crate::{
    NativeField, ROM_ADDRESS_BIT_COUNT, TRACE_BEFORE_RAM_RTC_BITS_START,
    TRACE_BUS_ADDRESS_BITS_START, TRACE_BUS_PHYSICAL_BITS_START, TRACE_BUS_SLOTS,
    TRACE_BUS_VALUE_BITS_START, TRACE_ROM_SELECTOR_START, UniformError,
};

use super::{
    BUS_AUXILIARY_OFFSET, BUS_BEFORE_OFFSET, BUS_INDEX_OFFSET, BUS_PHYSICAL_ADDRESS_OFFSET,
    BUS_VALUE_OFFSET, ConstraintSink, RowView, STATE_MBC3_RAM_ENABLED, STATE_MBC3_RAM_RTC_SELECT,
    STATE_MBC3_ROM_BANK, bit_selector, boolean, bus_field, bus_kind_bits, packed_bits,
    zero_from_bits,
};

pub(super) fn constrain_mapper_and_rom(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_rom_mapping(view, sink)?;
    constrain_external_ram_policy(view, sink)?;
    constrain_mapper_updates(view, sink)
}

fn constrain_external_ram_policy(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let ram_enabled = view.before(STATE_MBC3_RAM_ENABLED)?;
    let select_bits = TRACE_BEFORE_RAM_RTC_BITS_START;
    let available =
        ram_enabled * (one - view.value(select_bits + 2)?) * (one - view.value(select_bits + 3)?);
    for slot in 0..TRACE_BUS_SLOTS {
        let kinds = bus_kind_bits(view, slot)?;
        let open_read = bit_selector(kinds, 9)?;
        let ignored_write = bit_selector(kinds, 10)?;
        let selected = open_read + ignored_write;
        let address = TRACE_BUS_ADDRESS_BITS_START + slot * 16;
        sink.push(selected * (one - view.value(address + 15)?))?;
        sink.push(selected * view.value(address + 14)?)?;
        sink.push(selected * (one - view.value(address + 13)?))?;
        sink.push(selected * available)?;
        sink.push(selected * bus_field(view, slot, BUS_PHYSICAL_ADDRESS_OFFSET)?)?;
        sink.push(selected * bus_field(view, slot, BUS_BEFORE_OFFSET)?)?;
        sink.push(selected * bus_field(view, slot, BUS_AUXILIARY_OFFSET)?)?;
        sink.push(selected * bus_field(view, slot, BUS_INDEX_OFFSET)?)?;
        sink.push(
            open_read * (bus_field(view, slot, BUS_VALUE_OFFSET)? - NativeField::from_u64(0xff)),
        )?;
    }
    Ok(())
}

fn constrain_rom_mapping(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let bank = view.before(STATE_MBC3_ROM_BANK)?;
    for slot in 0..TRACE_BUS_SLOTS {
        let selected = view.value(TRACE_ROM_SELECTOR_START + slot)?;
        let address_bits = TRACE_BUS_ADDRESS_BITS_START + slot * 16;
        let physical_bits = TRACE_BUS_PHYSICAL_BITS_START + slot * ROM_ADDRESS_BIT_COUNT;
        let address = packed_bits(view, address_bits, 16)?;
        let physical = packed_bits(view, physical_bits, ROM_ADDRESS_BIT_COUNT)?;
        let bank_window = view.value(address_bits + 14)?;
        let outside_rom = view.value(address_bits + 15)?;
        let expected = address + bank_window * (bank - one) * NativeField::from_u64(0x4000);
        sink.push(selected * outside_rom)?;
        sink.push(selected * (physical - expected))?;
    }
    Ok(())
}

fn constrain_mapper_updates(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let mut control_count = NativeField::from_u64(0);
    let mut ram_update = NativeField::from_u64(0);
    let mut bank_update = NativeField::from_u64(0);
    let mut select_update = NativeField::from_u64(0);
    for slot in 0..TRACE_BUS_SLOTS {
        let control = bit_selector(bus_kind_bits(view, slot)?, 8)?;
        let address_bits = TRACE_BUS_ADDRESS_BITS_START + slot * 16;
        let value_bits = TRACE_BUS_VALUE_BITS_START + slot * 8;
        let [ram_segment, bank_segment, select_segment, _] =
            control_segments(view, control, address_bits)?;
        control_count += control;
        sink.push(control * view.value(address_bits + 15)?)?;
        sink.push(control * bus_field(view, slot, BUS_PHYSICAL_ADDRESS_OFFSET)?)?;
        ram_update += ram_segment
            * (ram_enable_value(view, value_bits)? - view.before(STATE_MBC3_RAM_ENABLED)?);
        bank_update += bank_segment
            * (mapped_rom_bank(view, value_bits)? - view.before(STATE_MBC3_ROM_BANK)?);
        select_update += select_segment
            * (packed_bits(view, value_bits, 4)? - view.before(STATE_MBC3_RAM_RTC_SELECT)?);
    }
    sink.push(boolean(control_count))?;
    sink.push(
        view.after(STATE_MBC3_RAM_ENABLED)? - view.before(STATE_MBC3_RAM_ENABLED)? - ram_update,
    )?;
    sink.push(view.after(STATE_MBC3_ROM_BANK)? - view.before(STATE_MBC3_ROM_BANK)? - bank_update)?;
    sink.push(
        view.after(STATE_MBC3_RAM_RTC_SELECT)?
            - view.before(STATE_MBC3_RAM_RTC_SELECT)?
            - select_update,
    )
}

fn control_segments(
    view: &RowView<'_>,
    control: NativeField,
    address_bits: usize,
) -> Result<[NativeField; 4], UniformError> {
    let one = NativeField::from_u64(1);
    let bit_thirteen = view.value(address_bits + 13)?;
    let bit_fourteen = view.value(address_bits + 14)?;
    Ok([
        control * (one - bit_fourteen) * (one - bit_thirteen),
        control * (one - bit_fourteen) * bit_thirteen,
        control * bit_fourteen * (one - bit_thirteen),
        control * bit_fourteen * bit_thirteen,
    ])
}

fn ram_enable_value(view: &RowView<'_>, value_bits: usize) -> Result<NativeField, UniformError> {
    let one = NativeField::from_u64(1);
    Ok((one - view.value(value_bits)?)
        * view.value(value_bits + 1)?
        * (one - view.value(value_bits + 2)?)
        * view.value(value_bits + 3)?)
}

fn mapped_rom_bank(view: &RowView<'_>, value_bits: usize) -> Result<NativeField, UniformError> {
    Ok(packed_bits(view, value_bits, 6)? + zero_from_bits(view, value_bits, 6)?)
}
