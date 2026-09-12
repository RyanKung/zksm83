//! Fail-closed DMG MMIO address, tuple, and interrupt-enable identities.

use akita_pcs::Ring;

use super::{
    BUS_ADDRESS_OFFSET, BUS_AUXILIARY_OFFSET, BUS_BEFORE_OFFSET, BUS_INDEX_OFFSET,
    BUS_PHYSICAL_ADDRESS_OFFSET, BUS_VALUE_OFFSET, ConstraintSink, RowView, bit_selector,
    bus_field, bus_kind_bits, packed_bits,
};
use crate::{
    NativeField, TRACE_BUS_ADDRESS_BITS_START, TRACE_BUS_SLOTS, TRACE_BUS_VALUE_BITS_START,
    UniformError,
};

const STATE_INTERRUPT_REQUEST: usize = 21;
const STATE_INTERRUPT_ENABLE: usize = 22;

pub(super) fn constrain_mmio_events(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let mut enable_update = NativeField::from_u64(0);
    for slot in 0..TRACE_BUS_SLOTS {
        let read = bus_kind(view, slot, 11)?;
        let write = bus_kind(view, slot, 12)?;
        let joypad = bus_kind(view, slot, 13)?;
        let mmio = read + write;
        constrain_high_byte(view, sink, slot, mmio)?;
        sink.push(read * (allowed_read(view, slot)? - one))?;
        sink.push(write * (allowed_write(view, slot)? - one))?;
        constrain_tuple(view, sink, slot, read, write, joypad)?;
        constrain_interrupt_registers(view, sink, slot, read, write)?;
        let enable_write = write * low_selector(view, slot, 0xff)?;
        let value = packed_bits(view, TRACE_BUS_VALUE_BITS_START + slot * 8, 5)?;
        enable_update += enable_write * (value - view.before(STATE_INTERRUPT_ENABLE)?);
    }
    sink.push(
        view.after(STATE_INTERRUPT_ENABLE)? - view.before(STATE_INTERRUPT_ENABLE)? - enable_update,
    )
}

fn constrain_high_byte(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    slot: usize,
    selected: NativeField,
) -> Result<(), UniformError> {
    let start = TRACE_BUS_ADDRESS_BITS_START + slot * 16;
    for bit in 8..16 {
        sink.push(selected * (view.value(start + bit)? - NativeField::from_u64(1)))?;
    }
    Ok(())
}

fn allowed_read(view: &RowView<'_>, slot: usize) -> Result<NativeField, UniformError> {
    allowed(view, slot, false)
}

fn allowed_write(view: &RowView<'_>, slot: usize) -> Result<NativeField, UniformError> {
    allowed(view, slot, true)
}

fn allowed(
    view: &RowView<'_>,
    slot: usize,
    includes_joypad: bool,
) -> Result<NativeField, UniformError> {
    let mut sum = NativeField::from_u64(0);
    if includes_joypad {
        sum += low_selector(view, slot, 0x00)?;
    }
    for address in [0x01_u8, 0x02, 0x04, 0x05, 0x06, 0x07, 0x0f, 0xff] {
        sum += low_selector(view, slot, address)?;
    }
    for address in 0x10_u8..=0x3f {
        sum += low_selector(view, slot, address)?;
    }
    for address in 0x40_u8..=0x4b {
        sum += low_selector(view, slot, address)?;
    }
    Ok(sum)
}

fn constrain_tuple(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    slot: usize,
    read: NativeField,
    write: NativeField,
    joypad: NativeField,
) -> Result<(), UniformError> {
    let plain = read + write;
    for offset in [
        BUS_PHYSICAL_ADDRESS_OFFSET,
        BUS_AUXILIARY_OFFSET,
        BUS_INDEX_OFFSET,
    ] {
        sink.push(plain * bus_field(view, slot, offset)?)?;
    }
    sink.push(read * bus_field(view, slot, BUS_BEFORE_OFFSET)?)?;
    sink.push(
        joypad * (bus_field(view, slot, BUS_ADDRESS_OFFSET)? - NativeField::from_u64(0xff00)),
    )?;
    sink.push(joypad * bus_field(view, slot, BUS_PHYSICAL_ADDRESS_OFFSET)?)
}

fn constrain_interrupt_registers(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    slot: usize,
    read: NativeField,
    write: NativeField,
) -> Result<(), UniformError> {
    let request = low_selector(view, slot, 0x0f)?;
    let enable = low_selector(view, slot, 0xff)?;
    let value = bus_field(view, slot, BUS_VALUE_OFFSET)?;
    let before = bus_field(view, slot, BUS_BEFORE_OFFSET)?;
    let visible_request = NativeField::from_u64(0xe0) + view.before(STATE_INTERRUPT_REQUEST)?;
    sink.push(read * request * (value - visible_request))?;
    sink.push(write * request * (before - visible_request))?;
    sink.push(read * enable * (value - view.before(STATE_INTERRUPT_ENABLE)?))?;
    sink.push(write * enable * (before - view.before(STATE_INTERRUPT_ENABLE)?))
}

fn low_selector(view: &RowView<'_>, slot: usize, value: u8) -> Result<NativeField, UniformError> {
    let start = TRACE_BUS_ADDRESS_BITS_START + slot * 16;
    let one = NativeField::from_u64(1);
    (0..8).try_fold(one, |selector, bit| {
        let actual = view.value(start + bit)?;
        Ok(if (value >> bit) & 1 == 1 {
            selector * actual
        } else {
            selector * (one - actual)
        })
    })
}

fn bus_kind(view: &RowView<'_>, slot: usize, code: u8) -> Result<NativeField, UniformError> {
    bit_selector(bus_kind_bits(view, slot)?, code)
}
