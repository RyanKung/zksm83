//! Ordered P1 sampling, selection writes, falling edges, and joypad IF updates.

use akita_pcs::Ring;

use super::{
    BUS_AUXILIARY_OFFSET, BUS_BEFORE_OFFSET, ConstraintSink, RowView, bit_selector, boolean,
    bus_field, bus_kind_bits, packed_bits,
};
use crate::{
    NativeField, TRACE_AFTER_INTERRUPT_REQUEST_BITS_START,
    TRACE_BEFORE_INTERRUPT_REQUEST_BITS_START, TRACE_BUS_ADDRESS_BITS_START, TRACE_BUS_SLOTS,
    TRACE_BUS_VALUE_BITS_START, TRACE_INTERRUPT_START, UniformError,
    trace::{
        TRACE_BEFORE_JOYPAD_BITS_START, TRACE_JOYPAD_FALL_NONE_START, TRACE_JOYPAD_IF_BIT_START,
        TRACE_JOYPAD_STAGE_BITS_START, TRACE_JOYPAD_STAGE_WIDTH, TRACE_JOYPAD_WRITE_START,
    },
};

const STATE_JOYPAD_PACK: usize = 36;

pub(super) fn constrain_joypad(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_state_bits(view, sink, TRACE_BEFORE_JOYPAD_BITS_START)?;
    sink.push(
        view.before(STATE_JOYPAD_PACK)? - joypad_pack(view, TRACE_BEFORE_JOYPAD_BITS_START)?,
    )?;
    let mut current_start = TRACE_BEFORE_JOYPAD_BITS_START;
    let mut current_if = view.value(TRACE_BEFORE_INTERRUPT_REQUEST_BITS_START + 4)?
        - view.value(TRACE_INTERRUPT_START + 4)?;
    for slot in 0..TRACE_BUS_SLOTS {
        let next_start = TRACE_JOYPAD_STAGE_BITS_START + slot * TRACE_JOYPAD_STAGE_WIDTH;
        constrain_state_bits(view, sink, next_start)?;
        constrain_slot_state(view, sink, slot, current_start, next_start)?;
        let falling = constrain_falling(view, sink, slot, current_start, next_start)?;
        current_if = constrain_if(view, sink, slot, current_if, falling)?;
        current_start = next_start;
    }
    sink.push(view.after(STATE_JOYPAD_PACK)? - joypad_pack(view, current_start)?)?;
    sink.push(view.value(TRACE_AFTER_INTERRUPT_REQUEST_BITS_START + 4)? - current_if)
}

fn constrain_state_bits(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    start: usize,
) -> Result<(), UniformError> {
    for bit in 0..TRACE_JOYPAD_STAGE_WIDTH {
        sink.push(boolean(view.value(start + bit)?))?;
    }
    Ok(())
}

fn constrain_slot_state(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    slot: usize,
    current: usize,
    next: usize,
) -> Result<(), UniformError> {
    let read = bus_kind(view, slot, 13)?;
    let write = view.value(TRACE_JOYPAD_WRITE_START + slot)?;
    sink.push(boolean(write))?;
    sink.push(write - bus_kind(view, slot, 12)? * low_selector(view, slot, 0x00)?)?;
    let current_buttons = packed_bits(view, current + 2, 8)?;
    let next_buttons = packed_bits(view, next + 2, 8)?;
    sink.push(
        next_buttons
            - current_buttons
            - read * (bus_field(view, slot, BUS_AUXILIARY_OFFSET)? - current_buttons),
    )?;
    let current_select = select_value(view, current)?;
    let next_select = select_value(view, next)?;
    let written_select = view.value(TRACE_BUS_VALUE_BITS_START + slot * 8 + 4)?
        * NativeField::from_u64(16)
        + view.value(TRACE_BUS_VALUE_BITS_START + slot * 8 + 5)? * NativeField::from_u64(32);
    sink.push(next_select - current_select - write * (written_select - current_select))?;
    constrain_bus_values(view, sink, slot, current, next, read, write)
}

fn constrain_bus_values(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    slot: usize,
    current: usize,
    next: usize,
    read: NativeField,
    write: NativeField,
) -> Result<(), UniformError> {
    let current_buttons = packed_bits(view, current + 2, 8)?;
    let next_buttons = packed_bits(view, next + 2, 8)?;
    sink.push(read * (bus_field(view, slot, BUS_BEFORE_OFFSET)? - current_buttons))?;
    sink.push(read * (bus_field(view, slot, BUS_AUXILIARY_OFFSET)? - next_buttons))?;
    let visible_before = visible_byte(view, current)?;
    sink.push(write * (bus_field(view, slot, BUS_BEFORE_OFFSET)? - visible_before))?;
    for bit in 0..8 {
        let actual = view.value(TRACE_BUS_VALUE_BITS_START + slot * 8 + bit)?;
        sink.push(read * (actual - visible_bit(view, current, next, bit)?))?;
    }
    Ok(())
}

fn constrain_falling(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    slot: usize,
    current: usize,
    next: usize,
) -> Result<NativeField, UniformError> {
    let falls = [
        line_fall(view, current, next, 0)?,
        line_fall(view, current, next, 1)?,
        line_fall(view, current, next, 2)?,
        line_fall(view, current, next, 3)?,
    ];
    let [fall_zero, fall_one, fall_two, fall_three] = falls;
    let first = view.value(TRACE_JOYPAD_FALL_NONE_START + slot * 2)?;
    let second = view.value(TRACE_JOYPAD_FALL_NONE_START + slot * 2 + 1)?;
    sink.push(
        first - (NativeField::from_u64(1) - fall_zero) * (NativeField::from_u64(1) - fall_one),
    )?;
    sink.push(
        second - (NativeField::from_u64(1) - fall_two) * (NativeField::from_u64(1) - fall_three),
    )?;
    Ok(NativeField::from_u64(1) - first * second)
}

fn line_fall(
    view: &RowView<'_>,
    current: usize,
    next: usize,
    bit: usize,
) -> Result<NativeField, UniformError> {
    Ok(visible_low_bit(view, current, bit)?
        * (NativeField::from_u64(1) - visible_low_bit(view, next, bit)?))
}

fn constrain_if(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    slot: usize,
    current: NativeField,
    falling: NativeField,
) -> Result<NativeField, UniformError> {
    let write = bus_kind(view, slot, 12)? * low_selector(view, slot, 0x0f)?;
    let written = view.value(TRACE_BUS_VALUE_BITS_START + slot * 8 + 4)?;
    let after_write = current + write * (written - current);
    let next = view.value(TRACE_JOYPAD_IF_BIT_START + slot)?;
    sink.push(boolean(next))?;
    sink.push(next - after_write - (NativeField::from_u64(1) - after_write) * falling)?;
    Ok(next)
}

fn joypad_pack(view: &RowView<'_>, start: usize) -> Result<NativeField, UniformError> {
    Ok(select_value(view, start)? + NativeField::from_u64(256) * packed_bits(view, start + 2, 8)?)
}

fn select_value(view: &RowView<'_>, start: usize) -> Result<NativeField, UniformError> {
    Ok(NativeField::from_u64(16) * view.value(start)?
        + NativeField::from_u64(32) * view.value(start + 1)?)
}

fn visible_byte(view: &RowView<'_>, start: usize) -> Result<NativeField, UniformError> {
    let mut value = NativeField::from_u64(0xc0) + select_value(view, start)?;
    for bit in 0..4 {
        value += NativeField::from_u64(1 << bit) * visible_low_bit(view, start, bit)?;
    }
    Ok(value)
}

fn visible_bit(
    view: &RowView<'_>,
    select_start: usize,
    button_start: usize,
    bit: usize,
) -> Result<NativeField, UniformError> {
    match bit {
        0..=3 => visible_low_bit_mixed(view, select_start, button_start, bit),
        4 | 5 => view.value(select_start + bit - 4),
        6 | 7 => Ok(NativeField::from_u64(1)),
        _ => Err(UniformError::Shape),
    }
}

fn visible_low_bit(
    view: &RowView<'_>,
    start: usize,
    bit: usize,
) -> Result<NativeField, UniformError> {
    visible_low_bit_mixed(view, start, start, bit)
}

fn visible_low_bit_mixed(
    view: &RowView<'_>,
    select_start: usize,
    button_start: usize,
    bit: usize,
) -> Result<NativeField, UniformError> {
    let one = NativeField::from_u64(1);
    let direction = one - (one - view.value(select_start)?) * view.value(button_start + 2 + bit)?;
    let action =
        one - (one - view.value(select_start + 1)?) * view.value(button_start + 6 + bit)?;
    Ok(direction * action)
}

fn low_selector(
    view: &RowView<'_>,
    slot: usize,
    expected: u8,
) -> Result<NativeField, UniformError> {
    let start = TRACE_BUS_ADDRESS_BITS_START + slot * 16;
    let one = NativeField::from_u64(1);
    (0..8).try_fold(one, |selector, bit| {
        let actual = view.value(start + bit)?;
        Ok(if (expected >> bit) & 1 == 1 {
            selector * actual
        } else {
            selector * (one - actual)
        })
    })
}

fn bus_kind(view: &RowView<'_>, slot: usize, code: u8) -> Result<NativeField, UniformError> {
    bit_selector(bus_kind_bits(view, slot)?, code)
}
