//! Exact serial register, countdown, completion, and IF-bit transition.

use akita_pcs::Ring;

use super::{
    BUS_VALUE_OFFSET, ConstraintSink, HALT_IDLE_MODE, HALT_UNTIL_SERIAL_MODE,
    HALT_UNTIL_TIMER_MODE, HALT_UNTIL_VBLANK_MODE, INSTRUCTION_MODE, INTERRUPT_MODE, RowView,
    boolean, bus_field, packed_bits, zero_from_bits,
};
use crate::{
    NativeField, TRACE_BUS_SLOTS, TRACE_BUS_VALUE_BITS_START, TRACE_CYCLE_INCREMENT,
    TRACE_INTERRUPT_START, UniformError,
    trace::device::{
        TRACE_AFTER_DMG_HIGH_BITS_START, TRACE_AFTER_DMG_LOW_BITS_START,
        TRACE_AFTER_INTERRUPT_REQUEST_BITS_START, TRACE_BEFORE_DMG_HIGH_BITS_START,
        TRACE_BEFORE_DMG_LOW_BITS_START, TRACE_BEFORE_INTERRUPT_ENABLE_BITS_START,
        TRACE_BEFORE_INTERRUPT_REQUEST_BITS_START, TRACE_SERIAL_AFTER_ZERO, TRACE_SERIAL_COMPLETED,
        TRACE_SERIAL_COMPLETION_GAP_BITS_START, TRACE_SERIAL_POST_ACTIVE,
        TRACE_SERIAL_POST_CONTROL_BITS_START, TRACE_SERIAL_POST_COUNTDOWN_BITS_START,
        TRACE_SERIAL_POST_DATA_BITS_START,
    },
};

pub(super) fn constrain_serial(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_witness_ranges(view, sink)?;
    constrain_post_write_state(view, sink)?;
    constrain_countdown(view, sink)?;
    constrain_halt_serial_guard(view, sink)?;
    constrain_completion_outputs(view, sink)?;
    constrain_interrupt(view, sink)
}

fn constrain_witness_ranges(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for (start, width) in [
        (TRACE_SERIAL_POST_DATA_BITS_START, 8),
        (TRACE_SERIAL_POST_CONTROL_BITS_START, 8),
        (TRACE_SERIAL_POST_COUNTDOWN_BITS_START, 13),
        (TRACE_SERIAL_COMPLETION_GAP_BITS_START, 5),
    ] {
        for bit in 0..width {
            sink.push(boolean(view.value(start + bit)?))?;
        }
    }
    for column in [
        TRACE_SERIAL_POST_ACTIVE,
        TRACE_SERIAL_AFTER_ZERO,
        TRACE_SERIAL_COMPLETED,
    ] {
        sink.push(boolean(view.value(column)?))?;
    }
    constrain_countdown_range(view, sink, TRACE_SERIAL_POST_COUNTDOWN_BITS_START)?;
    constrain_countdown_range(view, sink, TRACE_AFTER_DMG_HIGH_BITS_START + 48)
}

fn constrain_countdown_range(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    start: usize,
) -> Result<(), UniformError> {
    for bit in 0..12 {
        sink.push(view.value(start + 12)? * view.value(start + bit)?)?;
    }
    if start == TRACE_AFTER_DMG_HIGH_BITS_START + 48 {
        for bit in 13..16 {
            sink.push(view.value(start + bit)?)?;
        }
    }
    Ok(())
}

fn constrain_post_write_state(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_post_byte(
        view,
        sink,
        0x01,
        TRACE_BEFORE_DMG_LOW_BITS_START,
        TRACE_SERIAL_POST_DATA_BITS_START,
    )?;
    constrain_post_byte(
        view,
        sink,
        0x02,
        TRACE_BEFORE_DMG_LOW_BITS_START + 8,
        TRACE_SERIAL_POST_CONTROL_BITS_START,
    )?;
    let before = packed_bits(view, TRACE_BEFORE_DMG_HIGH_BITS_START + 48, 16)?;
    let after = packed_bits(view, TRACE_SERIAL_POST_COUNTDOWN_BITS_START, 13)?;
    let mut delta = NativeField::from_u64(0);
    for slot in 0..TRACE_BUS_SLOTS {
        let write = write_selector(view, slot, 0x02)?;
        let start = TRACE_BUS_VALUE_BITS_START + slot * 8;
        let starts_transfer = view.value(start)? * view.value(start + 7)?;
        delta += write * (NativeField::from_u64(4096) * starts_transfer - before);
    }
    sink.push(after - before - delta)
}

fn constrain_post_byte(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    address: u8,
    before_start: usize,
    post_start: usize,
) -> Result<(), UniformError> {
    let before = packed_bits(view, before_start, 8)?;
    let post = packed_bits(view, post_start, 8)?;
    let mut delta = NativeField::from_u64(0);
    for slot in 0..TRACE_BUS_SLOTS {
        delta += write_selector(view, slot, address)?
            * (bus_field(view, slot, BUS_VALUE_OFFSET)? - before);
    }
    sink.push(post - before - delta)
}

fn constrain_countdown(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let post = packed_bits(view, TRACE_SERIAL_POST_COUNTDOWN_BITS_START, 13)?;
    let after = packed_bits(view, TRACE_AFTER_DMG_HIGH_BITS_START + 48, 16)?;
    let active = view.value(TRACE_SERIAL_POST_ACTIVE)?;
    let after_zero = view.value(TRACE_SERIAL_AFTER_ZERO)?;
    let completed = view.value(TRACE_SERIAL_COMPLETED)?;
    sink.push(active - (one - zero_from_bits(view, TRACE_SERIAL_POST_COUNTDOWN_BITS_START, 13)?))?;
    sink.push(after_zero - zero_from_bits(view, TRACE_AFTER_DMG_HIGH_BITS_START + 48, 13)?)?;
    sink.push(completed - active * after_zero)?;
    let ticks = NativeField::from_u64(4) * view.value(TRACE_CYCLE_INCREMENT)?;
    sink.push(after - post + active * (one - completed) * ticks + completed * post)?;
    constrain_completion_boundary(view, sink, post, active, completed, ticks)
}

fn constrain_completion_boundary(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    post: NativeField,
    active: NativeField,
    completed: NativeField,
    ticks: NativeField,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let advancing = view.mode(INSTRUCTION_MODE)?
        + view.mode(HALT_IDLE_MODE)?
        + view.mode(INTERRUPT_MODE)?
        + view.mode(HALT_UNTIL_SERIAL_MODE)?;
    let quiet_long = view.mode(HALT_UNTIL_VBLANK_MODE)? + view.mode(HALT_UNTIL_TIMER_MODE)?;
    let gap = packed_bits(view, TRACE_SERIAL_COMPLETION_GAP_BITS_START, 5)?;
    sink.push((one - completed) * gap)?;
    sink.push(advancing * completed * (gap - ticks + post))?;
    sink.push(quiet_long * active)?;
    sink.push(quiet_long * view.value(TRACE_SERIAL_POST_CONTROL_BITS_START + 7)?)
}

fn constrain_halt_serial_guard(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let selected = view.mode(HALT_UNTIL_SERIAL_MODE)?;
    sink.push(selected * (view.value(TRACE_SERIAL_COMPLETED)? - one))?;
    sink.push(selected * packed_bits(view, TRACE_SERIAL_COMPLETION_GAP_BITS_START, 5)?)?;
    sink.push(selected * (view.value(TRACE_SERIAL_POST_CONTROL_BITS_START)? - one))?;
    sink.push(selected * (view.value(TRACE_SERIAL_POST_CONTROL_BITS_START + 7)? - one))?;
    sink.push(selected * (view.value(TRACE_BEFORE_INTERRUPT_ENABLE_BITS_START + 3)? - one))?;
    sink.push(selected * view.value(TRACE_BEFORE_DMG_LOW_BITS_START + 39)?)
}

fn constrain_completion_outputs(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let completed = view.value(TRACE_SERIAL_COMPLETED)?;
    let post_data = packed_bits(view, TRACE_SERIAL_POST_DATA_BITS_START, 8)?;
    let after_data = packed_bits(view, TRACE_AFTER_DMG_LOW_BITS_START, 8)?;
    sink.push(after_data - post_data - completed * (NativeField::from_u64(0xff) - post_data))?;
    let post_control = packed_bits(view, TRACE_SERIAL_POST_CONTROL_BITS_START, 8)?;
    let after_control = packed_bits(view, TRACE_AFTER_DMG_LOW_BITS_START + 8, 8)?;
    sink.push(
        after_control - post_control
            + NativeField::from_u64(128)
                * completed
                * view.value(TRACE_SERIAL_POST_CONTROL_BITS_START + 7)?,
    )
}

fn constrain_interrupt(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let initial = view.value(TRACE_BEFORE_INTERRUPT_REQUEST_BITS_START + 3)?
        - view.value(TRACE_INTERRUPT_START + 3)?;
    let mut after_write = initial;
    for slot in 0..TRACE_BUS_SLOTS {
        let write = write_selector(view, slot, 0x0f)?;
        let written = view.value(TRACE_BUS_VALUE_BITS_START + slot * 8 + 3)?;
        after_write += write * (written - initial);
    }
    let completed = view.value(TRACE_SERIAL_COMPLETED)?;
    let expected = after_write + (one - after_write) * completed;
    sink.push(view.value(TRACE_AFTER_INTERRUPT_REQUEST_BITS_START + 3)? - expected)
}

fn write_selector(
    view: &RowView<'_>,
    slot: usize,
    address: u8,
) -> Result<NativeField, UniformError> {
    Ok(bus_kind(view, slot, 12)? * low_selector(view, slot, address)?)
}

fn low_selector(
    view: &RowView<'_>,
    slot: usize,
    expected: u8,
) -> Result<NativeField, UniformError> {
    view.low_address_selector(slot, expected)
}

fn bus_kind(view: &RowView<'_>, slot: usize, code: u8) -> Result<NativeField, UniformError> {
    view.bus_kind_selector(slot, code)
}
