//! Exact DMG timer writes, bounded ticks, reload pipeline, divider, and IF bit.

use akita_pcs::Ring;

use super::{
    BUS_VALUE_OFFSET, ConstraintSink, RowView, bit_selector, boolean, bus_field, bus_kind_bits,
    packed_bits, zero_from_bits,
};
use crate::{
    NativeField, TRACE_BUS_ADDRESS_BITS_START, TRACE_BUS_SLOTS, TRACE_BUS_VALUE_BITS_START,
    TRACE_CYCLE_INCREMENT, TRACE_INTERRUPT_START, UniformError,
    trace::device::{
        TRACE_AFTER_DMG_LOW_BITS_START, TRACE_AFTER_INTERRUPT_REQUEST_BITS_START,
        TRACE_BEFORE_INTERRUPT_REQUEST_BITS_START, TRACE_BEFORE_TIMER_COUNTER_BITS_START,
        TRACE_BEFORE_TIMER_DIV_BITS_START, TRACE_BEFORE_TIMER_PHASE_BITS_START,
        TRACE_TIMER_AFTER_FF05_BITS_START, TRACE_TIMER_LONG_QUOTIENT_BITS_START,
        TRACE_TIMER_M_CYCLE_ACTIVE_START, TRACE_TIMER_PHASE_FIVE, TRACE_TIMER_POST_STATE_START,
        TRACE_TIMER_STAGE_START, TRACE_TIMER_STAGE_WIDTH,
    },
};

const STATE_TIMER_DIV: usize = 27;
const STATE_TIMER_COUNTER: usize = 28;
const STATE_TIMER_PHASE: usize = 29;
const STATE_TIMER_LATCH: usize = 30;
const INSTRUCTION_MODE: usize = 0;
const HALT_IDLE_MODE: usize = 1;
const HALT_UNTIL_VBLANK_MODE: usize = 2;
const BLUE_SOUND_WAIT_MODE: usize = 3;
const BLUE_DELAY_LOOP_MODE: usize = 4;
const BLUE_DMA_WAIT_MODE: usize = 5;
const INTERRUPT_MODE: usize = 8;

pub(super) fn constrain_timer(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_ranges(view, sink)?;
    constrain_cycle_selectors(view, sink)?;
    constrain_post_write(view, sink)?;
    for tick in 0..24 {
        constrain_tick(view, sink, tick)?;
    }
    constrain_final_state(view, sink)
}

fn constrain_ranges(view: &RowView<'_>, sink: &mut ConstraintSink<'_>) -> Result<(), UniformError> {
    constrain_timer_state_range(view, sink, TRACE_TIMER_POST_STATE_START, false)?;
    for bit in 0..8 {
        sink.push(boolean(
            view.value(TRACE_TIMER_AFTER_FF05_BITS_START + bit)?,
        ))?;
    }
    for tick in 0..24 {
        constrain_timer_state_range(view, sink, stage_start(tick), true)?;
    }
    for bit in 0..5 {
        sink.push(boolean(
            view.value(TRACE_TIMER_LONG_QUOTIENT_BITS_START + bit)?,
        ))?;
    }
    Ok(())
}

fn constrain_timer_state_range(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    start: usize,
    includes_reload: bool,
) -> Result<(), UniformError> {
    for bit in 0..29 {
        sink.push(boolean(view.value(start + bit)?))?;
    }
    constrain_phase_range(view, sink, start + 24)?;
    if includes_reload {
        for bit in 29..41 {
            sink.push(boolean(view.value(start + bit)?))?;
        }
        constrain_phase_range(view, sink, start + 37)?;
    }
    Ok(())
}

fn constrain_phase_range(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    start: usize,
) -> Result<(), UniformError> {
    sink.push(view.value(start + 2)? * view.value(start + 1)?)
}

fn constrain_cycle_selectors(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let regular =
        view.mode(INSTRUCTION_MODE)? + view.mode(HALT_IDLE_MODE)? + view.mode(INTERRUPT_MODE)?;
    let mut sum = NativeField::from_u64(0);
    let mut prior = NativeField::from_u64(1);
    for cycle in 0..6 {
        let active = view.value(TRACE_TIMER_M_CYCLE_ACTIVE_START + cycle)?;
        sink.push(boolean(active))?;
        sink.push(active * (NativeField::from_u64(1) - prior))?;
        sum += active;
        prior = active;
    }
    sink.push(sum - regular * view.value(TRACE_CYCLE_INCREMENT)?)
}

fn constrain_post_write(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_post_divider(view, sink)?;
    constrain_post_counter(view, sink)?;
    constrain_post_phase(view, sink)?;
    sink.push(view.value(TRACE_TIMER_POST_STATE_START + 27)? - view.before(STATE_TIMER_LATCH)?)?;
    constrain_post_interrupt(view, sink)
}

fn constrain_post_divider(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let before = packed_bits(view, TRACE_BEFORE_TIMER_DIV_BITS_START, 16)?;
    let post = packed_bits(view, TRACE_TIMER_POST_STATE_START, 16)?;
    let write = event_selector(view, 0x04)?;
    sink.push(post - before * (NativeField::from_u64(1) - write))
}

fn constrain_post_counter(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let before = packed_bits(view, TRACE_BEFORE_TIMER_COUNTER_BITS_START, 8)?;
    let modulo_before = packed_bits(
        view,
        crate::trace::device::TRACE_BEFORE_DMG_LOW_BITS_START + 16,
        8,
    )?;
    let phase_five = view.value(TRACE_TIMER_PHASE_FIVE)?;
    let mid = packed_bits(view, TRACE_TIMER_AFTER_FF05_BITS_START, 8)?;
    let mut first_delta = NativeField::from_u64(0);
    for slot in 0..TRACE_BUS_SLOTS {
        let write = write_selector(view, slot, 0x05)?;
        let written = bus_field(view, slot, BUS_VALUE_OFFSET)?;
        let replacement = phase_five * modulo_before + (one - phase_five) * written;
        first_delta += write * (replacement - before);
    }
    sink.push(mid - before - first_delta)?;
    let post = packed_bits(view, TRACE_TIMER_POST_STATE_START + 16, 8)?;
    let mut second_delta = NativeField::from_u64(0);
    for slot in 0..TRACE_BUS_SLOTS {
        let write = write_selector(view, slot, 0x06)?;
        second_delta += write * phase_five * (bus_field(view, slot, BUS_VALUE_OFFSET)? - mid);
    }
    sink.push(post - mid - second_delta)
}

fn constrain_post_phase(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let before = packed_bits(view, TRACE_BEFORE_TIMER_PHASE_BITS_START, 3)?;
    let post = packed_bits(view, TRACE_TIMER_POST_STATE_START + 24, 3)?;
    let write = event_selector(view, 0x05)?;
    let phase_five = view.value(TRACE_TIMER_PHASE_FIVE)?;
    sink.push(post - before + write * (one - phase_five) * before)
}

fn constrain_post_interrupt(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let initial = view.value(TRACE_BEFORE_INTERRUPT_REQUEST_BITS_START + 2)?
        - view.value(TRACE_INTERRUPT_START + 2)?;
    let mut post = initial;
    for slot in 0..TRACE_BUS_SLOTS {
        let write = write_selector(view, slot, 0x0f)?;
        let written = view.value(TRACE_BUS_VALUE_BITS_START + slot * 8 + 2)?;
        post += write * (written - initial);
    }
    sink.push(view.value(TRACE_TIMER_POST_STATE_START + 28)? - post)
}

fn constrain_tick(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    tick: usize,
) -> Result<(), UniformError> {
    let current = if tick == 0 {
        TRACE_TIMER_POST_STATE_START
    } else {
        stage_start(tick - 1)
    };
    let next = stage_start(tick);
    let active = view.value(TRACE_TIMER_M_CYCLE_ACTIVE_START + tick / 4)?;
    constrain_reload(view, sink, current, next)?;
    constrain_divider_tick(view, sink, current, next, active)?;
    let detector = detector_input(view, next)?;
    let falling = view.value(current + 27)? * (NativeField::from_u64(1) - detector);
    constrain_counter_tick(view, sink, current, next, active, falling)?;
    constrain_latch_and_interrupt(view, sink, current, next, active, detector)
}

fn constrain_reload(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    current: usize,
    next: usize,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let phase = packed_bits(view, current + 24, 3)?;
    let phase_five = fixed_selector(view, current + 24, 3, 5)?;
    let phase_nonzero = one - zero_from_bits(view, current + 24, 3)?;
    let counter = packed_bits(view, current + 16, 8)?;
    let modulo = packed_bits(view, TRACE_AFTER_DMG_LOW_BITS_START + 16, 8)?;
    let reload_counter = packed_bits(view, next + 29, 8)?;
    let reload_phase = packed_bits(view, next + 37, 3)?;
    sink.push(reload_counter - counter - phase_five * (modulo - counter))?;
    sink.push(reload_phase - phase - phase_nonzero * (one - phase_five) + phase_five * phase)
}

fn constrain_divider_tick(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    current: usize,
    next: usize,
    active: NativeField,
) -> Result<(), UniformError> {
    let before = packed_bits(view, current, 16)?;
    let after = packed_bits(view, next, 16)?;
    let wrap = view.value(next + 40)?;
    sink.push(boolean(wrap))?;
    sink.push(wrap - fixed_selector(view, current, 16, u16::MAX.into())?)?;
    sink.push(after - before - active + NativeField::from_u64(65_536) * active * wrap)
}

fn constrain_counter_tick(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    current: usize,
    next: usize,
    active: NativeField,
    falling: NativeField,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let counter = packed_bits(view, current + 16, 8)?;
    let phase = packed_bits(view, current + 24, 3)?;
    let reload_counter = packed_bits(view, next + 29, 8)?;
    let reload_phase = packed_bits(view, next + 37, 3)?;
    let counter_full = fixed_selector(view, next + 29, 8, 0xff)?;
    let overflow = falling * counter_full;
    let after_counter = packed_bits(view, next + 16, 8)?;
    let after_phase = packed_bits(view, next + 24, 3)?;
    sink.push(
        after_counter
            - counter
            - active * (reload_counter - counter + falling - NativeField::from_u64(256) * overflow),
    )?;
    sink.push(
        after_phase - phase - active * (reload_phase - phase + overflow * (one - reload_phase)),
    )
}

fn constrain_latch_and_interrupt(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    current: usize,
    next: usize,
    active: NativeField,
    detector: NativeField,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let latch = view.value(current + 27)?;
    sink.push(view.value(next + 27)? - latch - active * (detector - latch))?;
    let interrupt = view.value(current + 28)?;
    let phase_five = fixed_selector(view, current + 24, 3, 5)?;
    sink.push(view.value(next + 28)? - interrupt - active * (one - interrupt) * phase_five)
}

fn detector_input(view: &RowView<'_>, divider_start: usize) -> Result<NativeField, UniformError> {
    let control = TRACE_AFTER_DMG_LOW_BITS_START + 24;
    let bit_zero = view.value(control)?;
    let bit_one = view.value(control + 1)?;
    let one = NativeField::from_u64(1);
    let selected = (one - bit_zero) * (one - bit_one) * view.value(divider_start + 9)?
        + bit_zero * (one - bit_one) * view.value(divider_start + 3)?
        + (one - bit_zero) * bit_one * view.value(divider_start + 5)?
        + bit_zero * bit_one * view.value(divider_start + 7)?;
    Ok(view.value(control + 2)? * selected)
}

fn constrain_final_state(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let long = view.mode(HALT_UNTIL_VBLANK_MODE)?
        + view.mode(BLUE_SOUND_WAIT_MODE)?
        + view.mode(BLUE_DELAY_LOOP_MODE)?
        + view.mode(BLUE_DMA_WAIT_MODE)?;
    let nonlong = NativeField::from_u64(1) - long;
    let last = stage_start(23);
    for (state, offset, width) in [
        (STATE_TIMER_DIV, 0, 16),
        (STATE_TIMER_COUNTER, 16, 8),
        (STATE_TIMER_PHASE, 24, 3),
    ] {
        sink.push(nonlong * (view.after(state)? - packed_bits(view, last + offset, width)?))?;
    }
    sink.push(nonlong * (view.after(STATE_TIMER_LATCH)? - view.value(last + 27)?))?;
    sink.push(
        nonlong
            * (view.value(TRACE_AFTER_INTERRUPT_REQUEST_BITS_START + 2)?
                - view.value(last + 28)?),
    )?;
    constrain_long_transition(view, sink, long)
}

fn constrain_long_transition(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    long: NativeField,
) -> Result<(), UniformError> {
    let quotient = packed_bits(view, TRACE_TIMER_LONG_QUOTIENT_BITS_START, 5)?;
    sink.push((NativeField::from_u64(1) - long) * quotient)?;
    sink.push(long * view.value(TRACE_AFTER_DMG_LOW_BITS_START + 26)?)?;
    sink.push(long * packed_bits(view, TRACE_TIMER_POST_STATE_START + 24, 3)?)?;
    sink.push(long * view.value(TRACE_TIMER_POST_STATE_START + 27)?)?;
    let post_div = packed_bits(view, TRACE_TIMER_POST_STATE_START, 16)?;
    sink.push(
        long * (view.after(STATE_TIMER_DIV)?
            - post_div
            - NativeField::from_u64(4) * view.value(TRACE_CYCLE_INCREMENT)?
            + NativeField::from_u64(65_536) * quotient),
    )?;
    sink.push(
        long * (view.after(STATE_TIMER_COUNTER)?
            - packed_bits(view, TRACE_TIMER_POST_STATE_START + 16, 8)?),
    )?;
    sink.push(long * view.after(STATE_TIMER_PHASE)?)?;
    sink.push(long * view.after(STATE_TIMER_LATCH)?)?;
    sink.push(
        long * (view.value(TRACE_AFTER_INTERRUPT_REQUEST_BITS_START + 2)?
            - view.value(TRACE_TIMER_POST_STATE_START + 28)?),
    )
}

const fn stage_start(tick: usize) -> usize {
    TRACE_TIMER_STAGE_START + tick * TRACE_TIMER_STAGE_WIDTH
}

fn event_selector(view: &RowView<'_>, address: u8) -> Result<NativeField, UniformError> {
    let mut selected = NativeField::from_u64(0);
    for slot in 0..TRACE_BUS_SLOTS {
        selected += write_selector(view, slot, address)?;
    }
    Ok(selected)
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
    fixed_selector(
        view,
        TRACE_BUS_ADDRESS_BITS_START + slot * 16,
        8,
        expected.into(),
    )
}

fn fixed_selector(
    view: &RowView<'_>,
    start: usize,
    width: usize,
    expected: u64,
) -> Result<NativeField, UniformError> {
    let one = NativeField::from_u64(1);
    (0..width).try_fold(one, |selector, bit| {
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
