//! Compressed LCD position, frame quotient, VBlank crossing, and IF-zero relation.

use akita_pcs::Ring;

use super::{
    ConstraintSink, HALT_IDLE_MODE, HALT_UNTIL_VBLANK_MODE, INSTRUCTION_MODE, INTERRUPT_MODE,
    RowView, boolean, packed_bits,
};
use crate::{
    NativeField, TRACE_BUS_SLOTS, TRACE_BUS_VALUE_BITS_START, TRACE_CYCLE_INCREMENT,
    TRACE_INTERRUPT_START, UniformError,
    trace::device::{
        TRACE_AFTER_DMG_LOW_BITS_START, TRACE_AFTER_INTERRUPT_REQUEST_BITS_START,
        TRACE_AFTER_PPU_DOT_BITS_START, TRACE_AFTER_PPU_LINE_BITS_START,
        TRACE_BEFORE_DMG_LOW_BITS_START, TRACE_BEFORE_INTERRUPT_ENABLE_BITS_START,
        TRACE_BEFORE_INTERRUPT_REQUEST_BITS_START, TRACE_BEFORE_PPU_DOT_BITS_START,
        TRACE_BEFORE_PPU_LINE_BITS_START, TRACE_PPU_AFTER_COINCIDENCE, TRACE_PPU_AFTER_DOT_LT_80,
        TRACE_PPU_AFTER_DOT_LT_252, TRACE_PPU_AFTER_VBLANK, TRACE_PPU_DOT_LT_80,
        TRACE_PPU_DOT_LT_252, TRACE_PPU_FRAME_QUOTIENT_BITS_START, TRACE_PPU_LCD_DISABLE,
        TRACE_PPU_POST_COINCIDENCE, TRACE_PPU_POST_DOT_BITS_START, TRACE_PPU_POST_DOT_LT_80,
        TRACE_PPU_POST_DOT_LT_252, TRACE_PPU_POST_LINE_BITS_START, TRACE_PPU_POST_VBLANK,
        TRACE_PPU_STAT_AFTER, TRACE_PPU_STAT_BEFORE, TRACE_PPU_STAT_BOUNDARY_CROSSED,
        TRACE_PPU_STAT_EVENT, TRACE_PPU_STAT_GAP_BITS_START, TRACE_PPU_STAT_POST_WRITE,
        TRACE_PPU_STAT_RELEVANT_WRITE, TRACE_PPU_VBLANK, TRACE_PPU_VBLANK_EVENT,
        TRACE_PPU_VBLANK_GAP_BITS_START,
    },
};

const STATE_PPU_LINE: usize = 25;
const STATE_PPU_DOT: usize = 26;
const FRAME_T_CYCLES: u64 = 70_224;
const VBLANK_T_CYCLE: u64 = 65_664;
#[derive(Clone, Copy)]
struct StatColumns {
    register_start: usize,
    vblank: usize,
    below_80: usize,
    below_252: usize,
    coincidence: usize,
    signal: usize,
}

pub(super) fn constrain_ppu(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_witness_ranges(view, sink)?;
    constrain_disabled_state(view, sink)?;
    constrain_position(view, sink)?;
    constrain_vblank_event(view, sink)?;
    constrain_vblank_interrupt(view, sink)?;
    constrain_halt_vblank_guard(view, sink)?;
    constrain_stat(view, sink)
}

fn constrain_witness_ranges(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for (start, width) in [
        (TRACE_AFTER_PPU_LINE_BITS_START, 8),
        (TRACE_AFTER_PPU_DOT_BITS_START, 9),
        (TRACE_PPU_FRAME_QUOTIENT_BITS_START, 5),
        (TRACE_PPU_VBLANK_GAP_BITS_START, 21),
        (TRACE_PPU_POST_LINE_BITS_START, 8),
        (TRACE_PPU_POST_DOT_BITS_START, 9),
        (TRACE_PPU_STAT_GAP_BITS_START, 9),
    ] {
        for bit in 0..width {
            sink.push(boolean(view.value(start + bit)?))?;
        }
    }
    for column in [
        TRACE_PPU_LCD_DISABLE,
        TRACE_PPU_VBLANK_EVENT,
        TRACE_PPU_POST_VBLANK,
        TRACE_PPU_POST_DOT_LT_80,
        TRACE_PPU_POST_DOT_LT_252,
        TRACE_PPU_POST_COINCIDENCE,
        TRACE_PPU_AFTER_VBLANK,
        TRACE_PPU_AFTER_DOT_LT_80,
        TRACE_PPU_AFTER_DOT_LT_252,
        TRACE_PPU_AFTER_COINCIDENCE,
        TRACE_PPU_STAT_BEFORE,
        TRACE_PPU_STAT_POST_WRITE,
        TRACE_PPU_STAT_AFTER,
        TRACE_PPU_STAT_RELEVANT_WRITE,
        TRACE_PPU_STAT_BOUNDARY_CROSSED,
        TRACE_PPU_STAT_EVENT,
    ] {
        sink.push(boolean(view.value(column)?))?;
    }
    constrain_line_range(view, sink, TRACE_AFTER_PPU_LINE_BITS_START)?;
    constrain_dot_range(view, sink, TRACE_AFTER_PPU_DOT_BITS_START)?;
    constrain_line_range(view, sink, TRACE_PPU_POST_LINE_BITS_START)?;
    constrain_dot_range(view, sink, TRACE_PPU_POST_DOT_BITS_START)?;
    sink.push(
        view.after(STATE_PPU_LINE)? - packed_bits(view, TRACE_AFTER_PPU_LINE_BITS_START, 8)?,
    )?;
    sink.push(view.after(STATE_PPU_DOT)? - packed_bits(view, TRACE_AFTER_PPU_DOT_BITS_START, 9)?)
}

fn constrain_line_range(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    start: usize,
) -> Result<(), UniformError> {
    sink.push(view.value(start + 7)? * view.value(start + 6)?)?;
    sink.push(view.value(start + 7)? * view.value(start + 5)?)?;
    let bit_two_or_one = or(view.value(start + 2)?, view.value(start + 1)?);
    sink.push(
        view.value(start + 7)? * view.value(start + 4)? * view.value(start + 3)? * bit_two_or_one,
    )
}

fn constrain_dot_range(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    start: usize,
) -> Result<(), UniformError> {
    for bit in [5_usize, 4, 3] {
        sink.push(
            view.value(start + 8)?
                * view.value(start + 7)?
                * view.value(start + 6)?
                * view.value(start + bit)?,
        )?;
    }
    Ok(())
}

fn constrain_disabled_state(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let before_enabled = view.value(TRACE_BEFORE_DMG_LOW_BITS_START + 39)?;
    sink.push((one - before_enabled) * view.before(STATE_PPU_LINE)?)?;
    sink.push((one - before_enabled) * view.before(STATE_PPU_DOT)?)?;
    let mut disable = NativeField::from_u64(0);
    for slot in 0..TRACE_BUS_SLOTS {
        let selected = write_selector(view, slot, 0x40)?;
        let enabled = view.value(TRACE_BUS_VALUE_BITS_START + slot * 8 + 7)?;
        disable += selected * (one - enabled);
    }
    sink.push(view.value(TRACE_PPU_LCD_DISABLE)? - disable)
}

fn constrain_position(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_post_write_position(view, sink)?;
    let enabled = view.value(TRACE_AFTER_DMG_LOW_BITS_START + 39)?;
    let post = position(
        view,
        TRACE_PPU_POST_LINE_BITS_START,
        TRACE_PPU_POST_DOT_BITS_START,
    )?;
    let total = post + NativeField::from_u64(4) * view.value(TRACE_CYCLE_INCREMENT)?;
    let after = position(
        view,
        TRACE_AFTER_PPU_LINE_BITS_START,
        TRACE_AFTER_PPU_DOT_BITS_START,
    )?;
    let quotient = packed_bits(view, TRACE_PPU_FRAME_QUOTIENT_BITS_START, 5)?;
    sink.push(after - enabled * (total - NativeField::from_u64(FRAME_T_CYCLES) * quotient))?;
    sink.push((NativeField::from_u64(1) - enabled) * quotient)
}

fn constrain_post_write_position(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let keep = NativeField::from_u64(1) - view.value(TRACE_PPU_LCD_DISABLE)?;
    for (before, post, width) in [
        (
            TRACE_BEFORE_PPU_LINE_BITS_START,
            TRACE_PPU_POST_LINE_BITS_START,
            8,
        ),
        (
            TRACE_BEFORE_PPU_DOT_BITS_START,
            TRACE_PPU_POST_DOT_BITS_START,
            9,
        ),
    ] {
        for bit in 0..width {
            sink.push(view.value(post + bit)? - keep * view.value(before + bit)?)?;
        }
    }
    Ok(())
}

fn constrain_vblank_event(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let enabled = view.value(TRACE_AFTER_DMG_LOW_BITS_START + 39)?;
    let post = position(
        view,
        TRACE_PPU_POST_LINE_BITS_START,
        TRACE_PPU_POST_DOT_BITS_START,
    )?;
    let total = post + NativeField::from_u64(4) * view.value(TRACE_CYCLE_INCREMENT)?;
    let post_vblank = view.value(TRACE_PPU_POST_VBLANK)?;
    let next =
        NativeField::from_u64(VBLANK_T_CYCLE) + NativeField::from_u64(FRAME_T_CYCLES) * post_vblank;
    let event = view.value(TRACE_PPU_VBLANK_EVENT)?;
    let gap = packed_bits(view, TRACE_PPU_VBLANK_GAP_BITS_START, 21)?;
    let crossed_gap = total - next;
    let before_gap = next - total - one;
    sink.push(enabled * (gap - event * crossed_gap - (one - event) * before_gap))?;
    sink.push((one - enabled) * event)?;
    sink.push((one - enabled) * gap)?;
    sink.push(view.mode(HALT_UNTIL_VBLANK_MODE)? * (total - next))
}

fn constrain_halt_vblank_guard(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let selected = view.mode(HALT_UNTIL_VBLANK_MODE)?;
    sink.push(selected * (view.value(TRACE_BEFORE_DMG_LOW_BITS_START + 39)? - one))?;
    sink.push(selected * (view.value(TRACE_BEFORE_INTERRUPT_ENABLE_BITS_START)? - one))?;
    sink.push(selected * view.value(TRACE_BEFORE_INTERRUPT_ENABLE_BITS_START + 4)?)
}

fn constrain_vblank_interrupt(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let initial = view.value(TRACE_BEFORE_INTERRUPT_REQUEST_BITS_START)?
        - view.value(TRACE_INTERRUPT_START)?;
    let mut post = initial;
    for slot in 0..TRACE_BUS_SLOTS {
        let write = write_selector(view, slot, 0x0f)?;
        let written = view.value(TRACE_BUS_VALUE_BITS_START + slot * 8)?;
        post += write * (written - initial);
    }
    let event = view.value(TRACE_PPU_VBLANK_EVENT)?;
    let expected = post + (one - post) * event;
    sink.push(view.value(TRACE_AFTER_INTERRUPT_REQUEST_BITS_START)? - expected)
}

fn constrain_stat(view: &RowView<'_>, sink: &mut ConstraintSink<'_>) -> Result<(), UniformError> {
    constrain_position_predicates(
        view,
        sink,
        TRACE_PPU_POST_LINE_BITS_START,
        TRACE_PPU_POST_DOT_BITS_START,
        TRACE_PPU_POST_VBLANK,
        TRACE_PPU_POST_DOT_LT_80,
        TRACE_PPU_POST_DOT_LT_252,
    )?;
    constrain_position_predicates(
        view,
        sink,
        TRACE_AFTER_PPU_LINE_BITS_START,
        TRACE_AFTER_PPU_DOT_BITS_START,
        TRACE_PPU_AFTER_VBLANK,
        TRACE_PPU_AFTER_DOT_LT_80,
        TRACE_PPU_AFTER_DOT_LT_252,
    )?;
    constrain_coincidence(
        view,
        sink,
        TRACE_PPU_POST_LINE_BITS_START,
        TRACE_PPU_POST_COINCIDENCE,
    )?;
    constrain_coincidence(
        view,
        sink,
        TRACE_AFTER_PPU_LINE_BITS_START,
        TRACE_PPU_AFTER_COINCIDENCE,
    )?;
    constrain_stat_signals(view, sink)?;
    constrain_stat_event(view, sink)?;
    constrain_stat_interrupt(view, sink)
}

fn constrain_position_predicates(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    line: usize,
    dot: usize,
    vblank: usize,
    below_80: usize,
    below_252: usize,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    sink.push(view.value(vblank)? - view.value(line + 7)? * view.value(line + 4)?)?;
    let above_79 = view.value(dot + 6)? * or(view.value(dot + 5)?, view.value(dot + 4)?);
    let expected_80 =
        (one - view.value(dot + 8)?) * (one - view.value(dot + 7)?) * (one - above_79);
    sink.push(view.value(below_80)? - expected_80)?;
    let mut at_least_252_low = one;
    for bit in 2..=7 {
        at_least_252_low *= view.value(dot + bit)?;
    }
    let expected_252 = (one - view.value(dot + 8)?) * (one - at_least_252_low);
    sink.push(view.value(below_252)? - expected_252)
}

fn constrain_coincidence(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    line_start: usize,
    coincidence: usize,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let two = NativeField::from_u64(2);
    let mut equal = one;
    for bit in 0..8 {
        let line = view.value(line_start + bit)?;
        let compare =
            view.value(crate::trace::device::TRACE_AFTER_DMG_HIGH_BITS_START + 40 + bit)?;
        equal *= one - line - compare + two * line * compare;
    }
    sink.push(view.value(coincidence)? - equal)
}

fn constrain_stat_signals(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_stat_signal(
        view,
        sink,
        StatColumns {
            register_start: TRACE_BEFORE_DMG_LOW_BITS_START,
            vblank: TRACE_PPU_VBLANK,
            below_80: TRACE_PPU_DOT_LT_80,
            below_252: TRACE_PPU_DOT_LT_252,
            coincidence: crate::trace::device::TRACE_PPU_COINCIDENCE,
            signal: TRACE_PPU_STAT_BEFORE,
        },
    )?;
    constrain_stat_signal(
        view,
        sink,
        StatColumns {
            register_start: TRACE_AFTER_DMG_LOW_BITS_START,
            vblank: TRACE_PPU_POST_VBLANK,
            below_80: TRACE_PPU_POST_DOT_LT_80,
            below_252: TRACE_PPU_POST_DOT_LT_252,
            coincidence: TRACE_PPU_POST_COINCIDENCE,
            signal: TRACE_PPU_STAT_POST_WRITE,
        },
    )?;
    constrain_stat_signal(
        view,
        sink,
        StatColumns {
            register_start: TRACE_AFTER_DMG_LOW_BITS_START,
            vblank: TRACE_PPU_AFTER_VBLANK,
            below_80: TRACE_PPU_AFTER_DOT_LT_80,
            below_252: TRACE_PPU_AFTER_DOT_LT_252,
            coincidence: TRACE_PPU_AFTER_COINCIDENCE,
            signal: TRACE_PPU_STAT_AFTER,
        },
    )
}

fn constrain_stat_signal(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    columns: StatColumns,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let enabled = view.value(columns.register_start + 39)?;
    let vblank = view.value(columns.vblank)?;
    let below_80 = view.value(columns.below_80)?;
    let below_252 = view.value(columns.below_252)?;
    let control = columns.register_start + 40;
    let sources = [
        view.value(control + 3)? * (one - vblank) * (one - below_252),
        view.value(control + 4)? * vblank,
        view.value(control + 5)? * (one - vblank) * below_80,
        view.value(control + 6)? * view.value(columns.coincidence)?,
    ];
    let mut inactive = one;
    for source in sources {
        inactive *= one - source;
    }
    sink.push(view.value(columns.signal)? - enabled * (one - inactive))
}

fn constrain_stat_event(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let regular =
        view.mode(INSTRUCTION_MODE)? + view.mode(HALT_IDLE_MODE)? + view.mode(INTERRUPT_MODE)?;
    let enabled = view.value(TRACE_AFTER_DMG_LOW_BITS_START + 39)?;
    let running = regular * enabled;
    let boundary = view.value(TRACE_PPU_STAT_BOUNDARY_CROSSED)?;
    let gap = packed_bits(view, TRACE_PPU_STAT_GAP_BITS_START, 9)?;
    let dot = packed_bits(view, TRACE_PPU_POST_DOT_BITS_START, 9)?;
    let below_80 = view.value(TRACE_PPU_POST_DOT_LT_80)?;
    let below_252 = view.value(TRACE_PPU_POST_DOT_LT_252)?;
    let middle = (one - below_80) * below_252;
    let distance = NativeField::from_u64(80) * below_80
        + NativeField::from_u64(252) * middle
        + NativeField::from_u64(456) * (one - below_252)
        - dot;
    let elapsed = NativeField::from_u64(4) * view.value(TRACE_CYCLE_INCREMENT)?;
    let crossed_gap = elapsed - distance;
    let before_gap = distance - elapsed - one;
    sink.push(running * (gap - boundary * crossed_gap - (one - boundary) * before_gap))?;
    sink.push((one - running) * boundary)?;
    sink.push((one - running) * gap)?;
    constrain_stat_relevant_write(view, sink)?;
    constrain_long_stat_quiet(view, sink)?;
    let write = view.value(TRACE_PPU_STAT_RELEVANT_WRITE)?
        * (one - view.value(TRACE_PPU_STAT_BEFORE)?)
        * view.value(TRACE_PPU_STAT_POST_WRITE)?;
    let tick = boundary
        * (one - view.value(TRACE_PPU_STAT_POST_WRITE)?)
        * view.value(TRACE_PPU_STAT_AFTER)?;
    sink.push(view.value(TRACE_PPU_STAT_EVENT)? - write - tick + write * tick)
}

fn constrain_stat_relevant_write(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let mut selected = NativeField::from_u64(0);
    for slot in 0..TRACE_BUS_SLOTS {
        for address in [0x40, 0x41, 0x45] {
            selected += write_selector(view, slot, address)?;
        }
    }
    sink.push(view.value(TRACE_PPU_STAT_RELEVANT_WRITE)? - selected)
}

fn constrain_long_stat_quiet(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let long = view.mode(HALT_UNTIL_VBLANK_MODE)?;
    let enabled = view.value(TRACE_AFTER_DMG_LOW_BITS_START + 39)?;
    for bit in 3..=6 {
        sink.push(long * enabled * view.value(TRACE_AFTER_DMG_LOW_BITS_START + 40 + bit)?)?;
    }
    Ok(())
}

fn constrain_stat_interrupt(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let initial = view.value(TRACE_BEFORE_INTERRUPT_REQUEST_BITS_START + 1)?
        - view.value(TRACE_INTERRUPT_START + 1)?;
    let mut post = initial;
    for slot in 0..TRACE_BUS_SLOTS {
        let write = write_selector(view, slot, 0x0f)?;
        let written = view.value(TRACE_BUS_VALUE_BITS_START + slot * 8 + 1)?;
        post += write * (written - initial);
    }
    let event = view.value(TRACE_PPU_STAT_EVENT)?;
    let expected = post + (one - post) * event;
    sink.push(view.value(TRACE_AFTER_INTERRUPT_REQUEST_BITS_START + 1)? - expected)
}

fn position(
    view: &RowView<'_>,
    line_start: usize,
    dot_start: usize,
) -> Result<NativeField, UniformError> {
    Ok(
        NativeField::from_u64(456) * packed_bits(view, line_start, 8)?
            + packed_bits(view, dot_start, 9)?,
    )
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

fn or(left: NativeField, right: NativeField) -> NativeField {
    left + right - left * right
}
