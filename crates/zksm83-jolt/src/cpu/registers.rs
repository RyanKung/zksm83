//! Before-state DMG register ranges, visible values, and MMIO tuple bindings.

use akita_pcs::Ring;

use super::{
    BUS_BEFORE_OFFSET, BUS_VALUE_OFFSET, ConstraintSink, RowView, bit_selector, boolean, bus_field,
    bus_kind_bits, packed_bits,
};
use crate::{
    NativeField, TRACE_BUS_ADDRESS_BITS_START, TRACE_BUS_SLOTS, UniformError,
    trace::device::{
        TRACE_AFTER_DMG_HIGH_BITS_START, TRACE_AFTER_DMG_LOW_BITS_START,
        TRACE_BEFORE_DMA_BITS_START, TRACE_BEFORE_DMG_HIGH_BITS_START,
        TRACE_BEFORE_DMG_LOW_BITS_START, TRACE_BEFORE_PPU_DOT_BITS_START,
        TRACE_BEFORE_PPU_LINE_BITS_START, TRACE_BEFORE_TIMER_COUNTER_BITS_START,
        TRACE_BEFORE_TIMER_DIV_BITS_START, TRACE_BEFORE_TIMER_PHASE_BITS_START,
        TRACE_PPU_COINCIDENCE, TRACE_PPU_DOT_LT_80, TRACE_PPU_DOT_LT_252,
        TRACE_PPU_MODE_BITS_START, TRACE_PPU_VBLANK, TRACE_TIMER_PHASE_FIVE,
    },
};

const STATE_INTERRUPT_REQUEST: usize = 21;
const STATE_INTERRUPT_ENABLE: usize = 22;
const STATE_LOW_REGISTER_PACK: usize = 23;
const STATE_HIGH_REGISTER_PACK: usize = 24;
const STATE_PPU_LINE: usize = 25;
const STATE_PPU_DOT: usize = 26;
const STATE_TIMER_DIV: usize = 27;
const STATE_TIMER_COUNTER: usize = 28;
const STATE_TIMER_PHASE: usize = 29;
const STATE_TIMER_EDGE_LATCH: usize = 30;
const VISIBLE_REGISTER_COUNT: usize = 20;

pub(super) fn constrain_visible_registers(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_register_bits(view, sink)?;
    constrain_timer_and_ppu_ranges(view, sink)?;
    constrain_ppu_predicates(view, sink)?;
    constrain_static_register_writes(view, sink)?;
    constrain_mmio_values(view, sink)
}

fn constrain_register_bits(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for (start, width) in [
        (TRACE_BEFORE_DMG_LOW_BITS_START, 64),
        (TRACE_BEFORE_DMG_HIGH_BITS_START, 64),
        (TRACE_AFTER_DMG_LOW_BITS_START, 64),
        (TRACE_AFTER_DMG_HIGH_BITS_START, 64),
        (TRACE_BEFORE_TIMER_DIV_BITS_START, 16),
        (TRACE_BEFORE_TIMER_COUNTER_BITS_START, 8),
        (TRACE_BEFORE_TIMER_PHASE_BITS_START, 3),
        (TRACE_BEFORE_PPU_LINE_BITS_START, 8),
        (TRACE_BEFORE_PPU_DOT_BITS_START, 9),
    ] {
        constrain_bits(view, sink, start, width)?;
    }
    for (state, start, width) in [
        (STATE_LOW_REGISTER_PACK, TRACE_BEFORE_DMG_LOW_BITS_START, 64),
        (
            STATE_HIGH_REGISTER_PACK,
            TRACE_BEFORE_DMG_HIGH_BITS_START,
            64,
        ),
        (STATE_PPU_LINE, TRACE_BEFORE_PPU_LINE_BITS_START, 8),
        (STATE_PPU_DOT, TRACE_BEFORE_PPU_DOT_BITS_START, 9),
        (STATE_TIMER_DIV, TRACE_BEFORE_TIMER_DIV_BITS_START, 16),
        (
            STATE_TIMER_COUNTER,
            TRACE_BEFORE_TIMER_COUNTER_BITS_START,
            8,
        ),
        (STATE_TIMER_PHASE, TRACE_BEFORE_TIMER_PHASE_BITS_START, 3),
    ] {
        sink.push(view.before(state)? - packed_bits(view, start, width)?)?;
    }
    sink.push(
        view.after(STATE_LOW_REGISTER_PACK)?
            - packed_bits(view, TRACE_AFTER_DMG_LOW_BITS_START, 64)?,
    )?;
    sink.push(
        view.after(STATE_HIGH_REGISTER_PACK)?
            - packed_bits(view, TRACE_AFTER_DMG_HIGH_BITS_START, 64)?,
    )?;
    for start in [
        TRACE_BEFORE_DMG_LOW_BITS_START,
        TRACE_AFTER_DMG_LOW_BITS_START,
    ] {
        for bit in [27_usize, 28, 29, 30, 31, 40, 41, 42, 47] {
            sink.push(view.value(start + bit)?)?;
        }
    }
    sink.push(boolean(view.before(STATE_TIMER_EDGE_LATCH)?))?;
    sink.push(boolean(view.after(STATE_TIMER_EDGE_LATCH)?))
}

fn constrain_static_register_writes(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for (address, before, after, byte_index) in [
        (
            0x06,
            TRACE_BEFORE_DMG_LOW_BITS_START,
            TRACE_AFTER_DMG_LOW_BITS_START,
            2,
        ),
        (
            0x40,
            TRACE_BEFORE_DMG_LOW_BITS_START,
            TRACE_AFTER_DMG_LOW_BITS_START,
            4,
        ),
        (
            0x42,
            TRACE_BEFORE_DMG_LOW_BITS_START,
            TRACE_AFTER_DMG_LOW_BITS_START,
            6,
        ),
        (
            0x43,
            TRACE_BEFORE_DMG_LOW_BITS_START,
            TRACE_AFTER_DMG_LOW_BITS_START,
            7,
        ),
        (
            0x45,
            TRACE_BEFORE_DMG_HIGH_BITS_START,
            TRACE_AFTER_DMG_HIGH_BITS_START,
            5,
        ),
        (
            0x47,
            TRACE_BEFORE_DMG_HIGH_BITS_START,
            TRACE_AFTER_DMG_HIGH_BITS_START,
            0,
        ),
        (
            0x48,
            TRACE_BEFORE_DMG_HIGH_BITS_START,
            TRACE_AFTER_DMG_HIGH_BITS_START,
            1,
        ),
        (
            0x49,
            TRACE_BEFORE_DMG_HIGH_BITS_START,
            TRACE_AFTER_DMG_HIGH_BITS_START,
            2,
        ),
        (
            0x4a,
            TRACE_BEFORE_DMG_HIGH_BITS_START,
            TRACE_AFTER_DMG_HIGH_BITS_START,
            3,
        ),
        (
            0x4b,
            TRACE_BEFORE_DMG_HIGH_BITS_START,
            TRACE_AFTER_DMG_HIGH_BITS_START,
            4,
        ),
    ] {
        constrain_full_byte_write(view, sink, address, before, after, byte_index)?;
    }
    constrain_masked_byte_write(view, sink, 0x07, 3, &[0, 1, 2])?;
    constrain_masked_byte_write(view, sink, 0x41, 5, &[3, 4, 5, 6])
}

fn constrain_full_byte_write(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    address: u8,
    before_start: usize,
    after_start: usize,
    byte_index: usize,
) -> Result<(), UniformError> {
    let before = byte(view, before_start, byte_index)?;
    let after = byte(view, after_start, byte_index)?;
    let mut delta = NativeField::from_u64(0);
    for slot in 0..TRACE_BUS_SLOTS {
        let write = bus_kind(view, slot, 12)? * low_selector(view, slot, address)?;
        delta += write * (bus_field(view, slot, BUS_VALUE_OFFSET)? - before);
    }
    sink.push(after - before - delta)
}

fn constrain_masked_byte_write(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    address: u8,
    byte_index: usize,
    admitted_bits: &[usize],
) -> Result<(), UniformError> {
    let before = byte(view, TRACE_BEFORE_DMG_LOW_BITS_START, byte_index)?;
    let after = byte(view, TRACE_AFTER_DMG_LOW_BITS_START, byte_index)?;
    let mut delta = NativeField::from_u64(0);
    for slot in 0..TRACE_BUS_SLOTS {
        let write = bus_kind(view, slot, 12)? * low_selector(view, slot, address)?;
        let mut written = NativeField::from_u64(0);
        for bit in admitted_bits {
            written += NativeField::from_u64(1 << bit)
                * view.value(crate::TRACE_BUS_VALUE_BITS_START + slot * 8 + bit)?;
        }
        delta += write * (written - before);
    }
    sink.push(after - before - delta)
}

fn constrain_timer_and_ppu_ranges(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let phase = TRACE_BEFORE_TIMER_PHASE_BITS_START;
    sink.push(view.value(phase + 2)? * view.value(phase + 1)?)?;
    let line = TRACE_BEFORE_PPU_LINE_BITS_START;
    sink.push(view.value(line + 7)? * view.value(line + 6)?)?;
    sink.push(view.value(line + 7)? * view.value(line + 5)?)?;
    sink.push(
        view.value(line + 7)?
            * view.value(line + 4)?
            * view.value(line + 3)?
            * or(view.value(line + 2)?, view.value(line + 1)?),
    )?;
    let dot = TRACE_BEFORE_PPU_DOT_BITS_START;
    for bit in [5_usize, 4, 3] {
        sink.push(
            view.value(dot + 8)?
                * view.value(dot + 7)?
                * view.value(dot + 6)?
                * view.value(dot + bit)?,
        )?;
    }
    Ok(())
}

fn constrain_ppu_predicates(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    for column in [
        TRACE_TIMER_PHASE_FIVE,
        TRACE_PPU_VBLANK,
        TRACE_PPU_DOT_LT_80,
        TRACE_PPU_DOT_LT_252,
        TRACE_PPU_MODE_BITS_START,
        TRACE_PPU_MODE_BITS_START + 1,
        TRACE_PPU_COINCIDENCE,
    ] {
        sink.push(boolean(view.value(column)?))?;
    }
    let phase = TRACE_BEFORE_TIMER_PHASE_BITS_START;
    sink.push(
        view.value(TRACE_TIMER_PHASE_FIVE)?
            - view.value(phase)? * (one - view.value(phase + 1)?) * view.value(phase + 2)?,
    )?;
    constrain_ppu_position_predicates(view, sink)?;
    constrain_ppu_mode(view, sink)?;
    constrain_ppu_coincidence(view, sink)
}

fn constrain_ppu_position_predicates(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let line = TRACE_BEFORE_PPU_LINE_BITS_START;
    sink.push(view.value(TRACE_PPU_VBLANK)? - view.value(line + 7)? * view.value(line + 4)?)?;
    let dot = TRACE_BEFORE_PPU_DOT_BITS_START;
    let above_79 = view.value(dot + 6)? * or(view.value(dot + 5)?, view.value(dot + 4)?);
    let below_80 = (one - view.value(dot + 8)?) * (one - view.value(dot + 7)?) * (one - above_79);
    sink.push(view.value(TRACE_PPU_DOT_LT_80)? - below_80)?;
    let mut at_least_252_low = one;
    for bit in 2..=7 {
        at_least_252_low *= view.value(dot + bit)?;
    }
    let below_252 = (one - view.value(dot + 8)?) * (one - at_least_252_low);
    sink.push(view.value(TRACE_PPU_DOT_LT_252)? - below_252)
}

fn constrain_ppu_mode(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let enabled = view.value(TRACE_BEFORE_DMG_LOW_BITS_START + 39)?;
    let vblank = view.value(TRACE_PPU_VBLANK)?;
    let below_80 = view.value(TRACE_PPU_DOT_LT_80)?;
    let below_252 = view.value(TRACE_PPU_DOT_LT_252)?;
    let visible = vblank
        + (one - vblank)
            * (NativeField::from_u64(2) * below_80
                + NativeField::from_u64(3) * (one - below_80) * below_252);
    sink.push(packed_bits(view, TRACE_PPU_MODE_BITS_START, 2)? - enabled * visible)
}

fn constrain_ppu_coincidence(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let two = NativeField::from_u64(2);
    let mut equal = one;
    for bit in 0..8 {
        let line = view.value(TRACE_BEFORE_PPU_LINE_BITS_START + bit)?;
        let compare = view.value(TRACE_BEFORE_DMG_HIGH_BITS_START + 40 + bit)?;
        equal *= one - line - compare + two * line * compare;
    }
    sink.push(view.value(TRACE_PPU_COINCIDENCE)? - equal)
}

fn constrain_mmio_values(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let visible = visible_registers(view)?;
    for slot in 0..TRACE_BUS_SLOTS {
        let read = bus_kind(view, slot, 11)?;
        let write = bus_kind(view, slot, 12)?;
        let mut supported = NativeField::from_u64(0);
        let mut expected = NativeField::from_u64(0);
        for (address, value) in &visible {
            let selector = low_selector(view, slot, *address)?;
            supported += selector;
            expected += selector * *value;
        }
        sink.push(read * (supported * bus_field(view, slot, BUS_VALUE_OFFSET)? - expected))?;
        sink.push(write * (supported * bus_field(view, slot, BUS_BEFORE_OFFSET)? - expected))?;
    }
    Ok(())
}

fn visible_registers(
    view: &RowView<'_>,
) -> Result<[(u8, NativeField); VISIBLE_REGISTER_COUNT], UniformError> {
    let low = TRACE_BEFORE_DMG_LOW_BITS_START;
    let high = TRACE_BEFORE_DMG_HIGH_BITS_START;
    let tma = byte(view, low, 2)?;
    let counter = packed_bits(view, TRACE_BEFORE_TIMER_COUNTER_BITS_START, 8)?;
    let tima = counter + view.value(TRACE_TIMER_PHASE_FIVE)? * (tma - counter);
    let mode = packed_bits(view, TRACE_PPU_MODE_BITS_START, 2)?;
    let status = NativeField::from_u64(0x80)
        + byte(view, low, 5)?
        + NativeField::from_u64(4) * view.value(TRACE_PPU_COINCIDENCE)?
        + mode;
    Ok([
        (0x01, byte(view, low, 0)?),
        (0x02, byte(view, low, 1)?),
        (0x04, byte(view, TRACE_BEFORE_TIMER_DIV_BITS_START, 1)?),
        (0x05, tima),
        (0x06, tma),
        (0x07, NativeField::from_u64(0xf8) + byte(view, low, 3)?),
        (
            0x0f,
            NativeField::from_u64(0xe0) + view.before(STATE_INTERRUPT_REQUEST)?,
        ),
        (0x40, byte(view, low, 4)?),
        (0x41, status),
        (0x42, byte(view, low, 6)?),
        (0x43, byte(view, low, 7)?),
        (
            0x44,
            packed_bits(view, TRACE_BEFORE_PPU_LINE_BITS_START, 8)?,
        ),
        (0x45, byte(view, high, 5)?),
        (0x46, byte(view, TRACE_BEFORE_DMA_BITS_START, 0)?),
        (0x47, byte(view, high, 0)?),
        (0x48, byte(view, high, 1)?),
        (0x49, byte(view, high, 2)?),
        (0x4a, byte(view, high, 3)?),
        (0x4b, byte(view, high, 4)?),
        (0xff, view.before(STATE_INTERRUPT_ENABLE)?),
    ])
}

fn constrain_bits(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    start: usize,
    width: usize,
) -> Result<(), UniformError> {
    for bit in 0..width {
        sink.push(boolean(view.value(start + bit)?))?;
    }
    Ok(())
}

fn byte(view: &RowView<'_>, start: usize, byte: usize) -> Result<NativeField, UniformError> {
    packed_bits(view, start + byte * 8, 8)
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

fn or(left: NativeField, right: NativeField) -> NativeField {
    left + right - left * right
}
