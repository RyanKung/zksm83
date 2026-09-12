//! CPU-side identities for non-instruction DMG machine transitions.

use akita_pcs::Ring;

use super::{
    BUS_ADDRESS_OFFSET, BUS_PHYSICAL_ADDRESS_OFFSET, BUS_VALUE_OFFSET, ConstraintSink,
    DMA_BYTE_MODE, HALT_IDLE_MODE, HALT_WAKE_MODE, INTERRUPT_MODE, ISA_OPCODE, ISA_PREFIX, RowView,
    STATE_CYCLES, STATE_FLAGS, STATE_IME, STATE_MBC3_ROM_BANK, STATE_PC, STATE_PROFILE,
    STATE_RUN_STATE, STATE_SP, bit_selector, bus_field, bus_kind_bits, packed_bits, zero_from_bits,
};
use crate::{
    NativeField, TRACE_AFTER_CPU_BYTE_BITS_START, TRACE_BEFORE_CPU_BYTE_BITS_START,
    TRACE_BEFORE_PC_BITS_START, TRACE_BUS_SLOTS, TRACE_BUS_VALUE_BITS_START, TRACE_CYCLE_INCREMENT,
    TRACE_INTERRUPT_COUNT, TRACE_INTERRUPT_START, TRACE_STACK_FIRST_WRAP, TRACE_STACK_WRAP,
    TRACE_SUMMARY_AUX, UniformError,
};

const HALT_UNTIL_VBLANK_MODE: usize = 2;
const BLUE_SOUND_WAIT_MODE: usize = 3;
const BLUE_DELAY_LOOP_MODE: usize = 4;
const BLUE_DMA_WAIT_MODE: usize = 5;
const STATE_A: usize = 0;
const STATE_B: usize = 1;
const STATE_C: usize = 2;
const STATE_D: usize = 3;
const STATE_E: usize = 4;
const STATE_H: usize = 5;
const STATE_L: usize = 6;

pub(super) fn constrain_machine_cpu(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_machine_markers(view, sink)?;
    constrain_passive_cpu_modes(view, sink)?;
    constrain_blue_summaries(view, sink)?;
    constrain_halt_wake(view, sink)?;
    constrain_interrupt(view, sink)
}

fn constrain_machine_markers(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let noop = view.mode(BLUE_SOUND_WAIT_MODE)?
        + view.mode(BLUE_DELAY_LOOP_MODE)?
        + view.mode(BLUE_DMA_WAIT_MODE)?
        + view.mode(DMA_BYTE_MODE)?;
    let halt = view.mode(HALT_IDLE_MODE)?
        + view.mode(HALT_UNTIL_VBLANK_MODE)?
        + view.mode(HALT_WAKE_MODE)?;
    let interrupt = view.mode(INTERRUPT_MODE)?;
    sink.push((noop + halt + interrupt) * view.isa(ISA_PREFIX)?)?;
    sink.push(noop * view.isa(ISA_OPCODE)?)?;
    sink.push(halt * (view.isa(ISA_OPCODE)? - NativeField::from_u64(0x76)))?;
    sink.push(interrupt * (view.isa(ISA_OPCODE)? - NativeField::from_u64(0xff)))
}

fn constrain_passive_cpu_modes(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let passive = view.mode(HALT_IDLE_MODE)?
        + view.mode(HALT_UNTIL_VBLANK_MODE)?
        + view.mode(DMA_BYTE_MODE)?;
    for state in 0..STATE_CYCLES {
        sink.push(passive * (view.after(state)? - view.before(state)?))?;
    }
    sink.push(
        (view.mode(HALT_IDLE_MODE)? + view.mode(HALT_UNTIL_VBLANK_MODE)?)
            * (view.before(STATE_RUN_STATE)? - NativeField::from_u64(1)),
    )
}

fn constrain_halt_wake(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let wake = view.mode(HALT_WAKE_MODE)?;
    for state in 0..STATE_RUN_STATE {
        sink.push(wake * (view.after(state)? - view.before(state)?))?;
    }
    sink.push(wake * (view.before(STATE_RUN_STATE)? - NativeField::from_u64(1)))?;
    sink.push(wake * view.after(STATE_RUN_STATE)?)?;
    sink.push(wake * (view.after(STATE_CYCLES)? - view.before(STATE_CYCLES)?))
}

fn constrain_blue_summaries(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let sound = view.mode(BLUE_SOUND_WAIT_MODE)?;
    let delay = view.mode(BLUE_DELAY_LOOP_MODE)?;
    let dma = view.mode(BLUE_DMA_WAIT_MODE)?;
    let summary = sound + delay + dma;
    sink.push(summary * (view.before(STATE_PROFILE)? - NativeField::from_u64(1)))?;
    sink.push(summary * view.before(STATE_RUN_STATE)?)?;
    sink.push(summary * view.after(STATE_RUN_STATE)?)?;
    constrain_sound_wait(view, sink, sound)?;
    constrain_delay_loop(view, sink, delay)?;
    constrain_dma_wait(view, sink, dma)?;
    sink.push((NativeField::from_u64(1) - sound - delay) * view.value(TRACE_SUMMARY_AUX)?)
}

fn constrain_sound_wait(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    selected: NativeField,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    sink.push(selected * (view.before(STATE_PC)? - NativeField::from_u64(0x374f)))?;
    sink.push(selected * (view.before(STATE_IME)? - NativeField::from_u64(2)))?;
    preserve_cpu(
        view,
        sink,
        selected,
        &[STATE_B, STATE_C, STATE_D, STATE_E, STATE_SP, STATE_IME],
    )?;
    sink.push(selected * (view.after(STATE_H)? - NativeField::from_u64(0xc0)))?;
    sink.push(selected * (view.after(STATE_L)? - NativeField::from_u64(0x2d)))?;
    for (slot, address) in [(0, 0xc02a), (1, 0xc02b), (2, 0xc02d)] {
        constrain_bus_event(view, sink, selected, slot, 4, address, None)?;
    }
    constrain_empty_bus_tail(view, sink, selected, 3)?;
    for bit in 0..8 {
        let left = view.value(TRACE_BUS_VALUE_BITS_START + bit)?;
        let middle = view.value(TRACE_BUS_VALUE_BITS_START + 8 + bit)?;
        let right = view.value(TRACE_BUS_VALUE_BITS_START + 16 + bit)?;
        let expected = left + middle + right - left * middle - left * right - middle * right
            + left * middle * right;
        sink.push(
            selected
                * (view.value(TRACE_AFTER_CPU_BYTE_BITS_START + STATE_A * 8 + bit)? - expected),
        )?;
    }
    let zero = zero_from_bits(view, TRACE_AFTER_CPU_BYTE_BITS_START + STATE_A * 8, 8)?;
    let increment = view.value(TRACE_CYCLE_INCREMENT)?;
    let quotient = view.value(TRACE_SUMMARY_AUX)?;
    sink.push(selected * (view.after(STATE_FLAGS)? - NativeField::from_u64(128) * zero))?;
    sink.push(
        selected
            * (view.after(STATE_PC)?
                - NativeField::from_u64(0x374f)
                - NativeField::from_u64(12) * zero),
    )?;
    sink.push(selected * zero * (increment - NativeField::from_u64(18)))?;
    sink.push(selected * zero * quotient)?;
    sink.push(selected * (one - zero) * (increment - NativeField::from_u64(19) * quotient))
}

fn constrain_delay_loop(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    selected: NativeField,
) -> Result<(), UniformError> {
    let ime = view.before(STATE_IME)?;
    sink.push(selected * (view.before(STATE_PC)? - NativeField::from_u64(0x614d)))?;
    sink.push(selected * (view.before(STATE_MBC3_ROM_BANK)? - NativeField::from_u64(28)))?;
    sink.push(selected * ime * (ime - NativeField::from_u64(2)))?;
    preserve_cpu(
        view,
        sink,
        selected,
        &[STATE_B, STATE_C, STATE_H, STATE_L, STATE_SP, STATE_IME],
    )?;
    constrain_empty_bus_tail(view, sink, selected, 0)?;
    let before_de = view.before(STATE_D)? * NativeField::from_u64(256) + view.before(STATE_E)?;
    let after_de = view.after(STATE_D)? * NativeField::from_u64(256) + view.after(STATE_E)?;
    let iterations = view.value(TRACE_SUMMARY_AUX)?;
    sink.push(selected * (before_de - after_de - iterations))?;
    for bit in 0..8 {
        let high = view.value(TRACE_AFTER_CPU_BYTE_BITS_START + STATE_D * 8 + bit)?;
        let low = view.value(TRACE_AFTER_CPU_BYTE_BITS_START + STATE_E * 8 + bit)?;
        let expected = high + low - high * low;
        sink.push(
            selected
                * (view.value(TRACE_AFTER_CPU_BYTE_BITS_START + STATE_A * 8 + bit)? - expected),
        )?;
    }
    let zero = zero_from_bits(view, TRACE_AFTER_CPU_BYTE_BITS_START + STATE_A * 8, 8)?;
    sink.push(selected * ime * zero)?;
    sink.push(selected * (NativeField::from_u64(2) - ime) * view.after(STATE_D)?)?;
    sink.push(selected * (NativeField::from_u64(2) - ime) * view.after(STATE_E)?)?;
    sink.push(
        selected
            * (view.after(STATE_FLAGS)?
                - NativeField::from_u64(64) * (NativeField::from_u64(2) - ime)),
    )?;
    sink.push(
        selected
            * (view.after(STATE_PC)? - NativeField::from_u64(0x6155)
                + NativeField::from_u64(4) * ime),
    )?;
    sink.push(
        selected
            * (NativeField::from_u64(2) * view.value(TRACE_CYCLE_INCREMENT)?
                - NativeField::from_u64(20) * iterations
                + NativeField::from_u64(2)
                - ime),
    )
}

fn constrain_dma_wait(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    selected: NativeField,
) -> Result<(), UniformError> {
    sink.push(selected * (view.before(STATE_PC)? - NativeField::from_u64(0xff86)))?;
    sink.push(selected * (view.before(STATE_A)? - NativeField::from_u64(0x28)))?;
    sink.push(selected * view.before(STATE_IME)?)?;
    preserve_cpu(
        view,
        sink,
        selected,
        &[
            STATE_B, STATE_C, STATE_D, STATE_E, STATE_H, STATE_L, STATE_SP, STATE_IME,
        ],
    )?;
    for (slot, kind, address, value) in [
        (0, 14, 0xff86, 0x3d),
        (1, 14, 0xff87, 0x20),
        (2, 15, 0xff88, 0xfd),
    ] {
        constrain_bus_event(view, sink, selected, slot, kind, address, Some(value))?;
    }
    constrain_empty_bus_tail(view, sink, selected, 3)?;
    let carry = view.value(TRACE_BEFORE_CPU_BYTE_BITS_START + STATE_FLAGS * 8 + 4)?;
    sink.push(selected * view.after(STATE_A)?)?;
    sink.push(
        selected
            * (view.after(STATE_FLAGS)?
                - NativeField::from_u64(0xc0)
                - NativeField::from_u64(0x10) * carry),
    )?;
    sink.push(selected * (view.after(STATE_PC)? - NativeField::from_u64(0xff89)))?;
    sink.push(selected * (view.value(TRACE_CYCLE_INCREMENT)? - NativeField::from_u64(159)))
}

fn preserve_cpu(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    selected: NativeField,
    states: &[usize],
) -> Result<(), UniformError> {
    for state in states {
        sink.push(selected * (view.after(*state)? - view.before(*state)?))?;
    }
    Ok(())
}

fn constrain_bus_event(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    selected: NativeField,
    slot: usize,
    kind: u8,
    address: u64,
    value: Option<u64>,
) -> Result<(), UniformError> {
    let kind = bit_selector(bus_kind_bits(view, slot)?, kind)?;
    sink.push(selected * (kind - NativeField::from_u64(1)))?;
    sink.push(
        selected * (bus_field(view, slot, BUS_ADDRESS_OFFSET)? - NativeField::from_u64(address)),
    )?;
    sink.push(
        selected
            * (bus_field(view, slot, BUS_PHYSICAL_ADDRESS_OFFSET)?
                - NativeField::from_u64(address)),
    )?;
    if let Some(value) = value {
        sink.push(
            selected * (bus_field(view, slot, BUS_VALUE_OFFSET)? - NativeField::from_u64(value)),
        )?;
    }
    Ok(())
}

fn constrain_empty_bus_tail(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    selected: NativeField,
    start: usize,
) -> Result<(), UniformError> {
    for slot in start..TRACE_BUS_SLOTS {
        sink.push(selected * bus_field(view, slot, 0)?)?;
    }
    Ok(())
}

fn constrain_interrupt(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let interrupt = view.mode(INTERRUPT_MODE)?;
    let before_run = view.before(STATE_RUN_STATE)?;
    sink.push(
        interrupt
            * before_run
            * (before_run - NativeField::from_u64(1))
            * (before_run - NativeField::from_u64(3)),
    )?;
    sink.push(interrupt * (view.before(STATE_IME)? - NativeField::from_u64(2)))?;
    sink.push(interrupt * view.after(STATE_IME)?)?;
    sink.push(interrupt * view.after(STATE_RUN_STATE)?)?;
    for state in 0..STATE_PC {
        sink.push(interrupt * (view.after(state)? - view.before(state)?))?;
    }
    let mut vector = NativeField::from_u64(0);
    for (source, address) in [0x40_u64, 0x48, 0x50, 0x58, 0x60].into_iter().enumerate() {
        vector += view.value(TRACE_INTERRUPT_START + source)? * NativeField::from_u64(address);
    }
    sink.push(interrupt * (view.after(STATE_PC)? - vector))?;
    let wrap = view.value(TRACE_STACK_WRAP)?;
    let first_wrap = view.value(TRACE_STACK_FIRST_WRAP)?;
    sink.push(
        interrupt
            * (view.after(STATE_SP)? - view.before(STATE_SP)? + NativeField::from_u64(2)
                - NativeField::from_u64(65_536) * wrap),
    )?;
    sink.push(
        interrupt
            * (bus_field(view, 0, BUS_ADDRESS_OFFSET)? - view.before(STATE_SP)?
                + NativeField::from_u64(1)
                - NativeField::from_u64(65_536) * first_wrap),
    )?;
    sink.push(
        interrupt
            * (bus_field(view, 1, BUS_ADDRESS_OFFSET)? - view.before(STATE_SP)?
                + NativeField::from_u64(2)
                - NativeField::from_u64(65_536) * wrap),
    )?;
    let pc_high = packed_bits(view, TRACE_BEFORE_PC_BITS_START + 8, 8)?;
    let pc_low = packed_bits(view, TRACE_BEFORE_PC_BITS_START, 8)?;
    sink.push(interrupt * (bus_field(view, 0, BUS_VALUE_OFFSET)? - pc_high))?;
    sink.push(interrupt * (bus_field(view, 1, BUS_VALUE_OFFSET)? - pc_low))?;
    let mut source_sum = NativeField::from_u64(0);
    for source in 0..TRACE_INTERRUPT_COUNT {
        source_sum += view.value(TRACE_INTERRUPT_START + source)?;
    }
    sink.push(interrupt * (source_sum - NativeField::from_u64(1)))
}
