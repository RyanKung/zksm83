//! CPU-side identities for non-instruction DMG machine transitions.

use akita_pcs::Ring;

use super::{
    BUS_ADDRESS_OFFSET, BUS_VALUE_OFFSET, ConstraintSink, DMA_BYTE_MODE, HALT_IDLE_MODE,
    HALT_UNTIL_SERIAL_MODE, HALT_UNTIL_TIMER_MODE, HALT_UNTIL_VBLANK_MODE, HALT_WAKE_MODE,
    INTERRUPT_MODE, ISA_OPCODE, ISA_PREFIX, RowView, STATE_CYCLES, STATE_IME, STATE_PC,
    STATE_RUN_STATE, STATE_SP, bus_field, packed_bits,
};
use crate::{
    NativeField, TRACE_BEFORE_PC_BITS_START, TRACE_INTERRUPT_COUNT, TRACE_INTERRUPT_START,
    TRACE_STACK_FIRST_WRAP, TRACE_STACK_WRAP, UniformError,
};

pub(super) fn constrain_machine_cpu(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_machine_markers(view, sink)?;
    constrain_passive_cpu_modes(view, sink)?;
    constrain_halt_wake(view, sink)?;
    constrain_interrupt(view, sink)
}

fn constrain_machine_markers(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let noop = view.mode(DMA_BYTE_MODE)?;
    let halt = view.mode(HALT_IDLE_MODE)?
        + view.mode(HALT_UNTIL_VBLANK_MODE)?
        + view.mode(HALT_UNTIL_SERIAL_MODE)?
        + view.mode(HALT_UNTIL_TIMER_MODE)?
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
        + view.mode(HALT_UNTIL_SERIAL_MODE)?
        + view.mode(HALT_UNTIL_TIMER_MODE)?
        + view.mode(DMA_BYTE_MODE)?;
    for state in 0..STATE_CYCLES {
        sink.push(passive * (view.after(state)? - view.before(state)?))?;
    }
    sink.push(
        (view.mode(HALT_IDLE_MODE)?
            + view.mode(HALT_UNTIL_VBLANK_MODE)?
            + view.mode(HALT_UNTIL_SERIAL_MODE)?
            + view.mode(HALT_UNTIL_TIMER_MODE)?)
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
