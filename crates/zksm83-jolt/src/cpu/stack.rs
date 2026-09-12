//! Exact CALL, RET, RST, PUSH, POP, and stack-pointer identities.

use akita_pcs::Ring;

use super::{
    BUS_ADDRESS_OFFSET, BUS_VALUE_OFFSET, ConstraintSink, INSTRUCTION_MODE, INTERRUPT_MODE,
    RowView, STATE_FLAGS, argument_selector, boolean, bus_field, operation_selector, packed_bits,
};
use crate::{
    ISA_ARGUMENT_ZERO_BITS_START, NativeField, TRACE_BRANCH_TAKEN, TRACE_POP_FLAGS_LOW_NIBBLE,
    TRACE_POP_FLAGS_LOW_NIBBLE_BITS_START, TRACE_SEQUENTIAL_PC, TRACE_STACK_FIRST_WRAP,
    TRACE_STACK_WRAP, UniformError,
};

const STATE_A: usize = 0;
const STATE_B: usize = 1;
const STATE_C: usize = 2;
const STATE_D: usize = 3;
const STATE_E: usize = 4;
const STATE_H: usize = 5;
const STATE_L: usize = 6;
const STATE_SP: usize = 9;

pub(super) fn constrain_stack_operations(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    sink.push(boolean(view.value(TRACE_STACK_WRAP)?))?;
    sink.push(boolean(view.value(TRACE_STACK_FIRST_WRAP)?))?;
    for bit in 0..4 {
        sink.push(boolean(
            view.value(TRACE_POP_FLAGS_LOW_NIBBLE_BITS_START + bit)?,
        ))?;
    }
    sink.push(
        view.value(TRACE_POP_FLAGS_LOW_NIBBLE)?
            - packed_bits(view, TRACE_POP_FLAGS_LOW_NIBBLE_BITS_START, 4)?,
    )?;
    let instruction = view.mode(INSTRUCTION_MODE)?;
    constrain_pushes(view, sink, instruction)?;
    constrain_pops(view, sink, instruction)?;
    constrain_stack_witness_scope(view, sink, instruction)
}

fn constrain_pushes(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
) -> Result<(), UniformError> {
    let call = operation_selector(view, 34)?;
    let push = operation_selector(view, 35)?;
    let restart = operation_selector(view, 36)?;
    let branch = view.value(TRACE_BRANCH_TAKEN)?;
    let call_taken = call * branch;
    let push_control = call_taken + push + restart;
    let push_group = call + push + restart;
    let wrap = view.value(TRACE_STACK_WRAP)?;
    let first_wrap = view.value(TRACE_STACK_FIRST_WRAP)?;
    sink.push(
        instruction
            * push_group
            * (view.after(STATE_SP)? - view.before(STATE_SP)?
                + NativeField::from_u64(2) * push_control
                - NativeField::from_u64(65_536) * wrap),
    )?;
    let high_address = call_taken * bus_field(view, 3, BUS_ADDRESS_OFFSET)?
        + (push + restart) * bus_field(view, 1, BUS_ADDRESS_OFFSET)?;
    let low_address = call_taken * bus_field(view, 4, BUS_ADDRESS_OFFSET)?
        + (push + restart) * bus_field(view, 2, BUS_ADDRESS_OFFSET)?;
    sink.push(
        instruction
            * (high_address
                - push_control
                    * (view.before(STATE_SP)? - NativeField::from_u64(1)
                        + NativeField::from_u64(65_536) * first_wrap)),
    )?;
    sink.push(
        instruction
            * (low_address
                - push_control
                    * (view.before(STATE_SP)? - NativeField::from_u64(2)
                        + NativeField::from_u64(65_536) * wrap)),
    )?;
    let high_value = call_taken * bus_field(view, 3, BUS_VALUE_OFFSET)?
        + (push + restart) * bus_field(view, 1, BUS_VALUE_OFFSET)?;
    let low_value = call_taken * bus_field(view, 4, BUS_VALUE_OFFSET)?
        + (push + restart) * bus_field(view, 2, BUS_VALUE_OFFSET)?;
    let pushed_word = (call_taken + restart) * view.value(TRACE_SEQUENTIAL_PC)?
        + push * selected_stack_word(view)?;
    sink.push(instruction * (low_value + NativeField::from_u64(256) * high_value - pushed_word))
}

fn constrain_pops(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
) -> Result<(), UniformError> {
    let return_operation = operation_selector(view, 20)?;
    let pop = operation_selector(view, 24)?;
    let reti = operation_selector(view, 25)?;
    let branch = view.value(TRACE_BRANCH_TAKEN)?;
    let return_taken = return_operation * branch;
    let pop_control = return_taken + pop + reti;
    let pop_group = return_operation + pop + reti;
    let wrap = view.value(TRACE_STACK_WRAP)?;
    let first_wrap = view.value(TRACE_STACK_FIRST_WRAP)?;
    sink.push(
        instruction
            * pop_group
            * (view.after(STATE_SP)?
                - view.before(STATE_SP)?
                - NativeField::from_u64(2) * pop_control
                + NativeField::from_u64(65_536) * wrap),
    )?;
    sink.push(
        instruction
            * pop_group
            * (bus_field(view, 1, BUS_ADDRESS_OFFSET)? - pop_control * view.before(STATE_SP)?),
    )?;
    sink.push(
        instruction
            * pop_group
            * (bus_field(view, 2, BUS_ADDRESS_OFFSET)?
                - pop_control
                    * (view.before(STATE_SP)? + NativeField::from_u64(1)
                        - NativeField::from_u64(65_536) * first_wrap)),
    )?;
    let low = bus_field(view, 1, BUS_VALUE_OFFSET)?;
    let high = bus_field(view, 2, BUS_VALUE_OFFSET)?;
    for (argument, high_state, low_state) in [
        (0, STATE_B, STATE_C),
        (1, STATE_D, STATE_E),
        (2, STATE_H, STATE_L),
    ] {
        let route = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, argument)?;
        sink.push(instruction * pop * route * (view.after(high_state)? - high))?;
        sink.push(instruction * pop * route * (view.after(low_state)? - low))?;
    }
    let af = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 3)?;
    sink.push(instruction * pop * af * (view.after(STATE_A)? - high))?;
    sink.push(
        instruction
            * pop
            * af
            * (low - view.after(STATE_FLAGS)? - view.value(TRACE_POP_FLAGS_LOW_NIBBLE)?),
    )
}

fn constrain_stack_witness_scope(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let branch = view.value(TRACE_BRANCH_TAKEN)?;
    let stack_use = instruction
        * (operation_selector(view, 24)?
            + operation_selector(view, 25)?
            + operation_selector(view, 35)?
            + operation_selector(view, 36)?
            + branch * (operation_selector(view, 20)? + operation_selector(view, 34)?))
        + view.mode(INTERRUPT_MODE)?;
    sink.push((one - stack_use) * view.value(TRACE_STACK_WRAP)?)?;
    sink.push((one - stack_use) * view.value(TRACE_STACK_FIRST_WRAP)?)?;
    let pop_af = instruction
        * operation_selector(view, 24)?
        * argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 3)?;
    sink.push((one - pop_af) * view.value(TRACE_POP_FLAGS_LOW_NIBBLE)?)
}

fn selected_stack_word(view: &RowView<'_>) -> Result<NativeField, UniformError> {
    let mut selected = NativeField::from_u64(0);
    for (argument, high, low) in [
        (0, STATE_B, STATE_C),
        (1, STATE_D, STATE_E),
        (2, STATE_H, STATE_L),
        (3, STATE_A, STATE_FLAGS),
    ] {
        let word = view.before(high)? * NativeField::from_u64(256) + view.before(low)?;
        selected += argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, argument)? * word;
    }
    Ok(selected)
}
