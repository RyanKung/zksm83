//! Register, immediate, and accumulator-transfer identities.

use akita_pcs::Ring;

use super::{
    BUS_ADDRESS_OFFSET, BUS_VALUE_OFFSET, ConstraintSink, INSTRUCTION_MODE, RowView, STATE_FLAGS,
    argument_selector, boolean, bus_field, operation_selector, packed_bits,
};
use crate::{
    ISA_ARGUMENT_ONE_BITS_START, ISA_ARGUMENT_ZERO_BITS_START, NativeField, TRACE_ADDRESS_WRAP,
    TRACE_BEFORE_CPU_BYTE_BITS_START, TRACE_BEFORE_SP_BITS_START, TRACE_IMMEDIATE_HIGH,
    TRACE_IMMEDIATE_LOW, TRACE_OPERAND_VALUE, UniformError,
};

const STATE_A: usize = 0;
const STATE_B: usize = 1;
const STATE_C: usize = 2;
const STATE_D: usize = 3;
const STATE_E: usize = 4;
const STATE_H: usize = 5;
const STATE_L: usize = 6;
const STATE_SP: usize = 9;
const STATE_IME: usize = 10;
const STATE_RUN_STATE: usize = 11;

pub(super) fn constrain_data_and_simple_operations(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let instruction = view.mode(INSTRUCTION_MODE)?;
    constrain_immediate_loads(view, sink, instruction)?;
    constrain_store_sp(view, sink, instruction)?;
    constrain_load8(view, sink, instruction)?;
    constrain_accumulator_transfers(view, sink, instruction)?;
    constrain_simple_flag_operations(view, sink, instruction)?;
    constrain_low_power(view, sink, instruction)?;
    constrain_ime(view, sink, instruction)
}

fn constrain_store_sp(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
) -> Result<(), UniformError> {
    let store = operation_selector(view, 1)?;
    let wrap = view.value(TRACE_ADDRESS_WRAP)?;
    sink.push(boolean(wrap))?;
    let address = view.value(TRACE_IMMEDIATE_LOW)?
        + NativeField::from_u64(256) * view.value(TRACE_IMMEDIATE_HIGH)?;
    let low = packed_bits(view, TRACE_BEFORE_SP_BITS_START, 8)?;
    let high = packed_bits(view, TRACE_BEFORE_SP_BITS_START + 8, 8)?;
    sink.push(instruction * store * (bus_field(view, 3, BUS_ADDRESS_OFFSET)? - address))?;
    sink.push(instruction * store * (bus_field(view, 3, BUS_VALUE_OFFSET)? - low))?;
    sink.push(
        instruction
            * store
            * (bus_field(view, 4, BUS_ADDRESS_OFFSET)? - address - NativeField::from_u64(1)
                + NativeField::from_u64(65_536) * wrap),
    )?;
    sink.push(instruction * store * (bus_field(view, 4, BUS_VALUE_OFFSET)? - high))?;
    sink.push((NativeField::from_u64(1) - instruction * store) * wrap)
}

fn constrain_immediate_loads(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
) -> Result<(), UniformError> {
    let low = view.value(TRACE_IMMEDIATE_LOW)?;
    let high = view.value(TRACE_IMMEDIATE_HIGH)?;
    let word = low + NativeField::from_u64(256) * high;
    let load16 = operation_selector(view, 4)?;
    for (argument, high_state, low_state) in word_register_routes() {
        let route = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, argument)?;
        sink.push(instruction * load16 * route * (view.after(high_state)? - high))?;
        sink.push(instruction * load16 * route * (view.after(low_state)? - low))?;
    }
    let sp = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 3)?;
    sink.push(instruction * load16 * sp * (view.after(STATE_SP)? - word))?;

    let load8 = operation_selector(view, 11)?;
    for (argument, state) in byte_register_routes() {
        let route = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, argument)?;
        sink.push(instruction * load8 * route * (view.after(state)? - low))?;
    }
    let memory = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 6)?;
    let selected = instruction * load8 * memory;
    let hl = register_word(view, STATE_H, STATE_L)?;
    sink.push(selected * (bus_field(view, 2, BUS_ADDRESS_OFFSET)? - hl))?;
    sink.push(selected * (bus_field(view, 2, BUS_VALUE_OFFSET)? - low))?;
    let stop = operation_selector(view, 2)?;
    sink.push(instruction * stop * low)
}

fn constrain_load8(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
) -> Result<(), UniformError> {
    let load = operation_selector(view, 17)?;
    let operand = view.value(TRACE_OPERAND_VALUE)?;
    let selected_source = selected_byte_source(view, ISA_ARGUMENT_ONE_BITS_START, 4)?;
    sink.push(instruction * load * (operand - selected_source))?;
    for (argument, state) in byte_register_routes() {
        let route = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, argument)?;
        sink.push(instruction * load * route * (view.after(state)? - operand))?;
    }
    let memory = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 6)?;
    let selected = instruction * load * memory;
    let hl = register_word(view, STATE_H, STATE_L)?;
    sink.push(selected * (bus_field(view, 1, BUS_ADDRESS_OFFSET)? - hl))?;
    sink.push(selected * (bus_field(view, 1, BUS_VALUE_OFFSET)? - operand))
}

fn constrain_accumulator_transfers(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
) -> Result<(), UniformError> {
    let indirect = operation_selector(view, 6)?;
    let bc = register_word(view, STATE_B, STATE_C)?;
    let de = register_word(view, STATE_D, STATE_E)?;
    let hl = register_word(view, STATE_H, STATE_L)?;
    let address = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 0)? * bc
        + argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 1)? * de
        + (argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 2)?
            + argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 3)?)
            * hl;
    constrain_directional_transfer(
        view,
        sink,
        instruction * indirect,
        ISA_ARGUMENT_ONE_BITS_START,
        4,
        1,
        address,
    )?;

    let immediate_high = operation_selector(view, 21)?;
    let high_address = NativeField::from_u64(0xff00) + view.value(TRACE_IMMEDIATE_LOW)?;
    constrain_directional_transfer(
        view,
        sink,
        instruction * immediate_high,
        ISA_ARGUMENT_ZERO_BITS_START,
        3,
        2,
        high_address,
    )?;

    let register_high = operation_selector(view, 29)?;
    let c_address = NativeField::from_u64(0xff00) + view.before(STATE_C)?;
    constrain_directional_transfer(
        view,
        sink,
        instruction * register_high,
        ISA_ARGUMENT_ZERO_BITS_START,
        3,
        1,
        c_address,
    )?;

    let absolute = operation_selector(view, 30)?;
    let absolute_address = view.value(TRACE_IMMEDIATE_LOW)?
        + NativeField::from_u64(256) * view.value(TRACE_IMMEDIATE_HIGH)?;
    constrain_directional_transfer(
        view,
        sink,
        instruction * absolute,
        ISA_ARGUMENT_ZERO_BITS_START,
        3,
        3,
        absolute_address,
    )
}

fn constrain_directional_transfer(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    operation: NativeField,
    direction_start: usize,
    direction_width: usize,
    slot: usize,
    address: NativeField,
) -> Result<(), UniformError> {
    let direction_in = argument_selector(view, direction_start, direction_width, 0)?;
    let direction_out = argument_selector(view, direction_start, direction_width, 1)?;
    sink.push(operation * (bus_field(view, slot, BUS_ADDRESS_OFFSET)? - address))?;
    sink.push(
        operation
            * direction_in
            * (view.after(STATE_A)? - bus_field(view, slot, BUS_VALUE_OFFSET)?),
    )?;
    sink.push(
        operation
            * direction_out
            * (bus_field(view, slot, BUS_VALUE_OFFSET)? - view.before(STATE_A)?),
    )
}

fn constrain_simple_flag_operations(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
) -> Result<(), UniformError> {
    let zero = before_flag_bit(view, 7)?;
    let carry = before_flag_bit(view, 4)?;
    let complement = operation_selector(view, 14)?;
    sink.push(
        instruction
            * complement
            * (view.after(STATE_A)? + view.before(STATE_A)? - NativeField::from_u64(255)),
    )?;
    sink.push(
        instruction
            * complement
            * (view.after(STATE_FLAGS)?
                - zero * NativeField::from_u64(128)
                - NativeField::from_u64(96)
                - carry * NativeField::from_u64(16)),
    )?;
    let set_carry = operation_selector(view, 15)?;
    sink.push(
        instruction
            * set_carry
            * (view.after(STATE_FLAGS)?
                - zero * NativeField::from_u64(128)
                - NativeField::from_u64(16)),
    )?;
    let complement_carry = operation_selector(view, 16)?;
    sink.push(
        instruction
            * complement_carry
            * (view.after(STATE_FLAGS)?
                - zero * NativeField::from_u64(128)
                - (NativeField::from_u64(1) - carry) * NativeField::from_u64(16)),
    )
}

fn constrain_low_power(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
) -> Result<(), UniformError> {
    let stop = operation_selector(view, 2)?;
    sink.push(instruction * stop * (view.after(STATE_RUN_STATE)? - NativeField::from_u64(2)))?;
    let halt = operation_selector(view, 18)?;
    sink.push(
        instruction
            * halt
            * (view.after(STATE_RUN_STATE)? - NativeField::from_u64(1))
            * (view.after(STATE_RUN_STATE)? - NativeField::from_u64(3)),
    )
}

fn constrain_ime(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let before = view.before(STATE_IME)?;
    let after = view.after(STATE_IME)?;
    let disable = operation_selector(view, 32)?;
    let enable = operation_selector(view, 33)?;
    let reti = operation_selector(view, 25)?;
    sink.push(instruction * disable * after)?;
    sink.push(instruction * reti * (after - NativeField::from_u64(2)))?;
    let ordinary = one - disable - enable - reti;
    let case_zero = (before - one) * (before - NativeField::from_u64(2));
    let case_one = before * (before - NativeField::from_u64(2));
    let case_two = before * (before - one);
    sink.push(instruction * ordinary * case_zero * after)?;
    sink.push(instruction * enable * case_zero * (after - one))?;
    sink.push(instruction * (ordinary + enable) * case_one * (after - NativeField::from_u64(2)))?;
    sink.push(instruction * ordinary * case_two * (after - NativeField::from_u64(2)))?;
    sink.push(instruction * enable * case_two * (after - one))
}

fn selected_byte_source(
    view: &RowView<'_>,
    argument_start: usize,
    width: usize,
) -> Result<NativeField, UniformError> {
    let mut selected = NativeField::from_u64(0);
    for (argument, state) in byte_register_routes() {
        selected +=
            argument_selector(view, argument_start, width, argument)? * view.before(state)?;
    }
    selected +=
        argument_selector(view, argument_start, width, 6)? * bus_field(view, 1, BUS_VALUE_OFFSET)?;
    Ok(selected)
}

fn register_word(view: &RowView<'_>, high: usize, low: usize) -> Result<NativeField, UniformError> {
    Ok(view.before(high)? * NativeField::from_u64(256) + view.before(low)?)
}

fn before_flag_bit(view: &RowView<'_>, bit: usize) -> Result<NativeField, UniformError> {
    view.value(TRACE_BEFORE_CPU_BYTE_BITS_START + STATE_FLAGS * 8 + bit)
}

fn byte_register_routes() -> [(u8, usize); 7] {
    [
        (0, STATE_B),
        (1, STATE_C),
        (2, STATE_D),
        (3, STATE_E),
        (4, STATE_H),
        (5, STATE_L),
        (7, STATE_A),
    ]
}

fn word_register_routes() -> [(u8, usize, usize); 3] {
    [
        (0, STATE_B, STATE_C),
        (1, STATE_D, STATE_E),
        (2, STATE_H, STATE_L),
    ]
}
