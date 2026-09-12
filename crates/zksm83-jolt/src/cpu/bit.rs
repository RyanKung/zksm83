//! Exact accumulator rotations and CB-prefixed bit-operation identities.

use akita_pcs::Ring;

use super::{
    BUS_ADDRESS_OFFSET, BUS_VALUE_OFFSET, ConstraintSink, INSTRUCTION_MODE, RowView, STATE_FLAGS,
    argument_selector, bus_field, operation_selector,
};
use crate::{
    ISA_ARGUMENT_ONE_BITS_START, ISA_ARGUMENT_ZERO_BITS_START, NativeField, TRACE_ARITHMETIC_CARRY,
    TRACE_ARITHMETIC_HALF_CARRY, TRACE_BEFORE_CPU_BYTE_BITS_START, TRACE_OPERAND_BITS_START,
    TRACE_OPERAND_VALUE, TRACE_RESULT_BITS_START, TRACE_RESULT_VALUE, TRACE_RESULT_ZERO,
    UniformError,
};

const STATE_A: usize = 0;
const STATE_B: usize = 1;
const STATE_C: usize = 2;
const STATE_D: usize = 3;
const STATE_E: usize = 4;
const STATE_H: usize = 5;
const STATE_L: usize = 6;

pub(super) fn constrain_rotate_and_bit_operations(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let instruction = view.mode(INSTRUCTION_MODE)?;
    let accumulator_rotate = operation_selector(view, 12)?;
    let cb_rotate = operation_selector(view, 37)?;
    let test = operation_selector(view, 38)?;
    let reset = operation_selector(view, 39)?;
    let set = operation_selector(view, 40)?;
    let cb = cb_rotate + test + reset + set;
    constrain_operand_routing(view, sink, instruction, accumulator_rotate, cb)?;
    constrain_rotations(view, sink, instruction, accumulator_rotate, cb_rotate)?;
    constrain_bit_operations(view, sink, instruction, test, reset, set)?;
    constrain_cb_destination(view, sink, instruction, cb_rotate, test, reset, set)
}

fn constrain_operand_routing(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
    accumulator_rotate: NativeField,
    cb: NativeField,
) -> Result<(), UniformError> {
    let operand = view.value(TRACE_OPERAND_VALUE)?;
    sink.push(instruction * accumulator_rotate * (operand - view.before(STATE_A)?))?;
    let source = selected_cb_operand(view)?;
    sink.push(instruction * cb * (operand - source))
}

fn constrain_rotations(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
    accumulator_rotate: NativeField,
    cb_rotate: NativeField,
) -> Result<(), UniformError> {
    let rotate = accumulator_rotate + cb_rotate;
    let carry_in = before_flag_bit(view, 4)?;
    for code in 0..8 {
        let operation = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, code)?;
        let selected = instruction * rotate * operation;
        for bit in 0..8 {
            let expected = rotate_result_bit(view, code, bit, carry_in)?;
            sink.push(selected * (view.value(TRACE_RESULT_BITS_START + bit)? - expected))?;
        }
        let expected_carry = match code {
            0 | 2 | 4 => view.value(TRACE_OPERAND_BITS_START + 7)?,
            1 | 3 | 5 | 7 => view.value(TRACE_OPERAND_BITS_START)?,
            6 => NativeField::from_u64(0),
            _ => return Err(UniformError::Shape),
        };
        sink.push(selected * (view.value(TRACE_ARITHMETIC_CARRY)? - expected_carry))?;
    }
    sink.push(instruction * rotate * view.value(TRACE_ARITHMETIC_HALF_CARRY)?)?;
    sink.push(
        instruction
            * accumulator_rotate
            * (view.after(STATE_A)? - view.value(TRACE_RESULT_VALUE)?),
    )?;
    sink.push(
        instruction
            * accumulator_rotate
            * (view.after(STATE_FLAGS)?
                - NativeField::from_u64(16) * view.value(TRACE_ARITHMETIC_CARRY)?),
    )?;
    sink.push(
        instruction
            * cb_rotate
            * (view.after(STATE_FLAGS)?
                - NativeField::from_u64(128) * view.value(TRACE_RESULT_ZERO)?
                - NativeField::from_u64(16) * view.value(TRACE_ARITHMETIC_CARRY)?),
    )
}

fn constrain_bit_operations(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
    test: NativeField,
    reset: NativeField,
    set: NativeField,
) -> Result<(), UniformError> {
    let operand = view.value(TRACE_OPERAND_VALUE)?;
    let result = view.value(TRACE_RESULT_VALUE)?;
    sink.push(instruction * test * (result - operand))?;
    sink.push(instruction * (test + reset + set) * view.value(TRACE_ARITHMETIC_CARRY)?)?;
    sink.push(instruction * (test + reset + set) * view.value(TRACE_ARITHMETIC_HALF_CARRY)?)?;
    let mut selected_bit = NativeField::from_u64(0);
    for bit in 0..8 {
        let selector = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, bit)?;
        let operand_bit = view.value(TRACE_OPERAND_BITS_START + usize::from(bit))?;
        let result_bit = view.value(TRACE_RESULT_BITS_START + usize::from(bit))?;
        selected_bit += selector * operand_bit;
        sink.push(
            instruction
                * reset
                * (result_bit - operand_bit * (NativeField::from_u64(1) - selector)),
        )?;
        sink.push(
            instruction
                * set
                * (result_bit - operand_bit - selector * (NativeField::from_u64(1) - operand_bit)),
        )?;
    }
    let carry = before_flag_bit(view, 4)?;
    let expected_flags = (NativeField::from_u64(1) - selected_bit) * NativeField::from_u64(128)
        + NativeField::from_u64(32)
        + carry * NativeField::from_u64(16);
    sink.push(instruction * test * (view.after(STATE_FLAGS)? - expected_flags))
}

fn constrain_cb_destination(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
    rotate: NativeField,
    test: NativeField,
    reset: NativeField,
    set: NativeField,
) -> Result<(), UniformError> {
    let result = view.value(TRACE_RESULT_VALUE)?;
    let writes = rotate + reset + set;
    for (argument, state) in byte_register_routes() {
        let route = argument_selector(view, ISA_ARGUMENT_ONE_BITS_START, 4, argument)?;
        sink.push(instruction * writes * route * (view.after(state)? - result))?;
    }
    let memory = argument_selector(view, ISA_ARGUMENT_ONE_BITS_START, 4, 6)?;
    let hl = view.before(STATE_H)? * NativeField::from_u64(256) + view.before(STATE_L)?;
    let cb = rotate + test + reset + set;
    sink.push(instruction * cb * memory * (bus_field(view, 2, BUS_ADDRESS_OFFSET)? - hl))?;
    sink.push(
        instruction
            * cb
            * memory
            * (bus_field(view, 2, BUS_VALUE_OFFSET)? - view.value(TRACE_OPERAND_VALUE)?),
    )?;
    sink.push(instruction * writes * memory * (bus_field(view, 3, BUS_ADDRESS_OFFSET)? - hl))?;
    sink.push(instruction * writes * memory * (bus_field(view, 3, BUS_VALUE_OFFSET)? - result))
}

fn rotate_result_bit(
    view: &RowView<'_>,
    operation: u8,
    bit: usize,
    carry_in: NativeField,
) -> Result<NativeField, UniformError> {
    let zero = NativeField::from_u64(0);
    let result = match operation {
        0 => operand_bit(view, if bit == 0 { 7 } else { bit - 1 })?,
        1 => operand_bit(view, if bit == 7 { 0 } else { bit + 1 })?,
        2 if bit == 0 => carry_in,
        2 => operand_bit(view, bit - 1)?,
        3 if bit == 7 => carry_in,
        3 => operand_bit(view, bit + 1)?,
        4 if bit == 0 => zero,
        4 => operand_bit(view, bit - 1)?,
        5 if bit == 7 => operand_bit(view, 7)?,
        5 => operand_bit(view, bit + 1)?,
        6 if bit < 4 => operand_bit(view, bit + 4)?,
        6 => operand_bit(view, bit - 4)?,
        7 if bit == 7 => zero,
        7 => operand_bit(view, bit + 1)?,
        _ => return Err(UniformError::Shape),
    };
    Ok(result)
}

fn operand_bit(view: &RowView<'_>, bit: usize) -> Result<NativeField, UniformError> {
    view.value(TRACE_OPERAND_BITS_START + bit)
}

fn selected_cb_operand(view: &RowView<'_>) -> Result<NativeField, UniformError> {
    let mut selected = NativeField::from_u64(0);
    for (argument, state) in byte_register_routes() {
        selected += argument_selector(view, ISA_ARGUMENT_ONE_BITS_START, 4, argument)?
            * view.before(state)?;
    }
    selected += argument_selector(view, ISA_ARGUMENT_ONE_BITS_START, 4, 6)?
        * bus_field(view, 2, BUS_VALUE_OFFSET)?;
    Ok(selected)
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
