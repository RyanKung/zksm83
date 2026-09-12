//! Exact byte-arithmetic identities selected by the committed fixed ISA row.

use akita_pcs::Ring;

use super::{
    BUS_ADDRESS_OFFSET, BUS_VALUE_OFFSET, ConstraintSink, INSTRUCTION_MODE, RowView, STATE_FLAGS,
    argument_selector, boolean, bus_field, operation_selector, packed_bits,
};
use crate::{
    ISA_ARGUMENT_ONE_BITS_START, ISA_ARGUMENT_ZERO_BITS_START, NativeField, TRACE_ARITHMETIC_CARRY,
    TRACE_ARITHMETIC_HALF_CARRY, TRACE_BEFORE_CPU_BYTE_BITS_START, TRACE_OPERAND_BITS_START,
    TRACE_OPERAND_VALUE, TRACE_RESULT_BITS_START, TRACE_RESULT_VALUE, TRACE_RESULT_ZERO,
    TRACE_RESULT_ZERO_PRODUCTS_START, UniformError,
};

const BYTE_BITS: usize = 8;
const FLAGS_CARRY_BIT: usize = 4;
const REGISTER_A: usize = 0;
const REGISTER_B: usize = 1;
const REGISTER_C: usize = 2;
const REGISTER_D: usize = 3;
const REGISTER_E: usize = 4;
const REGISTER_H: usize = 5;
const REGISTER_L: usize = 6;

pub(super) fn constrain_byte_arithmetic(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_arithmetic_witness(view, sink)?;
    let instruction = view.mode(INSTRUCTION_MODE)?;
    let increment = operation_selector(view, 9)?;
    let decrement = operation_selector(view, 10)?;
    let load = operation_selector(view, 17)?;
    let alu = operation_selector(view, 19)?;
    let signed_sp = operation_selector(view, 22)? + operation_selector(view, 23)?;
    let rotate = operation_selector(view, 12)? + operation_selector(view, 37)?;
    let daa = operation_selector(view, 13)?;
    let bit = operation_selector(view, 38)?
        + operation_selector(view, 39)?
        + operation_selector(view, 40)?;
    let arithmetic = instruction * (increment + decrement + alu + signed_sp + rotate + daa + bit);
    constrain_operand_routing(view, sink, instruction, increment, decrement, alu)?;
    constrain_increment_decrement(view, sink, instruction, increment, decrement)?;
    constrain_alu(view, sink, instruction, alu)?;
    constrain_unused_witness(view, sink, arithmetic, instruction * load)
}

fn constrain_arithmetic_witness(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    for start in [TRACE_OPERAND_BITS_START, TRACE_RESULT_BITS_START] {
        for bit in 0..BYTE_BITS {
            sink.push(boolean(view.value(start + bit)?))?;
        }
    }
    for column in [
        TRACE_ARITHMETIC_CARRY,
        TRACE_ARITHMETIC_HALF_CARRY,
        TRACE_RESULT_ZERO,
    ] {
        sink.push(boolean(view.value(column)?))?;
    }
    sink.push(
        view.value(TRACE_OPERAND_VALUE)? - packed_bits(view, TRACE_OPERAND_BITS_START, BYTE_BITS)?,
    )?;
    sink.push(
        view.value(TRACE_RESULT_VALUE)? - packed_bits(view, TRACE_RESULT_BITS_START, BYTE_BITS)?,
    )?;
    for pair in 0..4 {
        let left = view.value(TRACE_RESULT_BITS_START + pair * 2)?;
        let right = view.value(TRACE_RESULT_BITS_START + pair * 2 + 1)?;
        let product = view.value(TRACE_RESULT_ZERO_PRODUCTS_START + pair)?;
        sink.push(product - (one - left) * (one - right))?;
    }
    let first_quartet = view.value(TRACE_RESULT_ZERO_PRODUCTS_START + 4)?;
    let second_quartet = view.value(TRACE_RESULT_ZERO_PRODUCTS_START + 5)?;
    sink.push(
        first_quartet
            - view.value(TRACE_RESULT_ZERO_PRODUCTS_START)?
                * view.value(TRACE_RESULT_ZERO_PRODUCTS_START + 1)?,
    )?;
    sink.push(
        second_quartet
            - view.value(TRACE_RESULT_ZERO_PRODUCTS_START + 2)?
                * view.value(TRACE_RESULT_ZERO_PRODUCTS_START + 3)?,
    )?;
    sink.push(view.value(TRACE_RESULT_ZERO)? - first_quartet * second_quartet)
}

fn constrain_operand_routing(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
    increment: NativeField,
    decrement: NativeField,
    alu: NativeField,
) -> Result<(), UniformError> {
    let operand = view.value(TRACE_OPERAND_VALUE)?;
    let target = selected_operand(view, ISA_ARGUMENT_ZERO_BITS_START, 3)?;
    let source = selected_operand(view, ISA_ARGUMENT_ONE_BITS_START, 4)?;
    sink.push(instruction * (increment + decrement) * (operand - target))?;
    sink.push(instruction * alu * (operand - source))
}

fn constrain_increment_decrement(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
    increment: NativeField,
    decrement: NativeField,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let operand = view.value(TRACE_OPERAND_VALUE)?;
    let result = view.value(TRACE_RESULT_VALUE)?;
    let carry = view.value(TRACE_ARITHMETIC_CARRY)?;
    let half = view.value(TRACE_ARITHMETIC_HALF_CARRY)?;
    let operand_low = packed_bits(view, TRACE_OPERAND_BITS_START, 4)?;
    let result_low = packed_bits(view, TRACE_RESULT_BITS_START, 4)?;
    sink.push(
        instruction * increment * (operand + one - result - NativeField::from_u64(256) * carry),
    )?;
    sink.push(
        instruction
            * increment
            * (operand_low + one - result_low - NativeField::from_u64(16) * half),
    )?;
    sink.push(
        instruction * decrement * (operand + NativeField::from_u64(256) * carry - result - one),
    )?;
    sink.push(
        instruction
            * decrement
            * (operand_low + NativeField::from_u64(16) * half - result_low - one),
    )?;
    constrain_increment_destination(view, sink, instruction, increment + decrement)?;
    let prior_carry = before_flag_bit(view, FLAGS_CARRY_BIT)?;
    let zero = view.value(TRACE_RESULT_ZERO)?;
    let increment_flags = zero * NativeField::from_u64(128)
        + half * NativeField::from_u64(32)
        + prior_carry * NativeField::from_u64(16);
    let decrement_flags = increment_flags + NativeField::from_u64(64);
    sink.push(instruction * increment * (view.after(STATE_FLAGS)? - increment_flags))?;
    sink.push(instruction * decrement * (view.after(STATE_FLAGS)? - decrement_flags))
}

fn constrain_increment_destination(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
    operation: NativeField,
) -> Result<(), UniformError> {
    let result = view.value(TRACE_RESULT_VALUE)?;
    for (argument, state) in register_routes() {
        let route = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, argument)?;
        sink.push(instruction * operation * route * (view.after(state)? - result))?;
    }
    let memory = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 6)?;
    let hl = view.before(REGISTER_H)? * NativeField::from_u64(256) + view.before(REGISTER_L)?;
    let selected = instruction * operation * memory;
    sink.push(selected * (bus_field(view, 1, BUS_ADDRESS_OFFSET)? - hl))?;
    sink.push(
        selected * (bus_field(view, 1, BUS_VALUE_OFFSET)? - view.value(TRACE_OPERAND_VALUE)?),
    )?;
    sink.push(selected * (bus_field(view, 2, BUS_ADDRESS_OFFSET)? - hl))?;
    sink.push(selected * (bus_field(view, 2, BUS_VALUE_OFFSET)? - result))
}

fn constrain_alu(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
    alu: NativeField,
) -> Result<(), UniformError> {
    let accumulator = view.before(REGISTER_A)?;
    let operand = view.value(TRACE_OPERAND_VALUE)?;
    let result = view.value(TRACE_RESULT_VALUE)?;
    let carry = view.value(TRACE_ARITHMETIC_CARRY)?;
    let half = view.value(TRACE_ARITHMETIC_HALF_CARRY)?;
    let carry_in = before_flag_bit(view, FLAGS_CARRY_BIT)?;
    let accumulator_low = packed_bits(view, TRACE_BEFORE_CPU_BYTE_BITS_START, 4)?;
    let operand_low = packed_bits(view, TRACE_OPERAND_BITS_START, 4)?;
    let result_low = packed_bits(view, TRACE_RESULT_BITS_START, 4)?;
    for (code, selected_carry) in [(0, NativeField::from_u64(0)), (1, carry_in)] {
        let operation = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, code)?;
        let selected = instruction * alu * operation;
        sink.push(
            selected
                * (accumulator + operand + selected_carry
                    - result
                    - NativeField::from_u64(256) * carry),
        )?;
        sink.push(
            selected
                * (accumulator_low + operand_low + selected_carry
                    - result_low
                    - NativeField::from_u64(16) * half),
        )?;
    }
    for (code, selected_carry) in [
        (2, NativeField::from_u64(0)),
        (3, carry_in),
        (7, NativeField::from_u64(0)),
    ] {
        let operation = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, code)?;
        let selected = instruction * alu * operation;
        sink.push(
            selected
                * (accumulator + NativeField::from_u64(256) * carry
                    - operand
                    - selected_carry
                    - result),
        )?;
        sink.push(
            selected
                * (accumulator_low + NativeField::from_u64(16) * half
                    - operand_low
                    - selected_carry
                    - result_low),
        )?;
    }
    constrain_logical_alu(view, sink, instruction, alu)?;
    constrain_alu_outputs(view, sink, instruction, alu)
}

fn constrain_logical_alu(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
    alu: NativeField,
) -> Result<(), UniformError> {
    for bit in 0..BYTE_BITS {
        let left = view.value(TRACE_BEFORE_CPU_BYTE_BITS_START + bit)?;
        let right = view.value(TRACE_OPERAND_BITS_START + bit)?;
        let product = left * right;
        let result = view.value(TRACE_RESULT_BITS_START + bit)?;
        for (code, expected) in [
            (4, product),
            (5, left + right - NativeField::from_u64(2) * product),
            (6, left + right - product),
        ] {
            let operation = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, code)?;
            sink.push(instruction * alu * operation * (result - expected))?;
        }
    }
    Ok(())
}

fn constrain_alu_outputs(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
    alu: NativeField,
) -> Result<(), UniformError> {
    let result = view.value(TRACE_RESULT_VALUE)?;
    let zero = view.value(TRACE_RESULT_ZERO)?;
    let half = view.value(TRACE_ARITHMETIC_HALF_CARRY)?;
    let carry = view.value(TRACE_ARITHMETIC_CARRY)?;
    for code in 0..8 {
        let operation = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, code)?;
        let selected = instruction * alu * operation;
        if code != 7 {
            sink.push(selected * (view.after(REGISTER_A)? - result))?;
        }
        let subtract = u64::from(matches!(code, 2 | 3 | 7));
        let derived = u64::from(matches!(code, 0 | 1 | 2 | 3 | 7));
        let and_half = u64::from(code == 4);
        let flags = zero * NativeField::from_u64(128)
            + NativeField::from_u64(subtract * 64)
            + half * NativeField::from_u64(derived * 32)
            + NativeField::from_u64(and_half * 32)
            + carry * NativeField::from_u64(derived * 16);
        sink.push(selected * (view.after(STATE_FLAGS)? - flags))?;
    }
    Ok(())
}

fn constrain_unused_witness(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    arithmetic: NativeField,
    load: NativeField,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    sink.push((one - arithmetic - load) * view.value(TRACE_OPERAND_VALUE)?)?;
    let unused = one - arithmetic;
    for column in [
        TRACE_RESULT_VALUE,
        TRACE_ARITHMETIC_CARRY,
        TRACE_ARITHMETIC_HALF_CARRY,
    ] {
        sink.push(unused * view.value(column)?)?;
    }
    sink.push(unused * (view.value(TRACE_RESULT_ZERO)? - one))
}

fn selected_operand(
    view: &RowView<'_>,
    argument_start: usize,
    width: usize,
) -> Result<NativeField, UniformError> {
    let mut selected = NativeField::from_u64(0);
    for (argument, state) in register_routes() {
        selected +=
            argument_selector(view, argument_start, width, argument)? * view.before(state)?;
    }
    let bus_value = bus_field(view, 1, BUS_VALUE_OFFSET)?;
    selected += argument_selector(view, argument_start, width, 6)? * bus_value;
    if width == 4 {
        selected += argument_selector(view, argument_start, width, 8)? * bus_value;
    }
    Ok(selected)
}

fn register_routes() -> [(u8, usize); 7] {
    [
        (0, REGISTER_B),
        (1, REGISTER_C),
        (2, REGISTER_D),
        (3, REGISTER_E),
        (4, REGISTER_H),
        (5, REGISTER_L),
        (7, REGISTER_A),
    ]
}

fn before_flag_bit(view: &RowView<'_>, bit: usize) -> Result<NativeField, UniformError> {
    view.value(TRACE_BEFORE_CPU_BYTE_BITS_START + STATE_FLAGS * BYTE_BITS + bit)
}
