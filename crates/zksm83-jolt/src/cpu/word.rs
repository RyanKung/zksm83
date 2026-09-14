//! Exact 16-bit, HL, and signed-SP instruction identities.

use akita_pcs::Ring;

use super::{
    ConstraintSink, INSTRUCTION_MODE, RowView, STATE_FLAGS, argument_selector, boolean,
    operation_selector, packed_bits,
};
use crate::{
    ISA_ARGUMENT_ZERO_BITS_START, NativeField, TRACE_ARITHMETIC_CARRY, TRACE_ARITHMETIC_HALF_CARRY,
    TRACE_BEFORE_CPU_BYTE_BITS_START, TRACE_BEFORE_SP_BITS_START, TRACE_IMMEDIATE_LOW,
    TRACE_IMMEDIATE_LOW_BITS_START, TRACE_OPERAND_VALUE, TRACE_RESULT_VALUE,
    TRACE_SIGNED_SP_OVERFLOW, TRACE_SIGNED_SP_UNDERFLOW, TRACE_WORD_CARRY, TRACE_WORD_HALF_CARRY,
    TRACE_WORD_WRAP, UniformError,
};

const STATE_B: usize = 1;
const STATE_C: usize = 2;
const STATE_D: usize = 3;
const STATE_E: usize = 4;
const STATE_H: usize = 5;
const STATE_L: usize = 6;
const STATE_SP: usize = 9;

pub(super) fn constrain_word_operations(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for column in [
        TRACE_WORD_WRAP,
        TRACE_WORD_CARRY,
        TRACE_WORD_HALF_CARRY,
        TRACE_SIGNED_SP_UNDERFLOW,
        TRACE_SIGNED_SP_OVERFLOW,
    ] {
        sink.push(boolean(view.value(column)?))?;
    }
    let instruction = view.mode(INSTRUCTION_MODE)?;
    constrain_increment_decrement(view, sink, instruction)?;
    constrain_add_hl(view, sink, instruction)?;
    constrain_signed_sp(view, sink, instruction)?;
    constrain_word_witness_scope(view, sink, instruction)
}

/// Packed-v2 affine word glue; table-backed word additions are constrained elsewhere.
pub(super) fn constrain_word_operations_with_lookup(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    sink.push(boolean(view.value(TRACE_WORD_WRAP)?))?;
    let instruction = view.mode(INSTRUCTION_MODE)?;
    constrain_increment_decrement(view, sink, instruction)?;
    constrain_word_wrap_scope(view, sink, instruction)
}

fn constrain_increment_decrement(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let increment = operation_selector(view, 7)?;
    let decrement = operation_selector(view, 8)?;
    let current = selected_register_word(view, false)?;
    let next = selected_register_word(view, true)?;
    let wrap = view.value(TRACE_WORD_WRAP)?;
    sink.push(
        instruction * increment * (next - current - one + NativeField::from_u64(65_536) * wrap),
    )?;
    sink.push(
        instruction * decrement * (next - current + one - NativeField::from_u64(65_536) * wrap),
    )?;
    let indirect = operation_selector(view, 6)?;
    let hl_increment = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 2)?;
    let hl_decrement = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 3)?;
    let current_hl = register_word(view, false, STATE_H, STATE_L)?;
    let next_hl = register_word(view, true, STATE_H, STATE_L)?;
    sink.push(
        instruction
            * indirect
            * hl_increment
            * (next_hl - current_hl - one + NativeField::from_u64(65_536) * wrap),
    )?;
    sink.push(
        instruction
            * indirect
            * hl_decrement
            * (next_hl - current_hl + one - NativeField::from_u64(65_536) * wrap),
    )?;
    let load_sp = operation_selector(view, 27)?;
    sink.push(instruction * load_sp * (view.after(STATE_SP)? - current_hl))
}

fn constrain_add_hl(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
) -> Result<(), UniformError> {
    let add = operation_selector(view, 5)?;
    let current = register_word(view, false, STATE_H, STATE_L)?;
    let next = register_word(view, true, STATE_H, STATE_L)?;
    let operand = selected_register_word(view, false)?;
    let carry = view.value(TRACE_WORD_CARRY)?;
    sink.push(
        instruction * add * (current + operand - next - NativeField::from_u64(65_536) * carry),
    )?;
    let current_low = word_low_twelve(view, 2)?;
    let operand_low = selected_word_low_twelve(view)?;
    let next_low = after_hl_low_twelve(view)?;
    let half = view.value(TRACE_WORD_HALF_CARRY)?;
    sink.push(
        instruction
            * add
            * (current_low + operand_low - next_low - NativeField::from_u64(4_096) * half),
    )?;
    let zero = before_flag_bit(view, 7)?;
    let flags = zero * NativeField::from_u64(128)
        + half * NativeField::from_u64(32)
        + carry * NativeField::from_u64(16);
    sink.push(instruction * add * (view.after(STATE_FLAGS)? - flags))
}

fn constrain_signed_sp(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
) -> Result<(), UniformError> {
    let add_sp = operation_selector(view, 22)?;
    let load_hl = operation_selector(view, 23)?;
    let signed = add_sp + load_hl;
    let immediate = view.value(TRACE_IMMEDIATE_LOW)?;
    sink.push(instruction * signed * (view.value(TRACE_OPERAND_VALUE)? - immediate))?;
    let sign = view.value(TRACE_IMMEDIATE_LOW_BITS_START + 7)?;
    let underflow = view.value(TRACE_SIGNED_SP_UNDERFLOW)?;
    let overflow = view.value(TRACE_SIGNED_SP_OVERFLOW)?;
    sink.push(underflow * overflow)?;
    let after_hl = register_word(view, true, STATE_H, STATE_L)?;
    let target_delta = -view.before(STATE_SP)? - immediate + NativeField::from_u64(256) * sign
        - NativeField::from_u64(65_536) * underflow
        + NativeField::from_u64(65_536) * overflow;
    sink.push(instruction * add_sp * (view.after(STATE_SP)? + target_delta))?;
    sink.push(instruction * load_hl * (after_hl + target_delta))?;
    let sp_low = packed_bits(view, TRACE_BEFORE_SP_BITS_START, 8)?;
    sink.push(
        instruction
            * signed
            * (sp_low + immediate
                - view.value(TRACE_RESULT_VALUE)?
                - NativeField::from_u64(256) * view.value(TRACE_ARITHMETIC_CARRY)?),
    )?;
    let sp_nibble = packed_bits(view, TRACE_BEFORE_SP_BITS_START, 4)?;
    let immediate_nibble = packed_bits(view, TRACE_IMMEDIATE_LOW_BITS_START, 4)?;
    let result_nibble = result_low_nibble(view)?;
    sink.push(
        instruction
            * signed
            * (sp_nibble + immediate_nibble
                - result_nibble
                - NativeField::from_u64(16) * view.value(TRACE_ARITHMETIC_HALF_CARRY)?),
    )?;
    let flags = view.value(TRACE_ARITHMETIC_HALF_CARRY)? * NativeField::from_u64(32)
        + view.value(TRACE_ARITHMETIC_CARRY)? * NativeField::from_u64(16);
    sink.push(instruction * signed * (view.after(STATE_FLAGS)? - flags))
}

fn constrain_word_witness_scope(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let indirect = operation_selector(view, 6)?;
    let changes_hl = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 2)?
        + argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 3)?;
    let wrap_use = instruction
        * (operation_selector(view, 7)? + operation_selector(view, 8)? + indirect * changes_hl);
    sink.push((one - wrap_use) * view.value(TRACE_WORD_WRAP)?)?;
    let add = instruction * operation_selector(view, 5)?;
    sink.push((one - add) * view.value(TRACE_WORD_CARRY)?)?;
    sink.push((one - add) * view.value(TRACE_WORD_HALF_CARRY)?)?;
    let signed = instruction * (operation_selector(view, 22)? + operation_selector(view, 23)?);
    sink.push((one - signed) * view.value(TRACE_SIGNED_SP_UNDERFLOW)?)?;
    sink.push((one - signed) * view.value(TRACE_SIGNED_SP_OVERFLOW)?)
}

fn constrain_word_wrap_scope(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    instruction: NativeField,
) -> Result<(), UniformError> {
    let indirect = operation_selector(view, 6)?;
    let changes_hl = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 2)?
        + argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 3)?;
    let wrap_use = instruction
        * (operation_selector(view, 7)? + operation_selector(view, 8)? + indirect * changes_hl);
    sink.push((NativeField::from_u64(1) - wrap_use) * view.value(TRACE_WORD_WRAP)?)
}

fn selected_register_word(view: &RowView<'_>, after: bool) -> Result<NativeField, UniformError> {
    let mut selected = NativeField::from_u64(0);
    for (argument, high, low) in [
        (0, STATE_B, STATE_C),
        (1, STATE_D, STATE_E),
        (2, STATE_H, STATE_L),
    ] {
        selected += argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, argument)?
            * register_word(view, after, high, low)?;
    }
    let sp = if after {
        view.after(STATE_SP)?
    } else {
        view.before(STATE_SP)?
    };
    selected += argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 3)? * sp;
    Ok(selected)
}

fn selected_word_low_twelve(view: &RowView<'_>) -> Result<NativeField, UniformError> {
    let mut selected = NativeField::from_u64(0);
    for argument in 0..4 {
        selected += argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, argument)?
            * word_low_twelve(view, argument)?;
    }
    Ok(selected)
}

fn word_low_twelve(view: &RowView<'_>, argument: u8) -> Result<NativeField, UniformError> {
    let (high_byte, low_byte) = match argument {
        0 => (STATE_B, STATE_C),
        1 => (STATE_D, STATE_E),
        2 => (STATE_H, STATE_L),
        3 => return packed_bits(view, TRACE_BEFORE_SP_BITS_START, 12),
        _ => return Err(UniformError::Shape),
    };
    let high_nibble = packed_bits(view, TRACE_BEFORE_CPU_BYTE_BITS_START + high_byte * 8, 4)?;
    Ok(view.before(low_byte)? + NativeField::from_u64(256) * high_nibble)
}

fn after_hl_low_twelve(view: &RowView<'_>) -> Result<NativeField, UniformError> {
    let high_nibble = packed_bits(
        view,
        crate::TRACE_AFTER_CPU_BYTE_BITS_START + STATE_H * 8,
        4,
    )?;
    Ok(view.after(STATE_L)? + NativeField::from_u64(256) * high_nibble)
}

fn result_low_nibble(view: &RowView<'_>) -> Result<NativeField, UniformError> {
    packed_bits(view, crate::TRACE_RESULT_BITS_START, 4)
}

fn register_word(
    view: &RowView<'_>,
    after: bool,
    high: usize,
    low: usize,
) -> Result<NativeField, UniformError> {
    let high = if after {
        view.after(high)?
    } else {
        view.before(high)?
    };
    let low = if after {
        view.after(low)?
    } else {
        view.before(low)?
    };
    Ok(high * NativeField::from_u64(256) + low)
}

fn before_flag_bit(view: &RowView<'_>, bit: usize) -> Result<NativeField, UniformError> {
    view.value(TRACE_BEFORE_CPU_BYTE_BITS_START + STATE_FLAGS * 8 + bit)
}
