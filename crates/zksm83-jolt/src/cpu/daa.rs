//! Exact low-degree SM83 decimal-adjust identities.

use akita_pcs::Ring;

use super::{ConstraintSink, INSTRUCTION_MODE, RowView, STATE_FLAGS, boolean, operation_selector};
use crate::{
    NativeField, TRACE_ARITHMETIC_CARRY, TRACE_ARITHMETIC_HALF_CARRY,
    TRACE_BEFORE_CPU_BYTE_BITS_START, TRACE_DAA_ACC_GT_99, TRACE_DAA_HIGH_ADJUST,
    TRACE_DAA_HIGH_EQUALS_NINE, TRACE_DAA_HIGH_GT_NINE, TRACE_DAA_LOW_ADJUST,
    TRACE_DAA_LOW_GT_NINE, TRACE_DAA_WRAP, TRACE_OPERAND_VALUE, TRACE_RESULT_VALUE,
    TRACE_RESULT_ZERO, UniformError,
};

const STATE_A: usize = 0;

pub(super) fn constrain_decimal_adjust(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    for column in TRACE_DAA_LOW_GT_NINE..=TRACE_DAA_WRAP {
        sink.push(boolean(view.value(column)?))?;
    }
    let instruction = view.mode(INSTRUCTION_MODE)?;
    let daa = operation_selector(view, 13)?;
    let selected = instruction * daa;
    let low_gt = view.value(TRACE_DAA_LOW_GT_NINE)?;
    let high_gt = view.value(TRACE_DAA_HIGH_GT_NINE)?;
    let high_eq_nine = view.value(TRACE_DAA_HIGH_EQUALS_NINE)?;
    let acc_gt = view.value(TRACE_DAA_ACC_GT_99)?;
    let low_adjust = view.value(TRACE_DAA_LOW_ADJUST)?;
    let high_adjust = view.value(TRACE_DAA_HIGH_ADJUST)?;
    let low_one = accumulator_bit(view, 1)?;
    let low_two = accumulator_bit(view, 2)?;
    let low_three = accumulator_bit(view, 3)?;
    let high_zero = accumulator_bit(view, 4)?;
    let high_one = accumulator_bit(view, 5)?;
    let high_two = accumulator_bit(view, 6)?;
    let high_three = accumulator_bit(view, 7)?;
    sink.push(selected * (low_gt - low_three * (low_two + low_one - low_two * low_one)))?;
    sink.push(selected * (high_gt - high_three * (high_two + high_one - high_two * high_one)))?;
    sink.push(
        selected * (high_eq_nine - high_three * (one - high_two) * (one - high_one) * high_zero),
    )?;
    sink.push(selected * (acc_gt - high_gt - high_eq_nine * low_gt))?;
    let subtract = before_flag_bit(view, 6)?;
    let half = before_flag_bit(view, 5)?;
    let carry = before_flag_bit(view, 4)?;
    let low_or = half + low_gt - half * low_gt;
    let high_or = carry + acc_gt - carry * acc_gt;
    sink.push(selected * (low_adjust - subtract * half - (one - subtract) * low_or))?;
    sink.push(selected * (high_adjust - subtract * carry - (one - subtract) * high_or))?;
    let correction =
        NativeField::from_u64(6) * low_adjust + NativeField::from_u64(96) * high_adjust;
    let wrap = view.value(TRACE_DAA_WRAP)?;
    let result = view.value(TRACE_RESULT_VALUE)?;
    sink.push(
        selected
            * (view.before(STATE_A)? + (one - NativeField::from_u64(2) * subtract) * correction
                - result
                - NativeField::from_u64(256) * wrap
                + NativeField::from_u64(512) * subtract * wrap),
    )?;
    sink.push(selected * (view.value(TRACE_OPERAND_VALUE)? - view.before(STATE_A)?))?;
    sink.push(selected * (view.after(STATE_A)? - result))?;
    sink.push(selected * (view.value(TRACE_ARITHMETIC_CARRY)? - high_adjust))?;
    sink.push(selected * view.value(TRACE_ARITHMETIC_HALF_CARRY)?)?;
    let flags = view.value(TRACE_RESULT_ZERO)? * NativeField::from_u64(128)
        + subtract * NativeField::from_u64(64)
        + high_adjust * NativeField::from_u64(16);
    sink.push(selected * (view.after(STATE_FLAGS)? - flags))?;
    for column in TRACE_DAA_LOW_GT_NINE..=TRACE_DAA_WRAP {
        sink.push((one - selected) * view.value(column)?)?;
    }
    Ok(())
}

fn accumulator_bit(view: &RowView<'_>, bit: usize) -> Result<NativeField, UniformError> {
    view.value(TRACE_BEFORE_CPU_BYTE_BITS_START + bit)
}

fn before_flag_bit(view: &RowView<'_>, bit: usize) -> Result<NativeField, UniformError> {
    view.value(TRACE_BEFORE_CPU_BYTE_BITS_START + STATE_FLAGS * 8 + bit)
}
