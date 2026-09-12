//! Native auxiliary predicates for the SM83 decimal-adjust instruction.

use zksm83_core::StepKind;
use zksm83_isa::AlignedInstruction;
use zksm83_trace::TraceRow;

use super::{
    NativeTraceError, TRACE_DAA_ACC_GT_99, TRACE_DAA_HIGH_ADJUST, TRACE_DAA_HIGH_EQUALS_NINE,
    TRACE_DAA_HIGH_GT_NINE, TRACE_DAA_LOW_ADJUST, TRACE_DAA_LOW_GT_NINE, TRACE_DAA_WRAP, append,
};

pub(super) fn append_daa_witness(
    columns: &mut [Vec<u64>],
    row: &TraceRow,
) -> Result<(), NativeTraceError> {
    let aligned = AlignedInstruction::from_decoded(row.effects().instruction());
    if row.effects().kind() != StepKind::Instruction || aligned.operation != 13 {
        return append_empty_daa_witness(columns);
    }
    let accumulator = row.before().cpu().registers().a;
    let flags = row.before().cpu().flags();
    let low_gt_nine = accumulator & 0x0f > 9;
    let high_gt_nine = accumulator >> 4 > 9;
    let high_equals_nine = accumulator >> 4 == 9;
    let acc_gt_99 = accumulator > 0x99;
    let low_adjust = if flags.subtract() {
        flags.half_carry()
    } else {
        flags.half_carry() || low_gt_nine
    };
    let high_adjust = if flags.subtract() {
        flags.carry()
    } else {
        flags.carry() || acc_gt_99
    };
    let correction = 6_u16 * u16::from(low_adjust) + 96_u16 * u16::from(high_adjust);
    let wrap = if flags.subtract() {
        u16::from(accumulator) < correction
    } else {
        u16::from(accumulator) + correction > u16::from(u8::MAX)
    };
    for (column, value) in [
        (TRACE_DAA_LOW_GT_NINE, low_gt_nine),
        (TRACE_DAA_HIGH_GT_NINE, high_gt_nine),
        (TRACE_DAA_HIGH_EQUALS_NINE, high_equals_nine),
        (TRACE_DAA_ACC_GT_99, acc_gt_99),
        (TRACE_DAA_LOW_ADJUST, low_adjust),
        (TRACE_DAA_HIGH_ADJUST, high_adjust),
        (TRACE_DAA_WRAP, wrap),
    ] {
        append(columns, column, u64::from(value))?;
    }
    Ok(())
}

pub(super) fn append_empty_daa_witness(columns: &mut [Vec<u64>]) -> Result<(), NativeTraceError> {
    for column in TRACE_DAA_LOW_GT_NINE..=TRACE_DAA_WRAP {
        append(columns, column, 0)?;
    }
    Ok(())
}
