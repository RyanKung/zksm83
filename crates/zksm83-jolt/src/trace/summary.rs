use zksm83_core::StepKind;
use zksm83_trace::TraceRow;

use crate::TRACE_SUMMARY_AUX;

use super::{NativeTraceError, append};

pub(super) fn append_aux(
    columns: &mut [Vec<u64>],
    row: &TraceRow,
    cycle_increment: u64,
) -> Result<(), NativeTraceError> {
    let value = match row.effects().kind() {
        StepKind::BlueSoundWait if row.after().cpu().registers().a != 0 => cycle_increment
            .checked_div(19)
            .filter(|quotient| quotient.checked_mul(19) == Some(cycle_increment))
            .ok_or(NativeTraceError::Layout)?,
        StepKind::BlueDelayLoop => {
            let before = row.before().cpu().registers();
            let after = row.after().cpu().registers();
            u64::from(
                u16::from_be_bytes([before.d, before.e])
                    .checked_sub(u16::from_be_bytes([after.d, after.e]))
                    .ok_or(NativeTraceError::Layout)?,
            )
        }
        _ => 0,
    };
    append(columns, TRACE_SUMMARY_AUX, value)
}

pub(super) fn append_empty_aux(columns: &mut [Vec<u64>]) -> Result<(), NativeTraceError> {
    append(columns, TRACE_SUMMARY_AUX, 0)
}
