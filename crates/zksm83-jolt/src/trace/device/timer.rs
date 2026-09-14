//! Witness helpers for long timer-interrupt advancement.

use zksm83_core::{StepKind, VmState};
use zksm83_trace::TraceRow;

use crate::trace::{NativeTraceError, append_bits};

use super::TRACE_TIMER_INTERRUPT_GAP_BITS_START;

pub(super) fn append_interrupt_gap(
    columns: &mut [Vec<u64>],
    before: VmState,
    increment: u64,
    row: Option<&TraceRow>,
) -> Result<(), NativeTraceError> {
    let gap = if row.is_some_and(|row| row.effects().kind() == StepKind::HaltUntilTimer) {
        let interrupt_t_cycles = before
            .dmg_devices()
            .timer()
            .t_cycles_until_interrupt()
            .ok_or(NativeTraceError::Layout)?;
        increment
            .checked_mul(4)
            .and_then(|ticks| ticks.checked_sub(u64::from(interrupt_t_cycles)))
            .ok_or(NativeTraceError::Layout)?
    } else {
        0
    };
    if gap >= 4 {
        return Err(NativeTraceError::Layout);
    }
    append_bits(columns, TRACE_TIMER_INTERRUPT_GAP_BITS_START, gap, 2)
}
