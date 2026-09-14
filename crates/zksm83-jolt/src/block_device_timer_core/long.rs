//! Closed-form timer constraints for long HALT rows.

use zksm83_core::StepKind;

use super::*;
use crate::block_boundary::local_state_value;

pub(super) fn append_long_timer_state(
    row: &mut [u64],
    block: &BasicBlock,
    block_index: usize,
) -> Result<(), BlockDeviceTimerCoreError> {
    let Some(kind) = block.rows().next().map(|source| source.effects().kind()) else {
        return Ok(());
    };
    let long = matches!(
        kind,
        StepKind::HaltUntilVBlank | StepKind::HaltUntilSerial | StepKind::HaltUntilTimer
    );
    if block.row_count() != 1 || !long {
        return Ok(());
    }
    append_bits(
        row,
        LONG_BEFORE_COUNTER_BITS_START,
        u64::from(block.initial_state().dmg_devices().timer().counter()),
        8,
    )?;
    append_bits(
        row,
        LONG_AFTER_COUNTER_BITS_START,
        u64::from(block.final_state().dmg_devices().timer().counter()),
        8,
    )?;
    if kind != StepKind::HaltUntilTimer {
        return Ok(());
    }
    let interrupt_ticks = block
        .initial_state()
        .dmg_devices()
        .timer()
        .t_cycles_until_interrupt()
        .ok_or(BlockDeviceTimerCoreError::InvalidTransition { block: block_index })?;
    let elapsed = block
        .m_cycle_count()
        .checked_mul(4)
        .ok_or(BlockDeviceTimerCoreError::InvalidTransition { block: block_index })?;
    let gap = elapsed
        .checked_sub(u64::from(interrupt_ticks))
        .ok_or(BlockDeviceTimerCoreError::InvalidTransition { block: block_index })?;
    if gap >= 4 {
        return Err(BlockDeviceTimerCoreError::InvalidTransition { block: block_index });
    }
    append_bits(row, LONG_TIMER_GAP_BITS_START, gap, 2)
}

pub(super) fn constrain_long_quiet_timer(
    timer: &[NativeField],
    boundary: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let long = halt_until_vblank_value(timer)? + halt_until_serial_value(timer)?;
    sink.push(long * low_pack_bit_value(timer, false, 26)?)?;
    for after in [false, true] {
        sink.push(long * device_state_value(boundary, after, STATE_TIMER_RELOAD_PHASE_INDEX)?)?;
        sink.push(long * device_state_value(boundary, after, STATE_TIMER_EDGE_LATCH_INDEX)?)?;
    }
    sink.push(
        long * (device_state_value(boundary, true, STATE_TIMER_COUNTER_INDEX)?
            - device_state_value(boundary, false, STATE_TIMER_COUNTER_INDEX)?),
    )?;
    sink.push(
        long * (interrupt_request_bit_value(timer, true, 2)?
            - interrupt_request_bit_value(timer, false, 2)?),
    )
}

pub(super) fn constrain_long_timer(
    timer: &[NativeField],
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let selected = halt_until_timer_value(timer)?;
    let one = NativeField::from_u64(1);
    sink.push(selected * (low_pack_bit_value(timer, false, 26)? - one))?;
    sink.push(selected * device_state_value(boundary, false, STATE_TIMER_RELOAD_PHASE_INDEX)?)?;
    let (period, remainder, fastest) = timer_period_and_remainder(timer)?;
    let before_latch = device_state_value(boundary, false, STATE_TIMER_EDGE_LATCH_INDEX)?;
    sink.push(selected * (before_latch - initial_timer_detector(timer)?))?;
    let before_counter = packed_bits(auxiliary, LONG_BEFORE_COUNTER_BITS_START, 8)?;
    let interrupt_ticks = period - remainder
        + (NativeField::from_u64(255) - before_counter) * period
        + NativeField::from_u64(5);
    let cycles = local_state_value(
        boundary,
        BASIC_BLOCK_INSTRUCTION_BOUND,
        STATE_CPU_M_CYCLES_INDEX,
    )? - local_state_value(boundary, 0, STATE_CPU_M_CYCLES_INDEX)?;
    let gap = packed_bits(auxiliary, LONG_TIMER_GAP_BITS_START, 2)?;
    sink.push(selected * (NativeField::from_u64(4) * cycles - interrupt_ticks - gap))?;
    sink.push(
        selected
            * (packed_bits(auxiliary, LONG_AFTER_COUNTER_BITS_START, 8)?
                - low_pack_byte(timer, 16)?),
    )?;
    sink.push(selected * device_state_value(boundary, true, STATE_TIMER_RELOAD_PHASE_INDEX)?)?;
    let gap_three = value(auxiliary, LONG_TIMER_GAP_BITS_START)?
        * value(auxiliary, LONG_TIMER_GAP_BITS_START + 1)?;
    sink.push(
        selected
            * (device_state_value(boundary, true, STATE_TIMER_EDGE_LATCH_INDEX)?
                - fastest * gap_three),
    )?;
    sink.push(selected * (interrupt_request_bit_value(timer, true, 2)? - one))
}

fn initial_timer_detector(timer: &[NativeField]) -> Result<NativeField, UniformError> {
    let bit_zero = low_pack_bit_value(timer, false, 24)?;
    let bit_one = low_pack_bit_value(timer, false, 25)?;
    let enabled = low_pack_bit_value(timer, false, 26)?;
    let one = NativeField::from_u64(1);
    let selected = (one - bit_zero) * (one - bit_one) * timer_div_bit_value(timer, false, 9)?
        + bit_zero * (one - bit_one) * timer_div_bit_value(timer, false, 3)?
        + (one - bit_zero) * bit_one * timer_div_bit_value(timer, false, 5)?
        + bit_zero * bit_one * timer_div_bit_value(timer, false, 7)?;
    Ok(enabled * selected)
}

fn timer_period_and_remainder(
    timer: &[NativeField],
) -> Result<(NativeField, NativeField, NativeField), UniformError> {
    let bit_zero = low_pack_bit_value(timer, false, 24)?;
    let bit_one = low_pack_bit_value(timer, false, 25)?;
    let one = NativeField::from_u64(1);
    let slow = (one - bit_zero) * (one - bit_one);
    let fastest = bit_zero * (one - bit_one);
    let medium = (one - bit_zero) * bit_one;
    let fast = bit_zero * bit_one;
    let period = NativeField::from_u64(1_024) * slow
        + NativeField::from_u64(16) * fastest
        + NativeField::from_u64(64) * medium
        + NativeField::from_u64(256) * fast;
    let remainder = slow * pack_timer_divider_width(timer, false, 10)?
        + fastest * pack_timer_divider_width(timer, false, 4)?
        + medium * pack_timer_divider_width(timer, false, 6)?
        + fast * pack_timer_divider_width(timer, false, 8)?;
    Ok((period, remainder, fastest))
}
