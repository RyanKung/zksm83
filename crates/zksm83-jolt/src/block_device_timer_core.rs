//! Shared bounded TIMA, reload, edge-latch, and timer-IF transition.

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_core::DmgTimerState;
use zksm83_trace::{BASIC_BLOCK_INSTRUCTION_BOUND, BASIC_BLOCK_M_CYCLE_BOUND, BasicBlock};

use crate::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_DEVICE_TIMER_COLUMN_COUNT,
    BLOCK_DEVICE_TIMER_CONSTRAINT_COUNT, BLOCK_DEVICE_TIMER_MAX_DEGREE,
    BLOCK_FRONTEND_COLUMN_COUNT, BLOCK_ROUTING_COLUMN_COUNT, BlockDevicePpuError,
    BlockDeviceSerialError, BlockDeviceTimerError, BlockDeviceTimerRelation,
    BlockDeviceTimerWitness, ConstraintOutput, NativeField, STATE_CPU_M_CYCLES_INDEX,
    STATE_TIMER_COUNTER_INDEX, STATE_TIMER_EDGE_LATCH_INDEX, STATE_TIMER_RELOAD_PHASE_INDEX,
    UNIFORM_ROW_COUNT, UniformError, UniformRelation,
    block_boundary::device_state_value,
    block_device::{device_io_selector_value, interrupt_source_bit, short_device_clocked_block},
    block_device_ppu::low_pack_bit_value,
    block_device_serial::interrupt_request_bit_value,
    block_device_timer::timer_div_bit_value,
    block_device_timer_stage::{
        STAGE_COUNTER_BITS_OFFSET, STAGE_COUNTER_OVERFLOW_OFFSET, STAGE_DIV_BITS_OFFSET,
        STAGE_DIV_WRAP_OFFSET, STAGE_INTERRUPT_OFFSET, STAGE_LATCH_OFFSET, STAGE_PHASE_BITS_OFFSET,
        STAGE_RELOAD_COUNTER_BITS_OFFSET, STAGE_RELOAD_PHASE_BITS_OFFSET, STAGE_WIDTH,
        TIMER_STAGE_COLUMN_COUNT, TIMER_TICK_BOUND,
    },
    block_machine::{
        halt_until_serial_value, halt_until_timer_value, halt_until_vblank_value,
        interrupt_source_value, short_cycle_active_value, short_device_clocked_value,
    },
    block_routing::cycle_owner_value,
};

mod long;

use long::{append_long_timer_state, constrain_long_quiet_timer, constrain_long_timer};

const TIMER_CORE_AUX_START: usize = BLOCK_DEVICE_TIMER_COLUMN_COUNT;
const QUIET_SELECTOR: usize = 0;
const BEFORE_COUNTER_BITS_START: usize = QUIET_SELECTOR + 1;
const BEFORE_PHASE_BITS_START: usize = BEFORE_COUNTER_BITS_START + 8;
const BEFORE_LATCH: usize = BEFORE_PHASE_BITS_START + 3;
const STAGE_START: usize = BEFORE_LATCH + 1;
const LONG_TIMER_GAP_BITS_START: usize = STAGE_START + TIMER_TICK_BOUND * STAGE_WIDTH;
const LONG_BEFORE_COUNTER_BITS_START: usize = LONG_TIMER_GAP_BITS_START + 2;
const LONG_AFTER_COUNTER_BITS_START: usize = LONG_BEFORE_COUNTER_BITS_START + 8;
const TIMER_CORE_AUX_COLUMN_COUNT: usize = LONG_AFTER_COUNTER_BITS_START + 8;
const TIMER_CORE_PER_TICK_CONSTRAINT_COUNT: usize = 12;
const TIMER_CORE_LONG_CONSTRAINT_COUNT: usize = 15;
const TIMER_CORE_ADDITIONAL_CONSTRAINT_COUNT: usize = 2
    + (STAGE_START - BEFORE_COUNTER_BITS_START) * 2
    + TIMER_STAGE_COLUMN_COUNT * 2
    + 2 * 2
    + 2 * 8 * 2
    + 2
    + 4
    + TIMER_TICK_BOUND * TIMER_CORE_PER_TICK_CONSTRAINT_COUNT
    + 5
    + TIMER_CORE_LONG_CONSTRAINT_COUNT;

pub(crate) const SHARED_TIMER_STAGE_COLUMN_START: usize = TIMER_CORE_AUX_START + STAGE_START;
pub(crate) const SHARED_TIMER_STAGE_COLUMN_COUNT: usize = TIMER_STAGE_COLUMN_COUNT;

/// Logical columns in the timer-divider relation plus the full bounded timer core.
pub const BLOCK_DEVICE_TIMER_CORE_COLUMN_COUNT: usize =
    BLOCK_DEVICE_TIMER_COLUMN_COUNT + TIMER_CORE_AUX_COLUMN_COUNT;
/// Identities in the bounded timer-core relation.
pub const BLOCK_DEVICE_TIMER_CORE_CONSTRAINT_COUNT: usize =
    BLOCK_DEVICE_TIMER_CONSTRAINT_COUNT + TIMER_CORE_ADDITIONAL_CONSTRAINT_COUNT;
/// Maximum total degree in the bounded timer-core relation.
pub const BLOCK_DEVICE_TIMER_CORE_MAX_DEGREE: usize = BLOCK_DEVICE_TIMER_MAX_DEGREE;

const _: () = assert!(BASIC_BLOCK_INSTRUCTION_BOUND == 4);
const _: () = assert!(BASIC_BLOCK_M_CYCLE_BOUND == 6);
const _: () = assert!(TIMER_TICK_BOUND == 24);
const _: () = assert!(TIMER_CORE_AUX_COLUMN_COUNT == 1_039);
const _: () = assert!(TIMER_CORE_ADDITIONAL_CONSTRAINT_COUNT == 2_392);
const _: () = assert!(BLOCK_DEVICE_TIMER_CORE_COLUMN_COUNT == 2_238);
const _: () = assert!(BLOCK_DEVICE_TIMER_CORE_CONSTRAINT_COUNT == 4_768);
const _: () = assert!(BLOCK_DEVICE_TIMER_CORE_MAX_DEGREE == 7);

/// Fixed-row witness carrying one 24-tick-bounded timer transition per quiet block.
#[derive(Debug)]
pub struct BlockDeviceTimerCoreWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to construct the shared packed-block timer-core witness.
#[derive(Debug, Error)]
pub enum BlockDeviceTimerCoreError {
    /// Timer-divider witness construction failed.
    #[error("packed-block timer-divider construction failed: {0}")]
    Timer(#[from] BlockDeviceTimerError),
    /// A validated block exposed an inconsistent timer-core transition.
    #[error("packed block {block} has an inconsistent quiet timer-core transition")]
    InvalidTransition {
        /// Zero-based packed-block row.
        block: usize,
    },
    /// Timer-core auxiliary columns violated their fixed layout.
    #[error("packed-block timer-core witness violated its typed layout")]
    Layout,
}

/// Timer-divider relation plus exact bounded TIMA, reload, latch, and IF semantics.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockDeviceTimerCoreRelation;

impl BlockDeviceTimerCoreWitness {
    /// Derives a shared timer-core witness for each bounded device-clocked block.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockDeviceTimerCoreError> {
        let timer = BlockDeviceTimerWitness::from_blocks(blocks)?;
        let active_block_count = timer.active_block_count();
        let mut auxiliary = (0..TIMER_CORE_AUX_COLUMN_COUNT)
            .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
            .collect::<Vec<_>>();
        for (block_index, block) in blocks.iter().enumerate() {
            let mut row = [0_u64; TIMER_CORE_AUX_COLUMN_COUNT];
            let quiet = quiet_instruction_block(block)?;
            set(&mut row, QUIET_SELECTOR, u64::from(quiet))?;
            if quiet {
                append_quiet_timer_core(&mut row, block, block_index)?;
            }
            append_long_timer_state(&mut row, block, block_index)?;
            for (column, value) in auxiliary.iter_mut().zip(row) {
                column.push(value);
            }
        }
        for column in &mut auxiliary {
            column.resize(UNIFORM_ROW_COUNT, 0);
        }
        let mut columns = timer.into_columns();
        columns.extend(auxiliary);
        if columns.len() != BLOCK_DEVICE_TIMER_CORE_COLUMN_COUNT {
            return Err(BlockDeviceTimerCoreError::Layout);
        }
        Ok(Self {
            columns,
            active_block_count,
        })
    }

    /// Returns every logical column in timer-divider-then-core order.
    #[must_use]
    pub fn columns(&self) -> &[Vec<u64>] {
        &self.columns
    }

    /// Returns the number of non-padding packed-block rows.
    #[must_use]
    pub const fn active_block_count(&self) -> usize {
        self.active_block_count
    }

    pub(crate) fn into_columns(self) -> Vec<Vec<u64>> {
        self.columns
    }
}

impl UniformRelation for BlockDeviceTimerCoreRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-device-timer-core/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [1_199_u64, 2_376, 24, 42, 2, 16, 2_238, 4_768, 2] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_DEVICE_TIMER_CORE_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_DEVICE_TIMER_CORE_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_DEVICE_TIMER_CORE_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_DEVICE_TIMER_CORE_COLUMN_COUNT
            || constraints.len() != BLOCK_DEVICE_TIMER_CORE_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let timer = row
            .get(..BLOCK_DEVICE_TIMER_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let auxiliary = row
            .get(TIMER_CORE_AUX_START..BLOCK_DEVICE_TIMER_CORE_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let (timer_constraints, core_constraints) =
            constraints.split_at_mut(BLOCK_DEVICE_TIMER_CONSTRAINT_COUNT);
        BlockDeviceTimerRelation.evaluate(timer, timer_constraints)?;
        constrain_timer_core(timer, auxiliary, core_constraints)
    }
}

fn quiet_instruction_block(block: &BasicBlock) -> Result<bool, BlockDeviceTimerCoreError> {
    short_device_clocked_block(block)
        .map_err(BlockDevicePpuError::from)
        .map_err(BlockDeviceSerialError::from)
        .map_err(BlockDeviceTimerError::from)
        .map_err(BlockDeviceTimerCoreError::from)
}

fn append_quiet_timer_core(
    row: &mut [u64],
    block: &BasicBlock,
    block_index: usize,
) -> Result<(), BlockDeviceTimerCoreError> {
    let mut timer = block.initial_state().dmg_devices().timer();
    let expected = block.final_state().dmg_devices().timer();
    let mut interrupt = block.initial_state().dmg_devices().interrupt_request() & 0x04 != 0;
    if interrupt_source_bit(block, 2) {
        interrupt = false;
    }
    let expected_interrupt = block.final_state().dmg_devices().interrupt_request() & 0x04 != 0;
    let active_ticks = block
        .m_cycle_count()
        .checked_mul(4)
        .and_then(|ticks| usize::try_from(ticks).ok())
        .ok_or(BlockDeviceTimerCoreError::InvalidTransition { block: block_index })?;
    if active_ticks > TIMER_TICK_BOUND {
        return Err(BlockDeviceTimerCoreError::InvalidTransition { block: block_index });
    }
    append_bits(
        row,
        BEFORE_COUNTER_BITS_START,
        u64::from(timer.counter()),
        8,
    )?;
    append_bits(
        row,
        BEFORE_PHASE_BITS_START,
        u64::from(timer.reload_phase()),
        3,
    )?;
    set(row, BEFORE_LATCH, u64::from(timer.edge_latch()))?;
    for tick in 0..TIMER_TICK_BOUND {
        let active = tick < active_ticks;
        append_timer_tick(row, tick, active, &mut timer, &mut interrupt)?;
    }
    if timer != expected || interrupt != expected_interrupt {
        return Err(BlockDeviceTimerCoreError::InvalidTransition { block: block_index });
    }
    Ok(())
}

fn append_timer_tick(
    row: &mut [u64],
    tick: usize,
    active: bool,
    timer: &mut DmgTimerState,
    interrupt: &mut bool,
) -> Result<(), BlockDeviceTimerCoreError> {
    let start = stage_start(tick).ok_or(BlockDeviceTimerCoreError::Layout)?;
    let (reload_counter, reload_phase) = reload_intermediate(*timer);
    let next_detector = detector_input(timer.raw_div().wrapping_add(1), timer.control());
    let falling = timer.edge_latch() && !next_detector;
    let div_wrap = active && timer.raw_div() == u16::MAX;
    let overflow = active && falling && reload_counter == u8::MAX;
    if active {
        *interrupt |= timer.advance_t_cycles(1) & 0x04 != 0;
    }
    append_timer_state(row, start, *timer, *interrupt)?;
    append_bits(
        row,
        checked_add(start, STAGE_RELOAD_COUNTER_BITS_OFFSET)?,
        u64::from(reload_counter),
        8,
    )?;
    append_bits(
        row,
        checked_add(start, STAGE_RELOAD_PHASE_BITS_OFFSET)?,
        u64::from(reload_phase),
        3,
    )?;
    set(
        row,
        checked_add(start, STAGE_DIV_WRAP_OFFSET)?,
        u64::from(div_wrap),
    )?;
    set(
        row,
        checked_add(start, STAGE_COUNTER_OVERFLOW_OFFSET)?,
        u64::from(overflow),
    )
}

fn append_timer_state(
    row: &mut [u64],
    start: usize,
    timer: DmgTimerState,
    interrupt: bool,
) -> Result<(), BlockDeviceTimerCoreError> {
    append_bits(row, start, u64::from(timer.raw_div()), 16)?;
    append_bits(
        row,
        checked_add(start, STAGE_COUNTER_BITS_OFFSET)?,
        u64::from(timer.counter()),
        8,
    )?;
    append_bits(
        row,
        checked_add(start, STAGE_PHASE_BITS_OFFSET)?,
        u64::from(timer.reload_phase()),
        3,
    )?;
    set(
        row,
        checked_add(start, STAGE_LATCH_OFFSET)?,
        u64::from(timer.edge_latch()),
    )?;
    set(
        row,
        checked_add(start, STAGE_INTERRUPT_OFFSET)?,
        u64::from(interrupt),
    )
}

const fn reload_intermediate(timer: DmgTimerState) -> (u8, u8) {
    if timer.reload_phase() == 5 {
        (timer.modulo(), 0)
    } else if timer.reload_phase() == 0 {
        (timer.counter(), 0)
    } else {
        (timer.counter(), timer.reload_phase() + 1)
    }
}

const fn detector_input(divider: u16, control: u8) -> bool {
    let mask = match control & 0x03 {
        0 => 1 << 9,
        1 => 1 << 3,
        2 => 1 << 5,
        _ => 1 << 7,
    };
    control & 0x04 != 0 && divider & mask != 0
}

fn append_bits(
    row: &mut [u64],
    start: usize,
    value: u64,
    width: usize,
) -> Result<(), BlockDeviceTimerCoreError> {
    for bit in 0..width {
        set(row, checked_add(start, bit)?, (value >> bit) & 1)?;
    }
    Ok(())
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), BlockDeviceTimerCoreError> {
    *row.get_mut(index)
        .ok_or(BlockDeviceTimerCoreError::Layout)? = value;
    Ok(())
}

fn checked_add(start: usize, offset: usize) -> Result<usize, BlockDeviceTimerCoreError> {
    start
        .checked_add(offset)
        .ok_or(BlockDeviceTimerCoreError::Layout)
}

fn constrain_timer_core(
    timer: &[NativeField],
    auxiliary: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if auxiliary.len() != TIMER_CORE_AUX_COLUMN_COUNT
        || constraints.len() != TIMER_CORE_ADDITIONAL_CONSTRAINT_COUNT
    {
        return Err(UniformError::Shape);
    }
    let frontend = timer
        .get(..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let device_io = device_io_selector_value(timer)?;
    let quiet = value(auxiliary, QUIET_SELECTOR)?;
    let one = NativeField::from_u64(1);
    let mut sink = ConstraintSink::new(constraints);
    sink.push(quiet * (quiet - one))?;
    sink.push(quiet - short_device_clocked_value(timer)? * (one - device_io))?;
    constrain_owned_bits(
        auxiliary,
        BEFORE_COUNTER_BITS_START,
        STAGE_START - BEFORE_COUNTER_BITS_START,
        quiet,
        &mut sink,
    )?;
    constrain_owned_bits(
        auxiliary,
        STAGE_START,
        SHARED_TIMER_STAGE_COLUMN_COUNT,
        // Invariant: quiet * device_io = 0 by the selector binding above.
        quiet + device_io,
        &mut sink,
    )?;
    let long_timer = halt_until_timer_value(timer)?;
    for gap in values(auxiliary, LONG_TIMER_GAP_BITS_START, 2)? {
        sink.push(*gap * (*gap - one))?;
        sink.push((one - long_timer) * *gap)?;
    }
    let long = halt_until_vblank_value(timer)? + halt_until_serial_value(timer)? + long_timer;
    for start in [
        LONG_BEFORE_COUNTER_BITS_START,
        LONG_AFTER_COUNTER_BITS_START,
    ] {
        for bit in values(auxiliary, start, 8)? {
            sink.push(*bit * (*bit - one))?;
            sink.push((one - long) * *bit)?;
        }
    }
    let boundary = frontend
        .get(BLOCK_ROUTING_COLUMN_COUNT..BLOCK_CONTROL_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    sink.push(
        long * (device_state_value(boundary, false, STATE_TIMER_COUNTER_INDEX)?
            - packed_bits(auxiliary, LONG_BEFORE_COUNTER_BITS_START, 8)?),
    )?;
    sink.push(
        long * (device_state_value(boundary, true, STATE_TIMER_COUNTER_INDEX)?
            - packed_bits(auxiliary, LONG_AFTER_COUNTER_BITS_START, 8)?),
    )?;
    constrain_initial_state(boundary, auxiliary, quiet, &mut sink)?;
    for tick in 0..TIMER_TICK_BOUND {
        constrain_tick(timer, auxiliary, tick, quiet, &mut sink)?;
    }
    constrain_final_state(timer, boundary, auxiliary, quiet, &mut sink)?;
    constrain_long_quiet_timer(timer, boundary, &mut sink)?;
    constrain_long_timer(timer, boundary, auxiliary, &mut sink)?;
    sink.finish()
}

fn constrain_initial_state(
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    quiet: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    sink.push(
        quiet
            * (device_state_value(boundary, false, STATE_TIMER_COUNTER_INDEX)?
                - packed_bits(auxiliary, BEFORE_COUNTER_BITS_START, 8)?),
    )?;
    sink.push(
        quiet
            * (device_state_value(boundary, false, STATE_TIMER_RELOAD_PHASE_INDEX)?
                - packed_bits(auxiliary, BEFORE_PHASE_BITS_START, 3)?),
    )?;
    sink.push(
        quiet
            * (device_state_value(boundary, false, STATE_TIMER_EDGE_LATCH_INDEX)?
                - value(auxiliary, BEFORE_LATCH)?),
    )?;
    constrain_phase_range(auxiliary, BEFORE_PHASE_BITS_START, quiet, sink)
}

fn constrain_tick(
    timer: &[NativeField],
    auxiliary: &[NativeField],
    tick: usize,
    quiet: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let active = cycle_active(timer, tick / 4)?;
    let current = current_timer_state(timer, auxiliary, tick)?;
    let next = stage_timer_state(auxiliary, tick)?;
    let reload_counter = stage_packed(auxiliary, tick, STAGE_RELOAD_COUNTER_BITS_OFFSET, 8)?;
    let reload_phase = stage_packed(auxiliary, tick, STAGE_RELOAD_PHASE_BITS_OFFSET, 3)?;
    constrain_phase_range(
        auxiliary,
        checked_stage_index(tick, STAGE_PHASE_BITS_OFFSET)?,
        quiet,
        sink,
    )?;
    constrain_phase_range(
        auxiliary,
        checked_stage_index(tick, STAGE_RELOAD_PHASE_BITS_OFFSET)?,
        quiet,
        sink,
    )?;
    constrain_reload(
        timer,
        auxiliary,
        quiet,
        current,
        reload_counter,
        reload_phase,
        sink,
    )?;
    constrain_tick_transition(
        timer,
        auxiliary,
        TickTransition {
            tick,
            quiet,
            active,
            current,
            next,
            reload_counter,
            reload_phase,
        },
        sink,
    )
}

fn constrain_tick_transition(
    timer: &[NativeField],
    auxiliary: &[NativeField],
    transition: TickTransition,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let TickTransition {
        tick,
        quiet,
        active,
        current,
        next,
        reload_counter,
        reload_phase,
    } = transition;
    let one = NativeField::from_u64(1);
    let wrap = stage_value(auxiliary, tick, STAGE_DIV_WRAP_OFFSET)?;
    let overflow = stage_value(auxiliary, tick, STAGE_COUNTER_OVERFLOW_OFFSET)?;
    let detector = timer_detector(timer, auxiliary, tick)?;
    let falling = current.latch * (one - detector);
    sink.push(quiet * wrap * (one - active))?;
    sink.push(quiet * overflow * (one - active))?;
    sink.push(quiet * overflow * (one - falling))?;
    sink.push(
        quiet
            * (next.divider - current.divider - active
                + NativeField::from_u64(65_536) * active * wrap),
    )?;
    sink.push(
        quiet
            * (next.counter
                - current.counter
                - active
                    * (reload_counter - current.counter + falling
                        - NativeField::from_u64(256) * overflow)),
    )?;
    sink.push(
        quiet
            * (next.phase
                - current.phase
                - active * (reload_phase - current.phase + overflow * (one - reload_phase))),
    )?;
    sink.push(quiet * (next.latch - current.latch - active * (detector - current.latch)))?;
    let phase_five = current_phase_five(auxiliary, tick)?;
    sink.push(
        quiet
            * (next.interrupt
                - current.interrupt
                - active * (one - current.interrupt) * phase_five),
    )
}

fn constrain_reload(
    timer: &[NativeField],
    auxiliary: &[NativeField],
    quiet: NativeField,
    current: TimerStateValues,
    reload_counter: NativeField,
    reload_phase: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let phase_five = current_phase_five_from_bits(auxiliary, current.source)?;
    let phase_zero = current_phase_zero_from_bits(auxiliary, current.source)?;
    let phase_nonzero = one - phase_zero;
    let modulo = low_pack_byte(timer, 16)?;
    sink.push(
        quiet * (reload_counter - current.counter - phase_five * (modulo - current.counter)),
    )?;
    sink.push(
        quiet
            * (reload_phase - current.phase - phase_nonzero * (one - phase_five)
                + phase_five * current.phase),
    )
}

fn constrain_final_state(
    timer: &[NativeField],
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    quiet: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let final_state = stage_timer_state(auxiliary, TIMER_TICK_BOUND - 1)?;
    let after_divider = pack_timer_divider(timer, true)?;
    for (actual, expected) in [
        (final_state.divider, after_divider),
        (
            final_state.counter,
            device_state_value(boundary, true, STATE_TIMER_COUNTER_INDEX)?,
        ),
        (
            final_state.phase,
            device_state_value(boundary, true, STATE_TIMER_RELOAD_PHASE_INDEX)?,
        ),
        (
            final_state.latch,
            device_state_value(boundary, true, STATE_TIMER_EDGE_LATCH_INDEX)?,
        ),
        (
            final_state.interrupt,
            interrupt_request_bit_value(timer, true, 2)?,
        ),
    ] {
        sink.push(quiet * (actual - expected))?;
    }
    Ok(())
}

fn current_timer_state(
    timer: &[NativeField],
    auxiliary: &[NativeField],
    tick: usize,
) -> Result<TimerStateValues, UniformError> {
    if tick == 0 {
        Ok(TimerStateValues {
            divider: pack_timer_divider(timer, false)?,
            counter: packed_bits(auxiliary, BEFORE_COUNTER_BITS_START, 8)?,
            phase: packed_bits(auxiliary, BEFORE_PHASE_BITS_START, 3)?,
            latch: value(auxiliary, BEFORE_LATCH)?,
            interrupt: interrupt_request_bit_value(timer, false, 2)?
                * (NativeField::from_u64(1) - interrupt_source_value(timer, 2)?),
            source: TimerStateSource::Before,
        })
    } else {
        let prior = tick.checked_sub(1).ok_or(UniformError::Shape)?;
        let mut state = stage_timer_state(auxiliary, prior)?;
        state.source = TimerStateSource::Stage(prior);
        Ok(state)
    }
}

fn stage_timer_state(
    auxiliary: &[NativeField],
    tick: usize,
) -> Result<TimerStateValues, UniformError> {
    Ok(TimerStateValues {
        divider: stage_packed(auxiliary, tick, STAGE_DIV_BITS_OFFSET, 16)?,
        counter: stage_packed(auxiliary, tick, STAGE_COUNTER_BITS_OFFSET, 8)?,
        phase: stage_packed(auxiliary, tick, STAGE_PHASE_BITS_OFFSET, 3)?,
        latch: stage_value(auxiliary, tick, STAGE_LATCH_OFFSET)?,
        interrupt: stage_value(auxiliary, tick, STAGE_INTERRUPT_OFFSET)?,
        source: TimerStateSource::Stage(tick),
    })
}

fn timer_detector(
    timer: &[NativeField],
    auxiliary: &[NativeField],
    tick: usize,
) -> Result<NativeField, UniformError> {
    let bit_zero = low_pack_bit_value(timer, false, 24)?;
    let bit_one = low_pack_bit_value(timer, false, 25)?;
    let enabled = low_pack_bit_value(timer, false, 26)?;
    let one = NativeField::from_u64(1);
    let selected = (one - bit_zero)
        * (one - bit_one)
        * stage_value(auxiliary, tick, STAGE_DIV_BITS_OFFSET + 9)?
        + bit_zero * (one - bit_one) * stage_value(auxiliary, tick, STAGE_DIV_BITS_OFFSET + 3)?
        + (one - bit_zero) * bit_one * stage_value(auxiliary, tick, STAGE_DIV_BITS_OFFSET + 5)?
        + bit_zero * bit_one * stage_value(auxiliary, tick, STAGE_DIV_BITS_OFFSET + 7)?;
    Ok(enabled * selected)
}

fn current_phase_five(auxiliary: &[NativeField], tick: usize) -> Result<NativeField, UniformError> {
    let source = if tick == 0 {
        TimerStateSource::Before
    } else {
        TimerStateSource::Stage(tick - 1)
    };
    current_phase_five_from_bits(auxiliary, source)
}

fn current_phase_five_from_bits(
    auxiliary: &[NativeField],
    source: TimerStateSource,
) -> Result<NativeField, UniformError> {
    fixed_phase_selector(auxiliary, source, 5)
}

fn current_phase_zero_from_bits(
    auxiliary: &[NativeField],
    source: TimerStateSource,
) -> Result<NativeField, UniformError> {
    fixed_phase_selector(auxiliary, source, 0)
}

fn fixed_phase_selector(
    auxiliary: &[NativeField],
    source: TimerStateSource,
    expected: u8,
) -> Result<NativeField, UniformError> {
    let one = NativeField::from_u64(1);
    (0..3).try_fold(one, |selector, bit| {
        let value = phase_bit(auxiliary, source, bit)?;
        Ok(if (expected >> bit) & 1 == 1 {
            selector * value
        } else {
            selector * (one - value)
        })
    })
}

fn phase_bit(
    auxiliary: &[NativeField],
    source: TimerStateSource,
    bit: usize,
) -> Result<NativeField, UniformError> {
    let index = match source {
        TimerStateSource::Before => BEFORE_PHASE_BITS_START.checked_add(bit),
        TimerStateSource::Stage(tick) => {
            checked_stage_index(tick, STAGE_PHASE_BITS_OFFSET + bit).ok()
        }
    }
    .ok_or(UniformError::Shape)?;
    value(auxiliary, index)
}

fn constrain_phase_range(
    row: &[NativeField],
    start: usize,
    quiet: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    sink.push(quiet * value(row, start + 2)? * value(row, start + 1)?)
}

fn cycle_active(timer: &[NativeField], cycle: usize) -> Result<NativeField, UniformError> {
    let mut instruction = NativeField::from_u64(0);
    for lane in 0..BASIC_BLOCK_INSTRUCTION_BOUND {
        instruction += cycle_owner_value(timer, cycle, lane)?;
    }
    Ok(instruction + short_cycle_active_value(timer, cycle)?)
}

fn pack_timer_divider(timer: &[NativeField], after: bool) -> Result<NativeField, UniformError> {
    pack_timer_divider_width(timer, after, 16)
}

fn pack_timer_divider_width(
    timer: &[NativeField],
    after: bool,
    width: usize,
) -> Result<NativeField, UniformError> {
    let mut packed = NativeField::from_u64(0);
    let mut power = NativeField::from_u64(1);
    for bit in 0..width {
        packed += power * timer_div_bit_value(timer, after, bit)?;
        power += power;
    }
    Ok(packed)
}

fn low_pack_byte(timer: &[NativeField], start: usize) -> Result<NativeField, UniformError> {
    let mut packed = NativeField::from_u64(0);
    let mut power = NativeField::from_u64(1);
    for bit in 0..8 {
        packed += power * low_pack_bit_value(timer, false, start + bit)?;
        power += power;
    }
    Ok(packed)
}

fn stage_packed(
    row: &[NativeField],
    tick: usize,
    offset: usize,
    width: usize,
) -> Result<NativeField, UniformError> {
    packed_bits(row, checked_stage_index(tick, offset)?, width)
}

fn stage_value(
    row: &[NativeField],
    tick: usize,
    offset: usize,
) -> Result<NativeField, UniformError> {
    value(row, checked_stage_index(tick, offset)?)
}

pub(crate) fn timer_stage_interrupt_value(
    row: &[NativeField],
    tick: usize,
) -> Result<NativeField, UniformError> {
    if row.len() < BLOCK_DEVICE_TIMER_CORE_COLUMN_COUNT || tick >= TIMER_TICK_BOUND {
        return Err(UniformError::Shape);
    }
    let auxiliary = row
        .get(TIMER_CORE_AUX_START..BLOCK_DEVICE_TIMER_CORE_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    stage_value(auxiliary, tick, STAGE_INTERRUPT_OFFSET)
}

fn checked_stage_index(tick: usize, offset: usize) -> Result<usize, UniformError> {
    tick.checked_mul(STAGE_WIDTH)
        .and_then(|value| value.checked_add(STAGE_START))
        .and_then(|value| value.checked_add(offset))
        .filter(|index| *index < TIMER_CORE_AUX_COLUMN_COUNT)
        .ok_or(UniformError::Shape)
}

fn stage_start(tick: usize) -> Option<usize> {
    tick.checked_mul(STAGE_WIDTH)
        .and_then(|value| value.checked_add(STAGE_START))
        .filter(|start| {
            start
                .checked_add(STAGE_WIDTH)
                .is_some_and(|end| end <= TIMER_CORE_AUX_COLUMN_COUNT)
        })
}

fn packed_bits(
    row: &[NativeField],
    start: usize,
    width: usize,
) -> Result<NativeField, UniformError> {
    let mut packed = NativeField::from_u64(0);
    let mut power = NativeField::from_u64(1);
    for bit in 0..width {
        packed += power * value(row, start.checked_add(bit).ok_or(UniformError::Shape)?)?;
        power += power;
    }
    Ok(packed)
}

fn values(row: &[NativeField], start: usize, count: usize) -> Result<&[NativeField], UniformError> {
    let end = start.checked_add(count).ok_or(UniformError::Shape)?;
    row.get(start..end).ok_or(UniformError::Shape)
}

fn constrain_owned_bits(
    auxiliary: &[NativeField],
    start: usize,
    width: usize,
    owner: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    for bit in values(auxiliary, start, width)? {
        sink.push(*bit * (*bit - one))?;
        sink.push((one - owner) * *bit)?;
    }
    Ok(())
}

fn value(row: &[NativeField], index: usize) -> Result<NativeField, UniformError> {
    row.get(index).copied().ok_or(UniformError::Shape)
}

#[derive(Clone, Copy)]
enum TimerStateSource {
    Before,
    Stage(usize),
}

#[derive(Clone, Copy)]
struct TimerStateValues {
    divider: NativeField,
    counter: NativeField,
    phase: NativeField,
    latch: NativeField,
    interrupt: NativeField,
    source: TimerStateSource,
}

#[derive(Clone, Copy)]
struct TickTransition {
    tick: usize,
    quiet: NativeField,
    active: NativeField,
    current: TimerStateValues,
    next: TimerStateValues,
    reload_counter: NativeField,
    reload_phase: NativeField,
}

struct ConstraintSink<'a> {
    constraints: &'a mut [NativeField],
    next: usize,
}

impl<'a> ConstraintSink<'a> {
    const fn new(constraints: &'a mut [NativeField]) -> Self {
        Self {
            constraints,
            next: 0,
        }
    }

    fn push(&mut self, value: NativeField) -> Result<(), UniformError> {
        *self
            .constraints
            .get_mut(self.next)
            .ok_or(UniformError::Shape)? = value;
        self.next = self.next.checked_add(1).ok_or(UniformError::Shape)?;
        Ok(())
    }

    fn finish(self) -> Result<(), UniformError> {
        if self.next == self.constraints.len() {
            Ok(())
        } else {
            Err(UniformError::Shape)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        block_test_support::{
            MachineEventFixture, flip_witness_bit, lookup_blocks, machine_event_block,
        },
        validate_uniform_witness,
    };

    #[test]
    fn quiet_block_advances_one_shared_timer_core() -> Result<(), Box<dyn std::error::Error>> {
        let blocks = lookup_blocks(
            &[0x00; BASIC_BLOCK_INSTRUCTION_BOUND],
            BASIC_BLOCK_INSTRUCTION_BOUND,
        )?;
        let witness = BlockDeviceTimerCoreWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockDeviceTimerCoreRelation, witness.columns())?;
        let mut mutated = witness.columns().to_vec();
        flip_witness_bit(&mut mutated, TIMER_CORE_AUX_START + QUIET_SELECTOR, 0)?;
        assert!(validate_uniform_witness(&BlockDeviceTimerCoreRelation, &mutated).is_err());
        Ok(())
    }

    #[test]
    fn long_timer_event_binds_exact_interrupt_gap() -> Result<(), Box<dyn std::error::Error>> {
        let blocks = machine_event_block(MachineEventFixture::HaltUntilTimer)?;
        let witness = BlockDeviceTimerCoreWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockDeviceTimerCoreRelation, witness.columns())?;
        let mut mutated = witness.columns().to_vec();
        flip_witness_bit(
            &mut mutated,
            TIMER_CORE_AUX_START + LONG_TIMER_GAP_BITS_START,
            0,
        )?;
        assert!(validate_uniform_witness(&BlockDeviceTimerCoreRelation, &mutated).is_err());
        Ok(())
    }
}
