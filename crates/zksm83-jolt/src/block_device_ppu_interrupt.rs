//! Shared VBlank, STAT-rising-edge, and remaining quiet-block IF transition.

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_core::{DmgDeviceState, StepKind};
use zksm83_trace::{BASIC_BLOCK_INSTRUCTION_BOUND, BasicBlock};

use crate::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_DEVICE_TIMER_CORE_COLUMN_COUNT,
    BLOCK_DEVICE_TIMER_CORE_CONSTRAINT_COUNT, BLOCK_DEVICE_TIMER_CORE_MAX_DEGREE,
    BLOCK_FRONTEND_COLUMN_COUNT, BLOCK_ROUTING_COLUMN_COUNT, BlockDeviceTimerCoreError,
    BlockDeviceTimerCoreRelation, BlockDeviceTimerCoreWitness, ConstraintOutput, NativeField,
    STATE_CPU_M_CYCLES_INDEX, STATE_PPU_DOT_INDEX, STATE_PPU_LINE_INDEX, UNIFORM_ROW_COUNT,
    UniformError, UniformRelation,
    block_boundary::{device_state_value, local_state_value},
    block_device::{device_clocked_block, device_io_selector_value, interrupt_acknowledged_mask},
    block_device_ppu::{low_pack_bit_value, ppu_dot_bit_value, ppu_line_bit_value},
    block_device_serial::{
        high_pack_bit_value, interrupt_request_bit_value, serial_completed_value,
        serial_completion_gap_bit_value,
    },
    block_device_timer_core::timer_stage_interrupt_value,
    block_machine::{
        before_interrupt_enable_bit_value, device_clocked_value, halt_idle_value,
        halt_until_vblank_value, interrupt_source_value, short_cycle_active_value,
    },
    block_metadata,
};

const PPU_INTERRUPT_AUX_START: usize = BLOCK_DEVICE_TIMER_CORE_COLUMN_COUNT;
const STATE_VBLANK: usize = 0;
const STATE_BELOW_80: usize = 1;
const STATE_BELOW_252: usize = 2;
const STATE_COINCIDENCE: usize = 3;
const STATE_SIGNAL: usize = 4;
const STATE_COINCIDENCE_PREFIX_START: usize = 5;
const STATE_SIGNAL_INACTIVE_PREFIX_START: usize = STATE_COINCIDENCE_PREFIX_START + 8;
const STATE_DOT_HIGH_PREFIX_START: usize = STATE_SIGNAL_INACTIVE_PREFIX_START + 4;
const STATE_WIDTH: usize = STATE_DOT_HIGH_PREFIX_START + 6;
const BEFORE_STATE_START: usize = 0;
const AFTER_STATE_START: usize = BEFORE_STATE_START + STATE_WIDTH;
const STAT_BOUNDARY: usize = AFTER_STATE_START + STATE_WIDTH;
const STAT_GAP_BITS_START: usize = STAT_BOUNDARY + 1;
const STAT_EVENT: usize = STAT_GAP_BITS_START + 9;
const VBLANK_EVENT: usize = STAT_EVENT + 1;
const VBLANK_GAP_BITS_START: usize = VBLANK_EVENT + 1;
const FINAL_PENDING_CLEAR_PREFIX_START: usize = VBLANK_GAP_BITS_START + 17;
const PPU_INTERRUPT_AUX_COLUMN_COUNT: usize = FINAL_PENDING_CLEAR_PREFIX_START + 5;
const PPU_INTERRUPT_ADDITIONAL_CONSTRAINT_COUNT: usize = 254;
const LINE_T_CYCLES: u64 = 456;
const FRAME_T_CYCLES: u64 = 154 * LINE_T_CYCLES;
const VBLANK_T_CYCLE: u64 = 144 * LINE_T_CYCLES;

/// Logical columns in the timer-core relation plus quiet-block PPU interrupts.
pub const BLOCK_DEVICE_PPU_INTERRUPT_COLUMN_COUNT: usize =
    BLOCK_DEVICE_TIMER_CORE_COLUMN_COUNT + PPU_INTERRUPT_AUX_COLUMN_COUNT;
/// Identities in the quiet-block PPU-interrupt relation.
pub const BLOCK_DEVICE_PPU_INTERRUPT_CONSTRAINT_COUNT: usize =
    BLOCK_DEVICE_TIMER_CORE_CONSTRAINT_COUNT + PPU_INTERRUPT_ADDITIONAL_CONSTRAINT_COUNT;
/// Maximum total degree in the quiet-block PPU-interrupt relation.
pub const BLOCK_DEVICE_PPU_INTERRUPT_MAX_DEGREE: usize = BLOCK_DEVICE_TIMER_CORE_MAX_DEGREE;

const _: () = assert!(BASIC_BLOCK_INSTRUCTION_BOUND == 4);
const _: () = assert!(STATE_WIDTH == 23);
const _: () = assert!(PPU_INTERRUPT_AUX_COLUMN_COUNT == 80);
const _: () = assert!(BLOCK_DEVICE_PPU_INTERRUPT_COLUMN_COUNT == 2_318);
const _: () = assert!(BLOCK_DEVICE_PPU_INTERRUPT_CONSTRAINT_COUNT == 5_022);
const _: () = assert!(BLOCK_DEVICE_PPU_INTERRUPT_MAX_DEGREE == 7);

/// Fixed-row witness carrying quiet-block VBlank and STAT interrupt transitions.
#[derive(Debug)]
pub struct BlockDevicePpuInterruptWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to construct the shared packed-block PPU-interrupt witness.
#[derive(Debug, Error)]
pub enum BlockDevicePpuInterruptError {
    /// Timer-core witness construction failed.
    #[error("packed-block timer-core construction failed: {0}")]
    TimerCore(#[from] BlockDeviceTimerCoreError),
    /// A validated block exposed an inconsistent quiet PPU-interrupt transition.
    #[error("packed block {block} has an inconsistent quiet PPU-interrupt transition")]
    InvalidTransition {
        /// Zero-based packed-block row.
        block: usize,
    },
    /// PPU-interrupt auxiliary columns violated their fixed layout.
    #[error("packed-block PPU-interrupt witness violated its typed layout")]
    Layout,
}

/// Timer-core relation plus quiet-block VBlank, STAT, and remaining IF semantics.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockDevicePpuInterruptRelation;

impl BlockDevicePpuInterruptWitness {
    /// Derives one PPU-interrupt witness for every bounded device-clocked block.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockDevicePpuInterruptError> {
        let timer_core = BlockDeviceTimerCoreWitness::from_blocks(blocks)?;
        let active_block_count = timer_core.active_block_count();
        let mut auxiliary = (0..PPU_INTERRUPT_AUX_COLUMN_COUNT)
            .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
            .collect::<Vec<_>>();
        for (block_index, block) in blocks.iter().enumerate() {
            let mut row = [0_u64; PPU_INTERRUPT_AUX_COLUMN_COUNT];
            append_ppu_interrupt(&mut row, block, block_index, clocked_block(block)?)?;
            for (column, value) in auxiliary.iter_mut().zip(row) {
                column.push(value);
            }
        }
        for column in &mut auxiliary {
            column.resize(UNIFORM_ROW_COUNT, 0);
        }
        let mut columns = timer_core.into_columns();
        columns.extend(auxiliary);
        if columns.len() != BLOCK_DEVICE_PPU_INTERRUPT_COLUMN_COUNT {
            return Err(BlockDevicePpuInterruptError::Layout);
        }
        Ok(Self {
            columns,
            active_block_count,
        })
    }

    /// Returns every logical column in timer-core-then-PPU-interrupt order.
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

impl UniformRelation for BlockDevicePpuInterruptRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-device-ppu-interrupt/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [2_238_u64, 4_768, 80, 70_224, 2_318, 5_022, 4] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_DEVICE_PPU_INTERRUPT_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_DEVICE_PPU_INTERRUPT_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_DEVICE_PPU_INTERRUPT_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_DEVICE_PPU_INTERRUPT_COLUMN_COUNT
            || constraints.len() != BLOCK_DEVICE_PPU_INTERRUPT_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let timer_core = row
            .get(..BLOCK_DEVICE_TIMER_CORE_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let auxiliary = row
            .get(PPU_INTERRUPT_AUX_START..BLOCK_DEVICE_PPU_INTERRUPT_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let (timer_constraints, ppu_interrupt_constraints) =
            constraints.split_at_mut(BLOCK_DEVICE_TIMER_CORE_CONSTRAINT_COUNT);
        BlockDeviceTimerCoreRelation.evaluate(timer_core, timer_constraints)?;
        constrain_ppu_interrupt(timer_core, auxiliary, ppu_interrupt_constraints)
    }
}

fn clocked_block(block: &BasicBlock) -> Result<bool, BlockDevicePpuInterruptError> {
    device_clocked_block(block).map_err(|_| BlockDevicePpuInterruptError::Layout)
}

fn append_ppu_interrupt(
    row: &mut [u64],
    block: &BasicBlock,
    block_index: usize,
    clocked: bool,
) -> Result<(), BlockDevicePpuInterruptError> {
    let before_device = block.initial_state().dmg_devices();
    let after_device = block.final_state().dmg_devices();
    let before = PpuInterruptState::from_device(before_device, block_index)?;
    let after = PpuInterruptState::from_device(after_device, block_index)?;
    append_interrupt_state(row, BEFORE_STATE_START, before)?;
    append_interrupt_state(row, AFTER_STATE_START, after)?;
    if !clocked {
        return Ok(());
    }
    let ticks = block
        .m_cycle_count()
        .checked_mul(4)
        .ok_or(BlockDevicePpuInterruptError::InvalidTransition { block: block_index })?;
    let stat_event = if halt_until_vblank_block(block) {
        false
    } else {
        append_stat_interval(row, before, after, ticks)?
    };
    let vblank_event = append_vblank_interval(row, before, ticks)?;
    append_final_pending_prefix(row, before_device, after_device)?;
    validate_interrupts(
        before_device,
        after_device,
        stat_event,
        vblank_event,
        interrupt_acknowledged_mask(block),
        block_index,
    )
}

fn halt_until_vblank_block(block: &BasicBlock) -> bool {
    block.row_count() == 1
        && block
            .rows()
            .next()
            .is_some_and(|row| row.effects().kind() == StepKind::HaltUntilVBlank)
}

fn append_final_pending_prefix(
    row: &mut [u64],
    before: DmgDeviceState,
    after: DmgDeviceState,
) -> Result<(), BlockDevicePpuInterruptError> {
    let mut clear = true;
    for bit in 0..5 {
        let requested = after.interrupt_request() >> bit & 1 == 1;
        let enabled = before.interrupt_enable() >> bit & 1 == 1;
        clear &= !(requested && enabled);
        set(
            row,
            checked_add(FINAL_PENDING_CLEAR_PREFIX_START, bit)?,
            u64::from(clear),
        )?;
    }
    Ok(())
}

fn append_interrupt_state(
    row: &mut [u64],
    start: usize,
    state: PpuInterruptState,
) -> Result<(), BlockDevicePpuInterruptError> {
    for (offset, selected) in [
        (STATE_VBLANK, state.vblank),
        (STATE_BELOW_80, state.below_80),
        (STATE_BELOW_252, state.below_252),
        (STATE_COINCIDENCE, state.coincidence),
        (STATE_SIGNAL, state.signal),
    ] {
        set(row, checked_add(start, offset)?, u64::from(selected))?;
    }
    let mut dot_prefix = true;
    for (prefix, bit) in (2..8).enumerate() {
        dot_prefix &= (state.dot >> bit) & 1 == 1;
        set(
            row,
            checked_add(start, STATE_DOT_HIGH_PREFIX_START + prefix)?,
            u64::from(dot_prefix),
        )?;
    }
    let mut coincidence_prefix = state.enabled;
    for bit in 0..8 {
        coincidence_prefix &= (state.line >> bit) & 1 == (state.line_compare >> bit) & 1;
        set(
            row,
            checked_add(start, STATE_COINCIDENCE_PREFIX_START + bit)?,
            u64::from(coincidence_prefix),
        )?;
    }
    let mut inactive_prefix = state.enabled;
    for (source, selected) in state.stat_sources().into_iter().enumerate() {
        inactive_prefix &= !selected;
        set(
            row,
            checked_add(start, STATE_SIGNAL_INACTIVE_PREFIX_START + source)?,
            u64::from(inactive_prefix),
        )?;
    }
    Ok(())
}

fn append_stat_interval(
    row: &mut [u64],
    before: PpuInterruptState,
    after: PpuInterruptState,
    ticks: u64,
) -> Result<bool, BlockDevicePpuInterruptError> {
    if !before.enabled {
        return Ok(false);
    }
    let dot = u64::from(before.dot);
    let boundary_dot = if dot < 80 {
        80
    } else if dot < 252 {
        252
    } else {
        LINE_T_CYCLES
    };
    let distance = boundary_dot
        .checked_sub(dot)
        .ok_or(BlockDevicePpuInterruptError::Layout)?;
    let (crossed, gap) = comparison_witness(ticks, distance)?;
    set(row, STAT_BOUNDARY, u64::from(crossed))?;
    append_bits(row, STAT_GAP_BITS_START, gap, 9)?;
    let event = crossed && !before.signal && after.signal;
    set(row, STAT_EVENT, u64::from(event))?;
    Ok(event)
}

fn append_vblank_interval(
    row: &mut [u64],
    before: PpuInterruptState,
    ticks: u64,
) -> Result<bool, BlockDevicePpuInterruptError> {
    if !before.enabled {
        return Ok(false);
    }
    let position = u64::from(before.line)
        .checked_mul(LINE_T_CYCLES)
        .and_then(|value| value.checked_add(u64::from(before.dot)))
        .ok_or(BlockDevicePpuInterruptError::Layout)?;
    let next = if position < VBLANK_T_CYCLE {
        VBLANK_T_CYCLE
    } else {
        VBLANK_T_CYCLE + FRAME_T_CYCLES
    };
    let distance = next
        .checked_sub(position)
        .ok_or(BlockDevicePpuInterruptError::Layout)?;
    let (event, gap) = comparison_witness(ticks, distance)?;
    set(row, VBLANK_EVENT, u64::from(event))?;
    append_bits(row, VBLANK_GAP_BITS_START, gap, 17)?;
    Ok(event)
}

fn comparison_witness(
    elapsed: u64,
    distance: u64,
) -> Result<(bool, u64), BlockDevicePpuInterruptError> {
    if elapsed >= distance {
        Ok((
            true,
            elapsed
                .checked_sub(distance)
                .ok_or(BlockDevicePpuInterruptError::Layout)?,
        ))
    } else {
        Ok((
            false,
            distance
                .checked_sub(elapsed)
                .and_then(|value| value.checked_sub(1))
                .ok_or(BlockDevicePpuInterruptError::Layout)?,
        ))
    }
}

fn validate_interrupts(
    before: DmgDeviceState,
    after: DmgDeviceState,
    stat_event: bool,
    vblank_event: bool,
    acknowledged: u8,
    block: usize,
) -> Result<(), BlockDevicePpuInterruptError> {
    let before_if = before.interrupt_request() & !acknowledged;
    let after_if = after.interrupt_request();
    let expected_vblank = before_if & 0x01 != 0 || vblank_event;
    let expected_stat = before_if & 0x02 != 0 || stat_event;
    let joypad_unchanged = before_if & 0x10 == after_if & 0x10;
    if (after_if & 0x01 != 0) != expected_vblank
        || (after_if & 0x02 != 0) != expected_stat
        || !joypad_unchanged
    {
        return Err(BlockDevicePpuInterruptError::InvalidTransition { block });
    }
    Ok(())
}

impl PpuInterruptState {
    fn from_device(
        device: DmgDeviceState,
        block: usize,
    ) -> Result<Self, BlockDevicePpuInterruptError> {
        let lcd_control = read_mmio(device, 0xff40, block)?;
        let stat_control = read_mmio(device, 0xff41, block)? & 0x78;
        let line_compare = read_mmio(device, 0xff45, block)?;
        let enabled = lcd_control & 0x80 != 0;
        let line = device.ppu_line();
        let dot = device.ppu_dot();
        let vblank = enabled && line >= 144;
        let below_80 = enabled && dot < 80;
        let below_252 = enabled && dot < 252;
        let coincidence = line == line_compare;
        let mode_zero = !vblank && !below_252;
        let signal = enabled
            && ((stat_control & 0x08 != 0 && mode_zero)
                || (stat_control & 0x10 != 0 && vblank)
                || (stat_control & 0x20 != 0 && below_80 && !vblank)
                || (stat_control & 0x40 != 0 && coincidence));
        Ok(Self {
            enabled,
            line,
            dot,
            line_compare,
            stat_control,
            vblank,
            below_80,
            below_252,
            coincidence,
            signal,
        })
    }

    const fn stat_sources(self) -> [bool; 4] {
        [
            self.stat_control & 0x08 != 0 && !self.vblank && !self.below_252,
            self.stat_control & 0x10 != 0 && self.vblank,
            self.stat_control & 0x20 != 0 && !self.vblank && self.below_80,
            self.stat_control & 0x40 != 0 && self.coincidence,
        ]
    }
}

fn read_mmio(
    device: DmgDeviceState,
    address: u16,
    block: usize,
) -> Result<u8, BlockDevicePpuInterruptError> {
    device
        .read_mmio(address)
        .ok_or(BlockDevicePpuInterruptError::InvalidTransition { block })
}

fn constrain_ppu_interrupt(
    timer_core: &[NativeField],
    auxiliary: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if auxiliary.len() != PPU_INTERRUPT_AUX_COLUMN_COUNT
        || constraints.len() != PPU_INTERRUPT_ADDITIONAL_CONSTRAINT_COUNT
    {
        return Err(UniformError::Shape);
    }
    let device_io = device_io_selector_value(timer_core)?;
    let one = NativeField::from_u64(1);
    let quiet = device_clocked_value(timer_core)? * (one - device_io);
    let block_active = block_metadata::block_active_value(timer_core)?;
    let mut sink = ConstraintSink::new(constraints);
    for (index, state) in auxiliary.iter().copied().enumerate() {
        let owner = if index < STAT_BOUNDARY {
            block_active
        } else {
            quiet
        };
        sink.push(state * (state - one))?;
        sink.push((one - owner) * state)?;
    }
    constrain_interrupt_state(timer_core, auxiliary, false, &mut sink)?;
    constrain_interrupt_state(timer_core, auxiliary, true, &mut sink)?;
    let frontend = timer_core
        .get(..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let boundary = frontend
        .get(BLOCK_ROUTING_COLUMN_COUNT..BLOCK_CONTROL_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    constrain_stat_interval(timer_core, boundary, auxiliary, quiet, &mut sink)?;
    constrain_vblank_interval(timer_core, boundary, auxiliary, quiet, &mut sink)?;
    constrain_interrupt_bits(timer_core, auxiliary, quiet, &mut sink)?;
    constrain_halt_idle_minimality(timer_core, auxiliary, quiet, &mut sink)?;
    let long_vblank = halt_until_vblank_value(timer_core)?;
    sink.push(long_vblank * (value(auxiliary, VBLANK_EVENT)? - one))?;
    sink.push(long_vblank * packed_bits(auxiliary, VBLANK_GAP_BITS_START, 17)?)?;
    sink.finish()
}

fn constrain_halt_idle_minimality(
    timer_core: &[NativeField],
    auxiliary: &[NativeField],
    quiet: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let halt_idle = halt_idle_value(timer_core)?;
    let mut all_clear = quiet;
    for bit in 0..5 {
        let pending = interrupt_request_bit_value(timer_core, true, bit)?
            * before_interrupt_enable_bit_value(timer_core, bit)?;
        let next = value(auxiliary, FINAL_PENDING_CLEAR_PREFIX_START + bit)?;
        sink.push(next - all_clear * (one - pending))?;
        all_clear = next;
    }
    sink.push(halt_idle * (one - short_cycle_active_value(timer_core, 5)?) * all_clear)?;
    constrain_halt_idle_event_gaps(timer_core, auxiliary, halt_idle, sink)
}

fn constrain_halt_idle_event_gaps(
    timer_core: &[NativeField],
    auxiliary: &[NativeField],
    halt_idle: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for (interrupt, event, start, width) in [
        (0, VBLANK_EVENT, VBLANK_GAP_BITS_START, 17),
        (1, STAT_EVENT, STAT_GAP_BITS_START, 9),
    ] {
        let selected = halt_idle
            * before_interrupt_enable_bit_value(timer_core, interrupt)?
            * value(auxiliary, event)?;
        for bit in 2..width {
            sink.push(selected * value(auxiliary, start + bit)?)?;
        }
    }
    let serial = halt_idle
        * before_interrupt_enable_bit_value(timer_core, 3)?
        * serial_completed_value(timer_core)?;
    for bit in 2..5 {
        sink.push(serial * serial_completion_gap_bit_value(timer_core, bit)?)?;
    }
    let timer = halt_idle * before_interrupt_enable_bit_value(timer_core, 2)?;
    for earlier_cycle in 1_usize..6 {
        let tick = earlier_cycle
            .checked_mul(4)
            .and_then(|value| value.checked_sub(1))
            .ok_or(UniformError::Shape)?;
        sink.push(
            timer
                * short_cycle_active_value(timer_core, earlier_cycle)?
                * timer_stage_interrupt_value(timer_core, tick)?,
        )?;
    }
    Ok(())
}

fn constrain_interrupt_state(
    timer_core: &[NativeField],
    auxiliary: &[NativeField],
    after: bool,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let start = state_start(after);
    let one = NativeField::from_u64(1);
    let enabled = low_pack_bit_value(timer_core, after, 39)?;
    let vblank = state_value(auxiliary, after, STATE_VBLANK)?;
    let below_80 = state_value(auxiliary, after, STATE_BELOW_80)?;
    let below_252 = state_value(auxiliary, after, STATE_BELOW_252)?;
    let coincidence = state_value(auxiliary, after, STATE_COINCIDENCE)?;
    let signal = state_value(auxiliary, after, STATE_SIGNAL)?;
    sink.push(
        vblank
            - enabled
                * ppu_line_bit_value(timer_core, after, 7)?
                * ppu_line_bit_value(timer_core, after, 4)?,
    )?;
    let above_79 = ppu_dot_bit_value(timer_core, after, 6)?
        * or(
            ppu_dot_bit_value(timer_core, after, 5)?,
            ppu_dot_bit_value(timer_core, after, 4)?,
        );
    sink.push(
        below_80
            - enabled
                * (one - ppu_dot_bit_value(timer_core, after, 8)?)
                * (one - ppu_dot_bit_value(timer_core, after, 7)?)
                * (one - above_79),
    )?;
    let mut dot_prefix = NativeField::from_u64(1);
    for prefix in 0..6 {
        dot_prefix *= ppu_dot_bit_value(timer_core, after, prefix + 2)?;
        sink.push(value(auxiliary, start + STATE_DOT_HIGH_PREFIX_START + prefix)? - dot_prefix)?;
        dot_prefix = value(auxiliary, start + STATE_DOT_HIGH_PREFIX_START + prefix)?;
    }
    sink.push(
        below_252 - enabled * (one - ppu_dot_bit_value(timer_core, after, 8)?) * (one - dot_prefix),
    )?;
    constrain_coincidence(
        timer_core,
        auxiliary,
        after,
        block_metadata::block_active_value(timer_core)?,
        coincidence,
        sink,
    )?;
    constrain_stat_signal(
        timer_core,
        auxiliary,
        after,
        StatSignalValues {
            enabled,
            vblank,
            below_80,
            below_252,
            coincidence,
            signal,
        },
        sink,
    )
}

fn constrain_coincidence(
    timer_core: &[NativeField],
    auxiliary: &[NativeField],
    after: bool,
    owner: NativeField,
    coincidence: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let start = state_start(after);
    let one = NativeField::from_u64(1);
    let two = NativeField::from_u64(2);
    let mut prefix = owner;
    for bit in 0..8 {
        let line = ppu_line_bit_value(timer_core, after, bit)?;
        let compare = high_pack_bit_value(timer_core, after, 40 + bit)?;
        let equal = one - line - compare + two * line * compare;
        let next = value(auxiliary, start + STATE_COINCIDENCE_PREFIX_START + bit)?;
        sink.push(next - prefix * equal)?;
        prefix = next;
    }
    sink.push(coincidence - prefix)
}

fn constrain_stat_signal(
    timer_core: &[NativeField],
    auxiliary: &[NativeField],
    after: bool,
    values: StatSignalValues,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let StatSignalValues {
        enabled,
        vblank,
        below_80,
        below_252,
        coincidence,
        signal,
    } = values;
    let start = state_start(after);
    let one = NativeField::from_u64(1);
    let sources = [
        low_pack_bit_value(timer_core, after, 43)? * (one - vblank) * (one - below_252),
        low_pack_bit_value(timer_core, after, 44)? * vblank,
        low_pack_bit_value(timer_core, after, 45)? * (one - vblank) * below_80,
        low_pack_bit_value(timer_core, after, 46)? * coincidence,
    ];
    let mut prefix = enabled;
    for (source, selected) in sources.into_iter().enumerate() {
        let next = value(
            auxiliary,
            start + STATE_SIGNAL_INACTIVE_PREFIX_START + source,
        )?;
        sink.push(next - prefix * (one - selected))?;
        prefix = next;
    }
    sink.push(signal - enabled + prefix)
}

fn constrain_stat_interval(
    timer_core: &[NativeField],
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    quiet: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let enabled = low_pack_bit_value(timer_core, false, 39)?;
    let active = quiet * enabled * (one - halt_until_vblank_value(timer_core)?);
    let dot = device_state_value(boundary, false, STATE_PPU_DOT_INDEX)?;
    let below_80 = state_value(auxiliary, false, STATE_BELOW_80)?;
    let below_252 = state_value(auxiliary, false, STATE_BELOW_252)?;
    let middle = (one - below_80) * below_252;
    let distance = NativeField::from_u64(80) * below_80
        + NativeField::from_u64(252) * middle
        + NativeField::from_u64(LINE_T_CYCLES) * (one - below_252)
        - dot;
    let elapsed = elapsed_t_cycles(boundary)?;
    constrain_comparison(
        auxiliary,
        ComparisonSpec {
            active,
            elapsed,
            distance,
            event_index: STAT_BOUNDARY,
            gap_start: STAT_GAP_BITS_START,
            gap_width: 9,
        },
        sink,
    )?;
    let before_signal = state_value(auxiliary, false, STATE_SIGNAL)?;
    let after_signal = state_value(auxiliary, true, STATE_SIGNAL)?;
    let boundary_crossed = value(auxiliary, STAT_BOUNDARY)?;
    sink.push(
        value(auxiliary, STAT_EVENT)? - boundary_crossed * (one - before_signal) * after_signal,
    )
}

fn constrain_vblank_interval(
    timer_core: &[NativeField],
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    quiet: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let enabled = low_pack_bit_value(timer_core, false, 39)?;
    let active = quiet * enabled;
    let position = NativeField::from_u64(LINE_T_CYCLES)
        * device_state_value(boundary, false, STATE_PPU_LINE_INDEX)?
        + device_state_value(boundary, false, STATE_PPU_DOT_INDEX)?;
    let next = NativeField::from_u64(VBLANK_T_CYCLE)
        + NativeField::from_u64(FRAME_T_CYCLES) * state_value(auxiliary, false, STATE_VBLANK)?;
    constrain_comparison(
        auxiliary,
        ComparisonSpec {
            active,
            elapsed: position + elapsed_t_cycles(boundary)?,
            distance: next,
            event_index: VBLANK_EVENT,
            gap_start: VBLANK_GAP_BITS_START,
            gap_width: 17,
        },
        sink,
    )
}

fn constrain_comparison(
    auxiliary: &[NativeField],
    spec: ComparisonSpec,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let ComparisonSpec {
        active,
        elapsed,
        distance,
        event_index,
        gap_start,
        gap_width,
    } = spec;
    let one = NativeField::from_u64(1);
    let event = value(auxiliary, event_index)?;
    let gap = packed_bits(auxiliary, gap_start, gap_width)?;
    let crossed_gap = elapsed - distance;
    let before_gap = distance - elapsed - one;
    sink.push(active * (gap - event * crossed_gap - (one - event) * before_gap))?;
    sink.push((one - active) * event)?;
    sink.push((one - active) * gap)
}

fn constrain_interrupt_bits(
    timer_core: &[NativeField],
    auxiliary: &[NativeField],
    quiet: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    for (bit, event) in [(0, VBLANK_EVENT), (1, STAT_EVENT)] {
        let before = interrupt_request_bit_value(timer_core, false, bit)?
            * (one - interrupt_source_value(timer_core, bit)?);
        let after = interrupt_request_bit_value(timer_core, true, bit)?;
        sink.push(quiet * (after - before - (one - before) * value(auxiliary, event)?))?;
    }
    sink.push(
        quiet
            * (interrupt_request_bit_value(timer_core, true, 4)?
                - interrupt_request_bit_value(timer_core, false, 4)?
                    * (one - interrupt_source_value(timer_core, 4)?)),
    )
}

fn elapsed_t_cycles(boundary: &[NativeField]) -> Result<NativeField, UniformError> {
    Ok(NativeField::from_u64(4)
        * (local_state_value(
            boundary,
            BASIC_BLOCK_INSTRUCTION_BOUND,
            STATE_CPU_M_CYCLES_INDEX,
        )? - local_state_value(boundary, 0, STATE_CPU_M_CYCLES_INDEX)?))
}

const fn state_start(after: bool) -> usize {
    if after {
        AFTER_STATE_START
    } else {
        BEFORE_STATE_START
    }
}

fn state_value(
    row: &[NativeField],
    after: bool,
    offset: usize,
) -> Result<NativeField, UniformError> {
    value(
        row,
        state_start(after)
            .checked_add(offset)
            .ok_or(UniformError::Shape)?,
    )
}

fn relation_state_value(
    row: &[NativeField],
    after: bool,
    offset: usize,
) -> Result<NativeField, UniformError> {
    if row.len() < BLOCK_DEVICE_PPU_INTERRUPT_COLUMN_COUNT {
        return Err(UniformError::Shape);
    }
    let index = PPU_INTERRUPT_AUX_START
        .checked_add(state_start(after))
        .and_then(|value| value.checked_add(offset))
        .ok_or(UniformError::Shape)?;
    value(row, index)
}

pub(crate) fn ppu_vblank_value(
    row: &[NativeField],
    after: bool,
) -> Result<NativeField, UniformError> {
    relation_state_value(row, after, STATE_VBLANK)
}

pub(crate) fn ppu_below_80_value(
    row: &[NativeField],
    after: bool,
) -> Result<NativeField, UniformError> {
    relation_state_value(row, after, STATE_BELOW_80)
}

pub(crate) fn ppu_below_252_value(
    row: &[NativeField],
    after: bool,
) -> Result<NativeField, UniformError> {
    relation_state_value(row, after, STATE_BELOW_252)
}

pub(crate) fn ppu_coincidence_value(
    row: &[NativeField],
    after: bool,
) -> Result<NativeField, UniformError> {
    relation_state_value(row, after, STATE_COINCIDENCE)
}

pub(crate) fn ppu_signal_value(
    row: &[NativeField],
    after: bool,
) -> Result<NativeField, UniformError> {
    relation_state_value(row, after, STATE_SIGNAL)
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

fn value(row: &[NativeField], index: usize) -> Result<NativeField, UniformError> {
    row.get(index).copied().ok_or(UniformError::Shape)
}

fn append_bits(
    row: &mut [u64],
    start: usize,
    value: u64,
    width: usize,
) -> Result<(), BlockDevicePpuInterruptError> {
    for bit in 0..width {
        set(row, checked_add(start, bit)?, (value >> bit) & 1)?;
    }
    Ok(())
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), BlockDevicePpuInterruptError> {
    *row.get_mut(index)
        .ok_or(BlockDevicePpuInterruptError::Layout)? = value;
    Ok(())
}

fn checked_add(start: usize, offset: usize) -> Result<usize, BlockDevicePpuInterruptError> {
    start
        .checked_add(offset)
        .ok_or(BlockDevicePpuInterruptError::Layout)
}

fn or(left: NativeField, right: NativeField) -> NativeField {
    left + right - left * right
}

#[derive(Clone, Copy)]
struct PpuInterruptState {
    enabled: bool,
    line: u8,
    dot: u16,
    line_compare: u8,
    stat_control: u8,
    vblank: bool,
    below_80: bool,
    below_252: bool,
    coincidence: bool,
    signal: bool,
}

#[derive(Clone, Copy)]
struct StatSignalValues {
    enabled: NativeField,
    vblank: NativeField,
    below_80: NativeField,
    below_252: NativeField,
    coincidence: NativeField,
    signal: NativeField,
}

#[derive(Clone, Copy)]
struct ComparisonSpec {
    active: NativeField,
    elapsed: NativeField,
    distance: NativeField,
    event_index: usize,
    gap_start: usize,
    gap_width: usize,
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
mod tests;
