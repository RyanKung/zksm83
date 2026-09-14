//! Typed PPU MMIO write-before-clock semantics for bounded device-I/O blocks.

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_core::{BusEventKind, DmgDeviceState};
use zksm83_trace::{BASIC_BLOCK_INSTRUCTION_BOUND, BasicBlock};

use crate::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_DEVICE_TIMER_MMIO_COLUMN_COUNT,
    BLOCK_DEVICE_TIMER_MMIO_CONSTRAINT_COUNT, BLOCK_DEVICE_TIMER_MMIO_MAX_DEGREE,
    BLOCK_FRONTEND_COLUMN_COUNT, BLOCK_ROUTING_COLUMN_COUNT, BlockDeviceTimerMmioError,
    BlockDeviceTimerMmioRelation, BlockDeviceTimerMmioWitness, ConstraintOutput, NativeField,
    STATE_CPU_M_CYCLES_INDEX, STATE_PPU_DOT_INDEX, STATE_PPU_LINE_INDEX, UNIFORM_ROW_COUNT,
    UniformError, UniformRelation,
    block_boundary::{device_state_value, local_state_value},
    block_device::device_io_selector_value,
    block_device_mmio::{
        mmio_address_selector_value, mmio_io_before_value, mmio_io_value, mmio_io_value_bit,
        mmio_read_selector_value, mmio_write_selector_value,
    },
    block_device_ppu::{low_pack_bit_value, ppu_dot_bit_value, ppu_line_bit_value},
    block_device_ppu_interrupt::{
        ppu_below_80_value, ppu_below_252_value, ppu_coincidence_value, ppu_signal_value,
        ppu_vblank_value,
    },
    block_device_serial::{high_pack_bit_value, interrupt_request_bit_value},
};

const LINE_T_CYCLES: u64 = 456;
const FRAME_T_CYCLES: u64 = 154 * LINE_T_CYCLES;
const VBLANK_T_CYCLE: u64 = 144 * LINE_T_CYCLES;

const PPU_MMIO_AUX_START: usize = BLOCK_DEVICE_TIMER_MMIO_COLUMN_COUNT;
const POST_LINE_BITS_START: usize = 0;
const POST_DOT_BITS_START: usize = POST_LINE_BITS_START + 8;
const POST_STATE_START: usize = POST_DOT_BITS_START + 9;
const STATE_VBLANK: usize = 0;
const STATE_BELOW_80: usize = 1;
const STATE_BELOW_252: usize = 2;
const STATE_COINCIDENCE: usize = 3;
const STATE_SIGNAL: usize = 4;
const STATE_COINCIDENCE_PREFIX_START: usize = 5;
const STATE_SIGNAL_INACTIVE_PREFIX_START: usize = STATE_COINCIDENCE_PREFIX_START + 8;
const STATE_DOT_HIGH_PREFIX_START: usize = STATE_SIGNAL_INACTIVE_PREFIX_START + 4;
const STATE_WIDTH: usize = STATE_DOT_HIGH_PREFIX_START + 6;
const LCD_DISABLE_WRITE: usize = POST_STATE_START + STATE_WIDTH;
const BASE_IF_ZERO: usize = LCD_DISABLE_WRITE + 1;
const BASE_IF_ONE: usize = BASE_IF_ZERO + 1;
const POST_IF_ONE: usize = BASE_IF_ONE + 1;
const IMMEDIATE_STAT_EVENT: usize = POST_IF_ONE + 1;
const FRAME_WRAP: usize = IMMEDIATE_STAT_EVENT + 1;
const STAT_BOUNDARY: usize = FRAME_WRAP + 1;
const STAT_GAP_BITS_START: usize = STAT_BOUNDARY + 1;
const STAT_EVENT: usize = STAT_GAP_BITS_START + 9;
const VBLANK_EVENT: usize = STAT_EVENT + 1;
const VBLANK_GAP_BITS_START: usize = VBLANK_EVENT + 1;
const PPU_MMIO_AUX_COLUMN_COUNT: usize = VBLANK_GAP_BITS_START + 17;
const PPU_MMIO_ADDITIONAL_CONSTRAINT_COUNT: usize = 214;

/// Logical columns in timer-MMIO plus exact PPU write-before-clock semantics.
pub const BLOCK_DEVICE_PPU_MMIO_COLUMN_COUNT: usize =
    BLOCK_DEVICE_TIMER_MMIO_COLUMN_COUNT + PPU_MMIO_AUX_COLUMN_COUNT;
/// Identities in the typed PPU-MMIO relation.
pub const BLOCK_DEVICE_PPU_MMIO_CONSTRAINT_COUNT: usize =
    BLOCK_DEVICE_TIMER_MMIO_CONSTRAINT_COUNT + PPU_MMIO_ADDITIONAL_CONSTRAINT_COUNT;
/// Maximum total degree in the typed PPU-MMIO relation.
pub const BLOCK_DEVICE_PPU_MMIO_MAX_DEGREE: usize = 15;

const _: () = assert!(BASIC_BLOCK_INSTRUCTION_BOUND == 4);
const _: () = assert!(STATE_WIDTH == 23);
const _: () = assert!(PPU_MMIO_AUX_COLUMN_COUNT == 75);
const _: () = assert!(BLOCK_DEVICE_TIMER_MMIO_MAX_DEGREE == 14);
const _: () = assert!(BLOCK_DEVICE_PPU_MMIO_COLUMN_COUNT == 3_338);
const _: () = assert!(BLOCK_DEVICE_PPU_MMIO_CONSTRAINT_COUNT == 8_003);
const _: () = assert!(BLOCK_DEVICE_PPU_MMIO_MAX_DEGREE == 15);

/// Fixed-row witness for PPU writes, immediate STAT edges, and bounded clocking.
#[derive(Debug)]
pub struct BlockDevicePpuMmioWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to construct the typed PPU-MMIO witness.
#[derive(Debug, Error)]
pub enum BlockDevicePpuMmioError {
    /// Timer-MMIO relation construction failed.
    #[error("packed-block timer-MMIO construction failed: {0}")]
    TimerMmio(#[from] BlockDeviceTimerMmioError),
    /// A validated device-I/O row exposed an inconsistent PPU transition.
    #[error("packed block {block} has an inconsistent PPU-MMIO transition")]
    InvalidTransition {
        /// Zero-based packed-block row.
        block: usize,
    },
    /// PPU-MMIO auxiliary columns violated their fixed layout.
    #[error("packed-block PPU-MMIO witness violated its typed layout")]
    Layout,
}

/// Timer-MMIO relation plus exact PPU MMIO and interrupt ordering.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockDevicePpuMmioRelation;

impl BlockDevicePpuMmioWitness {
    /// Derives one exact PPU transition for every typed device-I/O block.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockDevicePpuMmioError> {
        let timer = BlockDeviceTimerMmioWitness::from_blocks(blocks)?;
        let active_block_count = timer.active_block_count();
        let mut auxiliary = (0..PPU_MMIO_AUX_COLUMN_COUNT)
            .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
            .collect::<Vec<_>>();
        for (block_index, block) in blocks.iter().enumerate() {
            let mut row = [0_u64; PPU_MMIO_AUX_COLUMN_COUNT];
            append_ppu_mmio_row(&mut row, block, block_index)?;
            for (column, value) in auxiliary.iter_mut().zip(row) {
                column.push(value);
            }
        }
        for column in &mut auxiliary {
            column.resize(UNIFORM_ROW_COUNT, 0);
        }
        let mut columns = timer.into_columns();
        columns.extend(auxiliary);
        if columns.len() != BLOCK_DEVICE_PPU_MMIO_COLUMN_COUNT {
            return Err(BlockDevicePpuMmioError::Layout);
        }
        Ok(Self {
            columns,
            active_block_count,
        })
    }

    /// Returns every logical column in timer-MMIO-then-PPU-MMIO order.
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

impl UniformRelation for BlockDevicePpuMmioRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-device-ppu-mmio/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [3_263_u64, 7_789, 75, 214, 3_338, 8_003, 3] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_DEVICE_PPU_MMIO_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_DEVICE_PPU_MMIO_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_DEVICE_PPU_MMIO_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_DEVICE_PPU_MMIO_COLUMN_COUNT
            || constraints.len() != BLOCK_DEVICE_PPU_MMIO_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let timer = row
            .get(..BLOCK_DEVICE_TIMER_MMIO_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let auxiliary = row
            .get(PPU_MMIO_AUX_START..BLOCK_DEVICE_PPU_MMIO_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let (timer_constraints, ppu_constraints) =
            constraints.split_at_mut(BLOCK_DEVICE_TIMER_MMIO_CONSTRAINT_COUNT);
        BlockDeviceTimerMmioRelation.evaluate(timer, timer_constraints)?;
        constrain_ppu_mmio(timer, auxiliary, ppu_constraints)
    }
}

fn append_ppu_mmio_row(
    row: &mut [u64],
    block: &BasicBlock,
    block_index: usize,
) -> Result<(), BlockDevicePpuMmioError> {
    let Some((kind, event)) = typed_device_event(block, block_index)? else {
        return Ok(());
    };
    let before = block.initial_state().dmg_devices();
    let after = block.final_state().dmg_devices();
    let mut post = before;
    apply_event(&mut post, kind, event, block_index)?;
    let before_state = PpuState::from_device(before, block_index)?;
    let post_state = PpuState::from_device(post, block_index)?;
    append_bits(row, POST_LINE_BITS_START, u64::from(post.ppu_line()), 8)?;
    append_bits(row, POST_DOT_BITS_START, u64::from(post.ppu_dot()), 9)?;
    append_ppu_state(row, post_state)?;
    let write = kind == BusEventKind::DmgMmioWrite;
    let disable = write && event.address == 0xff40 && event.value & 0x80 == 0;
    set(row, LCD_DISABLE_WRITE, u64::from(disable))?;
    let ff0f = write && event.address == 0xff0f;
    let base_if_zero = if ff0f {
        event.value & 0x01 != 0
    } else {
        before.interrupt_request() & 0x01 != 0
    };
    let base_if_one = if ff0f {
        event.value & 0x02 != 0
    } else {
        before.interrupt_request() & 0x02 != 0
    };
    let immediate = write
        && matches!(event.address, 0xff40 | 0xff41 | 0xff45)
        && !before_state.signal
        && post_state.signal;
    set(row, BASE_IF_ZERO, u64::from(base_if_zero))?;
    set(row, BASE_IF_ONE, u64::from(base_if_one))?;
    set(row, POST_IF_ONE, u64::from(base_if_one || immediate))?;
    set(row, IMMEDIATE_STAT_EVENT, u64::from(immediate))?;
    let cycles = u8::try_from(block.m_cycle_count())
        .map_err(|_| BlockDevicePpuMmioError::InvalidTransition { block: block_index })?;
    let ticks = u64::from(cycles) * 4;
    let position = ppu_position(post.ppu_line(), post.ppu_dot());
    let advanced_position = position
        .checked_add(ticks)
        .ok_or(BlockDevicePpuMmioError::Layout)?;
    set(
        row,
        FRAME_WRAP,
        u64::from(post_state.enabled && advanced_position >= FRAME_T_CYCLES),
    )?;
    let mut projected = post;
    projected.advance_m_cycles(cycles);
    let final_state = PpuState::from_device(projected, block_index)?;
    append_stat_interval(row, post_state, final_state, ticks)?;
    append_vblank_interval(row, post_state, ticks)?;
    if !same_ppu_projection(projected, after)
        || post.interrupt_request() & 0x01 != u8::from(base_if_zero)
        || post.interrupt_request() & 0x02 != u8::from(base_if_one || immediate) << 1
    {
        return Err(BlockDevicePpuMmioError::InvalidTransition { block: block_index });
    }
    Ok(())
}

fn apply_event(
    post: &mut DmgDeviceState,
    kind: BusEventKind,
    event: zksm83_memory::BusTranscriptEvent,
    block: usize,
) -> Result<(), BlockDevicePpuMmioError> {
    match kind {
        BusEventKind::DmgMmioWrite => {
            if post.write_mmio(event.address, event.value) != Some(event.before) {
                return Err(BlockDevicePpuMmioError::InvalidTransition { block });
            }
        }
        BusEventKind::DmgMmioRead => {
            if post.read_mmio(event.address) != Some(event.value) {
                return Err(BlockDevicePpuMmioError::InvalidTransition { block });
            }
        }
        BusEventKind::DmgJoypadRead => {}
        _ => return Err(BlockDevicePpuMmioError::InvalidTransition { block }),
    }
    Ok(())
}

fn same_ppu_projection(expected: DmgDeviceState, actual: DmgDeviceState) -> bool {
    expected.ppu_line() == actual.ppu_line()
        && expected.ppu_dot() == actual.ppu_dot()
        && expected.low_register_pack() >> 32 & 0xffff == actual.low_register_pack() >> 32 & 0xffff
        && expected.high_register_pack() >> 40 & 0xff == actual.high_register_pack() >> 40 & 0xff
        && expected.interrupt_request() & 0x03 == actual.interrupt_request() & 0x03
}

fn typed_device_event(
    block: &BasicBlock,
    block_index: usize,
) -> Result<Option<(BusEventKind, zksm83_memory::BusTranscriptEvent)>, BlockDevicePpuMmioError> {
    let mut selected = None;
    for source in block.rows() {
        for event in source.effects().ordered_bus_events() {
            if !matches!(
                event.kind(),
                BusEventKind::DmgMmioRead
                    | BusEventKind::DmgMmioWrite
                    | BusEventKind::DmgJoypadRead
            ) {
                continue;
            }
            if selected.is_some() {
                return Err(BlockDevicePpuMmioError::InvalidTransition { block: block_index });
            }
            selected = Some((event.kind(), event.transcript_event()));
        }
    }
    Ok(selected)
}

fn append_ppu_state(row: &mut [u64], state: PpuState) -> Result<(), BlockDevicePpuMmioError> {
    for (offset, selected) in [
        (STATE_VBLANK, state.vblank),
        (STATE_BELOW_80, state.below_80),
        (STATE_BELOW_252, state.below_252),
        (STATE_COINCIDENCE, state.coincidence),
        (STATE_SIGNAL, state.signal),
    ] {
        set(row, POST_STATE_START + offset, u64::from(selected))?;
    }
    let mut coincidence_prefix = true;
    for bit in 0..8 {
        coincidence_prefix &= (state.line >> bit) & 1 == (state.line_compare >> bit) & 1;
        set(
            row,
            POST_STATE_START + STATE_COINCIDENCE_PREFIX_START + bit,
            u64::from(coincidence_prefix),
        )?;
    }
    let mut inactive_prefix = state.enabled;
    for (source, selected) in state.stat_sources().into_iter().enumerate() {
        inactive_prefix &= !selected;
        set(
            row,
            POST_STATE_START + STATE_SIGNAL_INACTIVE_PREFIX_START + source,
            u64::from(inactive_prefix),
        )?;
    }
    let mut dot_prefix = true;
    for (prefix, bit) in (2..8).enumerate() {
        dot_prefix &= (state.dot >> bit) & 1 == 1;
        set(
            row,
            POST_STATE_START + STATE_DOT_HIGH_PREFIX_START + prefix,
            u64::from(dot_prefix),
        )?;
    }
    Ok(())
}

fn append_stat_interval(
    row: &mut [u64],
    before: PpuState,
    after: PpuState,
    ticks: u64,
) -> Result<(), BlockDevicePpuMmioError> {
    if !before.enabled {
        return Ok(());
    }
    let boundary = if before.dot < 80 {
        80
    } else if before.dot < 252 {
        252
    } else {
        LINE_T_CYCLES
    };
    let distance = boundary
        .checked_sub(u64::from(before.dot))
        .ok_or(BlockDevicePpuMmioError::Layout)?;
    let (crossed, gap) = comparison_witness(ticks, distance)?;
    set(row, STAT_BOUNDARY, u64::from(crossed))?;
    append_bits(row, STAT_GAP_BITS_START, gap, 9)?;
    set(
        row,
        STAT_EVENT,
        u64::from(crossed && !before.signal && after.signal),
    )
}

fn append_vblank_interval(
    row: &mut [u64],
    before: PpuState,
    ticks: u64,
) -> Result<(), BlockDevicePpuMmioError> {
    if !before.enabled {
        return Ok(());
    }
    let position = ppu_position(before.line, before.dot);
    let next = if position < VBLANK_T_CYCLE {
        VBLANK_T_CYCLE
    } else {
        VBLANK_T_CYCLE + FRAME_T_CYCLES
    };
    let distance = next
        .checked_sub(position)
        .ok_or(BlockDevicePpuMmioError::Layout)?;
    let (event, gap) = comparison_witness(ticks, distance)?;
    set(row, VBLANK_EVENT, u64::from(event))?;
    append_bits(row, VBLANK_GAP_BITS_START, gap, 17)
}

fn comparison_witness(elapsed: u64, distance: u64) -> Result<(bool, u64), BlockDevicePpuMmioError> {
    if elapsed >= distance {
        Ok((
            true,
            elapsed
                .checked_sub(distance)
                .ok_or(BlockDevicePpuMmioError::Layout)?,
        ))
    } else {
        Ok((
            false,
            distance
                .checked_sub(elapsed)
                .and_then(|value| value.checked_sub(1))
                .ok_or(BlockDevicePpuMmioError::Layout)?,
        ))
    }
}

fn constrain_ppu_mmio(
    timer: &[NativeField],
    auxiliary: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if auxiliary.len() != PPU_MMIO_AUX_COLUMN_COUNT
        || constraints.len() != PPU_MMIO_ADDITIONAL_CONSTRAINT_COUNT
    {
        return Err(UniformError::Shape);
    }
    let one = NativeField::from_u64(1);
    let device_io = device_io_selector_value(timer)?;
    let mut sink = ConstraintSink::new(constraints);
    for column in auxiliary.iter().copied() {
        sink.push(column * (column - one))?;
        sink.push((one - device_io) * column)?;
    }
    let frontend = timer
        .get(..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let boundary = frontend
        .get(BLOCK_ROUTING_COLUMN_COUNT..BLOCK_CONTROL_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let write = mmio_write_selector_value(timer)?;
    let read = mmio_read_selector_value(timer)?;
    let disable = value(auxiliary, LCD_DISABLE_WRITE)?;
    sink.push(
        disable
            - mmio_address_selector_value(timer, 0x40)?
                * write
                * (one - mmio_io_value_bit(timer, 7)?),
    )?;
    constrain_post_position(timer, boundary, auxiliary, device_io, disable, &mut sink)?;
    constrain_post_state(timer, auxiliary, device_io, &mut sink)?;
    constrain_lcd_status_tuple(timer, read, write, &mut sink)?;
    let immediate = constrain_immediate_stat(timer, auxiliary, write, &mut sink)?;
    constrain_interrupts(timer, auxiliary, device_io, write, immediate, &mut sink)?;
    constrain_clocked_position(timer, boundary, auxiliary, device_io, &mut sink)?;
    constrain_stat_interval(timer, boundary, auxiliary, device_io, &mut sink)?;
    constrain_vblank_interval(timer, boundary, auxiliary, device_io, &mut sink)?;
    sink.finish()
}

fn constrain_post_position(
    timer: &[NativeField],
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    device_io: NativeField,
    disable: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    for bit in 0..8 {
        sink.push(
            value(auxiliary, POST_LINE_BITS_START + bit)?
                - device_io * ppu_line_bit_value(timer, false, bit)? * (one - disable),
        )?;
    }
    for bit in 0..9 {
        sink.push(
            value(auxiliary, POST_DOT_BITS_START + bit)?
                - device_io * ppu_dot_bit_value(timer, false, bit)? * (one - disable),
        )?;
    }
    let before_enabled = low_pack_bit_value(timer, false, 39)?;
    sink.push(
        device_io
            * (one - before_enabled)
            * device_state_value(boundary, false, STATE_PPU_LINE_INDEX)?,
    )?;
    sink.push(
        device_io
            * (one - before_enabled)
            * device_state_value(boundary, false, STATE_PPU_DOT_INDEX)?,
    )
}

fn constrain_post_state(
    timer: &[NativeField],
    auxiliary: &[NativeField],
    device_io: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let enabled = low_pack_bit_value(timer, true, 39)?;
    let active_enabled = device_io * enabled;
    let vblank = state_value(auxiliary, STATE_VBLANK)?;
    let below_80 = state_value(auxiliary, STATE_BELOW_80)?;
    let below_252 = state_value(auxiliary, STATE_BELOW_252)?;
    let coincidence = state_value(auxiliary, STATE_COINCIDENCE)?;
    let signal = state_value(auxiliary, STATE_SIGNAL)?;
    sink.push(
        vblank
            - active_enabled
                * value(auxiliary, POST_LINE_BITS_START + 7)?
                * value(auxiliary, POST_LINE_BITS_START + 4)?,
    )?;
    let above_79 = value(auxiliary, POST_DOT_BITS_START + 6)?
        * or(
            value(auxiliary, POST_DOT_BITS_START + 5)?,
            value(auxiliary, POST_DOT_BITS_START + 4)?,
        );
    sink.push(
        below_80
            - active_enabled
                * (one - value(auxiliary, POST_DOT_BITS_START + 8)?)
                * (one - value(auxiliary, POST_DOT_BITS_START + 7)?)
                * (one - above_79),
    )?;
    let mut dot_prefix = device_io;
    for bit in 2_usize..8 {
        let offset = bit.checked_sub(2).ok_or(UniformError::Shape)?;
        let next = state_value(auxiliary, STATE_DOT_HIGH_PREFIX_START + offset)?;
        sink.push(next - dot_prefix * value(auxiliary, POST_DOT_BITS_START + bit)?)?;
        dot_prefix = next;
    }
    sink.push(
        below_252
            - active_enabled
                * (one - value(auxiliary, POST_DOT_BITS_START + 8)?)
                * (one - dot_prefix),
    )?;
    constrain_post_coincidence(timer, auxiliary, device_io, coincidence, sink)?;
    constrain_post_signal(
        timer,
        auxiliary,
        active_enabled,
        [vblank, below_80, below_252, coincidence, signal],
        sink,
    )
}

fn constrain_post_coincidence(
    timer: &[NativeField],
    auxiliary: &[NativeField],
    owner: NativeField,
    coincidence: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let two = NativeField::from_u64(2);
    let mut prefix = owner;
    for bit in 0..8 {
        let line = value(auxiliary, POST_LINE_BITS_START + bit)?;
        let compare = high_pack_bit_value(timer, true, 40 + bit)?;
        let equal = one - line - compare + two * line * compare;
        let next = state_value(auxiliary, STATE_COINCIDENCE_PREFIX_START + bit)?;
        sink.push(next - prefix * equal)?;
        prefix = next;
    }
    sink.push(coincidence - prefix)
}

fn constrain_post_signal(
    timer: &[NativeField],
    auxiliary: &[NativeField],
    active_enabled: NativeField,
    states: [NativeField; 5],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let [vblank, below_80, below_252, coincidence, signal] = states;
    let one = NativeField::from_u64(1);
    let sources = [
        low_pack_bit_value(timer, true, 43)? * (one - vblank) * (one - below_252),
        low_pack_bit_value(timer, true, 44)? * vblank,
        low_pack_bit_value(timer, true, 45)? * (one - vblank) * below_80,
        low_pack_bit_value(timer, true, 46)? * coincidence,
    ];
    let mut prefix = active_enabled;
    for (source, selected) in sources.into_iter().enumerate() {
        let next = state_value(auxiliary, STATE_SIGNAL_INACTIVE_PREFIX_START + source)?;
        sink.push(next - prefix * (one - selected))?;
        prefix = next;
    }
    sink.push(signal - active_enabled + prefix)
}

fn constrain_lcd_status_tuple(
    timer: &[NativeField],
    read: NativeField,
    write: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let vblank = ppu_vblank_value(timer, false)?;
    let below_80 = ppu_below_80_value(timer, false)?;
    let below_252 = ppu_below_252_value(timer, false)?;
    let coincidence = ppu_coincidence_value(timer, false)?;
    let mode = vblank + (one - vblank) * below_252 * (NativeField::from_u64(3) - below_80);
    let mut visible = NativeField::from_u64(0x80) + NativeField::from_u64(4) * coincidence + mode;
    for bit in 3..7 {
        visible +=
            NativeField::from_u64(1_u64 << bit) * low_pack_bit_value(timer, false, 40 + bit)?;
    }
    let ff41 = mmio_address_selector_value(timer, 0x41)?;
    sink.push(ff41 * read * (mmio_io_value(timer)? - visible))?;
    sink.push(ff41 * write * (mmio_io_before_value(timer)? - visible))
}

fn constrain_immediate_stat(
    timer: &[NativeField],
    auxiliary: &[NativeField],
    write: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<NativeField, UniformError> {
    let one = NativeField::from_u64(1);
    let relevant = write
        * (mmio_address_selector_value(timer, 0x40)?
            + mmio_address_selector_value(timer, 0x41)?
            + mmio_address_selector_value(timer, 0x45)?);
    let immediate = value(auxiliary, IMMEDIATE_STAT_EVENT)?;
    sink.push(
        immediate
            - relevant
                * (one - ppu_signal_value(timer, false)?)
                * state_value(auxiliary, STATE_SIGNAL)?,
    )?;
    Ok(immediate)
}

fn constrain_interrupts(
    timer: &[NativeField],
    auxiliary: &[NativeField],
    device_io: NativeField,
    write: NativeField,
    immediate: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let ff0f = mmio_address_selector_value(timer, 0x0f)? * write;
    let base_zero = value(auxiliary, BASE_IF_ZERO)?;
    let base_one = value(auxiliary, BASE_IF_ONE)?;
    let post_one = value(auxiliary, POST_IF_ONE)?;
    for (bit, base) in [(0, base_zero), (1, base_one)] {
        let before = interrupt_request_bit_value(timer, false, bit)?;
        sink.push(base - device_io * before - ff0f * (mmio_io_value_bit(timer, bit)? - before))?;
    }
    sink.push(post_one - base_one - immediate * (one - base_one))?;
    sink.push(
        device_io * (interrupt_request_bit_value(timer, true, 0)? - base_zero)
            - value(auxiliary, VBLANK_EVENT)? * (one - base_zero),
    )?;
    sink.push(
        device_io * (interrupt_request_bit_value(timer, true, 1)? - post_one)
            - value(auxiliary, STAT_EVENT)? * (one - post_one),
    )
}

fn constrain_clocked_position(
    timer: &[NativeField],
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    device_io: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let enabled = low_pack_bit_value(timer, true, 39)?;
    let post_line = packed_bits(auxiliary, POST_LINE_BITS_START, 8)?;
    let post_dot = packed_bits(auxiliary, POST_DOT_BITS_START, 9)?;
    sink.push(device_io * (one - enabled) * post_line)?;
    sink.push(device_io * (one - enabled) * post_dot)?;
    let after_line = device_state_value(boundary, true, STATE_PPU_LINE_INDEX)?;
    let after_dot = device_state_value(boundary, true, STATE_PPU_DOT_INDEX)?;
    let wrap = value(auxiliary, FRAME_WRAP)?;
    sink.push(
        device_io
            * enabled
            * (after_line * NativeField::from_u64(LINE_T_CYCLES) + after_dot
                - post_line * NativeField::from_u64(LINE_T_CYCLES)
                - post_dot
                - elapsed_t_cycles(boundary)?
                + NativeField::from_u64(FRAME_T_CYCLES) * wrap),
    )?;
    sink.push(device_io * (one - enabled) * after_line)?;
    sink.push(device_io * (one - enabled) * after_dot)?;
    sink.push(device_io * (one - enabled) * wrap)
}

fn constrain_stat_interval(
    timer: &[NativeField],
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    device_io: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let enabled = low_pack_bit_value(timer, true, 39)?;
    let below_80 = state_value(auxiliary, STATE_BELOW_80)?;
    let below_252 = state_value(auxiliary, STATE_BELOW_252)?;
    let middle = (one - below_80) * below_252;
    let distance = NativeField::from_u64(80) * below_80
        + NativeField::from_u64(252) * middle
        + NativeField::from_u64(LINE_T_CYCLES) * (one - below_252)
        - packed_bits(auxiliary, POST_DOT_BITS_START, 9)?;
    constrain_comparison(
        auxiliary,
        ComparisonSpec {
            active: device_io * enabled,
            elapsed: elapsed_t_cycles(boundary)?,
            distance,
            event: STAT_BOUNDARY,
            gap_start: STAT_GAP_BITS_START,
            gap_width: 9,
        },
        sink,
    )?;
    sink.push(
        value(auxiliary, STAT_EVENT)?
            - value(auxiliary, STAT_BOUNDARY)?
                * (one - state_value(auxiliary, STATE_SIGNAL)?)
                * ppu_signal_value(timer, true)?,
    )
}

fn constrain_vblank_interval(
    timer: &[NativeField],
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    device_io: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let enabled = low_pack_bit_value(timer, true, 39)?;
    let position = NativeField::from_u64(LINE_T_CYCLES)
        * packed_bits(auxiliary, POST_LINE_BITS_START, 8)?
        + packed_bits(auxiliary, POST_DOT_BITS_START, 9)?;
    let next = NativeField::from_u64(VBLANK_T_CYCLE)
        + NativeField::from_u64(FRAME_T_CYCLES) * state_value(auxiliary, STATE_VBLANK)?;
    constrain_comparison(
        auxiliary,
        ComparisonSpec {
            active: device_io * enabled,
            elapsed: position + elapsed_t_cycles(boundary)?,
            distance: next,
            event: VBLANK_EVENT,
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
    let one = NativeField::from_u64(1);
    let event = value(auxiliary, spec.event)?;
    let gap = packed_bits(auxiliary, spec.gap_start, spec.gap_width)?;
    sink.push(
        spec.active
            * (gap
                - event * (spec.elapsed - spec.distance)
                - (one - event) * (spec.distance - spec.elapsed - one)),
    )?;
    sink.push((one - spec.active) * event)?;
    sink.push((one - spec.active) * gap)
}

fn state_value(row: &[NativeField], offset: usize) -> Result<NativeField, UniformError> {
    value(
        row,
        POST_STATE_START
            .checked_add(offset)
            .ok_or(UniformError::Shape)?,
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

fn ppu_position(line: u8, dot: u16) -> u64 {
    u64::from(line) * LINE_T_CYCLES + u64::from(dot)
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

fn append_bits(
    row: &mut [u64],
    start: usize,
    packed: u64,
    width: usize,
) -> Result<(), BlockDevicePpuMmioError> {
    for bit in 0..width {
        set(
            row,
            start
                .checked_add(bit)
                .ok_or(BlockDevicePpuMmioError::Layout)?,
            packed >> bit & 1,
        )?;
    }
    Ok(())
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), BlockDevicePpuMmioError> {
    *row.get_mut(index).ok_or(BlockDevicePpuMmioError::Layout)? = value;
    Ok(())
}

fn value(row: &[NativeField], index: usize) -> Result<NativeField, UniformError> {
    row.get(index).copied().ok_or(UniformError::Shape)
}

fn or(left: NativeField, right: NativeField) -> NativeField {
    left + right - left * right
}

#[derive(Clone, Copy)]
struct PpuState {
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

impl PpuState {
    fn from_device(device: DmgDeviceState, block: usize) -> Result<Self, BlockDevicePpuMmioError> {
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
) -> Result<u8, BlockDevicePpuMmioError> {
    device
        .read_mmio(address)
        .ok_or(BlockDevicePpuMmioError::InvalidTransition { block })
}

#[derive(Clone, Copy)]
struct ComparisonSpec {
    active: NativeField,
    elapsed: NativeField,
    distance: NativeField,
    event: usize,
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

    fn push(&mut self, constraint: NativeField) -> Result<(), UniformError> {
        *self
            .constraints
            .get_mut(self.next)
            .ok_or(UniformError::Shape)? = constraint;
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
