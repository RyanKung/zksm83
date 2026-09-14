//! Typed MMIO write-before-clock semantics for the bounded DMG timer core.

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_core::{BusEventKind, DmgTimerState};
use zksm83_trace::{BASIC_BLOCK_INSTRUCTION_BOUND, BASIC_BLOCK_M_CYCLE_BOUND, BasicBlock};

use crate::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_DEVICE_SERIAL_MMIO_COLUMN_COUNT,
    BLOCK_DEVICE_SERIAL_MMIO_CONSTRAINT_COUNT, BLOCK_DEVICE_SERIAL_MMIO_MAX_DEGREE,
    BLOCK_FRONTEND_COLUMN_COUNT, BLOCK_ROUTING_COLUMN_COUNT, BlockDeviceSerialMmioError,
    BlockDeviceSerialMmioRelation, BlockDeviceSerialMmioWitness, ConstraintOutput, NativeField,
    STATE_TIMER_COUNTER_INDEX, STATE_TIMER_EDGE_LATCH_INDEX, STATE_TIMER_RELOAD_PHASE_INDEX,
    UNIFORM_ROW_COUNT, UniformError, UniformRelation,
    block_boundary::device_state_value,
    block_device::device_io_selector_value,
    block_device_mmio::{
        mmio_address_selector_value, mmio_io_before_value, mmio_io_value, mmio_io_value_bit,
        mmio_read_selector_value, mmio_write_selector_value,
    },
    block_device_ppu::low_pack_bit_value,
    block_device_serial::interrupt_request_bit_value,
    block_device_timer::timer_div_bit_value,
    block_device_timer_core::{SHARED_TIMER_STAGE_COLUMN_COUNT, SHARED_TIMER_STAGE_COLUMN_START},
    block_device_timer_stage::{
        STAGE_COUNTER_BITS_OFFSET, STAGE_COUNTER_OVERFLOW_OFFSET, STAGE_DIV_BITS_OFFSET,
        STAGE_DIV_WRAP_OFFSET, STAGE_INTERRUPT_OFFSET, STAGE_LATCH_OFFSET, STAGE_PHASE_BITS_OFFSET,
        STAGE_RELOAD_COUNTER_BITS_OFFSET, STAGE_RELOAD_PHASE_BITS_OFFSET, STAGE_WIDTH,
        TIMER_TICK_BOUND,
    },
    block_routing::cycle_owner_value,
};

const TIMER_MMIO_AUX_START: usize = BLOCK_DEVICE_SERIAL_MMIO_COLUMN_COUNT;
const BEFORE_PHASE_BITS_START: usize = 0;
const POST_DIV_BITS_START: usize = BEFORE_PHASE_BITS_START + 3;
const POST_COUNTER_BITS_START: usize = POST_DIV_BITS_START + 16;
const POST_PHASE_BITS_START: usize = POST_COUNTER_BITS_START + 8;
const POST_LATCH: usize = POST_PHASE_BITS_START + 3;
const POST_MODULO_BITS_START: usize = POST_LATCH + 1;
const POST_CONTROL_BITS_START: usize = POST_MODULO_BITS_START + 8;
const POST_IF_TWO: usize = POST_CONTROL_BITS_START + 3;
const FF04_WRITE: usize = POST_IF_TWO + 1;
const FF05_WRITE: usize = FF04_WRITE + 1;
const FF06_WRITE: usize = FF05_WRITE + 1;
const FF07_WRITE: usize = FF06_WRITE + 1;
const FF05_READ: usize = FF07_WRITE + 1;
const FF0F_WRITE: usize = FF05_READ + 1;
const TIMER_MMIO_AUX_COLUMN_COUNT: usize = FF0F_WRITE + 1;
const TIMER_MMIO_EVENT_CONSTRAINT_COUNT: usize = 6;
const TIMER_MMIO_BEFORE_CONSTRAINT_COUNT: usize = 2;
const TIMER_MMIO_POST_CONSTRAINT_COUNT: usize = 8;
const TIMER_MMIO_TUPLE_CONSTRAINT_COUNT: usize = 2;
const TIMER_MMIO_PER_TICK_CONSTRAINT_COUNT: usize = 12;
const TIMER_MMIO_FINAL_CONSTRAINT_COUNT: usize = 7;
const TIMER_MMIO_SEMANTIC_CONSTRAINT_COUNT: usize = TIMER_MMIO_EVENT_CONSTRAINT_COUNT
    + TIMER_MMIO_BEFORE_CONSTRAINT_COUNT
    + TIMER_MMIO_POST_CONSTRAINT_COUNT
    + TIMER_MMIO_TUPLE_CONSTRAINT_COUNT
    + TIMER_TICK_BOUND * TIMER_MMIO_PER_TICK_CONSTRAINT_COUNT
    + TIMER_MMIO_FINAL_CONSTRAINT_COUNT;
const TIMER_MMIO_ADDITIONAL_CONSTRAINT_COUNT: usize =
    TIMER_MMIO_AUX_COLUMN_COUNT * 2 + TIMER_MMIO_SEMANTIC_CONSTRAINT_COUNT;

/// Logical columns in serial-MMIO plus exact timer write-before-clock semantics.
pub const BLOCK_DEVICE_TIMER_MMIO_COLUMN_COUNT: usize =
    BLOCK_DEVICE_SERIAL_MMIO_COLUMN_COUNT + TIMER_MMIO_AUX_COLUMN_COUNT;
/// Identities in the typed timer-MMIO relation.
pub const BLOCK_DEVICE_TIMER_MMIO_CONSTRAINT_COUNT: usize =
    BLOCK_DEVICE_SERIAL_MMIO_CONSTRAINT_COUNT + TIMER_MMIO_ADDITIONAL_CONSTRAINT_COUNT;
/// Maximum total degree in the typed timer-MMIO relation.
pub const BLOCK_DEVICE_TIMER_MMIO_MAX_DEGREE: usize = BLOCK_DEVICE_SERIAL_MMIO_MAX_DEGREE;

const _: () = assert!(BASIC_BLOCK_INSTRUCTION_BOUND == 4);
const _: () = assert!(BASIC_BLOCK_M_CYCLE_BOUND == 6);
const _: () = assert!(TIMER_TICK_BOUND == 24);
const _: () = assert!(TIMER_MMIO_AUX_COLUMN_COUNT == 49);
const _: () = assert!(TIMER_MMIO_SEMANTIC_CONSTRAINT_COUNT == 313);
const _: () = assert!(BLOCK_DEVICE_TIMER_MMIO_COLUMN_COUNT == 3_263);
const _: () = assert!(BLOCK_DEVICE_TIMER_MMIO_CONSTRAINT_COUNT == 7_789);
const _: () = assert!(BLOCK_DEVICE_TIMER_MMIO_MAX_DEGREE == 14);

/// Fixed-row witness for timer writes followed by at most 24 exact T-cycles.
#[derive(Debug)]
pub struct BlockDeviceTimerMmioWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to construct the typed timer-MMIO witness.
#[derive(Debug, Error)]
pub enum BlockDeviceTimerMmioError {
    /// Serial-MMIO relation construction failed.
    #[error("packed-block serial-MMIO construction failed: {0}")]
    SerialMmio(#[from] BlockDeviceSerialMmioError),
    /// A validated device-I/O row exposed an inconsistent timer transition.
    #[error("packed block {block} has an inconsistent timer-MMIO transition")]
    InvalidTransition {
        /// Zero-based packed-block row.
        block: usize,
    },
    /// Timer-MMIO auxiliary columns violated their fixed layout.
    #[error("packed-block timer-MMIO witness violated its typed layout")]
    Layout,
}

/// Serial-MMIO relation plus FF04-FF07 post-write bounded timer semantics.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockDeviceTimerMmioRelation;

impl BlockDeviceTimerMmioWitness {
    /// Derives one exact timer trace for every typed device-I/O block.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockDeviceTimerMmioError> {
        let serial = BlockDeviceSerialMmioWitness::from_blocks(blocks)?;
        let active_block_count = serial.active_block_count();
        let mut columns = serial.into_columns();
        let mut auxiliary = (0..TIMER_MMIO_AUX_COLUMN_COUNT)
            .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
            .collect::<Vec<_>>();
        for (block_index, block) in blocks.iter().enumerate() {
            let mut row = [0_u64; TIMER_MMIO_AUX_COLUMN_COUNT];
            let mut stage = [0_u64; SHARED_TIMER_STAGE_COLUMN_COUNT];
            if append_timer_mmio_row(&mut row, &mut stage, block, block_index)? {
                // Preservation: only device-I/O rows write here; quiet rows remain core-owned.
                write_shared_timer_stage(&mut columns, block_index, &stage)?;
            }
            for (column, value) in auxiliary.iter_mut().zip(row) {
                column.push(value);
            }
        }
        for column in &mut auxiliary {
            column.resize(UNIFORM_ROW_COUNT, 0);
        }
        columns.extend(auxiliary);
        if columns.len() != BLOCK_DEVICE_TIMER_MMIO_COLUMN_COUNT {
            return Err(BlockDeviceTimerMmioError::Layout);
        }
        Ok(Self {
            columns,
            active_block_count,
        })
    }

    /// Returns every logical column in serial-MMIO-then-timer-MMIO order.
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

impl UniformRelation for BlockDeviceTimerMmioRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-device-timer-mmio/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [3_214_u64, 7_378, 49, 411, 24, 42, 3_263, 7_789, 4] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_DEVICE_TIMER_MMIO_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_DEVICE_TIMER_MMIO_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_DEVICE_TIMER_MMIO_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_DEVICE_TIMER_MMIO_COLUMN_COUNT
            || constraints.len() != BLOCK_DEVICE_TIMER_MMIO_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let serial = row
            .get(..BLOCK_DEVICE_SERIAL_MMIO_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let auxiliary = row
            .get(TIMER_MMIO_AUX_START..BLOCK_DEVICE_TIMER_MMIO_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let (serial_constraints, timer_constraints) =
            constraints.split_at_mut(BLOCK_DEVICE_SERIAL_MMIO_CONSTRAINT_COUNT);
        BlockDeviceSerialMmioRelation.evaluate(serial, serial_constraints)?;
        constrain_timer_mmio(serial, auxiliary, timer_constraints)
    }
}

fn append_timer_mmio_row(
    row: &mut [u64],
    stage: &mut [u64],
    block: &BasicBlock,
    block_index: usize,
) -> Result<bool, BlockDeviceTimerMmioError> {
    let Some((kind, tuple)) = typed_device_event(block, block_index)? else {
        return Ok(false);
    };
    let before_device = block.initial_state().dmg_devices();
    let after_device = block.final_state().dmg_devices();
    let before = before_device.timer();
    let mut timer = before;
    append_bits(
        row,
        BEFORE_PHASE_BITS_START,
        u64::from(before.reload_phase()),
        3,
    )?;
    let read = kind == BusEventKind::DmgMmioRead;
    let write = kind == BusEventKind::DmgMmioWrite;
    if (0xff04..=0xff07).contains(&tuple.address) {
        let visible = timer
            .read(tuple.address)
            .ok_or(BlockDeviceTimerMmioError::InvalidTransition { block: block_index })?;
        if (read && tuple.value != visible) || (write && tuple.before != visible) {
            return Err(BlockDeviceTimerMmioError::InvalidTransition { block: block_index });
        }
        if write {
            let prior = timer
                .write(tuple.address, tuple.value)
                .ok_or(BlockDeviceTimerMmioError::InvalidTransition { block: block_index })?;
            if prior != visible {
                return Err(BlockDeviceTimerMmioError::InvalidTransition { block: block_index });
            }
        }
    }
    let mut interrupt = before_device.interrupt_request() & 0x04 != 0;
    if write && tuple.address == 0xff0f {
        interrupt = tuple.value & 0x04 != 0;
    }
    append_post_state(row, timer, interrupt)?;
    for (column, selected) in [
        (FF04_WRITE, write && tuple.address == 0xff04),
        (FF05_WRITE, write && tuple.address == 0xff05),
        (FF06_WRITE, write && tuple.address == 0xff06),
        (FF07_WRITE, write && tuple.address == 0xff07),
        (FF05_READ, read && tuple.address == 0xff05),
        (FF0F_WRITE, write && tuple.address == 0xff0f),
    ] {
        set(row, column, u64::from(selected))?;
    }
    let active_ticks = block
        .m_cycle_count()
        .checked_mul(4)
        .and_then(|ticks| usize::try_from(ticks).ok())
        .ok_or(BlockDeviceTimerMmioError::InvalidTransition { block: block_index })?;
    if active_ticks > TIMER_TICK_BOUND {
        return Err(BlockDeviceTimerMmioError::InvalidTransition { block: block_index });
    }
    for tick in 0..TIMER_TICK_BOUND {
        append_timer_tick(stage, tick, tick < active_ticks, &mut timer, &mut interrupt)?;
    }
    let expected_interrupt = after_device.interrupt_request() & 0x04 != 0;
    if timer != after_device.timer() || interrupt != expected_interrupt {
        return Err(BlockDeviceTimerMmioError::InvalidTransition { block: block_index });
    }
    Ok(true)
}

fn typed_device_event(
    block: &BasicBlock,
    block_index: usize,
) -> Result<Option<(BusEventKind, zksm83_memory::BusTranscriptEvent)>, BlockDeviceTimerMmioError> {
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
                return Err(BlockDeviceTimerMmioError::InvalidTransition { block: block_index });
            }
            selected = Some((event.kind(), event.transcript_event()));
        }
    }
    Ok(selected)
}

fn write_shared_timer_stage(
    columns: &mut [Vec<u64>],
    row: usize,
    stage: &[u64],
) -> Result<(), BlockDeviceTimerMmioError> {
    if stage.len() != SHARED_TIMER_STAGE_COLUMN_COUNT {
        return Err(BlockDeviceTimerMmioError::Layout);
    }
    let end = SHARED_TIMER_STAGE_COLUMN_START
        .checked_add(SHARED_TIMER_STAGE_COLUMN_COUNT)
        .ok_or(BlockDeviceTimerMmioError::Layout)?;
    let shared = columns
        .get_mut(SHARED_TIMER_STAGE_COLUMN_START..end)
        .ok_or(BlockDeviceTimerMmioError::Layout)?;
    for (column, value) in shared.iter_mut().zip(stage.iter().copied()) {
        *column
            .get_mut(row)
            .ok_or(BlockDeviceTimerMmioError::Layout)? = value;
    }
    Ok(())
}

fn append_post_state(
    row: &mut [u64],
    timer: DmgTimerState,
    interrupt: bool,
) -> Result<(), BlockDeviceTimerMmioError> {
    append_bits(row, POST_DIV_BITS_START, u64::from(timer.raw_div()), 16)?;
    append_bits(row, POST_COUNTER_BITS_START, u64::from(timer.counter()), 8)?;
    append_bits(
        row,
        POST_PHASE_BITS_START,
        u64::from(timer.reload_phase()),
        3,
    )?;
    set(row, POST_LATCH, u64::from(timer.edge_latch()))?;
    append_bits(row, POST_MODULO_BITS_START, u64::from(timer.modulo()), 8)?;
    append_bits(row, POST_CONTROL_BITS_START, u64::from(timer.control()), 3)?;
    set(row, POST_IF_TWO, u64::from(interrupt))
}

fn append_timer_tick(
    row: &mut [u64],
    tick: usize,
    active: bool,
    timer: &mut DmgTimerState,
    interrupt: &mut bool,
) -> Result<(), BlockDeviceTimerMmioError> {
    let start = stage_start(tick)?;
    let (reload_counter, reload_phase) = reload_intermediate(*timer);
    let detector = detector_input(timer.raw_div().wrapping_add(1), timer.control());
    let falling = timer.edge_latch() && !detector;
    let div_wrap = active && timer.raw_div() == u16::MAX;
    let overflow = active && falling && reload_counter == u8::MAX;
    if active {
        *interrupt |= timer.advance_t_cycles(1) & 0x04 != 0;
    }
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
        u64::from(*interrupt),
    )?;
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

fn constrain_timer_mmio(
    serial: &[NativeField],
    auxiliary: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if auxiliary.len() != TIMER_MMIO_AUX_COLUMN_COUNT
        || constraints.len() != TIMER_MMIO_ADDITIONAL_CONSTRAINT_COUNT
    {
        return Err(UniformError::Shape);
    }
    let one = NativeField::from_u64(1);
    let device_io = device_io_selector_value(serial)?;
    let stage = shared_timer_stage(serial)?;
    let mut sink = ConstraintSink::new(constraints);
    for column in auxiliary.iter().copied() {
        sink.push(column * (column - one))?;
        sink.push((one - device_io) * column)?;
    }
    let frontend = serial
        .get(..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let boundary = frontend
        .get(BLOCK_ROUTING_COLUMN_COUNT..BLOCK_CONTROL_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let read = mmio_read_selector_value(serial)?;
    let write = mmio_write_selector_value(serial)?;
    constrain_event_selectors(serial, auxiliary, read, write, &mut sink)?;
    constrain_before_phase(boundary, auxiliary, device_io, &mut sink)?;
    constrain_post_state(serial, boundary, auxiliary, device_io, &mut sink)?;
    constrain_ff05_tuple(serial, boundary, auxiliary, &mut sink)?;
    for tick in 0..TIMER_TICK_BOUND {
        constrain_tick(serial, auxiliary, stage, tick, device_io, &mut sink)?;
    }
    constrain_final_state(serial, boundary, auxiliary, stage, device_io, &mut sink)?;
    sink.finish()
}

fn constrain_event_selectors(
    serial: &[NativeField],
    auxiliary: &[NativeField],
    read: NativeField,
    write: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for (column, address, operation) in [
        (FF04_WRITE, 0x04, write),
        (FF05_WRITE, 0x05, write),
        (FF06_WRITE, 0x06, write),
        (FF07_WRITE, 0x07, write),
        (FF05_READ, 0x05, read),
        (FF0F_WRITE, 0x0f, write),
    ] {
        sink.push(
            value(auxiliary, column)? - mmio_address_selector_value(serial, address)? * operation,
        )?;
    }
    Ok(())
}

fn constrain_before_phase(
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    device_io: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    sink.push(
        device_io
            * (device_state_value(boundary, false, STATE_TIMER_RELOAD_PHASE_INDEX)?
                - packed_bits(auxiliary, BEFORE_PHASE_BITS_START, 3)?),
    )?;
    constrain_phase_range(auxiliary, BEFORE_PHASE_BITS_START, device_io, sink)
}

fn constrain_post_state(
    serial: &[NativeField],
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    device_io: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let ff04 = value(auxiliary, FF04_WRITE)?;
    let ff05 = value(auxiliary, FF05_WRITE)?;
    let ff06 = value(auxiliary, FF06_WRITE)?;
    let ff07 = value(auxiliary, FF07_WRITE)?;
    let ff0f = value(auxiliary, FF0F_WRITE)?;
    let before_div = timer_divider(serial, false)?;
    let post_div = packed_bits(auxiliary, POST_DIV_BITS_START, 16)?;
    sink.push(device_io * (post_div - before_div) + ff04 * before_div)?;
    let before_counter = device_state_value(boundary, false, STATE_TIMER_COUNTER_INDEX)?;
    let post_counter = packed_bits(auxiliary, POST_COUNTER_BITS_START, 8)?;
    let before_modulo = low_pack_byte(serial, false, 2)?;
    let phase_five = phase_selector(auxiliary, BEFORE_PHASE_BITS_START, 5)?;
    let written_counter = phase_five * before_modulo + (one - phase_five) * mmio_io_value(serial)?;
    sink.push(
        device_io * (post_counter - before_counter)
            - ff05 * (written_counter - before_counter)
            - ff06 * phase_five * (mmio_io_value(serial)? - before_counter),
    )?;
    let before_phase = packed_bits(auxiliary, BEFORE_PHASE_BITS_START, 3)?;
    let post_phase = packed_bits(auxiliary, POST_PHASE_BITS_START, 3)?;
    sink.push(device_io * (post_phase - before_phase) + ff05 * (one - phase_five) * before_phase)?;
    constrain_phase_range(auxiliary, POST_PHASE_BITS_START, device_io, sink)?;
    sink.push(
        device_io
            * (value(auxiliary, POST_LATCH)?
                - device_state_value(boundary, false, STATE_TIMER_EDGE_LATCH_INDEX)?),
    )?;
    let post_modulo = packed_bits(auxiliary, POST_MODULO_BITS_START, 8)?;
    sink.push(
        device_io * (post_modulo - before_modulo) - ff06 * (mmio_io_value(serial)? - before_modulo),
    )?;
    let before_control = low_pack_byte(serial, false, 3)?;
    let post_control = packed_bits(auxiliary, POST_CONTROL_BITS_START, 3)?;
    let written_control = packed_mmio_value(serial, 3)?;
    sink.push(
        device_io * (post_control - before_control) - ff07 * (written_control - before_control),
    )?;
    let before_if = interrupt_request_bit_value(serial, false, 2)?;
    sink.push(
        device_io * (value(auxiliary, POST_IF_TWO)? - before_if)
            - ff0f * (mmio_io_value_bit(serial, 2)? - before_if),
    )
}

fn constrain_ff05_tuple(
    serial: &[NativeField],
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let counter = device_state_value(boundary, false, STATE_TIMER_COUNTER_INDEX)?;
    let modulo = low_pack_byte(serial, false, 2)?;
    let phase_five = phase_selector(auxiliary, BEFORE_PHASE_BITS_START, 5)?;
    let visible = counter + phase_five * (modulo - counter);
    sink.push(value(auxiliary, FF05_READ)? * (mmio_io_value(serial)? - visible))?;
    sink.push(value(auxiliary, FF05_WRITE)? * (mmio_io_before_value(serial)? - visible))
}

fn constrain_tick(
    serial: &[NativeField],
    auxiliary: &[NativeField],
    stage: &[NativeField],
    tick: usize,
    device_io: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let current = current_state(auxiliary, stage, tick)?;
    let next = stage_state(stage, tick)?;
    let reload_counter = stage_packed(stage, tick, STAGE_RELOAD_COUNTER_BITS_OFFSET, 8)?;
    let reload_phase = stage_packed(stage, tick, STAGE_RELOAD_PHASE_BITS_OFFSET, 3)?;
    constrain_phase_range_source(auxiliary, stage, current.source, device_io, sink)?;
    constrain_phase_range(
        stage,
        checked_stage_index(tick, STAGE_RELOAD_PHASE_BITS_OFFSET)?,
        device_io,
        sink,
    )?;
    let one = NativeField::from_u64(1);
    let phase_five = phase_selector_source(auxiliary, stage, current.source, 5)?;
    let phase_zero = phase_selector_source(auxiliary, stage, current.source, 0)?;
    let modulo = packed_bits(auxiliary, POST_MODULO_BITS_START, 8)?;
    sink.push(
        device_io * (reload_counter - current.counter - phase_five * (modulo - current.counter)),
    )?;
    sink.push(
        device_io
            * (reload_phase - current.phase - (one - phase_zero) * (one - phase_five)
                + phase_five * current.phase),
    )?;
    let active = tick_active(serial, tick, device_io)?;
    let wrap = stage_value(stage, tick, STAGE_DIV_WRAP_OFFSET)?;
    let overflow = stage_value(stage, tick, STAGE_COUNTER_OVERFLOW_OFFSET)?;
    let detector = timer_detector(auxiliary, stage, tick)?;
    let falling = current.latch * (one - detector);
    sink.push(device_io * wrap * (one - active))?;
    sink.push(device_io * overflow * (one - active))?;
    sink.push(device_io * overflow * (one - falling))?;
    sink.push(
        device_io
            * (next.divider - current.divider - active
                + NativeField::from_u64(65_536) * active * wrap),
    )?;
    sink.push(
        device_io
            * (next.counter
                - current.counter
                - active
                    * (reload_counter - current.counter + falling
                        - NativeField::from_u64(256) * overflow)),
    )?;
    sink.push(
        device_io
            * (next.phase
                - current.phase
                - active * (reload_phase - current.phase + overflow * (one - reload_phase))),
    )?;
    sink.push(device_io * (next.latch - current.latch - active * (detector - current.latch)))?;
    sink.push(
        device_io
            * (next.interrupt
                - current.interrupt
                - active * (one - current.interrupt) * phase_five),
    )
}

fn constrain_final_state(
    serial: &[NativeField],
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    stage: &[NativeField],
    device_io: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let final_state = stage_state(stage, TIMER_TICK_BOUND - 1)?;
    for (actual, expected) in [
        (final_state.divider, timer_divider(serial, true)?),
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
            interrupt_request_bit_value(serial, true, 2)?,
        ),
        (
            packed_bits(auxiliary, POST_MODULO_BITS_START, 8)?,
            low_pack_byte(serial, true, 2)?,
        ),
        (
            packed_bits(auxiliary, POST_CONTROL_BITS_START, 3)?,
            low_pack_byte(serial, true, 3)?,
        ),
    ] {
        sink.push(device_io * (actual - expected))?;
    }
    Ok(())
}

fn current_state(
    auxiliary: &[NativeField],
    stage: &[NativeField],
    tick: usize,
) -> Result<TimerStateValues, UniformError> {
    if tick == 0 {
        Ok(TimerStateValues {
            divider: packed_bits(auxiliary, POST_DIV_BITS_START, 16)?,
            counter: packed_bits(auxiliary, POST_COUNTER_BITS_START, 8)?,
            phase: packed_bits(auxiliary, POST_PHASE_BITS_START, 3)?,
            latch: value(auxiliary, POST_LATCH)?,
            interrupt: value(auxiliary, POST_IF_TWO)?,
            source: TimerStateSource::Post,
        })
    } else {
        stage_state(stage, tick.checked_sub(1).ok_or(UniformError::Shape)?)
    }
}

fn stage_state(stage: &[NativeField], tick: usize) -> Result<TimerStateValues, UniformError> {
    Ok(TimerStateValues {
        divider: stage_packed(stage, tick, STAGE_DIV_BITS_OFFSET, 16)?,
        counter: stage_packed(stage, tick, STAGE_COUNTER_BITS_OFFSET, 8)?,
        phase: stage_packed(stage, tick, STAGE_PHASE_BITS_OFFSET, 3)?,
        latch: stage_value(stage, tick, STAGE_LATCH_OFFSET)?,
        interrupt: stage_value(stage, tick, STAGE_INTERRUPT_OFFSET)?,
        source: TimerStateSource::Stage(tick),
    })
}

fn timer_detector(
    auxiliary: &[NativeField],
    stage: &[NativeField],
    tick: usize,
) -> Result<NativeField, UniformError> {
    let zero = value(auxiliary, POST_CONTROL_BITS_START)?;
    let one_bit = value(auxiliary, POST_CONTROL_BITS_START + 1)?;
    let enabled = value(auxiliary, POST_CONTROL_BITS_START + 2)?;
    let one = NativeField::from_u64(1);
    let selected =
        (one - zero) * (one - one_bit) * stage_value(stage, tick, STAGE_DIV_BITS_OFFSET + 9)?
            + zero * (one - one_bit) * stage_value(stage, tick, STAGE_DIV_BITS_OFFSET + 3)?
            + (one - zero) * one_bit * stage_value(stage, tick, STAGE_DIV_BITS_OFFSET + 5)?
            + zero * one_bit * stage_value(stage, tick, STAGE_DIV_BITS_OFFSET + 7)?;
    Ok(enabled * selected)
}

fn tick_active(
    serial: &[NativeField],
    tick: usize,
    device_io: NativeField,
) -> Result<NativeField, UniformError> {
    let cycle = tick.checked_div(4).ok_or(UniformError::Shape)?;
    let mut active = NativeField::from_u64(0);
    for lane in 0..BASIC_BLOCK_INSTRUCTION_BOUND {
        active += cycle_owner_value(serial, cycle, lane)?;
    }
    Ok(device_io * active)
}

fn phase_selector_source(
    auxiliary: &[NativeField],
    stage: &[NativeField],
    source: TimerStateSource,
    expected: u8,
) -> Result<NativeField, UniformError> {
    match source {
        TimerStateSource::Post => phase_selector(auxiliary, POST_PHASE_BITS_START, expected),
        TimerStateSource::Stage(tick) => phase_selector(
            stage,
            checked_stage_index(tick, STAGE_PHASE_BITS_OFFSET)?,
            expected,
        ),
    }
}

fn phase_selector(
    row: &[NativeField],
    start: usize,
    expected: u8,
) -> Result<NativeField, UniformError> {
    let one = NativeField::from_u64(1);
    (0..3).try_fold(one, |selector, bit| {
        let actual = value(row, start + bit)?;
        Ok(if expected >> bit & 1 == 1 {
            selector * actual
        } else {
            selector * (one - actual)
        })
    })
}

fn constrain_phase_range_source(
    auxiliary: &[NativeField],
    stage: &[NativeField],
    source: TimerStateSource,
    owner: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    match source {
        TimerStateSource::Post => {
            constrain_phase_range(auxiliary, POST_PHASE_BITS_START, owner, sink)
        }
        TimerStateSource::Stage(tick) => constrain_phase_range(
            stage,
            checked_stage_index(tick, STAGE_PHASE_BITS_OFFSET)?,
            owner,
            sink,
        ),
    }
}

fn constrain_phase_range(
    row: &[NativeField],
    start: usize,
    owner: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    sink.push(owner * value(row, start + 2)? * value(row, start + 1)?)
}

fn stage_packed(
    stage: &[NativeField],
    tick: usize,
    offset: usize,
    width: usize,
) -> Result<NativeField, UniformError> {
    packed_bits(stage, checked_stage_index(tick, offset)?, width)
}

fn stage_value(
    stage: &[NativeField],
    tick: usize,
    offset: usize,
) -> Result<NativeField, UniformError> {
    value(stage, checked_stage_index(tick, offset)?)
}

fn timer_divider(row: &[NativeField], after: bool) -> Result<NativeField, UniformError> {
    let mut packed = NativeField::from_u64(0);
    let mut power = NativeField::from_u64(1);
    for bit in 0..16 {
        packed += power * timer_div_bit_value(row, after, bit)?;
        power += power;
    }
    Ok(packed)
}

fn low_pack_byte(
    row: &[NativeField],
    after: bool,
    byte: usize,
) -> Result<NativeField, UniformError> {
    if byte >= 8 {
        return Err(UniformError::Shape);
    }
    let start = byte.checked_mul(8).ok_or(UniformError::Shape)?;
    let mut packed = NativeField::from_u64(0);
    let mut power = NativeField::from_u64(1);
    for bit in 0..8 {
        packed += power * low_pack_bit_value(row, after, start + bit)?;
        power += power;
    }
    Ok(packed)
}

fn packed_mmio_value(row: &[NativeField], width: usize) -> Result<NativeField, UniformError> {
    let mut packed = NativeField::from_u64(0);
    let mut power = NativeField::from_u64(1);
    for bit in 0..width {
        packed += power * mmio_io_value_bit(row, bit)?;
        power += power;
    }
    Ok(packed)
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
    packed: u64,
    width: usize,
) -> Result<(), BlockDeviceTimerMmioError> {
    for bit in 0..width {
        set(row, checked_add(start, bit)?, packed >> bit & 1)?;
    }
    Ok(())
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), BlockDeviceTimerMmioError> {
    *row.get_mut(index)
        .ok_or(BlockDeviceTimerMmioError::Layout)? = value;
    Ok(())
}

fn stage_start(tick: usize) -> Result<usize, BlockDeviceTimerMmioError> {
    if tick >= TIMER_TICK_BOUND {
        return Err(BlockDeviceTimerMmioError::Layout);
    }
    tick.checked_mul(STAGE_WIDTH)
        .ok_or(BlockDeviceTimerMmioError::Layout)
}

fn checked_stage_index(tick: usize, offset: usize) -> Result<usize, UniformError> {
    if tick >= TIMER_TICK_BOUND || offset >= STAGE_WIDTH {
        return Err(UniformError::Shape);
    }
    tick.checked_mul(STAGE_WIDTH)
        .and_then(|start| start.checked_add(offset))
        .filter(|index| *index < SHARED_TIMER_STAGE_COLUMN_COUNT)
        .ok_or(UniformError::Shape)
}

fn shared_timer_stage(row: &[NativeField]) -> Result<&[NativeField], UniformError> {
    let end = SHARED_TIMER_STAGE_COLUMN_START
        .checked_add(SHARED_TIMER_STAGE_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    row.get(SHARED_TIMER_STAGE_COLUMN_START..end)
        .ok_or(UniformError::Shape)
}

fn checked_add(start: usize, offset: usize) -> Result<usize, BlockDeviceTimerMmioError> {
    start
        .checked_add(offset)
        .ok_or(BlockDeviceTimerMmioError::Layout)
}

fn value(row: &[NativeField], index: usize) -> Result<NativeField, UniformError> {
    row.get(index).copied().ok_or(UniformError::Shape)
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
enum TimerStateSource {
    Post,
    Stage(usize),
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
