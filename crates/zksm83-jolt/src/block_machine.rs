//! Typed machine-mode selection and CPU transition constraints for packed rows.

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_core::StepKind;
use zksm83_trace::{BASIC_BLOCK_BUS_EVENT_BOUND, BASIC_BLOCK_INSTRUCTION_BOUND, BasicBlock};

use crate::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_FLOW_CONSTRAINT_COUNT, BLOCK_FLOW_MAX_DEGREE,
    BLOCK_FRONTEND_COLUMN_COUNT, BLOCK_ISA_CONTROL_COLUMN_COUNT, BLOCK_ROUTING_COLUMN_COUNT,
    BlockFlowRelation, BlockFrontendError, BlockFrontendWitness, ConstraintOutput, NativeField,
    STATE_BUS_NEXT_INDEX, STATE_CPU_M_CYCLES_INDEX, STATE_INPUT_NEXT_INDEX, STATE_ISA_NEXT_INDEX,
    STATE_MACHINE_PROFILE_INDEX, STATE_OUTPUT_NEXT_INDEX, UNIFORM_ROW_COUNT, UniformError,
    UniformRelation,
    block_boundary::local_state_value,
    block_bus::{slot_active_value, slot_address_value, slot_kind_selector, slot_value_value},
    block_metadata,
};

const MACHINE_AUX_START: usize = BLOCK_FRONTEND_COLUMN_COUNT;
const HALT_IDLE_MODE: usize = 0;
const HALT_UNTIL_VBLANK_MODE: usize = 1;
const HALT_WAKE_MODE: usize = 2;
const INTERRUPT_MODE: usize = 3;
const DMA_BYTE_MODE: usize = 4;
const HALT_UNTIL_SERIAL_MODE: usize = 5;
const HALT_UNTIL_TIMER_MODE: usize = 6;
const MACHINE_MODE_COUNT: usize = 7;
const BEFORE_IF_BITS_START: usize = MACHINE_MODE_COUNT;
const BEFORE_IE_BITS_START: usize = BEFORE_IF_BITS_START + 5;
const BEFORE_PC_BITS_START: usize = BEFORE_IE_BITS_START + 5;
const BEFORE_SP_BITS_START: usize = BEFORE_PC_BITS_START + 16;
const INTERRUPT_SOURCE_START: usize = BEFORE_SP_BITS_START + 16;
const PENDING_CLEAR_PREFIX_START: usize = INTERRUPT_SOURCE_START + 5;
const STACK_WRAP: usize = PENDING_CLEAR_PREFIX_START + 5;
const STACK_FIRST_WRAP: usize = STACK_WRAP + 1;
const SHORT_CYCLE_ACTIVE_START: usize = STACK_FIRST_WRAP + 1;
const MACHINE_AUX_COLUMN_COUNT: usize = SHORT_CYCLE_ACTIVE_START + 6;
const MACHINE_ADDITIONAL_CONSTRAINT_COUNT: usize = 229;
const STATE_PC: usize = 8;
const STATE_SP: usize = 9;
const STATE_IME: usize = 10;
const STATE_RUN_STATE: usize = 11;
const MEMORY_WRITE_KIND: u8 = 5;
const DMA_SOURCE_KIND_ROM: u8 = 16;
const DMA_SOURCE_KIND_MEMORY: u8 = 17;

/// Logical columns in the packed flow relation plus typed machine state.
pub const BLOCK_MACHINE_COLUMN_COUNT: usize =
    BLOCK_FRONTEND_COLUMN_COUNT + MACHINE_AUX_COLUMN_COUNT;
/// Identities in the typed packed-machine relation.
pub const BLOCK_MACHINE_CONSTRAINT_COUNT: usize =
    BLOCK_FLOW_CONSTRAINT_COUNT + MACHINE_ADDITIONAL_CONSTRAINT_COUNT;
/// Maximum total degree in the typed packed-machine relation.
pub const BLOCK_MACHINE_MAX_DEGREE: usize = BLOCK_FLOW_MAX_DEGREE;

const _: () = assert!(BASIC_BLOCK_INSTRUCTION_BOUND == 4);
const _: () = assert!(BASIC_BLOCK_BUS_EVENT_BOUND == 5);
const _: () = assert!(STATE_CPU_M_CYCLES_INDEX == 12);
const _: () = assert!(MACHINE_AUX_COLUMN_COUNT == 67);
const _: () = assert!(BLOCK_MACHINE_COLUMN_COUNT == 840);
const _: () = assert!(BLOCK_MACHINE_CONSTRAINT_COUNT == 1_397);
const _: () = assert!(BLOCK_MACHINE_MAX_DEGREE == 7);

/// Fixed-row witness carrying one typed machine mode for each singleton machine block.
#[derive(Debug)]
pub struct BlockMachineWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to construct the packed machine-mode witness.
#[derive(Debug, Error)]
pub enum BlockMachineError {
    /// Packed front-end construction failed.
    #[error("packed-block front-end construction failed: {0}")]
    Frontend(#[from] BlockFrontendError),
    /// A non-instruction block was not one typed singleton machine transition.
    #[error("packed block {block} is not a canonical singleton machine transition")]
    InvalidMachineBlock {
        /// Zero-based packed-block row.
        block: usize,
    },
    /// Machine auxiliary columns violated their fixed layout.
    #[error("packed-block machine witness violated its typed layout")]
    Layout,
}

/// Flow relation plus one-hot machine modes, CPU semantics, and interrupt priority.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockMachineRelation;

impl BlockMachineWitness {
    /// Derives typed machine rows from the validated packed-block partition.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockMachineError> {
        let frontend = BlockFrontendWitness::from_blocks(blocks)?;
        let active_block_count = frontend.active_block_count();
        let mut auxiliary = (0..MACHINE_AUX_COLUMN_COUNT)
            .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
            .collect::<Vec<_>>();
        for (block_index, block) in blocks.iter().enumerate() {
            let mut row = [0_u64; MACHINE_AUX_COLUMN_COUNT];
            append_machine_row(&mut row, block, block_index)?;
            for (column, value) in auxiliary.iter_mut().zip(row) {
                column.push(value);
            }
        }
        for column in &mut auxiliary {
            column.resize(UNIFORM_ROW_COUNT, 0);
        }
        let mut columns = frontend.into_columns();
        columns.extend(auxiliary);
        if columns.len() != BLOCK_MACHINE_COLUMN_COUNT {
            return Err(BlockMachineError::Layout);
        }
        Ok(Self {
            columns,
            active_block_count,
        })
    }

    /// Returns every logical column in flow-then-machine order.
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

impl UniformRelation for BlockMachineRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-machine/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [773_u64, 1_168, 7, 67, 840, 1_397, 1] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_MACHINE_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_MACHINE_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_MACHINE_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_MACHINE_COLUMN_COUNT
            || constraints.len() != BLOCK_MACHINE_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let frontend = row
            .get(..BLOCK_FRONTEND_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let auxiliary = row
            .get(MACHINE_AUX_START..BLOCK_MACHINE_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let (flow_constraints, machine_constraints) =
            constraints.split_at_mut(BLOCK_FLOW_CONSTRAINT_COUNT);
        BlockFlowRelation.evaluate(frontend, flow_constraints)?;
        constrain_machine(frontend, auxiliary, machine_constraints)
    }
}

fn append_machine_row(
    row: &mut [u64],
    block: &BasicBlock,
    block_index: usize,
) -> Result<(), BlockMachineError> {
    if block.instruction_count() != 0 {
        return Ok(());
    }
    if block.row_count() != 1 {
        return Err(BlockMachineError::InvalidMachineBlock { block: block_index });
    }
    let source = block
        .rows()
        .next()
        .ok_or(BlockMachineError::InvalidMachineBlock { block: block_index })?;
    let kind = source.effects().kind();
    let mode = MachineMode::for_step(kind)
        .ok_or(BlockMachineError::InvalidMachineBlock { block: block_index })?;
    set(row, mode.index(), 1)?;
    if matches!(kind, StepKind::HaltIdle | StepKind::InterruptDispatch(_)) {
        let cycles = usize::try_from(block.m_cycle_count())
            .map_err(|_| BlockMachineError::InvalidMachineBlock { block: block_index })?;
        if cycles > 6 {
            return Err(BlockMachineError::InvalidMachineBlock { block: block_index });
        }
        for cycle in 0..6 {
            set(
                row,
                checked_add(SHORT_CYCLE_ACTIVE_START, cycle)?,
                u64::from(cycle < cycles),
            )?;
        }
    }
    let before = block.initial_state();
    append_bits(
        row,
        BEFORE_IF_BITS_START,
        u64::from(before.dmg_devices().interrupt_request()),
        5,
    )?;
    append_bits(
        row,
        BEFORE_IE_BITS_START,
        u64::from(before.dmg_devices().interrupt_enable()),
        5,
    )?;
    append_bits(row, BEFORE_PC_BITS_START, u64::from(before.cpu().pc()), 16)?;
    append_bits(row, BEFORE_SP_BITS_START, u64::from(before.cpu().sp()), 16)?;
    let mut clear_prefix = true;
    for bit in 0..5 {
        let pending = before.dmg_devices().interrupt_request() >> bit & 1 == 1
            && before.dmg_devices().interrupt_enable() >> bit & 1 == 1;
        clear_prefix &= !pending;
        set(
            row,
            checked_add(PENDING_CLEAR_PREFIX_START, bit)?,
            u64::from(clear_prefix),
        )?;
    }
    if let StepKind::InterruptDispatch(interrupt) = source.effects().kind() {
        set(
            row,
            checked_add(INTERRUPT_SOURCE_START, usize::from(interrupt.bit()))?,
            1,
        )?;
        let sp = before.cpu().sp();
        set(row, STACK_WRAP, u64::from(sp < 2))?;
        set(row, STACK_FIRST_WRAP, u64::from(sp == 0))?;
    }
    Ok(())
}

fn constrain_machine(
    frontend: &[NativeField],
    auxiliary: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if auxiliary.len() != MACHINE_AUX_COLUMN_COUNT
        || constraints.len() != MACHINE_ADDITIONAL_CONSTRAINT_COUNT
    {
        return Err(UniformError::Shape);
    }
    let block_active = block_metadata::block_active_value(frontend)?;
    let instruction = block_metadata::instruction_value(frontend)?;
    let machine = block_active - instruction;
    let one = NativeField::from_u64(1);
    let mut sink = ConstraintSink::new(constraints);
    for state in auxiliary.iter().copied() {
        sink.push(state * (state - one))?;
        sink.push((one - machine) * state)?;
    }
    let boundary = frontend
        .get(BLOCK_ROUTING_COLUMN_COUNT..BLOCK_CONTROL_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let bus = frontend
        .get(BLOCK_ISA_CONTROL_COLUMN_COUNT..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    constrain_mode_partition(bus, auxiliary, machine, &mut sink)?;
    constrain_machine_inputs(boundary, auxiliary, machine, &mut sink)?;
    constrain_interrupt_priority(auxiliary, machine, &mut sink)?;
    constrain_mode_selection(boundary, auxiliary, &mut sink)?;
    constrain_short_cycles(boundary, auxiliary, &mut sink)?;
    constrain_cpu(boundary, bus, auxiliary, machine, &mut sink)?;
    constrain_non_cpu_flow(boundary, bus, auxiliary, machine, &mut sink)?;
    sink.finish()
}

fn constrain_short_cycles(
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let mut active_sum = NativeField::from_u64(0);
    for cycle in 0..6 {
        let active = value(auxiliary, SHORT_CYCLE_ACTIVE_START + cycle)?;
        active_sum += active;
        if cycle != 5 {
            let next = value(auxiliary, SHORT_CYCLE_ACTIVE_START + cycle + 1)?;
            sink.push((one - active) * next)?;
        }
    }
    let selector = mode_value(auxiliary, HALT_IDLE_MODE)? + mode_value(auxiliary, INTERRUPT_MODE)?;
    sink.push(active_sum - selector * state_delta(boundary, STATE_CPU_M_CYCLES_INDEX)?)
}

fn constrain_mode_partition(
    bus: &[NativeField],
    auxiliary: &[NativeField],
    machine: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let mode_sum = values(auxiliary, 0, MACHINE_MODE_COUNT)?
        .iter()
        .copied()
        .fold(NativeField::from_u64(0), |sum, mode| sum + mode);
    sink.push(mode_sum - machine)?;
    let dma = mode_value(auxiliary, DMA_BYTE_MODE)?;
    let source = slot_kind_selector(bus, 0, DMA_SOURCE_KIND_ROM)?
        + slot_kind_selector(bus, 0, DMA_SOURCE_KIND_MEMORY)?;
    sink.push(dma - source)
}

fn constrain_machine_inputs(
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    machine: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for (state, start, width) in [
        (21, BEFORE_IF_BITS_START, 5),
        (22, BEFORE_IE_BITS_START, 5),
        (STATE_PC, BEFORE_PC_BITS_START, 16),
        (STATE_SP, BEFORE_SP_BITS_START, 16),
    ] {
        sink.push(
            machine
                * (local_state_value(boundary, 0, state)? - packed_bits(auxiliary, start, width)?),
        )?;
    }
    Ok(())
}

fn constrain_interrupt_priority(
    auxiliary: &[NativeField],
    machine: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let interrupt = mode_value(auxiliary, INTERRUPT_MODE)?;
    let mut higher_clear = machine;
    let mut source_sum = NativeField::from_u64(0);
    for bit in 0..5 {
        let pending = value(auxiliary, BEFORE_IF_BITS_START + bit)?
            * value(auxiliary, BEFORE_IE_BITS_START + bit)?;
        let next_clear = value(auxiliary, PENDING_CLEAR_PREFIX_START + bit)?;
        sink.push(next_clear - higher_clear * (one - pending))?;
        let source = value(auxiliary, INTERRUPT_SOURCE_START + bit)?;
        sink.push(source - interrupt * pending * higher_clear)?;
        source_sum += source;
        higher_clear = next_clear;
    }
    sink.push(source_sum - interrupt)
}

fn constrain_mode_selection(
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let before_run = local_state_value(boundary, 0, STATE_RUN_STATE)?;
    let after_run = local_state_value(boundary, BASIC_BLOCK_INSTRUCTION_BOUND, STATE_RUN_STATE)?;
    let before_ime = local_state_value(boundary, 0, STATE_IME)?;
    let after_ime = local_state_value(boundary, BASIC_BLOCK_INSTRUCTION_BOUND, STATE_IME)?;
    let interrupt = mode_value(auxiliary, INTERRUPT_MODE)?;
    sink.push(
        interrupt * before_run * (before_run - one) * (before_run - NativeField::from_u64(3)),
    )?;
    sink.push(interrupt * (before_ime - NativeField::from_u64(2)))?;
    sink.push(interrupt * after_ime)?;
    sink.push(interrupt * after_run)?;
    let none_pending = value(auxiliary, PENDING_CLEAR_PREFIX_START + 4)?;
    let wake = mode_value(auxiliary, HALT_WAKE_MODE)?;
    sink.push(wake * (before_run - one))?;
    sink.push(wake * after_run)?;
    sink.push(wake * before_ime * (before_ime - one))?;
    sink.push(wake * none_pending)?;
    let sleeping = sleeping_mode(auxiliary)?;
    sink.push(sleeping * (before_run - one))?;
    sink.push(sleeping * (none_pending - one))?;
    let vblank = mode_value(auxiliary, HALT_UNTIL_VBLANK_MODE)?;
    sink.push(vblank * (value(auxiliary, BEFORE_IE_BITS_START)? - one))?;
    sink.push(vblank * value(auxiliary, BEFORE_IE_BITS_START + 4)?)?;
    sink.push(
        mode_value(auxiliary, HALT_UNTIL_SERIAL_MODE)?
            * (value(auxiliary, BEFORE_IE_BITS_START + 3)? - one),
    )?;
    sink.push(
        mode_value(auxiliary, HALT_UNTIL_TIMER_MODE)?
            * (value(auxiliary, BEFORE_IE_BITS_START + 2)? - one),
    )?;
    constrain_machine_cycles(boundary, auxiliary, sink)
}

fn constrain_machine_cycles(
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let increment = state_delta(boundary, STATE_CPU_M_CYCLES_INDEX)?;
    let zero_cycle = mode_value(auxiliary, HALT_WAKE_MODE)? + mode_value(auxiliary, DMA_BYTE_MODE)?;
    sink.push(zero_cycle * increment)?;
    sink.push(mode_value(auxiliary, INTERRUPT_MODE)? * (increment - NativeField::from_u64(5)))?;
    let mut idle_range = mode_value(auxiliary, HALT_IDLE_MODE)?;
    for admitted in 1..=6 {
        idle_range *= increment - NativeField::from_u64(admitted);
    }
    sink.push(idle_range)
}

fn constrain_cpu(
    boundary: &[NativeField],
    bus: &[NativeField],
    auxiliary: &[NativeField],
    machine: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let passive = sleeping_mode(auxiliary)? + mode_value(auxiliary, DMA_BYTE_MODE)?;
    for state in 0..STATE_CPU_M_CYCLES_INDEX {
        sink.push(passive * state_delta(boundary, state)?)?;
    }
    let wake = mode_value(auxiliary, HALT_WAKE_MODE)?;
    for state in 0..STATE_RUN_STATE {
        sink.push(wake * state_delta(boundary, state)?)?;
    }
    let interrupt = mode_value(auxiliary, INTERRUPT_MODE)?;
    for state in 0..STATE_PC {
        sink.push(interrupt * state_delta(boundary, state)?)?;
    }
    constrain_interrupt_cpu(boundary, bus, auxiliary, machine, interrupt, sink)
}

fn constrain_interrupt_cpu(
    boundary: &[NativeField],
    bus: &[NativeField],
    auxiliary: &[NativeField],
    machine: NativeField,
    interrupt: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let mut vector = NativeField::from_u64(0);
    for (source, address) in [0x40_u64, 0x48, 0x50, 0x58, 0x60].into_iter().enumerate() {
        vector +=
            value(auxiliary, INTERRUPT_SOURCE_START + source)? * NativeField::from_u64(address);
    }
    sink.push(
        interrupt
            * (local_state_value(boundary, BASIC_BLOCK_INSTRUCTION_BOUND, STATE_PC)? - vector),
    )?;
    let before_sp = local_state_value(boundary, 0, STATE_SP)?;
    let after_sp = local_state_value(boundary, BASIC_BLOCK_INSTRUCTION_BOUND, STATE_SP)?;
    let wrap = value(auxiliary, STACK_WRAP)?;
    let first_wrap = value(auxiliary, STACK_FIRST_WRAP)?;
    sink.push(
        interrupt
            * (after_sp - before_sp + NativeField::from_u64(2)
                - NativeField::from_u64(65_536) * wrap),
    )?;
    sink.push(
        interrupt
            * (slot_address_value(bus, 0)? - before_sp + one
                - NativeField::from_u64(65_536) * first_wrap),
    )?;
    sink.push(
        interrupt
            * (slot_address_value(bus, 1)? - before_sp + NativeField::from_u64(2)
                - NativeField::from_u64(65_536) * wrap),
    )?;
    sink.push(
        interrupt
            * (slot_value_value(bus, 0)? - packed_bits(auxiliary, BEFORE_PC_BITS_START + 8, 8)?),
    )?;
    sink.push(
        interrupt * (slot_value_value(bus, 1)? - packed_bits(auxiliary, BEFORE_PC_BITS_START, 8)?),
    )?;
    for slot in 0..2 {
        sink.push(machine * (slot_kind_selector(bus, slot, MEMORY_WRITE_KIND)? - interrupt))?;
    }
    for slot in 2..BASIC_BLOCK_BUS_EVENT_BOUND {
        sink.push(interrupt * slot_active_value(bus, slot)?)?;
    }
    Ok(())
}

fn constrain_non_cpu_flow(
    boundary: &[NativeField],
    bus: &[NativeField],
    auxiliary: &[NativeField],
    machine: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for scalar in [
        13,
        14,
        15,
        STATE_INPUT_NEXT_INDEX,
        STATE_OUTPUT_NEXT_INDEX,
        STATE_BUS_NEXT_INDEX,
        STATE_ISA_NEXT_INDEX,
        STATE_MACHINE_PROFILE_INDEX,
    ] {
        sink.push(machine * state_delta(boundary, scalar)?)?;
    }
    let bus_free = sleeping_mode(auxiliary)? + mode_value(auxiliary, HALT_WAKE_MODE)?;
    for slot in 0..BASIC_BLOCK_BUS_EVENT_BOUND {
        sink.push(bus_free * slot_active_value(bus, slot)?)?;
    }
    Ok(())
}

fn sleeping_mode(auxiliary: &[NativeField]) -> Result<NativeField, UniformError> {
    Ok(mode_value(auxiliary, HALT_IDLE_MODE)?
        + mode_value(auxiliary, HALT_UNTIL_VBLANK_MODE)?
        + mode_value(auxiliary, HALT_UNTIL_SERIAL_MODE)?
        + mode_value(auxiliary, HALT_UNTIL_TIMER_MODE)?)
}

fn mode_value(row: &[NativeField], mode: usize) -> Result<NativeField, UniformError> {
    if mode >= MACHINE_MODE_COUNT {
        return Err(UniformError::Shape);
    }
    value(row, mode)
}

pub(crate) fn short_device_clocked_value(row: &[NativeField]) -> Result<NativeField, UniformError> {
    if row.len() < BLOCK_MACHINE_COLUMN_COUNT {
        return Err(UniformError::Shape);
    }
    Ok(block_metadata::instruction_value(row)?
        + value(row, MACHINE_AUX_START + HALT_IDLE_MODE)?
        + value(row, MACHINE_AUX_START + INTERRUPT_MODE)?)
}

pub(crate) fn device_clocked_value(row: &[NativeField]) -> Result<NativeField, UniformError> {
    Ok(short_device_clocked_value(row)?
        + value(row, MACHINE_AUX_START + HALT_UNTIL_VBLANK_MODE)?
        + value(row, MACHINE_AUX_START + HALT_UNTIL_SERIAL_MODE)?
        + value(row, MACHINE_AUX_START + HALT_UNTIL_TIMER_MODE)?)
}

pub(crate) fn halt_idle_value(row: &[NativeField]) -> Result<NativeField, UniformError> {
    if row.len() < BLOCK_MACHINE_COLUMN_COUNT {
        return Err(UniformError::Shape);
    }
    value(row, MACHINE_AUX_START + HALT_IDLE_MODE)
}

pub(crate) fn before_interrupt_enable_bit_value(
    row: &[NativeField],
    bit: usize,
) -> Result<NativeField, UniformError> {
    if row.len() < BLOCK_MACHINE_COLUMN_COUNT || bit >= 5 {
        return Err(UniformError::Shape);
    }
    value(row, MACHINE_AUX_START + BEFORE_IE_BITS_START + bit)
}

pub(crate) fn halt_until_vblank_value(row: &[NativeField]) -> Result<NativeField, UniformError> {
    if row.len() < BLOCK_MACHINE_COLUMN_COUNT {
        return Err(UniformError::Shape);
    }
    value(row, MACHINE_AUX_START + HALT_UNTIL_VBLANK_MODE)
}

pub(crate) fn halt_until_serial_value(row: &[NativeField]) -> Result<NativeField, UniformError> {
    if row.len() < BLOCK_MACHINE_COLUMN_COUNT {
        return Err(UniformError::Shape);
    }
    value(row, MACHINE_AUX_START + HALT_UNTIL_SERIAL_MODE)
}

pub(crate) fn halt_until_timer_value(row: &[NativeField]) -> Result<NativeField, UniformError> {
    if row.len() < BLOCK_MACHINE_COLUMN_COUNT {
        return Err(UniformError::Shape);
    }
    value(row, MACHINE_AUX_START + HALT_UNTIL_TIMER_MODE)
}

pub(crate) fn short_cycle_active_value(
    row: &[NativeField],
    cycle: usize,
) -> Result<NativeField, UniformError> {
    if row.len() < BLOCK_MACHINE_COLUMN_COUNT || cycle >= 6 {
        return Err(UniformError::Shape);
    }
    value(row, MACHINE_AUX_START + SHORT_CYCLE_ACTIVE_START + cycle)
}

pub(crate) fn interrupt_source_value(
    row: &[NativeField],
    bit: usize,
) -> Result<NativeField, UniformError> {
    if row.len() < BLOCK_MACHINE_COLUMN_COUNT || bit >= 5 {
        return Err(UniformError::Shape);
    }
    value(row, MACHINE_AUX_START + INTERRUPT_SOURCE_START + bit)
}

fn state_delta(boundary: &[NativeField], scalar: usize) -> Result<NativeField, UniformError> {
    Ok(
        local_state_value(boundary, BASIC_BLOCK_INSTRUCTION_BOUND, scalar)?
            - local_state_value(boundary, 0, scalar)?,
    )
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

fn value(row: &[NativeField], index: usize) -> Result<NativeField, UniformError> {
    row.get(index).copied().ok_or(UniformError::Shape)
}

fn append_bits(
    row: &mut [u64],
    start: usize,
    value: u64,
    width: usize,
) -> Result<(), BlockMachineError> {
    for bit in 0..width {
        set(row, checked_add(start, bit)?, value >> bit & 1)?;
    }
    Ok(())
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), BlockMachineError> {
    *row.get_mut(index).ok_or(BlockMachineError::Layout)? = value;
    Ok(())
}

fn checked_add(start: usize, offset: usize) -> Result<usize, BlockMachineError> {
    start.checked_add(offset).ok_or(BlockMachineError::Layout)
}

#[derive(Clone, Copy)]
enum MachineMode {
    HaltIdle,
    HaltUntilVBlank,
    HaltWake,
    Interrupt,
    DmaByte,
    HaltUntilSerial,
    HaltUntilTimer,
}

impl MachineMode {
    const fn for_step(kind: StepKind) -> Option<Self> {
        match kind {
            StepKind::HaltIdle => Some(Self::HaltIdle),
            StepKind::HaltUntilVBlank => Some(Self::HaltUntilVBlank),
            StepKind::HaltWake => Some(Self::HaltWake),
            StepKind::InterruptDispatch(_) => Some(Self::Interrupt),
            StepKind::DmaByte => Some(Self::DmaByte),
            StepKind::HaltUntilSerial => Some(Self::HaltUntilSerial),
            StepKind::HaltUntilTimer => Some(Self::HaltUntilTimer),
            StepKind::Instruction => None,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::HaltIdle => HALT_IDLE_MODE,
            Self::HaltUntilVBlank => HALT_UNTIL_VBLANK_MODE,
            Self::HaltWake => HALT_WAKE_MODE,
            Self::Interrupt => INTERRUPT_MODE,
            Self::DmaByte => DMA_BYTE_MODE,
            Self::HaltUntilSerial => HALT_UNTIL_SERIAL_MODE,
            Self::HaltUntilTimer => HALT_UNTIL_TIMER_MODE,
        }
    }
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
