//! Packed P1 sampling, select-line writes, falling edges, and joypad IF updates.

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_core::BusEventKind;
use zksm83_trace::BasicBlock;

use crate::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_DEVICE_MMIO_COLUMN_COUNT, BLOCK_DEVICE_MMIO_CONSTRAINT_COUNT,
    BLOCK_DEVICE_MMIO_MAX_DEGREE, BLOCK_FRONTEND_COLUMN_COUNT, BLOCK_ROUTING_COLUMN_COUNT,
    BlockDeviceMmioError, BlockDeviceMmioRelation, BlockDeviceMmioWitness, ConstraintOutput,
    NativeField, STATE_INPUT_NEXT_INDEX, STATE_JOYPAD_PACK_INDEX, UNIFORM_ROW_COUNT, UniformError,
    UniformRelation,
    block_boundary::{device_state_value, local_state_value},
    block_device::device_io_selector_value,
    block_device_mmio::{
        mmio_address_selector_value, mmio_io_auxiliary_value, mmio_io_before_value,
        mmio_io_index_value, mmio_io_value, mmio_io_value_bit, mmio_joypad_selector_value,
        mmio_write_selector_value,
    },
    block_device_serial::interrupt_request_bit_value,
    block_metadata,
};

const JOYPAD_AUX_START: usize = BLOCK_DEVICE_MMIO_COLUMN_COUNT;
const STATE_WIDTH: usize = 10;
const BEFORE_STATE_START: usize = 0;
const AFTER_STATE_START: usize = BEFORE_STATE_START + STATE_WIDTH;
const INPUT_BITS_START: usize = AFTER_STATE_START + STATE_WIDTH;
const BEFORE_VISIBLE_BITS_START: usize = INPUT_BITS_START + 8;
const AFTER_VISIBLE_BITS_START: usize = BEFORE_VISIBLE_BITS_START + 4;
const FALLING_BITS_START: usize = AFTER_VISIBLE_BITS_START + 4;
const FALLING_CLEAR_PREFIX_START: usize = FALLING_BITS_START + 4;
const P1_EVENT: usize = FALLING_CLEAR_PREFIX_START + 4;
const JOYPAD_AUX_COLUMN_COUNT: usize = P1_EVENT + 1;
const JOYPAD_ADDITIONAL_CONSTRAINT_COUNT: usize = 117;

/// Logical columns in the typed MMIO relation plus complete P1 semantics.
pub const BLOCK_DEVICE_JOYPAD_COLUMN_COUNT: usize =
    BLOCK_DEVICE_MMIO_COLUMN_COUNT + JOYPAD_AUX_COLUMN_COUNT;
/// Identities in the packed P1 relation.
pub const BLOCK_DEVICE_JOYPAD_CONSTRAINT_COUNT: usize =
    BLOCK_DEVICE_MMIO_CONSTRAINT_COUNT + JOYPAD_ADDITIONAL_CONSTRAINT_COUNT;
/// Maximum total degree in the packed P1 relation.
pub const BLOCK_DEVICE_JOYPAD_MAX_DEGREE: usize = BLOCK_DEVICE_MMIO_MAX_DEGREE;

const _: () = assert!(STATE_WIDTH == 10);
const _: () = assert!(JOYPAD_AUX_COLUMN_COUNT == 45);
const _: () = assert!(BLOCK_DEVICE_JOYPAD_COLUMN_COUNT == 2_505);
const _: () = assert!(BLOCK_DEVICE_JOYPAD_CONSTRAINT_COUNT == 5_543);
const _: () = assert!(BLOCK_DEVICE_JOYPAD_MAX_DEGREE == 14);

/// Fixed-row witness carrying generic P1 state and falling-edge semantics.
#[derive(Debug)]
pub struct BlockDeviceJoypadWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to construct the packed P1 witness.
#[derive(Debug, Error)]
pub enum BlockDeviceJoypadError {
    /// Typed MMIO witness construction failed.
    #[error("packed-block MMIO construction failed: {0}")]
    Mmio(#[from] BlockDeviceMmioError),
    /// A validated block exposed an inconsistent P1 or joypad-IF transition.
    #[error("packed block {block} has an inconsistent joypad transition")]
    InvalidTransition {
        /// Zero-based packed-block row.
        block: usize,
    },
    /// Joypad auxiliary columns violated their fixed layout.
    #[error("packed-block joypad witness violated its typed layout")]
    Layout,
}

/// Typed MMIO relation plus P1 sampling, selection, and interrupt semantics.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockDeviceJoypadRelation;

impl BlockDeviceJoypadWitness {
    /// Derives complete P1 columns from validated packed blocks.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockDeviceJoypadError> {
        let mmio = BlockDeviceMmioWitness::from_blocks(blocks)?;
        let active_block_count = mmio.active_block_count();
        let mut auxiliary = (0..JOYPAD_AUX_COLUMN_COUNT)
            .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
            .collect::<Vec<_>>();
        for (block_index, block) in blocks.iter().enumerate() {
            let mut row = [0_u64; JOYPAD_AUX_COLUMN_COUNT];
            append_joypad_row(&mut row, block, block_index)?;
            for (column, value) in auxiliary.iter_mut().zip(row) {
                column.push(value);
            }
        }
        for column in &mut auxiliary {
            column.resize(UNIFORM_ROW_COUNT, 0);
        }
        let mut columns = mmio.into_columns();
        columns.extend(auxiliary);
        if columns.len() != BLOCK_DEVICE_JOYPAD_COLUMN_COUNT {
            return Err(BlockDeviceJoypadError::Layout);
        }
        Ok(Self {
            columns,
            active_block_count,
        })
    }

    /// Returns every logical column in MMIO-then-joypad order.
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

impl UniformRelation for BlockDeviceJoypadRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-device-joypad/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [2_460_u64, 5_426, 45, 117, 2_505, 5_543, 5] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_DEVICE_JOYPAD_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_DEVICE_JOYPAD_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_DEVICE_JOYPAD_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_DEVICE_JOYPAD_COLUMN_COUNT
            || constraints.len() != BLOCK_DEVICE_JOYPAD_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let mmio = row
            .get(..BLOCK_DEVICE_MMIO_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let auxiliary = row
            .get(JOYPAD_AUX_START..BLOCK_DEVICE_JOYPAD_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let (mmio_constraints, joypad_constraints) =
            constraints.split_at_mut(BLOCK_DEVICE_MMIO_CONSTRAINT_COUNT);
        BlockDeviceMmioRelation.evaluate(mmio, mmio_constraints)?;
        constrain_joypad(mmio, auxiliary, joypad_constraints)
    }
}

fn append_joypad_row(
    row: &mut [u64],
    block: &BasicBlock,
    block_index: usize,
) -> Result<(), BlockDeviceJoypadError> {
    let before = JoypadState::from_pack(
        block.initial_state().dmg_devices().joypad_pack(),
        block_index,
    )?;
    let after =
        JoypadState::from_pack(block.final_state().dmg_devices().joypad_pack(), block_index)?;
    let event = typed_device_event(block, block_index)?;
    let mut expected = before;
    let mut input = 0_u8;
    let mut p1_event = false;
    if let Some((kind, tuple)) = event {
        if kind == BusEventKind::DmgJoypadRead {
            input = tuple.auxiliary;
            expected.buttons = input;
            p1_event = true;
        } else if kind == BusEventKind::DmgMmioWrite && tuple.address == 0xff00 {
            expected.select = tuple.value & 0x30;
            p1_event = true;
        }
    }
    if expected != after {
        return Err(BlockDeviceJoypadError::InvalidTransition { block: block_index });
    }
    let before_visible = before.visible();
    let after_visible = after.visible();
    let falling = (before_visible & !after_visible) & 0x0f;
    validate_interrupt_transition(block, event, falling, block_index)?;
    append_state(row, BEFORE_STATE_START, before)?;
    append_state(row, AFTER_STATE_START, after)?;
    append_bits(row, INPUT_BITS_START, u64::from(input), 8)?;
    append_bits(
        row,
        BEFORE_VISIBLE_BITS_START,
        u64::from(before_visible & 0x0f),
        4,
    )?;
    append_bits(
        row,
        AFTER_VISIBLE_BITS_START,
        u64::from(after_visible & 0x0f),
        4,
    )?;
    append_bits(row, FALLING_BITS_START, u64::from(falling), 4)?;
    let mut clear = true;
    for bit in 0..4 {
        clear &= falling >> bit & 1 == 0;
        set(row, FALLING_CLEAR_PREFIX_START + bit, u64::from(clear))?;
    }
    set(row, P1_EVENT, u64::from(p1_event))
}

fn typed_device_event(
    block: &BasicBlock,
    block_index: usize,
) -> Result<Option<(BusEventKind, zksm83_memory::BusTranscriptEvent)>, BlockDeviceJoypadError> {
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
                return Err(BlockDeviceJoypadError::InvalidTransition { block: block_index });
            }
            selected = Some((event.kind(), event.transcript_event()));
        }
    }
    Ok(selected)
}

fn validate_interrupt_transition(
    block: &BasicBlock,
    event: Option<(BusEventKind, zksm83_memory::BusTranscriptEvent)>,
    falling: u8,
    block_index: usize,
) -> Result<(), BlockDeviceJoypadError> {
    let Some((kind, tuple)) = event else {
        return Ok(());
    };
    let before = block.initial_state().dmg_devices().interrupt_request() & 0x10 != 0;
    let after = block.final_state().dmg_devices().interrupt_request() & 0x10 != 0;
    let mut expected = before;
    if kind == BusEventKind::DmgMmioWrite && tuple.address == 0xff0f {
        expected = tuple.value & 0x10 != 0;
    }
    if kind == BusEventKind::DmgJoypadRead
        || (kind == BusEventKind::DmgMmioWrite && tuple.address == 0xff00)
    {
        expected |= falling != 0;
    }
    if expected == after {
        Ok(())
    } else {
        Err(BlockDeviceJoypadError::InvalidTransition { block: block_index })
    }
}

fn append_state(
    row: &mut [u64],
    start: usize,
    state: JoypadState,
) -> Result<(), BlockDeviceJoypadError> {
    set(row, start, u64::from(state.select >> 4 & 1))?;
    set(row, start + 1, u64::from(state.select >> 5 & 1))?;
    append_bits(row, start + 2, u64::from(state.buttons), 8)
}

fn constrain_joypad(
    mmio: &[NativeField],
    auxiliary: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if auxiliary.len() != JOYPAD_AUX_COLUMN_COUNT
        || constraints.len() != JOYPAD_ADDITIONAL_CONSTRAINT_COUNT
    {
        return Err(UniformError::Shape);
    }
    let one = NativeField::from_u64(1);
    let block_active = block_metadata::block_active_value(mmio)?;
    let mut sink = ConstraintSink::new(constraints);
    for column in auxiliary.iter().copied() {
        sink.push(column * (column - one))?;
        sink.push((one - block_active) * column)?;
    }
    let frontend = mmio
        .get(..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let boundary = frontend
        .get(BLOCK_ROUTING_COLUMN_COUNT..BLOCK_CONTROL_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    constrain_state(boundary, auxiliary, false, block_active, &mut sink)?;
    constrain_state(boundary, auxiliary, true, block_active, &mut sink)?;
    let input = packed_bits(auxiliary, INPUT_BITS_START, 8)?;
    sink.push(input - mmio_io_auxiliary_value(mmio)?)?;
    let joypad = mmio_joypad_selector_value(mmio)?;
    let write = mmio_write_selector_value(mmio)?;
    let p1_event = value(auxiliary, P1_EVENT)?;
    sink.push(p1_event - joypad - mmio_address_selector_value(mmio, 0x00)? * write)?;
    let ff00_write = p1_event - joypad;
    constrain_state_transition(mmio, auxiliary, input, joypad, ff00_write, &mut sink)?;
    constrain_bus_tuple(mmio, auxiliary, boundary, joypad, ff00_write, &mut sink)?;
    let falling = constrain_falling(auxiliary, block_active, &mut sink)?;
    constrain_interrupt(mmio, falling, p1_event, write, &mut sink)?;
    sink.finish()
}

fn constrain_state(
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    after: bool,
    block_active: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let start = state_start(after);
    let packed = select_value(auxiliary, start)?
        + NativeField::from_u64(256) * packed_bits(auxiliary, start + 2, 8)?;
    sink.push(device_state_value(boundary, after, STATE_JOYPAD_PACK_INDEX)? - packed)?;
    let visible_start = if after {
        AFTER_VISIBLE_BITS_START
    } else {
        BEFORE_VISIBLE_BITS_START
    };
    for bit in 0..4 {
        sink.push(
            block_active
                * (value(auxiliary, visible_start + bit)?
                    - visible_low_bit(auxiliary, start, bit)?),
        )?;
    }
    Ok(())
}

fn constrain_state_transition(
    mmio: &[NativeField],
    auxiliary: &[NativeField],
    input: NativeField,
    joypad: NativeField,
    ff00_write: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let before_buttons = packed_bits(auxiliary, BEFORE_STATE_START + 2, 8)?;
    let after_buttons = packed_bits(auxiliary, AFTER_STATE_START + 2, 8)?;
    sink.push(after_buttons - before_buttons - joypad * (input - before_buttons))?;
    let before_select = select_value(auxiliary, BEFORE_STATE_START)?;
    let after_select = select_value(auxiliary, AFTER_STATE_START)?;
    let written_select = NativeField::from_u64(16) * mmio_io_value_bit(mmio, 4)?
        + NativeField::from_u64(32) * mmio_io_value_bit(mmio, 5)?;
    sink.push(after_select - before_select - ff00_write * (written_select - before_select))
}

fn constrain_bus_tuple(
    mmio: &[NativeField],
    auxiliary: &[NativeField],
    boundary: &[NativeField],
    joypad: NativeField,
    ff00_write: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let before_buttons = packed_bits(auxiliary, BEFORE_STATE_START + 2, 8)?;
    sink.push(joypad * (mmio_io_before_value(mmio)? - before_buttons))?;
    sink.push(joypad * (mmio_io_value(mmio)? - visible_byte(auxiliary, true)?))?;
    sink.push(
        joypad
            * (mmio_io_index_value(mmio)?
                - local_state_value(boundary, 0, STATE_INPUT_NEXT_INDEX)?),
    )?;
    sink.push(ff00_write * (mmio_io_before_value(mmio)? - visible_byte(auxiliary, false)?))
}

fn constrain_falling(
    auxiliary: &[NativeField],
    block_active: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<NativeField, UniformError> {
    let one = NativeField::from_u64(1);
    let mut clear = block_active;
    for bit in 0..4 {
        let falling = value(auxiliary, FALLING_BITS_START + bit)?;
        sink.push(
            falling
                - value(auxiliary, BEFORE_VISIBLE_BITS_START + bit)?
                    * (one - value(auxiliary, AFTER_VISIBLE_BITS_START + bit)?),
        )?;
        let next = value(auxiliary, FALLING_CLEAR_PREFIX_START + bit)?;
        sink.push(next - clear * (one - falling))?;
        clear = next;
    }
    Ok(block_active - clear)
}

fn constrain_interrupt(
    mmio: &[NativeField],
    falling: NativeField,
    p1_event: NativeField,
    write: NativeField,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let before = interrupt_request_bit_value(mmio, false, 4)?;
    let after = interrupt_request_bit_value(mmio, true, 4)?;
    let ff0f_write = mmio_address_selector_value(mmio, 0x0f)? * write;
    sink.push(
        device_io_selector_value(mmio)? * (after - before)
            - ff0f_write * (mmio_io_value_bit(mmio, 4)? - before)
            - p1_event * (falling - before * falling),
    )
}

fn visible_byte(row: &[NativeField], after: bool) -> Result<NativeField, UniformError> {
    let mut visible = NativeField::from_u64(0xc0) + select_value(row, state_start(after))?;
    let start = if after {
        AFTER_VISIBLE_BITS_START
    } else {
        BEFORE_VISIBLE_BITS_START
    };
    let mut power = NativeField::from_u64(1);
    for bit in 0..4 {
        visible += power * value(row, start + bit)?;
        power += power;
    }
    Ok(visible)
}

fn visible_low_bit(
    row: &[NativeField],
    state_start: usize,
    bit: usize,
) -> Result<NativeField, UniformError> {
    if bit >= 4 {
        return Err(UniformError::Shape);
    }
    let one = NativeField::from_u64(1);
    let direction = one - (one - value(row, state_start)?) * value(row, state_start + 2 + bit)?;
    let action = one - (one - value(row, state_start + 1)?) * value(row, state_start + 6 + bit)?;
    Ok(direction * action)
}

fn select_value(row: &[NativeField], start: usize) -> Result<NativeField, UniformError> {
    Ok(NativeField::from_u64(16) * value(row, start)?
        + NativeField::from_u64(32) * value(row, start + 1)?)
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
) -> Result<(), BlockDeviceJoypadError> {
    for bit in 0..width {
        set(
            row,
            start
                .checked_add(bit)
                .ok_or(BlockDeviceJoypadError::Layout)?,
            packed >> bit & 1,
        )?;
    }
    Ok(())
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), BlockDeviceJoypadError> {
    *row.get_mut(index).ok_or(BlockDeviceJoypadError::Layout)? = value;
    Ok(())
}

fn value(row: &[NativeField], index: usize) -> Result<NativeField, UniformError> {
    row.get(index).copied().ok_or(UniformError::Shape)
}

const fn state_start(after: bool) -> usize {
    if after {
        AFTER_STATE_START
    } else {
        BEFORE_STATE_START
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JoypadState {
    select: u8,
    buttons: u8,
}

impl JoypadState {
    fn from_pack(pack: u16, block: usize) -> Result<Self, BlockDeviceJoypadError> {
        let [select, buttons] = pack.to_le_bytes();
        if select & !0x30 != 0 {
            return Err(BlockDeviceJoypadError::InvalidTransition { block });
        }
        Ok(Self { select, buttons })
    }

    const fn visible(self) -> u8 {
        let mut low = 0x0f;
        if self.select & 0x10 == 0 {
            low &= !(self.buttons & 0x0f);
        }
        if self.select & 0x20 == 0 {
            low &= !((self.buttons >> 4) & 0x0f);
        }
        0xc0 | self.select | low
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
mod tests {
    use zksm83_memory::{MemoryImage, RomImage};
    use zksm83_trace::{LookupTraceBuilder, pack_witness_basic_blocks};

    use super::*;
    use crate::validate_uniform_witness;

    #[test]
    fn joypad_read_binds_sample_and_falling_interrupt() -> Result<(), Box<dyn std::error::Error>> {
        let blocks = fixture(&[0xf0, 0x00], vec![0x10], 1)?;
        let witness = BlockDeviceJoypadWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockDeviceJoypadRelation, witness.columns())?;

        let mut mutated = witness.columns().to_vec();
        let sample = mutated
            .get_mut(JOYPAD_AUX_START + INPUT_BITS_START + 4)
            .and_then(|column| column.first_mut())
            .ok_or(UniformError::Shape)?;
        *sample = 0;
        assert!(validate_uniform_witness(&BlockDeviceJoypadRelation, &mutated).is_err());
        Ok(())
    }

    #[test]
    fn p1_write_binds_visible_before_and_select_transition()
    -> Result<(), Box<dyn std::error::Error>> {
        let blocks = fixture(&[0x3e, 0x20, 0xe0, 0x00], Vec::new(), 2)?;
        let witness = BlockDeviceJoypadWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockDeviceJoypadRelation, witness.columns())?;
        Ok(())
    }

    fn fixture(
        program: &[u8],
        input: Vec<u8>,
        steps: u64,
    ) -> Result<Vec<BasicBlock>, Box<dyn std::error::Error>> {
        let mut bytes = vec![0_u8; 0x100 + program.len()];
        bytes
            .get_mut(0x100..)
            .ok_or(UniformError::Shape)?
            .copy_from_slice(program);
        let rom = RomImage::new(bytes.clone())?;
        let memory = MemoryImage::zeroed()?;
        let mut builder = LookupTraceBuilder::new_dmg_post_boot_mbc3(
            bytes,
            memory.checkpoint_bytes(),
            input,
            rom.root(),
            memory.root(),
        )?;
        Ok(pack_witness_basic_blocks(builder.run_exact_steps(steps)?)?)
    }
}
