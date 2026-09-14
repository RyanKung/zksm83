//! Packed DMG APU storage, visibility, power, DAC, trigger, and wave-RAM semantics.

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_core::{BusEventKind, DmgApuState, apu_read_mask};
use zksm83_trace::BasicBlock;

use crate::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_DEVICE_JOYPAD_COLUMN_COUNT,
    BLOCK_DEVICE_JOYPAD_CONSTRAINT_COUNT, BLOCK_DEVICE_JOYPAD_MAX_DEGREE,
    BLOCK_FRONTEND_COLUMN_COUNT, BLOCK_ROUTING_COLUMN_COUNT, BlockDeviceJoypadError,
    BlockDeviceJoypadRelation, BlockDeviceJoypadWitness, ConstraintOutput, NativeField,
    STATE_APU_CONTROL_HIGH_PACK_INDEX, STATE_APU_CONTROL_LOW_PACK_INDEX,
    STATE_APU_MIXER_PACK_INDEX, STATE_APU_WAVE_HIGH_PACK_INDEX, STATE_APU_WAVE_LOW_PACK_INDEX,
    UNIFORM_ROW_COUNT, UniformError, UniformRelation,
    block_boundary::device_state_value,
    block_device_mmio::{
        mmio_address_selector_value, mmio_io_before_value, mmio_io_value, mmio_io_value_bit,
        mmio_read_selector_value, mmio_write_selector_value,
    },
    block_metadata,
};

const APU_AUX_START: usize = BLOCK_DEVICE_JOYPAD_COLUMN_COUNT;
const PACK_WIDTH: usize = 64;
const PACK_COUNT: usize = 5;
const APU_STATE_WIDTH: usize = PACK_WIDTH * PACK_COUNT;
const BEFORE_BITS_START: usize = 0;
const AFTER_BITS_START: usize = BEFORE_BITS_START + APU_STATE_WIDTH;
const POWER_OFF: usize = AFTER_BITS_START + APU_STATE_WIDTH;
const POWER_ON: usize = POWER_OFF + 1;
const AFTER_DAC_ENABLED_START: usize = POWER_ON + 1;
const DAC_WRITE_START: usize = AFTER_DAC_ENABLED_START + 4;
const WRITTEN_DAC_ENABLED_START: usize = DAC_WRITE_START + 4;
const TRIGGER_START: usize = WRITTEN_DAC_ENABLED_START + 4;
const APU_WRITE: usize = TRIGGER_START + 4;
const APU_AUX_COLUMN_COUNT: usize = APU_WRITE + 1;
const APU_ADDITIONAL_CONSTRAINT_COUNT: usize = 1_678;
const MIXER_UNUSED_BYTE: usize = 7;

/// Logical columns in the joypad relation plus complete modeled APU semantics.
pub const BLOCK_DEVICE_APU_COLUMN_COUNT: usize =
    BLOCK_DEVICE_JOYPAD_COLUMN_COUNT + APU_AUX_COLUMN_COUNT;
/// Identities in the packed modeled-APU relation.
pub const BLOCK_DEVICE_APU_CONSTRAINT_COUNT: usize =
    BLOCK_DEVICE_JOYPAD_CONSTRAINT_COUNT + APU_ADDITIONAL_CONSTRAINT_COUNT;
/// Maximum total degree in the packed modeled-APU relation.
pub const BLOCK_DEVICE_APU_MAX_DEGREE: usize = BLOCK_DEVICE_JOYPAD_MAX_DEGREE;

const _: () = assert!(APU_STATE_WIDTH == 320);
const _: () = assert!(APU_AUX_COLUMN_COUNT == 659);
const _: () = assert!(BLOCK_DEVICE_APU_COLUMN_COUNT == 3_269);
const _: () = assert!(BLOCK_DEVICE_APU_CONSTRAINT_COUNT == 7_395);
const _: () = assert!(BLOCK_DEVICE_APU_MAX_DEGREE == 7);

/// Fixed-row witness carrying the five APU boundary packs and write predicates.
#[derive(Debug)]
pub struct BlockDeviceApuWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
}

/// Failure to construct the packed modeled-APU witness.
#[derive(Debug, Error)]
pub enum BlockDeviceApuError {
    /// Joypad relation construction failed.
    #[error("packed-block joypad construction failed: {0}")]
    Joypad(#[from] BlockDeviceJoypadError),
    /// A validated block exposed an inconsistent APU event or state transition.
    #[error("packed block {block} has an inconsistent APU transition")]
    InvalidTransition {
        /// Zero-based packed-block row.
        block: usize,
    },
    /// APU auxiliary columns violated their fixed layout.
    #[error("packed-block APU witness violated its typed layout")]
    Layout,
}

/// Joypad relation plus exact generic semantics for the modeled DMG APU state.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockDeviceApuRelation;

impl BlockDeviceApuWitness {
    /// Derives APU boundary decompositions and write predicates from packed blocks.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, BlockDeviceApuError> {
        let joypad = BlockDeviceJoypadWitness::from_blocks(blocks)?;
        let active_block_count = joypad.active_block_count();
        let mut auxiliary = (0..APU_AUX_COLUMN_COUNT)
            .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
            .collect::<Vec<_>>();
        for (block_index, block) in blocks.iter().enumerate() {
            let mut row = [0_u64; APU_AUX_COLUMN_COUNT];
            append_apu_row(&mut row, block, block_index)?;
            for (column, value) in auxiliary.iter_mut().zip(row) {
                column.push(value);
            }
        }
        for column in &mut auxiliary {
            column.resize(UNIFORM_ROW_COUNT, 0);
        }
        let mut columns = joypad.into_columns();
        columns.extend(auxiliary);
        if columns.len() != BLOCK_DEVICE_APU_COLUMN_COUNT {
            return Err(BlockDeviceApuError::Layout);
        }
        Ok(Self {
            columns,
            active_block_count,
        })
    }

    /// Returns every logical column in joypad-then-APU order.
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

impl UniformRelation for BlockDeviceApuRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-device-apu/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        for value in [2_610_u64, 5_717, 659, 1_678, 3_269, 7_395, 5] {
            statement.extend_from_slice(&value.to_le_bytes());
        }
        statement
    }

    fn column_count(&self) -> usize {
        BLOCK_DEVICE_APU_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        BLOCK_DEVICE_APU_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        BLOCK_DEVICE_APU_MAX_DEGREE
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != BLOCK_DEVICE_APU_COLUMN_COUNT
            || constraints.len() != BLOCK_DEVICE_APU_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        let joypad = row
            .get(..BLOCK_DEVICE_JOYPAD_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let auxiliary = row
            .get(APU_AUX_START..BLOCK_DEVICE_APU_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let (joypad_constraints, apu_constraints) =
            constraints.split_at_mut(BLOCK_DEVICE_JOYPAD_CONSTRAINT_COUNT);
        BlockDeviceJoypadRelation.evaluate(joypad, joypad_constraints)?;
        constrain_apu(joypad, auxiliary, apu_constraints)
    }
}

fn append_apu_row(
    row: &mut [u64],
    block: &BasicBlock,
    block_index: usize,
) -> Result<(), BlockDeviceApuError> {
    let before = block.initial_state().dmg_devices().apu();
    let after = block.final_state().dmg_devices().apu();
    let event = typed_device_event(block, block_index)?;
    validate_apu_transition(before, after, event, block_index)?;
    append_apu_state(row, false, before)?;
    append_apu_state(row, true, after)?;
    let value = event.map_or(0, |(_, tuple)| tuple.value);
    let apu_write = event.is_some_and(|(kind, tuple)| {
        kind == BusEventKind::DmgMmioWrite && (0xff10..=0xff3f).contains(&tuple.address)
    });
    let power_off = event.is_some_and(|(kind, tuple)| {
        kind == BusEventKind::DmgMmioWrite && tuple.address == 0xff26 && tuple.value & 0x80 == 0
    });
    let power_on = event.is_some_and(|(kind, tuple)| {
        kind == BusEventKind::DmgMmioWrite && tuple.address == 0xff26 && tuple.value & 0x80 != 0
    });
    set(row, POWER_OFF, u64::from(power_off))?;
    set(row, POWER_ON, u64::from(power_on))?;
    set(row, APU_WRITE, u64::from(apu_write))?;
    for channel in 0_u8..4 {
        let index = usize::from(channel);
        let dac_write = event.is_some_and(|(kind, tuple)| {
            kind == BusEventKind::DmgMmioWrite && tuple.address == dac_address(channel)
        });
        let trigger = event.is_some_and(|(kind, tuple)| {
            kind == BusEventKind::DmgMmioWrite
                && tuple.address == trigger_address(channel)
                && tuple.value & 0x80 != 0
        });
        set(
            row,
            AFTER_DAC_ENABLED_START + index,
            u64::from(dac_enabled(after, channel)),
        )?;
        set(row, DAC_WRITE_START + index, u64::from(dac_write))?;
        set(
            row,
            WRITTEN_DAC_ENABLED_START + index,
            u64::from(dac_enabled_value(value, channel)),
        )?;
        set(row, TRIGGER_START + index, u64::from(trigger))?;
    }
    Ok(())
}

fn typed_device_event(
    block: &BasicBlock,
    block_index: usize,
) -> Result<Option<(BusEventKind, zksm83_memory::BusTranscriptEvent)>, BlockDeviceApuError> {
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
                return Err(BlockDeviceApuError::InvalidTransition { block: block_index });
            }
            selected = Some((event.kind(), event.transcript_event()));
        }
    }
    Ok(selected)
}

fn validate_apu_transition(
    mut expected: DmgApuState,
    after: DmgApuState,
    event: Option<(BusEventKind, zksm83_memory::BusTranscriptEvent)>,
    block: usize,
) -> Result<(), BlockDeviceApuError> {
    if let Some((kind, tuple)) = event
        && (0xff10..=0xff3f).contains(&tuple.address)
    {
        let visible = expected
            .read(tuple.address)
            .ok_or(BlockDeviceApuError::InvalidTransition { block })?;
        if (kind == BusEventKind::DmgMmioRead && tuple.value != visible)
            || (kind == BusEventKind::DmgMmioWrite && tuple.before != visible)
        {
            return Err(BlockDeviceApuError::InvalidTransition { block });
        }
        if kind == BusEventKind::DmgMmioWrite {
            let prior = expected
                .write(tuple.address, tuple.value)
                .ok_or(BlockDeviceApuError::InvalidTransition { block })?;
            if prior != visible {
                return Err(BlockDeviceApuError::InvalidTransition { block });
            }
        }
    }
    if expected == after {
        Ok(())
    } else {
        Err(BlockDeviceApuError::InvalidTransition { block })
    }
}

fn append_apu_state(
    row: &mut [u64],
    after: bool,
    apu: DmgApuState,
) -> Result<(), BlockDeviceApuError> {
    for (pack, value) in [
        apu.control_low_pack(),
        apu.control_high_pack(),
        apu.mixer_pack(),
        apu.wave_low_pack(),
        apu.wave_high_pack(),
    ]
    .into_iter()
    .enumerate()
    {
        let start = pack_start(after, pack).map_err(|_| BlockDeviceApuError::Layout)?;
        append_bits(row, start, value, PACK_WIDTH)?;
    }
    Ok(())
}

fn constrain_apu(
    joypad: &[NativeField],
    auxiliary: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if auxiliary.len() != APU_AUX_COLUMN_COUNT
        || constraints.len() != APU_ADDITIONAL_CONSTRAINT_COUNT
    {
        return Err(UniformError::Shape);
    }
    let one = NativeField::from_u64(1);
    let block_active = block_metadata::block_active_value(joypad)?;
    let mut sink = ConstraintSink::new(constraints);
    for column in auxiliary.iter().copied() {
        sink.push(column * (column - one))?;
        sink.push((one - block_active) * column)?;
    }
    let frontend = joypad
        .get(..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let boundary = frontend
        .get(BLOCK_ROUTING_COLUMN_COUNT..BLOCK_CONTROL_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    constrain_packs(boundary, auxiliary, &mut sink)?;
    constrain_storage_masks(auxiliary, &mut sink)?;
    constrain_powered_off_states(auxiliary, &mut sink)?;
    constrain_bus_values(joypad, auxiliary, &mut sink)?;
    constrain_event_witnesses(joypad, auxiliary, &mut sink)?;
    constrain_control_updates(joypad, auxiliary, &mut sink)?;
    constrain_wave_updates(joypad, auxiliary, &mut sink)?;
    constrain_master_status(auxiliary, &mut sink)?;
    sink.finish()
}

fn constrain_packs(
    boundary: &[NativeField],
    auxiliary: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for pack in 0..PACK_COUNT {
        let scalar = pack_state_index(pack)?;
        for after in [false, true] {
            sink.push(
                device_state_value(boundary, after, scalar)?
                    - packed_bits(auxiliary, pack_start(after, pack)?, PACK_WIDTH)?,
            )?;
        }
    }
    Ok(())
}

fn constrain_storage_masks(
    auxiliary: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for address in 0x10_u8..=0x26 {
        let mask = apu_read_mask(0xff00 | u16::from(address));
        for after in [false, true] {
            let start = storage_bit_start(address, after)?;
            for bit in 0..8 {
                if mask >> bit & 1 == 1 {
                    sink.push(value(auxiliary, start + bit)?)?;
                }
            }
        }
    }
    for after in [false, true] {
        let start = pack_start(after, 2)?
            .checked_add(MIXER_UNUSED_BYTE * 8)
            .ok_or(UniformError::Shape)?;
        for bit in 0..8 {
            sink.push(value(auxiliary, start + bit)?)?;
        }
    }
    Ok(())
}

fn constrain_powered_off_states(
    auxiliary: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    for after in [false, true] {
        let power = state_bit(auxiliary, after, 2, 55)?;
        for address in 0x10_u8..=0x25 {
            if !is_length_register(address) {
                sink.push(
                    (one - power) * packed_bits(auxiliary, storage_bit_start(address, after)?, 8)?,
                )?;
            }
        }
        for channel in 0..4 {
            sink.push((one - power) * state_bit(auxiliary, after, 2, 48 + channel)?)?;
        }
    }
    Ok(())
}

fn constrain_bus_values(
    joypad: &[NativeField],
    auxiliary: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let read = mmio_read_selector_value(joypad)?;
    let write = mmio_write_selector_value(joypad)?;
    let mut selected = NativeField::from_u64(0);
    let mut expected = NativeField::from_u64(0);
    for address in 0x10_u8..=0x3f {
        let selector = mmio_address_selector_value(joypad, address)?;
        selected += selector;
        expected += selector * visible_byte(auxiliary, address)?;
    }
    sink.push(read * (selected * mmio_io_value(joypad)? - expected))?;
    sink.push(write * (selected * mmio_io_before_value(joypad)? - expected))
}

fn constrain_event_witnesses(
    joypad: &[NativeField],
    auxiliary: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let write = mmio_write_selector_value(joypad)?;
    let mut apu_address = NativeField::from_u64(0);
    for address in 0x10_u8..=0x3f {
        apu_address += mmio_address_selector_value(joypad, address)?;
    }
    sink.push(value(auxiliary, APU_WRITE)? - write * apu_address)?;
    let power = mmio_io_value_bit(joypad, 7)?;
    let power_write = write * mmio_address_selector_value(joypad, 0x26)?;
    sink.push(value(auxiliary, POWER_OFF)? - power_write * (one - power))?;
    sink.push(value(auxiliary, POWER_ON)? - power_write * power)?;
    for channel in 0_u8..4 {
        let index = usize::from(channel);
        let dac_write = value(auxiliary, DAC_WRITE_START + index)?;
        let selected_dac = value(auxiliary, APU_WRITE)?
            * mmio_address_selector_value(joypad, low_address(dac_address(channel))?)?;
        sink.push(dac_write - selected_dac)?;
        sink.push(
            value(auxiliary, WRITTEN_DAC_ENABLED_START + index)?
                - written_dac_enabled(joypad, channel)?,
        )?;
        let selected_trigger = value(auxiliary, APU_WRITE)?
            * mmio_address_selector_value(joypad, low_address(trigger_address(channel))?)?;
        sink.push(value(auxiliary, TRIGGER_START + index)? - selected_trigger * power)?;
        sink.push(
            value(auxiliary, AFTER_DAC_ENABLED_START + index)?
                - dac_enabled_from_pack(auxiliary, channel, true)?,
        )?;
    }
    Ok(())
}

fn constrain_control_updates(
    joypad: &[NativeField],
    auxiliary: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let powered = state_bit(auxiliary, false, 2, 55)?;
    let power_off = value(auxiliary, POWER_OFF)?;
    let apu_write = value(auxiliary, APU_WRITE)?;
    for address in 0x10_u8..=0x25 {
        let before = packed_bits(auxiliary, storage_bit_start(address, false)?, 8)?;
        let after = packed_bits(auxiliary, storage_bit_start(address, true)?, 8)?;
        let permission = if is_length_register(address) {
            one
        } else {
            powered
        };
        let selected = apu_write * mmio_address_selector_value(joypad, address)?;
        let written = written_stored_byte(joypad, address)?;
        sink.push(
            after - (one - power_off) * (before + permission * selected * (written - before)),
        )?;
    }
    Ok(())
}

fn constrain_wave_updates(
    joypad: &[NativeField],
    auxiliary: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let apu_write = value(auxiliary, APU_WRITE)?;
    for address in 0x30_u8..=0x3f {
        let before = packed_bits(auxiliary, storage_bit_start(address, false)?, 8)?;
        let after = packed_bits(auxiliary, storage_bit_start(address, true)?, 8)?;
        let selected = apu_write * mmio_address_selector_value(joypad, address)?;
        sink.push(after - before - selected * (mmio_io_value(joypad)? - before))?;
    }
    Ok(())
}

fn constrain_master_status(
    auxiliary: &[NativeField],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let before_power = state_bit(auxiliary, false, 2, 55)?;
    let after_power = state_bit(auxiliary, true, 2, 55)?;
    let off = value(auxiliary, POWER_OFF)?;
    let on = value(auxiliary, POWER_ON)?;
    sink.push(after_power - (one - off) * (before_power + on * (one - before_power)))?;
    for channel in 0..4 {
        let before = state_bit(auxiliary, false, 2, 48 + channel)?;
        let after = state_bit(auxiliary, true, 2, 48 + channel)?;
        let dac_write = value(auxiliary, DAC_WRITE_START + channel)?;
        let written = value(auxiliary, WRITTEN_DAC_ENABLED_START + channel)?;
        let disabled = dac_write * (one - written);
        let retained = before * (one - disabled);
        let activation = value(auxiliary, TRIGGER_START + channel)?
            * value(auxiliary, AFTER_DAC_ENABLED_START + channel)?;
        sink.push(after - (one - off) * (retained + (one - retained) * activation))?;
    }
    Ok(())
}

fn visible_byte(row: &[NativeField], address: u8) -> Result<NativeField, UniformError> {
    match address {
        0x10..=0x26 => Ok(packed_bits(row, storage_bit_start(address, false)?, 8)?
            + NativeField::from_u64(u64::from(apu_read_mask(0xff00 | u16::from(address))))),
        0x27..=0x2f => Ok(NativeField::from_u64(0xff)),
        0x30..=0x3f => packed_bits(row, storage_bit_start(address, false)?, 8),
        _ => Err(UniformError::Shape),
    }
}

fn written_stored_byte(joypad: &[NativeField], address: u8) -> Result<NativeField, UniformError> {
    let mask = apu_read_mask(0xff00 | u16::from(address));
    let mut packed = NativeField::from_u64(0);
    let mut power = NativeField::from_u64(1);
    for bit in 0..8 {
        if mask >> bit & 1 == 0 {
            packed += power * mmio_io_value_bit(joypad, bit)?;
        }
        power += power;
    }
    Ok(packed)
}

fn dac_enabled_from_pack(
    row: &[NativeField],
    channel: u8,
    after: bool,
) -> Result<NativeField, UniformError> {
    let address = low_address(dac_address(channel))?;
    let (first, width) = if channel == 2 { (7, 1) } else { (3, 5) };
    any_bits(row, storage_bit_start(address, after)? + first, width)
}

fn written_dac_enabled(joypad: &[NativeField], channel: u8) -> Result<NativeField, UniformError> {
    let (first, width) = if channel == 2 { (7, 1) } else { (3, 5) };
    let one = NativeField::from_u64(1);
    let mut zero = one;
    for bit in first..first + width {
        zero *= one - mmio_io_value_bit(joypad, bit)?;
    }
    Ok(one - zero)
}

fn any_bits(row: &[NativeField], start: usize, width: usize) -> Result<NativeField, UniformError> {
    let one = NativeField::from_u64(1);
    let mut zero = one;
    for bit in 0..width {
        zero *= one - value(row, start.checked_add(bit).ok_or(UniformError::Shape)?)?;
    }
    Ok(one - zero)
}

fn storage_bit_start(address: u8, after: bool) -> Result<usize, UniformError> {
    let (pack, byte) = match address {
        0x10..=0x17 => (0, usize::from(address - 0x10)),
        0x18..=0x1f => (1, usize::from(address - 0x18)),
        0x20..=0x26 => (2, usize::from(address - 0x20)),
        0x30..=0x37 => (3, usize::from(address - 0x30)),
        0x38..=0x3f => (4, usize::from(address - 0x38)),
        _ => return Err(UniformError::Shape),
    };
    pack_start(after, pack)?
        .checked_add(byte.checked_mul(8).ok_or(UniformError::Shape)?)
        .ok_or(UniformError::Shape)
}

fn pack_start(after: bool, pack: usize) -> Result<usize, UniformError> {
    if pack >= PACK_COUNT {
        return Err(UniformError::Shape);
    }
    let base = if after {
        AFTER_BITS_START
    } else {
        BEFORE_BITS_START
    };
    base.checked_add(pack.checked_mul(PACK_WIDTH).ok_or(UniformError::Shape)?)
        .ok_or(UniformError::Shape)
}

fn pack_state_index(pack: usize) -> Result<usize, UniformError> {
    match pack {
        0 => Ok(STATE_APU_CONTROL_LOW_PACK_INDEX),
        1 => Ok(STATE_APU_CONTROL_HIGH_PACK_INDEX),
        2 => Ok(STATE_APU_MIXER_PACK_INDEX),
        3 => Ok(STATE_APU_WAVE_LOW_PACK_INDEX),
        4 => Ok(STATE_APU_WAVE_HIGH_PACK_INDEX),
        _ => Err(UniformError::Shape),
    }
}

fn state_bit(
    row: &[NativeField],
    after: bool,
    pack: usize,
    bit: usize,
) -> Result<NativeField, UniformError> {
    if bit >= PACK_WIDTH {
        return Err(UniformError::Shape);
    }
    value(
        row,
        pack_start(after, pack)?
            .checked_add(bit)
            .ok_or(UniformError::Shape)?,
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

fn append_bits(
    row: &mut [u64],
    start: usize,
    packed: u64,
    width: usize,
) -> Result<(), BlockDeviceApuError> {
    for bit in 0..width {
        set(
            row,
            start.checked_add(bit).ok_or(BlockDeviceApuError::Layout)?,
            packed >> bit & 1,
        )?;
    }
    Ok(())
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), BlockDeviceApuError> {
    *row.get_mut(index).ok_or(BlockDeviceApuError::Layout)? = value;
    Ok(())
}

fn value(row: &[NativeField], index: usize) -> Result<NativeField, UniformError> {
    row.get(index).copied().ok_or(UniformError::Shape)
}

fn low_address(address: u16) -> Result<u8, UniformError> {
    u8::try_from(address & 0x00ff).map_err(|_| UniformError::Shape)
}

const fn is_length_register(address: u8) -> bool {
    matches!(address, 0x11 | 0x16 | 0x1b | 0x20)
}

const fn dac_address(channel: u8) -> u16 {
    match channel {
        0 => 0xff12,
        1 => 0xff17,
        2 => 0xff1a,
        _ => 0xff21,
    }
}

const fn trigger_address(channel: u8) -> u16 {
    match channel {
        0 => 0xff14,
        1 => 0xff19,
        2 => 0xff1e,
        _ => 0xff23,
    }
}

fn dac_enabled(apu: DmgApuState, channel: u8) -> bool {
    apu.read(dac_address(channel))
        .is_some_and(|value| dac_enabled_value(value, channel))
}

const fn dac_enabled_value(value: u8, channel: u8) -> bool {
    if channel == 2 {
        value & 0x80 != 0
    } else {
        value & 0xf8 != 0
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
    use crate::{
        block_test_support::{first_device_io_block_index, flip_witness_bit},
        validate_uniform_witness,
    };

    #[test]
    fn apu_power_storage_trigger_and_wave_writes_are_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let program = [
            0x3e, 0x00, 0xea, 0x26, 0xff, 0x3e, 0xc0, 0xea, 0x11, 0xff, 0x3e, 0xff, 0xea, 0x30,
            0xff, 0x3e, 0x80, 0xea, 0x26, 0xff, 0x3e, 0xf0, 0xea, 0x21, 0xff, 0x3e, 0x80, 0xea,
            0x23, 0xff,
        ];
        let blocks = fixture(&program, 12)?;
        let witness = BlockDeviceApuWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&BlockDeviceApuRelation, witness.columns())?;
        let device_row = first_device_io_block_index(&blocks)?;
        let mut mutated = witness.columns().to_vec();
        flip_witness_bit(&mut mutated, APU_AUX_START + BEFORE_BITS_START, device_row)?;
        assert!(validate_uniform_witness(&BlockDeviceApuRelation, &mutated).is_err());
        Ok(())
    }

    fn fixture(program: &[u8], steps: u64) -> Result<Vec<BasicBlock>, Box<dyn std::error::Error>> {
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
            Vec::new(),
            rom.root(),
            memory.root(),
        )?;
        Ok(pack_witness_basic_blocks(builder.run_exact_steps(steps)?)?)
    }
}
