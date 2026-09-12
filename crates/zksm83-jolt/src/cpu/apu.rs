//! APU register-pack ranges and exact CPU-visible FF10-FF3F values.

use akita_pcs::Ring;
use zksm83_core::apu_read_mask;

use super::{
    BUS_BEFORE_OFFSET, BUS_VALUE_OFFSET, ConstraintSink, RowView, bit_selector, boolean, bus_field,
    bus_kind_bits, packed_bits,
};
use crate::{
    NativeField, TRACE_BUS_ADDRESS_BITS_START, TRACE_BUS_SLOTS, UniformError,
    trace::device::{
        TRACE_AFTER_APU_CONTROL_HIGH_BITS_START, TRACE_AFTER_APU_CONTROL_LOW_BITS_START,
        TRACE_AFTER_APU_MIXER_BITS_START, TRACE_AFTER_APU_WAVE_HIGH_BITS_START,
        TRACE_AFTER_APU_WAVE_LOW_BITS_START, TRACE_APU_AFTER_DAC_ENABLED_START,
        TRACE_APU_DAC_WRITE_START, TRACE_APU_POWER_OFF, TRACE_APU_POWER_ON,
        TRACE_APU_TRIGGER_START, TRACE_APU_WRITTEN_DAC_ENABLED_START,
        TRACE_BEFORE_APU_CONTROL_HIGH_BITS_START, TRACE_BEFORE_APU_CONTROL_LOW_BITS_START,
        TRACE_BEFORE_APU_MIXER_BITS_START, TRACE_BEFORE_APU_WAVE_HIGH_BITS_START,
        TRACE_BEFORE_APU_WAVE_LOW_BITS_START,
    },
};

const STATE_APU_CONTROL_LOW_PACK: usize = 31;
const STATE_APU_CONTROL_HIGH_PACK: usize = 32;
const STATE_APU_MIXER_PACK: usize = 33;
const STATE_APU_WAVE_LOW_PACK: usize = 34;
const STATE_APU_WAVE_HIGH_PACK: usize = 35;

pub(super) fn constrain_apu(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_packs(view, sink)?;
    constrain_storage_masks(view, sink)?;
    constrain_powered_off_state(view, sink)?;
    constrain_bus_values(view, sink).and_then(|()| constrain_transitions(view, sink))
}

fn constrain_packs(view: &RowView<'_>, sink: &mut ConstraintSink<'_>) -> Result<(), UniformError> {
    for (state, before_start, after_start) in [
        (
            STATE_APU_CONTROL_LOW_PACK,
            TRACE_BEFORE_APU_CONTROL_LOW_BITS_START,
            TRACE_AFTER_APU_CONTROL_LOW_BITS_START,
        ),
        (
            STATE_APU_CONTROL_HIGH_PACK,
            TRACE_BEFORE_APU_CONTROL_HIGH_BITS_START,
            TRACE_AFTER_APU_CONTROL_HIGH_BITS_START,
        ),
        (
            STATE_APU_MIXER_PACK,
            TRACE_BEFORE_APU_MIXER_BITS_START,
            TRACE_AFTER_APU_MIXER_BITS_START,
        ),
        (
            STATE_APU_WAVE_LOW_PACK,
            TRACE_BEFORE_APU_WAVE_LOW_BITS_START,
            TRACE_AFTER_APU_WAVE_LOW_BITS_START,
        ),
        (
            STATE_APU_WAVE_HIGH_PACK,
            TRACE_BEFORE_APU_WAVE_HIGH_BITS_START,
            TRACE_AFTER_APU_WAVE_HIGH_BITS_START,
        ),
    ] {
        for start in [before_start, after_start] {
            for bit in 0..64 {
                sink.push(boolean(view.value(start + bit)?))?;
            }
        }
        sink.push(view.before(state)? - packed_bits(view, before_start, 64)?)?;
        sink.push(view.after(state)? - packed_bits(view, after_start, 64)?)?;
    }
    Ok(())
}

fn constrain_storage_masks(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for address in 0x10_u8..=0x26 {
        let mask = apu_read_mask(0xff00 | u16::from(address));
        for after in [false, true] {
            let (start, byte) = storage_location(address, after)?;
            for bit in 0..8 {
                if mask & (1 << bit) != 0 {
                    sink.push(view.value(start + byte * 8 + bit)?)?;
                }
            }
        }
    }
    Ok(())
}

fn constrain_powered_off_state(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let power = view.value(TRACE_BEFORE_APU_MIXER_BITS_START + 55)?;
    for address in 0x10_u8..=0x25 {
        if !is_length_register(address) {
            let (start, byte) = storage_location(address, false)?;
            sink.push((one - power) * packed_bits(view, start + byte * 8, 8)?)?;
        }
    }
    for channel in 0..4 {
        sink.push((one - power) * view.value(TRACE_BEFORE_APU_MIXER_BITS_START + 48 + channel)?)?;
    }
    Ok(())
}

fn constrain_bus_values(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for slot in 0..TRACE_BUS_SLOTS {
        let read = bus_kind(view, slot, 11)?;
        let write = bus_kind(view, slot, 12)?;
        let mut selected = NativeField::from_u64(0);
        let mut expected = NativeField::from_u64(0);
        for address in 0x10_u8..=0x3f {
            let selector = low_selector(view, slot, address)?;
            selected += selector;
            expected += selector * visible_byte(view, address)?;
        }
        sink.push(read * (selected * bus_field(view, slot, BUS_VALUE_OFFSET)? - expected))?;
        sink.push(write * (selected * bus_field(view, slot, BUS_BEFORE_OFFSET)? - expected))?;
    }
    Ok(())
}

fn visible_byte(view: &RowView<'_>, address: u8) -> Result<NativeField, UniformError> {
    match address {
        0x10..=0x26 => {
            let (start, byte) = storage_location(address, false)?;
            Ok(packed_bits(view, start + byte * 8, 8)?
                + NativeField::from_u64(u64::from(apu_read_mask(0xff00 | u16::from(address)))))
        }
        0x27..=0x2f => Ok(NativeField::from_u64(0xff)),
        0x30..=0x37 => packed_bits(
            view,
            TRACE_BEFORE_APU_WAVE_LOW_BITS_START + usize::from(address - 0x30) * 8,
            8,
        ),
        0x38..=0x3f => packed_bits(
            view,
            TRACE_BEFORE_APU_WAVE_HIGH_BITS_START + usize::from(address - 0x38) * 8,
            8,
        ),
        _ => Err(UniformError::Shape),
    }
}

fn storage_location(address: u8, after: bool) -> Result<(usize, usize), UniformError> {
    match address {
        0x10..=0x17 => Ok((
            if after {
                TRACE_AFTER_APU_CONTROL_LOW_BITS_START
            } else {
                TRACE_BEFORE_APU_CONTROL_LOW_BITS_START
            },
            usize::from(address - 0x10),
        )),
        0x18..=0x1f => Ok((
            if after {
                TRACE_AFTER_APU_CONTROL_HIGH_BITS_START
            } else {
                TRACE_BEFORE_APU_CONTROL_HIGH_BITS_START
            },
            usize::from(address - 0x18),
        )),
        0x20..=0x26 => Ok((
            if after {
                TRACE_AFTER_APU_MIXER_BITS_START
            } else {
                TRACE_BEFORE_APU_MIXER_BITS_START
            },
            usize::from(address - 0x20),
        )),
        _ => Err(UniformError::Shape),
    }
}

fn constrain_transitions(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_event_witnesses(view, sink)?;
    constrain_dac_state(view, sink)?;
    constrain_control_updates(view, sink)?;
    constrain_wave_updates(view, sink)?;
    constrain_master_status(view, sink)
}

fn constrain_event_witnesses(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for column in TRACE_APU_POWER_OFF..TRACE_APU_TRIGGER_START + 4 {
        sink.push(boolean(view.value(column)?))?;
    }
    let mut power_off = NativeField::from_u64(0);
    let mut power_on = NativeField::from_u64(0);
    for slot in 0..TRACE_BUS_SLOTS {
        let selected = write_selector(view, slot, 0x26)?;
        let power = view.value(crate::TRACE_BUS_VALUE_BITS_START + slot * 8 + 7)?;
        power_off += selected * (NativeField::from_u64(1) - power);
        power_on += selected * power;
    }
    sink.push(view.value(TRACE_APU_POWER_OFF)? - power_off)?;
    sink.push(view.value(TRACE_APU_POWER_ON)? - power_on)?;
    for channel in 0_u8..4 {
        constrain_channel_events(view, sink, channel)?;
    }
    Ok(())
}

fn constrain_channel_events(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    channel: u8,
) -> Result<(), UniformError> {
    let index = usize::from(channel);
    let mut dac_write = NativeField::from_u64(0);
    let mut written_enabled = NativeField::from_u64(0);
    let mut trigger = NativeField::from_u64(0);
    for slot in 0..TRACE_BUS_SLOTS {
        let dac = write_selector(view, slot, dac_address(channel))?;
        let enabled = written_dac_enabled(view, slot, channel)?;
        dac_write += dac;
        written_enabled += dac * enabled;
        trigger += write_selector(view, slot, trigger_address(channel))?
            * view.value(crate::TRACE_BUS_VALUE_BITS_START + slot * 8 + 7)?;
    }
    sink.push(view.value(TRACE_APU_DAC_WRITE_START + index)? - dac_write)?;
    sink.push(view.value(TRACE_APU_WRITTEN_DAC_ENABLED_START + index)? - written_enabled)?;
    sink.push(view.value(TRACE_APU_TRIGGER_START + index)? - trigger)
}

fn constrain_dac_state(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let powered = view.value(TRACE_BEFORE_APU_MIXER_BITS_START + 55)?;
    let power_off = view.value(TRACE_APU_POWER_OFF)?;
    for channel in 0_u8..4 {
        let index = usize::from(channel);
        let before = dac_enabled_from_pack(view, channel, false)?;
        let after = view.value(TRACE_APU_AFTER_DAC_ENABLED_START + index)?;
        let write = view.value(TRACE_APU_DAC_WRITE_START + index)?;
        let written = view.value(TRACE_APU_WRITTEN_DAC_ENABLED_START + index)?;
        let expected = (one - power_off) * (before + write * powered * (written - before));
        sink.push(after - expected)?;
        sink.push(after - dac_enabled_from_pack(view, channel, true)?)?;
    }
    Ok(())
}

fn constrain_control_updates(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let powered = view.value(TRACE_BEFORE_APU_MIXER_BITS_START + 55)?;
    let power_off = view.value(TRACE_APU_POWER_OFF)?;
    for address in 0x10_u8..=0x25 {
        let (before_start, before_byte) = storage_location(address, false)?;
        let (after_start, after_byte) = storage_location(address, true)?;
        let before = packed_bits(view, before_start + before_byte * 8, 8)?;
        let after = packed_bits(view, after_start + after_byte * 8, 8)?;
        let permission = if is_length_register(address) {
            one
        } else {
            powered
        };
        let mut delta = NativeField::from_u64(0);
        for slot in 0..TRACE_BUS_SLOTS {
            let write = write_selector(view, slot, address)?;
            delta += write * (written_stored_byte(view, slot, address)? - before);
        }
        sink.push(after - (one - power_off) * (before + permission * delta))?;
    }
    Ok(())
}

fn constrain_wave_updates(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for address in 0x30_u8..=0x3f {
        let (before_start, after_start, byte) = if address <= 0x37 {
            (
                TRACE_BEFORE_APU_WAVE_LOW_BITS_START,
                TRACE_AFTER_APU_WAVE_LOW_BITS_START,
                usize::from(address - 0x30),
            )
        } else {
            (
                TRACE_BEFORE_APU_WAVE_HIGH_BITS_START,
                TRACE_AFTER_APU_WAVE_HIGH_BITS_START,
                usize::from(address - 0x38),
            )
        };
        let before = packed_bits(view, before_start + byte * 8, 8)?;
        let after = packed_bits(view, after_start + byte * 8, 8)?;
        let mut delta = NativeField::from_u64(0);
        for slot in 0..TRACE_BUS_SLOTS {
            let write = write_selector(view, slot, address)?;
            delta += write * (bus_field(view, slot, BUS_VALUE_OFFSET)? - before);
        }
        sink.push(after - before - delta)?;
    }
    Ok(())
}

fn constrain_master_status(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let before_power = view.value(TRACE_BEFORE_APU_MIXER_BITS_START + 55)?;
    let after_power = view.value(TRACE_AFTER_APU_MIXER_BITS_START + 55)?;
    let off = view.value(TRACE_APU_POWER_OFF)?;
    let on = view.value(TRACE_APU_POWER_ON)?;
    sink.push(after_power - (one - off) * (before_power + on * (one - before_power)))?;
    for channel in 0..4 {
        let before = view.value(TRACE_BEFORE_APU_MIXER_BITS_START + 48 + channel)?;
        let after = view.value(TRACE_AFTER_APU_MIXER_BITS_START + 48 + channel)?;
        let dac_write = view.value(TRACE_APU_DAC_WRITE_START + channel)?;
        let written = view.value(TRACE_APU_WRITTEN_DAC_ENABLED_START + channel)?;
        let disabled = dac_write * (one - written);
        let retained = before * (one - disabled);
        let activation = view.value(TRACE_APU_TRIGGER_START + channel)?
            * view.value(TRACE_APU_AFTER_DAC_ENABLED_START + channel)?;
        sink.push(after - (one - off) * (retained + (one - retained) * activation))?;
    }
    Ok(())
}

fn dac_enabled_from_pack(
    view: &RowView<'_>,
    channel: u8,
    after: bool,
) -> Result<NativeField, UniformError> {
    let (address, first_bit, width) = match channel {
        0 => (0x12, 3, 5),
        1 => (0x17, 3, 5),
        2 => (0x1a, 7, 1),
        _ => (0x21, 3, 5),
    };
    let (start, byte) = storage_location(address, after)?;
    any_bits(view, start + byte * 8 + first_bit, width)
}

fn written_dac_enabled(
    view: &RowView<'_>,
    slot: usize,
    channel: u8,
) -> Result<NativeField, UniformError> {
    let (first_bit, width) = if channel == 2 { (7, 1) } else { (3, 5) };
    any_bits(
        view,
        crate::TRACE_BUS_VALUE_BITS_START + slot * 8 + first_bit,
        width,
    )
}

fn written_stored_byte(
    view: &RowView<'_>,
    slot: usize,
    address: u8,
) -> Result<NativeField, UniformError> {
    let mask = apu_read_mask(0xff00 | u16::from(address));
    let mut value = NativeField::from_u64(0);
    for bit in 0..8 {
        if mask & (1 << bit) == 0 {
            value += NativeField::from_u64(1 << bit)
                * view.value(crate::TRACE_BUS_VALUE_BITS_START + slot * 8 + bit)?;
        }
    }
    Ok(value)
}

fn any_bits(view: &RowView<'_>, start: usize, width: usize) -> Result<NativeField, UniformError> {
    let one = NativeField::from_u64(1);
    let mut zero = one;
    for bit in 0..width {
        zero *= one - view.value(start + bit)?;
    }
    Ok(one - zero)
}

const fn is_length_register(address: u8) -> bool {
    matches!(address, 0x11 | 0x16 | 0x1b | 0x20)
}

const fn dac_address(channel: u8) -> u8 {
    match channel {
        0 => 0x12,
        1 => 0x17,
        2 => 0x1a,
        _ => 0x21,
    }
}

const fn trigger_address(channel: u8) -> u8 {
    match channel {
        0 => 0x14,
        1 => 0x19,
        2 => 0x1e,
        _ => 0x23,
    }
}

fn write_selector(
    view: &RowView<'_>,
    slot: usize,
    address: u8,
) -> Result<NativeField, UniformError> {
    Ok(bus_kind(view, slot, 12)? * low_selector(view, slot, address)?)
}

fn low_selector(
    view: &RowView<'_>,
    slot: usize,
    expected: u8,
) -> Result<NativeField, UniformError> {
    let start = TRACE_BUS_ADDRESS_BITS_START + slot * 16;
    let one = NativeField::from_u64(1);
    (0..8).try_fold(one, |selector, bit| {
        let actual = view.value(start + bit)?;
        Ok(if (expected >> bit) & 1 == 1 {
            selector * actual
        } else {
            selector * (one - actual)
        })
    })
}

fn bus_kind(view: &RowView<'_>, slot: usize, code: u8) -> Result<NativeField, UniformError> {
    bit_selector(bus_kind_bits(view, slot)?, code)
}
