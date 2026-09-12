//! Interrupt-mask, priority, and HALT-selection identities.

use akita_pcs::Ring;

use super::{
    BUS_ADDRESS_OFFSET, BUS_VALUE_OFFSET, ConstraintSink, DMA_BYTE_MODE, HALT_IDLE_MODE,
    INSTRUCTION_MODE, RowView, STATE_IME, STATE_RUN_STATE, bit_selector, bus_field, bus_kind_bits,
    operation_selector, packed_bits, zero_from_bits,
};
use crate::{
    NativeField, TRACE_ACTIVE, TRACE_AFTER_DMA_BITS_START, TRACE_AFTER_INTERRUPT_ENABLE_BITS_START,
    TRACE_AFTER_INTERRUPT_REQUEST_BITS_START, TRACE_BEFORE_DMA_BITS_START,
    TRACE_BEFORE_INTERRUPT_ENABLE_BITS_START, TRACE_BEFORE_INTERRUPT_REQUEST_BITS_START,
    TRACE_BUS_ADDRESS_BITS_START, TRACE_BUS_SLOTS, TRACE_INTERRUPT_START, TRACE_PENDING_INTERRUPT,
    UniformError,
    trace::device::{
        TRACE_AFTER_DMA_REMAINING_BITS_START, TRACE_BEFORE_DMA_REMAINING_BITS_START,
        TRACE_BEFORE_DMG_LOW_BITS_START, TRACE_CPU_OAM_ACCESS_START, TRACE_PPU_DOT_LT_80,
        TRACE_PPU_DOT_LT_252, TRACE_PPU_VBLANK, TRACE_TIMER_M_CYCLE_ACTIVE_START,
    },
};

const INTERRUPT_BITS: usize = 5;
const HALT_UNTIL_VBLANK_MODE: usize = 2;
const BLUE_SOUND_WAIT_MODE: usize = 3;
const BLUE_DELAY_LOOP_MODE: usize = 4;
const BLUE_DMA_WAIT_MODE: usize = 5;
const HALT_WAKE_MODE: usize = 7;
const INTERRUPT_MODE: usize = 8;
const STATE_INTERRUPT_REQUEST: usize = 21;
const STATE_INTERRUPT_ENABLE: usize = 22;
const STATE_DMA_PACK: usize = 37;
const DMA_NEAR_END_INDICES: [u8; 5] = [155, 156, 157, 158, 159];

pub(super) fn constrain_interrupt_control(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_interrupt_masks(view, sink)?;
    constrain_dma_state(view, sink)?;
    constrain_device_bus_access(view, sink)?;
    let pending = pending_bits(view)?;
    let pending_any = view.value(TRACE_PENDING_INTERRUPT)?;
    sink.push(pending_any * (pending_any - NativeField::from_u64(1)))?;
    sink.push(pending_any - any(&pending))?;
    constrain_priority(view, sink, &pending)?;
    constrain_mode_selection(view, sink, pending_any)
}

fn constrain_device_bus_access(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let dma_active = view.value(TRACE_BEFORE_DMA_BITS_START + 16)?;
    let lcd_enabled = view.value(TRACE_BEFORE_DMG_LOW_BITS_START + 39)?;
    let visible = one - view.value(TRACE_PPU_VBLANK)?;
    let mode_three = lcd_enabled
        * visible
        * (one - view.value(TRACE_PPU_DOT_LT_80)?)
        * view.value(TRACE_PPU_DOT_LT_252)?;
    let mode_two_or_three = lcd_enabled * visible * view.value(TRACE_PPU_DOT_LT_252)?;
    for slot in 0..TRACE_BUS_SLOTS {
        let cpu = cpu_bus_selector(view, slot)?;
        constrain_dma_cpu_access(view, sink, slot, cpu, dma_active)?;
        let address = TRACE_BUS_ADDRESS_BITS_START + slot * 16;
        let vram = view.value(address + 15)?
            * (one - view.value(address + 14)?)
            * (one - view.value(address + 13)?);
        let oam = view.value(TRACE_CPU_OAM_ACCESS_START + slot)?;
        sink.push(oam * (oam - one))?;
        sink.push(oam - oam_address_selector(view, slot)?)?;
        sink.push(cpu * mode_three * vram)?;
        sink.push(cpu * mode_two_or_three * oam)?;
    }
    Ok(())
}

fn constrain_dma_cpu_access(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    slot: usize,
    cpu: NativeField,
    dma_active: NativeField,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let address = TRACE_BUS_ADDRESS_BITS_START + slot * 16;
    for bit in 8..16 {
        sink.push(dma_active * cpu * (one - view.value(address + bit)?))?;
    }
    sink.push(dma_active * cpu * (one - view.value(address + 7)?))?;
    sink.push(dma_active * cpu * fixed_byte_selector(view, address, 0xff)?)
}

fn oam_address_selector(view: &RowView<'_>, slot: usize) -> Result<NativeField, UniformError> {
    let one = NativeField::from_u64(1);
    let start = TRACE_BUS_ADDRESS_BITS_START + slot * 16;
    let mut high_fe = one - view.value(start + 8)?;
    for bit in 9..16 {
        high_fe *= view.value(start + bit)?;
    }
    let upper_low = view.value(start + 7)? * or(view.value(start + 6)?, view.value(start + 5)?);
    Ok(high_fe * (one - upper_low))
}

fn cpu_bus_selector(view: &RowView<'_>, slot: usize) -> Result<NativeField, UniformError> {
    let mut selected = NativeField::from_u64(0);
    for code in 1..=15 {
        selected += bus_kind(view, slot, code)?;
    }
    Ok(selected)
}

fn or(left: NativeField, right: NativeField) -> NativeField {
    left + right - left * right
}

fn constrain_dma_state(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    for start in [TRACE_BEFORE_DMA_BITS_START, TRACE_AFTER_DMA_BITS_START] {
        for bit in 0..32 {
            let value = view.value(start + bit)?;
            sink.push(value * (value - one))?;
        }
        for bit in 17..24 {
            sink.push(view.value(start + bit)?)?;
        }
    }
    sink.push(view.before(STATE_DMA_PACK)? - packed_bits(view, TRACE_BEFORE_DMA_BITS_START, 32)?)?;
    sink.push(view.after(STATE_DMA_PACK)? - packed_bits(view, TRACE_AFTER_DMA_BITS_START, 32)?)?;
    constrain_dma_snapshot(
        view,
        sink,
        TRACE_BEFORE_DMA_BITS_START,
        TRACE_BEFORE_DMA_REMAINING_BITS_START,
    )?;
    constrain_dma_snapshot(
        view,
        sink,
        TRACE_AFTER_DMA_BITS_START,
        TRACE_AFTER_DMA_REMAINING_BITS_START,
    )?;
    constrain_dma_general_transition(view, sink)?;
    constrain_dma_priority_and_copy(view, sink)?;
    constrain_dma_wait_pack(view, sink)
}

fn constrain_dma_snapshot(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    pack_start: usize,
    remaining_start: usize,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    for bit in 0..8 {
        let value = view.value(remaining_start + bit)?;
        sink.push(value * (value - one))?;
    }
    let index = packed_bits(view, pack_start + 8, 8)?;
    let active = view.value(pack_start + 16)?;
    let owed = packed_bits(view, pack_start + 24, 8)?;
    let remaining = packed_bits(view, remaining_start, 8)?;
    sink.push(index + owed + remaining - NativeField::from_u64(160))?;
    sink.push(active * fixed_byte_selector(view, pack_start + 8, 160)?)?;
    let owed_zero = zero_from_bits(view, pack_start + 24, 8)?;
    sink.push((one - owed_zero) * (one - active))?;
    sink.push((one - active) * index * (index - NativeField::from_u64(160)))
}

fn constrain_dma_general_transition(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let dma = view.mode(DMA_BYTE_MODE)?;
    let blue_wait = view.mode(BLUE_DMA_WAIT_MODE)?;
    let general = one - dma - blue_wait;
    let source = packed_bits(view, TRACE_BEFORE_DMA_BITS_START, 8)?;
    let index = packed_bits(view, TRACE_BEFORE_DMA_BITS_START + 8, 8)?;
    let active = view.value(TRACE_BEFORE_DMA_BITS_START + 16)?;
    let after_source = packed_bits(view, TRACE_AFTER_DMA_BITS_START, 8)?;
    let after_index = packed_bits(view, TRACE_AFTER_DMA_BITS_START + 8, 8)?;
    let after_active = view.value(TRACE_AFTER_DMA_BITS_START + 16)?;
    let mut write = NativeField::from_u64(0);
    let mut source_delta = NativeField::from_u64(0);
    for slot in 0..TRACE_BUS_SLOTS {
        let selected = dma_write_selector(view, slot)?;
        write += selected;
        source_delta += selected * (bus_field(view, slot, BUS_VALUE_OFFSET)? - source);
    }
    sink.push(general * (after_source - source - source_delta))?;
    sink.push(general * (after_index - index * (one - write)))?;
    sink.push(general * (after_active - active - write * (one - active)))?;
    constrain_dma_scheduling(view, sink, active)
}

fn constrain_dma_scheduling(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    active: NativeField,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let regular =
        view.mode(INSTRUCTION_MODE)? + view.mode(HALT_IDLE_MODE)? + view.mode(INTERRUPT_MODE)?;
    let excluded = regular + view.mode(DMA_BYTE_MODE)? + view.mode(BLUE_DMA_WAIT_MODE)?;
    let quiet_long = view.mode(HALT_UNTIL_VBLANK_MODE)?
        + view.mode(BLUE_SOUND_WAIT_MODE)?
        + view.mode(BLUE_DELAY_LOOP_MODE)?;
    let after_owed = packed_bits(view, TRACE_AFTER_DMA_BITS_START + 24, 8)?;
    let before_owed = packed_bits(view, TRACE_BEFORE_DMA_BITS_START + 24, 8)?;
    let mut scheduled = NativeField::from_u64(0);
    for cycle in 0..6 {
        let mut unavailable = NativeField::from_u64(0);
        for index in DMA_NEAR_END_INDICES.iter().copied().skip(5 - cycle) {
            unavailable += fixed_byte_selector(view, TRACE_BEFORE_DMA_BITS_START + 8, index)?;
        }
        scheduled += view.value(TRACE_TIMER_M_CYCLE_ACTIVE_START + cycle)? * (one - unavailable);
    }
    sink.push(regular * (after_owed - active * scheduled))?;
    sink.push((one - excluded) * (after_owed - before_owed))?;
    sink.push(quiet_long * active)
}

fn dma_write_selector(view: &RowView<'_>, slot: usize) -> Result<NativeField, UniformError> {
    Ok(bus_kind(view, slot, 12)?
        * fixed_byte_selector(view, TRACE_BUS_ADDRESS_BITS_START + slot * 16, 0x46)?)
}

fn constrain_dma_priority_and_copy(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let owed_zero = zero_from_bits(view, TRACE_BEFORE_DMA_BITS_START + 24, 8)?;
    let owed = packed_bits(view, TRACE_BEFORE_DMA_BITS_START + 24, 8)?;
    let dma = view.mode(DMA_BYTE_MODE)?;
    sink.push(view.value(TRACE_ACTIVE)? * (one - owed_zero) * (one - dma))?;
    sink.push(dma * (owed_zero - NativeField::from_u64(0)))?;
    sink.push(dma * (view.value(TRACE_BEFORE_DMA_BITS_START + 16)? - one))?;
    let source = packed_bits(view, TRACE_BEFORE_DMA_BITS_START, 8)?;
    let index = packed_bits(view, TRACE_BEFORE_DMA_BITS_START + 8, 8)?;
    let after_source = packed_bits(view, TRACE_AFTER_DMA_BITS_START, 8)?;
    let after_index = packed_bits(view, TRACE_AFTER_DMA_BITS_START + 8, 8)?;
    let after_owed = packed_bits(view, TRACE_AFTER_DMA_BITS_START + 24, 8)?;
    sink.push(dma * (after_source - source))?;
    sink.push(dma * (after_index - index - one))?;
    sink.push(dma * (after_owed - owed + one))?;
    let last = fixed_byte_selector(view, TRACE_BEFORE_DMA_BITS_START + 8, 159)?;
    sink.push(dma * (view.value(TRACE_AFTER_DMA_BITS_START + 16)? - one + last))?;
    for state in STATE_INTERRUPT_REQUEST..STATE_DMA_PACK {
        sink.push(dma * (view.after(state)? - view.before(state)?))?;
    }
    constrain_dma_copy_bus(view, sink, dma, source, index)
}

fn constrain_dma_copy_bus(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    dma: NativeField,
    source: NativeField,
    index: NativeField,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let source_kinds = bus_kind(view, 0, 16)? + bus_kind(view, 0, 17)?;
    sink.push(dma * (source_kinds - one))?;
    sink.push(dma * (bus_kind(view, 1, 18)? - one))?;
    for slot in 2..TRACE_BUS_SLOTS {
        sink.push(dma * bus_field(view, slot, 0)?)?;
    }
    let high_bit = view.value(TRACE_BEFORE_DMA_BITS_START + 7)?;
    sink.push(dma * (bus_kind(view, 0, 16)? - one + high_bit))?;
    sink.push(
        dma * (bus_field(view, 0, BUS_ADDRESS_OFFSET)?
            - source * NativeField::from_u64(256)
            - index),
    )?;
    sink.push(
        dma * (bus_field(view, 1, BUS_ADDRESS_OFFSET)? - NativeField::from_u64(0xfe00) - index),
    )?;
    sink.push(
        dma * (bus_field(view, 1, BUS_VALUE_OFFSET)? - bus_field(view, 0, BUS_VALUE_OFFSET)?),
    )?;
    let high_invalid = view.value(TRACE_BEFORE_DMA_BITS_START + 7)?
        * view.value(TRACE_BEFORE_DMA_BITS_START + 6)?
        * view.value(TRACE_BEFORE_DMA_BITS_START + 5)?;
    let index_over_159 = view.value(TRACE_BEFORE_DMA_BITS_START + 15)?
        * (view.value(TRACE_BEFORE_DMA_BITS_START + 14)?
            + view.value(TRACE_BEFORE_DMA_BITS_START + 13)?
            - view.value(TRACE_BEFORE_DMA_BITS_START + 14)?
                * view.value(TRACE_BEFORE_DMA_BITS_START + 13)?);
    sink.push(dma * high_invalid)?;
    sink.push(dma * index_over_159)
}

fn constrain_dma_wait_pack(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let selected = view.mode(BLUE_DMA_WAIT_MODE)?;
    let before_source = packed_bits(view, TRACE_BEFORE_DMA_BITS_START, 8)?;
    let after_source = packed_bits(view, TRACE_AFTER_DMA_BITS_START, 8)?;
    sink.push(selected * (after_source - before_source))?;
    for (start, expected_index, expected_active, expected_owed) in [
        (TRACE_BEFORE_DMA_BITS_START, 2, 1, 0),
        (TRACE_AFTER_DMA_BITS_START, 2, 1, 158),
    ] {
        sink.push(
            selected * (packed_bits(view, start + 8, 8)? - NativeField::from_u64(expected_index)),
        )?;
        sink.push(selected * (view.value(start + 16)? - NativeField::from_u64(expected_active)))?;
        sink.push(
            selected * (packed_bits(view, start + 24, 8)? - NativeField::from_u64(expected_owed)),
        )?;
    }
    Ok(())
}

fn fixed_byte_selector(
    view: &RowView<'_>,
    start: usize,
    expected: u8,
) -> Result<NativeField, UniformError> {
    let one = NativeField::from_u64(1);
    (0..8).try_fold(one, |selector, bit| {
        let value = view.value(start + bit)?;
        Ok(if (expected >> bit) & 1 == 1 {
            selector * value
        } else {
            selector * (one - value)
        })
    })
}

fn bus_kind(view: &RowView<'_>, slot: usize, code: u8) -> Result<NativeField, UniformError> {
    bit_selector(bus_kind_bits(view, slot)?, code)
}

fn constrain_interrupt_masks(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    for start in [
        TRACE_BEFORE_INTERRUPT_REQUEST_BITS_START,
        TRACE_BEFORE_INTERRUPT_ENABLE_BITS_START,
        TRACE_AFTER_INTERRUPT_REQUEST_BITS_START,
        TRACE_AFTER_INTERRUPT_ENABLE_BITS_START,
    ] {
        for bit in 0..INTERRUPT_BITS {
            let value = view.value(start + bit)?;
            sink.push(value * (value - NativeField::from_u64(1)))?;
        }
    }
    sink.push(
        view.before(STATE_INTERRUPT_REQUEST)?
            - packed_bits(
                view,
                TRACE_BEFORE_INTERRUPT_REQUEST_BITS_START,
                INTERRUPT_BITS,
            )?,
    )?;
    sink.push(
        view.before(STATE_INTERRUPT_ENABLE)?
            - packed_bits(
                view,
                TRACE_BEFORE_INTERRUPT_ENABLE_BITS_START,
                INTERRUPT_BITS,
            )?,
    )?;
    sink.push(
        view.after(STATE_INTERRUPT_REQUEST)?
            - packed_bits(
                view,
                TRACE_AFTER_INTERRUPT_REQUEST_BITS_START,
                INTERRUPT_BITS,
            )?,
    )?;
    sink.push(
        view.after(STATE_INTERRUPT_ENABLE)?
            - packed_bits(
                view,
                TRACE_AFTER_INTERRUPT_ENABLE_BITS_START,
                INTERRUPT_BITS,
            )?,
    )
}

fn pending_bits(view: &RowView<'_>) -> Result<[NativeField; INTERRUPT_BITS], UniformError> {
    Ok([
        pending_bit(view, 0)?,
        pending_bit(view, 1)?,
        pending_bit(view, 2)?,
        pending_bit(view, 3)?,
        pending_bit(view, 4)?,
    ])
}

fn pending_bit(view: &RowView<'_>, bit: usize) -> Result<NativeField, UniformError> {
    Ok(view.value(TRACE_BEFORE_INTERRUPT_REQUEST_BITS_START + bit)?
        * view.value(TRACE_BEFORE_INTERRUPT_ENABLE_BITS_START + bit)?)
}

fn any(bits: &[NativeField; INTERRUPT_BITS]) -> NativeField {
    let one = NativeField::from_u64(1);
    one - bits
        .iter()
        .copied()
        .fold(one, |none, bit| none * (one - bit))
}

fn constrain_priority(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    pending: &[NativeField; INTERRUPT_BITS],
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let interrupt = view.mode(INTERRUPT_MODE)?;
    let mut higher_clear = one;
    for (source, bit) in pending.iter().copied().enumerate() {
        let priority = bit * higher_clear;
        sink.push(view.value(TRACE_INTERRUPT_START + source)? - interrupt * priority)?;
        higher_clear *= one - bit;
    }
    Ok(())
}

fn constrain_mode_selection(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    pending: NativeField,
) -> Result<(), UniformError> {
    let ime = view.before(STATE_IME)?;
    let ime_enabled_scaled = ime * (ime - NativeField::from_u64(1));
    let instruction = view.mode(INSTRUCTION_MODE)?;
    let summaries = view.mode(BLUE_SOUND_WAIT_MODE)? + view.mode(BLUE_DELAY_LOOP_MODE)?;
    sink.push((instruction + summaries) * ime_enabled_scaled * pending)?;
    let wake = view.mode(HALT_WAKE_MODE)?;
    sink.push(wake * (pending - NativeField::from_u64(1)))?;
    sink.push(wake * ime_enabled_scaled)?;
    let sleeping = view.mode(HALT_IDLE_MODE)? + view.mode(HALT_UNTIL_VBLANK_MODE)?;
    sink.push(sleeping * pending)?;
    let halt = instruction * operation_selector(view, 18)?;
    let not_enabled_scaled = NativeField::from_u64(2) - ime_enabled_scaled;
    sink.push(
        halt * (view.after(STATE_RUN_STATE)?
            - NativeField::from_u64(1)
            - pending * not_enabled_scaled),
    )
}
