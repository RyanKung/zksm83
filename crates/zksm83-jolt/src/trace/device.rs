use zksm83_core::{BusEventKind, DmgInterrupt, StepKind, VmState};
use zksm83_trace::TraceRow;

use crate::{TRACE_BUS_SLOTS, TRACE_MEMORY_SLOT_WIDTH, TRACE_MEMORY_START};

use super::{NativeTraceError, append_bits};

mod timer;

const INTERRUPT_BITS: usize = 5;

/// First bit decomposing the before-state IF request mask.
pub const TRACE_BEFORE_INTERRUPT_REQUEST_BITS_START: usize =
    TRACE_MEMORY_START + TRACE_BUS_SLOTS * TRACE_MEMORY_SLOT_WIDTH;
/// First bit decomposing the before-state IE enable mask.
pub const TRACE_BEFORE_INTERRUPT_ENABLE_BITS_START: usize =
    TRACE_BEFORE_INTERRUPT_REQUEST_BITS_START + INTERRUPT_BITS;
/// First bit decomposing the after-state IF request mask.
pub const TRACE_AFTER_INTERRUPT_REQUEST_BITS_START: usize =
    TRACE_BEFORE_INTERRUPT_ENABLE_BITS_START + INTERRUPT_BITS;
/// First bit decomposing the after-state IE enable mask.
pub const TRACE_AFTER_INTERRUPT_ENABLE_BITS_START: usize =
    TRACE_AFTER_INTERRUPT_REQUEST_BITS_START + INTERRUPT_BITS;
/// Boolean indicating that at least one before-state IF/IE pair is set.
pub const TRACE_PENDING_INTERRUPT: usize = TRACE_AFTER_INTERRUPT_ENABLE_BITS_START + INTERRUPT_BITS;
/// First bit decomposing the before-state packed OAM DMA state.
pub const TRACE_BEFORE_DMA_BITS_START: usize = TRACE_PENDING_INTERRUPT + 1;
/// First bit decomposing the after-state packed OAM DMA state.
pub const TRACE_AFTER_DMA_BITS_START: usize = TRACE_BEFORE_DMA_BITS_START + 32;
/// Before-state P1 select bits four and five, followed by eight button bits.
pub const TRACE_BEFORE_JOYPAD_BITS_START: usize = TRACE_AFTER_DMA_BITS_START + 32;
/// First ten-bit joypad state after one ordered bus slot.
pub const TRACE_JOYPAD_STAGE_BITS_START: usize = TRACE_BEFORE_JOYPAD_BITS_START + 10;
/// Width of one select/button joypad stage.
pub const TRACE_JOYPAD_STAGE_WIDTH: usize = 10;
/// First Boolean selecting an FF00 MMIO write in one bus slot.
pub const TRACE_JOYPAD_WRITE_START: usize =
    TRACE_JOYPAD_STAGE_BITS_START + TRACE_BUS_SLOTS * TRACE_JOYPAD_STAGE_WIDTH;
/// First pair of witnesses proving no falling P1 line in low-bit pairs 0-1 and 2-3.
pub const TRACE_JOYPAD_FALL_NONE_START: usize = TRACE_JOYPAD_WRITE_START + TRACE_BUS_SLOTS;
/// First committed IF bit-four state after one ordered bus slot.
pub const TRACE_JOYPAD_IF_BIT_START: usize = TRACE_JOYPAD_FALL_NONE_START + TRACE_BUS_SLOTS * 2;
pub(crate) const TRACE_BEFORE_DMG_LOW_BITS_START: usize =
    TRACE_JOYPAD_IF_BIT_START + TRACE_BUS_SLOTS;
pub(crate) const TRACE_BEFORE_DMG_HIGH_BITS_START: usize = TRACE_BEFORE_DMG_LOW_BITS_START + 64;
pub(crate) const TRACE_BEFORE_TIMER_DIV_BITS_START: usize = TRACE_BEFORE_DMG_HIGH_BITS_START + 64;
pub(crate) const TRACE_BEFORE_TIMER_COUNTER_BITS_START: usize =
    TRACE_BEFORE_TIMER_DIV_BITS_START + 16;
pub(crate) const TRACE_BEFORE_TIMER_PHASE_BITS_START: usize =
    TRACE_BEFORE_TIMER_COUNTER_BITS_START + 8;
pub(crate) const TRACE_TIMER_PHASE_FIVE: usize = TRACE_BEFORE_TIMER_PHASE_BITS_START + 3;
pub(crate) const TRACE_BEFORE_PPU_LINE_BITS_START: usize = TRACE_TIMER_PHASE_FIVE + 1;
pub(crate) const TRACE_BEFORE_PPU_DOT_BITS_START: usize = TRACE_BEFORE_PPU_LINE_BITS_START + 8;
pub(crate) const TRACE_PPU_VBLANK: usize = TRACE_BEFORE_PPU_DOT_BITS_START + 9;
pub(crate) const TRACE_PPU_DOT_LT_80: usize = TRACE_PPU_VBLANK + 1;
pub(crate) const TRACE_PPU_DOT_LT_252: usize = TRACE_PPU_DOT_LT_80 + 1;
pub(crate) const TRACE_PPU_MODE_BITS_START: usize = TRACE_PPU_DOT_LT_252 + 1;
pub(crate) const TRACE_PPU_COINCIDENCE: usize = TRACE_PPU_MODE_BITS_START + 2;
pub(crate) const TRACE_BEFORE_APU_CONTROL_LOW_BITS_START: usize = TRACE_PPU_COINCIDENCE + 1;
pub(crate) const TRACE_BEFORE_APU_CONTROL_HIGH_BITS_START: usize =
    TRACE_BEFORE_APU_CONTROL_LOW_BITS_START + 64;
pub(crate) const TRACE_BEFORE_APU_MIXER_BITS_START: usize =
    TRACE_BEFORE_APU_CONTROL_HIGH_BITS_START + 64;
pub(crate) const TRACE_BEFORE_APU_WAVE_LOW_BITS_START: usize =
    TRACE_BEFORE_APU_MIXER_BITS_START + 64;
pub(crate) const TRACE_BEFORE_APU_WAVE_HIGH_BITS_START: usize =
    TRACE_BEFORE_APU_WAVE_LOW_BITS_START + 64;
pub(crate) const TRACE_AFTER_DMG_LOW_BITS_START: usize = TRACE_BEFORE_APU_WAVE_HIGH_BITS_START + 64;
pub(crate) const TRACE_AFTER_DMG_HIGH_BITS_START: usize = TRACE_AFTER_DMG_LOW_BITS_START + 64;
pub(crate) const TRACE_AFTER_APU_CONTROL_LOW_BITS_START: usize =
    TRACE_AFTER_DMG_HIGH_BITS_START + 64;
pub(crate) const TRACE_AFTER_APU_CONTROL_HIGH_BITS_START: usize =
    TRACE_AFTER_APU_CONTROL_LOW_BITS_START + 64;
pub(crate) const TRACE_AFTER_APU_MIXER_BITS_START: usize =
    TRACE_AFTER_APU_CONTROL_HIGH_BITS_START + 64;
pub(crate) const TRACE_AFTER_APU_WAVE_LOW_BITS_START: usize = TRACE_AFTER_APU_MIXER_BITS_START + 64;
pub(crate) const TRACE_AFTER_APU_WAVE_HIGH_BITS_START: usize =
    TRACE_AFTER_APU_WAVE_LOW_BITS_START + 64;
pub(crate) const TRACE_APU_POWER_OFF: usize = TRACE_AFTER_APU_WAVE_HIGH_BITS_START + 64;
pub(crate) const TRACE_APU_POWER_ON: usize = TRACE_APU_POWER_OFF + 1;
pub(crate) const TRACE_APU_AFTER_DAC_ENABLED_START: usize = TRACE_APU_POWER_ON + 1;
pub(crate) const TRACE_APU_DAC_WRITE_START: usize = TRACE_APU_AFTER_DAC_ENABLED_START + 4;
pub(crate) const TRACE_APU_WRITTEN_DAC_ENABLED_START: usize = TRACE_APU_DAC_WRITE_START + 4;
pub(crate) const TRACE_APU_TRIGGER_START: usize = TRACE_APU_WRITTEN_DAC_ENABLED_START + 4;
pub(crate) const TRACE_SERIAL_POST_DATA_BITS_START: usize = TRACE_APU_TRIGGER_START + 4;
pub(crate) const TRACE_SERIAL_POST_CONTROL_BITS_START: usize =
    TRACE_SERIAL_POST_DATA_BITS_START + 8;
pub(crate) const TRACE_SERIAL_POST_COUNTDOWN_BITS_START: usize =
    TRACE_SERIAL_POST_CONTROL_BITS_START + 8;
pub(crate) const TRACE_SERIAL_POST_ACTIVE: usize = TRACE_SERIAL_POST_COUNTDOWN_BITS_START + 13;
pub(crate) const TRACE_SERIAL_AFTER_ZERO: usize = TRACE_SERIAL_POST_ACTIVE + 1;
pub(crate) const TRACE_SERIAL_COMPLETED: usize = TRACE_SERIAL_AFTER_ZERO + 1;
pub(crate) const TRACE_TIMER_M_CYCLE_ACTIVE_START: usize = TRACE_SERIAL_COMPLETED + 1;
pub(crate) const TRACE_TIMER_AFTER_FF05_BITS_START: usize = TRACE_TIMER_M_CYCLE_ACTIVE_START + 6;
pub(crate) const TRACE_TIMER_POST_STATE_START: usize = TRACE_TIMER_AFTER_FF05_BITS_START + 8;
pub(crate) const TRACE_TIMER_STAGE_START: usize = TRACE_TIMER_POST_STATE_START + 29;
pub(crate) const TRACE_TIMER_STAGE_WIDTH: usize = 41;
pub(crate) const TRACE_TIMER_LONG_QUOTIENT_BITS_START: usize =
    TRACE_TIMER_STAGE_START + 24 * TRACE_TIMER_STAGE_WIDTH;
pub(crate) const TRACE_AFTER_PPU_LINE_BITS_START: usize = TRACE_TIMER_LONG_QUOTIENT_BITS_START + 5;
pub(crate) const TRACE_AFTER_PPU_DOT_BITS_START: usize = TRACE_AFTER_PPU_LINE_BITS_START + 8;
pub(crate) const TRACE_PPU_FRAME_QUOTIENT_BITS_START: usize = TRACE_AFTER_PPU_DOT_BITS_START + 9;
pub(crate) const TRACE_PPU_LCD_DISABLE: usize = TRACE_PPU_FRAME_QUOTIENT_BITS_START + 5;
pub(crate) const TRACE_PPU_VBLANK_EVENT: usize = TRACE_PPU_LCD_DISABLE + 1;
pub(crate) const TRACE_PPU_VBLANK_GAP_BITS_START: usize = TRACE_PPU_VBLANK_EVENT + 1;
pub(crate) const TRACE_PPU_POST_LINE_BITS_START: usize = TRACE_PPU_VBLANK_GAP_BITS_START + 21;
pub(crate) const TRACE_PPU_POST_DOT_BITS_START: usize = TRACE_PPU_POST_LINE_BITS_START + 8;
pub(crate) const TRACE_PPU_POST_VBLANK: usize = TRACE_PPU_POST_DOT_BITS_START + 9;
pub(crate) const TRACE_PPU_POST_DOT_LT_80: usize = TRACE_PPU_POST_VBLANK + 1;
pub(crate) const TRACE_PPU_POST_DOT_LT_252: usize = TRACE_PPU_POST_DOT_LT_80 + 1;
pub(crate) const TRACE_PPU_POST_COINCIDENCE: usize = TRACE_PPU_POST_DOT_LT_252 + 1;
pub(crate) const TRACE_PPU_AFTER_VBLANK: usize = TRACE_PPU_POST_COINCIDENCE + 1;
pub(crate) const TRACE_PPU_AFTER_DOT_LT_80: usize = TRACE_PPU_AFTER_VBLANK + 1;
pub(crate) const TRACE_PPU_AFTER_DOT_LT_252: usize = TRACE_PPU_AFTER_DOT_LT_80 + 1;
pub(crate) const TRACE_PPU_AFTER_COINCIDENCE: usize = TRACE_PPU_AFTER_DOT_LT_252 + 1;
pub(crate) const TRACE_PPU_STAT_BEFORE: usize = TRACE_PPU_AFTER_COINCIDENCE + 1;
pub(crate) const TRACE_PPU_STAT_POST_WRITE: usize = TRACE_PPU_STAT_BEFORE + 1;
pub(crate) const TRACE_PPU_STAT_AFTER: usize = TRACE_PPU_STAT_POST_WRITE + 1;
pub(crate) const TRACE_PPU_STAT_RELEVANT_WRITE: usize = TRACE_PPU_STAT_AFTER + 1;
pub(crate) const TRACE_PPU_STAT_BOUNDARY_CROSSED: usize = TRACE_PPU_STAT_RELEVANT_WRITE + 1;
pub(crate) const TRACE_PPU_STAT_EVENT: usize = TRACE_PPU_STAT_BOUNDARY_CROSSED + 1;
pub(crate) const TRACE_PPU_STAT_GAP_BITS_START: usize = TRACE_PPU_STAT_EVENT + 1;
pub(crate) const TRACE_BEFORE_DMA_REMAINING_BITS_START: usize = TRACE_PPU_STAT_GAP_BITS_START + 9;
pub(crate) const TRACE_AFTER_DMA_REMAINING_BITS_START: usize =
    TRACE_BEFORE_DMA_REMAINING_BITS_START + 8;
pub(crate) const TRACE_CPU_OAM_ACCESS_START: usize = TRACE_AFTER_DMA_REMAINING_BITS_START + 8;
pub(crate) const TRACE_SERIAL_COMPLETION_GAP_BITS_START: usize =
    TRACE_CPU_OAM_ACCESS_START + TRACE_BUS_SLOTS;
pub(crate) const TRACE_TIMER_INTERRUPT_GAP_BITS_START: usize =
    TRACE_SERIAL_COMPLETION_GAP_BITS_START + 5;
pub(super) const TRACE_DEVICE_COLUMN_END: usize = TRACE_TIMER_INTERRUPT_GAP_BITS_START + 2;

pub(super) fn append_state_bits(
    columns: &mut [Vec<u64>],
    before: VmState,
    after: VmState,
) -> Result<(), NativeTraceError> {
    for (start, value) in [
        (
            TRACE_BEFORE_INTERRUPT_REQUEST_BITS_START,
            before.dmg_devices().interrupt_request(),
        ),
        (
            TRACE_BEFORE_INTERRUPT_ENABLE_BITS_START,
            before.dmg_devices().interrupt_enable(),
        ),
        (
            TRACE_AFTER_INTERRUPT_REQUEST_BITS_START,
            after.dmg_devices().interrupt_request(),
        ),
        (
            TRACE_AFTER_INTERRUPT_ENABLE_BITS_START,
            after.dmg_devices().interrupt_enable(),
        ),
    ] {
        append_bits(columns, start, u64::from(value), INTERRUPT_BITS)?;
    }
    super::append(
        columns,
        TRACE_PENDING_INTERRUPT,
        u64::from(before.dmg_devices().pending_interrupt().is_some()),
    )?;
    append_bits(
        columns,
        TRACE_BEFORE_DMA_BITS_START,
        u64::from(before.dmg_devices().dma_pack()),
        32,
    )?;
    append_bits(
        columns,
        TRACE_AFTER_DMA_BITS_START,
        u64::from(after.dmg_devices().dma_pack()),
        32,
    )?;
    append_dma_remaining(columns, before, after)?;
    append_visible_register_bits(columns, before)?;
    append_after_register_bits(columns, after)?;
    append_after_apu_bits(columns, after)
}

fn append_dma_remaining(
    columns: &mut [Vec<u64>],
    before: VmState,
    after: VmState,
) -> Result<(), NativeTraceError> {
    for (start, devices) in [
        (TRACE_BEFORE_DMA_REMAINING_BITS_START, before.dmg_devices()),
        (TRACE_AFTER_DMA_REMAINING_BITS_START, after.dmg_devices()),
    ] {
        let remaining = 160_u8
            .checked_sub(devices.dma_index())
            .and_then(|value| value.checked_sub(devices.dma_owed()))
            .ok_or(NativeTraceError::Layout)?;
        append_bits(columns, start, u64::from(remaining), 8)?;
    }
    Ok(())
}

pub(super) fn append_bus_access_witness(
    columns: &mut [Vec<u64>],
    row: Option<&TraceRow>,
) -> Result<(), NativeTraceError> {
    let events = row.map_or(&[][..], |row| row.effects().ordered_bus_events());
    for slot in 0..TRACE_BUS_SLOTS {
        let oam = events.get(slot).is_some_and(|event| {
            let address = event.transcript_event().address;
            (0xfe00..=0xfe9f).contains(&address)
        });
        super::append(columns, TRACE_CPU_OAM_ACCESS_START + slot, u64::from(oam))?;
    }
    Ok(())
}

fn append_after_register_bits(
    columns: &mut [Vec<u64>],
    after: VmState,
) -> Result<(), NativeTraceError> {
    let devices = after.dmg_devices();
    append_bits(
        columns,
        TRACE_AFTER_DMG_LOW_BITS_START,
        devices.low_register_pack(),
        64,
    )?;
    append_bits(
        columns,
        TRACE_AFTER_DMG_HIGH_BITS_START,
        devices.high_register_pack(),
        64,
    )
}

fn append_after_apu_bits(columns: &mut [Vec<u64>], after: VmState) -> Result<(), NativeTraceError> {
    let apu = after.dmg_devices().apu();
    for (start, value) in [
        (
            TRACE_AFTER_APU_CONTROL_LOW_BITS_START,
            apu.control_low_pack(),
        ),
        (
            TRACE_AFTER_APU_CONTROL_HIGH_BITS_START,
            apu.control_high_pack(),
        ),
        (TRACE_AFTER_APU_MIXER_BITS_START, apu.mixer_pack()),
        (TRACE_AFTER_APU_WAVE_LOW_BITS_START, apu.wave_low_pack()),
        (TRACE_AFTER_APU_WAVE_HIGH_BITS_START, apu.wave_high_pack()),
    ] {
        append_bits(columns, start, value, 64)?;
    }
    Ok(())
}

fn append_visible_register_bits(
    columns: &mut [Vec<u64>],
    before: VmState,
) -> Result<(), NativeTraceError> {
    let devices = before.dmg_devices();
    let timer = devices.timer();
    append_bits(
        columns,
        TRACE_BEFORE_DMG_LOW_BITS_START,
        devices.low_register_pack(),
        64,
    )?;
    append_bits(
        columns,
        TRACE_BEFORE_DMG_HIGH_BITS_START,
        devices.high_register_pack(),
        64,
    )?;
    append_bits(
        columns,
        TRACE_BEFORE_TIMER_DIV_BITS_START,
        u64::from(timer.raw_div()),
        16,
    )?;
    append_bits(
        columns,
        TRACE_BEFORE_TIMER_COUNTER_BITS_START,
        u64::from(timer.counter()),
        8,
    )?;
    append_bits(
        columns,
        TRACE_BEFORE_TIMER_PHASE_BITS_START,
        u64::from(timer.reload_phase()),
        3,
    )?;
    super::append(
        columns,
        TRACE_TIMER_PHASE_FIVE,
        u64::from(timer.reload_phase() == 5),
    )?;
    append_bits(
        columns,
        TRACE_BEFORE_PPU_LINE_BITS_START,
        u64::from(devices.ppu_line()),
        8,
    )?;
    append_bits(
        columns,
        TRACE_BEFORE_PPU_DOT_BITS_START,
        u64::from(devices.ppu_dot()),
        9,
    )?;
    append_ppu_predicates(columns, devices)?;
    append_apu_bits(columns, devices)
}

fn append_ppu_predicates(
    columns: &mut [Vec<u64>],
    devices: zksm83_core::DmgDeviceState,
) -> Result<(), NativeTraceError> {
    let status = devices.read_mmio(0xff41).ok_or(NativeTraceError::Layout)?;
    for (column, value) in [
        (TRACE_PPU_VBLANK, u64::from(devices.ppu_line() >= 144)),
        (TRACE_PPU_DOT_LT_80, u64::from(devices.ppu_dot() < 80)),
        (TRACE_PPU_DOT_LT_252, u64::from(devices.ppu_dot() < 252)),
        (TRACE_PPU_MODE_BITS_START, u64::from(status & 1)),
        (TRACE_PPU_MODE_BITS_START + 1, u64::from((status >> 1) & 1)),
        (TRACE_PPU_COINCIDENCE, u64::from(status & 0x04 != 0)),
    ] {
        super::append(columns, column, value)?;
    }
    Ok(())
}

fn append_apu_bits(
    columns: &mut [Vec<u64>],
    devices: zksm83_core::DmgDeviceState,
) -> Result<(), NativeTraceError> {
    let apu = devices.apu();
    for (start, value) in [
        (
            TRACE_BEFORE_APU_CONTROL_LOW_BITS_START,
            apu.control_low_pack(),
        ),
        (
            TRACE_BEFORE_APU_CONTROL_HIGH_BITS_START,
            apu.control_high_pack(),
        ),
        (TRACE_BEFORE_APU_MIXER_BITS_START, apu.mixer_pack()),
        (TRACE_BEFORE_APU_WAVE_LOW_BITS_START, apu.wave_low_pack()),
        (TRACE_BEFORE_APU_WAVE_HIGH_BITS_START, apu.wave_high_pack()),
    ] {
        append_bits(columns, start, value, 64)?;
    }
    Ok(())
}

pub(super) fn append_apu_witness(
    columns: &mut [Vec<u64>],
    after: VmState,
    row: Option<&TraceRow>,
) -> Result<(), NativeTraceError> {
    let mut power_off = false;
    let mut power_on = false;
    let mut dac_write = [false; 4];
    let mut written_dac = [false; 4];
    let mut trigger = [false; 4];
    if let Some(row) = row {
        for event in row.effects().bus_events() {
            let tuple = event.transcript_event();
            if event.kind() != BusEventKind::DmgMmioWrite {
                continue;
            }
            if tuple.address == 0xff26 {
                power_off |= tuple.value & 0x80 == 0;
                power_on |= tuple.value & 0x80 != 0;
            }
            if let Some(channel) = dac_channel(tuple.address) {
                *dac_write
                    .get_mut(usize::from(channel))
                    .ok_or(NativeTraceError::Layout)? = true;
                *written_dac
                    .get_mut(usize::from(channel))
                    .ok_or(NativeTraceError::Layout)? = dac_enabled(channel, tuple.value);
            }
            if let Some(channel) = trigger_channel(tuple.address)
                && tuple.value & 0x80 != 0
            {
                *trigger
                    .get_mut(usize::from(channel))
                    .ok_or(NativeTraceError::Layout)? = true;
            }
        }
    }
    super::append(columns, TRACE_APU_POWER_OFF, u64::from(power_off))?;
    super::append(columns, TRACE_APU_POWER_ON, u64::from(power_on))?;
    for channel in 0_u8..4 {
        let index = usize::from(channel);
        let enabled = after
            .dmg_devices()
            .apu()
            .read(dac_address(channel))
            .is_some_and(|value| dac_enabled(channel, value));
        for (start, value) in [
            (TRACE_APU_AFTER_DAC_ENABLED_START, enabled),
            (
                TRACE_APU_DAC_WRITE_START,
                *dac_write.get(index).ok_or(NativeTraceError::Layout)?,
            ),
            (
                TRACE_APU_WRITTEN_DAC_ENABLED_START,
                *written_dac.get(index).ok_or(NativeTraceError::Layout)?,
            ),
            (
                TRACE_APU_TRIGGER_START,
                *trigger.get(index).ok_or(NativeTraceError::Layout)?,
            ),
        ] {
            super::append(columns, start + index, u64::from(value))?;
        }
    }
    Ok(())
}

pub(super) fn append_serial_witness(
    columns: &mut [Vec<u64>],
    before: VmState,
    after: VmState,
    row: Option<&TraceRow>,
) -> Result<(), NativeTraceError> {
    let mut data = before
        .dmg_devices()
        .read_mmio(0xff01)
        .ok_or(NativeTraceError::Layout)?;
    let mut control = before
        .dmg_devices()
        .read_mmio(0xff02)
        .ok_or(NativeTraceError::Layout)?;
    let mut countdown = serial_countdown(before)?;
    if let Some(row) = row {
        for event in row.effects().bus_events() {
            let tuple = event.transcript_event();
            if event.kind() != BusEventKind::DmgMmioWrite {
                continue;
            }
            match tuple.address {
                0xff01 => data = tuple.value,
                0xff02 => {
                    control = tuple.value;
                    countdown = if tuple.value & 0x81 == 0x81 { 4096 } else { 0 };
                }
                _ => {}
            }
        }
    }
    let after_countdown = serial_countdown(after)?;
    append_bits(
        columns,
        TRACE_SERIAL_POST_DATA_BITS_START,
        u64::from(data),
        8,
    )?;
    append_bits(
        columns,
        TRACE_SERIAL_POST_CONTROL_BITS_START,
        u64::from(control),
        8,
    )?;
    append_bits(
        columns,
        TRACE_SERIAL_POST_COUNTDOWN_BITS_START,
        u64::from(countdown),
        13,
    )?;
    for (column, value) in [
        (TRACE_SERIAL_POST_ACTIVE, countdown != 0),
        (TRACE_SERIAL_AFTER_ZERO, after_countdown == 0),
        (
            TRACE_SERIAL_COMPLETED,
            countdown != 0 && after_countdown == 0,
        ),
    ] {
        super::append(columns, column, u64::from(value))?;
    }
    let increment = after
        .cpu()
        .m_cycles()
        .checked_sub(before.cpu().m_cycles())
        .ok_or(NativeTraceError::CycleRegression { index: 0 })?;
    let regular = row.is_some_and(|row| {
        matches!(
            row.effects().kind(),
            StepKind::Instruction
                | StepKind::HaltIdle
                | StepKind::HaltUntilSerial
                | StepKind::InterruptDispatch(_)
        )
    });
    let gap = if regular && countdown != 0 && after_countdown == 0 {
        increment
            .checked_mul(4)
            .and_then(|ticks| ticks.checked_sub(u64::from(countdown)))
            .ok_or(NativeTraceError::Layout)?
    } else {
        0
    };
    if gap >= 32 {
        return Err(NativeTraceError::Layout);
    }
    append_bits(columns, TRACE_SERIAL_COMPLETION_GAP_BITS_START, gap, 5)
}

fn serial_countdown(state: VmState) -> Result<u16, NativeTraceError> {
    u16::try_from(state.dmg_devices().high_register_pack() >> 48)
        .map_err(|_| NativeTraceError::Layout)
}

pub(super) fn append_timer_witness(
    columns: &mut [Vec<u64>],
    before: VmState,
    after: VmState,
    row: Option<&TraceRow>,
) -> Result<(), NativeTraceError> {
    let increment = after
        .cpu()
        .m_cycles()
        .checked_sub(before.cpu().m_cycles())
        .ok_or(NativeTraceError::CycleRegression { index: 0 })?;
    let regular = row.is_some_and(|row| {
        matches!(
            row.effects().kind(),
            StepKind::Instruction | StepKind::HaltIdle | StepKind::InterruptDispatch(_)
        )
    });
    let regular_m_cycles = if regular {
        usize::try_from(increment).map_err(|_| NativeTraceError::Layout)?
    } else {
        0
    };
    if regular_m_cycles > 6 {
        return Err(NativeTraceError::Layout);
    }
    for cycle in 0..6 {
        super::append(
            columns,
            TRACE_TIMER_M_CYCLE_ACTIVE_START + cycle,
            u64::from(cycle < regular_m_cycles),
        )?;
    }
    let (mut timer, after_ff05, mut interrupt) = timer_post_write(before, row)?;
    append_bits(
        columns,
        TRACE_TIMER_AFTER_FF05_BITS_START,
        u64::from(after_ff05),
        8,
    )?;
    append_timer_state(columns, TRACE_TIMER_POST_STATE_START, timer, interrupt)?;
    for tick in 0..24 {
        let (reload_counter, reload_phase) = reload_intermediate(timer);
        let divider_wraps = timer.raw_div() == u16::MAX;
        if tick < regular_m_cycles * 4 {
            interrupt |= timer.advance_t_cycles(1) & 0x04 != 0;
        }
        let start = TRACE_TIMER_STAGE_START + tick * TRACE_TIMER_STAGE_WIDTH;
        append_timer_state(columns, start, timer, interrupt)?;
        append_bits(columns, start + 29, u64::from(reload_counter), 8)?;
        append_bits(columns, start + 37, u64::from(reload_phase), 3)?;
        super::append(columns, start + 40, u64::from(divider_wraps))?;
    }
    append_timer_long_quotient(columns, before, increment, row)?;
    timer::append_interrupt_gap(columns, before, increment, row)
}

fn timer_post_write(
    before: VmState,
    row: Option<&TraceRow>,
) -> Result<(zksm83_core::DmgTimerState, u8, bool), NativeTraceError> {
    let mut timer = before.dmg_devices().timer();
    let mut after_ff05 = timer.counter();
    let mut interrupt = before.dmg_devices().interrupt_request() & 0x04 != 0;
    if row
        .is_some_and(|row| row.effects().kind() == StepKind::InterruptDispatch(DmgInterrupt::Timer))
    {
        interrupt = false;
    }
    if let Some(row) = row {
        for event in row.effects().bus_events() {
            let tuple = event.transcript_event();
            if event.kind() != BusEventKind::DmgMmioWrite {
                continue;
            }
            if tuple.address == 0xff0f {
                interrupt = tuple.value & 0x04 != 0;
            }
            if (0xff04..=0xff07).contains(&tuple.address) {
                let _prior = timer.write(tuple.address, tuple.value);
                if tuple.address == 0xff05 {
                    after_ff05 = timer.counter();
                }
            }
        }
    }
    Ok((timer, after_ff05, interrupt))
}

fn append_timer_state(
    columns: &mut [Vec<u64>],
    start: usize,
    timer: zksm83_core::DmgTimerState,
    interrupt: bool,
) -> Result<(), NativeTraceError> {
    append_bits(columns, start, u64::from(timer.raw_div()), 16)?;
    append_bits(columns, start + 16, u64::from(timer.counter()), 8)?;
    append_bits(columns, start + 24, u64::from(timer.reload_phase()), 3)?;
    super::append(columns, start + 27, u64::from(timer.edge_latch()))?;
    super::append(columns, start + 28, u64::from(interrupt))
}

const fn reload_intermediate(timer: zksm83_core::DmgTimerState) -> (u8, u8) {
    if timer.reload_phase() == 5 {
        (timer.modulo(), 0)
    } else if timer.reload_phase() == 0 {
        (timer.counter(), 0)
    } else {
        (timer.counter(), timer.reload_phase() + 1)
    }
}

fn append_timer_long_quotient(
    columns: &mut [Vec<u64>],
    before: VmState,
    increment: u64,
    row: Option<&TraceRow>,
) -> Result<(), NativeTraceError> {
    let long = row.is_some_and(|row| {
        matches!(
            row.effects().kind(),
            StepKind::HaltUntilVBlank | StepKind::HaltUntilSerial | StepKind::HaltUntilTimer
        )
    });
    let quotient = if long {
        (u64::from(before.dmg_devices().timer().raw_div()) + increment * 4) >> 16
    } else {
        0
    };
    if quotient >= 32 {
        return Err(NativeTraceError::Layout);
    }
    append_bits(columns, TRACE_TIMER_LONG_QUOTIENT_BITS_START, quotient, 5)
}

pub(super) fn append_ppu_transition_witness(
    columns: &mut [Vec<u64>],
    before: VmState,
    after: VmState,
    row: Option<&TraceRow>,
) -> Result<(), NativeTraceError> {
    let before_devices = before.dmg_devices();
    let after_devices = after.dmg_devices();
    append_bits(
        columns,
        TRACE_AFTER_PPU_LINE_BITS_START,
        u64::from(after_devices.ppu_line()),
        8,
    )?;
    append_bits(
        columns,
        TRACE_AFTER_PPU_DOT_BITS_START,
        u64::from(after_devices.ppu_dot()),
        9,
    )?;
    let disable = ppu_disable_event(row);
    let post_position = if disable {
        0
    } else {
        ppu_position(before_devices)
    };
    let increment = after
        .cpu()
        .m_cycles()
        .checked_sub(before.cpu().m_cycles())
        .ok_or(NativeTraceError::CycleRegression { index: 0 })?;
    let enabled = after_devices
        .read_mmio(0xff40)
        .is_some_and(|value| value & 0x80 != 0);
    let total = post_position + increment * 4;
    let quotient = if enabled { total / 70_224 } else { 0 };
    if quotient >= 32 {
        return Err(NativeTraceError::Layout);
    }
    let post_vblank = !disable && before_devices.ppu_line() >= 144;
    let next_vblank = 65_664 + u64::from(post_vblank) * 70_224;
    let event = enabled && total >= next_vblank;
    let gap = if !enabled {
        0
    } else if event {
        total - next_vblank
    } else {
        next_vblank
            .checked_sub(total)
            .and_then(|difference| difference.checked_sub(1))
            .ok_or(NativeTraceError::Layout)?
    };
    if gap >= (1 << 21) {
        return Err(NativeTraceError::Layout);
    }
    append_bits(columns, TRACE_PPU_FRAME_QUOTIENT_BITS_START, quotient, 5)?;
    super::append(columns, TRACE_PPU_LCD_DISABLE, u64::from(disable))?;
    super::append(columns, TRACE_PPU_VBLANK_EVENT, u64::from(event))?;
    append_bits(columns, TRACE_PPU_VBLANK_GAP_BITS_START, gap, 21)?;
    append_stat_witness(columns, before, after, row, increment)
}

fn append_stat_witness(
    columns: &mut [Vec<u64>],
    before: VmState,
    after: VmState,
    row: Option<&TraceRow>,
    increment: u64,
) -> Result<(), NativeTraceError> {
    let before_devices = before.dmg_devices();
    let after_devices = after.dmg_devices();
    let (post_devices, relevant_write, write_event) = stat_post_write(before_devices, row)?;
    append_bits(
        columns,
        TRACE_PPU_POST_LINE_BITS_START,
        u64::from(post_devices.ppu_line()),
        8,
    )?;
    append_bits(
        columns,
        TRACE_PPU_POST_DOT_BITS_START,
        u64::from(post_devices.ppu_dot()),
        9,
    )?;
    append_stat_predicates(columns, post_devices, true)?;
    append_stat_predicates(columns, after_devices, false)?;
    let before_signal = stat_signal(before_devices)?;
    let post_signal = stat_signal(post_devices)?;
    let after_signal = stat_signal(after_devices)?;
    let regular = row.is_some_and(|row| {
        matches!(
            row.effects().kind(),
            StepKind::Instruction | StepKind::HaltIdle | StepKind::InterruptDispatch(_)
        )
    });
    let t_cycles = increment.checked_mul(4).ok_or(NativeTraceError::Layout)?;
    let (boundary, gap) = stat_boundary(post_devices, regular, t_cycles)?;
    let tick_event = boundary && !post_signal && after_signal;
    for (column, value) in [
        (TRACE_PPU_STAT_BEFORE, before_signal),
        (TRACE_PPU_STAT_POST_WRITE, post_signal),
        (TRACE_PPU_STAT_AFTER, after_signal),
        (TRACE_PPU_STAT_RELEVANT_WRITE, relevant_write),
        (TRACE_PPU_STAT_BOUNDARY_CROSSED, boundary),
        (TRACE_PPU_STAT_EVENT, write_event || tick_event),
    ] {
        super::append(columns, column, u64::from(value))?;
    }
    append_bits(columns, TRACE_PPU_STAT_GAP_BITS_START, gap, 9)?;
    Ok(())
}

fn append_stat_predicates(
    columns: &mut [Vec<u64>],
    devices: zksm83_core::DmgDeviceState,
    post_write: bool,
) -> Result<(), NativeTraceError> {
    let status = devices.read_mmio(0xff41).ok_or(NativeTraceError::Layout)?;
    let start = if post_write {
        TRACE_PPU_POST_VBLANK
    } else {
        TRACE_PPU_AFTER_VBLANK
    };
    for (offset, value) in [
        (0, devices.ppu_line() >= 144),
        (1, devices.ppu_dot() < 80),
        (2, devices.ppu_dot() < 252),
        (3, status & 0x04 != 0),
    ] {
        super::append(columns, start + offset, u64::from(value))?;
    }
    Ok(())
}

fn stat_post_write(
    before: zksm83_core::DmgDeviceState,
    row: Option<&TraceRow>,
) -> Result<(zksm83_core::DmgDeviceState, bool, bool), NativeTraceError> {
    let mut devices = before;
    let mut signal = stat_signal(devices)?;
    let mut relevant = false;
    let mut event = false;
    if let Some(row) = row {
        for bus in row.effects().bus_events() {
            let tuple = bus.transcript_event();
            if bus.kind() != BusEventKind::DmgMmioWrite {
                continue;
            }
            let is_relevant = matches!(tuple.address, 0xff40 | 0xff41 | 0xff45);
            let _prior = devices.write_mmio(tuple.address, tuple.value);
            let next = stat_signal(devices)?;
            relevant |= is_relevant;
            event |= is_relevant && !signal && next;
            signal = next;
        }
    }
    Ok((devices, relevant, event))
}

fn stat_boundary(
    devices: zksm83_core::DmgDeviceState,
    regular: bool,
    t_cycles: u64,
) -> Result<(bool, u64), NativeTraceError> {
    let enabled = devices
        .read_mmio(0xff40)
        .is_some_and(|value| value & 0x80 != 0);
    if !regular || !enabled {
        return Ok((false, 0));
    }
    let dot = u64::from(devices.ppu_dot());
    let next: u64 = if dot < 80 {
        80
    } else if dot < 252 {
        252
    } else {
        456
    };
    let distance = next.checked_sub(dot).ok_or(NativeTraceError::Layout)?;
    if t_cycles >= distance {
        Ok((true, t_cycles - distance))
    } else {
        Ok((false, distance - t_cycles - 1))
    }
}

fn stat_signal(devices: zksm83_core::DmgDeviceState) -> Result<bool, NativeTraceError> {
    let lcdc = devices.read_mmio(0xff40).ok_or(NativeTraceError::Layout)?;
    if lcdc & 0x80 == 0 {
        return Ok(false);
    }
    let stat = devices.read_mmio(0xff41).ok_or(NativeTraceError::Layout)?;
    let mode = stat & 0x03;
    Ok((stat & 0x08 != 0 && mode == 0)
        || (stat & 0x10 != 0 && mode == 1)
        || (stat & 0x20 != 0 && mode == 2)
        || (stat & 0x40 != 0 && stat & 0x04 != 0))
}

fn ppu_disable_event(row: Option<&TraceRow>) -> bool {
    row.is_some_and(|row| {
        row.effects().bus_events().any(|event| {
            let tuple = event.transcript_event();
            event.kind() == BusEventKind::DmgMmioWrite
                && tuple.address == 0xff40
                && tuple.value & 0x80 == 0
        })
    })
}

const fn ppu_position(devices: zksm83_core::DmgDeviceState) -> u64 {
    devices.ppu_line() as u64 * 456 + devices.ppu_dot() as u64
}

const fn dac_address(channel: u8) -> u16 {
    match channel {
        0 => 0xff12,
        1 => 0xff17,
        2 => 0xff1a,
        _ => 0xff21,
    }
}

const fn dac_channel(address: u16) -> Option<u8> {
    match address {
        0xff12 => Some(0),
        0xff17 => Some(1),
        0xff1a => Some(2),
        0xff21 => Some(3),
        _ => None,
    }
}

const fn trigger_channel(address: u16) -> Option<u8> {
    match address {
        0xff14 => Some(0),
        0xff19 => Some(1),
        0xff1e => Some(2),
        0xff23 => Some(3),
        _ => None,
    }
}

const fn dac_enabled(channel: u8, value: u8) -> bool {
    if channel == 2 {
        value & 0x80 != 0
    } else {
        value & 0xf8 != 0
    }
}

pub(super) fn append_joypad_witness(
    columns: &mut [Vec<u64>],
    before: VmState,
    row: Option<&TraceRow>,
) -> Result<(), NativeTraceError> {
    let [mut select, mut buttons] = before.dmg_devices().joypad_pack().to_le_bytes();
    append_joypad_bits(columns, TRACE_BEFORE_JOYPAD_BITS_START, select, buttons)?;
    let mut interrupt = before.dmg_devices().interrupt_request() & 0x10 != 0;
    if row.is_some_and(|row| {
        row.effects().kind() == StepKind::InterruptDispatch(DmgInterrupt::Joypad)
    }) {
        interrupt = false;
    }
    let events = row.map_or(&[][..], |row| row.effects().ordered_bus_events());
    for slot in 0..TRACE_BUS_SLOTS {
        let visible_before = visible_joypad(select, buttons);
        let event = events.get(slot);
        let mut joypad_write = false;
        if let Some(event) = event {
            let tuple = event.transcript_event();
            if event.kind() == BusEventKind::DmgJoypadRead {
                buttons = tuple.auxiliary;
            } else if event.kind() == BusEventKind::DmgMmioWrite && tuple.address == 0xff00 {
                select = tuple.value & 0x30;
                joypad_write = true;
            }
            if event.kind() == BusEventKind::DmgMmioWrite && tuple.address == 0xff0f {
                interrupt = tuple.value & 0x10 != 0;
            }
        }
        let visible_after = visible_joypad(select, buttons);
        let falls = (visible_before & !visible_after) & 0x0f;
        interrupt |= falls != 0;
        append_joypad_bits(
            columns,
            TRACE_JOYPAD_STAGE_BITS_START + slot * TRACE_JOYPAD_STAGE_WIDTH,
            select,
            buttons,
        )?;
        super::append(
            columns,
            TRACE_JOYPAD_WRITE_START + slot,
            u64::from(joypad_write),
        )?;
        super::append(
            columns,
            TRACE_JOYPAD_FALL_NONE_START + slot * 2,
            u64::from(falls & 0x03 == 0),
        )?;
        super::append(
            columns,
            TRACE_JOYPAD_FALL_NONE_START + slot * 2 + 1,
            u64::from(falls & 0x0c == 0),
        )?;
        super::append(
            columns,
            TRACE_JOYPAD_IF_BIT_START + slot,
            u64::from(interrupt),
        )?;
    }
    Ok(())
}

fn append_joypad_bits(
    columns: &mut [Vec<u64>],
    start: usize,
    select: u8,
    buttons: u8,
) -> Result<(), NativeTraceError> {
    super::append(columns, start, u64::from((select >> 4) & 1))?;
    super::append(columns, start + 1, u64::from((select >> 5) & 1))?;
    append_bits(columns, start + 2, u64::from(buttons), 8)
}

const fn visible_joypad(select: u8, buttons: u8) -> u8 {
    let mut low = 0x0f;
    if select & 0x10 == 0 {
        low &= !(buttons & 0x0f);
    }
    if select & 0x20 == 0 {
        low &= !((buttons >> 4) & 0x0f);
    }
    0xc0 | select | low
}
