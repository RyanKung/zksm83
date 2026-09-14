//! Typed DMG device state that participates in the pure VM relation.

use serde::{Deserialize, Serialize};

mod apu;
mod timer;

pub use apu::{DmgApuState, read_mask as apu_read_mask};
pub use timer::DmgTimerState;

const INTERRUPT_MASK: u8 = 0x1f;

/// One of the five priority-ordered DMG interrupt sources.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DmgInterrupt {
    /// LCD enters VBlank.
    VBlank,
    /// STAT interrupt line rises.
    LcdStat,
    /// TIMA reload requests service.
    Timer,
    /// Serial transfer completes.
    Serial,
    /// Selected joypad input line falls.
    Joypad,
}

impl DmgInterrupt {
    /// Returns the IF/IE bit selected by this interrupt.
    #[must_use]
    pub const fn bit(self) -> u8 {
        match self {
            Self::VBlank => 0,
            Self::LcdStat => 1,
            Self::Timer => 2,
            Self::Serial => 3,
            Self::Joypad => 4,
        }
    }

    /// Returns the CPU interrupt vector.
    #[must_use]
    pub const fn vector(self) -> u16 {
        match self {
            Self::VBlank => 0x40,
            Self::LcdStat => 0x48,
            Self::Timer => 0x50,
            Self::Serial => 0x58,
            Self::Joypad => 0x60,
        }
    }
}

/// Fold-carried DMG device snapshot.
///
/// This first device slice owns IF and IE. Later timer, PPU, joypad, serial,
/// and DMA additions extend this value rather than introducing ambient state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DmgDeviceState {
    interrupt_request: u8,
    interrupt_enable: u8,
    serial_data: u8,
    serial_control: u8,
    #[serde(default)]
    serial_cycles_remaining: u16,
    timer: DmgTimerState,
    apu: DmgApuState,
    lcd_control: u8,
    lcd_status_control: u8,
    scroll_y: u8,
    scroll_x: u8,
    background_palette: u8,
    object_palette_zero: u8,
    object_palette_one: u8,
    window_y: u8,
    window_x: u8,
    line_compare: u8,
    ppu_line: u8,
    ppu_dot: u16,
    joypad_select: u8,
    joypad_buttons: u8,
    #[serde(default)]
    dma_source_high: u8,
    #[serde(default)]
    dma_index: u8,
    #[serde(default)]
    dma_active: bool,
    #[serde(default)]
    dma_owed: u8,
}

impl DmgDeviceState {
    /// Returns a device-neutral state used by the synthetic clean-core profile.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            interrupt_request: 0,
            interrupt_enable: 0,
            serial_data: 0,
            serial_control: 0,
            serial_cycles_remaining: 0,
            timer: DmgTimerState::empty(),
            apu: DmgApuState::empty(),
            lcd_control: 0,
            lcd_status_control: 0,
            scroll_y: 0,
            scroll_x: 0,
            background_palette: 0,
            object_palette_zero: 0,
            object_palette_one: 0,
            window_y: 0,
            window_x: 0,
            line_compare: 0,
            ppu_line: 0,
            ppu_dot: 0,
            joypad_select: 0,
            joypad_buttons: 0,
            dma_source_high: 0,
            dma_index: 0,
            dma_active: false,
            dma_owed: 0,
        }
    }

    /// Returns the canonical DMG state immediately after the boot ROM exits.
    #[must_use]
    pub const fn dmg_post_boot() -> Self {
        Self {
            interrupt_request: 0x01,
            interrupt_enable: 0x00,
            serial_data: 0x00,
            serial_control: 0x7e,
            serial_cycles_remaining: 0,
            timer: DmgTimerState::dmg_post_boot(),
            apu: DmgApuState::dmg_post_boot(),
            lcd_control: 0x91,
            lcd_status_control: 0x00,
            scroll_y: 0x00,
            scroll_x: 0x00,
            background_palette: 0xfc,
            object_palette_zero: 0xff,
            object_palette_one: 0xff,
            window_y: 0x00,
            window_x: 0x00,
            line_compare: 0x00,
            ppu_line: 0,
            ppu_dot: 0,
            joypad_select: 0,
            joypad_buttons: 0,
            dma_source_high: 0,
            dma_index: 0,
            dma_active: false,
            dma_owed: 0,
        }
    }

    /// Returns the five stored IF request bits.
    #[must_use]
    pub const fn interrupt_request(self) -> u8 {
        self.interrupt_request
    }

    /// Returns the five stored IE enable bits.
    #[must_use]
    pub const fn interrupt_enable(self) -> u8 {
        self.interrupt_enable
    }

    /// Returns the highest-priority requested and enabled interrupt.
    #[must_use]
    pub const fn pending_interrupt(self) -> Option<DmgInterrupt> {
        let pending = self.interrupt_request & self.interrupt_enable;
        if pending & 0x01 != 0 {
            Some(DmgInterrupt::VBlank)
        } else if pending & 0x02 != 0 {
            Some(DmgInterrupt::LcdStat)
        } else if pending & 0x04 != 0 {
            Some(DmgInterrupt::Timer)
        } else if pending & 0x08 != 0 {
            Some(DmgInterrupt::Serial)
        } else if pending & 0x10 != 0 {
            Some(DmgInterrupt::Joypad)
        } else {
            None
        }
    }

    /// Clears the serviced IF request bit.
    pub(crate) fn acknowledge_interrupt(&mut self, interrupt: DmgInterrupt) {
        self.interrupt_request &= !(1 << interrupt.bit());
    }

    /// Returns the current PPU line in `0..=153`.
    #[must_use]
    pub const fn ppu_line(self) -> u8 {
        self.ppu_line
    }

    /// Returns the current dot within the 456-dot scanline.
    #[must_use]
    pub const fn ppu_dot(self) -> u16 {
        self.ppu_dot
    }

    /// Returns the complete fold-carried timer state.
    #[must_use]
    pub const fn timer(self) -> DmgTimerState {
        self.timer
    }

    /// Returns the fold-carried APU register and wave-RAM state.
    #[must_use]
    pub const fn apu(self) -> DmgApuState {
        self.apu
    }

    /// Packs P1 select bits and the last committed pressed-button mask.
    #[must_use]
    pub const fn joypad_pack(self) -> u16 {
        u16::from_le_bytes([self.joypad_select, self.joypad_buttons])
    }

    /// Returns the last raw P1 sample: directions in bits 0-3 and actions in bits 4-7.
    #[must_use]
    pub const fn joypad_buttons(self) -> u8 {
        self.joypad_buttons
    }

    /// Packs the OAM DMA source, byte cursor, active flag, and proof-serialization debt.
    #[must_use]
    pub const fn dma_pack(self) -> u32 {
        let active = if self.dma_active { 1 } else { 0 };
        u32::from_le_bytes([self.dma_source_high, self.dma_index, active, self.dma_owed])
    }

    /// Returns whether OAM DMA is currently transferring bytes.
    #[must_use]
    pub const fn dma_active(self) -> bool {
        self.dma_active
    }

    /// Returns DMA bytes whose concurrent copies must be serialized before another CPU step.
    #[must_use]
    pub const fn dma_owed(self) -> u8 {
        self.dma_owed
    }

    /// Returns the next OAM DMA byte cursor in `0..=160`.
    #[must_use]
    pub const fn dma_index(self) -> u8 {
        self.dma_index
    }

    /// Returns the current OAM DMA source byte address.
    #[must_use]
    pub const fn dma_source_address(self) -> u16 {
        (self.dma_source_high as u16) << 8 | self.dma_index as u16
    }

    /// Returns the current OAM DMA destination byte address.
    #[must_use]
    pub const fn dma_destination_address(self) -> u16 {
        0xfe00 | self.dma_index as u16
    }

    /// Records the copies concurrent with an already-timed CPU or machine step.
    pub(crate) fn schedule_dma_bytes(&mut self, m_cycles: u8, active_at_start: bool) {
        if !active_at_start {
            self.dma_owed = 0;
            return;
        }
        let remaining = 160_u8.saturating_sub(self.dma_index);
        self.dma_owed = m_cycles.min(remaining);
    }

    /// Advances the OAM DMA cursor after one authenticated serialized byte copy.
    pub(crate) fn complete_dma_byte(&mut self) {
        self.dma_owed = self.dma_owed.saturating_sub(1);
        if self.dma_index == 159 {
            self.dma_index = 160;
            self.dma_active = false;
        } else {
            self.dma_index = self.dma_index.saturating_add(1);
        }
    }

    /// Applies the next committed pressed-button mask and returns P1.
    pub fn sample_joypad(&mut self, buttons: u8) -> u8 {
        let before = self.visible_joypad();
        self.joypad_buttons = buttons;
        let after = self.visible_joypad();
        self.request_joypad_falling_edge(before, after);
        after
    }

    /// Reads an implemented interrupt register using its CPU-visible encoding.
    #[must_use]
    pub fn read_mmio(self, address: u16) -> Option<u8> {
        match address {
            0xff00 => Some(self.visible_joypad()),
            0xff01 => Some(self.serial_data),
            0xff02 => Some(self.serial_control),
            0xff04..=0xff07 => self.timer.read(address),
            0xff0f => Some(0xe0 | self.interrupt_request),
            0xff10..=0xff3f => self.apu.read(address),
            0xff40 => Some(self.lcd_control),
            0xff41 => Some(self.visible_lcd_status()),
            0xff42 => Some(self.scroll_y),
            0xff43 => Some(self.scroll_x),
            0xff44 => Some(self.ppu_line),
            0xff45 => Some(self.line_compare),
            0xff46 => Some(self.dma_source_high),
            0xff47 => Some(self.background_palette),
            0xff48 => Some(self.object_palette_zero),
            0xff49 => Some(self.object_palette_one),
            0xff4a => Some(self.window_y),
            0xff4b => Some(self.window_x),
            0xffff => Some(self.interrupt_enable),
            _ => None,
        }
    }

    /// Applies an implemented MMIO write and returns the prior visible byte.
    pub fn write_mmio(&mut self, address: u16, value: u8) -> Option<u8> {
        let before = self.read_mmio(address)?;
        let stat_before = self.stat_signal();
        match address {
            0xff00 => {
                self.joypad_select = value & 0x30;
                let after = self.visible_joypad();
                self.request_joypad_falling_edge(before, after);
            }
            0xff01 => self.serial_data = value,
            0xff02 => {
                self.serial_control = value;
                self.serial_cycles_remaining = if value & 0x81 == 0x81 { 4096 } else { 0 };
            }
            0xff04..=0xff07 => return self.timer.write(address, value),
            0xff0f => self.interrupt_request = value & INTERRUPT_MASK,
            0xff10..=0xff3f => return self.apu.write(address, value),
            0xff40 => {
                self.lcd_control = value;
                if !self.lcd_enabled() {
                    self.ppu_line = 0;
                    self.ppu_dot = 0;
                }
            }
            0xff41 => self.lcd_status_control = value & 0x78,
            0xff42 => self.scroll_y = value,
            0xff43 => self.scroll_x = value,
            0xff44 => {}
            0xff45 => self.line_compare = value,
            0xff46 => {
                self.dma_source_high = value;
                self.dma_index = 0;
                self.dma_active = true;
                self.dma_owed = 0;
            }
            0xff47 => self.background_palette = value,
            0xff48 => self.object_palette_zero = value,
            0xff49 => self.object_palette_one = value,
            0xff4a => self.window_y = value,
            0xff4b => self.window_x = value,
            0xffff => self.interrupt_enable = value & INTERRUPT_MASK,
            _ => return None,
        }
        if matches!(address, 0xff40 | 0xff41 | 0xff45) {
            self.request_stat_rising_edge(stat_before);
        }
        Some(before)
    }

    /// Packs the low MMIO group into the canonical little-endian fold word.
    #[must_use]
    pub const fn low_register_pack(self) -> u64 {
        u64::from_le_bytes([
            self.serial_data,
            self.serial_control,
            self.timer.modulo(),
            self.timer.control(),
            self.lcd_control,
            self.lcd_status_control,
            self.scroll_y,
            self.scroll_x,
        ])
    }

    /// Packs palette/window MMIO and the internal serial countdown into one fold word.
    #[must_use]
    pub const fn high_register_pack(self) -> u64 {
        u64::from_le_bytes([
            self.background_palette,
            self.object_palette_zero,
            self.object_palette_one,
            self.window_y,
            self.window_x,
            self.line_compare,
            self.serial_cycles_remaining.to_le_bytes()[0],
            self.serial_cycles_remaining.to_le_bytes()[1],
        ])
    }

    /// Advances instruction-clocked DMG PPU timing by the declared M-cycles.
    pub fn advance_m_cycles(&mut self, m_cycles: u8) {
        let t_cycles = m_cycles.saturating_mul(4);
        self.interrupt_request |= self.timer.advance_t_cycles(t_cycles);
        self.advance_serial_t_cycles(t_cycles);
        for _ in 0..t_cycles {
            self.advance_ppu_t_cycle();
        }
    }

    /// Returns the canonical 1-6 M-cycle HALT batch ending at the first enabled interrupt.
    #[must_use]
    pub fn halt_idle_m_cycles(self) -> u8 {
        let mut projected = self;
        for elapsed in 1..=6 {
            projected.advance_m_cycles(1);
            if projected.pending_interrupt().is_some() {
                return elapsed;
            }
        }
        6
    }

    /// Returns an exact long HALT skip to the next VBlank for the constrained quiet-device case.
    #[must_use]
    pub fn halt_until_vblank_m_cycles(self) -> Option<u16> {
        if self.pending_interrupt().is_some()
            || !self.lcd_enabled()
            || self.interrupt_enable & 0x01 == 0
            || self.interrupt_enable & 0x10 != 0
            || self.lcd_status_control != 0
            || self.timer.control() & 0x04 != 0
            || self.timer.reload_phase() != 0
            || self.timer.edge_latch()
            || self.serial_cycles_remaining != 0
            || self.serial_control & 0x80 != 0
            || self.dma_active
            || self.dma_owed != 0
        {
            return None;
        }
        const LINE_T_CYCLES: u32 = 456;
        const FRAME_T_CYCLES: u32 = 154 * LINE_T_CYCLES;
        const VBLANK_T_CYCLE: u32 = 144 * LINE_T_CYCLES;
        let position = u32::from(self.ppu_line) * LINE_T_CYCLES + u32::from(self.ppu_dot);
        let remaining = if position < VBLANK_T_CYCLE {
            VBLANK_T_CYCLE - position
        } else {
            FRAME_T_CYCLES - position + VBLANK_T_CYCLE
        };
        if remaining == 0 || remaining % 4 != 0 {
            return None;
        }
        u16::try_from(remaining / 4).ok()
    }

    /// Returns an exact long HALT skip to internal-clock serial completion when every other
    /// modeled device is quiet for the interval.
    #[must_use]
    pub fn halt_until_serial_m_cycles(self) -> Option<u16> {
        if self.pending_interrupt().is_some()
            || self.interrupt_enable & 0x08 == 0
            || self.lcd_enabled()
            || self.timer.control() & 0x04 != 0
            || self.timer.reload_phase() != 0
            || self.timer.edge_latch()
            || self.serial_control & 0x81 != 0x81
            || self.serial_cycles_remaining == 0
            || self.serial_cycles_remaining > 4096
            || !self.serial_cycles_remaining.is_multiple_of(4)
            || self.dma_active
            || self.dma_owed != 0
        {
            return None;
        }
        Some(self.serial_cycles_remaining / 4)
    }

    /// Returns an exact long HALT skip to the M-cycle containing the next timer interrupt when
    /// every other modeled device is quiet for the interval.
    #[must_use]
    pub fn halt_until_timer_m_cycles(self) -> Option<u32> {
        if self.pending_interrupt().is_some()
            || self.interrupt_enable & 0x04 == 0
            || self.lcd_enabled()
            || self.serial_cycles_remaining != 0
            || self.serial_control & 0x80 != 0
            || self.dma_active
            || self.dma_owed != 0
        {
            return None;
        }
        let t_cycles = self.timer.t_cycles_until_interrupt()?;
        t_cycles.checked_add(3).map(|rounded| rounded / 4)
    }

    pub(crate) fn advance_halt_until_vblank(&mut self, m_cycles: u16) {
        self.advance_quiet_long(u32::from(m_cycles));
    }

    pub(crate) fn advance_halt_until_serial(&mut self, m_cycles: u16) {
        self.advance_quiet_long(u32::from(m_cycles));
    }

    pub(crate) fn advance_halt_until_timer(&mut self, m_cycles: u32) {
        self.advance_quiet_long(m_cycles);
    }

    fn advance_quiet_long(&mut self, mut m_cycles: u32) {
        while m_cycles != 0 {
            let chunk = u8::try_from(m_cycles.min(63)).unwrap_or(63);
            self.advance_m_cycles(chunk);
            m_cycles -= u32::from(chunk);
        }
    }

    fn advance_serial_t_cycles(&mut self, t_cycles: u8) {
        if self.serial_cycles_remaining == 0 {
            return;
        }
        self.serial_cycles_remaining = self
            .serial_cycles_remaining
            .saturating_sub(u16::from(t_cycles));
        if self.serial_cycles_remaining == 0 {
            self.serial_control &= 0x7f;
            self.serial_data = 0xff;
            self.interrupt_request |= 0x08;
        }
    }

    /// Returns whether a CPU VRAM access is blocked in the current LCD mode.
    #[must_use]
    pub const fn cpu_vram_blocked(self) -> bool {
        self.lcd_enabled() && self.ppu_mode() == 3
    }

    /// Returns whether a CPU OAM access is blocked in the current LCD mode.
    #[must_use]
    pub const fn cpu_oam_blocked(self) -> bool {
        self.lcd_enabled() && matches!(self.ppu_mode(), 2 | 3)
    }

    fn advance_ppu_t_cycle(&mut self) {
        if !self.lcd_enabled() {
            self.ppu_line = 0;
            self.ppu_dot = 0;
            return;
        }
        let stat_before = self.stat_signal();
        self.ppu_dot += 1;
        if self.ppu_dot == 456 {
            self.ppu_dot = 0;
            self.ppu_line = if self.ppu_line == 153 {
                0
            } else {
                self.ppu_line + 1
            };
            if self.ppu_line == 144 {
                self.interrupt_request |= 0x01;
            }
        }
        self.request_stat_rising_edge(stat_before);
    }

    const fn lcd_enabled(self) -> bool {
        self.lcd_control & 0x80 != 0
    }

    const fn visible_lcd_status(self) -> u8 {
        let coincidence = if self.ppu_line == self.line_compare {
            0x04
        } else {
            0
        };
        0x80 | self.lcd_status_control | coincidence | self.ppu_mode()
    }

    const fn ppu_mode(self) -> u8 {
        if !self.lcd_enabled() {
            0
        } else if self.ppu_line >= 144 {
            1
        } else if self.ppu_dot < 80 {
            2
        } else if self.ppu_dot < 252 {
            3
        } else {
            0
        }
    }

    const fn stat_signal(self) -> bool {
        if !self.lcd_enabled() {
            return false;
        }
        let mode = self.ppu_mode();
        (self.lcd_status_control & 0x08 != 0 && mode == 0)
            || (self.lcd_status_control & 0x10 != 0 && mode == 1)
            || (self.lcd_status_control & 0x20 != 0 && mode == 2)
            || (self.lcd_status_control & 0x40 != 0 && self.ppu_line == self.line_compare)
    }

    fn request_stat_rising_edge(&mut self, before: bool) {
        if !before && self.stat_signal() {
            self.interrupt_request |= 0x02;
        }
    }

    const fn visible_joypad(self) -> u8 {
        let mut low = 0x0f;
        if self.joypad_select & 0x10 == 0 {
            low &= !(self.joypad_buttons & 0x0f);
        }
        if self.joypad_select & 0x20 == 0 {
            low &= !((self.joypad_buttons >> 4) & 0x0f);
        }
        0xc0 | self.joypad_select | low
    }

    fn request_joypad_falling_edge(&mut self, before: u8, after: u8) {
        if (before & !after) & 0x0f != 0 {
            self.interrupt_request |= 0x10;
        }
    }
}

impl Default for DmgDeviceState {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{DmgDeviceState, DmgInterrupt};

    #[test]
    fn interrupt_registers_mask_storage_and_preserve_visible_if_high_bits() {
        let mut state = DmgDeviceState::dmg_post_boot();
        assert_eq!(state.read_mmio(0xff0f), Some(0xe1));
        assert_eq!(state.write_mmio(0xff0f, 0xff), Some(0xe1));
        assert_eq!(state.interrupt_request(), 0x1f);
        assert_eq!(state.read_mmio(0xff0f), Some(0xff));
        assert_eq!(state.write_mmio(0xffff, 0xff), Some(0x00));
        assert_eq!(state.interrupt_enable(), 0x1f);
    }

    #[test]
    fn register_packs_bind_every_implemented_storage_byte() {
        let mut state = DmgDeviceState::dmg_post_boot();
        assert_eq!(
            state.low_register_pack().to_le_bytes(),
            [0x00, 0x7e, 0x00, 0x00, 0x91, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            state.high_register_pack().to_le_bytes(),
            [0xfc, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(state.write_mmio(0xff43, 0x42), Some(0x00));
        assert_eq!(state.read_mmio(0xff43), Some(0x42));
        assert_eq!(state.low_register_pack().to_le_bytes().last(), Some(&0x42));
    }

    #[test]
    fn ppu_clock_reaches_vblank_and_requests_interrupt() {
        let mut state = DmgDeviceState::dmg_post_boot();
        for _ in 0..16_416 {
            state.advance_m_cycles(1);
        }
        assert_eq!(state.ppu_line(), 144);
        assert_eq!(state.ppu_dot(), 0);
        assert_eq!(state.interrupt_request() & 1, 1);
        assert_eq!(state.read_mmio(0xff44), Some(144));
    }

    #[test]
    fn halt_idle_batch_stops_at_first_enabled_device_interrupt() {
        let mut state = DmgDeviceState::dmg_post_boot();
        for _ in 0..16_414 {
            state.advance_m_cycles(1);
        }
        assert_eq!((state.ppu_line(), state.ppu_dot()), (143, 448));
        assert_eq!(state.write_mmio(0xff0f, 0), Some(0xe1));
        assert_eq!(state.write_mmio(0xffff, 1), Some(0));
        assert_eq!(state.halt_idle_m_cycles(), 2);

        let mut projected = state;
        projected.advance_m_cycles(1);
        assert_eq!(projected.pending_interrupt(), None);
        projected.advance_m_cycles(1);
        assert_eq!(projected.pending_interrupt(), Some(DmgInterrupt::VBlank));
    }

    #[test]
    fn quiet_halt_can_advance_exactly_to_vblank() {
        let mut state = DmgDeviceState::dmg_post_boot();
        assert_eq!(state.write_mmio(0xff0f, 0), Some(0xe1));
        assert_eq!(state.write_mmio(0xffff, 1), Some(0));
        let elapsed = 16_416;
        assert_eq!(state.halt_until_vblank_m_cycles(), Some(elapsed));
        let mut reference = state;
        for _ in 0..elapsed {
            reference.advance_m_cycles(1);
        }
        state.advance_halt_until_vblank(elapsed);
        assert_eq!(state, reference);
        assert_eq!((state.ppu_line(), state.ppu_dot()), (144, 0));
        assert_eq!(state.pending_interrupt(), Some(DmgInterrupt::VBlank));
    }

    #[test]
    fn quiet_halt_can_advance_exactly_to_serial_completion() {
        let mut state = DmgDeviceState::dmg_post_boot();
        assert_eq!(state.write_mmio(0xff0f, 0), Some(0xe1));
        assert_eq!(state.write_mmio(0xffff, 0x08), Some(0));
        assert_eq!(state.write_mmio(0xff40, 0), Some(0x91));
        assert_eq!(state.write_mmio(0xff01, 0x12), Some(0));
        assert_eq!(state.write_mmio(0xff02, 0x81), Some(0x7e));
        assert_eq!(state.halt_until_serial_m_cycles(), Some(1024));
        let mut reference = state;
        for _ in 0..1024 {
            reference.advance_m_cycles(1);
        }
        state.advance_halt_until_serial(1024);
        assert_eq!(state, reference);
        assert_eq!(state.read_mmio(0xff01), Some(0xff));
        assert_eq!(state.read_mmio(0xff02), Some(0x01));
        assert_eq!(state.pending_interrupt(), Some(DmgInterrupt::Serial));
    }

    #[test]
    fn serial_long_halt_guard_fails_closed_on_competing_device_state() {
        let mut base = DmgDeviceState::dmg_post_boot();
        assert_eq!(base.write_mmio(0xff0f, 0), Some(0xe1));
        assert_eq!(base.write_mmio(0xffff, 0x08), Some(0));
        assert_eq!(base.write_mmio(0xff40, 0), Some(0x91));
        assert_eq!(base.write_mmio(0xff02, 0x81), Some(0x7e));
        assert_eq!(base.halt_until_serial_m_cycles(), Some(1024));

        let mut pending = base;
        assert_eq!(pending.write_mmio(0xff0f, 0x08), Some(0xe0));
        assert_eq!(pending.halt_until_serial_m_cycles(), None);
        let mut lcd = base;
        assert_eq!(lcd.write_mmio(0xff40, 0x80), Some(0));
        assert_eq!(lcd.halt_until_serial_m_cycles(), None);
        let mut timer = base;
        assert_eq!(timer.write_mmio(0xff07, 0x04), Some(0xf8));
        assert_eq!(timer.halt_until_serial_m_cycles(), None);
        let mut dma = base;
        assert_eq!(dma.write_mmio(0xff46, 0x12), Some(0));
        assert_eq!(dma.halt_until_serial_m_cycles(), None);
        let mut external = base;
        assert_eq!(external.write_mmio(0xff02, 0x80), Some(0x81));
        assert_eq!(external.halt_until_serial_m_cycles(), None);
    }

    #[test]
    fn quiet_halt_can_advance_to_the_m_cycle_containing_timer_interrupt() {
        let mut state = DmgDeviceState::dmg_post_boot();
        assert_eq!(state.write_mmio(0xff0f, 0), Some(0xe1));
        assert_eq!(state.write_mmio(0xffff, 0x04), Some(0));
        assert_eq!(state.write_mmio(0xff40, 0), Some(0x91));
        assert_eq!(state.write_mmio(0xff04, 0), Some(0xab));
        assert_eq!(state.write_mmio(0xff05, 0xff), Some(0));
        assert_eq!(state.write_mmio(0xff06, 0x42), Some(0));
        assert_eq!(state.write_mmio(0xff07, 0x05), Some(0xf8));
        assert_eq!(state.timer().t_cycles_until_interrupt(), Some(21));
        assert_eq!(state.halt_until_timer_m_cycles(), Some(6));
        let mut reference = state;
        for _ in 0..6 {
            reference.advance_m_cycles(1);
        }
        state.advance_halt_until_timer(6);
        assert_eq!(state, reference);
        assert_eq!(state.timer().counter(), 0x42);
        assert_eq!(state.timer().reload_phase(), 0);
        assert_eq!(state.pending_interrupt(), Some(DmgInterrupt::Timer));
    }

    #[test]
    fn stat_requests_only_on_composite_line_rising_edges() {
        let mut oam = DmgDeviceState::dmg_post_boot();
        assert_eq!(oam.write_mmio(0xff0f, 0), Some(0xe1));
        assert_eq!(oam.write_mmio(0xff41, 0x20), Some(0x86));
        assert_eq!(oam.interrupt_request() & 0x02, 0x02);

        let mut hblank = DmgDeviceState::dmg_post_boot();
        assert_eq!(hblank.write_mmio(0xff0f, 0), Some(0xe1));
        assert_eq!(hblank.write_mmio(0xff41, 0x08), Some(0x86));
        assert_eq!(hblank.interrupt_request() & 0x02, 0);
        hblank.advance_m_cycles(63);
        assert_eq!(hblank.ppu_dot(), 252);
        assert_eq!(hblank.interrupt_request() & 0x02, 0x02);
    }

    #[test]
    fn ppu_modes_expose_cpu_vram_and_oam_access_gates() {
        let mut state = DmgDeviceState::dmg_post_boot();
        assert!(!state.cpu_vram_blocked());
        assert!(state.cpu_oam_blocked());
        state.advance_m_cycles(20);
        assert!(state.cpu_vram_blocked());
        assert!(state.cpu_oam_blocked());
        state.advance_m_cycles(43);
        assert!(!state.cpu_vram_blocked());
        assert!(!state.cpu_oam_blocked());
    }

    #[test]
    fn internal_serial_transfer_completes_after_4096_t_cycles() {
        let mut state = DmgDeviceState::dmg_post_boot();
        assert_eq!(state.write_mmio(0xff0f, 0), Some(0xe1));
        assert_eq!(state.write_mmio(0xff01, 0x12), Some(0x00));
        assert_eq!(state.write_mmio(0xff02, 0x81), Some(0x7e));
        assert_eq!(
            &state.high_register_pack().to_le_bytes()[6..],
            &[0x00, 0x10]
        );
        for _ in 0..1023 {
            state.advance_m_cycles(1);
        }
        assert_eq!(state.interrupt_request() & 0x08, 0);
        assert_eq!(state.read_mmio(0xff02), Some(0x81));
        state.advance_m_cycles(1);
        assert_eq!(state.read_mmio(0xff01), Some(0xff));
        assert_eq!(state.read_mmio(0xff02), Some(0x01));
        assert_eq!(state.interrupt_request() & 0x08, 0x08);
        assert_eq!(
            &state.high_register_pack().to_le_bytes()[6..],
            &[0x00, 0x00]
        );
    }

    #[test]
    fn joypad_sample_is_active_low_and_requests_interrupt_on_falling_line() {
        let mut state = DmgDeviceState::dmg_post_boot();
        assert_eq!(state.read_mmio(0xff00), Some(0xcf));
        assert_eq!(state.sample_joypad(0x10), 0xce);
        assert_eq!(state.interrupt_request() & 0x10, 0x10);
        assert_eq!(state.joypad_buttons(), 0x10);
    }

    #[test]
    fn joypad_raw_groups_match_dmg_selection_lines() {
        let mut state = DmgDeviceState::dmg_post_boot();
        assert_eq!(state.write_mmio(0xff00, 0x20), Some(0xcf));
        assert_eq!(state.sample_joypad(0x80), 0xef);
        assert_eq!(state.write_mmio(0xff00, 0x10), Some(0xef));
        assert_eq!(state.read_mmio(0xff00), Some(0xd7));
        assert_eq!(state.sample_joypad(0x08), 0xdf);
        assert_eq!(state.write_mmio(0xff00, 0x20), Some(0xdf));
        assert_eq!(state.read_mmio(0xff00), Some(0xe7));
    }
}
