//! DMG divider and programmable-timer state.

use serde::{Deserialize, Serialize};

const TAC_UNUSED: u8 = 0xf8;
const TIMER_INTERRUPT: u8 = 0x04;

/// Fold-carried state of the DMG divider and TIMA pipeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DmgTimerState {
    raw_div: u16,
    counter: u8,
    modulo: u8,
    control: u8,
    edge_latch: bool,
    /// Zero means idle; `1..=5` encode overflow ticks `0..=4`.
    reload_phase: u8,
}

impl DmgTimerState {
    /// Returns a timer-neutral state for the clean-core profile.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            raw_div: 0,
            counter: 0,
            modulo: 0,
            control: 0,
            edge_latch: false,
            reload_phase: 0,
        }
    }

    /// Returns the canonical original-DMG state after its boot ROM exits.
    #[must_use]
    pub const fn dmg_post_boot() -> Self {
        Self {
            raw_div: 0xabcc,
            counter: 0,
            modulo: 0,
            control: 0,
            edge_latch: false,
            reload_phase: 0,
        }
    }

    /// Returns the internal 16-bit divider, not only its visible high byte.
    #[must_use]
    pub const fn raw_div(self) -> u16 {
        self.raw_div
    }

    /// Returns TIMA's stored counter byte.
    #[must_use]
    pub const fn counter(self) -> u8 {
        self.counter
    }

    /// Returns TMA.
    #[must_use]
    pub const fn modulo(self) -> u8 {
        self.modulo
    }

    /// Returns the three stored TAC bits.
    #[must_use]
    pub const fn control(self) -> u8 {
        self.control
    }

    /// Returns the falling-edge detector latch.
    #[must_use]
    pub const fn edge_latch(self) -> bool {
        self.edge_latch
    }

    /// Returns the canonical reload-pipeline phase in `0..=5`.
    #[must_use]
    pub const fn reload_phase(self) -> u8 {
        self.reload_phase
    }

    /// Reads FF04 through FF07 using their CPU-visible encodings.
    #[must_use]
    pub const fn read(self, address: u16) -> Option<u8> {
        match address {
            0xff04 => Some((self.raw_div >> 8) as u8),
            0xff05 if self.reload_phase == 5 => Some(self.modulo),
            0xff05 => Some(self.counter),
            0xff06 => Some(self.modulo),
            0xff07 => Some(TAC_UNUSED | self.control),
            _ => None,
        }
    }

    /// Applies a timer-register write and returns the prior visible byte.
    pub fn write(&mut self, address: u16, value: u8) -> Option<u8> {
        let before = self.read(address)?;
        match address {
            0xff04 => self.raw_div = 0,
            0xff05 => self.write_counter(value),
            0xff06 => self.write_modulo(value),
            0xff07 => self.control = value & 0x07,
            _ => return None,
        }
        Some(before)
    }

    /// Advances the timer by T-cycles and returns the interrupt bits raised.
    pub fn advance_t_cycles(&mut self, ticks: u8) -> u8 {
        let mut requested = 0;
        for _ in 0..ticks {
            requested |= self.tick();
        }
        requested
    }

    /// Returns exact T-cycles until the next reload interrupt for a stable enabled timer.
    ///
    /// A recent DIV/TAC write can leave the stored edge latch intentionally different from
    /// the current detector input. That transient case returns `None` and must advance through
    /// the ordinary bounded path before this shortcut is considered.
    #[must_use]
    pub fn t_cycles_until_interrupt(self) -> Option<u32> {
        if self.control & 0x04 == 0
            || self.reload_phase != 0
            || self.edge_latch != self.detector_input()
        {
            return None;
        }
        let period = match self.control & 0x03 {
            0 => 1024_u32,
            1 => 16,
            2 => 64,
            _ => 256,
        };
        let remainder = u32::from(self.raw_div) & (period - 1);
        let first_falling_edge = period - remainder;
        let later_falling_edges = u32::from(u8::MAX - self.counter) * period;
        first_falling_edge
            .checked_add(later_falling_edges)?
            .checked_add(5)
    }

    fn tick(&mut self) -> u8 {
        let requested = self.advance_reload_pipeline();
        self.raw_div = self.raw_div.wrapping_add(1);
        let detector = self.detector_input();
        let falling = self.edge_latch && !detector;
        self.edge_latch = detector;
        if falling {
            self.increment_counter();
        }
        requested
    }

    fn advance_reload_pipeline(&mut self) -> u8 {
        if self.reload_phase == 5 {
            self.counter = self.modulo;
            self.reload_phase = 0;
            TIMER_INTERRUPT
        } else {
            if self.reload_phase != 0 {
                self.reload_phase += 1;
            }
            0
        }
    }

    fn increment_counter(&mut self) {
        if self.counter == u8::MAX {
            self.counter = 0;
            self.reload_phase = 1;
        } else {
            self.counter += 1;
        }
    }

    fn write_counter(&mut self, value: u8) {
        if self.reload_phase == 5 {
            self.counter = self.modulo;
        } else {
            self.counter = value;
            self.reload_phase = 0;
        }
    }

    fn write_modulo(&mut self, value: u8) {
        self.modulo = value;
        if self.reload_phase == 5 {
            self.counter = value;
        }
    }

    fn detector_input(self) -> bool {
        let mask = match self.control & 0x03 {
            0 => 1 << 9,
            1 => 1 << 3,
            2 => 1 << 5,
            _ => 1 << 7,
        };
        self.control & 0x04 != 0 && self.raw_div & mask != 0
    }
}

impl Default for DmgTimerState {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{DmgTimerState, TIMER_INTERRUPT};

    #[test]
    fn post_boot_divider_has_the_dmg_phase() {
        let timer = DmgTimerState::dmg_post_boot();
        assert_eq!(timer.raw_div(), 0xabcc);
        assert_eq!(timer.read(0xff04), Some(0xab));
        assert_eq!(timer.read(0xff07), Some(0xf8));
    }

    #[test]
    fn every_tac_frequency_counts_on_its_selected_falling_edge() {
        for (control, period) in [(4_u8, 1024_u16), (5, 16), (6, 64), (7, 256)] {
            let mut timer = DmgTimerState::empty();
            let _prior = timer.write(0xff07, control);
            for _ in 0..period {
                let _requested = timer.advance_t_cycles(1);
            }
            assert_eq!(timer.counter(), 1, "control={control}");
        }
    }

    #[test]
    fn div_write_preserves_the_edge_latch_and_triggers_falling_edge() {
        let mut timer = DmgTimerState::empty();
        let _prior = timer.write(0xff07, 5);
        let _requested = timer.advance_t_cycles(8);
        assert!(timer.edge_latch());
        assert_eq!(timer.write(0xff04, 0x55), Some(0));
        let _requested = timer.advance_t_cycles(1);
        assert_eq!(timer.counter(), 1);
    }

    #[test]
    fn overflow_is_visible_as_zero_before_modulo_reload_and_interrupt() {
        let mut timer = DmgTimerState::empty();
        let _prior = timer.write(0xff05, 0xff);
        let _prior = timer.write(0xff06, 0x42);
        let _prior = timer.write(0xff07, 5);
        let _requested = timer.advance_t_cycles(16);
        assert_eq!(timer.read(0xff05), Some(0));
        assert_eq!(timer.reload_phase(), 1);
        assert_eq!(timer.advance_t_cycles(4), 0);
        assert_eq!(timer.read(0xff05), Some(0x42));
        assert_eq!(timer.advance_t_cycles(1), 0x04);
        assert_eq!(timer.reload_phase(), 0);
        assert_eq!(timer.counter(), 0x42);
    }

    #[test]
    fn exact_interrupt_distance_matches_tick_simulation() -> Result<(), &'static str> {
        for (control, counter) in [(4_u8, 0), (5, 0xff), (6, 0x80), (7, 0xfe)] {
            let mut timer = DmgTimerState::empty();
            let _prior = timer.write(0xff05, counter);
            let _prior = timer.write(0xff07, control);
            let expected = timer
                .t_cycles_until_interrupt()
                .ok_or("fresh enabled timer has an unstable edge latch")?;
            let mut projected = timer;
            let mut elapsed = 0_u32;
            loop {
                elapsed += 1;
                if projected.advance_t_cycles(1) & TIMER_INTERRUPT != 0 {
                    break;
                }
            }
            assert_eq!(elapsed, expected, "control={control}, counter={counter}");
        }
        Ok(())
    }

    #[test]
    fn tima_write_aborts_pending_reload_except_on_reload_cycle() {
        let mut timer = DmgTimerState::empty();
        let _prior = timer.write(0xff05, 0xff);
        let _prior = timer.write(0xff07, 5);
        let _requested = timer.advance_t_cycles(16);
        assert_eq!(timer.write(0xff05, 0x77), Some(0));
        assert_eq!(timer.reload_phase(), 0);
        assert_eq!(timer.counter(), 0x77);
    }
}
