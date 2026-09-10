//! Pure MBC3 mapper state for the one-MiB, no-RTC cartridge profile.

use serde::{Deserialize, Serialize};
use thiserror::Error;

const ROM_BANK_BYTES: u32 = 0x4000;
const ROM_BANK_MASK: u8 = 0x3f;
const SRAM_PHYSICAL_BASE: u32 = 0x1_0000;
const SRAM_BANK_BYTES: u32 = 0x2000;

/// MBC3 register state carried by every VM transition.
///
/// This first cartridge profile matches Pokémon Blue: one MiB of ROM, four
/// 8-KiB SRAM banks, battery-backed RAM, and no real-time clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Mbc3State {
    ram_enabled: bool,
    rom_bank: u8,
    ram_rtc_select: u8,
}

impl Mbc3State {
    /// Returns the power-on mapper state.
    #[must_use]
    pub const fn profile_initial() -> Self {
        Self {
            ram_enabled: false,
            rom_bank: 1,
            ram_rtc_select: 0,
        }
    }

    /// Constructs a validated mapper snapshot.
    pub const fn from_parts(
        ram_enabled: bool,
        rom_bank: u8,
        ram_rtc_select: u8,
    ) -> Result<Self, Mbc3StateError> {
        if rom_bank == 0 || rom_bank > ROM_BANK_MASK {
            return Err(Mbc3StateError::InvalidRomBank { rom_bank });
        }
        if ram_rtc_select > 0x0f {
            return Err(Mbc3StateError::InvalidRamRtcSelect { ram_rtc_select });
        }
        Ok(Self {
            ram_enabled,
            rom_bank,
            ram_rtc_select,
        })
    }

    /// Returns whether external cartridge RAM is enabled.
    #[must_use]
    pub const fn ram_enabled(self) -> bool {
        self.ram_enabled
    }

    /// Returns the effective one-MiB ROM bank in the switchable window.
    #[must_use]
    pub const fn rom_bank(self) -> u8 {
        self.rom_bank
    }

    /// Returns the four-bit RAM-bank or RTC-register selection.
    #[must_use]
    pub const fn ram_rtc_select(self) -> u8 {
        self.ram_rtc_select
    }

    /// Maps a CPU ROM address to its physical committed byte index.
    #[must_use]
    pub fn map_rom(self, address: u16) -> u32 {
        if address < 0x4000 {
            u32::from(address)
        } else {
            u32::from(self.rom_bank) * ROM_BANK_BYTES + (u32::from(address) - ROM_BANK_BYTES)
        }
    }

    /// Maps the external-RAM window when RAM is enabled and bank 0 through 3 is selected.
    #[must_use]
    pub fn map_ram(self, address: u16) -> Option<u32> {
        if !self.ram_enabled || self.ram_rtc_select > 3 || !(0xa000..=0xbfff).contains(&address) {
            return None;
        }
        Some(
            SRAM_PHYSICAL_BASE
                + u32::from(self.ram_rtc_select) * SRAM_BANK_BYTES
                + (u32::from(address) - 0xa000),
        )
    }

    pub(crate) const fn apply_control_write(&mut self, address: u16, value: u8) {
        match address {
            0x0000..=0x1fff => self.ram_enabled = value & 0x0f == 0x0a,
            0x2000..=0x3fff => {
                let selected = value & ROM_BANK_MASK;
                self.rom_bank = if selected == 0 { 1 } else { selected };
            }
            0x4000..=0x5fff => self.ram_rtc_select = value & 0x0f,
            0x6000..=0x7fff | 0x8000..=u16::MAX => {}
        }
    }
}

/// Invalid construction of a one-MiB MBC3 mapper state.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum Mbc3StateError {
    /// ROM bank zero is remapped to one and the one-MiB profile has 64 banks.
    #[error("MBC3 ROM bank {rom_bank} is outside 1..=63")]
    InvalidRomBank {
        /// Rejected effective ROM bank.
        rom_bank: u8,
    },
    /// The RAM/RTC selection register is four bits wide.
    #[error("MBC3 RAM/RTC selection 0x{ram_rtc_select:02x} exceeds four bits")]
    InvalidRamRtcSelect {
        /// Rejected selection register.
        ram_rtc_select: u8,
    },
}

#[cfg(test)]
mod tests {
    use super::Mbc3State;

    #[test]
    fn control_register_boundaries_preserve_mapper_invariants() {
        let mut state = Mbc3State::profile_initial();
        state.apply_control_write(0x0000, 0x1a);
        assert!(state.ram_enabled());
        state.apply_control_write(0x1fff, 0x00);
        assert!(!state.ram_enabled());

        state.apply_control_write(0x2000, 0x00);
        assert_eq!(state.rom_bank(), 1);
        state.apply_control_write(0x3fff, 0xff);
        assert_eq!(state.rom_bank(), 63);

        state.apply_control_write(0x4000, 0xff);
        assert_eq!(state.ram_rtc_select(), 15);
        let before_latch = state;
        state.apply_control_write(0x6000, 1);
        assert_eq!(state, before_latch);
    }

    #[test]
    fn logical_windows_map_to_distinct_physical_banks() -> Result<(), Box<dyn std::error::Error>> {
        let bank_two = Mbc3State::from_parts(true, 2, 1)?;
        assert_eq!(bank_two.map_rom(0x0000), 0x0000);
        assert_eq!(bank_two.map_rom(0x4000), 0x8000);
        assert_eq!(bank_two.map_rom(0x7fff), 0xbfff);
        assert_eq!(bank_two.map_ram(0xa000), Some(0x1_2000));
        assert_eq!(bank_two.map_ram(0xbfff), Some(0x1_3fff));
        Ok(())
    }
}
