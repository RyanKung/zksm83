//! Pure MBC3 mapper state for supported cartridge profiles.

use serde::{Deserialize, Serialize};
use thiserror::Error;

const ROM_BANK_BYTES: u32 = 0x4000;
const SRAM_PHYSICAL_BASE: u32 = 0x1_0000;
const SRAM_BANK_BYTES: u32 = 0x2000;

/// Supported MBC3 ROM sizes bound by native proof profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Mbc3RomSize {
    /// Sixteen 16-KiB ROM banks.
    Rom256KiB,
    /// Sixty-four 16-KiB ROM banks.
    Rom1MiB,
}

impl Mbc3RomSize {
    /// Returns the exact logical cartridge ROM byte length.
    #[must_use]
    pub const fn byte_length(self) -> usize {
        match self {
            Self::Rom256KiB => 256 * 1024,
            Self::Rom1MiB => 1024 * 1024,
        }
    }

    /// Returns the maximum effective switchable ROM bank.
    #[must_use]
    pub const fn max_bank(self) -> u8 {
        match self {
            Self::Rom256KiB => 0x0f,
            Self::Rom1MiB => 0x3f,
        }
    }

    const fn bank_mask(self) -> u8 {
        self.max_bank()
    }
}

/// Whether the cartridge header/profile exposes MBC3 RTC registers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Mbc3RtcMode {
    /// MBC3 without timer registers.
    NoRtc,
    /// MBC3 timer-capable header; RTC register execution remains fail-closed.
    RtcCapable,
}

/// Supported proof-time MBC3 cartridge profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Mbc3CartridgeProfile {
    rom_size: Mbc3RomSize,
    rtc: Mbc3RtcMode,
}

impl Mbc3CartridgeProfile {
    /// Returns the legacy one-MiB, no-RTC profile.
    #[must_use]
    pub const fn one_mib_no_rtc() -> Self {
        Self {
            rom_size: Mbc3RomSize::Rom1MiB,
            rtc: Mbc3RtcMode::NoRtc,
        }
    }

    /// Constructs a supported MBC3 cartridge profile.
    #[must_use]
    pub const fn new(rom_size: Mbc3RomSize, rtc: Mbc3RtcMode) -> Self {
        Self { rom_size, rtc }
    }

    /// Returns the proof-bound logical ROM size.
    #[must_use]
    pub const fn rom_size(self) -> Mbc3RomSize {
        self.rom_size
    }

    /// Returns whether this profile admits RTC-capable cartridge headers.
    #[must_use]
    pub const fn rtc(self) -> Mbc3RtcMode {
        self.rtc
    }
}

/// Decoded target of an MBC3 external-memory-window access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mbc3ExternalWindow {
    /// Battery-backed SRAM physical byte index.
    Ram(u32),
    /// Selected RTC register number. The current VM has no RTC register state.
    RtcRegister(u8),
    /// Disabled RAM, invalid selection, or closed external window.
    Unavailable,
}

/// MBC3 register state carried by every VM transition.
///
/// The current state stores only the register file common to the supported
/// profiles. ROM-size and RTC availability are selected by the machine profile.
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
        Self::from_profile_parts(
            Mbc3CartridgeProfile::one_mib_no_rtc(),
            ram_enabled,
            rom_bank,
            ram_rtc_select,
        )
    }

    /// Constructs a validated mapper snapshot for a concrete cartridge profile.
    pub const fn from_profile_parts(
        profile: Mbc3CartridgeProfile,
        ram_enabled: bool,
        rom_bank: u8,
        ram_rtc_select: u8,
    ) -> Result<Self, Mbc3StateError> {
        if rom_bank == 0 || rom_bank > profile.rom_size().max_bank() {
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

    /// Returns the effective ROM bank in the switchable window.
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
        self.map_rom_for(Mbc3CartridgeProfile::one_mib_no_rtc(), address)
    }

    /// Maps a CPU ROM address to its physical committed byte index.
    #[must_use]
    pub fn map_rom_for(self, _profile: Mbc3CartridgeProfile, address: u16) -> u32 {
        if address < 0x4000 {
            u32::from(address)
        } else {
            u32::from(self.rom_bank) * ROM_BANK_BYTES + (u32::from(address) - ROM_BANK_BYTES)
        }
    }

    /// Maps the external-RAM window when RAM is enabled and bank 0 through 3 is selected.
    #[must_use]
    pub fn map_ram(self, address: u16) -> Option<u32> {
        match self.external_window_for(Mbc3CartridgeProfile::one_mib_no_rtc(), address) {
            Mbc3ExternalWindow::Ram(physical) => Some(physical),
            Mbc3ExternalWindow::RtcRegister(_) | Mbc3ExternalWindow::Unavailable => None,
        }
    }

    /// Classifies a CPU access in the external-RAM/RTC address window.
    #[must_use]
    pub fn external_window_for(
        self,
        profile: Mbc3CartridgeProfile,
        address: u16,
    ) -> Mbc3ExternalWindow {
        if !self.ram_enabled || !(0xa000..=0xbfff).contains(&address) {
            return Mbc3ExternalWindow::Unavailable;
        }
        if self.ram_rtc_select <= 3 {
            return Mbc3ExternalWindow::Ram(
                SRAM_PHYSICAL_BASE
                    + u32::from(self.ram_rtc_select) * SRAM_BANK_BYTES
                    + (u32::from(address) - 0xa000),
            );
        }
        if profile.rtc() == Mbc3RtcMode::RtcCapable && (0x08..=0x0c).contains(&self.ram_rtc_select)
        {
            return Mbc3ExternalWindow::RtcRegister(self.ram_rtc_select);
        }
        Mbc3ExternalWindow::Unavailable
    }

    #[cfg(test)]
    const fn apply_control_write(&mut self, address: u16, value: u8) {
        self.apply_control_write_for(Mbc3CartridgeProfile::one_mib_no_rtc(), address, value);
    }

    pub(crate) const fn apply_control_write_for(
        &mut self,
        profile: Mbc3CartridgeProfile,
        address: u16,
        value: u8,
    ) {
        match address {
            0x0000..=0x1fff => self.ram_enabled = value & 0x0f == 0x0a,
            0x2000..=0x3fff => {
                let selected = value & profile.rom_size().bank_mask();
                self.rom_bank = if selected == 0 { 1 } else { selected };
            }
            0x4000..=0x5fff => self.ram_rtc_select = value & 0x0f,
            0x6000..=0x7fff | 0x8000..=u16::MAX => {}
        }
    }
}

/// Invalid construction of an MBC3 mapper state.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum Mbc3StateError {
    /// ROM bank zero is remapped to one and profile-specific banks are bounded.
    #[error("MBC3 ROM bank {rom_bank} is outside the cartridge profile")]
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
    use super::{Mbc3CartridgeProfile, Mbc3ExternalWindow, Mbc3RomSize, Mbc3RtcMode, Mbc3State};

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
    fn smaller_profile_masks_rom_bank_to_sixteen_banks() {
        let profile = Mbc3CartridgeProfile::new(Mbc3RomSize::Rom256KiB, Mbc3RtcMode::RtcCapable);
        let mut state = Mbc3State::profile_initial();
        state.apply_control_write_for(profile, 0x2000, 0xff);
        assert_eq!(state.rom_bank(), 15);
        assert_eq!(state.map_rom_for(profile, 0x4000), 0x3_c000);

        state.apply_control_write_for(profile, 0x2000, 0x10);
        assert_eq!(state.rom_bank(), 1);
    }

    #[test]
    fn rtc_register_selection_is_explicitly_classified() -> Result<(), Box<dyn std::error::Error>> {
        let profile = Mbc3CartridgeProfile::new(Mbc3RomSize::Rom256KiB, Mbc3RtcMode::RtcCapable);
        let state = Mbc3State::from_profile_parts(profile, true, 1, 0x08)?;
        assert_eq!(
            state.external_window_for(profile, 0xa123),
            Mbc3ExternalWindow::RtcRegister(0x08)
        );

        let no_rtc = Mbc3CartridgeProfile::new(Mbc3RomSize::Rom256KiB, Mbc3RtcMode::NoRtc);
        assert_eq!(
            state.external_window_for(no_rtc, 0xa123),
            Mbc3ExternalWindow::Unavailable
        );
        Ok(())
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
