//! Fold-carried DMG APU register and power-control state.

use serde::{Deserialize, Serialize};

const REGISTER_START: u16 = 0xff10;
const REGISTER_END: u16 = 0xff26;
const WAVE_START: u16 = 0xff30;
const WAVE_END: u16 = 0xff3f;

/// CPU-visible APU registers, channel status, and wave RAM.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DmgApuState {
    registers: [u8; 23],
    wave_ram: [u8; 16],
}

impl DmgApuState {
    /// Returns a powered-off zero state for the clean-core profile.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            registers: [0; 23],
            wave_ram: [0; 16],
        }
    }

    /// Returns the original-DMG register state left by the boot ROM.
    #[must_use]
    pub const fn dmg_post_boot() -> Self {
        Self {
            registers: [
                0, 0x80, 0xf3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x77, 0xf3, 0x81,
            ],
            wave_ram: [0; 16],
        }
    }

    /// Reads an APU register, unused APU byte, or wave-RAM byte.
    #[must_use]
    pub fn read(self, address: u16) -> Option<u8> {
        if (0xff27..=0xff2f).contains(&address) {
            return Some(0xff);
        }
        if (WAVE_START..=WAVE_END).contains(&address) {
            return self.wave_byte(address);
        }
        let stored = self.register_byte(address)?;
        Some(stored | read_mask(address))
    }

    /// Applies one APU write and returns the prior CPU-visible byte.
    pub fn write(&mut self, address: u16, value: u8) -> Option<u8> {
        let before = self.read(address)?;
        if (0xff27..=0xff2f).contains(&address) {
            return Some(before);
        }
        if (WAVE_START..=WAVE_END).contains(&address) {
            self.set_wave_byte(address, value)?;
            return Some(before);
        }
        if address == 0xff26 {
            self.write_power(value);
            return Some(before);
        }
        if !self.powered() && !is_length_register(address) {
            return Some(before);
        }
        let stored = value & !read_mask(address);
        self.set_register_byte(address, stored)?;
        self.apply_dac_and_trigger(address, value);
        Some(before)
    }

    /// Packs FF10-FF17 in ascending-address little-endian order.
    #[must_use]
    pub fn control_low_pack(self) -> u64 {
        pack_eight(self.registers.get(0..8))
    }

    /// Packs FF18-FF1F in ascending-address little-endian order.
    #[must_use]
    pub fn control_high_pack(self) -> u64 {
        pack_eight(self.registers.get(8..16))
    }

    /// Packs FF20-FF26 in ascending-address little-endian order.
    #[must_use]
    pub fn mixer_pack(self) -> u64 {
        pack_eight(self.registers.get(16..23))
    }

    /// Packs FF30-FF37 in ascending-address little-endian order.
    #[must_use]
    pub fn wave_low_pack(self) -> u64 {
        pack_eight(self.wave_ram.get(0..8))
    }

    /// Packs FF38-FF3F in ascending-address little-endian order.
    #[must_use]
    pub fn wave_high_pack(self) -> u64 {
        pack_eight(self.wave_ram.get(8..16))
    }

    fn powered(self) -> bool {
        self.register_byte(0xff26)
            .is_some_and(|value| value & 0x80 != 0)
    }

    fn write_power(&mut self, value: u8) {
        if value & 0x80 == 0 {
            self.registers.fill(0);
        } else if let Some(master) = self.registers.get_mut(22) {
            *master |= 0x80;
        }
    }

    fn apply_dac_and_trigger(&mut self, address: u16, value: u8) {
        if let Some(channel) = dac_register_channel(address)
            && value & 0xf8 == 0
        {
            self.set_channel_active(channel, false);
        }
        if address == 0xff1a && value & 0x80 == 0 {
            self.set_channel_active(2, false);
        }
        if let Some(channel) = trigger_register_channel(address)
            && value & 0x80 != 0
            && self.channel_dac_enabled(channel)
        {
            self.set_channel_active(channel, true);
        }
    }

    fn channel_dac_enabled(self, channel: u8) -> bool {
        let address = match channel {
            0 => 0xff12,
            1 => 0xff17,
            2 => 0xff1a,
            _ => 0xff21,
        };
        self.register_byte(address).is_some_and(|value| {
            if channel == 2 {
                value & 0x80 != 0
            } else {
                value & 0xf8 != 0
            }
        })
    }

    fn set_channel_active(&mut self, channel: u8, active: bool) {
        if let Some(master) = self.registers.get_mut(22) {
            let mask = 1_u8 << channel;
            *master = if active {
                *master | mask
            } else {
                *master & !mask
            };
        }
    }

    fn register_byte(self, address: u16) -> Option<u8> {
        let offset = address.checked_sub(REGISTER_START)?;
        if address > REGISTER_END {
            return None;
        }
        self.registers.get(usize::from(offset)).copied()
    }

    fn set_register_byte(&mut self, address: u16, value: u8) -> Option<()> {
        let offset = address.checked_sub(REGISTER_START)?;
        if address > REGISTER_END {
            return None;
        }
        *self.registers.get_mut(usize::from(offset))? = value;
        Some(())
    }

    fn wave_byte(self, address: u16) -> Option<u8> {
        let offset = address.checked_sub(WAVE_START)?;
        self.wave_ram.get(usize::from(offset)).copied()
    }

    fn set_wave_byte(&mut self, address: u16, value: u8) -> Option<()> {
        let offset = address.checked_sub(WAVE_START)?;
        *self.wave_ram.get_mut(usize::from(offset))? = value;
        Some(())
    }
}

impl Default for DmgApuState {
    fn default() -> Self {
        Self::empty()
    }
}

/// Returns bits that read as one and are not stored by the control relation.
#[must_use]
pub const fn read_mask(address: u16) -> u8 {
    match address {
        0xff10 => 0x80,
        0xff11 | 0xff16 => 0x3f,
        0xff13 | 0xff15 | 0xff18 | 0xff1b | 0xff1d | 0xff1f | 0xff20 => 0xff,
        0xff14 | 0xff19 | 0xff1e | 0xff23 => 0xbf,
        0xff1a => 0x7f,
        0xff1c => 0x9f,
        0xff26 => 0x70,
        _ => 0,
    }
}

fn is_length_register(address: u16) -> bool {
    matches!(address, 0xff11 | 0xff16 | 0xff1b | 0xff20)
}

fn dac_register_channel(address: u16) -> Option<u8> {
    match address {
        0xff12 => Some(0),
        0xff17 => Some(1),
        0xff21 => Some(3),
        _ => None,
    }
}

fn trigger_register_channel(address: u16) -> Option<u8> {
    match address {
        0xff14 => Some(0),
        0xff19 => Some(1),
        0xff1e => Some(2),
        0xff23 => Some(3),
        _ => None,
    }
}

fn pack_eight(bytes: Option<&[u8]>) -> u64 {
    let mut packed = [0_u8; 8];
    if let Some(bytes) = bytes {
        for (target, source) in packed.iter_mut().zip(bytes) {
            *target = *source;
        }
    }
    u64::from_le_bytes(packed)
}

#[cfg(test)]
mod tests {
    use super::DmgApuState;

    #[test]
    fn post_boot_registers_match_visible_dmg_values() {
        let apu = DmgApuState::dmg_post_boot();
        assert_eq!(apu.read(0xff11), Some(0xbf));
        assert_eq!(apu.read(0xff12), Some(0xf3));
        assert_eq!(apu.read(0xff24), Some(0x77));
        assert_eq!(apu.read(0xff25), Some(0xf3));
        assert_eq!(apu.read(0xff26), Some(0xf1));
    }

    #[test]
    fn power_off_clears_control_but_preserves_wave_ram() {
        let mut apu = DmgApuState::dmg_post_boot();
        assert_eq!(apu.write(0xff30, 0x42), Some(0));
        assert_eq!(apu.write(0xff26, 0), Some(0xf1));
        assert_eq!(apu.read(0xff12), Some(0));
        assert_eq!(apu.read(0xff24), Some(0));
        assert_eq!(apu.read(0xff26), Some(0x70));
        assert_eq!(apu.read(0xff30), Some(0x42));
    }

    #[test]
    fn trigger_and_dac_control_update_channel_status() {
        let mut apu = DmgApuState::dmg_post_boot();
        let _prior = apu.write(0xff17, 0xf0);
        let _prior = apu.write(0xff19, 0x80);
        assert_eq!(apu.read(0xff26), Some(0xf3));
        let _prior = apu.write(0xff17, 0);
        assert_eq!(apu.read(0xff26), Some(0xf1));
    }
}
