//! Address ownership for the first clean machine profile.

/// Typed owner of one address in `sm83-core-v1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressOwner {
    /// Immutable committed program ROM.
    Rom,
    /// Mutable committed byte memory.
    Memory,
    /// Declared byte input port.
    Input,
    /// Declared byte output port.
    Output,
    /// DMG memory-mapped device register.
    DmgMmio,
    /// DMG echo-RAM window, which aliases work RAM rather than owning storage.
    DmgEcho,
    /// Address with no declared owner in this profile.
    Unowned,
}

/// Input port address in `sm83-core-v1`.
pub const INPUT_PORT: u16 = 0xfff0;

/// Output port address in `sm83-core-v1`.
pub const OUTPUT_PORT: u16 = 0xfff1;

/// Returns the unique owner of an address in `sm83-core-v1`.
#[must_use]
pub const fn owner(address: u16) -> AddressOwner {
    match address {
        0x0000..=0x7fff => AddressOwner::Rom,
        0x8000..=0xffef => AddressOwner::Memory,
        INPUT_PORT => AddressOwner::Input,
        OUTPUT_PORT => AddressOwner::Output,
        _ => AddressOwner::Unowned,
    }
}

/// Returns the unique owner of an address in the DMG + MBC3 profile.
///
/// Cartridge RAM in `a000..=bfff` is refined by the mapper before this owner is
/// consulted. Echo RAM and MMIO remain distinct so neither can be mistaken for
/// independent mutable storage.
#[must_use]
pub const fn dmg_owner(address: u16) -> AddressOwner {
    match address {
        0x0000..=0x7fff => AddressOwner::Rom,
        0x8000..=0xdfff | 0xfe00..=0xfe9f | 0xff80..=0xfffe => AddressOwner::Memory,
        0xe000..=0xfdff => AddressOwner::DmgEcho,
        0xff00..=0xff7f | 0xffff => AddressOwner::DmgMmio,
        0xfea0..=0xfeff => AddressOwner::Unowned,
    }
}

#[cfg(test)]
mod tests {
    use super::{AddressOwner, dmg_owner};

    #[test]
    fn dmg_owner_keeps_aliases_and_devices_out_of_plain_memory() {
        assert_eq!(dmg_owner(0xdfff), AddressOwner::Memory);
        assert_eq!(dmg_owner(0xe000), AddressOwner::DmgEcho);
        assert_eq!(dmg_owner(0xfdff), AddressOwner::DmgEcho);
        assert_eq!(dmg_owner(0xfe00), AddressOwner::Memory);
        assert_eq!(dmg_owner(0xfea0), AddressOwner::Unowned);
        assert_eq!(dmg_owner(0xff00), AddressOwner::DmgMmio);
        assert_eq!(dmg_owner(0xff80), AddressOwner::Memory);
        assert_eq!(dmg_owner(0xffff), AddressOwner::DmgMmio);
    }
}
