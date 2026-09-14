//! Backend-neutral scalar encoding of the complete SM83 semantic boundary.

use zksm83_core::VmState;

/// Number of canonical `u64` limbs in a native semantic state boundary.
pub const STATE_SCALAR_COUNT: usize = 38;

/// State-scalar index of the cumulative CPU machine-cycle counter.
pub const STATE_CPU_M_CYCLES_INDEX: usize = 12;
/// State-scalar index of the next committed private-input position.
pub const STATE_INPUT_NEXT_INDEX: usize = 16;
/// State-scalar index of the next committed public-output position.
pub const STATE_OUTPUT_NEXT_INDEX: usize = 17;
/// State-scalar index of the next ordered bus-transcript position.
pub const STATE_BUS_NEXT_INDEX: usize = 18;
/// State-scalar index of the next fixed-ISA transcript position.
pub const STATE_ISA_NEXT_INDEX: usize = 19;
/// State-scalar index of the immutable machine-profile discriminator.
pub const STATE_MACHINE_PROFILE_INDEX: usize = 20;
/// State-scalar index of the DMG interrupt-request mask.
pub const STATE_INTERRUPT_REQUEST_INDEX: usize = 21;
/// State-scalar index of the DMG interrupt-enable mask.
pub const STATE_INTERRUPT_ENABLE_INDEX: usize = 22;
/// State-scalar index of the packed low DMG MMIO registers.
pub const STATE_DMG_LOW_REGISTER_PACK_INDEX: usize = 23;
/// State-scalar index of the packed high DMG MMIO registers.
pub const STATE_DMG_HIGH_REGISTER_PACK_INDEX: usize = 24;
/// State-scalar index of the current PPU line.
pub const STATE_PPU_LINE_INDEX: usize = 25;
/// State-scalar index of the current PPU dot.
pub const STATE_PPU_DOT_INDEX: usize = 26;
/// State-scalar index of the timer divider.
pub const STATE_TIMER_DIV_INDEX: usize = 27;
/// State-scalar index of the timer counter.
pub const STATE_TIMER_COUNTER_INDEX: usize = 28;
/// State-scalar index of the timer reload phase.
pub const STATE_TIMER_RELOAD_PHASE_INDEX: usize = 29;
/// State-scalar index of the timer edge latch.
pub const STATE_TIMER_EDGE_LATCH_INDEX: usize = 30;
/// State-scalar index of the packed low APU control registers.
pub const STATE_APU_CONTROL_LOW_PACK_INDEX: usize = 31;
/// State-scalar index of the packed high APU control registers.
pub const STATE_APU_CONTROL_HIGH_PACK_INDEX: usize = 32;
/// State-scalar index of the packed APU mixer registers.
pub const STATE_APU_MIXER_PACK_INDEX: usize = 33;
/// State-scalar index of the packed low APU wave RAM.
pub const STATE_APU_WAVE_LOW_PACK_INDEX: usize = 34;
/// State-scalar index of the packed high APU wave RAM.
pub const STATE_APU_WAVE_HIGH_PACK_INDEX: usize = 35;
/// State-scalar index of the packed joypad state.
pub const STATE_JOYPAD_PACK_INDEX: usize = 36;
/// State-scalar index of the packed OAM DMA state.
pub const STATE_DMA_PACK_INDEX: usize = 37;

/// Canonical scalar names in the same order as [`encode_state_scalars`].
pub const STATE_SCALAR_NAMES: [&str; STATE_SCALAR_COUNT] = [
    "cpu_a",
    "cpu_b",
    "cpu_c",
    "cpu_d",
    "cpu_e",
    "cpu_h",
    "cpu_l",
    "cpu_flags",
    "cpu_pc",
    "cpu_sp",
    "cpu_ime",
    "cpu_run_state",
    "cpu_m_cycles",
    "mbc3_ram_enabled",
    "mbc3_rom_bank",
    "mbc3_ram_rtc_select",
    "input_next_index",
    "output_next_index",
    "bus_event_next_index",
    "isa_row_next_index",
    "machine_profile",
    "dmg_interrupt_request",
    "dmg_interrupt_enable",
    "dmg_low_register_pack",
    "dmg_high_register_pack",
    "dmg_ppu_line",
    "dmg_ppu_dot",
    "dmg_timer_div",
    "dmg_timer_counter",
    "dmg_timer_reload_phase",
    "dmg_timer_edge_latch",
    "dmg_apu_control_low_pack",
    "dmg_apu_control_high_pack",
    "dmg_apu_mixer_pack",
    "dmg_apu_wave_low_pack",
    "dmg_apu_wave_high_pack",
    "dmg_joypad_pack",
    "dmg_dma_pack",
];

/// Public, backend-neutral encoding of one complete SM83 semantic boundary.
///
/// Authentication state is carried by separate typed commitment identities;
/// these limbs contain exactly the state consumed by the native CPU/device
/// relation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeStateBoundary {
    scalars: [u64; STATE_SCALAR_COUNT],
}

impl NativeStateBoundary {
    /// Encodes one VM state in the frozen native boundary layout.
    #[must_use]
    pub fn from_vm_state(state: VmState) -> Self {
        Self {
            scalars: encode_state_scalars(state),
        }
    }

    /// Returns the canonical scalar limbs in protocol order.
    #[must_use]
    pub const fn scalars(&self) -> &[u64; STATE_SCALAR_COUNT] {
        &self.scalars
    }

    pub(crate) const fn from_scalars(scalars: [u64; STATE_SCALAR_COUNT]) -> Self {
        Self { scalars }
    }

    pub(crate) fn append_canonical_bytes(&self, target: &mut Vec<u8>) {
        for scalar in self.scalars {
            target.extend_from_slice(&scalar.to_le_bytes());
        }
    }
}

/// Encodes every non-authentication component of one VM state as canonical
/// `u64` limbs.
///
/// Witness-authentication roots are deliberately absent: the native relation replaces them
/// with typed Akita commitment identities at the receipt boundary. The ordered
/// input, output, bus, and ISA cursors remain semantic state and are included.
#[must_use]
pub fn encode_state_scalars(state: VmState) -> [u64; STATE_SCALAR_COUNT] {
    let cpu = state.cpu();
    let registers = cpu.registers();
    let mbc3 = state.mbc3();
    let devices = state.dmg_devices();
    let timer = devices.timer();
    let apu = devices.apu();

    [
        u64::from(registers.a),
        u64::from(registers.b),
        u64::from(registers.c),
        u64::from(registers.d),
        u64::from(registers.e),
        u64::from(registers.h),
        u64::from(registers.l),
        u64::from(cpu.flags().byte()),
        u64::from(cpu.pc()),
        u64::from(cpu.sp()),
        u64::from(cpu.ime().code()),
        u64::from(cpu.run_state().code()),
        cpu.m_cycles(),
        u64::from(mbc3.ram_enabled()),
        u64::from(mbc3.rom_bank()),
        u64::from(mbc3.ram_rtc_select()),
        state.input_log().next_index(),
        state.output_log().next_index(),
        state.bus_transcript().next_index(),
        state.isa_transcript().next_index(),
        u64::from(state.profile().code()),
        u64::from(devices.interrupt_request()),
        u64::from(devices.interrupt_enable()),
        devices.low_register_pack(),
        devices.high_register_pack(),
        u64::from(devices.ppu_line()),
        u64::from(devices.ppu_dot()),
        u64::from(timer.raw_div()),
        u64::from(timer.counter()),
        u64::from(timer.reload_phase()),
        u64::from(timer.edge_latch()),
        apu.control_low_pack(),
        apu.control_high_pack(),
        apu.mixer_pack(),
        apu.wave_low_pack(),
        apu.wave_high_pack(),
        u64::from(devices.joypad_pack()),
        u64::from(devices.dma_pack()),
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use zksm83_core::VmState;
    use zksm83_memory::{MemoryImage, RomImage};

    use super::{STATE_SCALAR_COUNT, STATE_SCALAR_NAMES, encode_state_scalars};

    #[test]
    fn canonical_dmg_boundary_has_stable_scalar_layout() -> Result<(), Box<dyn std::error::Error>> {
        let rom = RomImage::new(vec![0])?;
        let memory = MemoryImage::zeroed()?;
        let state = VmState::dmg_post_boot_mbc3_initial(rom.root(), memory.root());
        let scalars = encode_state_scalars(state);

        assert_eq!(scalars.len(), STATE_SCALAR_COUNT);
        assert_eq!(scalars.first().copied(), Some(0x01));
        assert_eq!(scalars.get(7).copied(), Some(0xb0));
        assert_eq!(scalars.get(8).copied(), Some(0x0100));
        assert_eq!(scalars.get(9).copied(), Some(0xfffe));
        assert_eq!(scalars.get(14).copied(), Some(1));
        assert_eq!(scalars.get(20).copied(), Some(1));
        Ok(())
    }

    #[test]
    fn canonical_scalar_names_are_complete_and_unique() {
        let unique = STATE_SCALAR_NAMES.into_iter().collect::<BTreeSet<_>>();
        assert_eq!(STATE_SCALAR_NAMES.len(), STATE_SCALAR_COUNT);
        assert_eq!(unique.len(), STATE_SCALAR_COUNT);
    }
}
