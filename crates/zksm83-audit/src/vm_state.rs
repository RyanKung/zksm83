//! Stable field encoding of every fold-carried VM state component.

use pasta_curves::Fp;
use zksm83_core::VmState;

/// Number of Pasta-field columns in the canonical complete VM-state layout.
///
/// This is the canonical public-state order consumed by proof backends.
pub const VM_STATE_FIELD_COUNT: usize = 44;

/// Stable names in the same order as [`encode_vm_state`].
pub const VM_STATE_FIELD_NAMES: [&str; VM_STATE_FIELD_COUNT] = [
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
    "rom_root",
    "memory_root",
    "input_log_next_index",
    "input_log_root",
    "output_log_next_index",
    "output_log_root",
    "bus_transcript_next_index",
    "bus_transcript_root",
    "isa_transcript_next_index",
    "isa_transcript_root",
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

/// Encodes a complete VM boundary without hashing or omitting hidden device
/// state.
///
/// Every packed integer occupies at most 64 bits and is therefore injected
/// canonically into `Fp`. Commitment roots are already native `Fp` values.
/// The device packs include the internal timer edge/reload pipeline, serial
/// countdown, stored LCD STAT control bits, PPU dot/line, joypad selection,
/// DMA debt, and all APU/wave-RAM bytes.
#[must_use]
pub fn encode_vm_state(state: VmState) -> [Fp; VM_STATE_FIELD_COUNT] {
    let cpu = state.cpu();
    let registers = cpu.registers();
    let mbc3 = state.mbc3();
    let devices = state.dmg_devices();
    let timer = devices.timer();
    let apu = devices.apu();
    let input = state.input_log();
    let output = state.output_log();
    let bus = state.bus_transcript();
    let isa = state.isa_transcript();

    [
        Fp::from(u64::from(registers.a)),
        Fp::from(u64::from(registers.b)),
        Fp::from(u64::from(registers.c)),
        Fp::from(u64::from(registers.d)),
        Fp::from(u64::from(registers.e)),
        Fp::from(u64::from(registers.h)),
        Fp::from(u64::from(registers.l)),
        Fp::from(u64::from(cpu.flags().byte())),
        Fp::from(u64::from(cpu.pc())),
        Fp::from(u64::from(cpu.sp())),
        Fp::from(u64::from(cpu.ime().code())),
        Fp::from(u64::from(cpu.run_state().code())),
        Fp::from(cpu.m_cycles()),
        Fp::from(u64::from(mbc3.ram_enabled())),
        Fp::from(u64::from(mbc3.rom_bank())),
        Fp::from(u64::from(mbc3.ram_rtc_select())),
        state.rom_root().field(),
        state.memory_root().field(),
        Fp::from(input.next_index()),
        input.root().field(),
        Fp::from(output.next_index()),
        output.root().field(),
        Fp::from(bus.next_index()),
        bus.root().field(),
        Fp::from(isa.next_index()),
        isa.root().field(),
        Fp::from(u64::from(state.profile().code())),
        Fp::from(u64::from(devices.interrupt_request())),
        Fp::from(u64::from(devices.interrupt_enable())),
        Fp::from(devices.low_register_pack()),
        Fp::from(devices.high_register_pack()),
        Fp::from(u64::from(devices.ppu_line())),
        Fp::from(u64::from(devices.ppu_dot())),
        Fp::from(u64::from(timer.raw_div())),
        Fp::from(u64::from(timer.counter())),
        Fp::from(u64::from(timer.reload_phase())),
        Fp::from(u64::from(timer.edge_latch())),
        Fp::from(apu.control_low_pack()),
        Fp::from(apu.control_high_pack()),
        Fp::from(apu.mixer_pack()),
        Fp::from(apu.wave_low_pack()),
        Fp::from(apu.wave_high_pack()),
        Fp::from(u64::from(devices.joypad_pack())),
        Fp::from(u64::from(devices.dma_pack())),
    ]
}

/// Transposes complete VM states into the column-major layout consumed by the
/// committed shifted uniform-trace proof.
#[must_use]
pub fn encode_vm_state_columns(states: &[VmState]) -> Vec<Vec<Fp>> {
    let mut columns = (0..VM_STATE_FIELD_COUNT)
        .map(|_| Vec::with_capacity(states.len()))
        .collect::<Vec<_>>();
    for state in states {
        for (column, value) in columns.iter_mut().zip(encode_vm_state(*state)) {
            column.push(value);
        }
    }
    columns
}

#[cfg(test)]
mod tests {
    use pasta_curves::Fp;
    use zksm83_core::VmState;
    use zksm83_memory::{MemoryImage, RomImage};

    use super::{
        VM_STATE_FIELD_COUNT, VM_STATE_FIELD_NAMES, encode_vm_state, encode_vm_state_columns,
    };

    #[test]
    fn complete_post_boot_state_has_stable_field_layout() -> Result<(), Box<dyn std::error::Error>>
    {
        let rom = RomImage::new(vec![0])?;
        let memory = MemoryImage::zeroed()?;
        let state = VmState::dmg_post_boot_mbc3_initial(rom.root(), memory.root());
        let fields = encode_vm_state(state);

        assert_eq!(fields.len(), VM_STATE_FIELD_COUNT);
        assert_eq!(VM_STATE_FIELD_NAMES.len(), VM_STATE_FIELD_COUNT);
        assert_eq!(fields[0], Fp::from(0x01));
        assert_eq!(fields[7], Fp::from(0xb0));
        assert_eq!(fields[8], Fp::from(0x0100));
        assert_eq!(fields[9], Fp::from(0xfffe));
        assert_eq!(fields[14], Fp::from(1));
        assert_eq!(fields[16], rom.root().field());
        assert_eq!(fields[17], memory.root().field());
        assert_eq!(fields[25], state.isa_transcript().root().field());
        assert_eq!(fields[26], Fp::from(1));
        Ok(())
    }

    #[test]
    fn state_rows_transpose_without_reordering() -> Result<(), Box<dyn std::error::Error>> {
        let rom = RomImage::new(vec![0])?;
        let memory = MemoryImage::zeroed()?;
        let first = VmState::dmg_post_boot_mbc3_initial(rom.root(), memory.root());
        let second = first.with_bus_transcript(first.bus_transcript().append(
            zksm83_memory::BusTranscriptEvent {
                kind: 4,
                address: 0xc000,
                physical_address: 0xc000,
                before: 0,
                auxiliary: 0,
                value: 7,
                index: 0,
            },
        )?);

        let columns = encode_vm_state_columns(&[first, second]);
        assert_eq!(columns.len(), VM_STATE_FIELD_COUNT);
        assert!(columns.iter().all(|column| column.len() == 2));
        assert_eq!(columns.get(22), Some(&vec![Fp::from(0), Fp::from(1)]));
        let roots = columns
            .get(23)
            .ok_or_else(|| std::io::Error::other("missing bus root column"))?;
        assert_ne!(roots.first(), roots.get(1));
        Ok(())
    }
}
