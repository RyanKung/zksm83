//! Pure CPU, bus, flag, and profile-boundary proposition tests.

use zksm83_core::{
    BusWitness, CpuState, DmgDeviceState, DmgInterrupt, Flags, ImeState, MachineContext,
    MachineProfile, Mbc3State, Registers, RunState, StepError, StepInput, StepKind, StepRelation,
    VmState,
};
use zksm83_memory::{LogAccumulator, LogKind, MemoryImage, RomImage};

#[test]
fn undefined_opcode_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0xd3])?;
    let memory = MemoryImage::zeroed()?;
    let state = VmState::profile_initial(rom.root(), memory.root());
    let input = rom_input(&rom, &[0])?;
    assert!(matches!(
        StepRelation::apply(state, input),
        Err(StepError::UndefinedOpcode { opcode: 0xd3 })
    ));
    Ok(())
}

#[test]
fn dmg_post_boot_state_matches_the_cartridge_entry_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0_u8; 0x101])?;
    let memory = MemoryImage::zeroed()?;
    let state = VmState::dmg_post_boot_mbc3_initial(rom.root(), memory.root());
    let cpu = state.cpu();
    let registers = cpu.registers();

    assert_eq!(state.profile(), MachineProfile::DmgPostBootMbc3V1);
    assert_eq!(registers.a, 0x01);
    assert_eq!(registers.c, 0x13);
    assert_eq!(registers.e, 0xd8);
    assert_eq!(registers.h, 0x01);
    assert_eq!(registers.l, 0x4d);
    assert_eq!(cpu.flags().byte(), 0xb0);
    assert_eq!(cpu.pc(), 0x0100);
    assert_eq!(cpu.sp(), 0xfffe);
    assert_eq!(cpu.ime(), ImeState::Disabled);
    Ok(())
}

#[test]
fn dmg_if_read_is_typed_and_cannot_consume_clean_host_input()
-> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x102];
    let program = bytes
        .get_mut(0x100..0x102)
        .ok_or_else(|| std::io::Error::other("missing cartridge entry program"))?;
    program.copy_from_slice(&[0xf0, 0x0f]);
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let state = VmState::dmg_post_boot_mbc3_initial(rom.root(), memory.root());
    let input = rom_input(&rom, &[0x100, 0x101])?;

    let (after, effects) = StepRelation::apply(state, input)?;
    assert_eq!(after.cpu().registers().a, 0xe1);
    assert_eq!(after.input_log(), state.input_log());
    assert!(matches!(
        effects.bus_events().last(),
        Some(zksm83_core::BusEvent::DmgMmioRead {
            address: 0xff0f,
            value: 0xe1
        })
    ));
    Ok(())
}

#[test]
fn dmg_p1_read_consumes_and_commits_one_button_sample() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x102];
    let program = bytes
        .get_mut(0x100..0x102)
        .ok_or_else(|| std::io::Error::other("missing P1 read program"))?;
    program.copy_from_slice(&[0xf0, 0x00]);
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let state = VmState::dmg_post_boot_mbc3_initial(rom.root(), memory.root());
    let initial_transcript = state.bus_transcript();
    let mut witnesses = rom_witnesses(&rom, &[0x100, 0x101])?;
    witnesses.push(BusWitness::InputByte(0x10));
    let (after, effects) = StepRelation::apply(state, StepInput::new(witnesses))?;
    assert_eq!(after.cpu().registers().a, 0xce);
    assert_eq!(after.input_log().next_index(), 1);
    assert_eq!(after.dmg_devices().joypad_buttons(), 0x10);
    let expected_transcript = effects
        .bus_events()
        .try_fold(initial_transcript, |transcript, event| {
            transcript.append(event.transcript_event())
        })?;
    assert_eq!(after.bus_transcript(), expected_transcript);
    assert_eq!(after.bus_transcript().next_index(), 3);
    assert!(matches!(
        effects.bus_events().last(),
        Some(zksm83_core::BusEvent::DmgJoypadRead {
            index: 0,
            before_buttons: 0,
            buttons: 0x10,
            value: 0xce,
        })
    ));
    Ok(())
}

#[test]
fn changed_opcode_byte_fails_authentication() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0x00])?;
    let memory = MemoryImage::zeroed()?;
    let state = VmState::profile_initial(rom.root(), memory.root());
    let mut read = rom.read(0)?;
    read.value = 0x76;
    assert!(matches!(
        StepRelation::apply(state, StepInput::new(vec![BusWitness::Rom(read)])),
        Err(StepError::RomAuthentication(_))
    ));
    Ok(())
}

#[test]
fn changed_immediate_byte_fails_authentication() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0x06, 0x42])?;
    let memory = MemoryImage::zeroed()?;
    let state = VmState::profile_initial(rom.root(), memory.root());
    let mut immediate = rom.read(1)?;
    immediate.value = 0x43;
    let input = StepInput::new(vec![
        BusWitness::Rom(rom.read(0)?),
        BusWitness::Rom(immediate),
    ]);
    assert!(matches!(
        StepRelation::apply(state, input),
        Err(StepError::RomAuthentication(_))
    ));
    Ok(())
}

#[test]
fn flag_laws_match_execution_fixtures() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0x3e, 0x0f, 0xc6, 0x01, 0x76])?;
    let memory = MemoryImage::zeroed()?;
    let state = VmState::profile_initial(rom.root(), memory.root());
    let (state, _) = StepRelation::apply(state, rom_input(&rom, &[0, 1])?)?;
    let (state, _) = StepRelation::apply(state, rom_input(&rom, &[2, 3])?)?;

    assert_eq!(state.cpu().registers().a, 0x10);
    assert!(!state.cpu().flags().zero());
    assert!(!state.cpu().flags().subtract());
    assert!(state.cpu().flags().half_carry());
    assert!(!state.cpu().flags().carry());
    Ok(())
}

#[test]
fn memory_read_observes_latest_cpu_write() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0x21, 0x00, 0x80, 0x36, 0x42, 0x7e, 0x76])?;
    let mut memory = MemoryImage::zeroed()?;
    let state = VmState::profile_initial(rom.root(), memory.root());

    let (state, _) = StepRelation::apply(state, rom_input(&rom, &[0, 1, 2])?)?;
    let write = memory.write(0x8000, 0x42)?;
    let mut witnesses = rom_witnesses(&rom, &[3, 4])?;
    witnesses.push(BusWitness::MemoryWrite(write));
    let (state, _) = StepRelation::apply(state, StepInput::new(witnesses))?;

    let read = memory.read(0x8000)?;
    let mut witnesses = rom_witnesses(&rom, &[5])?;
    witnesses.push(BusWitness::MemoryRead(read));
    let (state, _) = StepRelation::apply(state, StepInput::new(witnesses))?;

    assert_eq!(state.cpu().registers().a, 0x42);
    assert_eq!(state.memory_root(), memory.root());
    Ok(())
}

#[test]
fn changed_memory_read_value_fails_authentication() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0x21, 0x00, 0x80, 0x7e])?;
    let memory = MemoryImage::zeroed()?;
    let state = VmState::profile_initial(rom.root(), memory.root());
    let (state, _) = StepRelation::apply(state, rom_input(&rom, &[0, 1, 2])?)?;
    let mut read = memory.read(0x8000)?;
    read.value = 1;
    let mut witnesses = rom_witnesses(&rom, &[3])?;
    witnesses.push(BusWitness::MemoryRead(read));
    assert!(matches!(
        StepRelation::apply(state, StepInput::new(witnesses)),
        Err(StepError::MemoryAuthentication(_))
    ));
    Ok(())
}

#[test]
fn changed_memory_write_value_or_address_fails() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0x21, 0x00, 0x80, 0x36, 0x42])?;
    let mut memory = MemoryImage::zeroed()?;
    let state = VmState::profile_initial(rom.root(), memory.root());
    let (state, _) = StepRelation::apply(state, rom_input(&rom, &[0, 1, 2])?)?;
    let write = memory.write(0x8000, 0x42)?;

    let mut changed_value = write;
    changed_value.after = 0x43;
    let mut value_witnesses = rom_witnesses(&rom, &[3, 4])?;
    value_witnesses.push(BusWitness::MemoryWrite(changed_value));
    assert!(matches!(
        StepRelation::apply(state, StepInput::new(value_witnesses)),
        Err(StepError::WriteValueMismatch { .. })
    ));

    let mut changed_address = write;
    changed_address.address = 0x8001;
    let mut address_witnesses = rom_witnesses(&rom, &[3, 4])?;
    address_witnesses.push(BusWitness::MemoryWrite(changed_address));
    assert!(matches!(
        StepRelation::apply(state, StepInput::new(address_witnesses)),
        Err(StepError::AddressMismatch { .. })
    ));
    Ok(())
}

#[test]
fn input_and_output_are_ordered_declared_events() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0xf0, 0xf0, 0xe0, 0xf1, 0x76])?;
    let memory = MemoryImage::zeroed()?;
    let state = VmState::profile_initial(rom.root(), memory.root());

    let mut input_witnesses = rom_witnesses(&rom, &[0, 1])?;
    input_witnesses.push(BusWitness::InputByte(0x5a));
    let (state, input_effects) = StepRelation::apply(state, StepInput::new(input_witnesses))?;
    let (state, output_effects) = StepRelation::apply(state, rom_input(&rom, &[2, 3])?)?;

    assert_eq!(
        state.input_log(),
        LogAccumulator::commit(LogKind::Input, &[0x5a])?
    );
    assert_eq!(
        state.output_log(),
        LogAccumulator::commit(LogKind::Output, &[0x5a])?
    );
    assert_eq!(input_effects.bus_events().count(), 3);
    assert_eq!(output_effects.bus_events().count(), 3);
    Ok(())
}

#[test]
fn cb_rotate_is_native_and_updates_flags() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0x06, 0x80, 0xcb, 0x00, 0x76])?;
    let memory = MemoryImage::zeroed()?;
    let state = VmState::profile_initial(rom.root(), memory.root());
    let (state, _) = StepRelation::apply(state, rom_input(&rom, &[0, 1])?)?;
    let (state, effects) = StepRelation::apply(state, rom_input(&rom, &[2, 3])?)?;

    assert_eq!(state.cpu().registers().b, 0x01);
    assert!(state.cpu().flags().carry());
    assert!(!state.cpu().flags().zero());
    assert_eq!(effects.instruction().encoded_opcode(), ([0xcb, 0x00], 2));
    Ok(())
}

#[test]
fn halt_and_ei_delay_are_explicit() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0xfb, 0x00, 0x76])?;
    let memory = MemoryImage::zeroed()?;
    let state = VmState::profile_initial(rom.root(), memory.root());
    let (state, _) = StepRelation::apply(state, rom_input(&rom, &[0])?)?;
    assert_eq!(state.cpu().ime(), ImeState::EnablePending);
    let (state, _) = StepRelation::apply(state, rom_input(&rom, &[1])?)?;
    assert_eq!(state.cpu().ime(), ImeState::Enabled);
    let (state, _) = StepRelation::apply(state, rom_input(&rom, &[2])?)?;
    assert_eq!(state.cpu().run_state(), RunState::Halted);
    assert!(matches!(
        StepRelation::apply(state, StepInput::new(Vec::new())),
        Err(StepError::CpuNotRunning {
            state: RunState::Halted
        })
    ));
    Ok(())
}

#[test]
fn dmg_interrupt_dispatch_clears_if_pushes_pc_and_selects_priority()
-> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0_u8; 0x101])?;
    let memory = MemoryImage::zeroed()?;
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior_ie = devices.write_mmio(0xffff, 0x1f);
    let _prior_if = devices.write_mmio(0xff0f, 0x1f);
    let cpu = CpuState::new(
        Registers::default(),
        Flags::default(),
        0x0100,
        0xfffe,
        ImeState::Enabled,
        RunState::Running,
        0,
    );
    let state = dmg_fixture_state(cpu, devices, &rom, &memory)?;
    let mut fork = memory.fork();
    let high = fork.write_mapped(0xfffd, 0xfffd, 0x01)?;
    let low = fork.write_mapped(0xfffc, 0xfffc, 0x00)?;
    let input = StepInput::new(vec![
        BusWitness::MemoryWrite(high),
        BusWitness::MemoryWrite(low),
    ]);

    let (after, effects) = StepRelation::apply(state, input)?;
    assert_eq!(
        effects.kind(),
        StepKind::InterruptDispatch(DmgInterrupt::VBlank)
    );
    assert_eq!(after.cpu().pc(), 0x0040);
    assert_eq!(after.cpu().sp(), 0xfffc);
    assert_eq!(after.cpu().ime(), ImeState::Disabled);
    assert_eq!(after.cpu().m_cycles(), 5);
    assert_eq!(after.dmg_devices().interrupt_request(), 0x1e);
    assert_eq!(effects.bus_events().count(), 2);
    Ok(())
}

#[test]
fn dmg_halt_idle_and_disabled_ime_wake_are_explicit() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0_u8; 0x101])?;
    let memory = MemoryImage::zeroed()?;
    let cpu = CpuState::new(
        Registers::default(),
        Flags::default(),
        0x0100,
        0xfffe,
        ImeState::Disabled,
        RunState::Halted,
        7,
    );
    let devices = DmgDeviceState::dmg_post_boot();
    let state = dmg_fixture_state(cpu, devices, &rom, &memory)?;
    let (idle, effects) = StepRelation::apply(state, StepInput::new(Vec::new()))?;
    assert_eq!(effects.kind(), StepKind::HaltIdle);
    assert_eq!(idle.cpu().run_state(), RunState::Halted);
    assert_eq!(idle.cpu().m_cycles(), 13);
    assert_eq!(idle.dmg_devices().timer().raw_div(), 0xabe4);

    let mut pending = idle.dmg_devices();
    let _prior_ie = pending.write_mmio(0xffff, 1);
    let wake_state = dmg_fixture_state(idle.cpu(), pending, &rom, &memory)?;
    let (awake, effects) = StepRelation::apply(wake_state, StepInput::new(Vec::new()))?;
    assert_eq!(effects.kind(), StepKind::HaltWake);
    assert_eq!(awake.cpu().run_state(), RunState::Running);
    assert_eq!(awake.cpu().m_cycles(), 13);
    assert_eq!(awake.dmg_devices().interrupt_request() & 1, 1);
    Ok(())
}

#[test]
fn dmg_halt_can_skip_exactly_to_serial_completion() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0_u8; 0x101])?;
    let memory = MemoryImage::zeroed()?;
    let cpu = CpuState::new(
        Registers::default(),
        Flags::default(),
        0x0100,
        0xfffe,
        ImeState::Enabled,
        RunState::Halted,
        7,
    );
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior_if = devices.write_mmio(0xff0f, 0);
    let _prior_ie = devices.write_mmio(0xffff, 0x08);
    let _prior_lcdc = devices.write_mmio(0xff40, 0);
    let _prior_data = devices.write_mmio(0xff01, 0x12);
    let _prior_control = devices.write_mmio(0xff02, 0x81);
    let state = dmg_fixture_state(cpu, devices, &rom, &memory)?;

    let (after, effects) = StepRelation::apply(state, StepInput::new(Vec::new()))?;
    assert_eq!(effects.kind(), StepKind::HaltUntilSerial);
    assert_eq!(after.cpu().m_cycles(), 1031);
    assert_eq!(after.cpu().run_state(), RunState::Halted);
    assert_eq!(after.dmg_devices().read_mmio(0xff01), Some(0xff));
    assert_eq!(after.dmg_devices().read_mmio(0xff02), Some(0x01));
    assert_eq!(
        after.dmg_devices().pending_interrupt(),
        Some(DmgInterrupt::Serial)
    );
    Ok(())
}

#[test]
fn dmg_halt_bug_suppresses_the_next_opcode_fetch_increment()
-> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x103];
    let program = bytes
        .get_mut(0x100..0x103)
        .ok_or_else(|| std::io::Error::other("missing HALT-bug program"))?;
    program.copy_from_slice(&[0x76, 0x3e, 0x42]);
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior_ie = devices.write_mmio(0xffff, 1);
    let state = dmg_fixture_state(CpuState::dmg_post_boot_initial(), devices, &rom, &memory)?;
    let (latched, halt) = StepRelation::apply(state, rom_input(&rom, &[0x100])?)?;
    assert_eq!(halt.kind(), StepKind::Instruction);
    assert_eq!(latched.cpu().run_state(), RunState::HaltBug);
    assert_eq!(latched.cpu().pc(), 0x0101);

    let (after, repeated_fetch) = StepRelation::apply(latched, rom_input(&rom, &[0x101, 0x101])?)?;
    assert_eq!(after.cpu().run_state(), RunState::Running);
    assert_eq!(after.cpu().pc(), 0x0102);
    assert_eq!(after.cpu().registers().a, 0x3e);
    let addresses = repeated_fetch
        .bus_events()
        .filter_map(|event| match event {
            zksm83_core::BusEvent::OpcodeFetch(read)
            | zksm83_core::BusEvent::ImmediateRead(read) => Some(read.address),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(addresses, vec![0x0101, 0x0101]);
    Ok(())
}

#[test]
fn dmg_cpu_video_memory_access_fails_closed_while_ppu_owns_the_bus()
-> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x101];
    *bytes
        .get_mut(0x100)
        .ok_or_else(|| std::io::Error::other("missing VRAM-read opcode"))? = 0x7e;
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let canonical = CpuState::dmg_post_boot_initial();
    let mut registers = canonical.registers();
    registers.h = 0x80;
    registers.l = 0x00;
    let cpu = CpuState::new(
        registers,
        canonical.flags(),
        canonical.pc(),
        canonical.sp(),
        canonical.ime(),
        canonical.run_state(),
        canonical.m_cycles(),
    );
    let mut devices = DmgDeviceState::dmg_post_boot();
    devices.advance_m_cycles(20);
    let state = dmg_fixture_state(cpu, devices, &rom, &memory)?;
    assert!(matches!(
        StepRelation::apply(state, rom_input(&rom, &[0x100])?),
        Err(StepError::DmgPpuCpuBusUnavailable { address: 0x8000 })
    ));
    Ok(())
}

#[test]
fn surplus_witness_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0x00])?;
    let memory = MemoryImage::zeroed()?;
    let state = VmState::profile_initial(rom.root(), memory.root());
    let input = rom_input(&rom, &[0, 0])?;
    assert!(matches!(
        StepRelation::apply(state, input),
        Err(StepError::SurplusWitnesses { remaining: 1 })
    ));
    Ok(())
}

#[test]
fn mbc3_control_write_changes_mapper_without_mutating_rom_root()
-> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0x3e, 0x02, 0xea, 0x00, 0x20, 0x76])?;
    let memory = MemoryImage::zeroed()?;
    let initial = VmState::profile_initial(rom.root(), memory.root());
    let (state, _) = StepRelation::apply(initial, rom_input(&rom, &[0, 1])?)?;
    let (state, effects) = StepRelation::apply(state, rom_input(&rom, &[2, 3, 4])?)?;

    assert_eq!(state.mbc3().rom_bank(), 2);
    assert_eq!(state.rom_root(), initial.rom_root());
    assert!(matches!(
        effects.bus_events().last(),
        Some(zksm83_core::BusEvent::Mbc3ControlWrite {
            address: 0x2000,
            value: 2
        })
    ));
    Ok(())
}

#[test]
fn mbc3_rejects_rom_witness_from_wrong_physical_bank() -> Result<(), Box<dyn std::error::Error>> {
    use zksm83_core::{CpuState, Flags, Mbc3State, Registers};

    let mut bytes = vec![0_u8; 0x8001];
    let bank_one = bytes
        .get_mut(0x4000)
        .ok_or_else(|| std::io::Error::other("missing bank-one byte"))?;
    *bank_one = 0x76;
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let cpu = CpuState::new(
        Registers::default(),
        Flags::default(),
        0x4000,
        0xff00,
        ImeState::Disabled,
        RunState::Running,
        0,
    );
    let state = VmState::from_parts_with_mbc3(
        cpu,
        Mbc3State::from_parts(false, 2, 0)?,
        rom.root(),
        memory.root(),
        LogAccumulator::empty(LogKind::Input),
        LogAccumulator::empty(LogKind::Output),
    )?;
    let wrong_bank = BusWitness::Rom(rom.read_mapped(0x4000, 0x4000)?);

    assert!(matches!(
        StepRelation::apply(state, StepInput::new(vec![wrong_bank])),
        Err(StepError::PhysicalAddressMismatch {
            expected: 0x8000,
            actual: 0x4000,
            ..
        })
    ));
    Ok(())
}

#[test]
fn arbitrary_rom_program_counter_uses_the_authenticated_instruction()
-> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x2346];
    *bytes.get_mut(0x2345).ok_or("missing fixture opcode")? = 0x00;
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let canonical = CpuState::dmg_post_boot_initial();
    let cpu = CpuState::new(
        canonical.registers(),
        canonical.flags(),
        0x2345,
        canonical.sp(),
        ImeState::Enabled,
        RunState::Running,
        0,
    );
    let before = dmg_fixture_state(cpu, DmgDeviceState::dmg_post_boot(), &rom, &memory)?;
    let (after, effects) = StepRelation::apply(
        before,
        StepInput::new(vec![BusWitness::Rom(rom.read(0x2345)?)]),
    )?;

    assert_eq!(effects.kind(), StepKind::Instruction);
    assert_eq!(after.cpu().pc(), 0x2346);
    assert_eq!(after.cpu().m_cycles(), 1);
    Ok(())
}

fn rom_input(rom: &RomImage, addresses: &[u16]) -> Result<StepInput, zksm83_memory::RomImageError> {
    Ok(StepInput::new(rom_witnesses(rom, addresses)?))
}

fn dmg_fixture_state(
    cpu: CpuState,
    devices: DmgDeviceState,
    rom: &RomImage,
    memory: &MemoryImage,
) -> Result<VmState, Box<dyn std::error::Error>> {
    Ok(VmState::from_profile_parts(
        MachineContext::new(MachineProfile::DmgPostBootMbc3V1, devices),
        cpu,
        Mbc3State::profile_initial(),
        rom.root(),
        memory.root(),
        LogAccumulator::empty(LogKind::Input),
        LogAccumulator::empty(LogKind::Output),
    )?)
}

fn rom_witnesses(
    rom: &RomImage,
    addresses: &[u16],
) -> Result<Vec<BusWitness>, zksm83_memory::RomImageError> {
    addresses
        .iter()
        .map(|address| rom.read(*address).map(BusWitness::Rom))
        .collect()
}
