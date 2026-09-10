//! Pure CPU, bus, flag, and profile-boundary proposition tests.

use zksm83_core::{
    BLUE_SOUND_WAIT_ROM_ROOT, BusWitness, CpuState, DmgDeviceState, DmgInterrupt, Flags, ImeState,
    MachineContext, MachineProfile, Mbc3State, Registers, RunState, StepError, StepInput, StepKind,
    StepRelation, VmState,
};
use zksm83_memory::{CommitmentRoot, LogAccumulator, LogKind, MemoryImage, RomImage};

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
fn blue_sound_wait_summarizes_authenticated_nonzero_loops_to_vblank()
-> Result<(), Box<dyn std::error::Error>> {
    let mut memory = MemoryImage::zeroed()?;
    memory.write(0xc02a, 0x40)?;
    memory.write(0xc02b, 0x02)?;
    memory.write(0xc02d, 0x01)?;
    let before = blue_sound_wait_state(&memory)?;
    let input = StepInput::new(
        [0xc02a, 0xc02b, 0xc02d]
            .into_iter()
            .map(|address| memory.read(address).map(BusWitness::MemoryRead))
            .collect::<Result<Vec<_>, _>>()?,
    );

    let (after, effects) = StepRelation::apply(before, input)?;

    assert_eq!(effects.kind(), StepKind::BlueSoundWait);
    assert_eq!(effects.bus_events().len(), 3);
    assert_eq!(after.cpu().m_cycles() - before.cpu().m_cycles(), 16_416);
    assert_eq!(after.cpu().pc(), 0x374f);
    assert_eq!(after.cpu().registers().a, 0x43);
    assert_eq!(
        (after.cpu().registers().h, after.cpu().registers().l),
        (0xc0, 0x2d)
    );
    assert_eq!(
        (
            after.dmg_devices().ppu_line(),
            after.dmg_devices().ppu_dot()
        ),
        (144, 0)
    );
    assert_eq!(after.dmg_devices().interrupt_request() & 1, 1);
    Ok(())
}

#[test]
fn blue_sound_wait_zero_channels_executes_only_the_final_fallthrough_loop()
-> Result<(), Box<dyn std::error::Error>> {
    let memory = MemoryImage::zeroed()?;
    let before = blue_sound_wait_state(&memory)?;
    let input = StepInput::new(
        [0xc02a, 0xc02b, 0xc02d]
            .into_iter()
            .map(|address| memory.read(address).map(BusWitness::MemoryRead))
            .collect::<Result<Vec<_>, _>>()?,
    );

    let (after, effects) = StepRelation::apply(before, input)?;

    assert_eq!(effects.kind(), StepKind::BlueSoundWait);
    assert_eq!(after.cpu().m_cycles() - before.cpu().m_cycles(), 18);
    assert_eq!(after.cpu().pc(), 0x375b);
    assert_eq!(after.cpu().registers().a, 0);
    assert_eq!(after.cpu().flags().byte(), 0x80);
    assert_eq!(
        (
            after.dmg_devices().ppu_line(),
            after.dmg_devices().ppu_dot()
        ),
        (0, 72)
    );
    Ok(())
}

#[test]
fn blue_sound_wait_is_not_available_under_a_different_rom_root()
-> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0_u8; 0x3750])?;
    let memory = MemoryImage::zeroed()?;
    let canonical = CpuState::dmg_post_boot_initial();
    let cpu = CpuState::new(
        canonical.registers(),
        canonical.flags(),
        0x374f,
        canonical.sp(),
        ImeState::Enabled,
        RunState::Running,
        0,
    );
    let state = dmg_fixture_state(cpu, DmgDeviceState::dmg_post_boot(), &rom, &memory)?;

    assert!(matches!(
        StepRelation::apply(state, StepInput::new(Vec::new())),
        Err(StepError::MissingWitness {
            request: zksm83_core::WitnessRequest::Rom {
                address: 0x374f,
                ..
            }
        })
    ));
    Ok(())
}

#[test]
fn blue_delay_loop_executes_all_de_iterations_with_exact_quiet_timing()
-> Result<(), Box<dyn std::error::Error>> {
    let memory = MemoryImage::zeroed()?;
    let mut registers = CpuState::dmg_post_boot_initial().registers();
    [registers.d, registers.e] = 7_000_u16.to_be_bytes();
    let cpu = CpuState::new(
        registers,
        Flags::default(),
        0x614d,
        0xdff1,
        ImeState::Disabled,
        RunState::Running,
        216_097,
    );
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior_if = devices.write_mmio(0xff0f, 0);
    let _prior_ie = devices.write_mmio(0xffff, 0x0d);
    let mut expected_devices = devices;
    let increment = 7_000_u32 * 10 - 1;
    for _ in 0..increment {
        expected_devices.advance_m_cycles(1);
    }
    let before = VmState::from_profile_parts(
        MachineContext::new(MachineProfile::DmgPostBootMbc3V1, devices),
        cpu,
        Mbc3State::from_parts(false, 28, 0)?,
        CommitmentRoot::from_bytes(BLUE_SOUND_WAIT_ROM_ROOT)?,
        memory.root(),
        LogAccumulator::empty(LogKind::Input),
        LogAccumulator::empty(LogKind::Output),
    )?;

    let (after, effects) = StepRelation::apply(before, StepInput::new(Vec::new()))?;

    assert_eq!(effects.kind(), StepKind::BlueDelayLoop);
    assert_eq!(effects.bus_events().len(), 0);
    assert_eq!(after.cpu().m_cycles() - before.cpu().m_cycles(), 69_999);
    assert_eq!(after.cpu().pc(), 0x6155);
    assert_eq!(after.cpu().registers().a, 0);
    assert_eq!(after.cpu().registers().d, 0);
    assert_eq!(after.cpu().registers().e, 0);
    assert_eq!(after.cpu().flags().byte(), 0x80);
    assert_eq!(after.dmg_devices(), expected_devices);
    Ok(())
}

#[test]
fn blue_delay_loop_preserves_exact_lcd_off_timing() -> Result<(), Box<dyn std::error::Error>> {
    let memory = MemoryImage::zeroed()?;
    let mut registers = CpuState::dmg_post_boot_initial().registers();
    [registers.d, registers.e] = 7_000_u16.to_be_bytes();
    let cpu = CpuState::new(
        registers,
        Flags::default(),
        0x614d,
        0xdff1,
        ImeState::Disabled,
        RunState::Running,
        216_097,
    );
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior_lcdc = devices.write_mmio(0xff40, 0x11);
    let mut expected_devices = devices;
    expected_devices.advance_m_cycles(63);
    for _ in 63..69_999 {
        expected_devices.advance_m_cycles(1);
    }
    let before = VmState::from_profile_parts(
        MachineContext::new(MachineProfile::DmgPostBootMbc3V1, devices),
        cpu,
        Mbc3State::from_parts(false, 28, 0)?,
        CommitmentRoot::from_bytes(BLUE_SOUND_WAIT_ROM_ROOT)?,
        memory.root(),
        LogAccumulator::empty(LogKind::Input),
        LogAccumulator::empty(LogKind::Output),
    )?;

    let (after, effects) = StepRelation::apply(before, StepInput::new(Vec::new()))?;

    assert_eq!(effects.kind(), StepKind::BlueDelayLoop);
    assert_eq!(after.dmg_devices(), expected_devices);
    assert_eq!(after.dmg_devices().ppu_line(), 0);
    assert_eq!(after.dmg_devices().ppu_dot(), 0);
    Ok(())
}

#[test]
fn blue_delay_summary_matches_real_rom_instructions() -> Result<(), Box<dyn std::error::Error>> {
    const ITERATIONS: u16 = 7;
    let memory = MemoryImage::zeroed()?;
    let mut registers = CpuState::dmg_post_boot_initial().registers();
    [registers.d, registers.e] = ITERATIONS.to_be_bytes();
    let cpu = CpuState::new(
        registers,
        Flags::default(),
        0x614d,
        0xdff1,
        ImeState::Disabled,
        RunState::Running,
        216_097,
    );
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior_if = devices.write_mmio(0xff0f, 0);
    let _prior_ie = devices.write_mmio(0xffff, 0x0d);
    let summary_before = VmState::from_profile_parts(
        MachineContext::new(MachineProfile::DmgPostBootMbc3V1, devices),
        cpu,
        Mbc3State::from_parts(false, 28, 0)?,
        CommitmentRoot::from_bytes(BLUE_SOUND_WAIT_ROM_ROOT)?,
        memory.root(),
        LogAccumulator::empty(LogKind::Input),
        LogAccumulator::empty(LogKind::Output),
    )?;
    let (summary_after, _) = StepRelation::apply(summary_before, StepInput::new(Vec::new()))?;

    let mut bytes = vec![0_u8; 0x72156];
    bytes
        .get_mut(0x7214d..0x72156)
        .ok_or_else(|| std::io::Error::other("missing delay-loop ROM window"))?
        .copy_from_slice(&[0x00, 0x00, 0x00, 0x1b, 0x7a, 0xb3, 0x20, 0xf8, 0xc9]);
    let rom = RomImage::new(bytes)?;
    let mut instruction_state = VmState::from_profile_parts(
        MachineContext::new(MachineProfile::DmgPostBootMbc3V1, devices),
        cpu,
        Mbc3State::from_parts(false, 28, 0)?,
        rom.root(),
        memory.root(),
        LogAccumulator::empty(LogKind::Input),
        LogAccumulator::empty(LogKind::Output),
    )?;
    while instruction_state.cpu().pc() != 0x6155 {
        let pc = instruction_state.cpu().pc();
        let physical = instruction_state.mbc3().map_rom(pc);
        let mut witnesses = vec![BusWitness::Rom(rom.read_mapped(pc, physical)?)];
        if pc == 0x6153 {
            witnesses.push(BusWitness::Rom(rom.read_mapped(0x6154, physical + 1)?));
        }
        (instruction_state, _) = StepRelation::apply(instruction_state, StepInput::new(witnesses))?;
    }

    assert_eq!(summary_after.cpu(), instruction_state.cpu());
    assert_eq!(summary_after.mbc3(), instruction_state.mbc3());
    assert_eq!(summary_after.dmg_devices(), instruction_state.dmg_devices());
    assert_eq!(summary_after.memory_root(), instruction_state.memory_root());
    assert_eq!(summary_after.input_log(), instruction_state.input_log());
    assert_eq!(summary_after.output_log(), instruction_state.output_log());
    Ok(())
}

#[test]
fn interruptible_blue_delay_slice_matches_complete_real_loop_iterations()
-> Result<(), Box<dyn std::error::Error>> {
    const ITERATIONS: u16 = 7;
    const SUMMARIZED_ITERATIONS: usize = 2;
    let memory = MemoryImage::zeroed()?;
    let mut registers = CpuState::dmg_post_boot_initial().registers();
    [registers.d, registers.e] = ITERATIONS.to_be_bytes();
    let cpu = CpuState::new(
        registers,
        Flags::default(),
        0x614d,
        0xdff1,
        ImeState::Enabled,
        RunState::Running,
        216_097,
    );
    let mut devices = DmgDeviceState::dmg_post_boot();
    for _ in 0..16_391 {
        devices.advance_m_cycles(1);
    }
    let _prior_if = devices.write_mmio(0xff0f, 0);
    let _prior_ie = devices.write_mmio(0xffff, 1);
    let summary_before = VmState::from_profile_parts(
        MachineContext::new(MachineProfile::DmgPostBootMbc3V1, devices),
        cpu,
        Mbc3State::from_parts(false, 28, 0)?,
        CommitmentRoot::from_bytes(BLUE_SOUND_WAIT_ROM_ROOT)?,
        memory.root(),
        LogAccumulator::empty(LogKind::Input),
        LogAccumulator::empty(LogKind::Output),
    )?;
    let (summary_after, effects) = StepRelation::apply(summary_before, StepInput::new(Vec::new()))?;
    assert_eq!(effects.kind(), StepKind::BlueDelayLoop);
    assert_eq!(summary_after.cpu().pc(), 0x614d);
    assert_eq!(
        u16::from_be_bytes([
            summary_after.cpu().registers().d,
            summary_after.cpu().registers().e,
        ]),
        5
    );
    assert_eq!(summary_after.cpu().m_cycles() - cpu.m_cycles(), 20);

    let mut bytes = vec![0_u8; 0x72156];
    bytes
        .get_mut(0x7214d..0x72156)
        .ok_or_else(|| std::io::Error::other("missing delay-loop ROM window"))?
        .copy_from_slice(&[0x00, 0x00, 0x00, 0x1b, 0x7a, 0xb3, 0x20, 0xf8, 0xc9]);
    let rom = RomImage::new(bytes)?;
    let mut instruction_state = VmState::from_profile_parts(
        MachineContext::new(MachineProfile::DmgPostBootMbc3V1, devices),
        cpu,
        Mbc3State::from_parts(false, 28, 0)?,
        rom.root(),
        memory.root(),
        LogAccumulator::empty(LogKind::Input),
        LogAccumulator::empty(LogKind::Output),
    )?;
    for _ in 0..SUMMARIZED_ITERATIONS * 7 {
        let pc = instruction_state.cpu().pc();
        let physical = instruction_state.mbc3().map_rom(pc);
        let mut witnesses = vec![BusWitness::Rom(rom.read_mapped(pc, physical)?)];
        if pc == 0x6153 {
            witnesses.push(BusWitness::Rom(rom.read_mapped(0x6154, physical + 1)?));
        }
        (instruction_state, _) = StepRelation::apply(instruction_state, StepInput::new(witnesses))?;
    }

    assert_eq!(summary_after.cpu(), instruction_state.cpu());
    assert_eq!(summary_after.mbc3(), instruction_state.mbc3());
    assert_eq!(summary_after.dmg_devices(), instruction_state.dmg_devices());
    assert_eq!(summary_after.memory_root(), instruction_state.memory_root());
    assert_eq!(summary_after.input_log(), instruction_state.input_log());
    assert_eq!(summary_after.output_log(), instruction_state.output_log());
    Ok(())
}

#[test]
fn blue_delay_loop_does_not_slice_without_enabled_vblank() -> Result<(), Box<dyn std::error::Error>>
{
    let memory = MemoryImage::zeroed()?;
    let mut registers = CpuState::dmg_post_boot_initial().registers();
    registers.e = 1;
    let cpu = CpuState::new(
        registers,
        Flags::default(),
        0x614d,
        0xdff1,
        ImeState::Enabled,
        RunState::Running,
        0,
    );
    let state = VmState::from_profile_parts(
        MachineContext::new(
            MachineProfile::DmgPostBootMbc3V1,
            DmgDeviceState::dmg_post_boot(),
        ),
        cpu,
        Mbc3State::from_parts(false, 28, 0)?,
        CommitmentRoot::from_bytes(BLUE_SOUND_WAIT_ROM_ROOT)?,
        memory.root(),
        LogAccumulator::empty(LogKind::Input),
        LogAccumulator::empty(LogKind::Output),
    )?;

    assert!(matches!(
        StepRelation::apply(state, StepInput::new(Vec::new())),
        Err(StepError::MissingWitness {
            request: zksm83_core::WitnessRequest::Rom {
                address: 0x614d,
                ..
            }
        })
    ));
    Ok(())
}

#[test]
fn blue_delay_loop_rejects_nonquiet_device_states() -> Result<(), Box<dyn std::error::Error>> {
    let mut timer = DmgDeviceState::dmg_post_boot();
    let _prior = timer.write_mmio(0xff07, 0x05);
    let mut serial = DmgDeviceState::dmg_post_boot();
    let _prior = serial.write_mmio(0xff02, 0x81);
    let mut stat = DmgDeviceState::dmg_post_boot();
    let _prior = stat.write_mmio(0xff41, 0x08);
    let mut dma = DmgDeviceState::dmg_post_boot();
    let _prior = dma.write_mmio(0xff46, 0xc0);
    let memory = MemoryImage::zeroed()?;

    for devices in [timer, serial, stat, dma] {
        let mut registers = CpuState::dmg_post_boot_initial().registers();
        registers.e = 1;
        let cpu = CpuState::new(
            registers,
            Flags::default(),
            0x614d,
            0xdff1,
            ImeState::Disabled,
            RunState::Running,
            0,
        );
        let state = VmState::from_profile_parts(
            MachineContext::new(MachineProfile::DmgPostBootMbc3V1, devices),
            cpu,
            Mbc3State::from_parts(false, 28, 0)?,
            CommitmentRoot::from_bytes(BLUE_SOUND_WAIT_ROM_ROOT)?,
            memory.root(),
            LogAccumulator::empty(LogKind::Input),
            LogAccumulator::empty(LogKind::Output),
        )?;
        let result = StepRelation::apply(state, StepInput::new(Vec::new()));
        assert!(!matches!(
            result,
            Ok((_, effects)) if effects.kind() == StepKind::BlueDelayLoop
        ));
    }
    Ok(())
}

#[test]
fn blue_dma_wait_summary_matches_interleaved_instruction_and_copy_steps()
-> Result<(), Box<dyn std::error::Error>> {
    let mut memory = MemoryImage::zeroed()?;
    for (address, value) in [
        (0xff80, 0x3e),
        (0xff81, 0x28),
        (0xff86, 0x3d),
        (0xff87, 0x20),
        (0xff88, 0xfd),
    ] {
        memory.write(address, value)?;
    }
    for offset in 0_u16..160 {
        memory.write(0xc000 + offset, offset as u8 ^ 0x5a)?;
    }
    let canonical = CpuState::dmg_post_boot_initial();
    let cpu = CpuState::new(
        canonical.registers(),
        canonical.flags(),
        0xff80,
        canonical.sp(),
        ImeState::Disabled,
        RunState::Running,
        1_000,
    );
    let mut devices = DmgDeviceState::dmg_post_boot();
    assert_eq!(devices.write_mmio(0xff46, 0xc0), Some(0));
    let state = VmState::from_profile_parts(
        MachineContext::new(MachineProfile::DmgPostBootMbc3V1, devices),
        cpu,
        Mbc3State::profile_initial(),
        CommitmentRoot::from_bytes(BLUE_SOUND_WAIT_ROM_ROOT)?,
        memory.root(),
        LogAccumulator::empty(LogKind::Input),
        LogAccumulator::empty(LogKind::Output),
    )?;
    let (scheduled, _) = StepRelation::apply(
        state,
        StepInput::new(vec![
            BusWitness::MemoryRead(memory.read(0xff80)?),
            BusWitness::MemoryRead(memory.read(0xff81)?),
        ]),
    )?;
    let after_first = apply_next_dma_byte(scheduled, &mut memory)?;
    let after_second = apply_next_dma_byte(after_first, &mut memory)?;
    assert_eq!(after_second.dmg_devices().dma_index(), 2);
    assert_eq!(after_second.dmg_devices().dma_owed(), 0);

    let prior_cpu = after_second.cpu();
    let loop_cpu = CpuState::new(
        prior_cpu.registers(),
        prior_cpu.flags(),
        0xff86,
        prior_cpu.sp(),
        prior_cpu.ime(),
        prior_cpu.run_state(),
        prior_cpu.m_cycles(),
    );
    let before = VmState::from_profile_parts(
        MachineContext::new(
            MachineProfile::DmgPostBootMbc3V1,
            after_second.dmg_devices(),
        ),
        loop_cpu,
        after_second.mbc3(),
        after_second.rom_root(),
        memory.root(),
        after_second.input_log(),
        after_second.output_log(),
    )?
    .with_bus_transcript(after_second.bus_transcript());
    assert!(zksm83_core::blue_dma_wait_candidate(before));

    let mut summary_memory = MemoryImage::from_checkpoint_bytes(memory.checkpoint_bytes())?;
    let (mut summary_state, summary_effects) = StepRelation::apply(
        before,
        StepInput::new(
            [0xff86, 0xff87, 0xff88]
                .into_iter()
                .map(|address| summary_memory.read(address).map(BusWitness::MemoryRead))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    )?;
    assert_eq!(summary_effects.kind(), StepKind::BlueDmaWait);
    assert_eq!(summary_state.dmg_devices().dma_owed(), 158);
    while summary_state.dmg_devices().dma_owed() != 0 {
        summary_state = apply_next_dma_byte(summary_state, &mut summary_memory)?;
    }

    let mut instruction_memory = memory;
    let mut instruction_state = before;
    while instruction_state.cpu().pc() != 0xff89 {
        let addresses: &[u16] = match instruction_state.cpu().pc() {
            0xff86 => &[0xff86],
            0xff87 => &[0xff87, 0xff88],
            pc => {
                return Err(std::io::Error::other(format!("unexpected loop PC {pc:#06x}")).into());
            }
        };
        let input = StepInput::new(
            addresses
                .iter()
                .map(|address| {
                    instruction_memory
                        .read(*address)
                        .map(BusWitness::MemoryRead)
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
        (instruction_state, _) = StepRelation::apply(instruction_state, input)?;
        while instruction_state.dmg_devices().dma_owed() != 0 {
            instruction_state = apply_next_dma_byte(instruction_state, &mut instruction_memory)?;
        }
    }

    assert_same_machine_state(summary_state, instruction_state);
    assert_ne!(
        summary_state.bus_transcript(),
        instruction_state.bus_transcript(),
        "the summary and instruction relations intentionally consume different event streams"
    );
    assert!(
        summary_state.bus_transcript().next_index()
            < instruction_state.bus_transcript().next_index()
    );
    assert_eq!(
        summary_memory.checkpoint_bytes(),
        instruction_memory.checkpoint_bytes()
    );
    assert_eq!(summary_state.cpu().flags().byte(), 0xd0);
    assert_eq!(
        summary_state.cpu().m_cycles() - before.cpu().m_cycles(),
        159
    );
    Ok(())
}

fn apply_next_dma_byte(
    state: VmState,
    memory: &mut MemoryImage,
) -> Result<VmState, Box<dyn std::error::Error>> {
    let source = state.dmg_devices().dma_source_address();
    let destination = state.dmg_devices().dma_destination_address();
    let read = memory.read(source)?;
    let write = memory.preview_write(destination, read.value)?;
    let (after, effects) = StepRelation::apply(
        state,
        StepInput::new(vec![
            BusWitness::MemoryRead(read),
            BusWitness::MemoryWrite(write),
        ]),
    )?;
    assert_eq!(effects.kind(), StepKind::DmaByte);
    memory.write(destination, read.value)?;
    assert_eq!(after.memory_root(), memory.root());
    Ok(after)
}

fn assert_same_machine_state(left: VmState, right: VmState) {
    assert_eq!(left.profile(), right.profile());
    assert_eq!(left.cpu(), right.cpu());
    assert_eq!(left.mbc3(), right.mbc3());
    assert_eq!(left.dmg_devices(), right.dmg_devices());
    assert_eq!(left.rom_root(), right.rom_root());
    assert_eq!(left.memory_root(), right.memory_root());
    assert_eq!(left.input_log(), right.input_log());
    assert_eq!(left.output_log(), right.output_log());
}

fn blue_sound_wait_state(memory: &MemoryImage) -> Result<VmState, Box<dyn std::error::Error>> {
    let canonical = CpuState::dmg_post_boot_initial();
    let cpu = CpuState::new(
        canonical.registers(),
        canonical.flags(),
        0x374f,
        canonical.sp(),
        ImeState::Enabled,
        RunState::Running,
        0,
    );
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior_if = devices.write_mmio(0xff0f, 0);
    let _prior_ie = devices.write_mmio(0xffff, 1);
    Ok(VmState::from_profile_parts(
        MachineContext::new(MachineProfile::DmgPostBootMbc3V1, devices),
        cpu,
        Mbc3State::profile_initial(),
        CommitmentRoot::from_bytes(BLUE_SOUND_WAIT_ROM_ROOT)?,
        memory.root(),
        LogAccumulator::empty(LogKind::Input),
        LogAccumulator::empty(LogKind::Output),
    )?)
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
