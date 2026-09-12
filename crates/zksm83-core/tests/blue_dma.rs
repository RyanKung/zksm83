//! Pokémon Blue DMA summary equivalence tests.

use zksm83_core::{
    BLUE_SOUND_WAIT_ROM_ROOT, BusWitness, CpuState, DmgDeviceState, ImeState, MachineContext,
    MachineProfile, Mbc3State, RunState, StepInput, StepKind, StepRelation, VmState,
};
use zksm83_memory::{CommitmentRoot, LogAccumulator, LogKind, MemoryImage};

#[test]
fn blue_dma_wait_summary_matches_interleaved_instruction_and_copy_steps()
-> Result<(), Box<dyn std::error::Error>> {
    let (before, memory) = dma_fixture()?;
    let mut summary_memory = MemoryImage::from_checkpoint_bytes(memory.checkpoint_bytes())?;
    let summary_state = run_summary(before, &mut summary_memory)?;
    let mut instruction_memory = memory;
    let instruction_state = run_instructions(before, &mut instruction_memory)?;

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

fn dma_fixture() -> Result<(VmState, MemoryImage), Box<dyn std::error::Error>> {
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
        CommitmentRoot::from_bytes(BLUE_SOUND_WAIT_ROM_ROOT),
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
    Ok((before, memory))
}

fn run_summary(
    before: VmState,
    memory: &mut MemoryImage,
) -> Result<VmState, Box<dyn std::error::Error>> {
    let (mut summary_state, summary_effects) = StepRelation::apply(
        before,
        StepInput::new(
            [0xff86, 0xff87, 0xff88]
                .into_iter()
                .map(|address| memory.read(address).map(BusWitness::MemoryRead))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    )?;
    assert_eq!(summary_effects.kind(), StepKind::BlueDmaWait);
    assert_eq!(summary_state.dmg_devices().dma_owed(), 158);
    while summary_state.dmg_devices().dma_owed() != 0 {
        summary_state = apply_next_dma_byte(summary_state, memory)?;
    }
    Ok(summary_state)
}

fn run_instructions(
    before: VmState,
    memory: &mut MemoryImage,
) -> Result<VmState, Box<dyn std::error::Error>> {
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
                .map(|address| memory.read(*address).map(BusWitness::MemoryRead))
                .collect::<Result<Vec<_>, _>>()?,
        );
        (instruction_state, _) = StepRelation::apply(instruction_state, input)?;
        while instruction_state.dmg_devices().dma_owed() != 0 {
            instruction_state = apply_next_dma_byte(instruction_state, memory)?;
        }
    }
    Ok(instruction_state)
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
