//! Generic basic-block semantic-boundary regression fixtures.

use zksm83_core::{
    BusWitness, CpuState, DmgDeviceState, Flags, ImeState, MachineContext, MachineProfile,
    Mbc3State, Registers, RunState, StepInput, VmState,
};
use zksm83_memory::{LogAccumulator, LogKind, MemoryImage, RomImage};
use zksm83_trace::{BasicBlockCut, TraceBuilder, TraceRow, plan_basic_blocks};

#[test]
fn planner_reports_end_low_power_and_interrupt_control_boundaries()
-> Result<(), Box<dyn std::error::Error>> {
    for (program, expected) in [
        (&[0x00][..], BasicBlockCut::EndOfTrace),
        (&[0x76][..], BasicBlockCut::LowPower),
        (&[0xf3][..], BasicBlockCut::InterruptControl),
    ] {
        let rom = RomImage::new(program.to_vec())?;
        let memory = MemoryImage::zeroed()?;
        let mut builder = TraceBuilder::new(rom, memory, Vec::new());
        let row = builder.step()?;
        assert_single_cut(&row, expected)?;
    }
    Ok(())
}

#[test]
fn planner_reports_protocol_io_and_mapper_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0xf0, 0xf0])?;
    let memory = MemoryImage::zeroed()?;
    let mut protocol = TraceBuilder::new(rom, memory, vec![0x42]);
    let input = protocol.step()?;
    assert_single_cut(&input, BasicBlockCut::ProtocolIo)?;

    let mut bytes = vec![0_u8; 0x105];
    bytes
        .get_mut(0x100..)
        .ok_or("missing mapper fixture")?
        .copy_from_slice(&[0x3e, 0x0a, 0xea, 0x00, 0x00]);
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let mut mapper = TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, Vec::new());
    let prefix = mapper.step()?;
    let write = mapper.step()?;
    let spans = plan_basic_blocks(&[prefix, write])?;
    assert_eq!(spans.len(), 2);
    assert_eq!(
        spans.get(1).ok_or("missing mapper span")?.cut(),
        BasicBlockCut::MapperChange
    );
    Ok(())
}

#[test]
fn planner_cuts_after_an_instruction_that_raises_an_enabled_interrupt()
-> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0])?;
    let memory = MemoryImage::zeroed()?;
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior = devices.write_mmio(0xff0f, 0);
    let _prior = devices.write_mmio(0xffff, 0x04);
    let _prior = devices.write_mmio(0xff04, 0);
    let _prior = devices.write_mmio(0xff05, 0xff);
    let _prior = devices.write_mmio(0xff06, 0x42);
    let _prior = devices.write_mmio(0xff07, 0x05);
    devices.advance_m_cycles(5);
    let before = dmg_running_state(devices, &rom, &memory)?;
    let row = TraceRow::execute(before, StepInput::new(vec![BusWitness::Rom(rom.read(0)?)]))?;
    assert_single_cut(&row, BasicBlockCut::InterruptPending)
}

fn assert_single_cut(
    row: &TraceRow,
    expected: BasicBlockCut,
) -> Result<(), Box<dyn std::error::Error>> {
    let spans = plan_basic_blocks(std::slice::from_ref(row))?;
    assert_eq!(spans.len(), 1);
    assert_eq!(spans.first().ok_or("missing planned span")?.cut(), expected);
    Ok(())
}

fn dmg_running_state(
    devices: DmgDeviceState,
    rom: &RomImage,
    memory: &MemoryImage,
) -> Result<VmState, Box<dyn std::error::Error>> {
    let cpu = CpuState::new(
        Registers::default(),
        Flags::default(),
        0,
        0xfffe,
        ImeState::Enabled,
        RunState::Running,
        0,
    );
    VmState::from_profile_parts(
        MachineContext::new(MachineProfile::DmgPostBootMbc3V1, devices),
        cpu,
        Mbc3State::profile_initial(),
        rom.root(),
        memory.root(),
        LogAccumulator::empty(LogKind::Input),
        LogAccumulator::empty(LogKind::Output),
    )
    .map_err(Into::into)
}
