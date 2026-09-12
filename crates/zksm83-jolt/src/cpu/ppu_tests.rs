use zksm83_core::{
    BusWitness, CpuState, DmgDeviceState, Flags, ImeState, MachineContext, MachineProfile,
    Mbc3State, Registers, RunState, StepInput, VmState,
};
use zksm83_memory::{LogAccumulator, LogKind, MemoryImage, RomImage};
use zksm83_trace::TraceRow;

use super::{CpuStructuralRelation, test_fixtures::*};
use crate::{
    NativeTraceWitness, UniformError,
    trace::device::{
        TRACE_PPU_FRAME_QUOTIENT_BITS_START, TRACE_PPU_STAT_BOUNDARY_CROSSED, TRACE_PPU_STAT_EVENT,
        TRACE_PPU_VBLANK_EVENT,
    },
};

#[test]
fn ppu_vblank_crossing_sets_interrupt() -> Result<(), Box<dyn std::error::Error>> {
    let row = ppu_row_at(16_415)?;
    assert_eq!(
        (
            row.after().dmg_devices().ppu_line(),
            row.after().dmg_devices().ppu_dot()
        ),
        (144, 0)
    );
    assert_eq!(row.after().dmg_devices().interrupt_request() & 1, 1);
    let trace = NativeTraceWitness::from_rows(&[&row])?;
    assert_row_satisfied(&CpuStructuralRelation, trace.columns(), 0)?;
    let mut missing_event = native_row(&trace, 0)?;
    set(&mut missing_event, TRACE_PPU_VBLANK_EVENT, 0)?;
    assert_native_row_rejected(&CpuStructuralRelation, &missing_event)?;
    Ok(())
}

#[test]
fn ppu_frame_wrap_does_not_reissue_vblank() -> Result<(), Box<dyn std::error::Error>> {
    let row = ppu_row_at(17_555)?;
    assert_eq!(
        (
            row.after().dmg_devices().ppu_line(),
            row.after().dmg_devices().ppu_dot()
        ),
        (0, 0)
    );
    assert_eq!(row.after().dmg_devices().interrupt_request() & 1, 0);
    let trace = NativeTraceWitness::from_rows(&[&row])?;
    assert_row_satisfied(&CpuStructuralRelation, trace.columns(), 0)?;
    let mut missing_quotient = native_row(&trace, 0)?;
    set(
        &mut missing_quotient,
        TRACE_PPU_FRAME_QUOTIENT_BITS_START,
        0,
    )?;
    assert_native_row_rejected(&CpuStructuralRelation, &missing_quotient)?;
    Ok(())
}

#[test]
fn stat_hblank_rising_edge_sets_interrupt() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0])?;
    let memory = MemoryImage::zeroed()?;
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior = devices.write_mmio(0xff0f, 0);
    devices.advance_m_cycles(62);
    let _prior = devices.write_mmio(0xff41, 0x08);
    let before = ppu_state(devices, &rom, &memory)?;
    let row = TraceRow::execute(before, StepInput::new(vec![BusWitness::Rom(rom.read(0)?)]))?;
    assert_eq!(row.after().dmg_devices().ppu_dot(), 252);
    assert_eq!(row.after().dmg_devices().interrupt_request() & 2, 2);
    let trace = NativeTraceWitness::from_rows(&[&row])?;
    assert_row_satisfied(&CpuStructuralRelation, trace.columns(), 0)?;

    let mut missing_boundary = native_row(&trace, 0)?;
    set(&mut missing_boundary, TRACE_PPU_STAT_BOUNDARY_CROSSED, 0)?;
    assert_native_row_rejected(&CpuStructuralRelation, &missing_boundary)?;
    let mut missing_event = native_row(&trace, 0)?;
    set(&mut missing_event, TRACE_PPU_STAT_EVENT, 0)?;
    assert_native_row_rejected(&CpuStructuralRelation, &missing_event)?;
    Ok(())
}

#[test]
fn stat_control_write_rising_edge_sets_interrupt() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0xea, 0x41, 0xff])?;
    let memory = MemoryImage::zeroed()?;
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior = devices.write_mmio(0xff0f, 0);
    let before = ppu_state_with_registers(
        devices,
        Registers {
            a: 0x20,
            ..Registers::default()
        },
        &rom,
        &memory,
    )?;
    let row = TraceRow::execute(
        before,
        StepInput::new(vec![
            BusWitness::Rom(rom.read(0)?),
            BusWitness::Rom(rom.read(1)?),
            BusWitness::Rom(rom.read(2)?),
        ]),
    )?;
    assert_eq!(row.after().dmg_devices().interrupt_request() & 2, 2);
    let trace = NativeTraceWitness::from_rows(&[&row])?;
    assert_row_satisfied(&CpuStructuralRelation, trace.columns(), 0)?;
    let mut missing_event = native_row(&trace, 0)?;
    set(&mut missing_event, TRACE_PPU_STAT_EVENT, 0)?;
    assert_native_row_rejected(&CpuStructuralRelation, &missing_event)?;
    Ok(())
}

#[test]
fn composite_stat_line_does_not_reissue_while_remaining_high()
-> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0])?;
    let memory = MemoryImage::zeroed()?;
    let mut devices = DmgDeviceState::dmg_post_boot();
    devices.advance_m_cycles(63);
    devices.advance_m_cycles(50);
    assert_eq!(devices.ppu_dot(), 452);
    let _prior = devices.write_mmio(0xff41, 0x28);
    let _prior = devices.write_mmio(0xff0f, 0);
    let before = ppu_state(devices, &rom, &memory)?;
    let row = TraceRow::execute(before, StepInput::new(vec![BusWitness::Rom(rom.read(0)?)]))?;
    assert_eq!(row.after().dmg_devices().ppu_dot(), 0);
    assert_eq!(row.after().dmg_devices().ppu_line(), 1);
    assert_eq!(row.after().dmg_devices().interrupt_request() & 2, 0);
    let trace = NativeTraceWitness::from_rows(&[&row])?;
    assert_row_satisfied(&CpuStructuralRelation, trace.columns(), 0)?;
    let mut false_event = native_row(&trace, 0)?;
    set(&mut false_event, TRACE_PPU_STAT_EVENT, 1)?;
    assert_native_row_rejected(&CpuStructuralRelation, &false_event)?;
    Ok(())
}

#[test]
fn stat_vblank_and_coincidence_boundaries_raise_edges() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0])?;
    let memory = MemoryImage::zeroed()?;
    let mut vblank = DmgDeviceState::dmg_post_boot();
    advance_devices_m_cycles(&mut vblank, 16_415)?;
    let _prior = vblank.write_mmio(0xff41, 0x10);
    let _prior = vblank.write_mmio(0xff0f, 0);
    let vblank_row = nop_row(vblank, &rom, &memory)?;
    assert_eq!(vblank_row.after().dmg_devices().interrupt_request() & 2, 2);

    let mut coincidence = DmgDeviceState::dmg_post_boot();
    coincidence.advance_m_cycles(63);
    coincidence.advance_m_cycles(50);
    let _prior = coincidence.write_mmio(0xff45, 1);
    let _prior = coincidence.write_mmio(0xff41, 0x40);
    let _prior = coincidence.write_mmio(0xff0f, 0);
    let coincidence_row = nop_row(coincidence, &rom, &memory)?;
    assert_eq!(
        coincidence_row.after().dmg_devices().interrupt_request() & 2,
        2
    );

    for row in [&vblank_row, &coincidence_row] {
        let trace = NativeTraceWitness::from_rows(&[row])?;
        assert_row_satisfied(&CpuStructuralRelation, trace.columns(), 0)?;
        let mut missing_event = native_row(&trace, 0)?;
        set(&mut missing_event, TRACE_PPU_STAT_EVENT, 0)?;
        assert_native_row_rejected(&CpuStructuralRelation, &missing_event)?;
    }
    Ok(())
}

fn ppu_row_at(m_cycles: u32) -> Result<TraceRow, Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0])?;
    let memory = MemoryImage::zeroed()?;
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior = devices.write_mmio(0xff0f, 0);
    advance_devices_m_cycles(&mut devices, m_cycles)?;
    let _prior = devices.write_mmio(0xff0f, 0);
    let before = ppu_state(devices, &rom, &memory)?;
    TraceRow::execute(before, StepInput::new(vec![BusWitness::Rom(rom.read(0)?)]))
        .map_err(Into::into)
}

fn nop_row(
    devices: DmgDeviceState,
    rom: &RomImage,
    memory: &MemoryImage,
) -> Result<TraceRow, Box<dyn std::error::Error>> {
    let before = ppu_state(devices, rom, memory)?;
    TraceRow::execute(before, StepInput::new(vec![BusWitness::Rom(rom.read(0)?)]))
        .map_err(Into::into)
}

fn advance_devices_m_cycles(
    devices: &mut DmgDeviceState,
    m_cycles: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..m_cycles / 63 {
        devices.advance_m_cycles(63);
    }
    devices.advance_m_cycles(u8::try_from(m_cycles % 63)?);
    Ok(())
}

fn ppu_state(
    devices: DmgDeviceState,
    rom: &RomImage,
    memory: &MemoryImage,
) -> Result<VmState, Box<dyn std::error::Error>> {
    ppu_state_with_registers(devices, Registers::default(), rom, memory)
}

fn ppu_state_with_registers(
    devices: DmgDeviceState,
    registers: Registers,
    rom: &RomImage,
    memory: &MemoryImage,
) -> Result<VmState, Box<dyn std::error::Error>> {
    let cpu = CpuState::new(
        registers,
        Flags::default(),
        0,
        0xfffe,
        ImeState::Disabled,
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

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), UniformError> {
    *row.get_mut(index).ok_or(UniformError::Shape)? = value;
    Ok(())
}
