use zksm83_core::{
    BusWitness, CpuState, DmgDeviceState, ImeState, MachineContext, MachineProfile, Mbc3State,
    RunState, StepInput, VmState,
};
use zksm83_memory::{LogAccumulator, LogKind, MemoryImage, RomImage};
use zksm83_trace::{TraceBuilder, TraceRow};

use super::{CpuStructuralRelation, test_fixtures::*};
use crate::{
    NativeTraceWitness, TRACE_AFTER_DMA_BITS_START, TRACE_AFTER_STATE_START, UniformError,
    trace::device::{TRACE_AFTER_DMA_REMAINING_BITS_START, TRACE_CPU_OAM_ACCESS_START},
};

#[test]
fn ff46_write_starts_dma_and_binds_source() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x106];
    bytes
        .get_mut(0x100..0x105)
        .ok_or(UniformError::Shape)?
        .copy_from_slice(&[0x3e, 0xc0, 0xea, 0x46, 0xff]);
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let mut builder = TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, Vec::new());
    let load = builder.step()?;
    let start = builder.step()?;
    let trace = NativeTraceWitness::from_rows(&[&load, &start])?;
    assert_row_satisfied(&CpuStructuralRelation, trace.columns(), 1)?;

    let mut wrong_source = native_row(&trace, 1)?;
    add(&mut wrong_source, TRACE_AFTER_STATE_START + 37, 1)?;
    set(&mut wrong_source, TRACE_AFTER_DMA_BITS_START, 1)?;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_source)?;

    let mut inactive = native_row(&trace, 1)?;
    subtract(&mut inactive, TRACE_AFTER_STATE_START + 37, 1 << 16)?;
    set(&mut inactive, TRACE_AFTER_DMA_BITS_START + 16, 0)?;
    assert_native_row_rejected(&CpuStructuralRelation, &inactive)?;
    Ok(())
}

#[test]
fn active_dma_schedules_exact_instruction_debt() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0])?;
    let mut memory = MemoryImage::zeroed()?;
    memory.write(0xff80, 0)?;
    let canonical = CpuState::dmg_post_boot_initial();
    let cpu = CpuState::new(
        canonical.registers(),
        canonical.flags(),
        0xff80,
        canonical.sp(),
        ImeState::Disabled,
        RunState::Running,
        0,
    );
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior = devices.write_mmio(0xff46, 0xc0);
    let before = VmState::from_profile_parts(
        MachineContext::new(MachineProfile::DmgPostBootMbc3V1, devices),
        cpu,
        Mbc3State::profile_initial(),
        rom.root(),
        memory.root(),
        LogAccumulator::empty(LogKind::Input),
        LogAccumulator::empty(LogKind::Output),
    )?;
    let row = TraceRow::execute(
        before,
        StepInput::new(vec![BusWitness::MemoryRead(memory.read(0xff80)?)]),
    )?;
    assert_eq!(row.after().dmg_devices().dma_owed(), 1);
    let trace = NativeTraceWitness::from_rows(&[&row])?;
    assert_row_satisfied(&CpuStructuralRelation, trace.columns(), 0)?;

    let mut missing_debt = native_row(&trace, 0)?;
    subtract(&mut missing_debt, TRACE_AFTER_STATE_START + 37, 1 << 24)?;
    set(&mut missing_debt, TRACE_AFTER_DMA_BITS_START + 24, 0)?;
    set_bits(
        &mut missing_debt,
        TRACE_AFTER_DMA_REMAINING_BITS_START,
        160,
        8,
    )?;
    assert_native_row_rejected(&CpuStructuralRelation, &missing_debt)?;
    Ok(())
}

#[test]
fn cpu_oam_access_is_bound_in_an_unblocked_lcd_mode() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0xea, 0x00, 0xfe])?;
    let memory = MemoryImage::zeroed()?;
    let write = memory.preview_write(0xfe00, 0x42)?;
    let canonical = CpuState::dmg_post_boot_initial();
    let mut registers = canonical.registers();
    registers.a = 0x42;
    let cpu = CpuState::new(
        registers,
        canonical.flags(),
        0,
        canonical.sp(),
        ImeState::Disabled,
        RunState::Running,
        0,
    );
    let mut devices = DmgDeviceState::dmg_post_boot();
    devices.advance_m_cycles(63);
    let before = VmState::from_profile_parts(
        MachineContext::new(MachineProfile::DmgPostBootMbc3V1, devices),
        cpu,
        Mbc3State::profile_initial(),
        rom.root(),
        memory.root(),
        LogAccumulator::empty(LogKind::Input),
        LogAccumulator::empty(LogKind::Output),
    )?;
    let row = TraceRow::execute(
        before,
        StepInput::new(vec![
            BusWitness::Rom(rom.read(0)?),
            BusWitness::Rom(rom.read(1)?),
            BusWitness::Rom(rom.read(2)?),
            BusWitness::MemoryWrite(write),
        ]),
    )?;
    let trace = NativeTraceWitness::from_rows(&[&row])?;
    assert_row_satisfied(&CpuStructuralRelation, trace.columns(), 0)?;
    let mut missing_oam = native_row(&trace, 0)?;
    set(&mut missing_oam, TRACE_CPU_OAM_ACCESS_START + 3, 0)?;
    assert_native_row_rejected(&CpuStructuralRelation, &missing_oam)?;
    Ok(())
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), UniformError> {
    *row.get_mut(index).ok_or(UniformError::Shape)? = value;
    Ok(())
}

fn set_bits(row: &mut [u64], start: usize, value: u64, width: usize) -> Result<(), UniformError> {
    for bit in 0..width {
        set(row, start + bit, (value >> bit) & 1)?;
    }
    Ok(())
}

fn add(row: &mut [u64], index: usize, increment: u64) -> Result<(), UniformError> {
    let value = row.get_mut(index).ok_or(UniformError::Shape)?;
    *value = value.checked_add(increment).ok_or(UniformError::Shape)?;
    Ok(())
}

fn subtract(row: &mut [u64], index: usize, decrement: u64) -> Result<(), UniformError> {
    let value = row.get_mut(index).ok_or(UniformError::Shape)?;
    *value = value.checked_sub(decrement).ok_or(UniformError::Shape)?;
    Ok(())
}
