use zksm83_core::{
    BusWitness, CpuState, DmgDeviceState, ImeState, MachineContext, MachineProfile, Mbc3State,
    RunState, StepInput, VmState,
};
use zksm83_memory::{CommitmentRoot, LogAccumulator, LogKind, MemoryImage, RomImage};
use zksm83_trace::TraceRow;

use super::{CpuStructuralRelation, test_fixtures::*};
use crate::{
    NativeTraceWitness, TRACE_AFTER_INTERRUPT_ENABLE_BITS_START, TRACE_AFTER_STATE_START,
    TRACE_BEFORE_INTERRUPT_ENABLE_BITS_START, TRACE_BEFORE_STATE_START, TRACE_CYCLE_INCREMENT,
    UniformError,
};

#[test]
fn halt_bug_fetch_resets_run_state_and_reuses_pc() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x103];
    bytes
        .get_mut(0x100..0x103)
        .ok_or(UniformError::Shape)?
        .copy_from_slice(&[0x76, 0x3e, 0x42]);
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior = devices.write_mmio(0xffff, 1);
    let before = dmg_state(
        CpuState::dmg_post_boot_initial(),
        devices,
        Mbc3State::profile_initial(),
        rom.root(),
        memory.root(),
    )?;
    let first = TraceRow::execute(
        before,
        StepInput::new(vec![BusWitness::Rom(rom.read(0x100)?)]),
    )?;
    let second = TraceRow::execute(
        first.after(),
        StepInput::new(vec![
            BusWitness::Rom(rom.read(0x101)?),
            BusWitness::Rom(rom.read(0x101)?),
        ]),
    )?;
    let trace = NativeTraceWitness::from_rows(&[&first, &second])?;
    assert_row_satisfied(&CpuStructuralRelation, trace.columns(), 0)?;
    assert_row_satisfied(&CpuStructuralRelation, trace.columns(), 1)?;

    let mut missed_entry = native_row(&trace, 0)?;
    *missed_entry
        .get_mut(TRACE_AFTER_STATE_START + 11)
        .ok_or(UniformError::Shape)? = u64::from(RunState::Halted.code());
    assert_native_row_rejected(&CpuStructuralRelation, &missed_entry)?;

    let mut tampered = native_row(&trace, 1)?;
    *tampered
        .get_mut(TRACE_AFTER_STATE_START + 11)
        .ok_or(UniformError::Shape)? = u64::from(RunState::HaltBug.code());
    assert_native_row_rejected(&CpuStructuralRelation, &tampered)?;
    Ok(())
}

#[test]
fn halt_until_vblank_binds_guard_and_exact_next_crossing() -> Result<(), Box<dyn std::error::Error>>
{
    let rom = RomImage::new(vec![0])?;
    let memory = MemoryImage::zeroed()?;
    let canonical = CpuState::dmg_post_boot_initial();
    let cpu = CpuState::new(
        canonical.registers(),
        canonical.flags(),
        0,
        canonical.sp(),
        ImeState::Disabled,
        RunState::Halted,
        0,
    );
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior_if = devices.write_mmio(0xff0f, 0);
    let _prior_ie = devices.write_mmio(0xffff, 1);
    let before = dmg_state(
        cpu,
        devices,
        Mbc3State::profile_initial(),
        rom.root(),
        memory.root(),
    )?;
    let row = TraceRow::execute(before, StepInput::new(Vec::new()))?;
    assert_eq!(
        (
            row.after().dmg_devices().ppu_line(),
            row.after().dmg_devices().ppu_dot()
        ),
        (144, 0)
    );
    let trace = NativeTraceWitness::from_rows(&[&row])?;
    assert_row_satisfied(&CpuStructuralRelation, trace.columns(), 0)?;

    let mut short = native_row(&trace, 0)?;
    subtract(&mut short, TRACE_AFTER_STATE_START + 12, 1)?;
    subtract(&mut short, TRACE_CYCLE_INCREMENT, 1)?;
    assert_native_row_rejected(&CpuStructuralRelation, &short)?;

    let mut missing_ie = native_row(&trace, 0)?;
    subtract(&mut missing_ie, TRACE_BEFORE_STATE_START + 22, 1)?;
    subtract(&mut missing_ie, TRACE_AFTER_STATE_START + 22, 1)?;
    set(&mut missing_ie, TRACE_BEFORE_INTERRUPT_ENABLE_BITS_START, 0)?;
    set(&mut missing_ie, TRACE_AFTER_INTERRUPT_ENABLE_BITS_START, 0)?;
    assert_native_row_rejected(&CpuStructuralRelation, &missing_ie)?;
    Ok(())
}

fn dmg_state(
    cpu: CpuState,
    devices: DmgDeviceState,
    mbc3: Mbc3State,
    rom_root: CommitmentRoot,
    memory_root: CommitmentRoot,
) -> Result<VmState, Box<dyn std::error::Error>> {
    VmState::from_profile_parts(
        MachineContext::new(MachineProfile::DmgPostBootMbc3V1, devices),
        cpu,
        mbc3,
        rom_root,
        memory_root,
        LogAccumulator::empty(LogKind::Input),
        LogAccumulator::empty(LogKind::Output),
    )
    .map_err(Into::into)
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), UniformError> {
    *row.get_mut(index).ok_or(UniformError::Shape)? = value;
    Ok(())
}

fn subtract(row: &mut [u64], index: usize, decrement: u64) -> Result<(), UniformError> {
    let value = row.get_mut(index).ok_or(UniformError::Shape)?;
    *value = value.checked_sub(decrement).ok_or(UniformError::Shape)?;
    Ok(())
}
