use zksm83_core::{
    BusWitness, CpuState, DmgDeviceState, Flags, ImeState, MachineContext, MachineProfile,
    Mbc3State, Registers, RunState, StepInput, StepKind, VmState,
};
use zksm83_memory::{LogAccumulator, LogKind, MemoryImage, RomImage};
use zksm83_trace::TraceRow;

use super::{CpuStructuralRelation, test_fixtures::*};
use crate::{
    NativeTraceWitness, TRACE_AFTER_STATE_START, UniformError,
    trace::device::{
        TRACE_AFTER_INTERRUPT_REQUEST_BITS_START, TRACE_TIMER_INTERRUPT_GAP_BITS_START,
        TRACE_TIMER_STAGE_START,
    },
};

#[test]
fn timer_overflow_reload_and_interrupt_are_exact() -> Result<(), Box<dyn std::error::Error>> {
    let (rows, trace) = overflow_trace()?;
    for row in 0..=trace.active_row_count() {
        assert_row_satisfied(&CpuStructuralRelation, trace.columns(), row)?;
    }
    let first = rows.first().ok_or(UniformError::Shape)?;
    assert_eq!(first.after().dmg_devices().timer().counter(), 0);
    assert_eq!(first.after().dmg_devices().timer().reload_phase(), 1);
    let second = rows.get(1).ok_or(UniformError::Shape)?;
    assert_eq!(second.after().dmg_devices().timer().reload_phase(), 5);
    let third = rows.get(2).ok_or(UniformError::Shape)?;
    assert_eq!(third.after().dmg_devices().timer().counter(), 0x42);
    assert_eq!(third.after().dmg_devices().timer().reload_phase(), 0);
    assert_eq!(third.after().dmg_devices().interrupt_request() & 0x04, 0x04);

    let mut missing_phase = native_row(&trace, 0)?;
    set(&mut missing_phase, TRACE_AFTER_STATE_START + 29, 0)?;
    assert_native_row_rejected(&CpuStructuralRelation, &missing_phase)?;
    let mut missing_interrupt = native_row(&trace, 2)?;
    set(&mut missing_interrupt, TRACE_AFTER_STATE_START + 21, 1)?;
    set(
        &mut missing_interrupt,
        TRACE_AFTER_INTERRUPT_REQUEST_BITS_START + 2,
        0,
    )?;
    assert_native_row_rejected(&CpuStructuralRelation, &missing_interrupt)?;
    let mut wrong_tick = native_row(&trace, 0)?;
    let value = wrong_tick
        .get(TRACE_TIMER_STAGE_START)
        .copied()
        .ok_or(UniformError::Shape)?;
    set(&mut wrong_tick, TRACE_TIMER_STAGE_START, value ^ 1)?;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_tick)?;
    Ok(())
}

#[test]
fn guarded_timer_halt_long_step_is_bound() -> Result<(), Box<dyn std::error::Error>> {
    let row = halt_until_timer_row()?;
    assert_eq!(row.effects().kind(), StepKind::HaltUntilTimer);
    assert_eq!(row.after().cpu().m_cycles(), 6);
    assert_eq!(row.after().dmg_devices().timer().counter(), 0x42);
    assert_eq!(row.after().dmg_devices().timer().raw_div(), 24);
    assert!(row.after().dmg_devices().timer().edge_latch());
    let trace = NativeTraceWitness::from_rows(&[&row])?;
    assert_row_satisfied(&CpuStructuralRelation, trace.columns(), 0)?;

    let mut wrong_gap = native_row(&trace, 0)?;
    set(&mut wrong_gap, TRACE_TIMER_INTERRUPT_GAP_BITS_START, 0)?;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_gap)?;
    let mut wrong_counter = native_row(&trace, 0)?;
    set(&mut wrong_counter, TRACE_AFTER_STATE_START + 28, 0x43)?;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_counter)?;
    Ok(())
}

fn overflow_trace() -> Result<(Vec<TraceRow>, NativeTraceWitness), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0; 3])?;
    let memory = MemoryImage::zeroed()?;
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior = devices.write_mmio(0xff04, 0);
    let _prior = devices.write_mmio(0xff05, 0xff);
    let _prior = devices.write_mmio(0xff06, 0x42);
    let _prior = devices.write_mmio(0xff07, 0x05);
    devices.advance_m_cycles(3);
    let mut state = timer_state(devices, &rom, &memory)?;
    let mut rows = Vec::with_capacity(3);
    for _ in 0..3 {
        let address = state.cpu().pc();
        let row = TraceRow::execute(
            state,
            StepInput::new(vec![BusWitness::Rom(rom.read(address)?)]),
        )?;
        state = row.after();
        rows.push(row);
    }
    let references = rows.iter().collect::<Vec<_>>();
    let trace = NativeTraceWitness::from_rows(&references)?;
    Ok((rows, trace))
}

fn halt_until_timer_row() -> Result<TraceRow, Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0])?;
    let memory = MemoryImage::zeroed()?;
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior = devices.write_mmio(0xff0f, 0);
    let _prior = devices.write_mmio(0xffff, 0x04);
    let _prior = devices.write_mmio(0xff40, 0);
    let _prior = devices.write_mmio(0xff04, 0);
    let _prior = devices.write_mmio(0xff05, 0xff);
    let _prior = devices.write_mmio(0xff06, 0x42);
    let _prior = devices.write_mmio(0xff07, 0x05);
    let cpu = CpuState::new(
        Registers::default(),
        Flags::default(),
        0,
        0xfffe,
        ImeState::Enabled,
        RunState::Halted,
        0,
    );
    let before = VmState::from_profile_parts(
        MachineContext::new(MachineProfile::DmgPostBootMbc3V1, devices),
        cpu,
        Mbc3State::profile_initial(),
        rom.root(),
        memory.root(),
        LogAccumulator::empty(LogKind::Input),
        LogAccumulator::empty(LogKind::Output),
    )?;
    TraceRow::execute(before, StepInput::new(Vec::new())).map_err(Into::into)
}

fn timer_state(
    devices: DmgDeviceState,
    rom: &RomImage,
    memory: &MemoryImage,
) -> Result<VmState, Box<dyn std::error::Error>> {
    let cpu = CpuState::new(
        Registers::default(),
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
