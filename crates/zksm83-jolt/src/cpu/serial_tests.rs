use zksm83_core::{
    BusWitness, CpuState, DmgDeviceState, Flags, ImeState, MachineContext, MachineProfile,
    Mbc3State, Registers, RunState, StepInput, VmState,
};
use zksm83_memory::{LogAccumulator, LogKind, MemoryImage, RomImage};
use zksm83_trace::{TraceBuilder, TraceRow};

use super::{CpuStructuralRelation, test_fixtures::*};
use crate::{
    NativeTraceWitness, TRACE_AFTER_STATE_START, UniformError,
    trace::device::{
        TRACE_AFTER_DMG_HIGH_BITS_START, TRACE_BEFORE_DMG_HIGH_BITS_START, TRACE_SERIAL_COMPLETED,
        TRACE_SERIAL_COMPLETION_GAP_BITS_START, TRACE_SERIAL_POST_COUNTDOWN_BITS_START,
    },
};

#[test]
fn serial_start_and_exact_countdown_are_bound() -> Result<(), Box<dyn std::error::Error>> {
    let trace = serial_start_trace()?;
    for row in 0..=trace.active_row_count() {
        assert_row_satisfied(&CpuStructuralRelation, trace.columns(), row)?;
    }
    let mut wrong_countdown = native_row(&trace, 3)?;
    add(&mut wrong_countdown, TRACE_AFTER_STATE_START + 24, 1 << 48)?;
    set(
        &mut wrong_countdown,
        TRACE_AFTER_DMG_HIGH_BITS_START + 48,
        1,
    )?;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_countdown)?;
    Ok(())
}

#[test]
fn serial_completion_sets_data_control_and_interrupt() -> Result<(), Box<dyn std::error::Error>> {
    let row = serial_completion_row()?;
    assert_eq!(row.after().dmg_devices().read_mmio(0xff01), Some(0xff));
    assert_eq!(row.after().dmg_devices().read_mmio(0xff02), Some(0x01));
    assert_eq!(row.after().dmg_devices().interrupt_request() & 0x08, 0x08);
    let trace = NativeTraceWitness::from_rows(&[&row])?;
    assert_row_satisfied(&CpuStructuralRelation, trace.columns(), 0)?;

    let mut missing_completion = native_row(&trace, 0)?;
    set(&mut missing_completion, TRACE_SERIAL_COMPLETED, 0)?;
    assert_native_row_rejected(&CpuStructuralRelation, &missing_completion)?;
    let mut wrong_post = native_row(&trace, 0)?;
    set(
        &mut wrong_post,
        TRACE_SERIAL_POST_COUNTDOWN_BITS_START + 2,
        0,
    )?;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_post)?;

    let mut wrong_gap = native_row(&trace, 0)?;
    set(&mut wrong_gap, TRACE_SERIAL_COMPLETION_GAP_BITS_START, 1)?;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_gap)?;

    let mut early_completion = native_row(&trace, 0)?;
    add(
        &mut early_completion,
        crate::TRACE_BEFORE_STATE_START + 24,
        4_u64 << 48,
    )?;
    set(
        &mut early_completion,
        TRACE_BEFORE_DMG_HIGH_BITS_START + 50,
        0,
    )?;
    set(
        &mut early_completion,
        TRACE_BEFORE_DMG_HIGH_BITS_START + 51,
        1,
    )?;
    set(
        &mut early_completion,
        TRACE_SERIAL_POST_COUNTDOWN_BITS_START + 2,
        0,
    )?;
    set(
        &mut early_completion,
        TRACE_SERIAL_POST_COUNTDOWN_BITS_START + 3,
        1,
    )?;
    assert_native_row_rejected(&CpuStructuralRelation, &early_completion)?;
    Ok(())
}

fn serial_start_trace() -> Result<NativeTraceWitness, Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x10c];
    bytes
        .get_mut(0x100..0x10c)
        .ok_or(UniformError::Shape)?
        .copy_from_slice(&[
            0x3e, 0x42, 0xea, 0x01, 0xff, // SB = 42
            0x3e, 0x81, 0xea, 0x02, 0xff, // SC = 81, start transfer
            0x76, 0x00,
        ]);
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let witness = TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, Vec::new()).run(5)?;
    NativeTraceWitness::from_witness(&witness).map_err(Into::into)
}

fn serial_completion_row() -> Result<TraceRow, Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0])?;
    let memory = MemoryImage::zeroed()?;
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior = devices.write_mmio(0xff01, 0x42);
    let _prior = devices.write_mmio(0xff02, 0x81);
    for _ in 0..16 {
        devices.advance_m_cycles(63);
    }
    devices.advance_m_cycles(15);
    let cpu = CpuState::new(
        Registers::default(),
        Flags::default(),
        0,
        0xfffe,
        ImeState::Disabled,
        RunState::Running,
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
    TraceRow::execute(before, StepInput::new(vec![BusWitness::Rom(rom.read(0)?)]))
        .map_err(Into::into)
}

fn set(row: &mut [u64], index: usize, value: u64) -> Result<(), UniformError> {
    *row.get_mut(index).ok_or(UniformError::Shape)? = value;
    Ok(())
}

fn add(row: &mut [u64], index: usize, increment: u64) -> Result<(), UniformError> {
    let value = row.get_mut(index).ok_or(UniformError::Shape)?;
    *value = value.checked_add(increment).ok_or(UniformError::Shape)?;
    Ok(())
}
