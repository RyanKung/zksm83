use zksm83_core::{
    BLUE_SOUND_WAIT_ROM_ROOT, BusWitness, CpuState, DmgDeviceState, Flags, ImeState,
    MachineContext, MachineProfile, Mbc3State, Registers, RunState, StepInput, StepRelation,
    VmState,
};
use zksm83_memory::{CommitmentRoot, LogAccumulator, LogKind, MemoryImage, RomImage};
use zksm83_trace::TraceRow;

use super::{CpuStructuralRelation, test_fixtures::*};
use crate::{
    NativeTraceWitness, TRACE_AFTER_DMA_BITS_START, TRACE_AFTER_INTERRUPT_ENABLE_BITS_START,
    TRACE_AFTER_STATE_START, TRACE_BEFORE_INTERRUPT_ENABLE_BITS_START, TRACE_BEFORE_STATE_START,
    TRACE_CYCLE_INCREMENT, TRACE_SUMMARY_AUX, UniformError,
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

#[test]
fn blue_sound_wait_binds_reads_or_branch_and_cycle_quotient()
-> Result<(), Box<dyn std::error::Error>> {
    for channels in [[0x40, 0x02, 0x01], [0, 0, 0]] {
        let mut memory = MemoryImage::zeroed()?;
        for (address, value) in [0xc02a, 0xc02b, 0xc02d].into_iter().zip(channels) {
            memory.write(address, value)?;
        }
        let before = blue_sound_state(memory.root())?;
        let input = StepInput::new(
            [0xc02a, 0xc02b, 0xc02d]
                .into_iter()
                .map(|address| memory.read(address).map(BusWitness::MemoryRead))
                .collect::<Result<Vec<_>, _>>()?,
        );
        let row = TraceRow::execute(before, input)?;
        let trace = NativeTraceWitness::from_rows(&[&row])?;
        assert_row_satisfied(&CpuStructuralRelation, trace.columns(), 0)?;

        let mut tampered = native_row(&trace, 0)?;
        *tampered
            .get_mut(TRACE_SUMMARY_AUX)
            .ok_or(UniformError::Shape)? = tampered
            .get(TRACE_SUMMARY_AUX)
            .copied()
            .ok_or(UniformError::Shape)?
            .wrapping_add(1);
        assert_native_row_rejected(&CpuStructuralRelation, &tampered)?;
    }
    Ok(())
}

#[test]
fn blue_delay_loop_binds_complete_and_interruptible_cpu_paths()
-> Result<(), Box<dyn std::error::Error>> {
    let memory = MemoryImage::zeroed()?;
    let complete = delay_row(
        ImeState::Disabled,
        DmgDeviceState::dmg_post_boot(),
        memory.root(),
    )?;
    let complete_trace = NativeTraceWitness::from_rows(&[&complete])?;
    assert_row_satisfied(&CpuStructuralRelation, complete_trace.columns(), 0)?;
    let mut wrong_iterations = native_row(&complete_trace, 0)?;
    *wrong_iterations
        .get_mut(TRACE_SUMMARY_AUX)
        .ok_or(UniformError::Shape)? = 6;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_iterations)?;

    let mut devices = DmgDeviceState::dmg_post_boot();
    for _ in 0..16_391 {
        devices.advance_m_cycles(1);
    }
    let _prior_if = devices.write_mmio(0xff0f, 0);
    let _prior_ie = devices.write_mmio(0xffff, 1);
    let sliced = delay_row(ImeState::Enabled, devices, memory.root())?;
    let sliced_trace = NativeTraceWitness::from_rows(&[&sliced])?;
    assert_row_satisfied(&CpuStructuralRelation, sliced_trace.columns(), 0)?;
    Ok(())
}

#[test]
fn blue_dma_wait_binds_hram_code_and_cpu_result() -> Result<(), Box<dyn std::error::Error>> {
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
    let _prior = devices.write_mmio(0xff46, 0xc0);
    let start = dmg_state(
        cpu,
        devices,
        Mbc3State::profile_initial(),
        blue_root()?,
        memory.root(),
    )?;
    let (scheduled, _) = StepRelation::apply(
        start,
        StepInput::new(vec![
            BusWitness::MemoryRead(memory.read(0xff80)?),
            BusWitness::MemoryRead(memory.read(0xff81)?),
        ]),
    )?;
    let (first, first_row) = apply_dma_byte(scheduled, &mut memory)?;
    let (second, second_row) = apply_dma_byte(first, &mut memory)?;
    let dma_trace = NativeTraceWitness::from_rows(&[&first_row, &second_row])?;
    assert_row_satisfied(&CpuStructuralRelation, dma_trace.columns(), 0)?;
    assert_row_satisfied(&CpuStructuralRelation, dma_trace.columns(), 1)?;
    let mut wrong_debt = native_row(&dma_trace, 0)?;
    let after_pack = wrong_debt
        .get_mut(TRACE_AFTER_STATE_START + 37)
        .ok_or(UniformError::Shape)?;
    *after_pack = after_pack
        .checked_sub(1_u64 << 24)
        .ok_or(UniformError::Shape)?;
    *wrong_debt
        .get_mut(TRACE_AFTER_DMA_BITS_START + 24)
        .ok_or(UniformError::Shape)? = 0;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_debt)?;
    let prior = second.cpu();
    let loop_cpu = CpuState::new(
        prior.registers(),
        prior.flags(),
        0xff86,
        prior.sp(),
        prior.ime(),
        prior.run_state(),
        prior.m_cycles(),
    );
    let before = dmg_state(
        loop_cpu,
        second.dmg_devices(),
        second.mbc3(),
        second.rom_root(),
        memory.root(),
    )?
    .with_bus_transcript(second.bus_transcript());
    let row = TraceRow::execute(
        before,
        StepInput::new(
            [0xff86, 0xff87, 0xff88]
                .into_iter()
                .map(|address| memory.read(address).map(BusWitness::MemoryRead))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    )?;
    let trace = NativeTraceWitness::from_rows(&[&row])?;
    assert_row_satisfied(&CpuStructuralRelation, trace.columns(), 0)?;
    Ok(())
}

fn blue_sound_state(memory_root: CommitmentRoot) -> Result<VmState, Box<dyn std::error::Error>> {
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
    dmg_state(
        cpu,
        devices,
        Mbc3State::profile_initial(),
        blue_root()?,
        memory_root,
    )
}

fn delay_row(
    ime: ImeState,
    devices: DmgDeviceState,
    memory_root: CommitmentRoot,
) -> Result<TraceRow, Box<dyn std::error::Error>> {
    let mut registers = Registers::default();
    [registers.d, registers.e] = 7_u16.to_be_bytes();
    let cpu = CpuState::new(
        registers,
        Flags::default(),
        0x614d,
        0xdff1,
        ime,
        RunState::Running,
        216_097,
    );
    let before = dmg_state(
        cpu,
        devices,
        Mbc3State::from_parts(false, 28, 0)?,
        blue_root()?,
        memory_root,
    )?;
    TraceRow::execute(before, StepInput::new(Vec::new())).map_err(Into::into)
}

fn apply_dma_byte(
    state: VmState,
    memory: &mut MemoryImage,
) -> Result<(VmState, TraceRow), Box<dyn std::error::Error>> {
    let source = state.dmg_devices().dma_source_address();
    let destination = state.dmg_devices().dma_destination_address();
    let read = memory.read(source)?;
    let write = memory.preview_write(destination, read.value)?;
    let row = TraceRow::execute(
        state,
        StepInput::new(vec![
            BusWitness::MemoryRead(read),
            BusWitness::MemoryWrite(write),
        ]),
    )?;
    let after = row.after();
    memory.write(destination, read.value)?;
    Ok((after, row))
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

fn blue_root() -> Result<CommitmentRoot, Box<dyn std::error::Error>> {
    Ok(CommitmentRoot::from_bytes(BLUE_SOUND_WAIT_ROM_ROOT))
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
