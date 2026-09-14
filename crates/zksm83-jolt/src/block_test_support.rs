//! Lookup-native fixtures shared by packed-relation unit tests.

use thiserror::Error;
use zksm83_core::{
    BusEventKind, BusWitness, CpuState, DmgDeviceState, Flags, ImeState, MachineContext,
    MachineProfile, Mbc3State, Registers, RunState, StepInput, VmState,
};
use zksm83_memory::{
    LogAccumulator, LogKind, MemoryImage, MemoryImageError, RomImage, RomImageError,
};
use zksm83_trace::{
    BasicBlock, BasicBlockPlanError, LookupTraceBuilder, LookupTraceBuilderError, TraceChunk,
    TraceRow, Witness, pack_witness_basic_blocks,
};

/// Failure to build a lookup-native packed-block fixture.
#[derive(Debug, Error)]
pub(crate) enum BlockFixtureError {
    /// The synthetic program is empty or cannot be placed at the post-boot PC.
    #[error("packed-block fixture has an invalid synthetic ROM layout")]
    RomLayout,
    /// The requested row count does not fit the trace builder's counter.
    #[error("packed-block fixture row count overflow")]
    RowCountOverflow,
    /// The fixture contains no packed block with one typed DMG device access.
    #[error("packed-block fixture contains no typed device-I/O block")]
    MissingDeviceIoBlock,
    /// Synthetic ROM construction failed.
    #[error(transparent)]
    Rom(#[from] RomImageError),
    /// Zeroed mutable-memory construction failed.
    #[error(transparent)]
    Memory(#[from] MemoryImageError),
    /// Lookup-native execution failed.
    #[error(transparent)]
    Trace(#[from] LookupTraceBuilderError),
    /// Packed-block planning failed.
    #[error(transparent)]
    Block(#[from] BasicBlockPlanError),
    /// A mutation fixture named a missing cell, a non-Boolean bit, or an overflowing value.
    #[error("packed-block mutation cell is invalid at column {column}, row {row}")]
    MutationCell {
        /// Zero-based witness column.
        column: usize,
        /// Zero-based witness row.
        row: usize,
    },
}

/// Generic non-instruction transition used by packed relation fixtures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MachineEventFixture {
    HaltIdle,
    HaltUntilVBlank,
    HaltWake,
    Interrupt,
    DmaByte,
    HaltUntilSerial,
    HaltUntilTimer,
}

/// Executes a synthetic program through the lookup-native v2 path and packs its rows.
pub(crate) fn lookup_blocks(
    program: &[u8],
    row_count: usize,
) -> Result<Vec<BasicBlock>, BlockFixtureError> {
    if program.is_empty() || row_count == 0 {
        return Err(BlockFixtureError::RomLayout);
    }
    let mut rom_bytes = vec![0_u8; 0x100 + program.len()];
    rom_bytes
        .get_mut(0x100..)
        .ok_or(BlockFixtureError::RomLayout)?
        .copy_from_slice(program);
    let rom = RomImage::new(rom_bytes.clone())?;
    let memory = MemoryImage::zeroed()?;
    let mut builder = LookupTraceBuilder::new_dmg_post_boot_mbc3(
        rom_bytes,
        memory.checkpoint_bytes(),
        Vec::new(),
        rom.root(),
        memory.root(),
    )?;
    let rows = u64::try_from(row_count).map_err(|_| BlockFixtureError::RowCountOverflow)?;
    let witness = builder.run_exact_steps(rows)?;
    pack_witness_basic_blocks(witness).map_err(Into::into)
}

/// Builds one packed singleton block for the selected generic machine event.
pub(crate) fn machine_event_block(
    event: MachineEventFixture,
) -> Result<Vec<BasicBlock>, Box<dyn std::error::Error>> {
    let row = match event {
        MachineEventFixture::HaltIdle => halt_idle_row()?,
        MachineEventFixture::HaltUntilVBlank => halt_until_vblank_row()?,
        MachineEventFixture::HaltWake => halt_wake_row()?,
        MachineEventFixture::Interrupt => interrupt_row()?,
        MachineEventFixture::DmaByte => dma_byte_row()?,
        MachineEventFixture::HaltUntilSerial => halt_until_serial_row()?,
        MachineEventFixture::HaltUntilTimer => halt_until_timer_row()?,
    };
    let witness = Witness::new(vec![TraceChunk::new(vec![row])?])?;
    pack_witness_basic_blocks(witness).map_err(Into::into)
}

/// Returns the first packed block containing a typed DMG device access.
pub(crate) fn first_device_io_block_index(
    blocks: &[BasicBlock],
) -> Result<usize, BlockFixtureError> {
    blocks
        .iter()
        .position(|block| {
            block.rows().any(|row| {
                row.effects().ordered_bus_events().iter().any(|event| {
                    matches!(
                        event.kind(),
                        BusEventKind::DmgMmioRead
                            | BusEventKind::DmgMmioWrite
                            | BusEventKind::DmgJoypadRead
                    )
                })
            })
        })
        .ok_or(BlockFixtureError::MissingDeviceIoBlock)
}

/// Flips one checked Boolean witness cell for a negative relation fixture.
pub(crate) fn flip_witness_bit(
    columns: &mut [Vec<u64>],
    column: usize,
    row: usize,
) -> Result<(), BlockFixtureError> {
    let value = columns
        .get_mut(column)
        .and_then(|values| values.get_mut(row))
        .ok_or(BlockFixtureError::MutationCell { column, row })?;
    *value = match *value {
        0 => 1,
        1 => 0,
        _ => return Err(BlockFixtureError::MutationCell { column, row }),
    };
    Ok(())
}

/// Increments one checked witness cell for a negative relation fixture.
pub(crate) fn increment_witness_cell(
    columns: &mut [Vec<u64>],
    column: usize,
    row: usize,
) -> Result<(), BlockFixtureError> {
    let value = columns
        .get_mut(column)
        .and_then(|values| values.get_mut(row))
        .ok_or(BlockFixtureError::MutationCell { column, row })?;
    *value = value
        .checked_add(1)
        .ok_or(BlockFixtureError::MutationCell { column, row })?;
    Ok(())
}

fn halt_idle_row() -> Result<TraceRow, Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0])?;
    let memory = MemoryImage::zeroed()?;
    execute_empty(machine_state(
        DmgDeviceState::dmg_post_boot(),
        ImeState::Disabled,
        RunState::Halted,
        &rom,
        &memory,
    )?)
}

fn halt_until_vblank_row() -> Result<TraceRow, Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0])?;
    let memory = MemoryImage::zeroed()?;
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior = devices.write_mmio(0xff0f, 0);
    let _prior = devices.write_mmio(0xffff, 0x01);
    execute_empty(machine_state(
        devices,
        ImeState::Enabled,
        RunState::Halted,
        &rom,
        &memory,
    )?)
}

fn halt_wake_row() -> Result<TraceRow, Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0])?;
    let memory = MemoryImage::zeroed()?;
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior = devices.write_mmio(0xff0f, 0x01);
    let _prior = devices.write_mmio(0xffff, 0x01);
    execute_empty(machine_state(
        devices,
        ImeState::Disabled,
        RunState::Halted,
        &rom,
        &memory,
    )?)
}

fn interrupt_row() -> Result<TraceRow, Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0])?;
    let mut memory = MemoryImage::zeroed()?;
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior = devices.write_mmio(0xff0f, 0x01);
    let _prior = devices.write_mmio(0xffff, 0x01);
    let before = machine_state(devices, ImeState::Enabled, RunState::Running, &rom, &memory)?;
    let high = memory.write_mapped(0xfffd, 0xfffd, 0)?;
    let low = memory.write_mapped(0xfffc, 0xfffc, 0)?;
    TraceRow::execute(
        before,
        StepInput::new(vec![
            BusWitness::MemoryWrite(high),
            BusWitness::MemoryWrite(low),
        ]),
    )
    .map_err(Into::into)
}

fn dma_byte_row() -> Result<TraceRow, Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0])?;
    let mut memory = MemoryImage::zeroed()?;
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior = devices.write_mmio(0xff46, 0);
    let before = machine_state(
        devices,
        ImeState::Disabled,
        RunState::Running,
        &rom,
        &memory,
    )?;
    let scheduled = TraceRow::execute(before, StepInput::new(vec![BusWitness::Rom(rom.read(0)?)]))?;
    let write = memory.write_mapped(0xfe00, 0xfe00, 0)?;
    TraceRow::execute(
        scheduled.after(),
        StepInput::new(vec![
            BusWitness::Rom(rom.read(0)?),
            BusWitness::MemoryWrite(write),
        ]),
    )
    .map_err(Into::into)
}

fn halt_until_serial_row() -> Result<TraceRow, Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0])?;
    let memory = MemoryImage::zeroed()?;
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior = devices.write_mmio(0xff0f, 0);
    let _prior = devices.write_mmio(0xffff, 0x08);
    let _prior = devices.write_mmio(0xff40, 0);
    let _prior = devices.write_mmio(0xff01, 0x42);
    let _prior = devices.write_mmio(0xff02, 0x81);
    execute_empty(machine_state(
        devices,
        ImeState::Enabled,
        RunState::Halted,
        &rom,
        &memory,
    )?)
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
    execute_empty(machine_state(
        devices,
        ImeState::Enabled,
        RunState::Halted,
        &rom,
        &memory,
    )?)
}

fn execute_empty(state: VmState) -> Result<TraceRow, Box<dyn std::error::Error>> {
    TraceRow::execute(state, StepInput::new(Vec::new())).map_err(Into::into)
}

fn machine_state(
    devices: DmgDeviceState,
    ime: ImeState,
    run_state: RunState,
    rom: &RomImage,
    memory: &MemoryImage,
) -> Result<VmState, Box<dyn std::error::Error>> {
    let cpu = CpuState::new(
        Registers::default(),
        Flags::default(),
        0,
        0xfffe,
        ime,
        run_state,
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
