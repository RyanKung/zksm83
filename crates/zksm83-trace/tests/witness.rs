//! Trace construction and continuity proposition tests.

use zksm83_core::{
    BusWitness, CpuState, MachineContext, MachineProfile, Mbc3State, RunState, StepInput, StepKind,
    VmState,
};
use zksm83_memory::{LogAccumulator, LogKind, MemoryImage, RomImage};
use zksm83_trace::{
    LookupTraceBuilder, TraceBuilder, TraceBuilderError, TraceChunk, TraceError, TraceRow,
    blue_rom_block_candidate,
};

#[test]
fn lookup_builder_matches_authenticated_semantics_and_ordered_events()
-> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x108];
    bytes
        .get_mut(0x100..0x107)
        .ok_or_else(|| std::io::Error::other("missing test ROM entry bytes"))?
        .copy_from_slice(&[
            0x21, 0x00, 0xc0, // LD HL,c000
            0x36, 0x2a, // LD (HL),2a
            0x7e, // LD A,(HL)
            0x00, // NOP
        ]);
    let rom = RomImage::new(bytes.clone())?;
    let rom_root = rom.root();
    let memory = MemoryImage::zeroed()?;
    let initial_memory = memory.checkpoint_bytes();
    let memory_root = memory.root();

    let mut authenticated = TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, Vec::new());
    let authenticated_witness = authenticated.run_exact_steps(3)?;
    let authenticated_memory = authenticated.checkpoint_memory();

    let mut lookup = LookupTraceBuilder::new_dmg_post_boot_mbc3(
        bytes,
        initial_memory,
        Vec::new(),
        rom_root,
        memory_root,
    )?;
    let lookup_witness = lookup.run_exact_steps(3)?;

    assert_eq!(lookup.checkpoint_memory(), authenticated_memory);
    let expected = authenticated_witness.final_state();
    let actual = lookup_witness.final_state();
    assert_eq!(actual.cpu(), expected.cpu());
    assert_eq!(actual.mbc3(), expected.mbc3());
    assert_eq!(actual.dmg_devices(), expected.dmg_devices());
    assert_eq!(actual.rom_root(), expected.rom_root());
    assert_eq!(actual.input_log(), expected.input_log());
    assert_eq!(actual.output_log(), expected.output_log());
    assert_eq!(actual.bus_transcript().next_index(), 0);
    assert_eq!(actual.isa_transcript().next_index(), 0);
    assert_ne!(actual.bus_transcript(), expected.bus_transcript());
    assert_ne!(actual.isa_transcript(), expected.isa_transcript());
    assert_eq!(actual.memory_root(), memory_root);
    assert_ne!(actual.memory_root(), expected.memory_root());

    for (lookup_row, authenticated_row) in lookup_witness.rows().zip(authenticated_witness.rows()) {
        assert_eq!(
            lookup_row.effects().kind(),
            authenticated_row.effects().kind()
        );
        assert_eq!(
            lookup_row.effects().instruction(),
            authenticated_row.effects().instruction()
        );
        let lookup_events = lookup_row
            .effects()
            .bus_events()
            .map(|event| event.transcript_event())
            .collect::<Vec<_>>();
        let authenticated_events = authenticated_row
            .effects()
            .bus_events()
            .map(|event| event.transcript_event())
            .collect::<Vec<_>>();
        assert_eq!(lookup_events, authenticated_events);
    }
    Ok(())
}

#[test]
fn lookup_streaming_boundary_resumes_without_legacy_transcripts()
-> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x108];
    bytes
        .get_mut(0x100..0x108)
        .ok_or_else(|| std::io::Error::other("missing lookup test program"))?
        .fill(0x00);
    let rom_root = RomImage::new(bytes.clone())?.root();
    let memory = MemoryImage::zeroed()?;
    let memory_root = memory.root();
    let initial_memory = memory.checkpoint_bytes();

    let mut one_shot = LookupTraceBuilder::new_dmg_post_boot_mbc3(
        bytes.clone(),
        initial_memory.clone(),
        Vec::new(),
        rom_root,
        memory_root,
    )?;
    let one_shot_boundary = one_shot.run_exact_boundary(4)?;

    let mut prefix = LookupTraceBuilder::new_dmg_post_boot_mbc3(
        bytes.clone(),
        initial_memory,
        Vec::new(),
        rom_root,
        memory_root,
    )?;
    let first = prefix.run_exact_boundary(2)?;
    let mut resumed = LookupTraceBuilder::resume_dmg_post_boot_mbc3(
        bytes,
        prefix.checkpoint_memory(),
        Vec::new(),
        first.final_state(),
    )?;
    let second = resumed.run_exact_boundary(2)?;

    assert_eq!(first.final_state(), second.initial_state());
    assert_eq!(second.final_state(), one_shot_boundary.final_state());
    assert_eq!(resumed.checkpoint_memory(), one_shot.checkpoint_memory());
    assert_eq!(second.metrics().relation_steps(), 2);
    assert_eq!(second.metrics().instructions(), 2);
    assert_eq!(second.final_state().bus_transcript().next_index(), 0);
    assert_eq!(second.final_state().isa_transcript().next_index(), 0);
    Ok(())
}

#[test]
fn streaming_pc_profile_counts_only_instruction_rows() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0x00, 0x18, 0xfd])?;
    let memory = MemoryImage::zeroed()?;
    let mut builder = TraceBuilder::new(rom, memory, Vec::new());
    let (boundary, profile) = builder.run_exact_boundary_profiled(6)?;

    assert_eq!(boundary.step_count(), 6);
    assert_eq!(
        profile.top(2),
        vec![
            zksm83_trace::ProgramCounterCount {
                pc: 0,
                rom_bank: Some(0),
                physical_pc: 0,
                count: 3,
            },
            zksm83_trace::ProgramCounterCount {
                pc: 1,
                rom_bank: Some(0),
                physical_pc: 1,
                count: 3,
            },
        ]
    );
    Ok(())
}

#[test]
fn validated_builder_executes_nontrivial_program() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![
        0x21, 0x00, 0x80, // LD HL,0x8000
        0x36, 0x2a, // LD (HL),0x2a
        0x7e, // LD A,(HL)
        0xc6, 0x10, // ADD A,0x10
        0xe0, 0xf1, // LDH (0xff00 + 0xf1),A
        0x76, // HALT
    ])?;
    let memory = MemoryImage::zeroed()?;
    let initial_memory_root = memory.root();
    let witness = TraceBuilder::new(rom, memory, Vec::new()).run(10)?;

    assert_eq!(witness.step_count(), 6);
    assert_eq!(witness.final_state().cpu().run_state(), RunState::Halted);
    assert_eq!(witness.final_state().cpu().registers().a, 0x3a);
    assert_ne!(witness.final_state().memory_root(), initial_memory_root);
    assert_eq!(
        witness.final_state().output_log(),
        LogAccumulator::commit(LogKind::Output, &[0x3a])?
    );
    Ok(())
}

#[test]
fn trace_row_order_is_bound() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0x00, 0x76])?;
    let memory = MemoryImage::zeroed()?;
    let state = VmState::profile_initial(rom.root(), memory.root());
    let first = TraceRow::execute(state, StepInput::new(vec![BusWitness::Rom(rom.read(0)?)]))?;
    let reordered = TraceRow::execute(state, StepInput::new(vec![BusWitness::Rom(rom.read(0)?)]))?;

    assert!(matches!(
        TraceChunk::new(vec![first, reordered]),
        Err(TraceError::DiscontinuousRow { index: 0 })
    ));
    Ok(())
}

#[test]
fn private_input_exhaustion_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0xf0, 0xf0, 0x76])?;
    let memory = MemoryImage::zeroed()?;
    let result = TraceBuilder::new(rom, memory, Vec::new()).run(3);
    assert!(matches!(
        result,
        Err(zksm83_trace::TraceBuilderError::InputExhausted { index: 0 })
    ));
    Ok(())
}

#[test]
fn unconsumed_private_input_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0x76])?;
    let memory = MemoryImage::zeroed()?;
    let result = TraceBuilder::new(rom, memory, vec![0x5a]).run(1);
    assert!(matches!(
        result,
        Err(zksm83_trace::TraceBuilderError::UnconsumedInput {
            consumed: 0,
            provided: 1
        })
    ));
    Ok(())
}

#[test]
fn dmg_post_boot_exact_chunk_starts_at_cartridge_entry_and_may_remain_running()
-> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x102];
    for address in 0x100..0x102 {
        let opcode = bytes
            .get_mut(address)
            .ok_or_else(|| std::io::Error::other("missing cartridge entry byte"))?;
        *opcode = 0x00;
    }
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let mut builder = TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, Vec::new());
    let witness = builder.run_exact_steps(2)?;

    assert_eq!(witness.initial_state().cpu().pc(), 0x0100);
    assert_eq!(witness.final_state().cpu().pc(), 0x0102);
    assert_eq!(witness.final_state().cpu().run_state(), RunState::Running);
    assert_eq!(witness.step_count(), 2);
    Ok(())
}

#[test]
fn exact_chunks_preserve_the_complete_shared_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x104];
    for address in 0x100..0x104 {
        let opcode = bytes
            .get_mut(address)
            .ok_or_else(|| std::io::Error::other("missing cartridge entry byte"))?;
        *opcode = 0x00;
    }
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let mut builder = TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, Vec::new());
    let first = builder.run_exact_steps(2)?;
    let second = builder.run_exact_steps(2)?;

    assert_eq!(first.final_state(), second.initial_state());
    assert_eq!(second.final_state().cpu().pc(), 0x0104);
    Ok(())
}

#[test]
fn semantic_boundary_stops_only_after_an_accepted_row() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x105];
    bytes
        .get_mut(0x100..0x105)
        .ok_or_else(|| std::io::Error::other("missing cartridge entry program"))?
        .fill(0x00);
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let mut builder = TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, Vec::new());

    let boundary = builder.run_until_boundary(5, |state| state.cpu().pc() == 0x0103)?;

    assert_eq!(boundary.step_count(), 3);
    assert_eq!(boundary.final_state().cpu().pc(), 0x0103);
    assert_eq!(builder.state(), boundary.final_state());
    Ok(())
}

#[test]
fn missing_semantic_boundary_preserves_the_accepted_prefix()
-> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x105];
    bytes
        .get_mut(0x100..0x105)
        .ok_or_else(|| std::io::Error::other("missing cartridge entry program"))?
        .fill(0x00);
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let mut builder = TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, Vec::new());

    let result = builder.run_until_boundary(2, |state| state.cpu().pc() == 0x0104);

    assert!(matches!(
        result,
        Err(TraceBuilderError::MilestoneNotReached { completed: 2 })
    ));
    assert_eq!(builder.state().cpu().pc(), 0x0102);
    Ok(())
}

#[test]
fn streaming_boundary_matches_retained_exact_witness() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x104];
    for address in 0x100..0x104 {
        let opcode = bytes
            .get_mut(address)
            .ok_or_else(|| std::io::Error::other("missing cartridge entry byte"))?;
        *opcode = 0x00;
    }
    let mut retained = TraceBuilder::new_dmg_post_boot_mbc3(
        RomImage::new(bytes.clone())?,
        MemoryImage::zeroed()?,
        Vec::new(),
    );
    let witness = retained.run_exact_steps(4)?;
    let mut streaming = TraceBuilder::new_dmg_post_boot_mbc3(
        RomImage::new(bytes)?,
        MemoryImage::zeroed()?,
        Vec::new(),
    );
    let boundary = streaming.run_exact_boundary(4)?;

    assert_eq!(boundary.initial_state(), witness.initial_state());
    assert_eq!(boundary.final_state(), witness.final_state());
    assert_eq!(boundary.step_count(), witness.step_count());
    assert_eq!(boundary.metrics().relation_steps(), 4);
    assert_eq!(boundary.metrics().instructions(), 4);
    assert_eq!(boundary.metrics().dma_byte_steps(), 0);
    Ok(())
}

#[test]
fn streaming_metrics_match_greedy_blue_rom_micro_block_packing()
-> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x105];
    bytes
        .get_mut(0x100..0x105)
        .ok_or_else(|| std::io::Error::other("missing cartridge-entry program"))?
        .fill(0x00);
    let mut builder = TraceBuilder::new_dmg_post_boot_mbc3(
        RomImage::new(bytes)?,
        MemoryImage::zeroed()?,
        Vec::new(),
    );

    let boundary = builder.run_exact_boundary(5)?;
    let metrics = boundary.metrics();

    assert_eq!(metrics.relation_steps(), 5);
    assert_eq!(metrics.instructions(), 5);
    assert_eq!(metrics.blue_rom_block_steps(), 1);
    assert_eq!(metrics.blue_rom_block_instructions(), 5);
    assert_eq!(metrics.blue_rom_block_saved_rows(), 4);
    Ok(())
}

#[test]
fn blue_rom_micro_block_metrics_include_immutable_immediate_fetches()
-> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x104];
    bytes
        .get_mut(0x100..0x104)
        .ok_or_else(|| std::io::Error::other("missing cartridge-entry program"))?
        .copy_from_slice(&[
            0x06, 0x12, // LD B,0x12: two fetches, two M-cycles
            0xaf, // XOR A: one fetch, one M-cycle
            0x04, // INC B: one fetch, one M-cycle
        ]);
    let mut builder = TraceBuilder::new_dmg_post_boot_mbc3(
        RomImage::new(bytes)?,
        MemoryImage::zeroed()?,
        Vec::new(),
    );

    let boundary = builder.run_exact_boundary(3)?;
    let metrics = boundary.metrics();

    assert_eq!(metrics.blue_rom_block_steps(), 1);
    assert_eq!(metrics.blue_rom_block_instructions(), 3);
    assert_eq!(metrics.blue_rom_block_saved_rows(), 2);
    Ok(())
}

#[test]
fn blue_rom_micro_blocks_include_safe_wram_reads_but_exclude_vram_reads()
-> Result<(), Box<dyn std::error::Error>> {
    let program = [
        0x21, 0x00, 0xc0, // LD HL,0xc000: three fetches, three M-cycles
        0x7e, // LD A,(HL): one fetch, one safe WRAM read, two M-cycles
    ];
    let mut bytes = vec![0_u8; 0x104];
    bytes
        .get_mut(0x100..0x104)
        .ok_or_else(|| std::io::Error::other("missing WRAM-read program"))?
        .copy_from_slice(&program);
    let mut memory = MemoryImage::zeroed()?;
    memory.write(0xc000, 0x42)?;
    let mut builder =
        TraceBuilder::new_dmg_post_boot_mbc3(RomImage::new(bytes)?, memory, Vec::new());
    let witness = builder.run_exact_steps(2)?;
    let rows = witness.rows().collect::<Vec<_>>();

    assert!(rows.iter().all(|row| blue_rom_block_candidate(row)));
    assert_eq!(witness.final_state().cpu().registers().a, 0x42);

    let mut vram_program = program;
    vram_program[2] = 0x80;
    let mut vram_bytes = vec![0_u8; 0x104];
    vram_bytes
        .get_mut(0x100..0x104)
        .ok_or_else(|| std::io::Error::other("missing VRAM-read program"))?
        .copy_from_slice(&vram_program);
    let mut vram_memory = MemoryImage::zeroed()?;
    vram_memory.write(0x8000, 0x24)?;
    let mut vram_builder =
        TraceBuilder::new_dmg_post_boot_mbc3(RomImage::new(vram_bytes)?, vram_memory, Vec::new());
    let vram = vram_builder.run_exact_steps(2)?;
    let vram_rows = vram.rows().collect::<Vec<_>>();

    let first_vram = vram_rows
        .first()
        .ok_or_else(|| std::io::Error::other("missing first VRAM row"))?;
    let second_vram = vram_rows
        .get(1)
        .ok_or_else(|| std::io::Error::other("missing second VRAM row"))?;
    assert!(blue_rom_block_candidate(first_vram));
    assert!(!blue_rom_block_candidate(second_vram));
    Ok(())
}

#[test]
fn resumed_checkpoint_matches_uninterrupted_execution() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x108];
    let program = bytes
        .get_mut(0x100..0x108)
        .ok_or_else(|| std::io::Error::other("missing cartridge-entry program"))?;
    program.copy_from_slice(&[0x3e, 0x42, 0xea, 0x00, 0xc0, 0x00, 0x00, 0x00]);

    let mut uninterrupted = TraceBuilder::new_dmg_post_boot_mbc3(
        RomImage::new(bytes.clone())?,
        MemoryImage::zeroed()?,
        Vec::new(),
    );
    let expected = uninterrupted.run_exact_boundary(4)?.final_state();

    let mut first = TraceBuilder::new_dmg_post_boot_mbc3(
        RomImage::new(bytes.clone())?,
        MemoryImage::zeroed()?,
        Vec::new(),
    );
    first.run_exact_boundary(2)?;
    let checkpoint_state = first.state();
    let checkpoint_memory = MemoryImage::from_checkpoint_bytes(first.checkpoint_memory())?;
    let mut resumed = TraceBuilder::resume(
        RomImage::new(bytes)?,
        checkpoint_memory,
        Vec::new(),
        checkpoint_state,
    )?;
    let actual = resumed.run_exact_boundary(2)?.final_state();

    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn resumed_checkpoint_recomputes_the_consumed_input_prefix()
-> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x102];
    let program = bytes
        .get_mut(0x100..0x102)
        .ok_or_else(|| std::io::Error::other("missing joypad-read program"))?;
    program.copy_from_slice(&[0xf0, 0x00]);
    let mut first = TraceBuilder::new_dmg_post_boot_mbc3(
        RomImage::new(bytes.clone())?,
        MemoryImage::zeroed()?,
        vec![0x80],
    );
    first.step()?;
    let state = first.state();
    let memory_bytes = first.checkpoint_memory();

    TraceBuilder::resume(
        RomImage::new(bytes.clone())?,
        MemoryImage::from_checkpoint_bytes(memory_bytes.clone())?,
        vec![0x80],
        state,
    )?;
    let wrong = TraceBuilder::resume(
        RomImage::new(bytes)?,
        MemoryImage::from_checkpoint_bytes(memory_bytes)?,
        vec![0x00],
        state,
    );
    assert!(matches!(
        wrong,
        Err(zksm83_trace::TraceBuilderError::CheckpointInputRootMismatch)
    ));
    Ok(())
}

#[test]
fn dmg_trace_authenticates_opcode_and_immediate_fetches_from_hram()
-> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0x00])?;
    let mut memory = MemoryImage::zeroed()?;
    memory.write(0xff80, 0x3e)?;
    memory.write(0xff81, 0x42)?;
    let canonical = CpuState::dmg_post_boot_initial();
    let cpu = CpuState::new(
        canonical.registers(),
        canonical.flags(),
        0xff80,
        canonical.sp(),
        canonical.ime(),
        canonical.run_state(),
        canonical.m_cycles(),
    );
    let state = VmState::from_profile_parts(
        MachineContext::new(
            MachineProfile::DmgPostBootMbc3V1,
            zksm83_core::DmgDeviceState::dmg_post_boot(),
        ),
        cpu,
        Mbc3State::profile_initial(),
        rom.root(),
        memory.root(),
        LogAccumulator::empty(LogKind::Input),
        LogAccumulator::empty(LogKind::Output),
    )?;
    let mut builder = TraceBuilder::resume(rom, memory, Vec::new(), state)?;
    let witness = builder.run_exact_steps(1)?;

    assert_eq!(witness.final_state().cpu().pc(), 0xff82);
    assert_eq!(witness.final_state().cpu().registers().a, 0x42);
    let mut events = witness
        .rows()
        .next()
        .ok_or_else(|| std::io::Error::other("missing HRAM trace row"))?
        .effects()
        .bus_events();
    assert!(matches!(
        events.next(),
        Some(zksm83_core::BusEvent::MemoryOpcodeFetch(_))
    ));
    assert!(matches!(
        events.next(),
        Some(zksm83_core::BusEvent::MemoryImmediateRead(_))
    ));
    Ok(())
}

#[test]
fn dmg_oam_dma_serializes_one_authenticated_copy_after_a_timed_hram_step()
-> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0x00])?;
    let mut memory = MemoryImage::zeroed()?;
    memory.write(0xff80, 0x00)?;
    memory.write(0xc000, 0x42)?;
    let canonical = CpuState::dmg_post_boot_initial();
    let cpu = CpuState::new(
        canonical.registers(),
        canonical.flags(),
        0xff80,
        canonical.sp(),
        canonical.ime(),
        canonical.run_state(),
        canonical.m_cycles(),
    );
    let mut devices = zksm83_core::DmgDeviceState::dmg_post_boot();
    assert_eq!(devices.write_mmio(0xff46, 0xc0), Some(0x00));
    let state = VmState::from_profile_parts(
        MachineContext::new(MachineProfile::DmgPostBootMbc3V1, devices),
        cpu,
        Mbc3State::profile_initial(),
        rom.root(),
        memory.root(),
        LogAccumulator::empty(LogKind::Input),
        LogAccumulator::empty(LogKind::Output),
    )?;
    let mut builder = TraceBuilder::resume(rom, memory, Vec::new(), state)?;
    let scheduled = builder.step()?;
    assert_eq!(scheduled.effects().kind(), StepKind::Instruction);
    assert_eq!(scheduled.after().dmg_devices().dma_owed(), 1);
    assert_eq!(
        scheduled.after().dmg_devices().dma_pack().to_le_bytes()[1],
        0
    );
    assert_eq!(scheduled.effects().bus_events().len(), 1);
    let row = builder.step()?;

    assert_eq!(row.effects().kind(), StepKind::DmaByte);
    assert_eq!(row.after().dmg_devices().dma_pack().to_le_bytes()[1], 1);
    assert_eq!(row.after().dmg_devices().dma_owed(), 0);
    assert_eq!(row.before().cpu().m_cycles(), row.after().cpu().m_cycles());
    assert_eq!(row.before().cpu().pc(), row.after().cpu().pc());
    let events = row.effects().bus_events().collect::<Vec<_>>();
    assert!(matches!(
        events.first(),
        Some(zksm83_core::BusEvent::DmgDmaMemoryRead(read)) if read.address == 0xc000 && read.value == 0x42
    ));
    assert!(matches!(
        events.get(1),
        Some(zksm83_core::BusEvent::DmgDmaWrite(write)) if write.address == 0xfe00 && write.after == 0x42
    ));
    Ok(())
}

#[test]
fn dmg_oam_dma_debt_drains_without_advancing_time_or_cpu() -> Result<(), Box<dyn std::error::Error>>
{
    let rom = RomImage::new(vec![0x00])?;
    let mut memory = MemoryImage::zeroed()?;
    memory.write(0xff80, 0x3e)?;
    memory.write(0xff81, 0x42)?;
    memory.write(0xc000, 0x11)?;
    memory.write(0xc001, 0x22)?;
    let canonical = CpuState::dmg_post_boot_initial();
    let cpu = CpuState::new(
        canonical.registers(),
        canonical.flags(),
        0xff80,
        canonical.sp(),
        canonical.ime(),
        canonical.run_state(),
        canonical.m_cycles(),
    );
    let mut devices = zksm83_core::DmgDeviceState::dmg_post_boot();
    assert_eq!(devices.write_mmio(0xff46, 0xc0), Some(0x00));
    let state = VmState::from_profile_parts(
        MachineContext::new(MachineProfile::DmgPostBootMbc3V1, devices),
        cpu,
        Mbc3State::profile_initial(),
        rom.root(),
        memory.root(),
        LogAccumulator::empty(LogKind::Input),
        LogAccumulator::empty(LogKind::Output),
    )?;
    let mut builder = TraceBuilder::resume(rom, memory, Vec::new(), state)?;
    let timed = builder.step()?;
    assert_eq!(timed.after().dmg_devices().dma_owed(), 2);
    assert_eq!(timed.after().cpu().pc(), 0xff82);
    let first = builder.step()?;
    let second = builder.step()?;

    assert_eq!(first.effects().kind(), StepKind::DmaByte);
    assert_eq!(second.effects().kind(), StepKind::DmaByte);
    assert_eq!(timed.after().cpu(), second.after().cpu());
    assert_eq!(
        timed.after().dmg_devices().ppu_line(),
        second.after().dmg_devices().ppu_line()
    );
    assert_eq!(
        timed.after().dmg_devices().ppu_dot(),
        second.after().dmg_devices().ppu_dot()
    );
    assert_eq!(second.after().dmg_devices().dma_owed(), 0);
    assert_eq!(second.after().dmg_devices().dma_pack().to_le_bytes()[1], 2);
    Ok(())
}

#[test]
fn multi_access_stack_steps_thread_memory_roots() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![
        0xcd, 0x06, 0x00, // CALL 0x0006
        0x76, // HALT after return
        0x00, 0x00, // Unexecuted padding
        0xc9, // RET
    ])?;
    let memory = MemoryImage::zeroed()?;
    let initial_root = memory.root();
    let witness = TraceBuilder::new(rom, memory, Vec::new()).run(4)?;

    assert_eq!(witness.step_count(), 3);
    assert_eq!(witness.final_state().cpu().sp(), 0xff00);
    assert_eq!(witness.final_state().cpu().run_state(), RunState::Halted);
    assert_ne!(witness.final_state().memory_root(), initial_root);
    Ok(())
}

#[test]
fn mbc3_trace_authenticates_banked_rom_and_isolates_sram_banks()
-> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x8000 + 19];
    let bank_zero = bytes
        .get_mut(..8)
        .ok_or_else(|| std::io::Error::other("missing bank-zero program"))?;
    bank_zero.copy_from_slice(&[
        0x3e, 0x02, // LD A,2
        0xea, 0x00, 0x20, // LD (0x2000),A
        0xc3, 0x00, 0x40, // JP 0x4000
    ]);
    let bank_two = bytes
        .get_mut(0x8000..0x8000 + 19)
        .ok_or_else(|| std::io::Error::other("missing bank-two program"))?;
    bank_two.copy_from_slice(&[
        0x3e, 0x0a, // LD A,0x0a
        0xea, 0x00, 0x00, // enable SRAM
        0x3e, 0x01, // LD A,1
        0xea, 0x00, 0x40, // select SRAM bank 1
        0x3e, 0x5a, // LD A,0x5a
        0xea, 0x00, 0xa0, // write SRAM
        0xfa, 0x00, 0xa0, // read SRAM
        0x76, // HALT
    ]);
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let witness = TraceBuilder::new(rom, memory, Vec::new()).run(16)?;

    assert_eq!(witness.final_state().cpu().run_state(), RunState::Halted);
    assert_eq!(witness.final_state().cpu().registers().a, 0x5a);
    assert_eq!(witness.final_state().mbc3().rom_bank(), 2);
    assert!(witness.final_state().mbc3().ram_enabled());
    assert_eq!(witness.final_state().mbc3().ram_rtc_select(), 1);
    Ok(())
}
