use zksm83_memory::{MemoryImage, RomImage};
use zksm83_trace::TraceBuilder;

use super::{BUS_VALUE_OFFSET, CpuStructuralRelation, test_fixtures::*};
use crate::{
    NativeTraceWitness, TRACE_AFTER_CPU_BYTE_BITS_START, TRACE_AFTER_STATE_START,
    TRACE_BUS_SLOT_WIDTH, TRACE_BUS_START, TRACE_BUS_VALUE_BITS_START, UniformError,
    trace::device::{
        TRACE_AFTER_DMG_LOW_BITS_START, TRACE_PPU_MODE_BITS_START, TRACE_TIMER_PHASE_FIVE,
    },
};

#[test]
fn visible_timer_and_ppu_register_reads_are_bound() -> Result<(), Box<dyn std::error::Error>> {
    let trace = visible_register_trace()?;
    for row in 0..=trace.active_row_count() {
        assert_row_satisfied(&CpuStructuralRelation, trace.columns(), row)?;
    }

    let mut wrong_div = native_row(&trace, 0)?;
    set(&mut wrong_div, TRACE_AFTER_STATE_START, 0xaa)?;
    set(&mut wrong_div, TRACE_AFTER_CPU_BYTE_BITS_START, 0)?;
    let value = TRACE_BUS_START + 3 * TRACE_BUS_SLOT_WIDTH + BUS_VALUE_OFFSET;
    set(&mut wrong_div, value, 0xaa)?;
    set(&mut wrong_div, TRACE_BUS_VALUE_BITS_START + 3 * 8, 0)?;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_div)?;
    Ok(())
}

#[test]
fn static_mmio_writes_update_and_mask_after_state() -> Result<(), Box<dyn std::error::Error>> {
    let trace = static_write_trace()?;
    for row in 0..=trace.active_row_count() {
        assert_row_satisfied(&CpuStructuralRelation, trace.columns(), row)?;
    }

    let mut wrong_tma = native_row(&trace, 1)?;
    add(&mut wrong_tma, TRACE_AFTER_STATE_START + 23, 1 << 16)?;
    set(&mut wrong_tma, TRACE_AFTER_DMG_LOW_BITS_START + 16, 1)?;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_tma)?;

    let mut unmasked_tac = native_row(&trace, 3)?;
    add(&mut unmasked_tac, TRACE_AFTER_STATE_START + 23, 8_u64 << 24)?;
    set(&mut unmasked_tac, TRACE_AFTER_DMG_LOW_BITS_START + 27, 1)?;
    assert_native_row_rejected(&CpuStructuralRelation, &unmasked_tac)?;
    Ok(())
}

#[test]
fn derived_timer_and_ppu_witnesses_are_not_free() -> Result<(), Box<dyn std::error::Error>> {
    let trace = visible_register_trace()?;
    let mut wrong_mode = native_row(&trace, 0)?;
    set(&mut wrong_mode, TRACE_PPU_MODE_BITS_START + 1, 0)?;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_mode)?;

    let mut wrong_phase = native_row(&trace, 0)?;
    set(&mut wrong_phase, TRACE_TIMER_PHASE_FIVE, 1)?;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_phase)?;
    Ok(())
}

fn visible_register_trace() -> Result<NativeTraceWitness, Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x111];
    bytes
        .get_mut(0x100..0x111)
        .ok_or(UniformError::Shape)?
        .copy_from_slice(&[
            0xfa, 0x04, 0xff, // LD A,(DIV)
            0xfa, 0x05, 0xff, // LD A,(TIMA)
            0xfa, 0x07, 0xff, // LD A,(TAC)
            0xfa, 0x41, 0xff, // LD A,(STAT)
            0xfa, 0x44, 0xff, // LD A,(LY)
            0x76, 0x00, // HALT plus padding byte
        ]);
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let witness = TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, Vec::new()).run(6)?;
    NativeTraceWitness::from_witness(&witness).map_err(Into::into)
}

fn static_write_trace() -> Result<NativeTraceWitness, Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x118];
    bytes
        .get_mut(0x100..0x118)
        .ok_or(UniformError::Shape)?
        .copy_from_slice(&[
            0x3e, 0x42, // LD A,42
            0xea, 0x06, 0xff, // LD (TMA),A
            0x3e, 0xff, // LD A,FF
            0xea, 0x07, 0xff, // LD (TAC),A
            0xea, 0x41, 0xff, // LD (STAT),A
            0xea, 0x42, 0xff, // LD (SCY),A
            0xea, 0x45, 0xff, // LD (LYC),A
            0xea, 0x47, 0xff, // LD (BGP),A
            0x76, 0x00, // HALT plus padding byte
        ]);
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let witness = TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, Vec::new()).run(9)?;
    NativeTraceWitness::from_witness(&witness).map_err(Into::into)
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
