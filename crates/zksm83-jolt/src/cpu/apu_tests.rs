use akita_pcs::Ring;
use zksm83_memory::{MemoryImage, RomImage};
use zksm83_trace::TraceBuilder;

use super::{BUS_VALUE_OFFSET, CPU_STRUCTURAL_MAX_DEGREE, CpuStructuralRelation, test_fixtures::*};
use crate::{
    NativeField, NativeTraceWitness, TRACE_AFTER_CPU_BYTE_BITS_START, TRACE_AFTER_STATE_START,
    TRACE_BEFORE_STATE_START, TRACE_BUS_SLOT_WIDTH, TRACE_BUS_START, TRACE_BUS_VALUE_BITS_START,
    UniformError, UniformRelation,
    trace::device::{
        TRACE_AFTER_APU_CONTROL_LOW_BITS_START, TRACE_AFTER_APU_MIXER_BITS_START,
        TRACE_AFTER_APU_WAVE_LOW_BITS_START, TRACE_BEFORE_APU_CONTROL_LOW_BITS_START,
    },
};

#[test]
fn apu_control_unused_and_wave_reads_are_exact() -> Result<(), Box<dyn std::error::Error>> {
    let trace = apu_register_trace()?;
    for row in 0..=trace.active_row_count() {
        assert_row_satisfied(&CpuStructuralRelation, trace.columns(), row)?;
    }
    let mut wrong_visible = native_row(&trace, 0)?;
    set(&mut wrong_visible, TRACE_AFTER_STATE_START, 0xbe)?;
    set(&mut wrong_visible, TRACE_AFTER_CPU_BYTE_BITS_START, 0)?;
    let value = TRACE_BUS_START + 3 * TRACE_BUS_SLOT_WIDTH + BUS_VALUE_OFFSET;
    set(&mut wrong_visible, value, 0xbe)?;
    set(&mut wrong_visible, TRACE_BUS_VALUE_BITS_START + 3 * 8, 0)?;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_visible)?;
    Ok(())
}

#[test]
fn apu_power_dac_trigger_and_wave_writes_are_bound() -> Result<(), Box<dyn std::error::Error>> {
    let trace = apu_write_trace()?;
    for row in 0..=trace.active_row_count() {
        assert_row_satisfied(&CpuStructuralRelation, trace.columns(), row)?;
    }

    let mut uncleared = native_row(&trace, 1)?;
    add(&mut uncleared, TRACE_AFTER_STATE_START + 31, 1)?;
    set(&mut uncleared, TRACE_AFTER_APU_CONTROL_LOW_BITS_START, 1)?;
    assert_native_row_rejected(&CpuStructuralRelation, &uncleared)?;

    let mut wrong_wave = native_row(&trace, 5)?;
    subtract(&mut wrong_wave, TRACE_AFTER_STATE_START + 34, 1)?;
    set(&mut wrong_wave, TRACE_AFTER_APU_WAVE_LOW_BITS_START, 0)?;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_wave)?;

    let mut missing_trigger = native_row(&trace, 11)?;
    subtract(&mut missing_trigger, TRACE_AFTER_STATE_START + 33, 1 << 51)?;
    set(
        &mut missing_trigger,
        TRACE_AFTER_APU_MIXER_BITS_START + 51,
        0,
    )?;
    assert_native_row_rejected(&CpuStructuralRelation, &missing_trigger)?;
    Ok(())
}

#[test]
fn apu_storage_cannot_claim_cpu_forced_one_bits() -> Result<(), Box<dyn std::error::Error>> {
    let trace = apu_register_trace()?;
    let mut wrong_storage = native_row(&trace, 0)?;
    let pack = wrong_storage
        .get(TRACE_BEFORE_STATE_START + 31)
        .copied()
        .ok_or(UniformError::Shape)?;
    set(
        &mut wrong_storage,
        TRACE_BEFORE_STATE_START + 31,
        pack + 256,
    )?;
    set(
        &mut wrong_storage,
        TRACE_BEFORE_APU_CONTROL_LOW_BITS_START + 8,
        1,
    )?;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_storage)?;
    Ok(())
}

#[test]
fn declared_degree_is_reached_by_apu_selector_polynomials() -> Result<(), Box<dyn std::error::Error>>
{
    let low = vec![NativeField::from_u64(0); crate::NATIVE_TRACE_COLUMN_COUNT];
    let high = vec![NativeField::from_u64(1); crate::NATIVE_TRACE_COLUMN_COUNT];
    let observed = interpolant_degree(&low, &high)?;
    assert_eq!(observed, CPU_STRUCTURAL_MAX_DEGREE);
    Ok(())
}

fn interpolant_degree(low: &[NativeField], high: &[NativeField]) -> Result<usize, UniformError> {
    let relation = CpuStructuralRelation;
    let sample_count = CPU_STRUCTURAL_MAX_DEGREE + 2;
    let mut values = (0..relation.constraint_count())
        .map(|_| Vec::with_capacity(sample_count))
        .collect::<Vec<_>>();
    for point in 0..sample_count {
        let point = NativeField::from_u64(u64::try_from(point).map_err(|_| UniformError::Shape)?);
        let row = low
            .iter()
            .copied()
            .zip(high.iter().copied())
            .map(|(low, high)| low + point * (high - low))
            .collect::<Vec<_>>();
        let mut constraints = vec![NativeField::from_u64(0); relation.constraint_count()];
        relation.evaluate(&row, &mut constraints)?;
        for (samples, value) in values.iter_mut().zip(constraints) {
            samples.push(value);
        }
    }
    values
        .into_iter()
        .map(observed_degree)
        .max()
        .ok_or(UniformError::Shape)
}

fn observed_degree(mut values: Vec<NativeField>) -> usize {
    let zero = NativeField::from_u64(0);
    let mut degree = 0;
    let mut order = 0;
    loop {
        if values.iter().any(|value| *value != zero) {
            degree = order;
        }
        if values.len() <= 1 {
            break;
        }
        values = values
            .windows(2)
            .filter_map(|pair| {
                pair.first()
                    .zip(pair.last())
                    .map(|(low, high)| *high - *low)
            })
            .collect();
        order += 1;
    }
    degree
}

fn apu_register_trace() -> Result<NativeTraceWitness, Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x10e];
    bytes
        .get_mut(0x100..0x10e)
        .ok_or(UniformError::Shape)?
        .copy_from_slice(&[
            0xfa, 0x11, 0xff, // LD A,(NR11), visible BF
            0xfa, 0x26, 0xff, // LD A,(NR52), visible F1
            0xfa, 0x27, 0xff, // LD A,(unused), visible FF
            0xfa, 0x30, 0xff, // LD A,(wave RAM)
            0x76, 0x00, // HALT plus padding byte
        ]);
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let witness = TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, Vec::new()).run(5)?;
    NativeTraceWitness::from_witness(&witness).map_err(Into::into)
}

fn apu_write_trace() -> Result<NativeTraceWitness, Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x120];
    bytes
        .get_mut(0x100..0x120)
        .ok_or(UniformError::Shape)?
        .copy_from_slice(&[
            0x3e, 0x00, 0xea, 0x26, 0xff, // power off
            0x3e, 0xc0, 0xea, 0x11, 0xff, // length write while off
            0x3e, 0xff, 0xea, 0x30, 0xff, // wave RAM write while off
            0x3e, 0x80, 0xea, 0x26, 0xff, // power on
            0x3e, 0xf0, 0xea, 0x21, 0xff, // channel-four DAC on
            0x3e, 0x80, 0xea, 0x23, 0xff, // channel-four trigger
            0x76, 0x00, // HALT plus padding byte
        ]);
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let witness = TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, Vec::new()).run(13)?;
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

fn subtract(row: &mut [u64], index: usize, decrement: u64) -> Result<(), UniformError> {
    let value = row.get_mut(index).ok_or(UniformError::Shape)?;
    *value = value.checked_sub(decrement).ok_or(UniformError::Shape)?;
    Ok(())
}
