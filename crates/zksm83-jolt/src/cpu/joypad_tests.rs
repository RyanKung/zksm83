use zksm83_memory::{MemoryImage, RomImage};
use zksm83_trace::TraceBuilder;

use super::{BUS_VALUE_OFFSET, CpuStructuralRelation, test_fixtures::*};
use crate::{
    NativeTraceWitness, TRACE_AFTER_CPU_BYTE_BITS_START, TRACE_AFTER_STATE_START,
    TRACE_BUS_SLOT_WIDTH, TRACE_BUS_START, TRACE_BUS_VALUE_BITS_START,
};

#[test]
fn joypad_sample_binds_value_pack_and_falling_interrupt() -> Result<(), Box<dyn std::error::Error>>
{
    let witness = dmg_trace(&[0xfa, 0x00, 0xff, 0x76], vec![0x10], 2)?;
    let trace = NativeTraceWitness::from_witness(&witness)?;
    assert_row_satisfied(&CpuStructuralRelation, trace.columns(), 0)?;
    assert_eq!(trace.final_state().dmg_devices().interrupt_request(), 0x11);
    assert_eq!(trace.final_state().dmg_devices().joypad_pack(), 0x1000);

    let mut wrong_value = native_row(&trace, 0)?;
    set(&mut wrong_value, TRACE_AFTER_STATE_START, 0xcf)?;
    set(&mut wrong_value, TRACE_AFTER_CPU_BYTE_BITS_START, 1)?;
    set(
        &mut wrong_value,
        TRACE_BUS_START + 3 * TRACE_BUS_SLOT_WIDTH + BUS_VALUE_OFFSET,
        0xcf,
    )?;
    set(&mut wrong_value, TRACE_BUS_VALUE_BITS_START + 3 * 8, 1)?;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_value)?;
    Ok(())
}

#[test]
fn joypad_read_modify_write_uses_the_sampled_buttons_in_slot_order()
-> Result<(), Box<dyn std::error::Error>> {
    let witness = dmg_trace(&[0x21, 0x00, 0xff, 0x34, 0x76], vec![0], 3)?;
    let trace = NativeTraceWitness::from_witness(&witness)?;
    assert_row_satisfied(&CpuStructuralRelation, trace.columns(), 1)?;
    assert_eq!(trace.final_state().dmg_devices().joypad_pack(), 0x0010);

    let mut wrong_pack = native_row(&trace, 1)?;
    set(&mut wrong_pack, TRACE_AFTER_STATE_START + 36, 0)?;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_pack)?;
    Ok(())
}

fn set(values: &mut [u64], index: usize, value: u64) -> Result<(), crate::UniformError> {
    *values.get_mut(index).ok_or(crate::UniformError::Shape)? = value;
    Ok(())
}

fn dmg_trace(
    program: &[u8],
    input: Vec<u8>,
    steps: u64,
) -> Result<zksm83_trace::Witness, Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x100 + program.len()];
    bytes
        .get_mut(0x100..)
        .ok_or(crate::UniformError::Shape)?
        .copy_from_slice(program);
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    Ok(TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, input).run(steps)?)
}
