use zksm83_memory::{MemoryImage, RomImage};
use zksm83_trace::TraceBuilder;

use super::{CpuStructuralRelation, test_fixtures::*};
use crate::{
    NativeTraceWitness, TRACE_AFTER_INTERRUPT_ENABLE_BITS_START, TRACE_AFTER_STATE_START,
    UniformError,
};

#[test]
fn interrupt_enable_mmio_read_write_and_visible_value_are_bound()
-> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x10a];
    bytes
        .get_mut(0x100..0x10a)
        .ok_or(UniformError::Shape)?
        .copy_from_slice(&[
            0x3e, 0x01, // LD A,1
            0xea, 0xff, 0xff, // LD (0xffff),A
            0xfa, 0xff, 0xff, // LD A,(0xffff)
            0x76, 0x00, // HALT plus padding byte
        ]);
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let witness = TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, Vec::new()).run(4)?;
    let trace = NativeTraceWitness::from_witness(&witness)?;
    for row in 0..=trace.active_row_count() {
        assert_row_satisfied(&CpuStructuralRelation, trace.columns(), row)?;
    }

    let mut wrong_enable = native_row(&trace, 1)?;
    *wrong_enable
        .get_mut(TRACE_AFTER_STATE_START + 22)
        .ok_or(UniformError::Shape)? = 0;
    *wrong_enable
        .get_mut(TRACE_AFTER_INTERRUPT_ENABLE_BITS_START)
        .ok_or(UniformError::Shape)? = 0;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_enable)?;
    Ok(())
}
