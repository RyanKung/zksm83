use zksm83_memory::{MemoryImage, RomImage};
use zksm83_trace::TraceBuilder;

use super::{BUS_INDEX_OFFSET, CpuStructuralRelation, test_fixtures::*};
use crate::{NativeTraceWitness, TRACE_BUS_START, UniformError};

#[test]
fn input_output_and_transcript_cursors_follow_ordered_bus_slots()
-> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![
        0xfa, 0xf0, 0xff, // LD A,(0xfff0)
        0xea, 0xf1, 0xff, // LD (0xfff1),A
        0x76, // HALT
    ])?;
    let memory = MemoryImage::zeroed()?;
    let witness = TraceBuilder::new(rom, memory, vec![0x42]).run(3)?;
    let trace = NativeTraceWitness::from_witness(&witness)?;
    for row in 0..=trace.active_row_count() {
        assert_row_satisfied(&CpuStructuralRelation, trace.columns(), row)?;
    }

    let mut wrong_input_index = native_row(&trace, 0)?;
    let slot = TRACE_BUS_START + 3 * crate::TRACE_BUS_SLOT_WIDTH;
    *wrong_input_index
        .get_mut(slot + BUS_INDEX_OFFSET)
        .ok_or(UniformError::Shape)? = 1;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_input_index)?;
    Ok(())
}
