//! Native trace-column tests.

use zksm83_core::{BusWitness, StepInput, StepRelation, VmState};
use zksm83_memory::{MemoryImage, RomImage};
use zksm83_trace::TraceRow;

use super::{
    NATIVE_TRACE_COLUMN_COUNT, NativeTraceWitness, TRACE_ACTIVE, TRACE_ISA_ADDRESS_START,
    TRACE_MODE_START,
};
use crate::UNIFORM_ROW_COUNT;

#[test]
fn validated_rows_encode_and_padding_is_canonical() -> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0x00])?;
    let memory = MemoryImage::zeroed()?;
    let before = VmState::profile_initial(rom.root(), memory.root());
    let input = StepInput::new(vec![BusWitness::Rom(rom.read(0)?)]);
    let (after, effects) = StepRelation::apply(before, input)?;
    let row = TraceRow::execute(before, StepInput::new(vec![BusWitness::Rom(rom.read(0)?)]))?;
    assert_eq!(row.after(), after);
    assert_eq!(row.effects(), &effects);
    let witness = NativeTraceWitness::from_rows(&[&row])?;
    assert_eq!(witness.columns().len(), NATIVE_TRACE_COLUMN_COUNT);
    assert!(
        witness
            .columns()
            .iter()
            .all(|column| column.len() == UNIFORM_ROW_COUNT)
    );
    let missing = || std::io::Error::other("missing native trace column");
    assert_eq!(
        witness
            .columns()
            .get(TRACE_ACTIVE)
            .ok_or_else(missing)?
            .first(),
        Some(&1)
    );
    assert_eq!(
        witness
            .columns()
            .get(TRACE_ACTIVE)
            .ok_or_else(missing)?
            .get(1),
        Some(&0)
    );
    assert_eq!(
        witness
            .columns()
            .get(TRACE_MODE_START + 6)
            .ok_or_else(missing)?
            .get(1),
        Some(&1)
    );
    assert_eq!(
        witness
            .columns()
            .get(TRACE_ISA_ADDRESS_START)
            .ok_or_else(missing)?
            .get(1),
        Some(&1)
    );
    assert_eq!(witness.active_row_count(), 1);
    assert_eq!(witness.initial_state(), before);
    assert_eq!(witness.final_state(), after);
    witness.isa_lookup_columns()?;
    Ok(())
}
