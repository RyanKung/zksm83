//! Native trace-column tests.

use zksm83_core::{BusWitness, StepInput, StepRelation, VmState};
use zksm83_memory::{MemoryImage, RomImage};
use zksm83_trace::TraceRow;

use super::{
    NATIVE_TRACE_COLUMN_COUNT, NativeTraceWitness, TRACE_ACTIVE, TRACE_BEFORE_CPU_BYTE_BITS_START,
    TRACE_BEFORE_ROM_BANK_BITS_START, TRACE_BUS_ADDRESS_BITS_START, TRACE_BUS_START,
    TRACE_ISA_ADDRESS_START, TRACE_MEMORY_START, TRACE_MODE_START, TRACE_ROM_SELECTOR_START,
    TRACE_ROW_BITS_START, encode_padding_row,
};
use crate::{
    TRACE_BUS_SLOTS, TRACE_MEMORY_SLOT_WIDTH, TRACE_ROW_BIT_COUNT, UNIFORM_ROW_COUNT,
    fixed_isa_table,
};

#[test]
fn trace_column_families_partition_v2_layout() {
    let device_start = TRACE_MEMORY_START + TRACE_BUS_SLOTS * TRACE_MEMORY_SLOT_WIDTH;
    let families = [
        ("state", 0, TRACE_ACTIVE, 76),
        ("control and ISA", TRACE_ACTIVE, TRACE_BUS_START, 64),
        (
            "bus tuples",
            TRACE_BUS_START,
            TRACE_BEFORE_CPU_BYTE_BITS_START,
            60,
        ),
        (
            "CPU helpers",
            TRACE_BEFORE_CPU_BYTE_BITS_START,
            TRACE_BUS_ADDRESS_BITS_START,
            280,
        ),
        (
            "bus decompositions",
            TRACE_BUS_ADDRESS_BITS_START,
            TRACE_BEFORE_ROM_BANK_BITS_START,
            260,
        ),
        (
            "mapper",
            TRACE_BEFORE_ROM_BANK_BITS_START,
            TRACE_ROM_SELECTOR_START,
            20,
        ),
        (
            "ROM lookup",
            TRACE_ROM_SELECTOR_START,
            TRACE_ROW_BITS_START,
            10,
        ),
        ("row index", TRACE_ROW_BITS_START, TRACE_MEMORY_START, 14),
        ("memory", TRACE_MEMORY_START, device_start, 190),
        ("devices", device_start, NATIVE_TRACE_COLUMN_COUNT, 2_307),
    ];
    let mut expected_start = 0;
    for (name, start, end, expected_width) in families {
        assert_eq!(start, expected_start, "gap or overlap before {name}");
        assert_eq!(end - start, expected_width, "width drift in {name}");
        expected_start = end;
    }
    assert_eq!(expected_start, NATIVE_TRACE_COLUMN_COUNT);
}

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
            .get(TRACE_MODE_START + super::TRACE_MODE_COUNT - 1)
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
    let padding_index = UNIFORM_ROW_COUNT / 2 + 1;
    let mut canonical = (0..NATIVE_TRACE_COLUMN_COUNT)
        .map(|_| Vec::with_capacity(1))
        .collect::<Vec<_>>();
    encode_padding_row(&mut canonical, after, padding_index, &fixed_isa_table()?)?;
    for (actual, expected) in witness.columns().iter().zip(canonical.iter()) {
        assert_eq!(actual.get(padding_index), expected.first());
    }
    for bit in 0..TRACE_ROW_BIT_COUNT {
        assert_eq!(
            witness
                .columns()
                .get(TRACE_ROW_BITS_START + bit)
                .and_then(|column| column.last()),
            Some(&u64::from((((UNIFORM_ROW_COUNT - 1) >> bit) & 1) != 0))
        );
    }
    Ok(())
}
