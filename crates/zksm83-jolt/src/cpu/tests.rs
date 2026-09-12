use std::cell::Cell;

use akita_pcs::Ring;
use zksm83_core::{BusWitness, ImeState, Registers, StepInput, VmState};
use zksm83_memory::{MemoryImage, RomImage};
use zksm83_trace::{TraceBuilder, TraceRow};

use super::test_fixtures::*;
use super::{
    BUS_PHYSICAL_ADDRESS_OFFSET, BUS_VALUE_OFFSET, CPU_STRUCTURAL_CONSTRAINT_COUNT,
    CpuStructuralRelation, STATE_MBC3_ROM_BANK, evaluate_constraints,
    evaluate_constraints_with_access,
};
use crate::{
    NATIVE_TRACE_COLUMN_COUNT, NativeField, NativeTraceWitness, TRACE_ACTIVE,
    TRACE_AFTER_ROM_BANK_BITS_START, TRACE_AFTER_STATE_START, TRACE_BUS_PHYSICAL_BITS_START,
    TRACE_BUS_SLOT_WIDTH, TRACE_BUS_START, TRACE_BUS_VALUE_BITS_START, UniformError,
    UniformRelation,
};

#[test]
fn validated_nop_and_padding_satisfy_structural_relation() -> Result<(), Box<dyn std::error::Error>>
{
    let rom = RomImage::new(vec![0x00])?;
    let memory = MemoryImage::zeroed()?;
    let before = VmState::profile_initial(rom.root(), memory.root());
    let row = TraceRow::execute(before, StepInput::new(vec![BusWitness::Rom(rom.read(0)?)]))?;
    let witness = NativeTraceWitness::from_rows(&[&row])?;
    let relation = CpuStructuralRelation;
    assert_row_satisfied(&relation, witness.columns(), 0)?;
    assert_row_satisfied(&relation, witness.columns(), 1)?;

    let mut tampered = witness
        .columns()
        .iter()
        .map(|column| column.first().copied().ok_or(UniformError::Shape))
        .collect::<Result<Vec<_>, _>>()?;
    *tampered.get_mut(TRACE_ACTIVE).ok_or(UniformError::Shape)? = 2;
    let mut constraints = vec![NativeField::from_u64(0); CPU_STRUCTURAL_CONSTRAINT_COUNT];
    relation.evaluate(
        &tampered
            .into_iter()
            .map(NativeField::from_u64)
            .collect::<Vec<_>>(),
        &mut constraints,
    )?;
    assert!(
        constraints
            .iter()
            .any(|constraint| *constraint != NativeField::from_u64(0))
    );
    let mut tampered_rom_value = witness
        .columns()
        .iter()
        .map(|column| column.first().copied().ok_or(UniformError::Shape))
        .collect::<Result<Vec<_>, _>>()?;
    *tampered_rom_value
        .get_mut(crate::TRACE_ROM_VALUE_START)
        .ok_or(UniformError::Shape)? = 1;
    assert_native_row_rejected(&relation, &tampered_rom_value)?;
    Ok(())
}

#[test]
fn structural_relation_used_slot_count_is_stable() -> Result<(), Box<dyn std::error::Error>> {
    let trace = single_opcode_trace(0x00)?;
    let row = native_row(&trace, 0)?
        .into_iter()
        .map(NativeField::from_u64)
        .collect::<Vec<_>>();
    let mut constraints = vec![NativeField::from_u64(0); CPU_STRUCTURAL_CONSTRAINT_COUNT];
    assert_eq!(evaluate_constraints(&row, &mut constraints)?, 5355);
    Ok(())
}

#[test]
fn structural_relation_reads_every_native_trace_column() -> Result<(), Box<dyn std::error::Error>> {
    let trace = single_opcode_trace(0x00)?;
    let row = native_row(&trace, 0)?
        .into_iter()
        .map(NativeField::from_u64)
        .collect::<Vec<_>>();
    let accessed = (0..NATIVE_TRACE_COLUMN_COUNT)
        .map(|_| Cell::new(false))
        .collect::<Vec<_>>();
    let mut constraints = vec![NativeField::from_u64(0); CPU_STRUCTURAL_CONSTRAINT_COUNT];
    evaluate_constraints_with_access(&row, &mut constraints, &accessed)?;
    let unread = accessed
        .iter()
        .enumerate()
        .filter_map(|(index, value)| (!value.get()).then_some(index))
        .collect::<Vec<_>>();
    assert!(unread.is_empty(), "unread native trace columns: {unread:?}");
    Ok(())
}

#[test]
fn mbc3_bank_update_and_banked_rom_mapping_are_bound() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x8001];
    bytes
        .get_mut(..8)
        .ok_or(UniformError::Shape)?
        .copy_from_slice(&[
            0x3e, 0x02, // LD A,2
            0xea, 0x00, 0x20, // LD (0x2000),A
            0xc3, 0x00, 0x40, // JP 0x4000
        ]);
    *bytes.get_mut(0x8000).ok_or(UniformError::Shape)? = 0x76;
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let witness = TraceBuilder::new(rom, memory, Vec::new()).run(4)?;
    let trace = NativeTraceWitness::from_witness(&witness)?;
    let relation = CpuStructuralRelation;
    for row in 0..=trace.active_row_count() {
        assert_row_satisfied(&relation, trace.columns(), row)?;
    }

    let mut wrong_bank = native_row(&trace, 1)?;
    *wrong_bank
        .get_mut(TRACE_AFTER_STATE_START + STATE_MBC3_ROM_BANK)
        .ok_or(UniformError::Shape)? = 3;
    *wrong_bank
        .get_mut(TRACE_AFTER_ROM_BANK_BITS_START)
        .ok_or(UniformError::Shape)? = 1;
    *wrong_bank
        .get_mut(TRACE_AFTER_ROM_BANK_BITS_START + 1)
        .ok_or(UniformError::Shape)? = 1;
    assert_native_row_rejected(&relation, &wrong_bank)?;

    let mut wrong_physical = native_row(&trace, 3)?;
    *wrong_physical
        .get_mut(TRACE_BUS_START + BUS_PHYSICAL_ADDRESS_OFFSET)
        .ok_or(UniformError::Shape)? = 0x8001;
    *wrong_physical
        .get_mut(TRACE_BUS_PHYSICAL_BITS_START)
        .ok_or(UniformError::Shape)? = 1;
    assert_native_row_rejected(&relation, &wrong_physical)?;
    Ok(())
}

#[test]
fn mbc3_zero_bank_ram_enable_and_ram_select_updates_are_bound()
-> Result<(), Box<dyn std::error::Error>> {
    let program = vec![
        0x3e, 0x00, 0xea, 0x00, 0x20, // bank zero maps to bank one
        0x3e, 0x1a, 0xea, 0x00, 0x00, // low nibble 0x0a enables RAM
        0x3e, 0x05, 0xea, 0x00, 0x40, // select RAM/RTC value five
        0x76,
    ];
    let rom = RomImage::new(program)?;
    let memory = MemoryImage::zeroed()?;
    let witness = TraceBuilder::new(rom, memory, Vec::new()).run(7)?;
    let trace = NativeTraceWitness::from_witness(&witness)?;
    let relation = CpuStructuralRelation;
    for row in 0..=trace.active_row_count() {
        assert_row_satisfied(&relation, trace.columns(), row)?;
    }
    assert_eq!(trace.final_state().mbc3().rom_bank(), 1);
    assert!(trace.final_state().mbc3().ram_enabled());
    assert_eq!(trace.final_state().mbc3().ram_rtc_select(), 5);
    Ok(())
}

#[test]
fn mbc3_disabled_ram_open_bus_and_ignored_write_are_bound() -> Result<(), Box<dyn std::error::Error>>
{
    let program = vec![
        0xfa, 0x00, 0xa0, // disabled RAM reads as 0xff
        0x3e, 0x77, // LD A,0x77
        0xea, 0x00, 0xa0, // disabled RAM write is ignored
        0x76,
    ];
    let rom = RomImage::new(program)?;
    let memory = MemoryImage::zeroed()?;
    let witness = TraceBuilder::new(rom, memory, Vec::new()).run(4)?;
    let trace = NativeTraceWitness::from_witness(&witness)?;
    let relation = CpuStructuralRelation;
    for row in 0..=trace.active_row_count() {
        assert_row_satisfied(&relation, trace.columns(), row)?;
    }

    let mut tampered = native_row(&trace, 0)?;
    let bus_value = TRACE_BUS_START + 3 * TRACE_BUS_SLOT_WIDTH + BUS_VALUE_OFFSET;
    *tampered.get_mut(bus_value).ok_or(UniformError::Shape)? = 0xfe;
    let value_bits = TRACE_BUS_VALUE_BITS_START + 3 * 8;
    *tampered.get_mut(value_bits).ok_or(UniformError::Shape)? = 0;
    assert_native_row_rejected(&relation, &tampered)?;
    Ok(())
}

#[test]
fn inc_dec_and_every_alu8_family_satisfy_and_bind_arithmetic_witness()
-> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (0x04, 0x12, 0xff, 0x10),
        (0x05, 0x12, 0x00, 0x10),
        (0x80, 0xf0, 0x30, 0x00),
        (0x88, 0x0f, 0x00, 0x10),
        (0x90, 0x00, 0x01, 0x00),
        (0x98, 0x10, 0x0f, 0x10),
        (0xa0, 0xa5, 0x3c, 0x00),
        (0xa8, 0xa5, 0x3c, 0x00),
        (0xb0, 0xa5, 0x3c, 0x00),
        (0xb8, 0x00, 0x00, 0x00),
    ];
    let relation = CpuStructuralRelation;
    for (opcode, accumulator, operand, flags) in cases {
        let trace = arithmetic_opcode_trace(opcode, accumulator, operand, flags)?;
        assert_row_satisfied(&relation, trace.columns(), 0)?;
    }

    let trace = arithmetic_opcode_trace(0x80, 0xf0, 0x30, 0)?;
    let mut tampered = trace
        .columns()
        .iter()
        .map(|column| column.first().copied().ok_or(UniformError::Shape))
        .collect::<Result<Vec<_>, _>>()?;
    let result = tampered
        .get_mut(crate::TRACE_RESULT_VALUE)
        .ok_or(UniformError::Shape)?;
    *result = result.wrapping_add(1);
    assert_native_row_rejected(&relation, &tampered)?;
    Ok(())
}

#[test]
fn relative_absolute_and_hl_control_flow_is_bound() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (vec![0x18, 0x80], 0x00, 0x0000),
        (vec![0x20, 0x7f], 0x80, 0x0000),
        (vec![0xc3, 0x34, 0x12], 0x00, 0x0000),
        (vec![0xca, 0x78, 0x56], 0x80, 0x0000),
        (vec![0xc2, 0x78, 0x56], 0x80, 0x0000),
        (vec![0xe9], 0x00, 0xbeef),
    ];
    let relation = CpuStructuralRelation;
    for (bytes, flags, hl) in cases {
        let trace = control_opcode_trace(bytes, flags, hl)?;
        assert_row_satisfied(&relation, trace.columns(), 0)?;
    }

    let trace = control_opcode_trace(vec![0x18, 0x80], 0, 0)?;
    let mut tampered = trace
        .columns()
        .iter()
        .map(|column| column.first().copied().ok_or(UniformError::Shape))
        .collect::<Result<Vec<_>, _>>()?;
    let sequential = tampered
        .get_mut(crate::TRACE_SEQUENTIAL_PC)
        .ok_or(UniformError::Shape)?;
    *sequential = sequential.wrapping_add(1);
    assert_native_row_rejected(&relation, &tampered)?;

    let trace = control_opcode_trace(vec![0xc3, 0x34, 0x12], 0, 0)?;
    let mut changed_fetch = trace
        .columns()
        .iter()
        .map(|column| column.first().copied().ok_or(UniformError::Shape))
        .collect::<Result<Vec<_>, _>>()?;
    *changed_fetch
        .get_mut(crate::TRACE_BUS_START + 10)
        .ok_or(UniformError::Shape)? = 0;
    assert_native_row_rejected(&relation, &changed_fetch)?;
    Ok(())
}

#[test]
fn register_load_flag_low_power_and_ime_operations_are_bound()
-> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (
            vec![0x01, 0x34, 0x12],
            Registers::default(),
            0x00,
            ImeState::Disabled,
        ),
        (
            vec![0x06, 0xa5],
            Registers::default(),
            0x00,
            ImeState::Disabled,
        ),
        (
            vec![0x41],
            Registers {
                c: 0x42,
                ..Registers::default()
            },
            0x00,
            ImeState::Disabled,
        ),
        (
            vec![0x2f],
            Registers {
                a: 0x55,
                ..Registers::default()
            },
            0x90,
            ImeState::Disabled,
        ),
        (vec![0x37], Registers::default(), 0x80, ImeState::Disabled),
        (vec![0x3f], Registers::default(), 0x90, ImeState::Disabled),
        (
            vec![0xf3],
            Registers::default(),
            0x00,
            ImeState::EnablePending,
        ),
        (vec![0xfb], Registers::default(), 0x00, ImeState::Enabled),
        (
            vec![0x00],
            Registers::default(),
            0x00,
            ImeState::EnablePending,
        ),
        (
            vec![0x10, 0x00],
            Registers::default(),
            0x00,
            ImeState::Disabled,
        ),
    ];
    let relation = CpuStructuralRelation;
    for (bytes, registers, flags, ime) in cases {
        let trace = register_opcode_trace(bytes, registers, flags, ime)?;
        assert_row_satisfied(&relation, trace.columns(), 0)?;
    }
    Ok(())
}
