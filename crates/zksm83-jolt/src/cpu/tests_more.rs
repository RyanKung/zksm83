use zksm83_core::{
    BusWitness, CpuState, DmgDeviceState, Flags, ImeState, MachineContext, MachineProfile,
    Mbc3State, Registers, RunState, StepInput, VmState,
};
use zksm83_memory::{LogAccumulator, LogKind, MemoryImage, RomImage};
use zksm83_trace::TraceRow;

use super::test_fixtures::*;
use super::{
    CpuStructuralRelation, prove_native_cpu_structural, prove_native_rom_cpu,
    verify_native_cpu_structural, verify_native_rom_cpu,
};
use crate::{
    NativeTraceWitness, ROM_IMAGE_BYTES, TRACE_INTERRUPT_START, UniformError, commit_rom,
    commit_witness,
};

#[test]
fn word_and_signed_sp_operations_are_bound() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (
            vec![0x09],
            Registers {
                b: 0x00,
                c: 0x01,
                h: 0xff,
                l: 0xff,
                ..Registers::default()
            },
            0x80,
        ),
        (
            vec![0x03],
            Registers {
                b: 0xff,
                c: 0xff,
                ..Registers::default()
            },
            0x00,
        ),
        (
            vec![0xf9],
            Registers {
                h: 0x12,
                l: 0x34,
                ..Registers::default()
            },
            0x00,
        ),
        (vec![0xe8, 0xff], Registers::default(), 0x00),
        (vec![0xf8, 0x01], Registers::default(), 0x00),
    ];
    let relation = CpuStructuralRelation;
    for (bytes, registers, flags) in cases {
        let trace = register_opcode_trace(bytes, registers, flags, ImeState::Disabled)?;
        assert_row_satisfied(&relation, trace.columns(), 0)?;
    }
    Ok(())
}

#[test]
fn push_pop_and_call_stack_relations_are_bound() -> Result<(), Box<dyn std::error::Error>> {
    let relation = CpuStructuralRelation;
    for trace in [push_bc_trace()?, pop_bc_trace()?, call_trace()?] {
        assert_row_satisfied(&relation, trace.columns(), 0)?;
    }
    Ok(())
}

#[test]
fn accumulator_and_cb_rotate_bit_families_are_bound() -> Result<(), Box<dyn std::error::Error>> {
    let relation = CpuStructuralRelation;
    let accumulator = register_opcode_trace(
        vec![0x17],
        Registers {
            a: 0x80,
            ..Registers::default()
        },
        0x10,
        ImeState::Disabled,
    )?;
    assert_row_satisfied(&relation, accumulator.columns(), 0)?;
    let cases = [
        (
            0x11,
            Registers {
                c: 0x80,
                ..Registers::default()
            },
            0x10,
        ),
        (
            0x00,
            Registers {
                b: 0x80,
                ..Registers::default()
            },
            0x00,
        ),
        (
            0x7c,
            Registers {
                h: 0x7f,
                ..Registers::default()
            },
            0x10,
        ),
        (
            0x87,
            Registers {
                a: 0xff,
                ..Registers::default()
            },
            0x80,
        ),
        (
            0xdb,
            Registers {
                e: 0x00,
                ..Registers::default()
            },
            0x80,
        ),
        (
            0x37,
            Registers {
                a: 0xf0,
                ..Registers::default()
            },
            0x00,
        ),
    ];
    for (opcode, registers, flags) in cases {
        let trace = cb_opcode_trace(opcode, registers, flags)?;
        assert_row_satisfied(&relation, trace.columns(), 0)?;
    }
    Ok(())
}

#[test]
fn decimal_adjust_add_and_subtract_paths_are_bound() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (0x9a, 0x00),
        (0x15, 0x20),
        (0x99, 0x10),
        (0x00, 0x60),
        (0x66, 0x70),
        (0x09, 0x00),
    ];
    let relation = CpuStructuralRelation;
    for (accumulator, flags) in cases {
        let trace = register_opcode_trace(
            vec![0x27],
            Registers {
                a: accumulator,
                ..Registers::default()
            },
            flags,
            ImeState::Disabled,
        )?;
        assert_row_satisfied(&relation, trace.columns(), 0)?;
    }
    Ok(())
}

#[test]
fn interrupt_dispatch_cpu_and_stack_relations_are_bound() -> Result<(), Box<dyn std::error::Error>>
{
    let rom = RomImage::new(vec![0; 0x101])?;
    let mut memory = MemoryImage::zeroed()?;
    let mut devices = DmgDeviceState::dmg_post_boot();
    let _prior_enable = devices.write_mmio(0xffff, 0x1f);
    let _prior_request = devices.write_mmio(0xff0f, 0x1f);
    let cpu = CpuState::new(
        Registers::default(),
        Flags::default(),
        0x0100,
        0xfffe,
        ImeState::Enabled,
        RunState::Running,
        0,
    );
    let before = VmState::from_profile_parts(
        MachineContext::new(MachineProfile::DmgPostBootMbc3V1, devices),
        cpu,
        Mbc3State::profile_initial(),
        rom.root(),
        memory.root(),
        LogAccumulator::empty(LogKind::Input),
        LogAccumulator::empty(LogKind::Output),
    )?;
    let high = memory.write_mapped(0xfffd, 0xfffd, 0x01)?;
    let low = memory.write_mapped(0xfffc, 0xfffc, 0x00)?;
    let row = TraceRow::execute(
        before,
        StepInput::new(vec![
            BusWitness::MemoryWrite(high),
            BusWitness::MemoryWrite(low),
        ]),
    )?;
    let trace = NativeTraceWitness::from_rows(&[&row])?;
    assert_row_satisfied(&CpuStructuralRelation, trace.columns(), 0)?;
    let mut wrong_priority = native_row(&trace, 0)?;
    *wrong_priority
        .get_mut(TRACE_INTERRUPT_START)
        .ok_or(UniformError::Shape)? = 0;
    *wrong_priority
        .get_mut(TRACE_INTERRUPT_START + 4)
        .ok_or(UniformError::Shape)? = 1;
    assert_native_row_rejected(&CpuStructuralRelation, &wrong_priority)?;
    Ok(())
}

#[test]
#[ignore = "expensive twenty-six-group CPU relation plus shared ISA Shout gate"]
fn shared_cpu_and_isa_claims_verify_and_reject_commitment_substitution()
-> Result<(), Box<dyn std::error::Error>> {
    let trace = single_opcode_trace(0x00)?;
    let proof = prove_native_cpu_structural(&trace)?;
    verify_native_cpu_structural(&proof)?;
    assert_eq!(proof.commitments().column_count(), trace.columns().len());
    assert_eq!(proof.commitments().group_count(), 26);

    let other_trace = single_opcode_trace(0x04)?;
    let other = commit_witness(other_trace.columns())?;
    let mut substituted = proof;
    substituted.commitments = other.into_commitments();
    assert!(verify_native_cpu_structural(&substituted).is_err());
    Ok(())
}

#[test]
#[ignore = "expensive twenty-six-group CPU, ISA, and one-MiB ROM Akita gate"]
fn shared_cpu_isa_and_rom_claims_reject_rom_substitution() -> Result<(), Box<dyn std::error::Error>>
{
    let image = vec![0_u8; ROM_IMAGE_BYTES];
    let rom_image = RomImage::new(image.clone())?;
    let memory = MemoryImage::zeroed()?;
    let before = VmState::profile_initial(rom_image.root(), memory.root());
    let row = TraceRow::execute(
        before,
        StepInput::new(vec![BusWitness::Rom(rom_image.read(0)?)]),
    )?;
    let trace = NativeTraceWitness::from_rows(&[&row])?;
    let rom = commit_rom(&image)?;
    let proof = prove_native_rom_cpu(&trace, &rom)?;
    verify_native_rom_cpu(&proof, rom.commitment())?;

    let mut substitute_image = image;
    *substitute_image.last_mut().ok_or(UniformError::Shape)? = 1;
    let substitute = commit_rom(&substitute_image)?;
    assert!(verify_native_rom_cpu(&proof, substitute.commitment()).is_err());
    Ok(())
}
