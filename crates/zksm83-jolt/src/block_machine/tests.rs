use zksm83_core::StepKind;

use super::*;
use crate::{
    block_test_support::{
        MachineEventFixture, flip_witness_bit, lookup_blocks, machine_event_block,
    },
    validate_uniform_witness,
};

#[test]
fn instruction_block_keeps_machine_plane_canonical() -> Result<(), Box<dyn std::error::Error>> {
    let blocks = lookup_blocks(
        &[0x00; BASIC_BLOCK_INSTRUCTION_BOUND],
        BASIC_BLOCK_INSTRUCTION_BOUND,
    )?;
    let witness = BlockMachineWitness::from_blocks(&blocks)?;
    validate_uniform_witness(&BlockMachineRelation, witness.columns())?;
    let mut mutated = witness.columns().to_vec();
    flip_witness_bit(&mut mutated, MACHINE_AUX_START + HALT_IDLE_MODE, 0)?;
    assert!(validate_uniform_witness(&BlockMachineRelation, &mutated).is_err());
    Ok(())
}

#[test]
fn every_machine_event_mode_has_a_rejection_sentinel() -> Result<(), Box<dyn std::error::Error>> {
    for (fixture, expected, mutation) in machine_event_cases() {
        let blocks = machine_event_block(fixture)?;
        let block = blocks.first().ok_or(UniformError::Shape)?;
        let row = block.rows().next().ok_or(UniformError::Shape)?;
        assert_eq!(row.effects().kind(), expected);
        assert_event_satisfied_and_mutation_rejected(&blocks, mutation)?;
    }
    Ok(())
}

fn machine_event_cases() -> [(MachineEventFixture, StepKind, usize); 7] {
    [
        (
            MachineEventFixture::HaltIdle,
            StepKind::HaltIdle,
            SHORT_CYCLE_ACTIVE_START,
        ),
        (
            MachineEventFixture::HaltUntilVBlank,
            StepKind::HaltUntilVBlank,
            BEFORE_IE_BITS_START,
        ),
        (
            MachineEventFixture::HaltWake,
            StepKind::HaltWake,
            PENDING_CLEAR_PREFIX_START,
        ),
        (
            MachineEventFixture::Interrupt,
            StepKind::InterruptDispatch(zksm83_core::DmgInterrupt::VBlank),
            INTERRUPT_SOURCE_START,
        ),
        (
            MachineEventFixture::DmaByte,
            StepKind::DmaByte,
            DMA_BYTE_MODE,
        ),
        (
            MachineEventFixture::HaltUntilSerial,
            StepKind::HaltUntilSerial,
            BEFORE_IE_BITS_START + 3,
        ),
        (
            MachineEventFixture::HaltUntilTimer,
            StepKind::HaltUntilTimer,
            BEFORE_IE_BITS_START + 2,
        ),
    ]
}

fn assert_event_satisfied_and_mutation_rejected(
    blocks: &[zksm83_trace::BasicBlock],
    mutation: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let block = blocks.first().ok_or(UniformError::Shape)?;
    assert_eq!(block.instruction_count(), 0);
    assert_eq!(block.cut(), zksm83_trace::BasicBlockCut::MachineEvent);
    let witness = BlockMachineWitness::from_blocks(blocks)?;
    validate_uniform_witness(&BlockMachineRelation, witness.columns())?;
    let mut mutated = witness.columns().to_vec();
    flip_witness_bit(&mut mutated, MACHINE_AUX_START + mutation, 0)?;
    assert!(validate_uniform_witness(&BlockMachineRelation, &mutated).is_err());
    Ok(())
}
