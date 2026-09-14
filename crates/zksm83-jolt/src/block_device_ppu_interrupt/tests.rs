use super::*;
use crate::{
    block_test_support::{
        MachineEventFixture, flip_witness_bit, lookup_blocks, machine_event_block,
    },
    validate_uniform_witness,
};

#[test]
fn quiet_block_binds_ppu_interrupt_edges() -> Result<(), Box<dyn std::error::Error>> {
    let blocks = lookup_blocks(
        &[0x00; BASIC_BLOCK_INSTRUCTION_BOUND],
        BASIC_BLOCK_INSTRUCTION_BOUND,
    )?;
    let witness = BlockDevicePpuInterruptWitness::from_blocks(&blocks)?;
    validate_uniform_witness(&BlockDevicePpuInterruptRelation, witness.columns())?;
    let mut mutated = witness.columns().to_vec();
    flip_witness_bit(
        &mut mutated,
        PPU_INTERRUPT_AUX_START + BEFORE_STATE_START + STATE_VBLANK,
        0,
    )?;
    assert!(validate_uniform_witness(&BlockDevicePpuInterruptRelation, &mutated).is_err());
    Ok(())
}

#[test]
fn long_vblank_event_binds_exact_crossing() -> Result<(), Box<dyn std::error::Error>> {
    let blocks = machine_event_block(MachineEventFixture::HaltUntilVBlank)?;
    let witness = BlockDevicePpuInterruptWitness::from_blocks(&blocks)?;
    validate_uniform_witness(&BlockDevicePpuInterruptRelation, witness.columns())?;
    let mut mutated = witness.columns().to_vec();
    flip_witness_bit(&mut mutated, PPU_INTERRUPT_AUX_START + VBLANK_EVENT, 0)?;
    assert!(validate_uniform_witness(&BlockDevicePpuInterruptRelation, &mutated).is_err());
    Ok(())
}
