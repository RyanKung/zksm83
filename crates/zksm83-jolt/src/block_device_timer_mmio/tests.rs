use zksm83_memory::{MemoryImage, RomImage};
use zksm83_trace::{LookupTraceBuilder, pack_witness_basic_blocks};

use super::*;
use crate::{
    block_test_support::{first_device_io_block_index, flip_witness_bit},
    validate_uniform_witness,
};

#[test]
fn tac_write_is_applied_before_instruction_clocking() -> Result<(), Box<dyn std::error::Error>> {
    let program = [0x3e, 0x05, 0xea, 0x07, 0xff];
    let blocks = fixture(&program, 2)?;
    let witness = BlockDeviceTimerMmioWitness::from_blocks(&blocks)?;
    validate_uniform_witness(&BlockDeviceTimerMmioRelation, witness.columns())?;
    let device_row = first_device_io_block_index(&blocks)?;
    let mut mutated = witness.columns().to_vec();
    flip_witness_bit(&mut mutated, TIMER_MMIO_AUX_START + FF07_WRITE, device_row)?;
    assert!(validate_uniform_witness(&BlockDeviceTimerMmioRelation, &mutated).is_err());

    let mut shared_stage_mutation = witness.columns().to_vec();
    flip_witness_bit(
        &mut shared_stage_mutation,
        SHARED_TIMER_STAGE_COLUMN_START + STAGE_COUNTER_OVERFLOW_OFFSET,
        device_row,
    )?;
    let prefix = shared_stage_mutation
        .get(..BLOCK_DEVICE_SERIAL_MMIO_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    validate_uniform_witness(&BlockDeviceSerialMmioRelation, prefix)?;
    assert!(
        validate_uniform_witness(&BlockDeviceTimerMmioRelation, &shared_stage_mutation).is_err()
    );
    Ok(())
}

fn fixture(program: &[u8], steps: u64) -> Result<Vec<BasicBlock>, Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; 0x100 + program.len()];
    bytes
        .get_mut(0x100..)
        .ok_or(UniformError::Shape)?
        .copy_from_slice(program);
    let rom = RomImage::new(bytes.clone())?;
    let memory = MemoryImage::zeroed()?;
    let mut builder = LookupTraceBuilder::new_dmg_post_boot_mbc3(
        bytes,
        memory.checkpoint_bytes(),
        Vec::new(),
        rom.root(),
        memory.root(),
    )?;
    Ok(pack_witness_basic_blocks(builder.run_exact_steps(steps)?)?)
}
