use zksm83_memory::{MemoryImage, RomImage};
use zksm83_trace::{LookupTraceBuilder, pack_witness_basic_blocks};

use super::*;
use crate::{
    block_test_support::{first_device_io_block_index, flip_witness_bit},
    validate_uniform_witness,
};

#[test]
fn ff41_write_binds_immediate_stat_then_clock_order() -> Result<(), Box<dyn std::error::Error>> {
    let program = [0x3e, 0x20, 0xea, 0x41, 0xff];
    let mut bytes = vec![0_u8; 0x100 + program.len()];
    bytes
        .get_mut(0x100..)
        .ok_or(UniformError::Shape)?
        .copy_from_slice(&program);
    let rom = RomImage::new(bytes.clone())?;
    let memory = MemoryImage::zeroed()?;
    let mut builder = LookupTraceBuilder::new_dmg_post_boot_mbc3(
        bytes,
        memory.checkpoint_bytes(),
        Vec::new(),
        rom.root(),
        memory.root(),
    )?;
    let blocks = pack_witness_basic_blocks(builder.run_exact_steps(2)?)?;
    let witness = BlockDevicePpuMmioWitness::from_blocks(&blocks)?;
    validate_uniform_witness(&BlockDevicePpuMmioRelation, witness.columns())?;
    let device_row = first_device_io_block_index(&blocks)?;
    let mut mutated = witness.columns().to_vec();
    flip_witness_bit(
        &mut mutated,
        PPU_MMIO_AUX_START + IMMEDIATE_STAT_EVENT,
        device_row,
    )?;
    assert!(validate_uniform_witness(&BlockDevicePpuMmioRelation, &mutated).is_err());
    Ok(())
}
