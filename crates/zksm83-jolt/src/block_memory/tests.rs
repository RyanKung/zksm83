use zksm83_memory::{MemoryImage, RomImage};
use zksm83_trace::{LookupTraceBuilder, pack_witness_basic_blocks};

use super::*;
use crate::validate_uniform_witness;

#[test]
fn packed_memory_chronology_binds_repeated_wram_events() -> Result<(), Box<dyn std::error::Error>> {
    let program = [0x21, 0x00, 0xc0, 0x34, 0x7e, 0x18, 0xfc];
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
    let blocks = pack_witness_basic_blocks(builder.run_exact_steps(4)?)?;
    let witness = BlockMemoryWitness::from_blocks(&blocks)?;
    validate_uniform_witness(&BlockMemoryRelation, witness.columns())?;
    assert_eq!(witness.final_memory_timestamps().len(), MEMORY_IMAGE_BYTES);
    Ok(())
}

#[test]
fn packed_joypad_input_index_follows_boundary_cursor() -> Result<(), Box<dyn std::error::Error>> {
    let program = [0xfa, 0x00, 0xff];
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
        vec![0x5a],
        rom.root(),
        memory.root(),
    )?;
    let blocks = pack_witness_basic_blocks(builder.run_exact_steps(1)?)?;
    let (block_index, input_slot) = blocks
        .iter()
        .enumerate()
        .find_map(|(block_index, block)| {
            block
                .rows()
                .flat_map(|row| row.effects().ordered_bus_events())
                .position(|event| event.kind() == BusEventKind::DmgJoypadRead)
                .map(|slot| (block_index, slot))
        })
        .ok_or(UniformError::Shape)?;
    let witness = BlockMemoryWitness::from_blocks(&blocks)?;
    validate_uniform_witness(&BlockMemoryRelation, witness.columns())?;

    let mut mutated = witness.columns().to_vec();
    let event_index_column = BLOCK_ISA_CONTROL_COLUMN_COUNT
        .checked_add(crate::block_bus::slot_index_column(input_slot)?)
        .ok_or(UniformError::Shape)?;
    let event_index = mutated
        .get_mut(event_index_column)
        .and_then(|column| column.get_mut(block_index))
        .ok_or(UniformError::Shape)?;
    *event_index = event_index.checked_add(1).ok_or(UniformError::Shape)?;
    assert!(validate_uniform_witness(&BlockMemoryRelation, &mutated).is_err());
    Ok(())
}
