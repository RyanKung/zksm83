//! Authentication and root-threading proposition tests.

use zksm83_memory::{
    HashDomain, MemoryImage, MemoryRead, MemoryTranscript, MemoryTranscriptError, MemoryWrite,
    MerklePath, RomImage, RomImageError, RomRead, RomReadError, hash_elements,
};

const ONE_MIB: usize = 1_048_576;

#[test]
fn memory_read_observes_latest_write() -> Result<(), Box<dyn std::error::Error>> {
    let mut image = MemoryImage::zeroed()?;
    let mut transcript = MemoryTranscript::new(image.root());
    let old_read = image.read(0x8000)?;
    transcript.read(old_read)?;

    let write = image.write(0x8000, 0x42)?;
    transcript.write(write)?;
    let latest_read = image.read(0x8000)?;
    assert_eq!(latest_read.value, 0x42);
    transcript.read(latest_read)?;

    assert!(matches!(
        transcript.read(old_read),
        Err(MemoryTranscriptError::RootMismatch { .. })
    ));
    Ok(())
}

#[test]
fn dmg_high_hram_bytes_authenticate_without_becoming_clean_host_ports()
-> Result<(), Box<dyn std::error::Error>> {
    let mut memory = MemoryImage::zeroed()?;
    let write = memory.write(0xfffd, 0x42)?;
    assert_eq!(write.address, 0xfffd);
    assert_eq!(write.after, 0x42);
    let read = memory.read(0xfffd)?;
    assert_eq!(read.value, 0x42);
    read.verify(memory.root())?;
    Ok(())
}

#[test]
fn memory_write_updates_root() -> Result<(), Box<dyn std::error::Error>> {
    let mut image = MemoryImage::zeroed()?;
    let initial_root = image.root();
    let mut transcript = MemoryTranscript::new(initial_root);
    let write = image.write(0x9000, 0xa5)?;
    transcript.write(write)?;

    assert_ne!(initial_root, image.root());
    assert_eq!(transcript.current_root(), image.root());
    Ok(())
}

#[test]
fn rom_read_rejects_wrong_root() -> Result<(), Box<dyn std::error::Error>> {
    let image = RomImage::new(vec![0x00, 0x76])?;
    let changed_image = RomImage::new(vec![0x01, 0x76])?;
    let read = image.read(0)?;

    read.verify(image.root())?;
    assert!(matches!(
        read.verify(changed_image.root()),
        Err(RomReadError::RootMismatch { .. })
    ));
    Ok(())
}

#[test]
fn rom_verification_cache_rejects_a_tampered_full_path() -> Result<(), Box<dyn std::error::Error>> {
    let image = RomImage::new(vec![0x00, 0x76])?;
    let changed_image = RomImage::new(vec![0x01, 0x76])?;
    let read = image.read(0)?;
    read.verify(image.root())?;

    let mut siblings = [image.root(); 20];
    for (destination, source) in siblings.iter_mut().zip(read.path.siblings()) {
        *destination = source;
    }
    siblings[0] = changed_image.root();
    let tampered = RomRead {
        path: MerklePath::new(siblings),
        ..read
    };

    assert!(matches!(
        tampered.verify(image.root()),
        Err(RomReadError::RootMismatch { .. })
    ));
    Ok(())
}

#[test]
fn memory_verification_caches_reject_tampered_full_paths() -> Result<(), Box<dyn std::error::Error>>
{
    let memory = MemoryImage::zeroed()?;
    let replacement = RomImage::new(vec![0xa5])?.root();
    let root = memory.root();

    let read = memory.read(0xc123)?;
    read.verify(root)?;
    let tampered_read = MemoryRead {
        path: replace_first_sibling(read.path, replacement),
        ..read
    };
    assert!(matches!(
        tampered_read.verify(root),
        Err(MemoryTranscriptError::RootMismatch { .. })
    ));

    let write = memory.preview_write(0xc123, 0x42)?;
    write.verify(root)?;
    let tampered_write = MemoryWrite {
        path: replace_first_sibling(write.path, replacement),
        ..write
    };
    assert!(matches!(
        tampered_write.verify(root),
        Err(MemoryTranscriptError::RootMismatch { .. })
    ));
    Ok(())
}

fn replace_first_sibling(
    path: MerklePath,
    replacement: zksm83_memory::CommitmentRoot,
) -> MerklePath {
    let mut siblings = [replacement; 20];
    for (destination, source) in siblings.iter_mut().zip(path.siblings()) {
        *destination = source;
    }
    siblings[0] = replacement;
    MerklePath::new(siblings)
}

#[test]
fn roots_have_canonical_round_trip_encoding() -> Result<(), Box<dyn std::error::Error>> {
    let image = RomImage::new(vec![0x00])?;
    let encoded = image.root().to_bytes();
    assert_eq!(
        zksm83_memory::CommitmentRoot::from_bytes(encoded)?,
        image.root()
    );
    Ok(())
}

#[test]
fn poseidon_cache_keys_bind_domain_and_both_inputs() {
    let zero = pasta_curves::Fp::from(0_u64);
    let one = pasta_curves::Fp::from(1_u64);
    let expected = hash_elements(HashDomain::RomLeaf, zero, zero);

    assert_eq!(hash_elements(HashDomain::RomLeaf, zero, zero), expected);
    assert_ne!(hash_elements(HashDomain::MemoryLeaf, zero, zero), expected);
    assert_ne!(hash_elements(HashDomain::RomLeaf, one, zero), expected);
    assert_ne!(hash_elements(HashDomain::RomLeaf, zero, one), expected);
}

#[test]
fn rom_image_accepts_complete_one_mibibyte_cartridge() -> Result<(), Box<dyn std::error::Error>> {
    let mut cartridge = vec![0_u8; ONE_MIB];
    let last = cartridge
        .last_mut()
        .ok_or_else(|| std::io::Error::other("missing one-MiB final byte"))?;
    *last = 0x42;

    let image = RomImage::new(cartridge)?;
    image.read(0)?.verify(image.root())?;
    Ok(())
}

#[test]
fn rom_root_binds_bytes_beyond_the_cpu_window() -> Result<(), Box<dyn std::error::Error>> {
    let original = RomImage::new(vec![0_u8; 65_537])?;
    let mut changed = vec![0_u8; 65_537];
    let final_byte = changed
        .last_mut()
        .ok_or_else(|| std::io::Error::other("missing changed final byte"))?;
    *final_byte = 1;
    let changed = RomImage::new(changed)?;

    assert_ne!(original.root(), changed.root());
    Ok(())
}

#[test]
fn rom_image_rejects_more_than_one_mibibyte() {
    assert!(matches!(
        RomImage::new(vec![0_u8; ONE_MIB + 1]),
        Err(RomImageError::ProgramTooLarge { actual, maximum })
            if actual == ONE_MIB + 1 && maximum == ONE_MIB
    ));
}

#[test]
fn mapped_sram_banks_authenticate_distinct_physical_bytes() -> Result<(), Box<dyn std::error::Error>>
{
    let mut image = MemoryImage::zeroed()?;
    let bank_zero = 0x1_0000;
    let bank_one = 0x1_2000;
    image.write_mapped(0xa000, bank_zero, 0x11)?;
    image.write_mapped(0xa000, bank_one, 0x22)?;

    let zero = image.read_mapped(0xa000, bank_zero)?;
    let one = image.read_mapped(0xa000, bank_one)?;
    zero.verify(image.root())?;
    one.verify(image.root())?;
    assert_eq!(zero.value, 0x11);
    assert_eq!(one.value, 0x22);
    assert_ne!(zero.physical_address, one.physical_address);
    Ok(())
}

#[test]
fn checkpoint_round_trip_preserves_banked_sram_and_root() -> Result<(), Box<dyn std::error::Error>>
{
    let mut original = MemoryImage::zeroed()?;
    original.write_mapped(0xa000, 0x1_6000, 0x5a)?;
    original.write(0xc123, 0xa5)?;
    let restored = MemoryImage::from_checkpoint_bytes(original.checkpoint_bytes())?;

    assert_eq!(restored.root(), original.root());
    assert_eq!(restored.read_mapped(0xa000, 0x1_6000)?.value, 0x5a);
    assert_eq!(restored.read(0xc123)?.value, 0xa5);
    Ok(())
}

#[test]
fn battery_sram_round_trip_preserves_all_four_mbc3_banks() -> Result<(), Box<dyn std::error::Error>>
{
    let mut sram = vec![0_u8; 32_768];
    for (index, byte) in sram.iter_mut().enumerate() {
        *byte = u8::try_from(index % 251)?;
    }
    let image = MemoryImage::with_battery_sram(sram.clone())?;

    assert_eq!(image.battery_sram_bytes()?, sram);
    for bank in 0_u32..4 {
        let physical = 0x1_0000 + bank * 0x2000;
        let expected = sram
            .get(usize::try_from(bank * 0x2000)?)
            .copied()
            .ok_or_else(|| std::io::Error::other("missing SRAM bank byte"))?;
        assert_eq!(image.read_mapped(0xa000, physical)?.value, expected);
    }
    Ok(())
}
