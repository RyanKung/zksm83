use std::io::Cursor;

use zksm83_memory::{MemoryImage, RomImage};
use zksm83_trace::{TraceBuilder, TraceRow, Witness, pack_witness_basic_blocks};

use super::{
    CommitmentIdentity, CommitmentKind, NativeBoundary, NativeReceipt, NativeReceiptStreamProver,
    NativeSegmentWitness, NativeStatement, ProtocolLogIdentities, verify_native_receipt,
    verify_native_receipt_bytes, verify_native_receipt_reader,
};
use crate::{
    BlockCpuWitness, MEMORY_IMAGE_BYTES, NativeProtocolVersion, NativeStateBoundary,
    ROM_IMAGE_BYTES,
};

#[test]
fn commitment_kind_codes_are_stable_and_reject_unknown_values() {
    let cases = [
        (CommitmentKind::Rom, 0),
        (CommitmentKind::MutableMemory, 1),
        (CommitmentKind::InputLog, 2),
        (CommitmentKind::OutputLog, 3),
        (CommitmentKind::BusLog, 4),
        (CommitmentKind::IsaLog, 5),
    ];
    for (kind, code) in cases {
        assert_eq!(kind.code(), code);
        assert_eq!(CommitmentKind::from_code(code), Some(kind));
    }
    assert_eq!(CommitmentKind::from_code(6), None);
}

#[test]
fn statement_decoder_rejects_wrong_magic() {
    assert!(NativeStatement::from_bytes(b"not-a-native-statement").is_err());
}

#[test]
fn stream_reader_rejects_truncated_header() -> Result<(), Box<dyn std::error::Error>> {
    let expected = structural_statement()?;
    assert!(verify_native_receipt_reader(Cursor::new(b"ZKSM83R1"), &expected).is_err());
    Ok(())
}

#[test]
fn statement_wire_is_canonical_and_binds_every_field() -> Result<(), Box<dyn std::error::Error>> {
    let statement = structural_statement()?;
    let bytes = statement.to_bytes()?;
    assert_eq!(NativeStatement::from_bytes(&bytes)?, statement);

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(NativeStatement::from_bytes(&trailing).is_err());

    let mut tampered = statement.clone();
    tampered.statement_id[0] ^= 1;
    assert!(NativeStatement::from_bytes(&tampered.to_bytes()?).is_err());

    let mut impossible = statement;
    impossible.segment_count = impossible
        .relation_row_count
        .checked_add(1)
        .ok_or("segment count overflow")?;
    impossible.statement_id = impossible.compute_id();
    assert!(NativeStatement::from_bytes(&impossible.to_bytes()?).is_err());
    Ok(())
}

#[test]
fn statement_wire_rejects_v1_and_accepts_only_v2() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(NativeProtocolVersion::from_code(1), None);
    let v2 = structural_statement_for(NativeProtocolVersion::V2)?;
    let v2_bytes = v2.to_bytes()?;

    assert_eq!(v2_bytes.get(..8), Some(b"ZKSM83S2".as_slice()));
    assert_eq!(NativeStatement::from_bytes(&v2_bytes)?, v2);

    let mut relabeled = v2_bytes;
    relabeled
        .get_mut(..8)
        .ok_or("missing statement magic")?
        .copy_from_slice(b"ZKSM83S1");
    assert!(NativeStatement::from_bytes(&relabeled).is_err());
    Ok(())
}

#[test]
fn receipt_magic_and_numeric_version_must_agree() -> Result<(), Box<dyn std::error::Error>> {
    for (magic, wrong_version) in [(b"ZKSM83R1", 2_u64), (b"ZKSM83R2", 1_u64)] {
        let mut bytes = magic.to_vec();
        bytes.extend_from_slice(&wrong_version.to_le_bytes());
        assert!(NativeReceipt::from_bytes(&bytes).is_err());
    }
    Ok(())
}

#[test]
fn receipt_and_embedded_statement_versions_cannot_be_mixed()
-> Result<(), Box<dyn std::error::Error>> {
    let v2_statement = structural_statement()?.to_bytes()?;
    for (receipt_magic, version, statement_magic) in [
        (b"ZKSM83R1", 1_u64, b"ZKSM83S2"),
        (b"ZKSM83R2", 2_u64, b"ZKSM83S1"),
    ] {
        let mut statement = v2_statement.clone();
        statement
            .get_mut(..8)
            .ok_or("missing statement magic")?
            .copy_from_slice(statement_magic);
        let mut bytes = receipt_magic.to_vec();
        bytes.extend_from_slice(&version.to_le_bytes());
        bytes.extend_from_slice(&u64::try_from(statement.len())?.to_le_bytes());
        bytes.extend_from_slice(&statement);
        assert!(matches!(
            NativeReceipt::from_bytes(&bytes),
            Err(super::NativeReceiptError::UnsupportedBackend)
        ));
    }
    Ok(())
}

#[test]
fn statement_decoder_rejects_every_single_byte_mutation_and_truncation()
-> Result<(), Box<dyn std::error::Error>> {
    let statement = structural_statement()?;
    let bytes = statement.to_bytes()?;
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        let byte = changed.get_mut(index).ok_or("statement mutation index")?;
        *byte ^= 1;
        assert!(NativeStatement::from_bytes(&changed).is_err());
    }
    for length in 0..bytes.len() {
        let truncated = bytes.get(..length).ok_or("statement truncation range")?;
        assert!(NativeStatement::from_bytes(truncated).is_err());
    }
    Ok(())
}

#[test]
fn receipt_decoders_reject_deterministic_noise_and_hostile_lengths()
-> Result<(), Box<dyn std::error::Error>> {
    let expected = structural_statement()?;
    let mut state = 0x7d36_51a9_204b_f83d_u64;
    for length in [0, 1, 7, 8, 15, 16, 31, 64, 255, 1024, 4096] {
        let mut bytes = vec![0_u8; length];
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = u8::try_from(state & 0xff)?;
        }
        assert!(NativeReceipt::from_bytes(&bytes).is_err());
        assert!(verify_native_receipt_reader(Cursor::new(&bytes), &expected).is_err());
    }

    let mut hostile = b"ZKSM83R1".to_vec();
    hostile.extend_from_slice(&super::NATIVE_RECEIPT_VERSION.to_le_bytes());
    hostile.extend_from_slice(&u64::MAX.to_le_bytes());
    assert!(NativeReceipt::from_bytes(&hostile).is_err());
    assert!(verify_native_receipt_reader(Cursor::new(hostile), &expected).is_err());
    Ok(())
}

#[test]
fn zero_cursor_requires_the_unique_empty_log_identity() -> Result<(), Box<dyn std::error::Error>> {
    let statement = structural_statement()?;
    let mut boundary = statement.initial.clone();
    boundary.logs.bus.digest[0] ^= 1;
    assert!(
        boundary
            .validate_for(NativeProtocolVersion::current())
            .is_err()
    );
    Ok(())
}

#[test]
#[ignore = "expensive complete v2 paired receipt, canonical wire, and tamper matrix gate"]
fn native_receipt_round_trip_and_structural_tampering_are_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let started = std::time::Instant::now();
    let (trace, rom_bytes, initial_bytes, final_bytes) = receipt_trace()?;
    let rom = crate::commit_rom(&rom_bytes)?;
    let initial_memory = crate::commit_memory(&initial_bytes)?;
    let final_memory = crate::commit_memory(&final_bytes)?;
    eprintln!("receipt gate commitments: {:.2?}", started.elapsed());
    let witness = NativeSegmentWitness::new(&trace, &initial_memory, &final_memory);
    let mut prover = NativeReceiptStreamProver::new(&rom, Cursor::new(Vec::new()))?;
    prover.append(witness)?;
    let mut bytes = Vec::new();
    let statement = prover.finish(&mut bytes)?;
    eprintln!("receipt gate proof: {:.2?}", started.elapsed());
    let expected = NativeStatement::from_bytes(&statement.to_bytes()?)?;
    eprintln!(
        "receipt gate encoded: {:.2?}, {} bytes",
        started.elapsed(),
        bytes.len()
    );
    let decoded = NativeReceipt::from_bytes(&bytes)?;
    assert_eq!(decoded.to_bytes()?, bytes);
    eprintln!("receipt gate decoded: {:.2?}", started.elapsed());
    assert_eq!(
        verify_native_receipt(&decoded, &expected)?.segment_count(),
        1
    );
    eprintln!("receipt gate parsed verify: {:.2?}", started.elapsed());
    assert_eq!(
        verify_native_receipt_bytes(&bytes, &expected)?.statement_id(),
        expected.statement_id()
    );
    assert_eq!(
        verify_native_receipt_reader(Cursor::new(&bytes), &expected)?.statement_id(),
        expected.statement_id()
    );
    eprintln!("receipt gate byte verify: {:.2?}", started.elapsed());

    let mut wrong = expected.clone();
    wrong.relation_row_count = wrong
        .relation_row_count
        .checked_add(1)
        .ok_or("step count overflow")?;
    wrong.statement_id = wrong.compute_id();
    assert!(verify_native_receipt(&decoded, &wrong).is_err());

    let mut wrong = expected.clone();
    wrong.transition_count = wrong
        .transition_count
        .checked_add(1)
        .ok_or("transition count overflow")?;
    wrong.statement_id = wrong.compute_id();
    assert!(verify_native_receipt(&decoded, &wrong).is_err());

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(verify_native_receipt_bytes(&trailing, &expected).is_err());

    let mut changed_proof = bytes;
    let last = changed_proof.last_mut().ok_or("empty receipt")?;
    *last ^= 1;
    assert!(verify_native_receipt_bytes(&changed_proof, &expected).is_err());

    let mut omitted = decoded.clone();
    omitted.segments.clear();
    assert!(verify_native_receipt(&omitted, &expected).is_err());

    let mut wrong_transition_count = decoded.clone();
    let first = wrong_transition_count
        .segments
        .first_mut()
        .ok_or("missing segment")?;
    first.transition_count = first
        .transition_count
        .checked_add(1)
        .ok_or("transition count overflow")?;
    assert!(verify_native_receipt(&wrong_transition_count, &expected).is_err());

    let mut duplicated = decoded.clone();
    let segment = duplicated
        .segments
        .first()
        .cloned()
        .ok_or("missing segment")?;
    duplicated.segments.push(segment);
    assert!(verify_native_receipt(&duplicated, &expected).is_err());

    let mut reordered = decoded;
    let first = reordered.segments.first_mut().ok_or("missing segment")?;
    first.segment_index = 1;
    assert!(verify_native_receipt(&reordered, &expected).is_err());
    eprintln!("receipt gate tamper matrix: {:.2?}", started.elapsed());
    Ok(())
}

#[test]
#[ignore = "expensive two-segment v2 paired receipt and exact boundary-chain gate"]
fn two_segment_receipt_authenticates_exact_shared_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let started = std::time::Instant::now();
    let (traces, rom_bytes, memories) = two_segment_trace()?;
    let rom = crate::commit_rom(&rom_bytes)?;
    let committed_memories = memories
        .iter()
        .map(|memory| crate::commit_memory(memory))
        .collect::<Result<Vec<_>, _>>()?;
    let first_trace = traces.first().ok_or("missing first trace")?;
    let second_trace = traces.get(1).ok_or("missing second trace")?;
    let initial_memory = committed_memories.first().ok_or("missing initial memory")?;
    let middle_memory = committed_memories.get(1).ok_or("missing middle memory")?;
    let final_memory = committed_memories.get(2).ok_or("missing final memory")?;
    let mut prover = NativeReceiptStreamProver::new(&rom, Cursor::new(Vec::new()))?;
    prover.append(NativeSegmentWitness::new(
        first_trace,
        initial_memory,
        middle_memory,
    ))?;
    eprintln!("two-segment first frame: {:.2?}", started.elapsed());
    prover.append(NativeSegmentWitness::new(
        second_trace,
        middle_memory,
        final_memory,
    ))?;
    eprintln!("two-segment receipt proof: {:.2?}", started.elapsed());
    let mut receipt_bytes = Vec::new();
    let statement = prover.finish(&mut receipt_bytes)?;
    let expected = NativeStatement::from_bytes(&statement.to_bytes()?)?;
    assert_eq!(expected.segment_count(), 2);
    assert_eq!(expected.transition_count(), 2);
    assert_eq!(expected.relation_row_count(), 2);
    assert_eq!(
        verify_native_receipt_reader(Cursor::new(&receipt_bytes), &expected)?.segment_count(),
        2
    );
    let receipt = NativeReceipt::from_bytes(&receipt_bytes)?;
    assert_eq!(
        verify_native_receipt(&receipt, &expected)?.segment_count(),
        2
    );

    let mut broken_link = receipt.clone();
    let wrong_boundary = broken_link
        .segments
        .first()
        .map(|segment| segment.initial.clone())
        .ok_or("missing first segment")?;
    let second = broken_link
        .segments
        .get_mut(1)
        .ok_or("missing second segment")?;
    second.initial = wrong_boundary;
    assert!(verify_native_receipt(&broken_link, &expected).is_err());

    let mut reordered = receipt;
    reordered.segments.swap(0, 1);
    assert!(verify_native_receipt(&reordered, &expected).is_err());
    eprintln!("two-segment receipt gate: {:.2?}", started.elapsed());
    Ok(())
}

fn structural_statement() -> Result<NativeStatement, Box<dyn std::error::Error>> {
    structural_statement_for(NativeProtocolVersion::current())
}

fn structural_statement_for(
    protocol: NativeProtocolVersion,
) -> Result<NativeStatement, Box<dyn std::error::Error>> {
    let mut scalars = [0_u64; crate::STATE_SCALAR_COUNT];
    scalars[20] = 1;
    let state = NativeStateBoundary::from_scalars(scalars);
    let memory = super::identity::direct_identity(
        protocol,
        CommitmentKind::MutableMemory,
        u64::try_from(MEMORY_IMAGE_BYTES)?,
        b"structural-memory-commitment",
    )?;
    let boundary = NativeBoundary {
        state,
        memory,
        logs: ProtocolLogIdentities::empty_for(protocol),
    };
    let rom = super::identity::direct_identity(
        protocol,
        CommitmentKind::Rom,
        u64::try_from(ROM_IMAGE_BYTES)?,
        b"structural-rom-commitment",
    )?;
    NativeStatement::new_for(protocol, rom, boundary.clone(), boundary, 1, 1, 1).map_err(Into::into)
}

type ReceiptTrace = (BlockCpuWitness, Vec<u8>, Vec<u8>, Vec<u8>);

fn receipt_trace() -> Result<ReceiptTrace, Box<dyn std::error::Error>> {
    let mut rom_bytes = vec![0_u8; ROM_IMAGE_BYTES];
    let program = [
        0x3e, 0x5a, // LD A,0x5a
        0xea, 0x00, 0xc0, // LD (0xc000),A
        0xfa, 0x00, 0xc0, // LD A,(0xc000)
        0x76, // HALT
    ];
    let target = rom_bytes
        .get_mut(0x100..0x100 + program.len())
        .ok_or("ROM fixture")?;
    target.copy_from_slice(&program);
    let rom = RomImage::new(rom_bytes.clone())?;
    let memory = MemoryImage::zeroed()?;
    let mut builder = TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, Vec::new());
    let initial = builder.checkpoint_memory();
    let mut rows = Vec::<TraceRow>::new();
    for _ in 0..4 {
        rows.push(builder.step()?);
    }
    let final_memory = builder.checkpoint_memory();
    let blocks = pack_witness_basic_blocks(Witness::from_rows(rows)?)?;
    Ok((
        BlockCpuWitness::from_blocks(&blocks)?,
        rom_bytes,
        initial,
        final_memory,
    ))
}

type TwoSegmentTrace = ([BlockCpuWitness; 2], Vec<u8>, [Vec<u8>; 3]);

fn two_segment_trace() -> Result<TwoSegmentTrace, Box<dyn std::error::Error>> {
    let mut rom_bytes = vec![0_u8; ROM_IMAGE_BYTES];
    let program = [
        0x3e, 0x5a, // LD A,0x5a
        0xea, 0x00, 0xc0, // LD (0xc000),A
    ];
    let target = rom_bytes
        .get_mut(0x100..0x100 + program.len())
        .ok_or("ROM fixture")?;
    target.copy_from_slice(&program);
    let rom = RomImage::new(rom_bytes.clone())?;
    let memory = MemoryImage::zeroed()?;
    let mut builder = TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, Vec::new());
    let initial = builder.checkpoint_memory();
    let first = builder.step()?;
    let middle = builder.checkpoint_memory();
    let second = builder.step()?;
    let final_memory = builder.checkpoint_memory();
    let first = pack_witness_basic_blocks(Witness::from_rows(vec![first])?)?;
    let second = pack_witness_basic_blocks(Witness::from_rows(vec![second])?)?;
    let traces = [
        BlockCpuWitness::from_blocks(&first)?,
        BlockCpuWitness::from_blocks(&second)?,
    ];
    Ok((traces, rom_bytes, [initial, middle, final_memory]))
}

#[test]
fn direct_commitment_identities_are_typed_and_layout_separated()
-> Result<(), Box<dyn std::error::Error>> {
    let rom_identity: CommitmentIdentity = super::identity::direct_identity(
        NativeProtocolVersion::current(),
        CommitmentKind::Rom,
        u64::try_from(ROM_IMAGE_BYTES)?,
        b"same-commitment-bytes",
    )?;
    let memory_identity = super::identity::direct_identity(
        NativeProtocolVersion::current(),
        CommitmentKind::MutableMemory,
        u64::try_from(MEMORY_IMAGE_BYTES)?,
        b"same-commitment-bytes",
    )?;
    assert_eq!(rom_identity.kind(), CommitmentKind::Rom);
    assert_eq!(memory_identity.kind(), CommitmentKind::MutableMemory);
    assert_ne!(
        rom_identity.layout_digest(),
        memory_identity.layout_digest()
    );
    assert_ne!(rom_identity.digest(), memory_identity.digest());
    Ok(())
}
