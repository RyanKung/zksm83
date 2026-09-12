use akita_pcs::Ring;
use sha2::{Digest, Sha256};
use zksm83_memory::{MemoryImage, RomImage};
use zksm83_trace::{TraceBuilder, TraceRow};

use super::{
    MEMORY_IMAGE_BYTES, MEMORY_LAYOUT, MEMORY_SCHEDULE_ARTIFACT, MEMORY_TABLE_NUM_VARIABLES,
    MemoryCommitment, MutableMemoryError, commit_memory, prove_mutable_memory,
    verify_mutable_memory,
};
use crate::{
    AKITA_MEMORY_SCHEDULE_SHA256, CPU_STRUCTURAL_CONSTRAINT_COUNT, CpuStructuralRelation,
    NativeExecutionClaim, NativeField, NativeTraceWitness, TRACE_BUS_SLOTS,
    TRACE_MEMORY_DELTA_BITS_OFFSET, TRACE_MEMORY_PREDECESSOR_BITS_OFFSET, TRACE_MEMORY_SLOT_WIDTH,
    TRACE_MEMORY_START, TRACE_MEMORY_TIMESTAMP_BITS, UniformRelation, commit_protocol_logs,
    commit_rom, commit_witness,
    pcs::scheme,
    prove_native_memory_cpu, verify_native_memory_cpu,
    wire::{Wire, WireReader, WireWriter},
};

type MemoryTrace = (NativeTraceWitness, Vec<u8>, Vec<u8>);

const _: () = assert!(TRACE_BUS_SLOTS * (1 << 14) < (1 << 17));

#[test]
#[ignore = "expensive pair of 128-KiB Akita commitments and wire round trip"]
fn identical_memory_images_have_identical_commitments() -> Result<(), MutableMemoryError> {
    let image = vec![0x5a; MEMORY_IMAGE_BYTES];
    let first = commit_memory(&image)?;
    let second = commit_memory(&image)?;
    assert_eq!(first.commitment(), second.commitment());
    let mut writer = WireWriter::new();
    first
        .commitment()
        .encode(&mut writer)
        .map_err(|error| MutableMemoryError::Pcs(format!("encoding failed: {error}")))?;
    let encoded = writer.finish();
    let mut reader = WireReader::new(&encoded);
    let decoded = MemoryCommitment::decode(&mut reader)
        .map_err(|error| MutableMemoryError::Pcs(format!("decoding failed: {error}")))?;
    reader
        .finish()
        .map_err(|error| MutableMemoryError::Pcs(format!("EOF check failed: {error}")))?;
    assert_eq!(
        first.commitment().canonical_bytes()?,
        decoded.canonical_bytes()?
    );
    Ok(())
}

#[test]
fn pinned_memory_schedule_admits_exact_column_shape() -> Result<(), MutableMemoryError> {
    let scheme = scheme(MEMORY_LAYOUT)?;
    let admitted = scheme.schedules().catalog().rows().any(|row| {
        row.profiles().final_group.group.num_vars() == MEMORY_TABLE_NUM_VARIABLES
            && row.profiles().final_group.group.num_polynomials() == 1
            && row.profiles().precommitteds.is_empty()
    });
    assert!(admitted);
    assert_eq!(MEMORY_IMAGE_BYTES, 1 << 17);
    assert_eq!(
        format!("{:x}", Sha256::digest(MEMORY_SCHEDULE_ARTIFACT)),
        AKITA_MEMORY_SCHEDULE_SHA256
    );
    Ok(())
}

#[test]
fn rejects_non_profile_memory_length() {
    assert!(matches!(
        commit_memory(&[0; 65_536]),
        Err(MutableMemoryError::InvalidMemoryLength { .. })
    ));
}

#[test]
fn trace_orders_write_then_latest_read_and_binds_timestamp_delta()
-> Result<(), Box<dyn std::error::Error>> {
    let (trace, initial, final_memory) = memory_trace()?;
    assert_eq!(initial.get(0xc000).copied(), Some(0));
    assert_eq!(final_memory.get(0xc000).copied(), Some(0x5a));
    assert_eq!(trace.final_memory_timestamps().get(0xc000), Some(&14));
    assert_eq!(
        memory_bits(&trace, 1, 3, TRACE_MEMORY_PREDECESSOR_BITS_OFFSET)?,
        0
    );
    assert_eq!(
        memory_bits(&trace, 1, 3, TRACE_MEMORY_DELTA_BITS_OFFSET)?,
        8
    );
    assert_eq!(
        memory_bits(&trace, 2, 3, TRACE_MEMORY_PREDECESSOR_BITS_OFFSET)?,
        9
    );
    assert_eq!(
        memory_bits(&trace, 2, 3, TRACE_MEMORY_DELTA_BITS_OFFSET)?,
        4
    );

    let relation = CpuStructuralRelation;
    assert_row_satisfied(&relation, &trace, 1)?;
    assert_row_satisfied(&relation, &trace, 2)?;
    let mut tampered = row_values(&trace, 2)?;
    let predecessor =
        TRACE_MEMORY_START + 3 * TRACE_MEMORY_SLOT_WIDTH + TRACE_MEMORY_PREDECESSOR_BITS_OFFSET;
    let bit = tampered
        .get_mut(predecessor)
        .ok_or(MutableMemoryError::Shape)?;
    *bit = NativeField::from_u64(0);
    assert_row_rejected(&relation, &tampered)?;
    Ok(())
}

#[test]
#[ignore = "expensive twenty-six-group trace plus five 128-KiB memory commitments and openings"]
fn committed_latest_value_proof_rejects_final_memory_substitution()
-> Result<(), Box<dyn std::error::Error>> {
    let (trace, initial_bytes, final_bytes) = memory_trace()?;
    let trace_witness = commit_witness(trace.columns())?;
    let initial = commit_memory(&initial_bytes)?;
    let final_memory = commit_memory(&final_bytes)?;
    let proof = prove_mutable_memory(&trace, &trace_witness, &initial, &final_memory)?;
    verify_mutable_memory(
        &proof,
        trace_witness.commitments(),
        initial.commitment(),
        final_memory.commitment(),
    )?;

    let mut alternative = final_bytes;
    let last = alternative.last_mut().ok_or(MutableMemoryError::Shape)?;
    *last ^= 1;
    let alternative = commit_memory(&alternative)?;
    assert!(
        verify_mutable_memory(
            &proof,
            trace_witness.commitments(),
            initial.commitment(),
            alternative.commitment(),
        )
        .is_err()
    );
    Ok(())
}

#[test]
#[ignore = "expensive complete CPU, ISA, ROM, and ordered-memory composite gate"]
fn composite_cpu_isa_rom_and_memory_claims_share_trace_commitments()
-> Result<(), Box<dyn std::error::Error>> {
    let (trace, initial_bytes, final_bytes) = memory_trace()?;
    let mut rom_bytes = memory_program();
    rom_bytes.resize(crate::ROM_IMAGE_BYTES, 0);
    let rom = commit_rom(&rom_bytes)?;
    let initial = commit_memory(&initial_bytes)?;
    let final_memory = commit_memory(&final_bytes)?;
    let claim = NativeExecutionClaim::from_trace(&trace)?;
    let logs = commit_protocol_logs(&trace)?;
    let proof = prove_native_memory_cpu(&trace, &claim, &logs, &rom, &initial, &final_memory)?;
    verify_native_memory_cpu(
        &proof,
        &claim,
        logs.commitment(),
        rom.commitment(),
        initial.commitment(),
        final_memory.commitment(),
    )?;
    Ok(())
}

fn memory_trace() -> Result<MemoryTrace, Box<dyn std::error::Error>> {
    let program = memory_program();
    let rom = RomImage::new(program)?;
    let memory = MemoryImage::zeroed()?;
    let mut builder = TraceBuilder::new(rom, memory, Vec::new());
    let initial = builder.checkpoint_memory();
    let mut rows = Vec::<TraceRow>::new();
    for _ in 0..4 {
        rows.push(builder.step()?);
    }
    let final_memory = builder.checkpoint_memory();
    let references = rows.iter().collect::<Vec<_>>();
    Ok((
        NativeTraceWitness::from_rows(&references)?,
        initial,
        final_memory,
    ))
}

fn memory_program() -> Vec<u8> {
    vec![
        0x3e, 0x5a, // LD A,0x5a
        0xea, 0x00, 0xc0, // LD (0xc000),A
        0xfa, 0x00, 0xc0, // LD A,(0xc000)
        0x76, // HALT
    ]
}

fn memory_bits(
    trace: &NativeTraceWitness,
    row: usize,
    slot: usize,
    offset: usize,
) -> Result<u64, MutableMemoryError> {
    let start = TRACE_MEMORY_START + slot * TRACE_MEMORY_SLOT_WIDTH + offset;
    let mut value = 0_u64;
    for bit in 0..TRACE_MEMORY_TIMESTAMP_BITS {
        let limb = trace
            .columns()
            .get(start + bit)
            .and_then(|column| column.get(row))
            .copied()
            .ok_or(MutableMemoryError::Shape)?;
        value |= limb << bit;
    }
    Ok(value)
}

fn row_values(
    trace: &NativeTraceWitness,
    row: usize,
) -> Result<Vec<NativeField>, MutableMemoryError> {
    trace
        .columns()
        .iter()
        .map(|column| {
            column
                .get(row)
                .copied()
                .map(NativeField::from_u64)
                .ok_or(MutableMemoryError::Shape)
        })
        .collect()
}

fn assert_row_satisfied(
    relation: &CpuStructuralRelation,
    trace: &NativeTraceWitness,
    row: usize,
) -> Result<(), MutableMemoryError> {
    let row = row_values(trace, row)?;
    let mut constraints = vec![NativeField::from_u64(0); CPU_STRUCTURAL_CONSTRAINT_COUNT];
    relation.evaluate(&row, &mut constraints)?;
    assert!(
        constraints
            .iter()
            .all(|value| *value == NativeField::from_u64(0))
    );
    Ok(())
}

fn assert_row_rejected(
    relation: &CpuStructuralRelation,
    row: &[NativeField],
) -> Result<(), MutableMemoryError> {
    let mut constraints = vec![NativeField::from_u64(0); CPU_STRUCTURAL_CONSTRAINT_COUNT];
    relation.evaluate(row, &mut constraints)?;
    assert!(
        constraints
            .iter()
            .any(|value| *value != NativeField::from_u64(0))
    );
    Ok(())
}
