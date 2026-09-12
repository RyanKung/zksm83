use sha2::{Digest, Sha256};
use zksm83_memory::{MemoryImage, RomImage};
use zksm83_trace::{TraceBuilder, TraceRow};

use super::{
    AKITA_LOG_SCHEDULE_SHA256, BUS_START, INPUT_START, ISA_START, LOG_LAYOUT,
    LOG_SCHEDULE_ARTIFACT, NativeExecutionClaim, OUTPUT_START, PROTOCOL_LOG_NUM_VARIABLES,
    ProtocolLogError, commit_protocol_logs, expected_counts, extract_entries, log_columns,
    prove_protocol_logs, verify_protocol_logs,
};
use crate::{NativeTraceWitness, commit_witness, pcs::scheme};

fn io_trace(input: u8) -> Result<NativeTraceWitness, Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![
        0xfa, 0xf0, 0xff, // LD A,(0xfff0)
        0xea, 0xf1, 0xff, // LD (0xfff1),A
        0x76, // HALT
    ])?;
    let memory = MemoryImage::zeroed()?;
    let mut builder = TraceBuilder::new(rom, memory, vec![input]);
    let rows = [builder.step()?, builder.step()?, builder.step()?];
    let references = rows.iter().collect::<Vec<&TraceRow>>();
    NativeTraceWitness::from_rows(&references).map_err(Into::into)
}

#[test]
fn pinned_log_schedule_admits_exact_group_shape() -> Result<(), ProtocolLogError> {
    let scheme = scheme(LOG_LAYOUT)?;
    let admitted = scheme.schedules().catalog().rows().any(|row| {
        row.profiles().final_group.group.num_vars() == PROTOCOL_LOG_NUM_VARIABLES
            && row.profiles().final_group.group.num_polynomials() == 128
            && row.profiles().precommitteds.is_empty()
    });
    assert!(admitted);
    assert_eq!(
        format!("{:x}", Sha256::digest(LOG_SCHEDULE_ARTIFACT)),
        AKITA_LOG_SCHEDULE_SHA256
    );
    Ok(())
}

#[test]
fn canonical_tables_extract_all_four_ordered_logs() -> Result<(), Box<dyn std::error::Error>> {
    let trace = io_trace(0x5a)?;
    let entries = extract_entries(trace.columns())?;
    assert_eq!(entries.bus.len(), 9);
    assert_eq!(entries.input, vec![[0, 0x5a]]);
    assert_eq!(entries.output, vec![[0, 0x5a]]);
    assert_eq!(entries.isa.len(), 3);

    let columns = log_columns(&trace)?;
    for (start, count) in [
        (BUS_START, 9),
        (INPUT_START, 1),
        (OUTPUT_START, 1),
        (ISA_START, 3),
    ] {
        let selector = columns.get(start).ok_or(ProtocolLogError::Shape)?;
        assert_eq!(
            selector.iter().take(count).sum::<u64>(),
            u64::try_from(count)?
        );
        assert!(selector.iter().skip(count).all(|value| *value == 0));
    }
    let claim = NativeExecutionClaim::from_trace(&trace)?;
    assert_eq!(expected_counts(&claim)?, [9, 1, 1, 3]);
    Ok(())
}

#[test]
fn joypad_input_commits_sample_not_rendered_register_value()
-> Result<(), Box<dyn std::error::Error>> {
    let mut program = vec![0; 0x100];
    program.extend_from_slice(&[0xf0, 0x00, 0x76]); // LDH A,(0xff00)
    let rom = RomImage::new(program)?;
    let memory = MemoryImage::zeroed()?;
    let mut builder = TraceBuilder::new_dmg_post_boot_mbc3(rom, memory, vec![0x10]);
    let rows = [builder.step()?];
    let references = rows.iter().collect::<Vec<&TraceRow>>();
    let trace = NativeTraceWitness::from_rows(&references)?;
    let entries = extract_entries(trace.columns())?;
    assert_eq!(entries.input, vec![[0, 0x10]]);
    Ok(())
}

#[test]
#[ignore = "expensive twenty-six-group trace plus 128-KiB protocol-log proof"]
fn committed_protocol_logs_reject_table_substitution() -> Result<(), Box<dyn std::error::Error>> {
    let trace = io_trace(0x5a)?;
    let claim = NativeExecutionClaim::from_trace(&trace)?;
    let trace_witness = commit_witness(trace.columns())?;
    let logs = commit_protocol_logs(&trace)?;
    let proof = prove_protocol_logs(&trace, &trace_witness, &logs, &claim)?;
    verify_protocol_logs(
        &proof,
        trace_witness.commitments(),
        logs.commitment(),
        &claim,
    )?;

    let alternative_trace = io_trace(0xa5)?;
    let alternative = commit_protocol_logs(&alternative_trace)?;
    assert!(
        verify_protocol_logs(
            &proof,
            trace_witness.commitments(),
            alternative.commitment(),
            &claim,
        )
        .is_err()
    );
    Ok(())
}
