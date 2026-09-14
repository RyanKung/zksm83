use super::{
    AKITA_AUXILIARY_SCHEDULE_SHA256, AKITA_SCHEDULE_SHA256, BASIC_BLOCK_INSTRUCTION_BOUND,
    CliError, EXPECTED_CHECKPOINT_SCHEMA, ExpectedCheckpoint, ExpectedState, InputIdentities,
    MAX_NATIVE_SEGMENT_COUNT, MAX_NATIVE_STREAM_RECEIPT_BYTES, NATIVE_RECEIPT_VERSION,
    PROGRESS_SCHEMA, PROOF_COMPOSITION_REVISION_V2, PROTOCOL_ID, ProverProgress, RtcArg,
    SpoolRecovery, UNIFORM_ROW_COUNT, fill_packed_segment_with_capacity, native_backend_digest,
    resolve_cartridge_selection, spool_recovery, validate_endpoint, validate_expected_artifact,
    validate_progress, validate_verified_counters,
};
use zksm83_core::{
    CpuState, DmgDeviceState, MachineContext, MachineProfile, Mbc3CartridgeProfile, Mbc3RomSize,
    Mbc3RtcMode, Mbc3State, VmState,
};
use zksm83_jolt::ROM_IMAGE_BYTES;
use zksm83_memory::{CommitmentRoot, LogAccumulator, LogKind, MemoryImage, RomImage};

#[test]
fn legacy_roots_do_not_override_exact_native_endpoint_checks()
-> Result<(), Box<dyn std::error::Error>> {
    let (expected, actual, memory, rom, input) = fixture()?;
    validate_endpoint(actual, &memory, &rom, &input, &expected)?;

    let mut changed_memory = memory.clone();
    let byte = changed_memory
        .get_mut(0)
        .ok_or_else(|| std::io::Error::other("missing memory byte"))?;
    *byte ^= 1;
    assert!(validate_endpoint(actual, &changed_memory, &rom, &input, &expected).is_err());

    let changed_input = [8_u8];
    assert!(validate_endpoint(actual, &memory, &rom, &changed_input, &expected).is_err());
    Ok(())
}

#[test]
fn preflight_rejects_a_short_rom() -> Result<(), Box<dyn std::error::Error>> {
    let (expected, _, _, _, _) = fixture()?;
    let cartridge = super::CartridgeSelection {
        profile: Mbc3CartridgeProfile::one_mib_no_rtc(),
        machine_profile: MachineProfile::DmgPostBootMbc3V1,
    };
    assert!(validate_expected_artifact(&expected, &[0], cartridge).is_err());
    Ok(())
}

#[test]
fn auto_cartridge_selection_accepts_gbstudio_mbc3_timer_rom()
-> Result<(), Box<dyn std::error::Error>> {
    let mut args = fixture_args();
    args.rtc = RtcArg::Auto;
    let mut rom = vec![0_u8; 256 * 1024];
    let cartridge_type = rom
        .get_mut(0x0147)
        .ok_or_else(|| std::io::Error::other("missing cartridge type header"))?;
    *cartridge_type = 0x10;
    let cartridge = resolve_cartridge_selection(&args, &rom)?;
    assert_eq!(
        cartridge.profile,
        Mbc3CartridgeProfile::new(Mbc3RomSize::Rom256KiB, Mbc3RtcMode::RtcCapable)
    );
    assert_eq!(
        cartridge.machine_profile,
        MachineProfile::DmgPostBootMbc3Rom256KiBRtcV1
    );
    Ok(())
}

#[test]
fn spool_length_policy_rejects_loss_and_discards_only_uncheckpointed_tail() {
    assert!(matches!(spool_recovery(8, 8), Ok(SpoolRecovery::Exact)));
    assert!(matches!(
        spool_recovery(9, 8),
        Ok(SpoolRecovery::DiscardUncheckpointedTail)
    ));
    assert!(matches!(
        spool_recovery(7, 8),
        Err(CliError::ProgressMismatch(
            "spool is shorter than checkpoint"
        ))
    ));
}

#[test]
fn progress_schema_capacity_and_input_identities_are_exact()
-> Result<(), Box<dyn std::error::Error>> {
    let (_, state, memory, _, _) = fixture()?;
    let identities = InputIdentities {
        rom: [1; 32],
        input: [2; 32],
        expected: [3; 32],
    };
    let mut progress = ProverProgress {
        schema: PROGRESS_SCHEMA.to_owned(),
        receipt_version: NATIVE_RECEIPT_VERSION,
        protocol_id: PROTOCOL_ID.to_owned(),
        proof_composition_revision: PROOF_COMPOSITION_REVISION_V2.to_owned(),
        backend_digest_sha256: hex::encode(native_backend_digest()),
        trace_schedule_sha256: AKITA_SCHEDULE_SHA256.to_owned(),
        auxiliary_schedule_sha256: AKITA_AUXILIARY_SCHEDULE_SHA256.to_owned(),
        rom_sha256: hex::encode(identities.rom),
        input_sha256: hex::encode(identities.input),
        expected_checkpoint_sha256: hex::encode(identities.expected),
        relation_row_capacity: UNIFORM_ROW_COUNT,
        segment_count: 1,
        completed_steps: 1,
        relation_row_count: 1,
        spool_bytes: 1,
        state,
        memory_hex: hex::encode(memory),
    };
    validate_progress(&progress, identities)?;
    validate_verified_counters(&progress, 1, 1, 1, 1)?;

    progress.completed_steps = 2;
    assert!(validate_verified_counters(&progress, 1, 1, 1, 1).is_err());
    progress.completed_steps = 1;

    progress.schema = "unsupported".to_owned();
    assert!(validate_progress(&progress, identities).is_err());
    progress.schema = PROGRESS_SCHEMA.to_owned();

    progress.receipt_version = 1;
    assert!(validate_progress(&progress, identities).is_err());
    progress.receipt_version = NATIVE_RECEIPT_VERSION;
    progress.protocol_id = "unsupported".to_owned();
    assert!(validate_progress(&progress, identities).is_err());
    progress.protocol_id = PROTOCOL_ID.to_owned();
    progress.proof_composition_revision = "unsupported".to_owned();
    assert!(validate_progress(&progress, identities).is_err());
    progress.proof_composition_revision = PROOF_COMPOSITION_REVISION_V2.to_owned();
    progress.backend_digest_sha256 = hex::encode([7; 32]);
    assert!(validate_progress(&progress, identities).is_err());
    progress.backend_digest_sha256 = hex::encode(native_backend_digest());
    progress.trace_schedule_sha256 = "unsupported".to_owned();
    assert!(validate_progress(&progress, identities).is_err());
    progress.trace_schedule_sha256 = AKITA_SCHEDULE_SHA256.to_owned();
    progress.auxiliary_schedule_sha256 = "unsupported".to_owned();
    assert!(validate_progress(&progress, identities).is_err());
    progress.auxiliary_schedule_sha256 = AKITA_AUXILIARY_SCHEDULE_SHA256.to_owned();

    progress.segment_count =
        u64::try_from(MAX_NATIVE_SEGMENT_COUNT).map_err(std::io::Error::other)? + 1;
    assert!(validate_progress(&progress, identities).is_err());
    progress.segment_count = 1;
    progress.relation_row_count =
        u64::try_from(UNIFORM_ROW_COUNT).map_err(std::io::Error::other)? + 1;
    assert!(validate_progress(&progress, identities).is_err());
    progress.relation_row_count = 1;
    progress.completed_steps =
        u64::try_from(BASIC_BLOCK_INSTRUCTION_BOUND).map_err(std::io::Error::other)? + 1;
    assert!(validate_progress(&progress, identities).is_err());
    progress.completed_steps = 1;
    progress.spool_bytes = MAX_NATIVE_STREAM_RECEIPT_BYTES + 1;
    assert!(validate_progress(&progress, identities).is_err());
    progress.spool_bytes = 1;

    progress.relation_row_capacity = UNIFORM_ROW_COUNT + 1;
    assert!(validate_progress(&progress, identities).is_err());
    progress.relation_row_capacity = UNIFORM_ROW_COUNT;
    progress.input_sha256 = hex::encode([9; 32]);
    assert!(validate_progress(&progress, identities).is_err());
    Ok(())
}

#[test]
fn packed_segment_fills_rows_without_exceeding_raw_step_bound()
-> Result<(), Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0_u8; 64])?;
    let memory = MemoryImage::zeroed()?;
    let mut builder = super::TraceBuilder::new(rom, memory, Vec::new());
    let packed = fill_packed_segment_with_capacity(&mut builder, 32, 8)?;
    let retained_steps = packed
        .blocks
        .iter()
        .map(zksm83_trace::BasicBlock::row_count)
        .sum::<usize>();
    assert_eq!(packed.blocks.len(), 8);
    assert_eq!(u64::try_from(retained_steps)?, packed.completed_steps);
    assert!(packed.completed_steps > 8);
    assert!(packed.completed_steps <= 32);
    for (expected, block) in packed.blocks.iter().enumerate() {
        let prior_rows = packed
            .blocks
            .get(..expected)
            .ok_or("packed block prefix")?
            .iter()
            .map(zksm83_trace::BasicBlock::row_count)
            .sum::<usize>();
        assert_eq!(block.source_row_start(), prior_rows);
    }
    Ok(())
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let rom = vec![0_u8; ROM_IMAGE_BYTES];
    let rom_root = RomImage::new(rom.clone())?.root();
    let memory_image = MemoryImage::zeroed()?;
    let memory = memory_image.checkpoint_bytes();
    let input = vec![7_u8];
    let input_log = LogAccumulator::commit(LogKind::Input, &input)?;
    let output_log = LogAccumulator::empty(LogKind::Output);
    let cpu = CpuState::dmg_post_boot_initial();
    let devices = DmgDeviceState::dmg_post_boot();
    let actual = VmState::from_profile_parts(
        MachineContext::new(MachineProfile::DmgPostBootMbc3V1, devices),
        cpu,
        Mbc3State::profile_initial(),
        rom_root,
        memory_image.root(),
        input_log,
        output_log,
    )?;
    let expected = ExpectedCheckpoint {
        schema: EXPECTED_CHECKPOINT_SCHEMA.to_owned(),
        completed_steps: 1,
        state: ExpectedState {
            profile: MachineProfile::DmgPostBootMbc3V1,
            cpu,
            mbc3: Mbc3State::profile_initial(),
            dmg_devices: devices,
            _legacy_rom_root: CommitmentRoot::zero(),
            _legacy_memory_root: CommitmentRoot::zero(),
            input_log,
            output_log,
        },
        memory_hex: hex::encode(&memory),
    };
    Ok((expected, actual, memory, rom, input))
}

type Fixture = (ExpectedCheckpoint, VmState, Vec<u8>, Vec<u8>, Vec<u8>);

fn fixture_args() -> super::Args {
    super::Args {
        rom: "rom.gb".into(),
        rom_size: super::RomSizeArg::Auto,
        rtc: RtcArg::Auto,
        input: "input.bin".into(),
        expected_checkpoint: "expected.json".into(),
        spool: "proof.spool".into(),
        progress_checkpoint: "progress.json".into(),
        receipt: "receipt.bin".into(),
        statement: "statement.bin".into(),
        resume: false,
        segment_limit: None,
        preflight_only: false,
        inspect_progress_only: false,
    }
}
