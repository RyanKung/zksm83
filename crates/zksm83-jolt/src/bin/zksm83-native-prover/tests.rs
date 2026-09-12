use super::{
    AKITA_AUXILIARY_SCHEDULE_SHA256, AKITA_SCHEDULE_SHA256, CliError, EXPECTED_CHECKPOINT_SCHEMA,
    ExpectedCheckpoint, ExpectedState, InputIdentities, NATIVE_RECEIPT_VERSION, PROGRESS_SCHEMA,
    PROTOCOL_ID, ProverProgress, ROM_BYTE_LENGTH, SpoolRecovery, UNIFORM_ROW_COUNT, spool_recovery,
    validate_endpoint, validate_expected_artifact, validate_progress,
};
use zksm83_core::{CpuState, DmgDeviceState, MachineContext, MachineProfile, Mbc3State, VmState};
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
    assert!(validate_expected_artifact(&expected, &[0]).is_err());
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
        trace_schedule_sha256: AKITA_SCHEDULE_SHA256.to_owned(),
        auxiliary_schedule_sha256: AKITA_AUXILIARY_SCHEDULE_SHA256.to_owned(),
        rom_sha256: hex::encode(identities.rom),
        input_sha256: hex::encode(identities.input),
        expected_checkpoint_sha256: hex::encode(identities.expected),
        segment_capacity: UNIFORM_ROW_COUNT,
        segment_count: 1,
        relation_step_count: 1,
        spool_bytes: 1,
        state,
        memory_hex: hex::encode(memory),
    };
    validate_progress(&progress, identities)?;

    progress.schema = "unsupported".to_owned();
    assert!(validate_progress(&progress, identities).is_err());
    progress.schema = PROGRESS_SCHEMA.to_owned();

    progress.receipt_version = 1;
    assert!(validate_progress(&progress, identities).is_err());
    progress.receipt_version = NATIVE_RECEIPT_VERSION;
    progress.protocol_id = "unsupported".to_owned();
    assert!(validate_progress(&progress, identities).is_err());
    progress.protocol_id = PROTOCOL_ID.to_owned();
    progress.trace_schedule_sha256 = "unsupported".to_owned();
    assert!(validate_progress(&progress, identities).is_err());
    progress.trace_schedule_sha256 = AKITA_SCHEDULE_SHA256.to_owned();
    progress.auxiliary_schedule_sha256 = "unsupported".to_owned();
    assert!(validate_progress(&progress, identities).is_err());
    progress.auxiliary_schedule_sha256 = AKITA_AUXILIARY_SCHEDULE_SHA256.to_owned();

    progress.segment_capacity = UNIFORM_ROW_COUNT + 1;
    assert!(validate_progress(&progress, identities).is_err());
    progress.segment_capacity = UNIFORM_ROW_COUNT;
    progress.input_sha256 = hex::encode([9; 32]);
    assert!(validate_progress(&progress, identities).is_err());
    Ok(())
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let rom = vec![0_u8; ROM_BYTE_LENGTH];
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
