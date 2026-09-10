//! End-to-end receipt rejection and production-path proposition tests.

use std::{fs, io, path::Path, sync::OnceLock};

use zksm83_memory::{LogAccumulator, LogKind, MemoryImage, RomImage};
use zksm83_receipt::{Receipt, ReceiptError};
use zksm83_trace::TraceBuilder;

const DEMO_ROM: &[u8] = &[
    0x21, 0x00, 0x80, 0x36, 0x2a, 0x7e, 0xc6, 0x10, 0xe0, 0xf1, 0x76,
];

fn fixture() -> Result<Receipt, io::Error> {
    static RECEIPT: OnceLock<Result<Receipt, String>> = OnceLock::new();
    match RECEIPT.get_or_init(|| create_fixture().map_err(|error| error.to_string())) {
        Ok(receipt) => Ok(receipt.clone()),
        Err(error) => Err(io::Error::other(error.clone())),
    }
}

fn create_fixture() -> Result<Receipt, Box<dyn std::error::Error>> {
    let witness = TraceBuilder::new(
        RomImage::new(DEMO_ROM.to_vec())?,
        MemoryImage::zeroed()?,
        Vec::new(),
    )
    .run(20)?;
    Ok(Receipt::prove(&witness)?)
}

#[test]
#[ignore = "expensive Halo2 receipt gate; run explicitly"]
fn receipt_rejects_changed_rom_root() -> Result<(), Box<dyn std::error::Error>> {
    let mut receipt = fixture()?;
    receipt.statement.rom_root = RomImage::new(vec![0x00, 0x76])?.root();
    receipt.statement.receipt_id = receipt.statement.recompute_id();
    assert!(matches!(receipt.verify(), Err(ReceiptError::Proof(_))));
    Ok(())
}

#[test]
#[ignore = "expensive Halo2 receipt gate; run explicitly"]
fn receipt_rejects_changed_input_root() -> Result<(), Box<dyn std::error::Error>> {
    let mut receipt = fixture()?;
    receipt.statement.input_root = LogAccumulator::commit(LogKind::Input, &[0x5a])?.root();
    assert!(matches!(
        receipt.verify(),
        Err(ReceiptError::ReceiptIdMismatch)
    ));
    Ok(())
}

#[test]
#[ignore = "expensive Halo2 receipt gate; run explicitly"]
fn receipt_rejects_changed_final_memory_root() -> Result<(), Box<dyn std::error::Error>> {
    let mut receipt = fixture()?;
    receipt.statement.final_memory_root = MemoryImage::new(vec![0x01])?.root();
    assert!(matches!(
        receipt.verify(),
        Err(ReceiptError::ReceiptIdMismatch)
    ));
    Ok(())
}

#[test]
#[ignore = "expensive Halo2 receipt gate; run explicitly"]
fn receipt_rejects_changed_proof_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let mut receipt = fixture()?;
    let byte = receipt.proof.first_mut().ok_or("fixture proof is empty")?;
    *byte ^= 1;
    assert!(matches!(receipt.verify(), Err(ReceiptError::Proof(_))));
    Ok(())
}

#[test]
#[ignore = "expensive Halo2 receipt gate; run explicitly"]
fn receipt_rejects_changed_opcode_shape() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = fixture()?.to_json_pretty()?;
    let mut value: serde_json::Value = serde_json::from_str(&encoded)?;
    let opcode = value
        .pointer_mut("/shape/steps/0/instruction/encoding/Primary")
        .ok_or("fixture opcode path is absent")?;
    *opcode = serde_json::Value::from(0);
    let receipt = Receipt::from_json(&serde_json::to_string(&value)?)?;
    assert!(matches!(receipt.verify(), Err(ReceiptError::Proof(_))));
    Ok(())
}

#[test]
#[ignore = "expensive Halo2 receipt gate; run explicitly"]
fn receipt_rejects_changed_step_count() -> Result<(), Box<dyn std::error::Error>> {
    let mut receipt = fixture()?;
    receipt.statement.step_count = receipt.statement.step_count.saturating_add(1);
    assert!(matches!(
        receipt.verify(),
        Err(ReceiptError::ReceiptIdMismatch)
    ));
    Ok(())
}

#[test]
#[ignore = "expensive Halo2 receipt gate; run explicitly"]
fn receipt_rejects_unsupported_version_and_profile() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = fixture()?.to_json_pretty()?;
    let changed_version = encoded.replace("zksm83-core/2", "zksm83-core/3");
    let changed_profile = encoded.replace("sm83-core-v1", "sm83-core-v2");
    assert!(matches!(
        Receipt::from_json(&changed_version),
        Err(ReceiptError::Encoding(_))
    ));
    assert!(matches!(
        Receipt::from_json(&changed_profile),
        Err(ReceiptError::Encoding(_))
    ));
    Ok(())
}

#[test]
#[ignore = "expensive Halo2 receipt gate; run explicitly"]
fn verifier_rejects_a_different_expected_statement() -> Result<(), Box<dyn std::error::Error>> {
    let receipt = fixture()?;
    let mut expected = receipt.statement;
    expected.step_count = expected.step_count.saturating_add(1);
    expected.receipt_id = expected.recompute_id();
    assert!(matches!(
        receipt.verify_against(expected),
        Err(ReceiptError::PublicStatementMismatch)
    ));
    Ok(())
}

#[test]
fn native_emulator_is_not_in_proof_path() -> Result<(), Box<dyn std::error::Error>> {
    let receipt_manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates = receipt_manifest
        .parent()
        .ok_or("receipt crate has no crates directory")?;
    let workspace = crates.parent().ok_or("crates directory has no workspace")?;
    let root_manifest = fs::read_to_string(workspace.join("Cargo.toml"))?;
    assert!(!root_manifest.contains("backup/"));
    assert!(!root_manifest.to_ascii_lowercase().contains("oxgbc"));
    for entry in fs::read_dir(crates)? {
        let path = entry?.path().join("Cargo.toml");
        if path.is_file() {
            let manifest = fs::read_to_string(path)?;
            assert!(!manifest.contains("backup/"));
            assert!(!manifest.to_ascii_lowercase().contains("oxgbc"));
        }
    }
    Ok(())
}
