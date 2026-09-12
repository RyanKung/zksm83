//! Standalone verifier for canonical native-SM83 transparent receipts.

use std::{
    env,
    fs::{self, File},
    io::{self, BufReader},
    path::Path,
    process::ExitCode,
};

use thiserror::Error;
use zksm83_jolt::{
    MAX_NATIVE_STATEMENT_BYTES, MAX_NATIVE_STREAM_RECEIPT_BYTES, NativeReceiptError,
    NativeStatement, verify_native_receipt_reader,
};

#[derive(Debug, Error)]
enum CliError {
    #[error("usage: zksm83-native-verifier <expected-statement.bin> <receipt.bin>")]
    Usage,
    #[error("{kind} file exceeds the protocol byte limit")]
    Length { kind: &'static str },
    #[error("failed to read {kind} file {path}: {source}")]
    Read {
        kind: &'static str,
        path: String,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Receipt(#[from] NativeReceiptError),
}

fn main() -> ExitCode {
    match run() {
        Ok(statement_id) => {
            println!("verified statement {}", hex(statement_id));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("verification failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<[u8; 32], CliError> {
    let mut arguments = env::args_os().skip(1);
    let statement_path = arguments.next().ok_or(CliError::Usage)?;
    let receipt_path = arguments.next().ok_or(CliError::Usage)?;
    if arguments.next().is_some() {
        return Err(CliError::Usage);
    }
    let statement_bytes = read_bounded(
        Path::new(&statement_path),
        "statement",
        MAX_NATIVE_STATEMENT_BYTES,
    )?;
    let receipt_path = Path::new(&receipt_path);
    require_bounded_receipt(receipt_path)?;
    let receipt = File::open(receipt_path).map_err(|source| CliError::Read {
        kind: "receipt",
        path: receipt_path.display().to_string(),
        source,
    })?;
    let expected = NativeStatement::from_bytes(&statement_bytes)?;
    Ok(verify_native_receipt_reader(BufReader::new(receipt), &expected)?.statement_id())
}

fn require_bounded_receipt(path: &Path) -> Result<(), CliError> {
    let metadata = fs::metadata(path).map_err(|source| CliError::Read {
        kind: "receipt",
        path: path.display().to_string(),
        source,
    })?;
    if metadata.len() > MAX_NATIVE_STREAM_RECEIPT_BYTES {
        return Err(CliError::Length { kind: "receipt" });
    }
    Ok(())
}

fn read_bounded(path: &Path, kind: &'static str, maximum: usize) -> Result<Vec<u8>, CliError> {
    let metadata = fs::metadata(path).map_err(|source| CliError::Read {
        kind,
        path: path.display().to_string(),
        source,
    })?;
    if metadata.len() > u64::try_from(maximum).map_err(|_| CliError::Length { kind })? {
        return Err(CliError::Length { kind });
    }
    fs::read(path).map_err(|source| CliError::Read {
        kind,
        path: path.display().to_string(),
        source,
    })
}

fn hex(bytes: [u8; 32]) -> String {
    bytes
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
