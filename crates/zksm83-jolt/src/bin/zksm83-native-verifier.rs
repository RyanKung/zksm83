//! Standalone verifier for canonical native-SM83 transparent receipts.

use std::{
    env,
    ffi::OsString,
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
    run_from(env::args_os().skip(1))
}

fn run_from<I>(arguments: I) -> Result<[u8; 32], CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();
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

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsString,
        fs::{self, File},
        io,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::{
        CliError, MAX_NATIVE_STATEMENT_BYTES, MAX_NATIVE_STREAM_RECEIPT_BYTES, read_bounded,
        require_bounded_receipt, run_from,
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn argument_and_file_failures_are_closed() -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            run_from(Vec::<OsString>::new()),
            Err(CliError::Usage)
        ));
        assert!(matches!(
            run_from([OsString::from("statement")]),
            Err(CliError::Usage)
        ));
        assert!(matches!(
            run_from([
                OsString::from("statement"),
                OsString::from("receipt"),
                OsString::from("extra"),
            ]),
            Err(CliError::Usage)
        ));

        let directory = TestDirectory::new()?;
        let missing = directory.path().join("missing.statement");
        let receipt = directory.path().join("receipt.bin");
        fs::write(&receipt, [])?;
        assert!(matches!(
            run_from([missing.into_os_string(), receipt.clone().into_os_string()]),
            Err(CliError::Read {
                kind: "statement",
                ..
            })
        ));

        let malformed = directory.path().join("malformed.statement");
        fs::write(&malformed, b"not-a-native-statement")?;
        assert!(matches!(
            run_from([malformed.into_os_string(), receipt.into_os_string()]),
            Err(CliError::Receipt(_))
        ));
        Ok(())
    }

    #[test]
    fn sparse_oversize_inputs_are_rejected_before_reading() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = TestDirectory::new()?;
        let statement = directory.path().join("oversize.statement");
        File::create(&statement)?.set_len(u64::try_from(MAX_NATIVE_STATEMENT_BYTES)? + 1)?;
        assert!(matches!(
            read_bounded(&statement, "statement", MAX_NATIVE_STATEMENT_BYTES),
            Err(CliError::Length { kind: "statement" })
        ));

        let receipt = directory.path().join("oversize.receipt");
        File::create(&receipt)?.set_len(MAX_NATIVE_STREAM_RECEIPT_BYTES + 1)?;
        assert!(matches!(
            require_bounded_receipt(&receipt),
            Err(CliError::Length { kind: "receipt" })
        ));
        Ok(())
    }

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> io::Result<Self> {
            let ordinal = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "zksm83-native-verifier-{}-{ordinal}",
                std::process::id()
            ));
            fs::create_dir(&path)?;
            Ok(Self { path })
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.path);
        }
    }
}
