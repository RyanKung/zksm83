//! Standalone verifier for canonical native-SM83 transparent receipts.

use std::{
    env,
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, BufReader},
    path::Path,
    process::ExitCode,
};

use thiserror::Error;
use zksm83_jolt::{
    MAX_NATIVE_STATEMENT_BYTES, MAX_NATIVE_STREAM_RECEIPT_BYTES, NativeProverBackend,
    NativeProverBackendError, NativeProverBackendKind, NativeReceiptError, NativeStatement,
    native_proof_phase_metrics, verify_native_receipt_reader_with_backend,
};

#[derive(Debug, Error)]
enum CliError {
    #[error(
        "usage: zksm83-native-verifier [--proof-backend cpu|cuda] [--cuda-device N] <expected-statement.bin> <receipt.bin>"
    )]
    Usage,
    #[error("invalid proof backend {0}")]
    InvalidProofBackend(String),
    #[error("invalid CUDA device ordinal {0}")]
    InvalidCudaDevice(String),
    #[error("--cuda-device requires --proof-backend cuda")]
    CudaDeviceWithCpuBackend,
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
    ProverBackend(#[from] NativeProverBackendError),
    #[error(transparent)]
    Receipt(#[from] NativeReceiptError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProofBackendArg {
    Cpu,
    Cuda,
}

#[derive(Debug, Eq, PartialEq)]
struct VerifierArgs {
    statement_path: OsString,
    receipt_path: OsString,
    proof_backend: ProofBackendArg,
    cuda_device: Option<usize>,
}

fn main() -> ExitCode {
    let phases_before = native_proof_phase_metrics();
    match run() {
        Ok((statement_id, version)) => {
            let phases = native_proof_phase_metrics().since(phases_before);
            println!(
                "verified receipt_version={} statement={} verify_seconds={:.3}",
                version,
                hex(statement_id),
                phases.verify().as_secs_f64()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("verification failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<([u8; 32], u64), CliError> {
    run_from(env::args_os().skip(1))
}

fn run_from<I>(arguments: I) -> Result<([u8; 32], u64), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let args = parse_args(arguments)?;
    let backend = initialize_verifier_backend(args.proof_backend, args.cuda_device)?;
    let statement_bytes = read_bounded(
        Path::new(&args.statement_path),
        "statement",
        MAX_NATIVE_STATEMENT_BYTES,
    )?;
    let receipt_path = Path::new(&args.receipt_path);
    require_bounded_receipt(receipt_path)?;
    let receipt = File::open(receipt_path).map_err(|source| CliError::Read {
        kind: "receipt",
        path: receipt_path.display().to_string(),
        source,
    })?;
    let expected = NativeStatement::from_bytes(&statement_bytes)?;
    let verified =
        verify_native_receipt_reader_with_backend(BufReader::new(receipt), &expected, &backend)?;
    Ok((verified.statement_id(), expected.protocol().code()))
}

fn parse_args<I>(arguments: I) -> Result<VerifierArgs, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut proof_backend = ProofBackendArg::Cpu;
    let mut cuda_device = None;
    let mut positional = Vec::with_capacity(2);
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        if argument == OsStr::new("--proof-backend") {
            let value = arguments.next().ok_or(CliError::Usage)?;
            proof_backend = parse_proof_backend(&value)?;
        } else if let Some(value) = option_value(&argument, "--proof-backend") {
            proof_backend = parse_proof_backend_str(value)?;
        } else if argument == OsStr::new("--cuda-device") {
            let value = arguments.next().ok_or(CliError::Usage)?;
            cuda_device = Some(parse_cuda_device(&value)?);
        } else if let Some(value) = option_value(&argument, "--cuda-device") {
            cuda_device = Some(parse_cuda_device_str(value)?);
        } else if argument
            .to_str()
            .is_some_and(|value| value.starts_with("--"))
        {
            return Err(CliError::Usage);
        } else {
            positional.push(argument);
            if positional.len() > 2 {
                return Err(CliError::Usage);
            }
        }
    }
    if positional.len() != 2 {
        return Err(CliError::Usage);
    }
    let receipt_path = positional.pop().ok_or(CliError::Usage)?;
    let statement_path = positional.pop().ok_or(CliError::Usage)?;
    Ok(VerifierArgs {
        statement_path,
        receipt_path,
        proof_backend,
        cuda_device,
    })
}

fn option_value<'a>(argument: &'a OsStr, option: &str) -> Option<&'a str> {
    argument
        .to_str()
        .and_then(|value| value.strip_prefix(option))
        .and_then(|value| value.strip_prefix('='))
}

fn parse_proof_backend(value: &OsStr) -> Result<ProofBackendArg, CliError> {
    value.to_str().map_or_else(
        || {
            Err(CliError::InvalidProofBackend(
                value.to_string_lossy().into_owned(),
            ))
        },
        parse_proof_backend_str,
    )
}

fn parse_proof_backend_str(value: &str) -> Result<ProofBackendArg, CliError> {
    match value {
        "cpu" => Ok(ProofBackendArg::Cpu),
        "cuda" => Ok(ProofBackendArg::Cuda),
        _ => Err(CliError::InvalidProofBackend(value.to_owned())),
    }
}

fn parse_cuda_device(value: &OsStr) -> Result<usize, CliError> {
    value.to_str().map_or_else(
        || {
            Err(CliError::InvalidCudaDevice(
                value.to_string_lossy().into_owned(),
            ))
        },
        parse_cuda_device_str,
    )
}

fn parse_cuda_device_str(value: &str) -> Result<usize, CliError> {
    value
        .parse()
        .map_err(|_| CliError::InvalidCudaDevice(value.to_owned()))
}

fn initialize_verifier_backend(
    selection: ProofBackendArg,
    cuda_device: Option<usize>,
) -> Result<NativeProverBackend, CliError> {
    NativeProverBackend::initialize(verifier_backend_kind(selection, cuda_device)?)
        .map_err(Into::into)
}

fn verifier_backend_kind(
    selection: ProofBackendArg,
    cuda_device: Option<usize>,
) -> Result<NativeProverBackendKind, CliError> {
    match (selection, cuda_device) {
        (ProofBackendArg::Cpu, None) => Ok(NativeProverBackendKind::Cpu),
        (ProofBackendArg::Cpu, Some(_)) => Err(CliError::CudaDeviceWithCpuBackend),
        (ProofBackendArg::Cuda, device_ordinal) => Ok(NativeProverBackendKind::Cuda {
            device_ordinal: device_ordinal.unwrap_or(0),
        }),
    }
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
