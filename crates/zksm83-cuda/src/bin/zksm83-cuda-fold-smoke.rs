//! CUDA field-fold differential smoke test.

use std::process::ExitCode;

use jolt_field::{Prime128OffsetA7F7, Ring};
use thiserror::Error;
use zksm83_cuda::{CudaFoldError, fold_binary_layer_cuda};

const INPUT_LENGTH: u64 = 4096;
const CHALLENGE: u64 = 7;

#[derive(Debug, Error)]
enum SmokeError {
    #[error(transparent)]
    Cuda(#[from] CudaFoldError),
    #[error("CUDA field fold differs from the native field at output index {index}")]
    Mismatch { index: usize },
    #[error("native field-fold oracle received an incomplete pair")]
    IncompleteOraclePair,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => {
            println!("CUDA field fold matches the native field oracle");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("CUDA field fold smoke test failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), SmokeError> {
    let values = (0..INPUT_LENGTH)
        .map(Prime128OffsetA7F7::from_u64)
        .collect::<Vec<_>>();
    let challenge = Prime128OffsetA7F7::from_u64(CHALLENGE);
    let expected = values
        .chunks_exact(2)
        .map(|pair| fold_pair(pair, challenge))
        .collect::<Result<Vec<_>, _>>()?;
    let actual = fold_binary_layer_cuda(0, &values, challenge)?;
    if let Some(index) = actual
        .iter()
        .zip(&expected)
        .position(|(actual, expected)| actual != expected)
    {
        return Err(SmokeError::Mismatch { index });
    }
    if actual.len() != expected.len() {
        return Err(SmokeError::Mismatch {
            index: actual.len().min(expected.len()),
        });
    }
    Ok(())
}

fn fold_pair(
    pair: &[Prime128OffsetA7F7],
    challenge: Prime128OffsetA7F7,
) -> Result<Prime128OffsetA7F7, SmokeError> {
    let Some((low, remaining)) = pair.split_first() else {
        return Err(SmokeError::IncompleteOraclePair);
    };
    let Some(high) = remaining.first() else {
        return Err(SmokeError::IncompleteOraclePair);
    };
    Ok(*low + challenge * (*high - *low))
}
