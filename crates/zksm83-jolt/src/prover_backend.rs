use core::fmt::{self, Display, Formatter};

use thiserror::Error;

use crate::{NativeField, field_fold::FieldFoldError};

/// Selects the execution backend for prover-only field folding.
///
/// This choice does not enter the transcript, proof encoding, backend digest,
/// or verifier. Both variants must produce the same canonical field values.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum NativeProverBackendKind {
    /// Execute every proof phase on the CPU.
    #[default]
    Cpu,
    /// Execute supported dense field-fold layers on one CUDA device.
    Cuda {
        /// Zero-based CUDA device ordinal.
        device_ordinal: usize,
    },
}

/// Failure to initialize or execute a selected native prover backend.
#[derive(Debug, Error)]
pub enum NativeProverBackendError {
    /// The binary was compiled without the optional `cuda` feature.
    #[error("the CUDA proof backend requires the zksm83-jolt `cuda` feature")]
    CudaFeatureDisabled,
    /// cuda-oxide currently supports Linux hosts only.
    #[error("the CUDA proof backend requires a Linux host")]
    CudaUnsupportedHost,
    /// CUDA initialization, transfer, launch, or output validation failed.
    #[cfg(all(feature = "cuda", target_os = "linux"))]
    #[error(transparent)]
    Cuda(#[from] zksm83_cuda::CudaFoldError),
}

enum NativeProverBackendState {
    Cpu,
    #[cfg(all(feature = "cuda", target_os = "linux"))]
    Cuda(zksm83_cuda::CudaFieldFolder),
}

/// Initialized execution resources for one native prover.
///
/// The CPU constructor is infallible. CUDA construction validates the selected
/// device and retains its context and kernel module across proof rounds.
pub struct NativeProverBackend {
    kind: NativeProverBackendKind,
    state: NativeProverBackendState,
}

impl NativeProverBackendKind {
    /// Returns whether this selection requests CUDA execution.
    #[must_use]
    pub const fn uses_cuda(self) -> bool {
        matches!(self, Self::Cuda { .. })
    }
}

impl Display for NativeProverBackendKind {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cpu => formatter.write_str("cpu"),
            Self::Cuda { device_ordinal } => write!(formatter, "cuda:{device_ordinal}"),
        }
    }
}

impl NativeProverBackend {
    /// Constructs the default CPU prover backend.
    #[must_use]
    pub const fn cpu() -> Self {
        Self {
            kind: NativeProverBackendKind::Cpu,
            state: NativeProverBackendState::Cpu,
        }
    }

    /// Initializes the requested prover backend.
    pub fn initialize(kind: NativeProverBackendKind) -> Result<Self, NativeProverBackendError> {
        match kind {
            NativeProverBackendKind::Cpu => Ok(Self::cpu()),
            NativeProverBackendKind::Cuda { device_ordinal } => cuda_backend(device_ordinal),
        }
    }

    /// Returns the execution selection represented by this initialized backend.
    #[must_use]
    pub const fn kind(&self) -> NativeProverBackendKind {
        self.kind
    }

    pub(crate) fn fold_binary_layer(
        &self,
        values: &mut Vec<NativeField>,
        challenge: NativeField,
    ) -> Result<(), FieldFoldError> {
        match &self.state {
            NativeProverBackendState::Cpu => {
                crate::field_fold::fold_binary_layer_cpu(values, challenge)
            }
            #[cfg(all(feature = "cuda", target_os = "linux"))]
            NativeProverBackendState::Cuda(folder) => {
                let folded = folder.fold_binary_layer(values, challenge)?;
                *values = folded;
                Ok(())
            }
        }
    }

    pub(crate) fn fold_binary_layer_from_slice(
        &self,
        values: &[NativeField],
        challenge: NativeField,
    ) -> Result<Vec<NativeField>, FieldFoldError> {
        match &self.state {
            NativeProverBackendState::Cpu => {
                crate::field_fold::fold_binary_layer_from_slice_cpu(values, challenge)
            }
            #[cfg(all(feature = "cuda", target_os = "linux"))]
            NativeProverBackendState::Cuda(folder) => folder
                .fold_binary_layer(values, challenge)
                .map_err(Into::into),
        }
    }
}

impl Default for NativeProverBackend {
    fn default() -> Self {
        Self::cpu()
    }
}

#[cfg(all(feature = "cuda", target_os = "linux"))]
fn cuda_backend(device_ordinal: usize) -> Result<NativeProverBackend, NativeProverBackendError> {
    let folder = zksm83_cuda::CudaFieldFolder::new(device_ordinal)?;
    Ok(NativeProverBackend {
        kind: NativeProverBackendKind::Cuda { device_ordinal },
        state: NativeProverBackendState::Cuda(folder),
    })
}

#[cfg(not(feature = "cuda"))]
const fn cuda_backend(
    _device_ordinal: usize,
) -> Result<NativeProverBackend, NativeProverBackendError> {
    Err(NativeProverBackendError::CudaFeatureDisabled)
}

#[cfg(all(feature = "cuda", not(target_os = "linux")))]
const fn cuda_backend(
    _device_ordinal: usize,
) -> Result<NativeProverBackend, NativeProverBackendError> {
    Err(NativeProverBackendError::CudaUnsupportedHost)
}

#[cfg(test)]
mod tests {
    #[cfg(not(all(feature = "cuda", target_os = "linux")))]
    use super::NativeProverBackendError;
    use super::{NativeProverBackend, NativeProverBackendKind};
    use crate::{FieldFoldError, NativeField};
    use akita_pcs::Ring;

    #[test]
    fn cpu_backend_is_the_default_and_never_requests_cuda() {
        let backend = NativeProverBackend::default();
        assert_eq!(backend.kind(), NativeProverBackendKind::Cpu);
        assert!(!backend.kind().uses_cuda());
        assert_eq!(backend.kind().to_string(), "cpu");
    }

    #[test]
    fn explicit_cpu_backend_preserves_canonical_fold_semantics() -> Result<(), FieldFoldError> {
        let backend = NativeProverBackend::cpu();
        let input = [1_u64, 2, 3, 4].map(NativeField::from_u64);
        let expected = [5_u64, 7].map(NativeField::from_u64);
        let from_slice = backend.fold_binary_layer_from_slice(&input, NativeField::from_u64(4))?;
        let mut in_place = input.to_vec();
        backend.fold_binary_layer(&mut in_place, NativeField::from_u64(4))?;
        assert_eq!(from_slice, expected);
        assert_eq!(in_place, expected);
        Ok(())
    }

    #[cfg(not(feature = "cuda"))]
    #[test]
    fn cuda_selection_fails_when_the_feature_is_disabled() {
        assert!(matches!(
            NativeProverBackend::initialize(NativeProverBackendKind::Cuda { device_ordinal: 3 }),
            Err(NativeProverBackendError::CudaFeatureDisabled)
        ));
    }

    #[cfg(all(feature = "cuda", not(target_os = "linux")))]
    #[test]
    fn cuda_selection_fails_on_an_unsupported_host() {
        assert!(matches!(
            NativeProverBackend::initialize(NativeProverBackendKind::Cuda { device_ordinal: 3 }),
            Err(NativeProverBackendError::CudaUnsupportedHost)
        ));
    }
}
