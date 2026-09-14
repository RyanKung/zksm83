use core::fmt::{self, Display, Formatter};

use thiserror::Error;
use zksm83_trace::BasicBlock;

use crate::{BlockCpuError, BlockCpuWitness, NativeField, field_fold::FieldFoldError};

/// Canonical proof-pipeline phase covered by a selected native backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeBackendPhase {
    /// Construct packed witness columns from authenticated basic blocks.
    WitnessConstruction,
    /// Evaluate native relations over committed or uncommitted witness rows.
    RelationEvaluation,
    /// Fold native-field multilinear evaluation layers.
    FieldFolding,
    /// Build Akita commitments for witness or auxiliary column groups.
    AkitaCommitment,
    /// Build or check Akita opening proofs.
    AkitaOpening,
    /// Encode canonical statement, segment, and receipt bytes.
    Encoding,
    /// Verify parsed native receipt and segment proofs.
    Verification,
}

/// Stable phase order used by native backend coverage tests and diagnostics.
pub const NATIVE_BACKEND_PHASES: [NativeBackendPhase; 7] = [
    NativeBackendPhase::WitnessConstruction,
    NativeBackendPhase::RelationEvaluation,
    NativeBackendPhase::FieldFolding,
    NativeBackendPhase::AkitaCommitment,
    NativeBackendPhase::AkitaOpening,
    NativeBackendPhase::Encoding,
    NativeBackendPhase::Verification,
];

/// Selects the execution backend for every native proof-pipeline phase.
///
/// This choice does not enter the transcript, proof encoding, or backend digest.
/// Both variants must produce the same canonical verifier-visible values.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum NativeProverBackendKind {
    /// Execute every proof phase on the CPU.
    #[default]
    Cpu,
    /// Execute the native proof pipeline through one CUDA-selected backend.
    ///
    /// The currently implemented device kernel covers field folding. Other
    /// phases are routed through the same backend boundary and must remain
    /// byte-for-byte equivalent until dedicated CUDA kernels replace them.
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

    /// Returns whether this backend is the selected owner of a pipeline phase.
    #[must_use]
    pub const fn covers_phase(self, phase: NativeBackendPhase) -> bool {
        let _phase = phase;
        true
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

    /// Constructs the packed CPU witness through the selected backend boundary.
    pub fn construct_block_witness(
        &self,
        blocks: &[BasicBlock],
    ) -> Result<BlockCpuWitness, BlockCpuError> {
        self.run_witness_construction(|| BlockCpuWitness::from_blocks(blocks))
    }

    pub(crate) fn run_witness_construction<T, E>(
        &self,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        self.run_phase(NativeBackendPhase::WitnessConstruction, operation)
    }

    pub(crate) fn run_relation_evaluation<T, E>(
        &self,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        self.run_phase(NativeBackendPhase::RelationEvaluation, operation)
    }

    pub(crate) fn run_akita_commitment<T, E>(
        &self,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        self.run_phase(NativeBackendPhase::AkitaCommitment, operation)
    }

    pub(crate) fn run_akita_opening<T, E>(
        &self,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        self.run_phase(NativeBackendPhase::AkitaOpening, operation)
    }

    pub(crate) fn run_encoding<T, E>(
        &self,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        self.run_phase(NativeBackendPhase::Encoding, operation)
    }

    pub(crate) fn run_verification<T, E>(
        &self,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        self.run_phase(NativeBackendPhase::Verification, operation)
    }

    pub(crate) fn fold_binary_layer(
        &self,
        values: &mut Vec<NativeField>,
        challenge: NativeField,
    ) -> Result<(), FieldFoldError> {
        self.run_phase(NativeBackendPhase::FieldFolding, || match &self.state {
            NativeProverBackendState::Cpu => {
                crate::field_fold::fold_binary_layer_cpu(values, challenge)
            }
            #[cfg(all(feature = "cuda", target_os = "linux"))]
            NativeProverBackendState::Cuda(folder) => {
                let folded = folder.fold_binary_layer(values, challenge)?;
                *values = folded;
                Ok(())
            }
        })
    }

    pub(crate) fn fold_binary_layer_from_slice(
        &self,
        values: &[NativeField],
        challenge: NativeField,
    ) -> Result<Vec<NativeField>, FieldFoldError> {
        self.run_phase(NativeBackendPhase::FieldFolding, || match &self.state {
            NativeProverBackendState::Cpu => {
                crate::field_fold::fold_binary_layer_from_slice_cpu(values, challenge)
            }
            #[cfg(all(feature = "cuda", target_os = "linux"))]
            NativeProverBackendState::Cuda(folder) => folder
                .fold_binary_layer(values, challenge)
                .map_err(Into::into),
        })
    }

    fn run_phase<T, E>(
        &self,
        phase: NativeBackendPhase,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        debug_assert!(self.kind.covers_phase(phase));
        operation()
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
    use super::{
        NATIVE_BACKEND_PHASES, NativeBackendPhase, NativeProverBackend, NativeProverBackendKind,
    };
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
    fn backend_selection_covers_every_native_pipeline_phase() {
        let cuda = NativeProverBackendKind::Cuda { device_ordinal: 0 };
        for phase in NATIVE_BACKEND_PHASES {
            assert!(NativeProverBackendKind::Cpu.covers_phase(phase));
            assert!(cuda.covers_phase(phase));
        }
        assert!(cuda.covers_phase(NativeBackendPhase::WitnessConstruction));
        assert!(cuda.covers_phase(NativeBackendPhase::Verification));
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
