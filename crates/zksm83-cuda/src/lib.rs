//! Experimental CUDA primitives for the native SM83 prover.
//!
//! This crate does not change the proof protocol or verifier. Its first slice
//! provides a portable `sm_70+` field-fold kernel and an exact CPU oracle. The
//! CUDA runtime probes the selected device and retains its actual compute
//! capability instead of fixing the implementation to one GPU generation.

#![deny(missing_docs)]
#![deny(unsafe_code)]

mod capability;
mod field;
#[cfg(all(feature = "cuda", target_os = "linux"))]
#[allow(unsafe_code)]
mod runtime;

pub use capability::{
    CapabilityError, ComputeCapability, FieldKernelVariant, KernelTarget,
    MINIMUM_COMPUTE_CAPABILITY,
};
pub use field::FieldElement;
use jolt_field::Prime128OffsetA7F7;
use thiserror::Error;

/// A persistent CUDA field-fold execution context.
///
/// Construction probes the selected device once and loads the generated
/// kernel module. Each fold still owns its input and output buffers, while the
/// CUDA context and module remain alive across proof rounds.
pub struct CudaFieldFolder {
    #[cfg(all(feature = "cuda", target_os = "linux"))]
    inner: runtime::CudaFieldFolder,
    #[cfg(not(all(feature = "cuda", target_os = "linux")))]
    unavailable: core::marker::PhantomData<()>,
}

/// Why the CUDA runtime cannot be used by this build.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CudaUnavailable {
    /// The crate was compiled without its `cuda` feature.
    #[error("zksm83-cuda was built without the `cuda` feature")]
    FeatureDisabled,
    /// cuda-oxide currently supports Linux hosts only.
    #[error("zksm83-cuda requires a Linux host")]
    UnsupportedHost,
}

/// Failure while executing the CUDA field-fold primitive.
#[derive(Debug, Error)]
pub enum CudaFoldError {
    /// A binary fold needs at least one complete pair and no trailing value.
    #[error("CUDA binary field fold requires a nontrivial even length, received {length}")]
    InvalidLength {
        /// Number of input field elements.
        length: usize,
    },
    /// The folded layer cannot be represented by the CUDA launch index type.
    #[error("CUDA binary field fold output length {length} exceeds u32")]
    LengthOverflow {
        /// Number of output field elements.
        length: usize,
    },
    /// Device capability discovery or validation failed.
    #[error(transparent)]
    Capability(#[from] CapabilityError),
    /// The CUDA kernel returned a non-canonical field representation.
    #[error("CUDA binary field fold returned a non-canonical field element")]
    NonCanonicalOutput,
    /// CUDA support is absent from this build or host.
    #[error(transparent)]
    Unavailable(#[from] CudaUnavailable),
    /// The CUDA driver rejected a context, allocation, transfer, or launch.
    #[cfg(all(feature = "cuda", target_os = "linux"))]
    #[error(transparent)]
    Driver(#[from] cuda_core::DriverError),
    /// The embedded cuda-oxide module could not be loaded.
    #[cfg(all(feature = "cuda", target_os = "linux"))]
    #[error(transparent)]
    Module(#[from] cuda_host::EmbeddedModuleError),
    /// The requested launch does not satisfy the kernel contract.
    #[cfg(all(feature = "cuda", target_os = "linux"))]
    #[error(transparent)]
    LaunchContract(#[from] cuda_core::LaunchContractError),
    /// Concurrent execution state is unavailable after a host panic.
    #[cfg(all(feature = "cuda", target_os = "linux"))]
    #[error("CUDA field-fold execution state was poisoned")]
    RuntimeStatePoisoned,
}

impl CudaFieldFolder {
    /// Initializes the selected CUDA device and validates its compute capability.
    pub fn new(device_ordinal: usize) -> Result<Self, CudaFoldError> {
        #[cfg(all(feature = "cuda", target_os = "linux"))]
        {
            runtime::CudaFieldFolder::new(device_ordinal).map(|inner| Self { inner })
        }
        #[cfg(not(all(feature = "cuda", target_os = "linux")))]
        {
            let _device_ordinal = device_ordinal;
            Err(cuda_unavailable().into())
        }
    }

    /// Folds one native-field layer on this CUDA device.
    pub fn fold_binary_layer(
        &self,
        values: &[Prime128OffsetA7F7],
        challenge: Prime128OffsetA7F7,
    ) -> Result<Vec<Prime128OffsetA7F7>, CudaFoldError> {
        #[cfg(all(feature = "cuda", target_os = "linux"))]
        {
            self.inner.fold_binary_layer(values, challenge)
        }
        #[cfg(not(all(feature = "cuda", target_os = "linux")))]
        {
            let _request = (&self.unavailable, values, challenge);
            Err(cuda_unavailable().into())
        }
    }
}

/// Folds one native-field layer on the selected CUDA device.
///
/// The operation is explicit: it never falls back to the CPU. Builds without
/// CUDA support return [`CudaFoldError::Unavailable`].
pub fn fold_binary_layer_cuda(
    device_ordinal: usize,
    values: &[Prime128OffsetA7F7],
    challenge: Prime128OffsetA7F7,
) -> Result<Vec<Prime128OffsetA7F7>, CudaFoldError> {
    CudaFieldFolder::new(device_ordinal)?.fold_binary_layer(values, challenge)
}

#[cfg(not(all(feature = "cuda", target_os = "linux")))]
const fn cuda_unavailable() -> CudaUnavailable {
    #[cfg(not(feature = "cuda"))]
    {
        CudaUnavailable::FeatureDisabled
    }
    #[cfg(all(feature = "cuda", not(target_os = "linux")))]
    {
        CudaUnavailable::UnsupportedHost
    }
}

#[cfg(all(test, not(all(feature = "cuda", target_os = "linux"))))]
mod tests {
    use super::{CudaFoldError, cuda_unavailable, fold_binary_layer_cuda};
    use jolt_field::{Prime128OffsetA7F7, Ring};

    #[test]
    fn explicit_cuda_request_does_not_fall_back_to_cpu() {
        let values = [
            Prime128OffsetA7F7::from_u64(1),
            Prime128OffsetA7F7::from_u64(2),
        ];
        assert!(matches!(
            fold_binary_layer_cuda(0, &values, Prime128OffsetA7F7::from_u64(3)),
            Err(CudaFoldError::Unavailable(reason)) if reason == cuda_unavailable()
        ));
    }
}
