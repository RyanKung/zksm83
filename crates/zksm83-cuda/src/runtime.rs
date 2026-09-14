use std::sync::{Arc, Mutex};

use cuda_core::{CudaContext, DeviceBuffer, LaunchConfig1D};
use cuda_device::{DisjointSlice, cuda_module, kernel, launch_bounds, launch_contract, thread};
use jolt_field::Prime128OffsetA7F7;

use crate::{ComputeCapability, CudaFoldError, FieldElement, KernelTarget};

const BLOCK_SIZE: u32 = 256;

pub(crate) struct CudaFieldFolder {
    context: Arc<CudaContext>,
    module: kernels::LoadedModule,
    execution_lock: Mutex<()>,
}

#[cuda_module]
mod kernels {
    use super::*;

    #[kernel]
    #[launch_bounds(256)]
    #[launch_contract(
        domain = 1,
        block = (256, 1, 1),
        dynamic_shared = 0,
        requires = (input.len() >= output.len() * 2,),
    )]
    pub fn fold_binary_layer(
        input: &[[u64; 2]],
        challenge: [u64; 2],
        mut output: DisjointSlice<[u64; 2]>,
    ) {
        let output_index = thread::index_1d();
        let pair_index = output_index.get();
        let Some(low_index) = pair_index.checked_mul(2) else {
            return;
        };
        let Some(high_index) = low_index.checked_add(1) else {
            return;
        };
        let Some(low) = input.get(low_index).copied() else {
            return;
        };
        let Some(high) = input.get(high_index).copied() else {
            return;
        };
        let Some(destination) = output.get_mut(output_index) else {
            return;
        };
        let [low_low, low_high] = low;
        let [high_low, high_high] = high;
        let [challenge_low, challenge_high] = challenge;
        let Some(low) = FieldElement::from_canonical_limbs(low_low, low_high) else {
            return;
        };
        let Some(high) = FieldElement::from_canonical_limbs(high_low, high_high) else {
            return;
        };
        let Some(challenge) = FieldElement::from_canonical_limbs(challenge_low, challenge_high)
        else {
            return;
        };
        *destination = FieldElement::fold(low, high, challenge).limbs();
    }
}

impl CudaFieldFolder {
    pub(crate) fn new(device_ordinal: usize) -> Result<Self, CudaFoldError> {
        let context = CudaContext::new(device_ordinal)?;
        let (major, minor) = context.compute_capability()?;
        let capability = ComputeCapability::from_driver(major, minor)?;
        let _target = KernelTarget::for_device(capability)?;
        // SAFETY: this crate is the sole owner of the embedded module generated
        // from `kernels`; no second module supplies conflicting entry definitions.
        let module = unsafe { kernels::load(&context)? };
        Ok(Self {
            context,
            module,
            execution_lock: Mutex::new(()),
        })
    }

    pub(crate) fn fold_binary_layer(
        &self,
        values: &[Prime128OffsetA7F7],
        challenge: Prime128OffsetA7F7,
    ) -> Result<Vec<Prime128OffsetA7F7>, CudaFoldError> {
        validate_fold_length(values.len())?;
        let _execution_guard = self
            .execution_lock
            .lock()
            .map_err(|_| CudaFoldError::RuntimeStatePoisoned)?;
        self.context.bind_to_thread()?;
        let folded_length = values.len() / 2;
        let folded_length_u32 =
            u32::try_from(folded_length).map_err(|_| CudaFoldError::LengthOverflow {
                length: folded_length,
            })?;
        let stream = self.context.default_stream();
        let input = values
            .iter()
            .copied()
            .map(FieldElement::from_native)
            .map(FieldElement::limbs)
            .collect::<Vec<_>>();
        let input_device = DeviceBuffer::from_host(&stream, &input)?;
        let mut output_device = DeviceBuffer::<[u64; 2]>::zeroed(&stream, folded_length)?;
        let grid_size = folded_length_u32.div_ceil(BLOCK_SIZE);
        let launch = self
            .module
            .prepare_fold_binary_layer(LaunchConfig1D::new(grid_size, BLOCK_SIZE, 0))?;
        self.module.fold_binary_layer(
            &stream,
            &launch,
            &input_device,
            FieldElement::from_native(challenge).limbs(),
            &mut output_device,
        )?;
        output_device
            .to_host_vec(&stream)?
            .into_iter()
            .map(|[low, high]| {
                FieldElement::from_canonical_limbs(low, high)
                    .and_then(FieldElement::to_native)
                    .ok_or(CudaFoldError::NonCanonicalOutput)
            })
            .collect()
    }
}

fn validate_fold_length(length: usize) -> Result<(), CudaFoldError> {
    if length < 2 || !length.is_multiple_of(2) {
        return Err(CudaFoldError::InvalidLength { length });
    }
    Ok(())
}
