use thiserror::Error;

use crate::NativeField;

#[derive(Debug, Error)]
/// Failure to fold a native-field evaluation layer on a selected prover backend.
pub enum FieldFoldError {
    /// A binary fold requires at least one complete pair and no trailing value.
    #[error("binary field fold requires a nontrivial even-length layer")]
    InvalidLength,
    /// Checked pair-index arithmetic overflowed.
    #[error("binary field fold index arithmetic overflowed")]
    IndexOverflow,
    /// CUDA initialization, transfer, launch, or output validation failed.
    #[cfg(all(feature = "cuda", target_os = "linux"))]
    #[error(transparent)]
    Cuda(#[from] zksm83_cuda::CudaFoldError),
}

pub(crate) fn fold_binary_layer(
    values: &mut Vec<NativeField>,
    challenge: NativeField,
) -> Result<(), FieldFoldError> {
    fold_binary_layer_cpu(values, challenge)
}

pub(crate) fn fold_binary_layer_cpu(
    values: &mut Vec<NativeField>,
    challenge: NativeField,
) -> Result<(), FieldFoldError> {
    if values.len() < 2 || !values.len().is_multiple_of(2) {
        return Err(FieldFoldError::InvalidLength);
    }
    let folded_len = values.len() / 2;
    for pair_index in 0..folded_len {
        let low_index = pair_index
            .checked_mul(2)
            .ok_or(FieldFoldError::IndexOverflow)?;
        let high_index = low_index
            .checked_add(1)
            .ok_or(FieldFoldError::IndexOverflow)?;
        let low = values
            .get(low_index)
            .copied()
            .ok_or(FieldFoldError::InvalidLength)?;
        let high = values
            .get(high_index)
            .copied()
            .ok_or(FieldFoldError::InvalidLength)?;
        let output = values
            .get_mut(pair_index)
            .ok_or(FieldFoldError::InvalidLength)?;
        *output = low + challenge * (high - low);
    }
    values.truncate(folded_len);
    Ok(())
}

pub(crate) fn fold_binary_layer_from_slice(
    values: &[NativeField],
    challenge: NativeField,
) -> Result<Vec<NativeField>, FieldFoldError> {
    fold_binary_layer_from_slice_cpu(values, challenge)
}

pub(crate) fn fold_binary_layer_from_slice_cpu(
    values: &[NativeField],
    challenge: NativeField,
) -> Result<Vec<NativeField>, FieldFoldError> {
    if values.len() < 2 || !values.len().is_multiple_of(2) {
        return Err(FieldFoldError::InvalidLength);
    }
    let mut folded = Vec::with_capacity(values.len() / 2);
    for pair in values.chunks_exact(2) {
        let low = pair.first().copied().ok_or(FieldFoldError::InvalidLength)?;
        let high = pair.get(1).copied().ok_or(FieldFoldError::InvalidLength)?;
        folded.push(low + challenge * (high - low));
    }
    Ok(folded)
}

pub(crate) fn evaluate_mle(
    values: &[NativeField],
    point: &[NativeField],
) -> Result<NativeField, FieldFoldError> {
    let shift = u32::try_from(point.len()).map_err(|_| FieldFoldError::IndexOverflow)?;
    let expected = 1_usize
        .checked_shl(shift)
        .ok_or(FieldFoldError::IndexOverflow)?;
    if values.len() != expected {
        return Err(FieldFoldError::InvalidLength);
    }
    let Some((first, remaining)) = point.split_first() else {
        return values.first().copied().ok_or(FieldFoldError::InvalidLength);
    };
    let mut folded = fold_binary_layer_from_slice(values, *first)?;
    for challenge in remaining {
        fold_binary_layer(&mut folded, *challenge)?;
    }
    folded.first().copied().ok_or(FieldFoldError::InvalidLength)
}

#[cfg(test)]
mod tests {
    use super::{FieldFoldError, fold_binary_layer, fold_binary_layer_from_slice};
    use crate::NativeField;
    use akita_pcs::Ring;

    #[test]
    fn binary_fold_preserves_affine_values_without_reallocation() -> Result<(), FieldFoldError> {
        let mut values = (0..8).map(NativeField::from_u64).collect::<Vec<_>>();
        let allocation = values.as_ptr();
        let capacity = values.capacity();
        fold_binary_layer(&mut values, NativeField::from_u64(3))?;
        assert_eq!(
            values,
            [3, 5, 7, 9]
                .into_iter()
                .map(NativeField::from_u64)
                .collect::<Vec<_>>()
        );
        fold_binary_layer(&mut values, NativeField::from_u64(2))?;
        assert_eq!(
            values,
            [7, 11]
                .into_iter()
                .map(NativeField::from_u64)
                .collect::<Vec<_>>()
        );
        assert_eq!(values.as_ptr(), allocation);
        assert_eq!(values.capacity(), capacity);
        Ok(())
    }

    #[test]
    fn binary_fold_rejects_invalid_lengths_without_mutation() {
        for mut values in [
            vec![],
            vec![NativeField::from_u64(1)],
            vec![
                NativeField::from_u64(1),
                NativeField::from_u64(2),
                NativeField::from_u64(3),
            ],
        ] {
            let original = values.clone();
            assert!(matches!(
                fold_binary_layer(&mut values, NativeField::from_u64(2)),
                Err(FieldFoldError::InvalidLength)
            ));
            assert_eq!(values, original);
        }
    }

    #[test]
    fn borrowed_binary_fold_allocates_only_the_folded_layer() -> Result<(), FieldFoldError> {
        let values = (0..8).map(NativeField::from_u64).collect::<Vec<_>>();
        let folded = fold_binary_layer_from_slice(&values, NativeField::from_u64(3))?;
        assert_eq!(folded.len(), values.len() / 2);
        assert_eq!(folded.capacity(), values.len() / 2);
        assert_eq!(
            folded,
            [3, 5, 7, 9]
                .into_iter()
                .map(NativeField::from_u64)
                .collect::<Vec<_>>()
        );
        Ok(())
    }
}
