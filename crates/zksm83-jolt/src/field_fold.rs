use thiserror::Error;

use crate::NativeField;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum FieldFoldError {
    #[error("binary field fold requires a nontrivial even-length layer")]
    InvalidLength,
    #[error("binary field fold index arithmetic overflowed")]
    IndexOverflow,
}

pub(crate) fn fold_binary_layer(
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

#[cfg(test)]
mod tests {
    use super::{FieldFoldError, fold_binary_layer};
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
}
