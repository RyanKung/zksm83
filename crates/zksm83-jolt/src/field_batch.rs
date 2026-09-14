//! Bounded batch inversion for trace-derived field denominators.

use jolt_field::{Field, Ring};
use rayon::prelude::*;
use thiserror::Error;

use crate::NativeField;

/// Number of trace rows processed by one independent batch inversion.
pub(crate) const FIELD_BATCH_ROW_CHUNK: usize = 4_096;

/// A selected reciprocal request, overwritten with `scale / denominator`.
#[derive(Clone, Copy)]
pub(crate) struct SelectedDenominator {
    scale: NativeField,
    denominator: NativeField,
}

impl SelectedDenominator {
    /// Creates one reciprocal request. A zero scale suppresses inversion.
    pub(crate) const fn new(scale: NativeField, denominator: NativeField) -> Self {
        Self { scale, denominator }
    }

    /// Returns the selected reciprocal after batch inversion.
    pub(crate) const fn value(self) -> NativeField {
        self.denominator
    }
}

/// Failure while constructing a bounded reciprocal batch.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum FieldBatchError {
    /// The number of scalar requests overflowed the host address space.
    #[error("field batch inversion shape overflowed")]
    Shape,
    /// A selected denominator was zero.
    #[error("field batch inversion encountered a selected zero denominator")]
    ZeroDenominator,
}

/// Applies Montgomery batch inversion to a row-major chunk in place.
///
/// Each chunk uses one field inversion and a linear number of multiplications.
/// Entries with a zero scale are mapped to zero without entering the product.
pub(crate) fn batch_invert_selected<const N: usize>(
    rows: &mut [[SelectedDenominator; N]],
) -> Result<(), FieldBatchError> {
    let entry_count = rows.len().checked_mul(N).ok_or(FieldBatchError::Shape)?;
    let zero = NativeField::from_u64(0);
    let mut prefix_products = Vec::with_capacity(entry_count);
    let mut product = NativeField::from_u64(1);
    for entry in rows.iter().flat_map(|row| row.iter()) {
        prefix_products.push(product);
        if entry.scale != zero {
            if entry.denominator == zero {
                return Err(FieldBatchError::ZeroDenominator);
            }
            product *= entry.denominator;
        }
    }
    let mut product_inverse = product.inverse().ok_or(FieldBatchError::ZeroDenominator)?;
    let mut prefixes = prefix_products.into_iter().rev();
    for entry in rows.iter_mut().rev().flat_map(|row| row.iter_mut().rev()) {
        let prefix = prefixes.next().ok_or(FieldBatchError::Shape)?;
        if entry.scale == zero {
            entry.denominator = zero;
        } else {
            let denominator = entry.denominator;
            entry.denominator = entry.scale * prefix * product_inverse;
            product_inverse *= denominator;
        }
    }
    if prefixes.next().is_some() {
        return Err(FieldBatchError::Shape);
    }
    Ok(())
}

/// Builds selected reciprocal rows in bounded chunks and emits column-major limbs.
///
/// Only the returned columns scale with `row_count`; denominator, prefix, and
/// encoded-row storage are bounded by [`FIELD_BATCH_ROW_CHUNK`]. The payload is
/// carried from row construction to encoding without entering the inversion.
pub(crate) fn selected_inverse_columns<const N: usize, const M: usize, T, E>(
    row_count: usize,
    prepare: impl Fn(usize) -> Result<([SelectedDenominator; N], T), E> + Sync,
    encode: impl Fn([SelectedDenominator; N], T) -> Result<[u64; M], E> + Sync,
    map_batch_error: impl Fn(FieldBatchError) -> E,
) -> Result<Vec<Vec<u64>>, E>
where
    T: Send,
    E: Send,
{
    let mut columns = (0..M)
        .map(|_| Vec::with_capacity(row_count))
        .collect::<Vec<_>>();
    let mut start = 0_usize;
    while start < row_count {
        let end = start.saturating_add(FIELD_BATCH_ROW_CHUNK).min(row_count);
        let prepared = (start..end)
            .into_par_iter()
            .map(&prepare)
            .collect::<Result<Vec<_>, _>>()?;
        let (mut rows, payloads): (Vec<_>, Vec<_>) = prepared.into_iter().unzip();
        batch_invert_selected(&mut rows).map_err(&map_batch_error)?;
        let encoded = rows
            .into_par_iter()
            .zip(payloads.into_par_iter())
            .map(|(row, payload)| encode(row, payload))
            .collect::<Result<Vec<_>, _>>()?;
        for row in encoded {
            for (column, value) in columns.iter_mut().zip(row) {
                column.push(value);
            }
        }
        start = end;
    }
    Ok(columns)
}
