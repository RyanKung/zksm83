use akita_pcs::Ring;
use rayon::prelude::*;

use super::{NativeField, ProductSumcheckError};

const PARALLEL_MIN_ENTRIES: usize = 256;

pub(super) struct SparseTable {
    entries: Vec<(usize, NativeField)>,
    length: usize,
}

impl SparseTable {
    pub(super) fn new(
        entries: Vec<(usize, NativeField)>,
        length: usize,
    ) -> Result<Self, ProductSumcheckError> {
        if length == 0 {
            return Err(ProductSumcheckError::EmptyTable);
        }
        if !length.is_power_of_two() {
            return Err(ProductSumcheckError::NonPowerOfTwo);
        }
        if entries.iter().any(|(index, _)| *index >= length) {
            return Err(ProductSumcheckError::LengthMismatch);
        }
        Ok(Self {
            entries: normalize(entries),
            length,
        })
    }

    pub(super) const fn length(&self) -> usize {
        self.length
    }

    pub(super) fn inner_product(
        &self,
        right: &[NativeField],
    ) -> Result<NativeField, ProductSumcheckError> {
        self.validate_right(right)?;
        self.entries
            .par_iter()
            .with_min_len(PARALLEL_MIN_ENTRIES)
            .try_fold(
                || NativeField::from_u64(0),
                |sum, (index, value)| {
                    Ok(sum
                        + *value
                            * right
                                .get(*index)
                                .copied()
                                .ok_or(ProductSumcheckError::LengthMismatch)?)
                },
            )
            .try_reduce(|| NativeField::from_u64(0), |left, right| Ok(left + right))
    }

    pub(super) fn round(
        &self,
        right: &[NativeField],
    ) -> Result<[NativeField; 3], ProductSumcheckError> {
        self.validate_right(right)?;
        if self.length == 1 {
            return Err(ProductSumcheckError::FoldingShape);
        }
        let points = [
            NativeField::from_u64(0),
            NativeField::from_u64(1),
            NativeField::from_u64(2),
        ];
        self.entries
            .par_iter()
            .with_min_len(PARALLEL_MIN_ENTRIES)
            .map(|(index, value)| sparse_entry_round(*index, *value, right, points))
            .try_reduce(
                || [NativeField::from_u64(0); 3],
                |mut left, right| {
                    for (target, value) in left.iter_mut().zip(right) {
                        *target += value;
                    }
                    Ok(left)
                },
            )
    }

    pub(super) fn fold(&mut self, challenge: NativeField) -> Result<(), ProductSumcheckError> {
        if self.length <= 1 || !self.length.is_power_of_two() {
            return Err(ProductSumcheckError::FoldingShape);
        }
        let one_minus = NativeField::from_u64(1) - challenge;
        let folded = self
            .entries
            .drain(..)
            .map(|(index, value)| {
                let scale = if index.is_multiple_of(2) {
                    one_minus
                } else {
                    challenge
                };
                (index / 2, scale * value)
            })
            .collect();
        self.entries = merge_sorted(folded);
        self.length /= 2;
        Ok(())
    }

    pub(super) fn final_value(&self) -> Result<NativeField, ProductSumcheckError> {
        if self.length != 1 {
            return Err(ProductSumcheckError::FoldingShape);
        }
        match self.entries.as_slice() {
            [] => Ok(NativeField::from_u64(0)),
            [(0, value)] => Ok(*value),
            _ => Err(ProductSumcheckError::FoldingShape),
        }
    }

    fn validate_right(&self, right: &[NativeField]) -> Result<(), ProductSumcheckError> {
        if right.len() != self.length {
            return Err(ProductSumcheckError::LengthMismatch);
        }
        Ok(())
    }
}

fn sparse_entry_round(
    index: usize,
    value: NativeField,
    right: &[NativeField],
    points: [NativeField; 3],
) -> Result<[NativeField; 3], ProductSumcheckError> {
    let pair_start = (index / 2)
        .checked_mul(2)
        .ok_or(ProductSumcheckError::FoldingShape)?;
    let right_zero = right
        .get(pair_start)
        .copied()
        .ok_or(ProductSumcheckError::FoldingShape)?;
    let right_one = right
        .get(
            pair_start
                .checked_add(1)
                .ok_or(ProductSumcheckError::FoldingShape)?,
        )
        .copied()
        .ok_or(ProductSumcheckError::FoldingShape)?;
    Ok(points.map(|point| {
        let left = if index.is_multiple_of(2) {
            value * (NativeField::from_u64(1) - point)
        } else {
            value * point
        };
        left * (right_zero + point * (right_one - right_zero))
    }))
}

fn normalize(mut entries: Vec<(usize, NativeField)>) -> Vec<(usize, NativeField)> {
    entries.sort_unstable_by_key(|(index, _)| *index);
    merge_sorted(entries)
}

fn merge_sorted(entries: Vec<(usize, NativeField)>) -> Vec<(usize, NativeField)> {
    let mut normalized: Vec<(usize, NativeField)> = Vec::with_capacity(entries.len());
    for (index, value) in entries {
        match normalized.last_mut() {
            Some((last_index, last_value)) if *last_index == index => *last_value += value,
            _ => normalized.push((index, value)),
        }
    }
    let zero = NativeField::from_u64(0);
    normalized.retain(|(_, value)| *value != zero);
    normalized
}
