use std::sync::Arc;

use akita_pcs::Ring;

use super::{NativeField, ProductSumcheckError};
use crate::NativeProverBackend;

#[derive(Clone)]
pub(crate) enum FactorSource<'a> {
    Borrowed(&'a [NativeField]),
    Shared(Arc<[NativeField]>),
}

impl FactorSource<'_> {
    fn values(&self) -> &[NativeField] {
        match self {
            Self::Borrowed(values) => values,
            Self::Shared(values) => values,
        }
    }
}

/// Compact first-round factor that avoids materializing derived evaluation tables.
#[derive(Clone)]
pub(crate) enum SumcheckFactor<'a> {
    /// An existing multilinear evaluation table, optionally shared by many terms.
    Values(FactorSource<'a>),
    /// One affine transformation of an existing multilinear table.
    Affine {
        source: FactorSource<'a>,
        scale: NativeField,
        offset: NativeField,
    },
    /// One constant multilinear polynomial.
    Constant { value: NativeField, len: usize },
    /// A constant plus scaled existing tables and an optional scaled row index.
    LinearCombination {
        sources: Vec<(FactorSource<'a>, NativeField)>,
        index_scale: NativeField,
        offset: NativeField,
        len: usize,
    },
}

pub(super) enum FoldedFactor {
    Table(Vec<NativeField>),
    Constant { value: NativeField, len: usize },
}

pub(super) trait SumcheckTable: Sync {
    fn table_len(&self) -> usize;
    fn table_value(&self, index: usize) -> Result<NativeField, ProductSumcheckError>;
}

impl<'a> SumcheckFactor<'a> {
    pub(crate) const fn borrowed(values: &'a [NativeField]) -> Self {
        Self::Values(FactorSource::Borrowed(values))
    }

    pub(crate) fn shared(values: Arc<[NativeField]>) -> Self {
        Self::Values(FactorSource::Shared(values))
    }

    pub(crate) fn scaled(values: &'a [NativeField], scale: NativeField) -> Self {
        Self::Affine {
            source: FactorSource::Borrowed(values),
            scale,
            offset: NativeField::from_u64(0),
        }
    }

    pub(crate) const fn affine(
        values: &'a [NativeField],
        scale: NativeField,
        offset: NativeField,
    ) -> Self {
        Self::Affine {
            source: FactorSource::Borrowed(values),
            scale,
            offset,
        }
    }

    pub(crate) const fn constant(value: NativeField, len: usize) -> Self {
        Self::Constant { value, len }
    }

    pub(crate) fn linear_combination(
        sources: Vec<(&'a [NativeField], NativeField)>,
        index_scale: NativeField,
        offset: NativeField,
        len: usize,
    ) -> Self {
        Self::LinearCombination {
            sources: sources
                .into_iter()
                .map(|(values, scale)| (FactorSource::Borrowed(values), scale))
                .collect(),
            index_scale,
            offset,
            len,
        }
    }

    pub(super) fn same_table(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Values(left), Self::Values(right)) => {
                let left = left.values();
                let right = right.values();
                left.len() == right.len() && std::ptr::eq(left.as_ptr(), right.as_ptr())
            }
            _ => false,
        }
    }

    pub(super) fn fold(self, challenge: NativeField) -> Result<FoldedFactor, ProductSumcheckError> {
        match self {
            Self::Constant { value, len } => {
                if len < 2 || !len.is_multiple_of(2) {
                    return Err(ProductSumcheckError::FoldingShape);
                }
                Ok(FoldedFactor::Constant {
                    value,
                    len: len / 2,
                })
            }
            factor => {
                let len = factor.table_len();
                if len < 2 || !len.is_multiple_of(2) {
                    return Err(ProductSumcheckError::FoldingShape);
                }
                let mut values = Vec::with_capacity(len / 2);
                for pair in 0..len / 2 {
                    let low_index = pair
                        .checked_mul(2)
                        .ok_or(ProductSumcheckError::FoldingShape)?;
                    let high_index = low_index
                        .checked_add(1)
                        .ok_or(ProductSumcheckError::FoldingShape)?;
                    let low = factor.table_value(low_index)?;
                    let high = factor.table_value(high_index)?;
                    values.push(low + challenge * (high - low));
                }
                Ok(FoldedFactor::Table(values))
            }
        }
    }
}

impl SumcheckTable for SumcheckFactor<'_> {
    fn table_len(&self) -> usize {
        match self {
            Self::Values(source) | Self::Affine { source, .. } => source.values().len(),
            Self::Constant { len, .. } | Self::LinearCombination { len, .. } => *len,
        }
    }

    fn table_value(&self, index: usize) -> Result<NativeField, ProductSumcheckError> {
        match self {
            Self::Values(source) => value_at(source.values(), index),
            Self::Affine {
                source,
                scale,
                offset,
            } => Ok(*scale * value_at(source.values(), index)? + *offset),
            Self::Constant { value, len } => {
                if index >= *len {
                    return Err(ProductSumcheckError::FoldingShape);
                }
                Ok(*value)
            }
            Self::LinearCombination {
                sources,
                index_scale,
                offset,
                len,
            } => {
                if index >= *len {
                    return Err(ProductSumcheckError::FoldingShape);
                }
                let index_field = NativeField::from_u64(
                    u64::try_from(index).map_err(|_| ProductSumcheckError::ProofShape)?,
                );
                sources.iter().try_fold(
                    *offset + *index_scale * index_field,
                    |value, (source, scale)| Ok(value + *scale * value_at(source.values(), index)?),
                )
            }
        }
    }
}

impl SumcheckTable for FoldedFactor {
    fn table_len(&self) -> usize {
        match self {
            Self::Table(values) => values.len(),
            Self::Constant { len, .. } => *len,
        }
    }

    fn table_value(&self, index: usize) -> Result<NativeField, ProductSumcheckError> {
        match self {
            Self::Table(values) => value_at(values, index),
            Self::Constant { value, len } => {
                if index >= *len {
                    return Err(ProductSumcheckError::FoldingShape);
                }
                Ok(*value)
            }
        }
    }
}

impl FoldedFactor {
    pub(super) fn fold(
        &mut self,
        challenge: NativeField,
        backend: &NativeProverBackend,
    ) -> Result<(), ProductSumcheckError> {
        match self {
            Self::Table(values) => super::fold(values, challenge, backend),
            Self::Constant { len, .. } => {
                if *len < 2 || !len.is_multiple_of(2) {
                    return Err(ProductSumcheckError::FoldingShape);
                }
                *len /= 2;
                Ok(())
            }
        }
    }
}

fn value_at(values: &[NativeField], index: usize) -> Result<NativeField, ProductSumcheckError> {
    values
        .get(index)
        .copied()
        .ok_or(ProductSumcheckError::FoldingShape)
}
