use akita_pcs::Ring;
use rayon::prelude::*;

use super::{
    NativeField, ProductSumcheckError, SumcheckTable, pair_values, usize_to_field,
    validate_factors, validate_tables, validate_terms,
};

const PARALLEL_MIN_ROWS: usize = 256;

pub(super) fn inner_product(
    left: &[NativeField],
    right: &[NativeField],
) -> Result<NativeField, ProductSumcheckError> {
    validate_tables(left, right)?;
    Ok(left
        .par_iter()
        .with_min_len(PARALLEL_MIN_ROWS)
        .copied()
        .zip(right.par_iter().with_min_len(PARALLEL_MIN_ROWS).copied())
        .map(|(left, right)| left * right)
        .reduce(|| NativeField::from_u64(0), |sum, value| sum + value))
}

pub(super) fn sum_of_products<T: SumcheckTable>(
    factors: &[T],
) -> Result<NativeField, ProductSumcheckError> {
    validate_factors(factors)?;
    let length = factors
        .first()
        .map(SumcheckTable::table_len)
        .ok_or(ProductSumcheckError::EmptyFactors)?;
    (0..length)
        .into_par_iter()
        .with_min_len(PARALLEL_MIN_ROWS)
        .try_fold(
            || NativeField::from_u64(0),
            |sum, index| Ok(sum + product_at(factors, index)?),
        )
        .try_reduce(|| NativeField::from_u64(0), |left, right| Ok(left + right))
}

pub(super) fn shared_sum_of_term_products<T: SumcheckTable>(
    shared: &T,
    terms: &[Vec<T>],
) -> Result<NativeField, ProductSumcheckError> {
    let (_, _, length) = validate_terms(terms)?;
    if shared.table_len() != length {
        return Err(ProductSumcheckError::LengthMismatch);
    }
    (0..length)
        .into_par_iter()
        .with_min_len(PARALLEL_MIN_ROWS)
        .try_fold(
            || NativeField::from_u64(0),
            |sum, index| {
                let term_sum =
                    terms
                        .iter()
                        .try_fold(NativeField::from_u64(0), |term_sum, factors| {
                            Ok::<_, ProductSumcheckError>(term_sum + product_at(factors, index)?)
                        })?;
                Ok(sum + shared.table_value(index)? * term_sum)
            },
        )
        .try_reduce(|| NativeField::from_u64(0), |left, right| Ok(left + right))
}

pub(super) fn product_round(
    left: &[NativeField],
    right: &[NativeField],
) -> Result<[NativeField; 3], ProductSumcheckError> {
    validate_tables(left, right)?;
    if left.len() == 1 {
        return Err(ProductSumcheckError::FoldingShape);
    }
    let points = [
        NativeField::from_u64(0),
        NativeField::from_u64(1),
        NativeField::from_u64(2),
    ];
    left.par_chunks_exact(2)
        .with_min_len(PARALLEL_MIN_ROWS)
        .zip(right.par_chunks_exact(2).with_min_len(PARALLEL_MIN_ROWS))
        .map(|(left_pair, right_pair)| product_pair(left_pair, right_pair, points))
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

pub(super) fn multi_product_round<T: SumcheckTable>(
    factors: &[T],
) -> Result<Vec<NativeField>, ProductSumcheckError> {
    validate_factors(factors)?;
    let length = factors
        .first()
        .map(SumcheckTable::table_len)
        .ok_or(ProductSumcheckError::EmptyFactors)?;
    if length == 1 {
        return Err(ProductSumcheckError::FoldingShape);
    }
    let evaluation_count = factors
        .len()
        .checked_add(1)
        .ok_or(ProductSumcheckError::ProofShape)?;
    let points = interpolation_points(evaluation_count)?;
    parallel_round(length / 2, evaluation_count, |pair_index, evaluations| {
        accumulate_factor_pair(factors, pair_index, &points, evaluations)
    })
}

pub(super) fn shared_sum_product_round<T: SumcheckTable>(
    shared: &T,
    terms: &[Vec<T>],
) -> Result<Vec<NativeField>, ProductSumcheckError> {
    let (_, factor_count, length) = validate_terms(terms)?;
    if shared.table_len() != length {
        return Err(ProductSumcheckError::LengthMismatch);
    }
    if length == 1 {
        return Err(ProductSumcheckError::FoldingShape);
    }
    let evaluation_count = factor_count
        .checked_add(2)
        .ok_or(ProductSumcheckError::ProofShape)?;
    let points = interpolation_points(evaluation_count)?;
    parallel_round(length / 2, evaluation_count, |pair_index, evaluations| {
        let pair_start = pair_index
            .checked_mul(2)
            .ok_or(ProductSumcheckError::FoldingShape)?;
        let pair_end = pair_start
            .checked_add(1)
            .ok_or(ProductSumcheckError::FoldingShape)?;
        let shared_zero = shared.table_value(pair_start)?;
        let shared_one = shared.table_value(pair_end)?;
        for (point, evaluation) in points.iter().copied().zip(evaluations) {
            let shared_value = shared_zero + point * (shared_one - shared_zero);
            let term_sum =
                terms
                    .iter()
                    .try_fold(NativeField::from_u64(0), |term_sum, factors| {
                        let product = factors.iter().try_fold(
                            NativeField::from_u64(1),
                            |product, factor| {
                                let zero = factor.table_value(pair_start)?;
                                let one = factor.table_value(pair_end)?;
                                Ok::<_, ProductSumcheckError>(
                                    product * (zero + point * (one - zero)),
                                )
                            },
                        )?;
                        Ok::<_, ProductSumcheckError>(term_sum + product)
                    })?;
            *evaluation += shared_value * term_sum;
        }
        Ok(())
    })
}

fn parallel_round(
    pair_count: usize,
    evaluation_count: usize,
    accumulate: impl Fn(usize, &mut [NativeField]) -> Result<(), ProductSumcheckError> + Sync,
) -> Result<Vec<NativeField>, ProductSumcheckError> {
    (0..pair_count)
        .into_par_iter()
        .with_min_len(PARALLEL_MIN_ROWS)
        .try_fold(
            || vec![NativeField::from_u64(0); evaluation_count],
            |mut evaluations, pair_index| {
                accumulate(pair_index, &mut evaluations)?;
                Ok(evaluations)
            },
        )
        .try_reduce(
            || vec![NativeField::from_u64(0); evaluation_count],
            |mut left, right| {
                for (target, value) in left.iter_mut().zip(right) {
                    *target += value;
                }
                Ok(left)
            },
        )
}

fn accumulate_factor_pair<T: SumcheckTable>(
    factors: &[T],
    pair_index: usize,
    points: &[NativeField],
    evaluations: &mut [NativeField],
) -> Result<(), ProductSumcheckError> {
    let pair_start = pair_index
        .checked_mul(2)
        .ok_or(ProductSumcheckError::FoldingShape)?;
    let pair_end = pair_start
        .checked_add(1)
        .ok_or(ProductSumcheckError::FoldingShape)?;
    for (point, evaluation) in points.iter().copied().zip(evaluations) {
        let product = factors
            .iter()
            .try_fold(NativeField::from_u64(1), |product, factor| {
                let zero = factor.table_value(pair_start)?;
                let one = factor.table_value(pair_end)?;
                Ok::<_, ProductSumcheckError>(product * (zero + point * (one - zero)))
            })?;
        *evaluation += product;
    }
    Ok(())
}

fn product_pair(
    left_pair: &[NativeField],
    right_pair: &[NativeField],
    points: [NativeField; 3],
) -> Result<[NativeField; 3], ProductSumcheckError> {
    let (left_zero, left_one) = pair_values(left_pair)?;
    let (right_zero, right_one) = pair_values(right_pair)?;
    Ok(points.map(|point| {
        let left_at = left_zero + point * (left_one - left_zero);
        let right_at = right_zero + point * (right_one - right_zero);
        left_at * right_at
    }))
}

fn product_at<T: SumcheckTable>(
    factors: &[T],
    index: usize,
) -> Result<NativeField, ProductSumcheckError> {
    factors
        .iter()
        .try_fold(NativeField::from_u64(1), |product, factor| {
            Ok(product * factor.table_value(index)?)
        })
}

fn interpolation_points(count: usize) -> Result<Vec<NativeField>, ProductSumcheckError> {
    (0..count).map(usize_to_field).collect()
}
