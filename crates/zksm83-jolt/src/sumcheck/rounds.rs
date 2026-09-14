use akita_pcs::Ring;
use rayon::prelude::*;

use super::{
    NativeField, ProductSumcheckError, SumcheckTable, pair_values, usize_to_field, validate_tables,
    validate_terms,
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
    (0..length / 2)
        .into_par_iter()
        .with_min_len(PARALLEL_MIN_ROWS)
        .try_fold(
            || {
                (
                    vec![NativeField::from_u64(0); evaluation_count],
                    vec![NativeField::from_u64(1); evaluation_count],
                )
            },
            |(mut evaluations, mut products), pair_index| {
                accumulate_shared_pair(
                    shared,
                    terms,
                    pair_index,
                    &points,
                    &mut evaluations,
                    &mut products,
                )?;
                Ok((evaluations, products))
            },
        )
        .try_reduce(
            || {
                (
                    vec![NativeField::from_u64(0); evaluation_count],
                    vec![NativeField::from_u64(1); evaluation_count],
                )
            },
            |(mut left, products), (right, _)| {
                for (target, value) in left.iter_mut().zip(right) {
                    *target += value;
                }
                Ok((left, products))
            },
        )
        .map(|(evaluations, _)| evaluations)
}

fn accumulate_shared_pair<T: SumcheckTable>(
    shared: &T,
    terms: &[Vec<T>],
    pair_index: usize,
    points: &[NativeField],
    evaluations: &mut [NativeField],
    products: &mut [NativeField],
) -> Result<(), ProductSumcheckError> {
    if points.len() != evaluations.len() || points.len() != products.len() || points.len() < 2 {
        return Err(ProductSumcheckError::ProofShape);
    }
    let pair_start = pair_index
        .checked_mul(2)
        .ok_or(ProductSumcheckError::FoldingShape)?;
    let pair_end = pair_start
        .checked_add(1)
        .ok_or(ProductSumcheckError::FoldingShape)?;
    let shared_zero = shared.table_value(pair_start)?;
    let shared_one = shared.table_value(pair_end)?;
    let one = NativeField::from_u64(1);
    for factors in terms {
        products.fill(one);
        for factor in factors {
            let zero = factor.table_value(pair_start)?;
            let one_value = factor.table_value(pair_end)?;
            *products
                .first_mut()
                .ok_or(ProductSumcheckError::ProofShape)? *= zero;
            *products
                .get_mut(1)
                .ok_or(ProductSumcheckError::ProofShape)? *= one_value;
            for (product, point) in products.iter_mut().skip(2).zip(points.iter().skip(2)) {
                *product *= zero + *point * (one_value - zero);
            }
        }
        for (index, (evaluation, product)) in
            evaluations.iter_mut().zip(products.iter()).enumerate()
        {
            let shared_value = match index {
                0 => shared_zero,
                1 => shared_one,
                _ => {
                    let point = points
                        .get(index)
                        .copied()
                        .ok_or(ProductSumcheckError::ProofShape)?;
                    shared_zero + point * (shared_one - shared_zero)
                }
            };
            *evaluation += shared_value * *product;
        }
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
