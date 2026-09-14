use akita_pcs::{AkitaTranscript, Ring, Transcript};
use jolt_field::Field;
use rayon::prelude::*;

use super::relation::{initialize_constraint_output, trim_zero_suffix};
use super::{NativeField, UniformError, UniformRelation};

type SumcheckOutput = (Vec<Vec<NativeField>>, Vec<NativeField>, Vec<NativeField>);

const PARALLEL_SUMCHECK_PAIR_THRESHOLD: usize = 64;
const SUMCHECK_CHUNKS_PER_THREAD: usize = 4;

pub(super) fn prove_sumcheck<C>(
    relation: &impl UniformRelation,
    columns: &[C],
    mut weights: Vec<NativeField>,
    constraint_mix: NativeField,
    transcript: &mut AkitaTranscript<NativeField>,
) -> Result<SumcheckOutput, UniformError>
where
    C: AsRef<[NativeField]> + Sync,
{
    let _phase = crate::metrics::start(crate::metrics::Phase::Sumcheck);
    if weights.len() < 2
        || !weights.len().is_power_of_two()
        || columns
            .iter()
            .any(|column| column.as_ref().len() != weights.len())
    {
        return Err(UniformError::Shape);
    }
    let round_evaluations = relation
        .max_constraint_degree()
        .checked_add(2)
        .ok_or(UniformError::Shape)?;
    let interpolation_points = interpolation_points(round_evaluations)?;
    let constraint_powers = constraint_powers(relation.constraint_count(), constraint_mix);
    let mut rounds = Vec::with_capacity(weights.len().ilog2() as usize);
    let mut opening_point = Vec::with_capacity(rounds.capacity());
    let mut claim = NativeField::from_u64(0);
    let zero = NativeField::from_u64(0);
    let mut constraint_scratch = vec![zero; relation.constraint_count()];
    let message = parallel_sumcheck_round_precomputed(
        relation,
        columns,
        &weights,
        &interpolation_points,
        &constraint_powers,
    )?;
    let at_zero = message.first().copied().ok_or(UniformError::Sumcheck)?;
    let at_one = message.get(1).copied().ok_or(UniformError::Sumcheck)?;
    if at_zero + at_one != claim {
        return Err(UniformError::Unsatisfied);
    }
    absorb_round(transcript, rounds.len(), &message)?;
    let challenge = transcript.challenge_scalar(b"sumcheck-round");
    claim = evaluate_lagrange(&message, challenge)?;
    let mut columns = fold_borrowed_columns(columns, challenge)?;
    fold_column(&mut weights, challenge)?;
    rounds.push(message);
    opening_point.push(challenge);
    while weights.len() > 1 {
        let message = parallel_sumcheck_round_precomputed(
            relation,
            &columns,
            &weights,
            &interpolation_points,
            &constraint_powers,
        )?;
        let at_zero = message.first().copied().ok_or(UniformError::Sumcheck)?;
        let at_one = message.get(1).copied().ok_or(UniformError::Sumcheck)?;
        if at_zero + at_one != claim {
            return Err(UniformError::Unsatisfied);
        }
        absorb_round(transcript, rounds.len(), &message)?;
        let challenge = transcript.challenge_scalar(b"sumcheck-round");
        claim = evaluate_lagrange(&message, challenge)?;
        fold_columns(&mut columns, challenge)?;
        fold_column(&mut weights, challenge)?;
        rounds.push(message);
        opening_point.push(challenge);
    }
    let opened_values = columns
        .iter()
        .map(|column| column.first().copied().ok_or(UniformError::Shape))
        .collect::<Result<Vec<_>, _>>()?;
    let terminal_weight = weights.first().copied().ok_or(UniformError::Shape)?;
    let terminal_relation = combined_relation_with_scratch(
        relation,
        &opened_values,
        constraint_mix,
        &mut constraint_scratch,
    )?;
    if claim != terminal_weight * terminal_relation {
        return Err(UniformError::TerminalMismatch);
    }
    Ok((rounds, opening_point, opened_values))
}

pub(super) fn replay_sumcheck(
    relation: &impl UniformRelation,
    rounds: &[Vec<NativeField>],
    opened_values: &[NativeField],
    row_point: &[NativeField],
    constraint_mix: NativeField,
    transcript: &mut AkitaTranscript<NativeField>,
) -> Result<Vec<NativeField>, UniformError> {
    let expected_message_len = relation
        .max_constraint_degree()
        .checked_add(2)
        .ok_or(UniformError::Shape)?;
    if rounds.len() != row_point.len() || opened_values.len() != relation.column_count() {
        return Err(UniformError::Shape);
    }
    let mut claim = NativeField::from_u64(0);
    let mut opening_point = Vec::with_capacity(rounds.len());
    for (round_index, message) in rounds.iter().enumerate() {
        if message.len() != expected_message_len {
            return Err(UniformError::Sumcheck);
        }
        let at_zero = message.first().copied().ok_or(UniformError::Sumcheck)?;
        let at_one = message.get(1).copied().ok_or(UniformError::Sumcheck)?;
        if at_zero + at_one != claim {
            return Err(UniformError::Sumcheck);
        }
        absorb_round(transcript, round_index, message)?;
        let challenge = transcript.challenge_scalar(b"sumcheck-round");
        claim = evaluate_lagrange(message, challenge)?;
        opening_point.push(challenge);
    }
    let terminal_weight = equality_evaluation(row_point, &opening_point)?;
    let terminal_relation = combined_relation(relation, opened_values, constraint_mix)?;
    if claim != terminal_weight * terminal_relation {
        return Err(UniformError::TerminalMismatch);
    }
    Ok(opening_point)
}

#[cfg(test)]
pub(super) fn sumcheck_round<C>(
    relation: &impl UniformRelation,
    columns: &[C],
    weights: &[NativeField],
    constraint_mix: NativeField,
    evaluation_count: usize,
    row_scratch: &mut [NativeField],
    constraint_scratch: &mut [NativeField],
) -> Result<Vec<NativeField>, UniformError>
where
    C: AsRef<[NativeField]> + Sync,
{
    if columns
        .iter()
        .any(|column| column.as_ref().len() != weights.len())
        || weights.len() < 2
        || !weights.len().is_multiple_of(2)
        || row_scratch.len() != columns.len()
        || constraint_scratch.len() != relation.constraint_count()
    {
        return Err(UniformError::Shape);
    }
    let points = interpolation_points(evaluation_count)?;
    let constraint_powers = constraint_powers(relation.constraint_count(), constraint_mix);
    sumcheck_round_precomputed(
        relation,
        columns,
        weights,
        &points,
        &constraint_powers,
        row_scratch,
        constraint_scratch,
    )
}

#[allow(clippy::too_many_arguments)]
fn sumcheck_round_precomputed<C>(
    relation: &impl UniformRelation,
    columns: &[C],
    weights: &[NativeField],
    points: &[NativeField],
    constraint_powers: &[NativeField],
    row_scratch: &mut [NativeField],
    constraint_scratch: &mut [NativeField],
) -> Result<Vec<NativeField>, UniformError>
where
    C: AsRef<[NativeField]>,
{
    let zero = NativeField::from_u64(0);
    let mut message = vec![zero; points.len()];
    let mut low_row = vec![zero; columns.len()];
    let mut row_deltas = vec![zero; columns.len()];
    for pair_index in 0..(weights.len() / 2) {
        accumulate_pair(
            relation,
            columns,
            weights,
            pair_index,
            points,
            constraint_powers,
            &mut message,
            row_scratch,
            &mut low_row,
            &mut row_deltas,
            constraint_scratch,
        )?;
    }
    Ok(message)
}

#[cfg(test)]
pub(super) fn parallel_sumcheck_round<C>(
    relation: &impl UniformRelation,
    columns: &[C],
    weights: &[NativeField],
    constraint_mix: NativeField,
    evaluation_count: usize,
) -> Result<Vec<NativeField>, UniformError>
where
    C: AsRef<[NativeField]> + Sync,
{
    validate_round_shape(relation, columns, weights, evaluation_count)?;
    let points = interpolation_points(evaluation_count)?;
    let constraint_powers = constraint_powers(relation.constraint_count(), constraint_mix);
    parallel_sumcheck_round_precomputed(relation, columns, weights, &points, &constraint_powers)
}

fn parallel_sumcheck_round_precomputed<C>(
    relation: &impl UniformRelation,
    columns: &[C],
    weights: &[NativeField],
    points: &[NativeField],
    constraint_powers: &[NativeField],
) -> Result<Vec<NativeField>, UniformError>
where
    C: AsRef<[NativeField]> + Sync,
{
    validate_round_shape(relation, columns, weights, points.len())?;
    if constraint_powers.len() != relation.constraint_count() {
        return Err(UniformError::Shape);
    }
    let pair_count = weights.len() / 2;
    let thread_count = rayon::current_num_threads();
    if pair_count < PARALLEL_SUMCHECK_PAIR_THRESHOLD || thread_count == 1 {
        let zero = NativeField::from_u64(0);
        let mut row = vec![zero; relation.column_count()];
        let mut constraints = vec![zero; relation.constraint_count()];
        return sumcheck_round_precomputed(
            relation,
            columns,
            weights,
            points,
            constraint_powers,
            &mut row,
            &mut constraints,
        );
    }
    let desired_chunks = thread_count
        .saturating_mul(SUMCHECK_CHUNKS_PER_THREAD)
        .clamp(1, pair_count);
    let pairs_per_chunk = pair_count.div_ceil(desired_chunks);
    let chunk_count = pair_count.div_ceil(pairs_per_chunk);
    (0..chunk_count)
        .into_par_iter()
        .map(|chunk| {
            evaluate_pair_chunk(
                relation,
                columns,
                weights,
                points,
                constraint_powers,
                chunk,
                pairs_per_chunk,
            )
        })
        .try_reduce(
            || vec![NativeField::from_u64(0); points.len()],
            merge_round_messages,
        )
}

fn evaluate_pair_chunk<C>(
    relation: &impl UniformRelation,
    columns: &[C],
    weights: &[NativeField],
    points: &[NativeField],
    constraint_powers: &[NativeField],
    chunk: usize,
    pairs_per_chunk: usize,
) -> Result<Vec<NativeField>, UniformError>
where
    C: AsRef<[NativeField]>,
{
    let pair_count = weights.len() / 2;
    let start = chunk
        .checked_mul(pairs_per_chunk)
        .ok_or(UniformError::Shape)?;
    let end = start.saturating_add(pairs_per_chunk).min(pair_count);
    let zero = NativeField::from_u64(0);
    let mut message = vec![zero; points.len()];
    let mut row = vec![zero; relation.column_count()];
    let mut low_row = vec![zero; relation.column_count()];
    let mut row_deltas = vec![zero; relation.column_count()];
    let mut constraints = vec![zero; relation.constraint_count()];
    for pair_index in start..end {
        accumulate_pair(
            relation,
            columns,
            weights,
            pair_index,
            points,
            constraint_powers,
            &mut message,
            &mut row,
            &mut low_row,
            &mut row_deltas,
            &mut constraints,
        )?;
    }
    Ok(message)
}

#[allow(clippy::too_many_arguments)]
fn accumulate_pair<C>(
    relation: &impl UniformRelation,
    columns: &[C],
    weights: &[NativeField],
    pair_index: usize,
    points: &[NativeField],
    constraint_powers: &[NativeField],
    message: &mut [NativeField],
    row: &mut [NativeField],
    low_row: &mut [NativeField],
    row_deltas: &mut [NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError>
where
    C: AsRef<[NativeField]>,
{
    load_pair_rows(columns, pair_index, low_row, row_deltas)?;
    let (weight_low, weight_delta) = pair_low_and_delta(weights, pair_index)?;
    for (point, evaluation) in points.iter().copied().zip(message) {
        interpolate_loaded_row(low_row, row_deltas, point, row)?;
        let weight = weight_low + point * weight_delta;
        *evaluation +=
            weight * combined_relation_with_powers(relation, row, constraint_powers, constraints)?;
    }
    Ok(())
}

fn merge_round_messages(
    mut left: Vec<NativeField>,
    right: Vec<NativeField>,
) -> Result<Vec<NativeField>, UniformError> {
    if left.len() != right.len() {
        return Err(UniformError::Shape);
    }
    for (left, right) in left.iter_mut().zip(right) {
        *left += right;
    }
    Ok(left)
}

fn validate_round_shape<C>(
    relation: &impl UniformRelation,
    columns: &[C],
    weights: &[NativeField],
    evaluation_count: usize,
) -> Result<(), UniformError>
where
    C: AsRef<[NativeField]>,
{
    if evaluation_count == 0
        || columns.len() != relation.column_count()
        || columns
            .iter()
            .any(|column| column.as_ref().len() != weights.len())
        || weights.len() < 2
        || !weights.len().is_multiple_of(2)
    {
        return Err(UniformError::Shape);
    }
    Ok(())
}

fn load_pair_rows<C>(
    columns: &[C],
    pair_index: usize,
    low_row: &mut [NativeField],
    row_deltas: &mut [NativeField],
) -> Result<(), UniformError>
where
    C: AsRef<[NativeField]>,
{
    if columns.len() != low_row.len() || columns.len() != row_deltas.len() {
        return Err(UniformError::Shape);
    }
    for ((low_output, delta_output), column) in low_row.iter_mut().zip(row_deltas).zip(columns) {
        let (low, delta) = pair_low_and_delta(column.as_ref(), pair_index)?;
        *low_output = low;
        *delta_output = delta;
    }
    Ok(())
}

fn pair_low_and_delta(
    values: &[NativeField],
    pair_index: usize,
) -> Result<(NativeField, NativeField), UniformError> {
    let start = pair_index.checked_mul(2).ok_or(UniformError::Shape)?;
    let low = values.get(start).copied().ok_or(UniformError::Shape)?;
    let high = values
        .get(start.checked_add(1).ok_or(UniformError::Shape)?)
        .copied()
        .ok_or(UniformError::Shape)?;
    Ok((low, high - low))
}

fn interpolate_loaded_row(
    low_row: &[NativeField],
    row_deltas: &[NativeField],
    point: NativeField,
    output: &mut [NativeField],
) -> Result<(), UniformError> {
    if low_row.len() != row_deltas.len() || low_row.len() != output.len() {
        return Err(UniformError::Shape);
    }
    for ((output, low), delta) in output.iter_mut().zip(low_row).zip(row_deltas) {
        *output = *low + point * *delta;
    }
    Ok(())
}

fn combined_relation(
    relation: &impl UniformRelation,
    row: &[NativeField],
    constraint_mix: NativeField,
) -> Result<NativeField, UniformError> {
    let mut constraints = vec![NativeField::from_u64(0); relation.constraint_count()];
    combined_relation_with_scratch(relation, row, constraint_mix, &mut constraints)
}

pub(super) fn combined_relation_with_scratch(
    relation: &impl UniformRelation,
    row: &[NativeField],
    constraint_mix: NativeField,
    constraints: &mut [NativeField],
) -> Result<NativeField, UniformError> {
    let powers = constraint_powers(relation.constraint_count(), constraint_mix);
    combined_relation_with_powers(relation, row, &powers, constraints)
}

fn combined_relation_with_powers(
    relation: &impl UniformRelation,
    row: &[NativeField],
    constraint_powers: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<NativeField, UniformError> {
    if row.len() != relation.column_count() {
        return Err(UniformError::Shape);
    }
    let zero = NativeField::from_u64(0);
    if constraints.len() != relation.constraint_count()
        || constraint_powers.len() != relation.constraint_count()
    {
        return Err(UniformError::Shape);
    }
    initialize_constraint_output(relation, constraints);
    relation.evaluate(row, constraints)?;
    let mut combined = zero;
    let mixed_constraints = trim_zero_suffix(constraints);
    for (constraint, power) in mixed_constraints.iter().copied().zip(constraint_powers) {
        combined += *power * constraint;
    }
    Ok(combined)
}

fn constraint_powers(count: usize, mix: NativeField) -> Vec<NativeField> {
    let mut power = NativeField::from_u64(1);
    (0..count)
        .map(|_| {
            let current = power;
            power *= mix;
            current
        })
        .collect()
}

fn interpolation_points(count: usize) -> Result<Vec<NativeField>, UniformError> {
    (0..count)
        .map(|point| {
            u64::try_from(point)
                .map(NativeField::from_u64)
                .map_err(|_| UniformError::Shape)
        })
        .collect()
}

fn fold_columns(
    columns: &mut [Vec<NativeField>],
    challenge: NativeField,
) -> Result<(), UniformError> {
    columns
        .par_iter_mut()
        .try_for_each(|column| fold_column(column, challenge))
}

fn fold_borrowed_columns<C>(
    columns: &[C],
    challenge: NativeField,
) -> Result<Vec<Vec<NativeField>>, UniformError>
where
    C: AsRef<[NativeField]> + Sync,
{
    columns
        .par_iter()
        .map(|column| {
            crate::field_fold::fold_binary_layer_from_slice(column.as_ref(), challenge)
                .map_err(|_| UniformError::Shape)
        })
        .collect()
}

fn fold_column(values: &mut Vec<NativeField>, challenge: NativeField) -> Result<(), UniformError> {
    crate::field_fold::fold_binary_layer(values, challenge).map_err(|_| UniformError::Shape)
}

fn evaluate_lagrange(
    evaluations: &[NativeField],
    point: NativeField,
) -> Result<NativeField, UniformError> {
    if evaluations.is_empty() {
        return Err(UniformError::Sumcheck);
    }
    let mut result = NativeField::from_u64(0);
    for (index, evaluation) in evaluations.iter().enumerate() {
        let index_field =
            NativeField::from_u64(u64::try_from(index).map_err(|_| UniformError::Shape)?);
        let mut numerator = NativeField::from_u64(1);
        let mut denominator = NativeField::from_u64(1);
        for other in 0..evaluations.len() {
            if other == index {
                continue;
            }
            let other_field =
                NativeField::from_u64(u64::try_from(other).map_err(|_| UniformError::Shape)?);
            numerator *= point - other_field;
            denominator *= index_field - other_field;
        }
        let inverse = denominator
            .inverse()
            .ok_or(UniformError::NonInvertibleInterpolation)?;
        result += *evaluation * numerator * inverse;
    }
    Ok(result)
}

fn equality_evaluation(
    left: &[NativeField],
    right: &[NativeField],
) -> Result<NativeField, UniformError> {
    if left.len() != right.len() {
        return Err(UniformError::Shape);
    }
    let one = NativeField::from_u64(1);
    Ok(left
        .iter()
        .copied()
        .zip(right.iter().copied())
        .fold(one, |product, (left, right)| {
            product * (left * right + (one - left) * (one - right))
        }))
}

fn absorb_round(
    transcript: &mut AkitaTranscript<NativeField>,
    round_index: usize,
    message: &[NativeField],
) -> Result<(), UniformError> {
    let index = u64::try_from(round_index).map_err(|_| UniformError::Shape)?;
    transcript.append_bytes(b"sumcheck-round-index", &index.to_le_bytes());
    for value in message {
        transcript.append_field(b"sumcheck-round-evaluation", value);
    }
    Ok(())
}
