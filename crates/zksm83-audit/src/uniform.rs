//! Committed uniform low-degree trace relations.
//!
//! This is the glue-proof substrate used between SM83 Shout/Twist instances:
//! columns are committed once, all per-row identities are mixed into one
//! Fiat-Shamir sumcheck, and every terminal column evaluation is bound by one
//! batched IPA opening.

use ff::{Field, PrimeField};
use pasta_curves::Fp;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    BatchedIpaLinearOpeningProof, BatchedIpaOpeningProof, IpaCommitment, IpaError, IpaParameters,
    shout::eq_evaluations,
    sumcheck::{Transcript, encode_dynamic_round, evaluate_lagrange},
};

const PROTOCOL_DOMAIN: &[u8] = b"zksm83-uniform-trace/v1";

/// A fixed low-degree relation applied independently to every trace row.
pub trait UniformRelation {
    /// Stable domain separating this relation from every other column layout.
    fn domain(&self) -> &'static [u8];

    /// Number of committed witness columns consumed by one row.
    fn column_count(&self) -> usize;

    /// Number of identities that must each equal zero on every row.
    fn constraint_count(&self) -> usize;

    /// Maximum total degree of any identity returned by `evaluate`.
    fn max_constraint_degree(&self) -> usize;

    /// Evaluates every identity at one (possibly non-Boolean) row point.
    fn evaluate(&self, row: &[Fp], constraints: &mut [Fp]) -> Result<(), UniformTraceError>;
}

/// Succinct proof that committed columns satisfy one uniform row relation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommittedUniformTraceProof {
    commitments: Vec<IpaCommitment>,
    sumcheck_rounds: Vec<Vec<Fp>>,
    opening: BatchedIpaOpeningProof,
}

impl CommittedUniformTraceProof {
    /// Proves all row identities over equally sized power-of-two columns.
    pub fn prove(
        parameters: &IpaParameters,
        relation: &impl UniformRelation,
        columns: &[Vec<Fp>],
    ) -> Result<Self, UniformTraceError> {
        validate_relation(parameters, relation, columns)?;
        let commitments = parameters.commit_batch(columns)?;
        let mut transcript = relation_transcript(parameters, relation, &commitments);
        let (row_point, constraint_mix) =
            relation_challenges(&mut transcript, parameters.vector_len().ilog2() as usize)?;
        let weights = eq_evaluations(&row_point).map_err(|_| UniformTraceError::Shape)?;
        let (sumcheck_rounds, opening_point) =
            prove_sumcheck(relation, columns, weights, constraint_mix, &mut transcript)?;
        let opening = parameters.open_batch_precommitted(columns, &opening_point, &commitments)?;
        Ok(Self {
            commitments,
            sumcheck_rounds,
            opening,
        })
    }

    /// Verifies the uniform identities without receiving any witness column.
    pub fn verify(
        &self,
        parameters: &IpaParameters,
        relation: &impl UniformRelation,
    ) -> Result<(), UniformTraceError> {
        validate_relation_shape(parameters, relation, self.commitments.len())?;
        let expected_rounds = parameters.vector_len().ilog2() as usize;
        let mut transcript = relation_transcript(parameters, relation, &self.commitments);
        let (row_point, constraint_mix) = relation_challenges(&mut transcript, expected_rounds)?;
        let (opening_point, terminal_claim) = replay_sumcheck(
            relation.max_constraint_degree(),
            Fp::ZERO,
            &self.sumcheck_rounds,
            expected_rounds,
            &mut transcript,
        )?;
        parameters.verify_batch(&self.commitments, &opening_point, &self.opening)?;
        let terminal_weight = equality_evaluation(&row_point, &opening_point)?;
        let terminal_relation =
            combined_relation(relation, self.opening.claimed_values(), constraint_mix)?;
        if terminal_claim != terminal_weight * terminal_relation {
            return Err(UniformTraceError::TerminalMismatch);
        }
        Ok(())
    }

    /// Returns the committed column count.
    #[must_use]
    pub fn column_count(&self) -> usize {
        self.commitments.len()
    }

    /// Returns the committed witness columns in relation order.
    #[must_use]
    pub fn commitments(&self) -> &[IpaCommitment] {
        &self.commitments
    }

    /// Returns the sumcheck round count, equal to log2 of the trace length.
    #[must_use]
    pub fn round_count(&self) -> usize {
        self.sumcheck_rounds.len()
    }

    /// Returns the proof size in curve points and scalar field elements.
    #[must_use]
    pub fn element_count(&self) -> (usize, usize) {
        let (points, opening_scalars) = self.opening.element_count();
        let sumcheck_scalars = self.sumcheck_rounds.iter().map(Vec::len).sum::<usize>();
        (
            points.saturating_add(self.commitments.len()),
            opening_scalars.saturating_add(sumcheck_scalars),
        )
    }
}

/// A uniform transition relation over committed state columns, their shift,
/// and row-local witness columns.
///
/// `next` is cryptographically fixed to `current[i + 1]` for every non-final
/// row and to the verifier-supplied final boundary on the last row. The
/// `first_selector` argument is one only on row zero, allowing the relation to
/// bind its verifier-supplied initial boundary without a separate opening.
pub trait ShiftedUniformRelation {
    /// Stable domain separating the transition and column layout.
    fn domain(&self) -> &'static [u8];

    /// Canonical public statement bytes, including the initial boundary.
    fn statement_bytes(&self) -> Vec<u8>;

    /// Number of committed state columns.
    fn state_column_count(&self) -> usize;

    /// Number of committed row-local witness columns.
    ///
    /// Local columns are consumed by the row relation, but are not shifted or
    /// exposed as recursive state boundaries.
    fn local_column_count(&self) -> usize;

    /// Number of transition identities returned for each row.
    fn constraint_count(&self) -> usize;

    /// Maximum total degree of any transition identity.
    fn max_constraint_degree(&self) -> usize;

    /// Evaluates all transition identities at one sumcheck point.
    fn evaluate(
        &self,
        current: &[Fp],
        next: &[Fp],
        local: &[Fp],
        first_selector: Fp,
        constraints: &mut [Fp],
    ) -> Result<(), UniformTraceError>;
}

/// Succinct sequential trace proof with a verifier-bound final state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommittedShiftedUniformTraceProof {
    commitments: Vec<IpaCommitment>,
    sumcheck_rounds: Vec<Vec<Fp>>,
    current_opening: BatchedIpaOpeningProof,
    shifted_opening: BatchedIpaLinearOpeningProof,
}

impl CommittedShiftedUniformTraceProof {
    /// Proves a complete power-of-two segment from the relation's initial
    /// boundary through `final_values`.
    pub fn prove(
        parameters: &IpaParameters,
        relation: &impl ShiftedUniformRelation,
        state_columns: &[Vec<Fp>],
        local_columns: &[Vec<Fp>],
        final_values: &[Fp],
    ) -> Result<Self, UniformTraceError> {
        validate_shifted_relation(
            parameters,
            relation,
            state_columns,
            local_columns,
            final_values,
        )?;
        let columns = state_columns
            .iter()
            .chain(local_columns)
            .cloned()
            .collect::<Vec<_>>();
        let commitments = parameters.commit_batch(&columns)?;
        let mut transcript =
            shifted_relation_transcript(parameters, relation, &commitments, final_values);
        let variables = parameters.vector_len().ilog2() as usize;
        let (row_point, constraint_mix) = relation_challenges(&mut transcript, variables)?;
        let weights = eq_evaluations(&row_point).map_err(|_| UniformTraceError::Shape)?;
        let next_columns = shifted_columns(state_columns, final_values)?;
        let first_selector = first_selector(parameters.vector_len());
        let (sumcheck_rounds, opening_point) = prove_shifted_sumcheck(
            relation,
            state_columns,
            &next_columns,
            local_columns,
            first_selector,
            weights,
            constraint_mix,
            &mut transcript,
        )?;
        let current_opening =
            parameters.open_batch_precommitted(&columns, &opening_point, &commitments)?;
        let shift_weights = shifted_equality_weights(&opening_point)?;
        let state_commitments = commitments
            .get(..state_columns.len())
            .ok_or(UniformTraceError::Shape)?;
        let shifted_opening = parameters.open_batch_linear_precommitted(
            state_columns,
            &shift_weights,
            state_commitments,
        )?;
        Ok(Self {
            commitments,
            sumcheck_rounds,
            current_opening,
            shifted_opening,
        })
    }

    /// Verifies the sequential relation against only commitments and the
    /// verifier-supplied final boundary.
    pub fn verify(
        &self,
        parameters: &IpaParameters,
        relation: &impl ShiftedUniformRelation,
        final_values: &[Fp],
    ) -> Result<(), UniformTraceError> {
        validate_shifted_relation_shape(
            parameters,
            relation,
            self.commitments.len(),
            final_values,
        )?;
        let variables = parameters.vector_len().ilog2() as usize;
        let mut transcript =
            shifted_relation_transcript(parameters, relation, &self.commitments, final_values);
        let (row_point, constraint_mix) = relation_challenges(&mut transcript, variables)?;
        let (opening_point, terminal_claim) = replay_sumcheck(
            relation.max_constraint_degree(),
            Fp::ZERO,
            &self.sumcheck_rounds,
            variables,
            &mut transcript,
        )?;
        parameters.verify_batch(&self.commitments, &opening_point, &self.current_opening)?;
        let shift_weights = shifted_equality_weights(&opening_point)?;
        let state_commitments = self
            .commitments
            .get(..relation.state_column_count())
            .ok_or(UniformTraceError::Shape)?;
        parameters.verify_batch_linear(state_commitments, &shift_weights, &self.shifted_opening)?;
        let equality = eq_evaluations(&opening_point).map_err(|_| UniformTraceError::Shape)?;
        let final_weight = equality.last().copied().ok_or(UniformTraceError::Shape)?;
        let next = self
            .shifted_opening
            .claimed_values()
            .iter()
            .copied()
            .zip(final_values)
            .map(|(shifted, final_value)| shifted + final_weight * final_value)
            .collect::<Vec<_>>();
        let first = equality.first().copied().ok_or(UniformTraceError::Shape)?;
        let current_claims = self.current_opening.claimed_values();
        let (current, local) = current_claims.split_at(relation.state_column_count());
        let terminal_relation =
            combined_shifted_relation(relation, current, &next, local, first, constraint_mix)?;
        let terminal_weight = equality_evaluation(&row_point, &opening_point)?;
        if terminal_claim != terminal_weight * terminal_relation {
            return Err(UniformTraceError::TerminalMismatch);
        }
        Ok(())
    }

    /// Returns the total committed state and local column count.
    #[must_use]
    pub fn column_count(&self) -> usize {
        self.commitments.len()
    }

    /// Returns committed state columns followed by committed local columns.
    #[must_use]
    pub fn commitments(&self) -> &[IpaCommitment] {
        &self.commitments
    }

    /// Returns the logarithmic number of sumcheck rounds.
    #[must_use]
    pub fn round_count(&self) -> usize {
        self.sumcheck_rounds.len()
    }

    /// Returns the proof size in curve points and scalar field elements.
    #[must_use]
    pub fn element_count(&self) -> (usize, usize) {
        let (current_points, current_scalars) = self.current_opening.element_count();
        let (shifted_points, shifted_scalars) = self.shifted_opening.element_count();
        let sumcheck_scalars = self.sumcheck_rounds.iter().map(Vec::len).sum::<usize>();
        (
            self.commitments
                .len()
                .saturating_add(current_points)
                .saturating_add(shifted_points),
            current_scalars
                .saturating_add(shifted_scalars)
                .saturating_add(sumcheck_scalars),
        )
    }
}

/// A committed uniform trace statement, witness, or proof is malformed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum UniformTraceError {
    /// The relation or column vector has an invalid shape.
    #[error("uniform trace relation or column shape is invalid")]
    Shape,
    /// The declared relation domain is empty.
    #[error("uniform trace relation domain must not be empty")]
    EmptyDomain,
    /// The relation declared zero columns, constraints, or degree.
    #[error("uniform trace relation dimensions must be non-zero")]
    EmptyRelation,
    /// A relation evaluator returned a vector with the wrong shape.
    #[error("uniform trace relation evaluator rejected a row")]
    Relation,
    /// A Fiat-Shamir mixing challenge was zero.
    #[error("uniform trace Fiat-Shamir mixing challenge was zero")]
    ZeroChallenge,
    /// A sumcheck round had the wrong degree or did not preserve its claim.
    #[error("uniform trace sumcheck failed")]
    Sumcheck,
    /// The terminal polynomial evaluation disagreed with opened trace columns.
    #[error("uniform trace terminal opening does not satisfy the relation")]
    TerminalMismatch,
    /// The polynomial commitment or batched opening failed.
    #[error(transparent)]
    Ipa(#[from] IpaError),
}

fn validate_shifted_relation(
    parameters: &IpaParameters,
    relation: &impl ShiftedUniformRelation,
    state_columns: &[Vec<Fp>],
    local_columns: &[Vec<Fp>],
    final_values: &[Fp],
) -> Result<(), UniformTraceError> {
    let column_count = state_columns
        .len()
        .checked_add(local_columns.len())
        .ok_or(UniformTraceError::Shape)?;
    validate_shifted_relation_shape(parameters, relation, column_count, final_values)?;
    if state_columns
        .iter()
        .chain(local_columns)
        .any(|column| column.len() != parameters.vector_len())
    {
        return Err(UniformTraceError::Shape);
    }
    Ok(())
}

fn validate_shifted_relation_shape(
    parameters: &IpaParameters,
    relation: &impl ShiftedUniformRelation,
    column_count: usize,
    final_values: &[Fp],
) -> Result<(), UniformTraceError> {
    if relation.domain().is_empty() || relation.statement_bytes().is_empty() {
        return Err(UniformTraceError::EmptyDomain);
    }
    if relation.state_column_count() == 0
        || relation.constraint_count() == 0
        || relation.max_constraint_degree() == 0
    {
        return Err(UniformTraceError::EmptyRelation);
    }
    let expected_columns = relation
        .state_column_count()
        .checked_add(relation.local_column_count())
        .ok_or(UniformTraceError::Shape)?;
    if expected_columns != column_count
        || final_values.len() != relation.state_column_count()
        || parameters.vector_len() == 0
        || !parameters.vector_len().is_power_of_two()
    {
        return Err(UniformTraceError::Shape);
    }
    Ok(())
}

fn shifted_relation_transcript(
    parameters: &IpaParameters,
    relation: &impl ShiftedUniformRelation,
    commitments: &[IpaCommitment],
    final_values: &[Fp],
) -> Transcript {
    let public_statement = relation.statement_bytes();
    let mut statement = Vec::new();
    statement.extend_from_slice(&(relation.domain().len() as u64).to_le_bytes());
    statement.extend_from_slice(relation.domain());
    statement.extend_from_slice(&(public_statement.len() as u64).to_le_bytes());
    statement.extend_from_slice(&public_statement);
    statement.extend_from_slice(&(parameters.vector_len() as u64).to_le_bytes());
    statement.extend_from_slice(&(relation.state_column_count() as u64).to_le_bytes());
    statement.extend_from_slice(&(relation.local_column_count() as u64).to_le_bytes());
    statement.extend_from_slice(&(relation.constraint_count() as u64).to_le_bytes());
    statement.extend_from_slice(&(relation.max_constraint_degree() as u64).to_le_bytes());
    for commitment in commitments {
        statement.extend_from_slice(&commitment.to_bytes());
    }
    for value in final_values {
        statement.extend_from_slice(value.to_repr().as_ref());
    }
    Transcript::new(b"zksm83-shifted-uniform-trace/v2", &statement)
}

fn shifted_columns(
    columns: &[Vec<Fp>],
    final_values: &[Fp],
) -> Result<Vec<Vec<Fp>>, UniformTraceError> {
    if columns.len() != final_values.len() {
        return Err(UniformTraceError::Shape);
    }
    columns
        .iter()
        .zip(final_values)
        .map(|(column, final_value)| {
            if column.is_empty() {
                return Err(UniformTraceError::Shape);
            }
            let mut shifted = column.iter().copied().skip(1).collect::<Vec<_>>();
            shifted.push(*final_value);
            Ok(shifted)
        })
        .collect()
}

fn first_selector(length: usize) -> Vec<Fp> {
    let mut selector = vec![Fp::ZERO; length];
    if let Some(first) = selector.first_mut() {
        *first = Fp::ONE;
    }
    selector
}

#[allow(clippy::too_many_arguments)]
fn prove_shifted_sumcheck(
    relation: &impl ShiftedUniformRelation,
    state_columns: &[Vec<Fp>],
    next_columns: &[Vec<Fp>],
    local_columns: &[Vec<Fp>],
    first_selector: Vec<Fp>,
    weights: Vec<Fp>,
    constraint_mix: Fp,
    transcript: &mut Transcript,
) -> Result<(Vec<Vec<Fp>>, Vec<Fp>), UniformTraceError> {
    if state_columns.len() != next_columns.len()
        || first_selector.len() != weights.len()
        || state_columns
            .iter()
            .chain(next_columns)
            .chain(local_columns)
            .any(|column| column.len() != weights.len())
    {
        return Err(UniformTraceError::Shape);
    }
    let mut current = state_columns.to_vec();
    let mut next = next_columns.to_vec();
    let mut local = local_columns.to_vec();
    let mut first = first_selector;
    let mut folded_weights = weights;
    let mut rounds = Vec::with_capacity(folded_weights.len().ilog2() as usize);
    let mut challenges = Vec::with_capacity(rounds.capacity());
    let round_degree = relation
        .max_constraint_degree()
        .checked_add(1)
        .ok_or(UniformTraceError::Shape)?;
    while folded_weights.len() > 1 {
        let mut message = vec![Fp::ZERO; round_degree.saturating_add(1)];
        for (point_index, evaluation) in message.iter_mut().enumerate() {
            let point = Fp::from(point_index as u64);
            for row_index in 0..folded_weights.len() / 2 {
                let current_row = interpolate_row(&current, row_index, point)?;
                let next_row = interpolate_row(&next, row_index, point)?;
                let local_row = interpolate_row(&local, row_index, point)?;
                let first_value = interpolate_pair(&first, row_index, point)?;
                let weight = interpolate_pair(&folded_weights, row_index, point)?;
                *evaluation += weight
                    * combined_shifted_relation(
                        relation,
                        &current_row,
                        &next_row,
                        &local_row,
                        first_value,
                        constraint_mix,
                    )?;
            }
        }
        let challenge =
            transcript.challenge(b"uniform-sumcheck-round", &encode_dynamic_round(&message));
        fold_columns(&mut current, challenge)?;
        fold_columns(&mut next, challenge)?;
        fold_columns(&mut local, challenge)?;
        fold_column(&mut first, challenge)?;
        fold_column(&mut folded_weights, challenge)?;
        rounds.push(message);
        challenges.push(challenge);
    }
    Ok((rounds, challenges))
}

fn combined_shifted_relation(
    relation: &impl ShiftedUniformRelation,
    current: &[Fp],
    next: &[Fp],
    local: &[Fp],
    first_selector: Fp,
    mix: Fp,
) -> Result<Fp, UniformTraceError> {
    if current.len() != relation.state_column_count()
        || next.len() != relation.state_column_count()
        || local.len() != relation.local_column_count()
    {
        return Err(UniformTraceError::Shape);
    }
    let mut constraints = vec![Fp::ZERO; relation.constraint_count()];
    relation.evaluate(current, next, local, first_selector, &mut constraints)?;
    let mut coefficient = Fp::ONE;
    Ok(constraints.into_iter().fold(Fp::ZERO, |sum, constraint| {
        let mixed = sum + coefficient * constraint;
        coefficient *= mix;
        mixed
    }))
}

fn shifted_equality_weights(point: &[Fp]) -> Result<Vec<Fp>, UniformTraceError> {
    let equality = eq_evaluations(point).map_err(|_| UniformTraceError::Shape)?;
    let mut shifted = vec![Fp::ZERO; equality.len()];
    for (target, weight) in shifted.iter_mut().skip(1).zip(equality) {
        *target = weight;
    }
    Ok(shifted)
}

fn validate_relation(
    parameters: &IpaParameters,
    relation: &impl UniformRelation,
    columns: &[Vec<Fp>],
) -> Result<(), UniformTraceError> {
    validate_relation_shape(parameters, relation, columns.len())?;
    if columns
        .iter()
        .any(|column| column.len() != parameters.vector_len())
    {
        return Err(UniformTraceError::Shape);
    }
    Ok(())
}

fn validate_relation_shape(
    parameters: &IpaParameters,
    relation: &impl UniformRelation,
    column_count: usize,
) -> Result<(), UniformTraceError> {
    if relation.domain().is_empty() {
        return Err(UniformTraceError::EmptyDomain);
    }
    if relation.column_count() == 0
        || relation.constraint_count() == 0
        || relation.max_constraint_degree() == 0
    {
        return Err(UniformTraceError::EmptyRelation);
    }
    if relation.column_count() != column_count
        || parameters.vector_len() == 0
        || !parameters.vector_len().is_power_of_two()
    {
        return Err(UniformTraceError::Shape);
    }
    Ok(())
}

fn relation_transcript(
    parameters: &IpaParameters,
    relation: &impl UniformRelation,
    commitments: &[IpaCommitment],
) -> Transcript {
    let mut statement = Vec::new();
    statement.extend_from_slice(&(relation.domain().len() as u64).to_le_bytes());
    statement.extend_from_slice(relation.domain());
    statement.extend_from_slice(&(parameters.vector_len() as u64).to_le_bytes());
    statement.extend_from_slice(&(relation.column_count() as u64).to_le_bytes());
    statement.extend_from_slice(&(relation.constraint_count() as u64).to_le_bytes());
    statement.extend_from_slice(&(relation.max_constraint_degree() as u64).to_le_bytes());
    for commitment in commitments {
        statement.extend_from_slice(&commitment.to_bytes());
    }
    Transcript::new(PROTOCOL_DOMAIN, &statement)
}

fn relation_challenges(
    transcript: &mut Transcript,
    row_variables: usize,
) -> Result<(Vec<Fp>, Fp), UniformTraceError> {
    let row_point = (0..row_variables)
        .map(|index| transcript.challenge(b"uniform-row-point", &(index as u64).to_le_bytes()))
        .collect::<Vec<_>>();
    let constraint_mix = transcript.challenge(b"uniform-constraint-mix", &[]);
    if constraint_mix == Fp::ZERO {
        return Err(UniformTraceError::ZeroChallenge);
    }
    Ok((row_point, constraint_mix))
}

fn prove_sumcheck(
    relation: &impl UniformRelation,
    columns: &[Vec<Fp>],
    weights: Vec<Fp>,
    constraint_mix: Fp,
    transcript: &mut Transcript,
) -> Result<(Vec<Vec<Fp>>, Vec<Fp>), UniformTraceError> {
    let mut folded_columns = columns.to_vec();
    let mut folded_weights = weights;
    let mut rounds = Vec::with_capacity(folded_weights.len().ilog2() as usize);
    let mut challenges = Vec::with_capacity(rounds.capacity());
    let round_degree = relation
        .max_constraint_degree()
        .checked_add(1)
        .ok_or(UniformTraceError::Shape)?;
    while folded_weights.len() > 1 {
        let mut message = vec![Fp::ZERO; round_degree.saturating_add(1)];
        for (point_index, evaluation) in message.iter_mut().enumerate() {
            let point = Fp::from(point_index as u64);
            for row_index in 0..folded_weights.len() / 2 {
                let row = interpolate_row(&folded_columns, row_index, point)?;
                let weight = interpolate_pair(&folded_weights, row_index, point)?;
                *evaluation += weight * combined_relation(relation, &row, constraint_mix)?;
            }
        }
        let challenge =
            transcript.challenge(b"uniform-sumcheck-round", &encode_dynamic_round(&message));
        fold_columns(&mut folded_columns, challenge)?;
        fold_column(&mut folded_weights, challenge)?;
        rounds.push(message);
        challenges.push(challenge);
    }
    Ok((rounds, challenges))
}

fn replay_sumcheck(
    max_constraint_degree: usize,
    initial_claim: Fp,
    rounds: &[Vec<Fp>],
    expected_rounds: usize,
    transcript: &mut Transcript,
) -> Result<(Vec<Fp>, Fp), UniformTraceError> {
    if rounds.len() != expected_rounds {
        return Err(UniformTraceError::Sumcheck);
    }
    let expected_degree = max_constraint_degree
        .checked_add(1)
        .ok_or(UniformTraceError::Shape)?;
    let mut claim = initial_claim;
    let mut challenges = Vec::with_capacity(expected_rounds);
    for message in rounds {
        if message.len() != expected_degree.saturating_add(1) {
            return Err(UniformTraceError::Sumcheck);
        }
        let at_zero = message
            .first()
            .copied()
            .ok_or(UniformTraceError::Sumcheck)?;
        let at_one = message.get(1).copied().ok_or(UniformTraceError::Sumcheck)?;
        if at_zero + at_one != claim {
            return Err(UniformTraceError::Sumcheck);
        }
        let challenge =
            transcript.challenge(b"uniform-sumcheck-round", &encode_dynamic_round(message));
        claim = evaluate_lagrange(message, challenge).map_err(|_| UniformTraceError::Sumcheck)?;
        challenges.push(challenge);
    }
    Ok((challenges, claim))
}

fn combined_relation(
    relation: &impl UniformRelation,
    row: &[Fp],
    mix: Fp,
) -> Result<Fp, UniformTraceError> {
    if row.len() != relation.column_count() {
        return Err(UniformTraceError::Shape);
    }
    let mut constraints = vec![Fp::ZERO; relation.constraint_count()];
    relation.evaluate(row, &mut constraints)?;
    let mut coefficient = Fp::ONE;
    Ok(constraints.into_iter().fold(Fp::ZERO, |sum, constraint| {
        let mixed = sum + coefficient * constraint;
        coefficient *= mix;
        mixed
    }))
}

fn interpolate_row(
    columns: &[Vec<Fp>],
    pair_index: usize,
    point: Fp,
) -> Result<Vec<Fp>, UniformTraceError> {
    columns
        .iter()
        .map(|column| interpolate_pair(column, pair_index, point))
        .collect()
}

fn interpolate_pair(values: &[Fp], pair_index: usize, point: Fp) -> Result<Fp, UniformTraceError> {
    let low_index = pair_index.checked_mul(2).ok_or(UniformTraceError::Shape)?;
    let high_index = low_index.checked_add(1).ok_or(UniformTraceError::Shape)?;
    let low = values
        .get(low_index)
        .copied()
        .ok_or(UniformTraceError::Shape)?;
    let high = values
        .get(high_index)
        .copied()
        .ok_or(UniformTraceError::Shape)?;
    Ok(low + point * (high - low))
}

fn fold_columns(columns: &mut [Vec<Fp>], challenge: Fp) -> Result<(), UniformTraceError> {
    for column in columns {
        fold_column(column, challenge)?;
    }
    Ok(())
}

fn fold_column(values: &mut Vec<Fp>, challenge: Fp) -> Result<(), UniformTraceError> {
    if values.len() <= 1 || !values.len().is_power_of_two() {
        return Err(UniformTraceError::Shape);
    }
    let mut folded = Vec::with_capacity(values.len() / 2);
    for pair in values.chunks_exact(2) {
        let low = pair.first().copied().ok_or(UniformTraceError::Shape)?;
        let high = pair.get(1).copied().ok_or(UniformTraceError::Shape)?;
        folded.push(low + challenge * (high - low));
    }
    *values = folded;
    Ok(())
}

fn equality_evaluation(left: &[Fp], right: &[Fp]) -> Result<Fp, UniformTraceError> {
    if left.len() != right.len() {
        return Err(UniformTraceError::Shape);
    }
    Ok(left
        .iter()
        .zip(right)
        .fold(Fp::ONE, |product, (left, right)| {
            product * (*left * *right + (Fp::ONE - left) * (Fp::ONE - right))
        }))
}

#[cfg(test)]
mod tests {
    use ff::{Field, PrimeField};
    use pasta_curves::Fp;

    use super::{
        CommittedShiftedUniformTraceProof, CommittedUniformTraceProof, ShiftedUniformRelation,
        UniformRelation, UniformTraceError,
    };
    use crate::IpaParameters;

    struct BooleanAddRelation;

    struct IncrementRelation {
        initial: Fp,
    }

    impl UniformRelation for BooleanAddRelation {
        fn domain(&self) -> &'static [u8] {
            b"zksm83-test-boolean-add/v1"
        }

        fn column_count(&self) -> usize {
            3
        }

        fn constraint_count(&self) -> usize {
            2
        }

        fn max_constraint_degree(&self) -> usize {
            2
        }

        fn evaluate(&self, row: &[Fp], constraints: &mut [Fp]) -> Result<(), UniformTraceError> {
            let x = row.first().copied().ok_or(UniformTraceError::Relation)?;
            let y = row.get(1).copied().ok_or(UniformTraceError::Relation)?;
            let z = row.get(2).copied().ok_or(UniformTraceError::Relation)?;
            let add = constraints.first_mut().ok_or(UniformTraceError::Relation)?;
            *add = x + y - z;
            let boolean = constraints.get_mut(1).ok_or(UniformTraceError::Relation)?;
            *boolean = x * (x - Fp::ONE);
            Ok(())
        }
    }

    impl ShiftedUniformRelation for IncrementRelation {
        fn domain(&self) -> &'static [u8] {
            b"zksm83-test-increment/v1"
        }

        fn statement_bytes(&self) -> Vec<u8> {
            self.initial.to_repr().as_ref().to_vec()
        }

        fn state_column_count(&self) -> usize {
            1
        }

        fn local_column_count(&self) -> usize {
            1
        }

        fn constraint_count(&self) -> usize {
            2
        }

        fn max_constraint_degree(&self) -> usize {
            2
        }

        fn evaluate(
            &self,
            current: &[Fp],
            next: &[Fp],
            local: &[Fp],
            first_selector: Fp,
            constraints: &mut [Fp],
        ) -> Result<(), UniformTraceError> {
            let current = current
                .first()
                .copied()
                .ok_or(UniformTraceError::Relation)?;
            let next = next.first().copied().ok_or(UniformTraceError::Relation)?;
            let increment = local.first().copied().ok_or(UniformTraceError::Relation)?;
            let boundary = constraints.first_mut().ok_or(UniformTraceError::Relation)?;
            *boundary = first_selector * (current - self.initial);
            let transition = constraints.get_mut(1).ok_or(UniformTraceError::Relation)?;
            *transition = next - current - increment;
            Ok(())
        }
    }

    #[test]
    fn uniform_trace_round_trip_and_tamper_rejection() -> Result<(), Box<dyn std::error::Error>> {
        let columns = vec![
            [0_u64, 1, 0, 1, 1, 0, 1, 0].map(Fp::from).to_vec(),
            [3_u64, 5, 7, 11, 13, 17, 19, 23].map(Fp::from).to_vec(),
            [3_u64, 6, 7, 12, 14, 17, 20, 23].map(Fp::from).to_vec(),
        ];
        let parameters = IpaParameters::new(8)?;
        let proof = CommittedUniformTraceProof::prove(&parameters, &BooleanAddRelation, &columns)?;
        proof.verify(&parameters, &BooleanAddRelation)?;
        assert_eq!(proof.column_count(), 3);
        assert_eq!(proof.round_count(), 3);
        assert_eq!(proof.element_count(), (9, 16));

        let mut wrong_round = proof.clone();
        let first = wrong_round
            .sumcheck_rounds
            .first_mut()
            .and_then(|round| round.first_mut())
            .ok_or_else(|| std::io::Error::other("missing sumcheck round"))?;
        *first += Fp::ONE;
        assert_eq!(
            wrong_round.verify(&parameters, &BooleanAddRelation),
            Err(UniformTraceError::Sumcheck)
        );

        let mut wrong_commitment = proof.clone();
        wrong_commitment.commitments.swap(0, 1);
        assert!(
            wrong_commitment
                .verify(&parameters, &BooleanAddRelation)
                .is_err()
        );

        let mut invalid_columns = columns.clone();
        let value = invalid_columns
            .get_mut(2)
            .and_then(|column| column.get_mut(4))
            .ok_or_else(|| std::io::Error::other("missing invalid witness cell"))?;
        *value += Fp::ONE;
        let invalid_proof =
            CommittedUniformTraceProof::prove(&parameters, &BooleanAddRelation, &invalid_columns)?;
        assert_eq!(
            invalid_proof.verify(&parameters, &BooleanAddRelation),
            Err(UniformTraceError::Sumcheck)
        );
        Ok(())
    }

    #[test]
    fn shifted_uniform_trace_binds_order_and_both_boundaries()
    -> Result<(), Box<dyn std::error::Error>> {
        let columns = vec![[5_u64, 6, 7, 8, 9, 10, 11, 12].map(Fp::from).to_vec()];
        let local_columns = vec![[1_u64; 8].map(Fp::from).to_vec()];
        let parameters = IpaParameters::new(8)?;
        let relation = IncrementRelation {
            initial: Fp::from(5),
        };
        let final_values = [Fp::from(13)];
        let proof = CommittedShiftedUniformTraceProof::prove(
            &parameters,
            &relation,
            &columns,
            &local_columns,
            &final_values,
        )?;
        proof.verify(&parameters, &relation, &final_values)?;
        assert_eq!(proof.column_count(), 2);
        assert_eq!(proof.round_count(), 3);
        assert_eq!(proof.element_count(), (14, 17));

        assert!(
            proof
                .verify(&parameters, &relation, &[Fp::from(14)])
                .is_err()
        );
        let wrong_initial = IncrementRelation {
            initial: Fp::from(6),
        };
        assert!(
            proof
                .verify(&parameters, &wrong_initial, &final_values)
                .is_err()
        );

        let mut invalid_columns = columns.clone();
        let value = invalid_columns
            .first_mut()
            .and_then(|column| column.get_mut(3))
            .ok_or_else(|| std::io::Error::other("missing transition witness cell"))?;
        *value += Fp::ONE;
        let invalid_proof = CommittedShiftedUniformTraceProof::prove(
            &parameters,
            &relation,
            &invalid_columns,
            &local_columns,
            &final_values,
        )?;
        assert!(
            invalid_proof
                .verify(&parameters, &relation, &final_values)
                .is_err()
        );

        let mut invalid_local = local_columns;
        let value = invalid_local
            .first_mut()
            .and_then(|column| column.get_mut(4))
            .ok_or_else(|| std::io::Error::other("missing local witness cell"))?;
        *value += Fp::ONE;
        let invalid_local_proof = CommittedShiftedUniformTraceProof::prove(
            &parameters,
            &relation,
            &columns,
            &invalid_local,
            &final_values,
        )?;
        assert!(
            invalid_local_proof
                .verify(&parameters, &relation, &final_values)
                .is_err()
        );
        Ok(())
    }
}
