//! Native-field product sumchecks used by lookup and memory arguments.

use akita_pcs::{AkitaTranscript, Ring, Transcript};
use jolt_field::Field;
use rayon::prelude::*;
use thiserror::Error;

use crate::{
    NativeField,
    metrics::{self, Phase},
};

mod factor;
mod rounds;
mod sparse;

pub(crate) use factor::SumcheckFactor;
use factor::{FoldedFactor, SumcheckTable};
use rounds::{inner_product, product_round, shared_sum_of_term_products, shared_sum_product_round};
use sparse::SparseTable;

/// Proof that a Boolean-hypercube sum equals an inner product of two MLEs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProductSumcheckProof {
    pub(crate) rounds: Vec<[NativeField; 3]>,
    pub(crate) final_left: NativeField,
    pub(crate) final_right: NativeField,
}

/// Sumcheck proof for a sum of equally shaped pointwise factor products.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SumOfProductsSumcheckProof {
    pub(crate) rounds: Vec<Vec<NativeField>>,
    pub(crate) final_terms: Vec<Vec<NativeField>>,
}

/// Invalid product-sumcheck witness, proof, or transcript reduction.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum ProductSumcheckError {
    /// At least one factor table is required.
    #[error("sumcheck factor list is empty")]
    EmptyFactors,
    /// Evaluation tables must be non-empty.
    #[error("sumcheck evaluation table is empty")]
    EmptyTable,
    /// Evaluation table lengths differ.
    #[error("sumcheck table lengths differ")]
    LengthMismatch,
    /// Multilinear evaluation tables require a power-of-two length.
    #[error("sumcheck table length is not a power of two")]
    NonPowerOfTwo,
    /// Proof has the wrong variable, factor, or polynomial degree shape.
    #[error("sumcheck proof shape is invalid")]
    ProofShape,
    /// A round polynomial does not sum to the previous claim.
    #[error("sumcheck round does not match the previous claim")]
    RoundClaimMismatch,
    /// Terminal oracle evaluations do not multiply to the reduced claim.
    #[error("sumcheck terminal values do not match the reduced claim")]
    FinalClaimMismatch,
    /// A fixed interpolation denominator unexpectedly had no inverse.
    #[error("sumcheck interpolation denominator is not invertible")]
    NonInvertibleInterpolation,
    /// Internal pair folding lost a table element.
    #[error("sumcheck folding shape invariant failed")]
    FoldingShape,
}

impl ProductSumcheckProof {
    pub(crate) fn prove(
        left: &[NativeField],
        right: &[NativeField],
        transcript: &mut AkitaTranscript<NativeField>,
    ) -> Result<(Self, NativeField, Vec<NativeField>), ProductSumcheckError> {
        let _phase = metrics::start(Phase::Sumcheck);
        validate_tables(left, right)?;
        let claim = inner_product(left, right)?;
        let mut rounds = Vec::with_capacity(variable_count(left.len())?);
        let mut point = Vec::with_capacity(rounds.capacity());
        if left.len() == 1 {
            return finish_product_sumcheck(left, right, rounds, claim, point, transcript);
        }
        let message = product_round(left, right)?;
        absorb_round(transcript, b"product-sumcheck", rounds.len(), &message)?;
        let challenge = transcript.challenge_scalar(b"product-sumcheck-challenge");
        let (left, right) = rayon::join(
            || fold_borrowed(left, challenge),
            || fold_borrowed(right, challenge),
        );
        let mut left = left?;
        let mut right = right?;
        rounds.push(message);
        point.push(challenge);
        while left.len() > 1 {
            let message = product_round(&left, &right)?;
            absorb_round(transcript, b"product-sumcheck", rounds.len(), &message)?;
            let challenge = transcript.challenge_scalar(b"product-sumcheck-challenge");
            fold(&mut left, challenge)?;
            fold(&mut right, challenge)?;
            rounds.push(message);
            point.push(challenge);
        }
        finish_product_sumcheck(&left, &right, rounds, claim, point, transcript)
    }

    pub(crate) fn prove_sparse_left(
        left_entries: Vec<(usize, NativeField)>,
        logical_length: usize,
        right: &[NativeField],
        transcript: &mut AkitaTranscript<NativeField>,
    ) -> Result<(Self, NativeField, Vec<NativeField>), ProductSumcheckError> {
        let _phase = metrics::start(Phase::Sumcheck);
        let mut left = SparseTable::new(left_entries, logical_length)?;
        if right.len() != logical_length {
            return Err(ProductSumcheckError::LengthMismatch);
        }
        let claim = left.inner_product(right)?;
        let mut rounds = Vec::with_capacity(variable_count(logical_length)?);
        let mut point = Vec::with_capacity(rounds.capacity());
        if logical_length == 1 {
            let left = [left.final_value()?];
            return finish_product_sumcheck(&left, right, rounds, claim, point, transcript);
        }
        let message = left.round(right)?;
        absorb_round(transcript, b"product-sumcheck", rounds.len(), &message)?;
        let challenge = transcript.challenge_scalar(b"product-sumcheck-challenge");
        let (left_result, folded_right) =
            rayon::join(|| left.fold(challenge), || fold_borrowed(right, challenge));
        left_result?;
        let mut right = folded_right?;
        rounds.push(message);
        point.push(challenge);
        while left.length() > 1 {
            let message = left.round(&right)?;
            absorb_round(transcript, b"product-sumcheck", rounds.len(), &message)?;
            let challenge = transcript.challenge_scalar(b"product-sumcheck-challenge");
            let (left_result, right_result) =
                rayon::join(|| left.fold(challenge), || fold(&mut right, challenge));
            left_result?;
            right_result?;
            rounds.push(message);
            point.push(challenge);
        }
        let left = [left.final_value()?];
        finish_product_sumcheck(&left, &right, rounds, claim, point, transcript)
    }

    pub(crate) fn verify(
        &self,
        initial_claim: NativeField,
        expected_rounds: usize,
        transcript: &mut AkitaTranscript<NativeField>,
    ) -> Result<Vec<NativeField>, ProductSumcheckError> {
        if self.rounds.len() != expected_rounds {
            return Err(ProductSumcheckError::ProofShape);
        }
        let mut claim = initial_claim;
        let mut point = Vec::with_capacity(expected_rounds);
        for (round_index, message) in self.rounds.iter().enumerate() {
            if message[0] + message[1] != claim {
                return Err(ProductSumcheckError::RoundClaimMismatch);
            }
            absorb_round(transcript, b"product-sumcheck", round_index, message)?;
            let challenge = transcript.challenge_scalar(b"product-sumcheck-challenge");
            claim = evaluate_lagrange(message, challenge)?;
            point.push(challenge);
        }
        if claim != self.final_left * self.final_right {
            return Err(ProductSumcheckError::FinalClaimMismatch);
        }
        absorb_finals(
            transcript,
            b"product-sumcheck-final",
            &[self.final_left, self.final_right],
        )?;
        Ok(point)
    }

    pub(crate) const fn final_left(&self) -> NativeField {
        self.final_left
    }

    pub(crate) const fn final_right(&self) -> NativeField {
        self.final_right
    }
}

impl SumOfProductsSumcheckProof {
    pub(crate) fn prove_shared_first(
        terms: Vec<Vec<SumcheckFactor<'_>>>,
        transcript: &mut AkitaTranscript<NativeField>,
    ) -> Result<(Self, NativeField, Vec<NativeField>), ProductSumcheckError> {
        let _phase = metrics::start(Phase::Sumcheck);
        let (shared, terms) = split_shared_first(terms)?;
        let (_, _, mut current_len) = validate_terms(&terms)?;
        if shared.table_len() != current_len {
            return Err(ProductSumcheckError::LengthMismatch);
        }
        let claim = shared_sum_of_term_products(&shared, &terms)?;
        let mut rounds = Vec::with_capacity(variable_count(current_len)?);
        let mut point = Vec::with_capacity(rounds.capacity());
        if current_len == 1 {
            return finish_shared_sum_of_products(
                &shared, &terms, rounds, claim, point, transcript,
            );
        }
        let message = shared_sum_product_round(&shared, &terms)?;
        absorb_round(
            transcript,
            b"sum-of-products-sumcheck",
            rounds.len(),
            &message,
        )?;
        let challenge = transcript.challenge_scalar(b"sum-of-products-sumcheck-challenge");
        let (shared, terms) = rayon::join(
            || shared.fold(challenge),
            || fold_initial_terms(terms, challenge),
        );
        let mut shared = shared?;
        let mut terms = terms?;
        current_len /= 2;
        rounds.push(message);
        point.push(challenge);
        while current_len > 1 {
            let message = shared_sum_product_round(&shared, &terms)?;
            absorb_round(
                transcript,
                b"sum-of-products-sumcheck",
                rounds.len(),
                &message,
            )?;
            let challenge = transcript.challenge_scalar(b"sum-of-products-sumcheck-challenge");
            let (shared_result, terms_result) = rayon::join(
                || shared.fold(challenge),
                || {
                    terms.par_iter_mut().try_for_each(|term| {
                        term.par_iter_mut()
                            .try_for_each(|factor| factor.fold(challenge))
                    })
                },
            );
            shared_result?;
            terms_result?;
            current_len /= 2;
            rounds.push(message);
            point.push(challenge);
        }
        finish_shared_sum_of_products(&shared, &terms, rounds, claim, point, transcript)
    }

    pub(crate) fn verify(
        &self,
        initial_claim: NativeField,
        expected_rounds: usize,
        expected_terms: usize,
        expected_factors: usize,
        transcript: &mut AkitaTranscript<NativeField>,
    ) -> Result<Vec<NativeField>, ProductSumcheckError> {
        self.validate_shape(expected_rounds, expected_terms, expected_factors)?;
        let mut claim = initial_claim;
        let mut point = Vec::with_capacity(expected_rounds);
        for (round_index, message) in self.rounds.iter().enumerate() {
            if message
                .first()
                .copied()
                .ok_or(ProductSumcheckError::ProofShape)?
                + message
                    .get(1)
                    .copied()
                    .ok_or(ProductSumcheckError::ProofShape)?
                != claim
            {
                return Err(ProductSumcheckError::RoundClaimMismatch);
            }
            absorb_round(
                transcript,
                b"sum-of-products-sumcheck",
                round_index,
                message,
            )?;
            let challenge = transcript.challenge_scalar(b"sum-of-products-sumcheck-challenge");
            claim = evaluate_lagrange(message, challenge)?;
            point.push(challenge);
        }
        if claim != terminal_term_sum(&self.final_terms) {
            return Err(ProductSumcheckError::FinalClaimMismatch);
        }
        absorb_term_finals(transcript, &self.final_terms)?;
        Ok(point)
    }

    pub(crate) fn final_terms(&self) -> &[Vec<NativeField>] {
        &self.final_terms
    }

    fn validate_shape(
        &self,
        rounds: usize,
        terms: usize,
        factors: usize,
    ) -> Result<(), ProductSumcheckError> {
        if self.rounds.len() != rounds
            || self.final_terms.len() != terms
            || self.final_terms.iter().any(|term| term.len() != factors)
            || self.rounds.iter().any(|round| round.len() != factors + 1)
        {
            return Err(ProductSumcheckError::ProofShape);
        }
        Ok(())
    }
}

fn split_shared_first(
    terms: Vec<Vec<SumcheckFactor<'_>>>,
) -> Result<(SumcheckFactor<'_>, Vec<Vec<SumcheckFactor<'_>>>), ProductSumcheckError> {
    let mut terms = terms.into_iter();
    let mut first = terms
        .next()
        .ok_or(ProductSumcheckError::EmptyFactors)?
        .into_iter();
    let shared = first.next().ok_or(ProductSumcheckError::EmptyFactors)?;
    let mut stripped = vec![first.collect::<Vec<_>>()];
    for term in terms {
        let mut factors = term.into_iter();
        let candidate = factors.next().ok_or(ProductSumcheckError::EmptyFactors)?;
        if !shared.same_table(&candidate) {
            return Err(ProductSumcheckError::LengthMismatch);
        }
        stripped.push(factors.collect());
    }
    Ok((shared, stripped))
}

fn finish_product_sumcheck(
    left: &[NativeField],
    right: &[NativeField],
    rounds: Vec<[NativeField; 3]>,
    claim: NativeField,
    point: Vec<NativeField>,
    transcript: &mut AkitaTranscript<NativeField>,
) -> Result<(ProductSumcheckProof, NativeField, Vec<NativeField>), ProductSumcheckError> {
    let final_left = first_value(left)?;
    let final_right = first_value(right)?;
    absorb_finals(
        transcript,
        b"product-sumcheck-final",
        &[final_left, final_right],
    )?;
    Ok((
        ProductSumcheckProof {
            rounds,
            final_left,
            final_right,
        },
        claim,
        point,
    ))
}

fn finish_shared_sum_of_products<T: SumcheckTable>(
    shared: &T,
    terms: &[Vec<T>],
    rounds: Vec<Vec<NativeField>>,
    claim: NativeField,
    point: Vec<NativeField>,
    transcript: &mut AkitaTranscript<NativeField>,
) -> Result<(SumOfProductsSumcheckProof, NativeField, Vec<NativeField>), ProductSumcheckError> {
    let shared_value = shared.table_value(0)?;
    let final_terms = terms
        .iter()
        .map(|term| {
            let mut factors = Vec::with_capacity(term.len() + 1);
            factors.push(shared_value);
            factors.extend(
                term.iter()
                    .map(|factor| factor.table_value(0))
                    .collect::<Result<Vec<_>, _>>()?,
            );
            Ok(factors)
        })
        .collect::<Result<Vec<_>, ProductSumcheckError>>()?;
    absorb_term_finals(transcript, &final_terms)?;
    Ok((
        SumOfProductsSumcheckProof {
            rounds,
            final_terms,
        },
        claim,
        point,
    ))
}

fn fold_borrowed(
    values: &[NativeField],
    challenge: NativeField,
) -> Result<Vec<NativeField>, ProductSumcheckError> {
    crate::field_fold::fold_binary_layer_from_slice(values, challenge)
        .map_err(|_| ProductSumcheckError::FoldingShape)
}

fn fold_initial_factors(
    factors: Vec<SumcheckFactor<'_>>,
    challenge: NativeField,
) -> Result<Vec<FoldedFactor>, ProductSumcheckError> {
    factors
        .into_par_iter()
        .map(|factor| factor.fold(challenge))
        .collect()
}

fn fold_initial_terms(
    terms: Vec<Vec<SumcheckFactor<'_>>>,
    challenge: NativeField,
) -> Result<Vec<Vec<FoldedFactor>>, ProductSumcheckError> {
    terms
        .into_par_iter()
        .map(|term| fold_initial_factors(term, challenge))
        .collect()
}

fn validate_tables(
    left: &[NativeField],
    right: &[NativeField],
) -> Result<(), ProductSumcheckError> {
    if left.is_empty() {
        return Err(ProductSumcheckError::EmptyTable);
    }
    if left.len() != right.len() {
        return Err(ProductSumcheckError::LengthMismatch);
    }
    if !left.len().is_power_of_two() {
        return Err(ProductSumcheckError::NonPowerOfTwo);
    }
    Ok(())
}

fn validate_terms<T: SumcheckTable>(
    terms: &[Vec<T>],
) -> Result<(usize, usize, usize), ProductSumcheckError> {
    let first_term = terms.first().ok_or(ProductSumcheckError::EmptyFactors)?;
    let first_factor = first_term
        .first()
        .ok_or(ProductSumcheckError::EmptyFactors)?;
    if first_factor.table_len() == 0 || !first_factor.table_len().is_power_of_two() {
        return Err(ProductSumcheckError::NonPowerOfTwo);
    }
    let factor_count = first_term.len();
    let table_len = first_factor.table_len();
    if terms.iter().any(|term| {
        term.len() != factor_count || term.iter().any(|factor| factor.table_len() != table_len)
    }) {
        return Err(ProductSumcheckError::LengthMismatch);
    }
    Ok((terms.len(), factor_count, table_len))
}

fn variable_count(length: usize) -> Result<usize, ProductSumcheckError> {
    if length == 0 || !length.is_power_of_two() {
        return Err(ProductSumcheckError::NonPowerOfTwo);
    }
    usize::try_from(length.ilog2()).map_err(|_| ProductSumcheckError::ProofShape)
}

fn terminal_term_sum(terms: &[Vec<NativeField>]) -> NativeField {
    terms
        .iter()
        .map(|term| {
            term.iter()
                .copied()
                .fold(NativeField::from_u64(1), |product, factor| product * factor)
        })
        .fold(NativeField::from_u64(0), |sum, term| sum + term)
}

fn fold(table: &mut Vec<NativeField>, challenge: NativeField) -> Result<(), ProductSumcheckError> {
    if table.len() <= 1 || !table.len().is_power_of_two() {
        return Err(ProductSumcheckError::FoldingShape);
    }
    crate::field_fold::fold_binary_layer(table, challenge)
        .map_err(|_| ProductSumcheckError::FoldingShape)
}

fn pair_values(pair: &[NativeField]) -> Result<(NativeField, NativeField), ProductSumcheckError> {
    let zero = pair
        .first()
        .copied()
        .ok_or(ProductSumcheckError::FoldingShape)?;
    let one = pair
        .get(1)
        .copied()
        .ok_or(ProductSumcheckError::FoldingShape)?;
    Ok((zero, one))
}

fn first_value(values: &[NativeField]) -> Result<NativeField, ProductSumcheckError> {
    values
        .first()
        .copied()
        .ok_or(ProductSumcheckError::EmptyTable)
}

fn evaluate_lagrange(
    evaluations: &[NativeField],
    point: NativeField,
) -> Result<NativeField, ProductSumcheckError> {
    if evaluations.is_empty() {
        return Err(ProductSumcheckError::ProofShape);
    }
    let mut result = NativeField::from_u64(0);
    for (index, evaluation) in evaluations.iter().enumerate() {
        let index_field = usize_to_field(index)?;
        let mut numerator = NativeField::from_u64(1);
        let mut denominator = NativeField::from_u64(1);
        for other in 0..evaluations.len() {
            if other == index {
                continue;
            }
            let other_field = usize_to_field(other)?;
            numerator *= point - other_field;
            denominator *= index_field - other_field;
        }
        let inverse = denominator
            .inverse()
            .ok_or(ProductSumcheckError::NonInvertibleInterpolation)?;
        result += *evaluation * numerator * inverse;
    }
    Ok(result)
}

fn usize_to_field(value: usize) -> Result<NativeField, ProductSumcheckError> {
    let value = u64::try_from(value).map_err(|_| ProductSumcheckError::ProofShape)?;
    Ok(NativeField::from_u64(value))
}

fn absorb_round(
    transcript: &mut AkitaTranscript<NativeField>,
    label: &[u8],
    round_index: usize,
    evaluations: &[NativeField],
) -> Result<(), ProductSumcheckError> {
    let round_index = u64::try_from(round_index).map_err(|_| ProductSumcheckError::ProofShape)?;
    let evaluation_count =
        u64::try_from(evaluations.len()).map_err(|_| ProductSumcheckError::ProofShape)?;
    transcript.append_bytes(label, &round_index.to_le_bytes());
    transcript.append_bytes(
        b"sumcheck-evaluation-count",
        &evaluation_count.to_le_bytes(),
    );
    for evaluation in evaluations {
        transcript.append_field(b"sumcheck-evaluation", evaluation);
    }
    Ok(())
}

fn absorb_finals(
    transcript: &mut AkitaTranscript<NativeField>,
    label: &[u8],
    finals: &[NativeField],
) -> Result<(), ProductSumcheckError> {
    let count = u64::try_from(finals.len()).map_err(|_| ProductSumcheckError::ProofShape)?;
    transcript.append_bytes(label, &count.to_le_bytes());
    for value in finals {
        transcript.append_field(b"sumcheck-final", value);
    }
    Ok(())
}

fn absorb_term_finals(
    transcript: &mut AkitaTranscript<NativeField>,
    terms: &[Vec<NativeField>],
) -> Result<(), ProductSumcheckError> {
    let term_count = u64::try_from(terms.len()).map_err(|_| ProductSumcheckError::ProofShape)?;
    transcript.append_bytes(b"sum-of-products-term-count", &term_count.to_le_bytes());
    for term in terms {
        let factor_count =
            u64::try_from(term.len()).map_err(|_| ProductSumcheckError::ProofShape)?;
        transcript.append_bytes(b"sum-of-products-factor-count", &factor_count.to_le_bytes());
        for factor in term {
            transcript.append_field(b"sum-of-products-final", factor);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use akita_pcs::{AkitaTranscript, Ring};

    use super::{NativeField, ProductSumcheckProof, SumOfProductsSumcheckProof, SumcheckFactor};

    fn transcript(side: bool) -> AkitaTranscript<NativeField> {
        let mut transcript = if side {
            AkitaTranscript::unbound_prover(b"zksm83-sumcheck-test/v1")
        } else {
            AkitaTranscript::unbound_verifier(b"zksm83-sumcheck-test/v1")
        };
        transcript.bind_instance_bytes(b"test-instance");
        transcript
    }

    #[test]
    fn product_sumcheck_round_trip_and_tamper_rejection() -> Result<(), Box<dyn std::error::Error>>
    {
        let left = [1_u64, 2, 3, 4].map(NativeField::from_u64);
        let right = [5_u64, 6, 7, 8].map(NativeField::from_u64);
        let (proof, claim, prover_point) =
            ProductSumcheckProof::prove(&left, &right, &mut transcript(true))?;
        let verifier_point = proof.verify(claim, 2, &mut transcript(false))?;
        assert_eq!(prover_point, verifier_point);

        let mut tampered = proof;
        let first = tampered
            .rounds
            .first_mut()
            .ok_or("missing product sumcheck round")?;
        first[0] += NativeField::from_u64(1);
        assert!(tampered.verify(claim, 2, &mut transcript(false)).is_err());
        Ok(())
    }

    #[test]
    fn sum_of_products_round_trip_and_tamper_rejection() -> Result<(), Box<dyn std::error::Error>> {
        let shared = vec![1, 2, 3, 4]
            .into_iter()
            .map(NativeField::from_u64)
            .collect::<Vec<_>>();
        let terms = vec![vec![vec![5, 6, 7, 8]], vec![vec![9, 2, 4, 1]]]
            .into_iter()
            .map(|term| {
                term.into_iter()
                    .map(|factor| factor.into_iter().map(NativeField::from_u64).collect())
                    .collect()
            })
            .collect::<Vec<Vec<Vec<_>>>>();
        let compact = terms
            .iter()
            .map(|term| {
                std::iter::once(SumcheckFactor::borrowed(&shared))
                    .chain(term.iter().map(|factor| SumcheckFactor::borrowed(factor)))
                    .collect()
            })
            .collect();
        let (proof, claim, prover_point) =
            SumOfProductsSumcheckProof::prove_shared_first(compact, &mut transcript(true))?;
        let verifier_point = proof.verify(claim, 2, 2, 2, &mut transcript(false))?;
        assert_eq!(prover_point, verifier_point);

        let mut tampered = proof;
        let first = tampered
            .rounds
            .first_mut()
            .and_then(|round| round.first_mut())
            .ok_or("missing sum-of-products round")?;
        *first += NativeField::from_u64(1);
        assert!(
            tampered
                .verify(claim, 2, 2, 2, &mut transcript(false))
                .is_err()
        );
        Ok(())
    }
}
