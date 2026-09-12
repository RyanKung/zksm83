//! Native-field product sumchecks used by lookup and memory arguments.

use akita_pcs::{AkitaTranscript, Ring, Transcript};
use jolt_field::Field;
use thiserror::Error;

use crate::{
    NativeField,
    metrics::{self, Phase},
};

/// Proof that a Boolean-hypercube sum equals an inner product of two MLEs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProductSumcheckProof {
    pub(crate) rounds: Vec<[NativeField; 3]>,
    pub(crate) final_left: NativeField,
    pub(crate) final_right: NativeField,
}

/// Sumcheck proof for a pointwise product of non-empty factor columns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MultiProductSumcheckProof {
    pub(crate) rounds: Vec<Vec<NativeField>>,
    pub(crate) final_factors: Vec<NativeField>,
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
        let mut left = left.to_vec();
        let mut right = right.to_vec();
        let claim = inner_product(&left, &right)?;
        let mut rounds = Vec::with_capacity(variable_count(left.len())?);
        let mut point = Vec::with_capacity(rounds.capacity());
        while left.len() > 1 {
            let message = product_round(&left, &right)?;
            absorb_round(transcript, b"product-sumcheck", rounds.len(), &message)?;
            let challenge = transcript.challenge_scalar(b"product-sumcheck-challenge");
            fold(&mut left, challenge)?;
            fold(&mut right, challenge)?;
            rounds.push(message);
            point.push(challenge);
        }
        let final_left = first_value(&left)?;
        let final_right = first_value(&right)?;
        absorb_finals(
            transcript,
            b"product-sumcheck-final",
            &[final_left, final_right],
        )?;
        Ok((
            Self {
                rounds,
                final_left,
                final_right,
            },
            claim,
            point,
        ))
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

impl MultiProductSumcheckProof {
    pub(crate) fn prove(
        factors: &[Vec<NativeField>],
        transcript: &mut AkitaTranscript<NativeField>,
    ) -> Result<(Self, NativeField, Vec<NativeField>), ProductSumcheckError> {
        let _phase = metrics::start(Phase::Sumcheck);
        validate_factors(factors)?;
        let mut factors = factors.to_vec();
        let claim = sum_of_products(&factors)?;
        let mut current_len = factors
            .first()
            .map(Vec::len)
            .ok_or(ProductSumcheckError::EmptyFactors)?;
        let mut rounds = Vec::with_capacity(variable_count(current_len)?);
        let mut point = Vec::with_capacity(rounds.capacity());
        while current_len > 1 {
            let message = multi_product_round(&factors)?;
            absorb_round(
                transcript,
                b"multi-product-sumcheck",
                rounds.len(),
                &message,
            )?;
            let challenge = transcript.challenge_scalar(b"multi-product-sumcheck-challenge");
            for factor in &mut factors {
                fold(factor, challenge)?;
            }
            current_len /= 2;
            rounds.push(message);
            point.push(challenge);
        }
        let final_factors = factors
            .iter()
            .map(|factor| first_value(factor))
            .collect::<Result<Vec<_>, _>>()?;
        absorb_finals(transcript, b"multi-product-sumcheck-final", &final_factors)?;
        Ok((
            Self {
                rounds,
                final_factors,
            },
            claim,
            point,
        ))
    }

    pub(crate) fn verify(
        &self,
        initial_claim: NativeField,
        expected_rounds: usize,
        expected_factors: usize,
        transcript: &mut AkitaTranscript<NativeField>,
    ) -> Result<Vec<NativeField>, ProductSumcheckError> {
        let expected_evaluations = expected_factors
            .checked_add(1)
            .ok_or(ProductSumcheckError::ProofShape)?;
        if self.rounds.len() != expected_rounds
            || self.final_factors.len() != expected_factors
            || self
                .rounds
                .iter()
                .any(|message| message.len() != expected_evaluations)
        {
            return Err(ProductSumcheckError::ProofShape);
        }
        let mut claim = initial_claim;
        let mut point = Vec::with_capacity(expected_rounds);
        for (round_index, message) in self.rounds.iter().enumerate() {
            let at_zero = message
                .first()
                .copied()
                .ok_or(ProductSumcheckError::ProofShape)?;
            let at_one = message
                .get(1)
                .copied()
                .ok_or(ProductSumcheckError::ProofShape)?;
            if at_zero + at_one != claim {
                return Err(ProductSumcheckError::RoundClaimMismatch);
            }
            absorb_round(transcript, b"multi-product-sumcheck", round_index, message)?;
            let challenge = transcript.challenge_scalar(b"multi-product-sumcheck-challenge");
            claim = evaluate_lagrange(message, challenge)?;
            point.push(challenge);
        }
        let final_claim = self
            .final_factors
            .iter()
            .copied()
            .fold(NativeField::from_u64(1), |product, factor| product * factor);
        if claim != final_claim {
            return Err(ProductSumcheckError::FinalClaimMismatch);
        }
        absorb_finals(
            transcript,
            b"multi-product-sumcheck-final",
            &self.final_factors,
        )?;
        Ok(point)
    }

    pub(crate) fn final_factors(&self) -> &[NativeField] {
        &self.final_factors
    }
}

impl SumOfProductsSumcheckProof {
    pub(crate) fn prove(
        terms: &[Vec<Vec<NativeField>>],
        transcript: &mut AkitaTranscript<NativeField>,
    ) -> Result<(Self, NativeField, Vec<NativeField>), ProductSumcheckError> {
        let _phase = metrics::start(Phase::Sumcheck);
        let (_, _, mut current_len) = validate_terms(terms)?;
        let claim = sum_of_term_products(terms)?;
        let mut terms = terms.to_vec();
        let mut rounds = Vec::with_capacity(variable_count(current_len)?);
        let mut point = Vec::with_capacity(rounds.capacity());
        while current_len > 1 {
            let message = sum_product_round(&terms)?;
            absorb_round(
                transcript,
                b"sum-of-products-sumcheck",
                rounds.len(),
                &message,
            )?;
            let challenge = transcript.challenge_scalar(b"sum-of-products-sumcheck-challenge");
            for term in &mut terms {
                for factor in term {
                    fold(factor, challenge)?;
                }
            }
            current_len /= 2;
            rounds.push(message);
            point.push(challenge);
        }
        let final_terms = terms
            .iter()
            .map(|term| term.iter().map(|factor| first_value(factor)).collect())
            .collect::<Result<Vec<Vec<_>>, _>>()?;
        absorb_term_finals(transcript, &final_terms)?;
        Ok((
            Self {
                rounds,
                final_terms,
            },
            claim,
            point,
        ))
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

fn validate_factors(factors: &[Vec<NativeField>]) -> Result<(), ProductSumcheckError> {
    let first = factors.first().ok_or(ProductSumcheckError::EmptyFactors)?;
    if first.is_empty() {
        return Err(ProductSumcheckError::EmptyTable);
    }
    if !first.len().is_power_of_two() {
        return Err(ProductSumcheckError::NonPowerOfTwo);
    }
    if factors.iter().any(|factor| factor.len() != first.len()) {
        return Err(ProductSumcheckError::LengthMismatch);
    }
    Ok(())
}

fn validate_terms(
    terms: &[Vec<Vec<NativeField>>],
) -> Result<(usize, usize, usize), ProductSumcheckError> {
    let first_term = terms.first().ok_or(ProductSumcheckError::EmptyFactors)?;
    let first_factor = first_term
        .first()
        .ok_or(ProductSumcheckError::EmptyFactors)?;
    if first_factor.is_empty() || !first_factor.len().is_power_of_two() {
        return Err(ProductSumcheckError::NonPowerOfTwo);
    }
    let factor_count = first_term.len();
    let table_len = first_factor.len();
    if terms.iter().any(|term| {
        term.len() != factor_count || term.iter().any(|factor| factor.len() != table_len)
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

fn inner_product(
    left: &[NativeField],
    right: &[NativeField],
) -> Result<NativeField, ProductSumcheckError> {
    validate_tables(left, right)?;
    Ok(left
        .iter()
        .copied()
        .zip(right.iter().copied())
        .fold(NativeField::from_u64(0), |sum, (left, right)| {
            sum + left * right
        }))
}

fn sum_of_products(factors: &[Vec<NativeField>]) -> Result<NativeField, ProductSumcheckError> {
    validate_factors(factors)?;
    let length = factors
        .first()
        .map(Vec::len)
        .ok_or(ProductSumcheckError::EmptyFactors)?;
    (0..length).try_fold(NativeField::from_u64(0), |sum, index| {
        let product = factors
            .iter()
            .try_fold(NativeField::from_u64(1), |product, factor| {
                factor
                    .get(index)
                    .copied()
                    .map(|value| product * value)
                    .ok_or(ProductSumcheckError::FoldingShape)
            })?;
        Ok(sum + product)
    })
}

fn sum_of_term_products(
    terms: &[Vec<Vec<NativeField>>],
) -> Result<NativeField, ProductSumcheckError> {
    let (_, _, length) = validate_terms(terms)?;
    (0..length).try_fold(NativeField::from_u64(0), |sum, index| {
        let row_sum = terms
            .iter()
            .try_fold(NativeField::from_u64(0), |term_sum, factors| {
                let product =
                    factors
                        .iter()
                        .try_fold(NativeField::from_u64(1), |product, factor| {
                            factor
                                .get(index)
                                .copied()
                                .map(|value| product * value)
                                .ok_or(ProductSumcheckError::FoldingShape)
                        })?;
                Ok::<_, ProductSumcheckError>(term_sum + product)
            })?;
        Ok(sum + row_sum)
    })
}

fn product_round(
    left: &[NativeField],
    right: &[NativeField],
) -> Result<[NativeField; 3], ProductSumcheckError> {
    validate_tables(left, right)?;
    if left.len() == 1 {
        return Err(ProductSumcheckError::FoldingShape);
    }
    let mut evaluations = [NativeField::from_u64(0); 3];
    for (left_pair, right_pair) in left.chunks_exact(2).zip(right.chunks_exact(2)) {
        let (left_zero, left_one) = pair_values(left_pair)?;
        let (right_zero, right_one) = pair_values(right_pair)?;
        for (point_index, evaluation) in evaluations.iter_mut().enumerate() {
            let point = usize_to_field(point_index)?;
            let left_at = left_zero + point * (left_one - left_zero);
            let right_at = right_zero + point * (right_one - right_zero);
            *evaluation += left_at * right_at;
        }
    }
    Ok(evaluations)
}

fn multi_product_round(
    factors: &[Vec<NativeField>],
) -> Result<Vec<NativeField>, ProductSumcheckError> {
    validate_factors(factors)?;
    let length = factors
        .first()
        .map(Vec::len)
        .ok_or(ProductSumcheckError::EmptyFactors)?;
    if length == 1 {
        return Err(ProductSumcheckError::FoldingShape);
    }
    let evaluation_count = factors
        .len()
        .checked_add(1)
        .ok_or(ProductSumcheckError::ProofShape)?;
    let mut evaluations = vec![NativeField::from_u64(0); evaluation_count];
    for pair_start in (0..length).step_by(2) {
        for (point_index, evaluation) in evaluations.iter_mut().enumerate() {
            let point = usize_to_field(point_index)?;
            let product =
                factors
                    .iter()
                    .try_fold(NativeField::from_u64(1), |product, factor| {
                        let zero = factor
                            .get(pair_start)
                            .copied()
                            .ok_or(ProductSumcheckError::FoldingShape)?;
                        let one = factor
                            .get(
                                pair_start
                                    .checked_add(1)
                                    .ok_or(ProductSumcheckError::FoldingShape)?,
                            )
                            .copied()
                            .ok_or(ProductSumcheckError::FoldingShape)?;
                        Ok::<_, ProductSumcheckError>(product * (zero + point * (one - zero)))
                    })?;
            *evaluation += product;
        }
    }
    Ok(evaluations)
}

fn sum_product_round(
    terms: &[Vec<Vec<NativeField>>],
) -> Result<Vec<NativeField>, ProductSumcheckError> {
    let (_, factor_count, length) = validate_terms(terms)?;
    if length == 1 {
        return Err(ProductSumcheckError::FoldingShape);
    }
    let mut evaluations = vec![NativeField::from_u64(0); factor_count + 1];
    for pair_start in (0..length).step_by(2) {
        for (point_index, evaluation) in evaluations.iter_mut().enumerate() {
            let point = usize_to_field(point_index)?;
            for factors in terms {
                let product =
                    factors
                        .iter()
                        .try_fold(NativeField::from_u64(1), |product, factor| {
                            let zero = factor
                                .get(pair_start)
                                .copied()
                                .ok_or(ProductSumcheckError::FoldingShape)?;
                            let one = factor
                                .get(pair_start + 1)
                                .copied()
                                .ok_or(ProductSumcheckError::FoldingShape)?;
                            Ok::<_, ProductSumcheckError>(product * (zero + point * (one - zero)))
                        })?;
                *evaluation += product;
            }
        }
    }
    Ok(evaluations)
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
    let mut folded = Vec::with_capacity(table.len() / 2);
    for pair in table.chunks_exact(2) {
        let (zero, one) = pair_values(pair)?;
        folded.push(zero + challenge * (one - zero));
    }
    *table = folded;
    Ok(())
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

    use super::{
        MultiProductSumcheckProof, NativeField, ProductSumcheckProof, SumOfProductsSumcheckProof,
    };

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
    fn multi_product_sumcheck_round_trip_and_tamper_rejection()
    -> Result<(), Box<dyn std::error::Error>> {
        let factors = [[1_u64, 2, 3, 4], [5_u64, 6, 7, 8], [2_u64, 0, 1, 3]]
            .map(|factor| factor.map(NativeField::from_u64).to_vec());
        let (proof, claim, prover_point) =
            MultiProductSumcheckProof::prove(&factors, &mut transcript(true))?;
        let verifier_point = proof.verify(claim, 2, 3, &mut transcript(false))?;
        assert_eq!(prover_point, verifier_point);

        let mut tampered = proof;
        let first = tampered
            .rounds
            .first_mut()
            .and_then(|round| round.first_mut())
            .ok_or("missing multi-product sumcheck round")?;
        *first += NativeField::from_u64(1);
        assert!(
            tampered
                .verify(claim, 2, 3, &mut transcript(false))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn sum_of_products_round_trip_and_tamper_rejection() -> Result<(), Box<dyn std::error::Error>> {
        let terms = vec![
            vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]],
            vec![vec![2, 0, 1, 3], vec![9, 2, 4, 1]],
        ]
        .into_iter()
        .map(|term| {
            term.into_iter()
                .map(|factor| factor.into_iter().map(NativeField::from_u64).collect())
                .collect()
        })
        .collect::<Vec<Vec<Vec<_>>>>();
        let (proof, claim, prover_point) =
            SumOfProductsSumcheckProof::prove(&terms, &mut transcript(true))?;
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
