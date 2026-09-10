//! Fiat-Shamir product sumcheck over two multilinear evaluation tables.

use ff::{Field, FromUniformBytes, PrimeField};
use pasta_curves::Fp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use thiserror::Error;

/// Proof that a claimed Boolean-hypercube sum equals the sum of two MLEs' product.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ProductSumcheckProof {
    rounds: Vec<[Fp; 3]>,
    final_left: Fp,
    final_right: Fp,
}

/// Sumcheck for a pointwise product of an arbitrary non-empty factor list.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct MultiProductSumcheckProof {
    rounds: Vec<Vec<Fp>>,
    final_factors: Vec<Fp>,
}

/// Deterministic domain-separated Fiat-Shamir transcript.
#[derive(Clone)]
pub(crate) struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    pub(crate) fn new(domain: &[u8], statement: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(domain.len() + statement.len() + 16);
        bytes.extend_from_slice(&(domain.len() as u64).to_le_bytes());
        bytes.extend_from_slice(domain);
        bytes.extend_from_slice(&(statement.len() as u64).to_le_bytes());
        bytes.extend_from_slice(statement);
        Self { bytes }
    }

    pub(crate) fn challenge(&mut self, label: &[u8], payload: &[u8]) -> Fp {
        self.bytes
            .extend_from_slice(&(label.len() as u64).to_le_bytes());
        self.bytes.extend_from_slice(label);
        self.bytes
            .extend_from_slice(&(payload.len() as u64).to_le_bytes());
        self.bytes.extend_from_slice(payload);
        let digest = Sha512::digest(&self.bytes);
        let mut uniform = [0_u8; 64];
        uniform.copy_from_slice(&digest);
        let challenge = Fp::from_uniform_bytes(&uniform);
        self.bytes.extend_from_slice(challenge.to_repr().as_ref());
        challenge
    }

    pub(crate) fn append(&mut self, label: &[u8], payload: &[u8]) {
        self.bytes
            .extend_from_slice(&(label.len() as u64).to_le_bytes());
        self.bytes.extend_from_slice(label);
        self.bytes
            .extend_from_slice(&(payload.len() as u64).to_le_bytes());
        self.bytes.extend_from_slice(payload);
    }
}

impl ProductSumcheckProof {
    pub(crate) fn prove(
        left: &[Fp],
        right: &[Fp],
        transcript: &mut Transcript,
    ) -> Result<(Self, Fp), ProductSumcheckError> {
        validate_tables(left, right)?;
        let mut left = left.to_vec();
        let mut right = right.to_vec();
        let claim = inner_product(&left, &right)?;
        let mut rounds = Vec::with_capacity(left.len().ilog2() as usize);
        while left.len() > 1 {
            let message = round_message(&left, &right)?;
            let challenge = transcript.challenge(b"product-sumcheck-round", &encode_round(message));
            fold(&mut left, challenge)?;
            fold(&mut right, challenge)?;
            rounds.push(message);
        }
        let final_left = left
            .first()
            .copied()
            .ok_or(ProductSumcheckError::EmptyTable)?;
        let final_right = right
            .first()
            .copied()
            .ok_or(ProductSumcheckError::EmptyTable)?;
        transcript.append(
            b"product-sumcheck-finals",
            &encode_round([final_left, final_right, Fp::ZERO]),
        );
        Ok((
            Self {
                rounds,
                final_left,
                final_right,
            },
            claim,
        ))
    }

    pub(crate) fn verify(
        &self,
        initial_claim: Fp,
        expected_rounds: usize,
        transcript: &mut Transcript,
    ) -> Result<Vec<Fp>, ProductSumcheckError> {
        if self.rounds.len() != expected_rounds {
            return Err(ProductSumcheckError::WrongRoundCount {
                actual: self.rounds.len(),
                expected: expected_rounds,
            });
        }
        let mut claim = initial_claim;
        let mut challenges = Vec::with_capacity(expected_rounds);
        for message in &self.rounds {
            let at_zero = message
                .first()
                .copied()
                .ok_or(ProductSumcheckError::FoldingShape)?;
            let at_one = message
                .get(1)
                .copied()
                .ok_or(ProductSumcheckError::FoldingShape)?;
            if at_zero + at_one != claim {
                return Err(ProductSumcheckError::RoundClaimMismatch);
            }
            let challenge =
                transcript.challenge(b"product-sumcheck-round", &encode_round(*message));
            claim = evaluate_quadratic(*message, challenge)?;
            challenges.push(challenge);
        }
        if claim != self.final_left * self.final_right {
            return Err(ProductSumcheckError::FinalClaimMismatch);
        }
        transcript.append(
            b"product-sumcheck-finals",
            &encode_round([self.final_left, self.final_right, Fp::ZERO]),
        );
        Ok(challenges)
    }

    pub(crate) const fn final_left(&self) -> Fp {
        self.final_left
    }

    pub(crate) const fn final_right(&self) -> Fp {
        self.final_right
    }

    pub(crate) fn round_count(&self) -> usize {
        self.rounds.len()
    }

    pub(crate) fn field_elements(&self) -> usize {
        self.rounds.len().saturating_mul(3).saturating_add(2)
    }
}

impl MultiProductSumcheckProof {
    pub(crate) fn prove(
        factors: &[Vec<Fp>],
        transcript: &mut Transcript,
    ) -> Result<(Self, Fp), ProductSumcheckError> {
        validate_factors(factors)?;
        let mut factors = factors.to_vec();
        let claim = sum_of_products(&factors)?;
        let mut current_len = factors
            .first()
            .map(Vec::len)
            .ok_or(ProductSumcheckError::EmptyFactors)?;
        let mut rounds = Vec::with_capacity(current_len.ilog2() as usize);
        while current_len > 1 {
            let message = multi_round_message(&factors)?;
            let challenge = transcript.challenge(
                b"multi-product-sumcheck-round",
                &encode_dynamic_round(&message),
            );
            for factor in &mut factors {
                fold(factor, challenge)?;
            }
            current_len /= 2;
            rounds.push(message);
        }
        let final_factors = factors
            .iter()
            .map(|factor| {
                factor
                    .first()
                    .copied()
                    .ok_or(ProductSumcheckError::EmptyTable)
            })
            .collect::<Result<Vec<_>, _>>()?;
        transcript.append(
            b"multi-product-sumcheck-finals",
            &encode_dynamic_round(&final_factors),
        );
        Ok((
            Self {
                rounds,
                final_factors,
            },
            claim,
        ))
    }

    pub(crate) fn verify(
        &self,
        initial_claim: Fp,
        expected_rounds: usize,
        expected_factors: usize,
        transcript: &mut Transcript,
    ) -> Result<Vec<Fp>, ProductSumcheckError> {
        if self.rounds.len() != expected_rounds {
            return Err(ProductSumcheckError::WrongRoundCount {
                actual: self.rounds.len(),
                expected: expected_rounds,
            });
        }
        if self.final_factors.len() != expected_factors {
            return Err(ProductSumcheckError::WrongFactorCount {
                actual: self.final_factors.len(),
                expected: expected_factors,
            });
        }
        let expected_evaluations = expected_factors
            .checked_add(1)
            .ok_or(ProductSumcheckError::FoldingShape)?;
        let mut claim = initial_claim;
        let mut challenges = Vec::with_capacity(expected_rounds);
        for message in &self.rounds {
            if message.len() != expected_evaluations {
                return Err(ProductSumcheckError::WrongRoundDegree {
                    actual: message.len().saturating_sub(1),
                    expected: expected_factors,
                });
            }
            let at_zero = message
                .first()
                .copied()
                .ok_or(ProductSumcheckError::FoldingShape)?;
            let at_one = message
                .get(1)
                .copied()
                .ok_or(ProductSumcheckError::FoldingShape)?;
            if at_zero + at_one != claim {
                return Err(ProductSumcheckError::RoundClaimMismatch);
            }
            let challenge = transcript.challenge(
                b"multi-product-sumcheck-round",
                &encode_dynamic_round(message),
            );
            claim = evaluate_lagrange(message, challenge)?;
            challenges.push(challenge);
        }
        let final_claim = self
            .final_factors
            .iter()
            .copied()
            .fold(Fp::ONE, |product, factor| product * factor);
        if claim != final_claim {
            return Err(ProductSumcheckError::FinalClaimMismatch);
        }
        transcript.append(
            b"multi-product-sumcheck-finals",
            &encode_dynamic_round(&self.final_factors),
        );
        Ok(challenges)
    }

    pub(crate) fn final_factors(&self) -> &[Fp] {
        &self.final_factors
    }

    pub(crate) fn field_elements(&self) -> usize {
        self.rounds
            .iter()
            .map(Vec::len)
            .sum::<usize>()
            .saturating_add(self.final_factors.len())
    }
}

/// A product sumcheck proof or input table is malformed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum ProductSumcheckError {
    /// At least one factor table is required.
    #[error("sumcheck factor list is empty")]
    EmptyFactors,
    /// Evaluation tables must be non-empty.
    #[error("sumcheck evaluation table is empty")]
    EmptyTable,
    /// Evaluation table lengths differ.
    #[error("sumcheck table lengths differ: {left} and {right}")]
    LengthMismatch { left: usize, right: usize },
    /// Multilinear evaluation tables require a power-of-two length.
    #[error("sumcheck table length {length} is not a power of two")]
    NonPowerOfTwo { length: usize },
    /// Proof has the wrong number of variable rounds.
    #[error("sumcheck has {actual} rounds, expected {expected}")]
    WrongRoundCount { actual: usize, expected: usize },
    /// Proof has the wrong number of terminal factor evaluations.
    #[error("sumcheck has {actual} factors, expected {expected}")]
    WrongFactorCount { actual: usize, expected: usize },
    /// A round polynomial has the wrong degree.
    #[error("sumcheck round has degree {actual}, expected {expected}")]
    WrongRoundDegree { actual: usize, expected: usize },
    /// A round polynomial does not sum to the prior claim at zero and one.
    #[error("sumcheck round does not match prior claim")]
    RoundClaimMismatch,
    /// Final oracle evaluations do not multiply to the reduced claim.
    #[error("sumcheck final oracle values do not match reduced claim")]
    FinalClaimMismatch,
    /// Fixed interpolation denominator unexpectedly had no inverse.
    #[error("sumcheck interpolation denominator is not invertible")]
    NonInvertibleInterpolation,
    /// Internal pair folding lost a table element.
    #[error("sumcheck folding shape invariant failed")]
    FoldingShape,
}

fn validate_factors(factors: &[Vec<Fp>]) -> Result<(), ProductSumcheckError> {
    let first = factors.first().ok_or(ProductSumcheckError::EmptyFactors)?;
    if first.is_empty() {
        return Err(ProductSumcheckError::EmptyTable);
    }
    if !first.len().is_power_of_two() {
        return Err(ProductSumcheckError::NonPowerOfTwo {
            length: first.len(),
        });
    }
    for factor in factors.iter().skip(1) {
        if factor.len() != first.len() {
            return Err(ProductSumcheckError::LengthMismatch {
                left: first.len(),
                right: factor.len(),
            });
        }
    }
    Ok(())
}

fn sum_of_products(factors: &[Vec<Fp>]) -> Result<Fp, ProductSumcheckError> {
    validate_factors(factors)?;
    let length = factors
        .first()
        .map(Vec::len)
        .ok_or(ProductSumcheckError::EmptyFactors)?;
    (0..length).try_fold(Fp::ZERO, |sum, index| {
        let product = factors.iter().try_fold(Fp::ONE, |product, factor| {
            factor
                .get(index)
                .copied()
                .map(|value| product * value)
                .ok_or(ProductSumcheckError::FoldingShape)
        })?;
        Ok(sum + product)
    })
}

fn multi_round_message(factors: &[Vec<Fp>]) -> Result<Vec<Fp>, ProductSumcheckError> {
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
        .ok_or(ProductSumcheckError::FoldingShape)?;
    let mut evaluations = vec![Fp::ZERO; evaluation_count];
    for pair_start in (0..length).step_by(2) {
        for (point, evaluation) in evaluations.iter_mut().enumerate() {
            let point =
                Fp::from(u64::try_from(point).map_err(|_| ProductSumcheckError::FoldingShape)?);
            let product = factors.iter().try_fold(Fp::ONE, |product, factor| {
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
    Ok(evaluations)
}

pub(crate) fn evaluate_lagrange(evaluations: &[Fp], point: Fp) -> Result<Fp, ProductSumcheckError> {
    let mut result = Fp::ZERO;
    for (index, evaluation) in evaluations.iter().enumerate() {
        let index_field =
            Fp::from(u64::try_from(index).map_err(|_| ProductSumcheckError::FoldingShape)?);
        let mut numerator = Fp::ONE;
        let mut denominator = Fp::ONE;
        for other in 0..evaluations.len() {
            if other == index {
                continue;
            }
            let other_field =
                Fp::from(u64::try_from(other).map_err(|_| ProductSumcheckError::FoldingShape)?);
            numerator *= point - other_field;
            denominator *= index_field - other_field;
        }
        let inverse = Option::<Fp>::from(denominator.invert())
            .ok_or(ProductSumcheckError::NonInvertibleInterpolation)?;
        result += evaluation * numerator * inverse;
    }
    Ok(result)
}

fn validate_tables(left: &[Fp], right: &[Fp]) -> Result<(), ProductSumcheckError> {
    if left.is_empty() {
        return Err(ProductSumcheckError::EmptyTable);
    }
    if left.len() != right.len() {
        return Err(ProductSumcheckError::LengthMismatch {
            left: left.len(),
            right: right.len(),
        });
    }
    if !left.len().is_power_of_two() {
        return Err(ProductSumcheckError::NonPowerOfTwo { length: left.len() });
    }
    Ok(())
}

fn inner_product(left: &[Fp], right: &[Fp]) -> Result<Fp, ProductSumcheckError> {
    validate_tables(left, right)?;
    Ok(left
        .iter()
        .zip(right)
        .fold(Fp::ZERO, |sum, (left, right)| sum + left * right))
}

fn round_message(left: &[Fp], right: &[Fp]) -> Result<[Fp; 3], ProductSumcheckError> {
    validate_tables(left, right)?;
    if left.len() == 1 {
        return Err(ProductSumcheckError::FoldingShape);
    }
    let mut evaluations = [Fp::ZERO; 3];
    for (left_pair, right_pair) in left.chunks_exact(2).zip(right.chunks_exact(2)) {
        let left_zero = left_pair
            .first()
            .copied()
            .ok_or(ProductSumcheckError::FoldingShape)?;
        let left_one = left_pair
            .get(1)
            .copied()
            .ok_or(ProductSumcheckError::FoldingShape)?;
        let right_zero = right_pair
            .first()
            .copied()
            .ok_or(ProductSumcheckError::FoldingShape)?;
        let right_one = right_pair
            .get(1)
            .copied()
            .ok_or(ProductSumcheckError::FoldingShape)?;
        for (point, evaluation) in evaluations.iter_mut().enumerate() {
            let point = Fp::from(point as u64);
            let left_at = left_zero + point * (left_one - left_zero);
            let right_at = right_zero + point * (right_one - right_zero);
            *evaluation += left_at * right_at;
        }
    }
    Ok(evaluations)
}

fn fold(table: &mut Vec<Fp>, challenge: Fp) -> Result<(), ProductSumcheckError> {
    if table.len() <= 1 || !table.len().is_power_of_two() {
        return Err(ProductSumcheckError::FoldingShape);
    }
    let mut folded = Vec::with_capacity(table.len() / 2);
    for pair in table.chunks_exact(2) {
        let zero = pair
            .first()
            .copied()
            .ok_or(ProductSumcheckError::FoldingShape)?;
        let one = pair
            .get(1)
            .copied()
            .ok_or(ProductSumcheckError::FoldingShape)?;
        folded.push(zero + challenge * (one - zero));
    }
    *table = folded;
    Ok(())
}

fn evaluate_quadratic(evaluations: [Fp; 3], point: Fp) -> Result<Fp, ProductSumcheckError> {
    let two_inverse = Option::<Fp>::from(Fp::from(2).invert())
        .ok_or(ProductSumcheckError::NonInvertibleInterpolation)?;
    let [at_zero, at_one, at_two] = evaluations;
    Ok(
        at_zero * (point - Fp::ONE) * (point - Fp::from(2)) * two_inverse
            - at_one * point * (point - Fp::from(2))
            + at_two * point * (point - Fp::ONE) * two_inverse,
    )
}

fn encode_round(round: [Fp; 3]) -> Vec<u8> {
    round
        .iter()
        .flat_map(|value| value.to_repr().as_ref().to_vec())
        .collect()
}

pub(crate) fn encode_dynamic_round(round: &[Fp]) -> Vec<u8> {
    round
        .iter()
        .flat_map(|value| value.to_repr().as_ref().to_vec())
        .collect()
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use pasta_curves::Fp;

    use super::{MultiProductSumcheckProof, ProductSumcheckProof, Transcript};

    #[test]
    fn product_sumcheck_round_trip_and_tamper_rejection() -> Result<(), Box<dyn std::error::Error>>
    {
        let left = [1_u64, 2, 3, 4].map(Fp::from);
        let right = [5_u64, 6, 7, 8].map(Fp::from);
        let mut prover_transcript = Transcript::new(b"test", b"statement");
        let (proof, claim) = ProductSumcheckProof::prove(&left, &right, &mut prover_transcript)?;
        let mut verifier_transcript = Transcript::new(b"test", b"statement");
        assert_eq!(proof.verify(claim, 2, &mut verifier_transcript)?.len(), 2);

        let mut tampered = proof;
        let first = tampered
            .rounds
            .first_mut()
            .ok_or_else(|| std::io::Error::other("missing sumcheck round"))?;
        let at_zero = first
            .first_mut()
            .ok_or_else(|| std::io::Error::other("missing zero evaluation"))?;
        *at_zero += Fp::ONE;
        let mut verifier_transcript = Transcript::new(b"test", b"statement");
        assert!(tampered.verify(claim, 2, &mut verifier_transcript).is_err());
        Ok(())
    }

    #[test]
    fn multi_product_sumcheck_round_trip_and_tamper_rejection()
    -> Result<(), Box<dyn std::error::Error>> {
        let factors = vec![
            [1_u64, 2, 3, 4].map(Fp::from).to_vec(),
            [5_u64, 6, 7, 8].map(Fp::from).to_vec(),
            [2_u64, 0, 1, 3].map(Fp::from).to_vec(),
            [4_u64, 3, 2, 1].map(Fp::from).to_vec(),
        ];
        let mut prover_transcript = Transcript::new(b"multi-test", b"statement");
        let (proof, claim) = MultiProductSumcheckProof::prove(&factors, &mut prover_transcript)?;
        let mut verifier_transcript = Transcript::new(b"multi-test", b"statement");
        assert_eq!(
            proof.verify(claim, 2, 4, &mut verifier_transcript)?.len(),
            2
        );

        let mut tampered = proof;
        let first = tampered
            .rounds
            .first_mut()
            .and_then(|round| round.first_mut())
            .ok_or_else(|| std::io::Error::other("missing sumcheck round"))?;
        *first += Fp::ONE;
        let mut verifier_transcript = Transcript::new(b"multi-test", b"statement");
        assert!(
            tampered
                .verify(claim, 2, 4, &mut verifier_transcript)
                .is_err()
        );
        Ok(())
    }
}
