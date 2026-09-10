//! Transparent inner-product polynomial commitments for multilinear tables.
//!
//! This is a binding, non-hiding commitment and a logarithmic-size opening
//! argument over the Vesta group. Parameters are deterministically generated
//! with independent hash-to-curve domains. Verification is linear in the
//! committed vector length; this module is the sound PCS boundary needed to
//! replace explicit terminal vectors, not yet the final fast-verifier PCS.

use ff::{Field, FromUniformBytes, PrimeField};
use halo2_proofs::arithmetic::{CurveExt, best_multiexp};
use pasta_curves::{
    Fp,
    group::{Curve, GroupEncoding},
    vesta,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use thiserror::Error;

use crate::{shout::eq_evaluations, sumcheck::Transcript};

const PCS_DOMAIN: &[u8] = b"zksm83-mle-ipa-pcs/v1";
const BATCH_DOMAIN: &[u8] = b"zksm83-mle-ipa-batch/v1";
const LINEAR_PCS_DOMAIN: &[u8] = b"zksm83-linear-ipa-pcs/v1";
const LINEAR_BATCH_DOMAIN: &[u8] = b"zksm83-linear-ipa-batch/v1";

/// A binding commitment to one power-of-two multilinear evaluation vector.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IpaCommitment(vesta::Affine);

/// Deterministic Vesta generators for one fixed vector length.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpaParameters {
    value_generators: Vec<vesta::Affine>,
    product_generator: vesta::Affine,
}

/// Logarithmic inner-product opening proof for one multilinear evaluation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IpaOpeningProof {
    left: Vec<vesta::Affine>,
    right: Vec<vesta::Affine>,
    final_value: Fp,
}

/// One logarithmic opening that binds evaluations of many committed columns.
///
/// The random linear-combination challenge is derived after absorbing every
/// claimed evaluation, so a prover cannot choose unbound per-column claims
/// after seeing the batching coefficients.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchedIpaOpeningProof {
    claimed_values: Vec<Fp>,
    opening: IpaOpeningProof,
}

/// One logarithmic batch opening against an arbitrary shared public vector.
///
/// This is used for shifted trace columns: the public vector is the shifted
/// multilinear equality vector derived from the sumcheck terminal point.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchedIpaLinearOpeningProof {
    claimed_values: Vec<Fp>,
    opening: IpaOpeningProof,
}

impl IpaParameters {
    /// Deterministically derives independent generators for `vector_len` entries.
    pub fn new(vector_len: usize) -> Result<Self, IpaError> {
        validate_vector_len(vector_len)?;
        let value_generators = derive_generators(b"value-generator", vector_len);
        let product_generator = derive_generator(b"product-generator", 0).to_affine();
        Ok(Self {
            value_generators,
            product_generator,
        })
    }

    /// Returns the committed vector length supported by these parameters.
    #[must_use]
    pub fn vector_len(&self) -> usize {
        self.value_generators.len()
    }

    /// Commits to a complete multilinear evaluation vector.
    pub fn commit(&self, values: &[Fp]) -> Result<IpaCommitment, IpaError> {
        self.require_values(values)?;
        Ok(IpaCommitment(
            best_multiexp(values, &self.value_generators).to_affine(),
        ))
    }

    /// Applies sparse additive updates to an existing vector commitment.
    /// Repeated indices are applied in order and therefore add together.
    pub fn apply_updates(
        &self,
        commitment: IpaCommitment,
        updates: &[(usize, Fp)],
    ) -> Result<IpaCommitment, IpaError> {
        let mut coefficients = Vec::with_capacity(updates.len());
        let mut generators = Vec::with_capacity(updates.len());
        for (index, delta) in updates {
            let generator = self.value_generators.get(*index).copied().ok_or(
                IpaError::UpdateIndexOutOfRange {
                    index: *index,
                    vector_len: self.vector_len(),
                },
            )?;
            coefficients.push(*delta);
            generators.push(generator);
        }
        let delta = best_multiexp(&coefficients, &generators);
        Ok(IpaCommitment(
            (vesta::Point::from(commitment.0) + delta).to_affine(),
        ))
    }

    /// Opens `values` at the multilinear point `point`.
    pub fn open(&self, values: &[Fp], point: &[Fp]) -> Result<IpaOpeningProof, IpaError> {
        self.require_values(values)?;
        self.require_point(point)?;
        let commitment = self.commit(values)?;
        self.open_precommitted(values, point, commitment)
    }

    /// Commits to each equally sized column independently.
    pub fn commit_batch(&self, columns: &[Vec<Fp>]) -> Result<Vec<IpaCommitment>, IpaError> {
        if columns.is_empty() {
            return Err(IpaError::EmptyBatch);
        }
        columns.iter().map(|column| self.commit(column)).collect()
    }

    /// Computes a public linear combination of commitments using the same
    /// coefficients as the corresponding committed vectors.
    pub fn combine_commitments(
        commitments: &[IpaCommitment],
        coefficients: &[Fp],
    ) -> Result<IpaCommitment, IpaError> {
        aggregate_commitments(commitments, coefficients)
    }

    /// Opens many committed columns at one shared multilinear point.
    ///
    /// Verification performs one length-`N` IPA verification plus a linear
    /// combination of column commitments, rather than one length-`N`
    /// verification per column.
    pub fn open_batch(
        &self,
        columns: &[Vec<Fp>],
        point: &[Fp],
    ) -> Result<(Vec<IpaCommitment>, BatchedIpaOpeningProof), IpaError> {
        self.require_point(point)?;
        let commitments = self.commit_batch(columns)?;
        let proof = self.open_batch_precommitted(columns, point, &commitments)?;
        Ok((commitments, proof))
    }

    pub(crate) fn open_batch_precommitted(
        &self,
        columns: &[Vec<Fp>],
        point: &[Fp],
        commitments: &[IpaCommitment],
    ) -> Result<BatchedIpaOpeningProof, IpaError> {
        if columns.is_empty() || columns.len() != commitments.len() {
            return Err(IpaError::BatchLengthMismatch {
                commitments: commitments.len(),
                claims: columns.len(),
            });
        }
        let claimed_values = columns
            .iter()
            .map(|column| evaluate_mle(column, point))
            .collect::<Result<Vec<_>, _>>()?;
        let challenge = batch_challenge(commitments, point, &claimed_values)?;
        let coefficients = powers(challenge, columns.len());
        let aggregate_values = aggregate_columns(columns, &coefficients, self.vector_len())?;
        let aggregate_commitment = aggregate_commitments(commitments, &coefficients)?;
        let opening = self.open_precommitted(&aggregate_values, point, aggregate_commitment)?;
        Ok(BatchedIpaOpeningProof {
            claimed_values,
            opening,
        })
    }

    /// Verifies a shared-point batch opening against only column commitments.
    pub fn verify_batch(
        &self,
        commitments: &[IpaCommitment],
        point: &[Fp],
        proof: &BatchedIpaOpeningProof,
    ) -> Result<(), IpaError> {
        self.require_point(point)?;
        if commitments.is_empty() {
            return Err(IpaError::EmptyBatch);
        }
        if commitments.len() != proof.claimed_values.len() {
            return Err(IpaError::BatchLengthMismatch {
                commitments: commitments.len(),
                claims: proof.claimed_values.len(),
            });
        }
        let challenge = batch_challenge(commitments, point, &proof.claimed_values)?;
        let coefficients = powers(challenge, commitments.len());
        let aggregate_commitment = aggregate_commitments(commitments, &coefficients)?;
        let aggregate_claim = inner_product(&proof.claimed_values, &coefficients)?;
        self.verify(aggregate_commitment, point, aggregate_claim, &proof.opening)
    }

    pub(crate) fn open_batch_linear_precommitted(
        &self,
        columns: &[Vec<Fp>],
        public_weights: &[Fp],
        commitments: &[IpaCommitment],
    ) -> Result<BatchedIpaLinearOpeningProof, IpaError> {
        if columns.is_empty() || columns.len() != commitments.len() {
            return Err(IpaError::BatchLengthMismatch {
                commitments: commitments.len(),
                claims: columns.len(),
            });
        }
        self.require_values(public_weights)?;
        let claimed_values = columns
            .iter()
            .map(|column| inner_product(column, public_weights))
            .collect::<Result<Vec<_>, _>>()?;
        let challenge = linear_batch_challenge(commitments, public_weights, &claimed_values)?;
        let coefficients = powers(challenge, columns.len());
        let aggregate_values = aggregate_columns(columns, &coefficients, self.vector_len())?;
        let aggregate_commitment = aggregate_commitments(commitments, &coefficients)?;
        let aggregate_claim = inner_product(&claimed_values, &coefficients)?;
        let transcript =
            linear_opening_transcript(aggregate_commitment, public_weights, aggregate_claim);
        let opening =
            self.open_with_public(&aggregate_values, public_weights.to_vec(), transcript)?;
        Ok(BatchedIpaLinearOpeningProof {
            claimed_values,
            opening,
        })
    }

    /// Opens many columns against one arbitrary shared public weight vector.
    pub fn open_batch_linear(
        &self,
        columns: &[Vec<Fp>],
        public_weights: &[Fp],
    ) -> Result<(Vec<IpaCommitment>, BatchedIpaLinearOpeningProof), IpaError> {
        let commitments = self.commit_batch(columns)?;
        let proof = self.open_batch_linear_precommitted(columns, public_weights, &commitments)?;
        Ok((commitments, proof))
    }

    /// Verifies a shared arbitrary-linear opening for many commitments.
    pub fn verify_batch_linear(
        &self,
        commitments: &[IpaCommitment],
        public_weights: &[Fp],
        proof: &BatchedIpaLinearOpeningProof,
    ) -> Result<(), IpaError> {
        self.require_values(public_weights)?;
        if commitments.is_empty() || commitments.len() != proof.claimed_values.len() {
            return Err(IpaError::BatchLengthMismatch {
                commitments: commitments.len(),
                claims: proof.claimed_values.len(),
            });
        }
        let challenge = linear_batch_challenge(commitments, public_weights, &proof.claimed_values)?;
        let coefficients = powers(challenge, commitments.len());
        let aggregate_commitment = aggregate_commitments(commitments, &coefficients)?;
        let aggregate_claim = inner_product(&proof.claimed_values, &coefficients)?;
        let transcript =
            linear_opening_transcript(aggregate_commitment, public_weights, aggregate_claim);
        self.verify_with_public(
            aggregate_commitment,
            public_weights,
            aggregate_claim,
            &proof.opening,
            transcript,
        )
    }

    pub(crate) fn open_precommitted(
        &self,
        values: &[Fp],
        point: &[Fp],
        commitment: IpaCommitment,
    ) -> Result<IpaOpeningProof, IpaError> {
        self.require_values(values)?;
        self.require_point(point)?;
        let public = eq_evaluations(point).map_err(|_| IpaError::PointShape)?;
        let claimed_value = inner_product(values, &public)?;
        let transcript = opening_transcript(commitment, point, claimed_value);
        self.open_with_public(values, public, transcript)
    }

    fn open_with_public(
        &self,
        values: &[Fp],
        public: Vec<Fp>,
        mut transcript: Transcript,
    ) -> Result<IpaOpeningProof, IpaError> {
        self.require_values(values)?;
        self.require_values(&public)?;
        let mut private = values.to_vec();
        let mut public = public;
        let mut value_generators = self.value_generators.clone();
        let expected_rounds = self.vector_len().ilog2() as usize;
        let mut left = Vec::with_capacity(expected_rounds);
        let mut right = Vec::with_capacity(expected_rounds);

        while private.len() > 1 {
            let half = private.len() / 2;
            let (private_low, private_high) = private.split_at(half);
            let (public_low, public_high) = public.split_at(half);
            let (value_low, value_high) = value_generators.split_at(half);

            let left_product = inner_product(private_low, public_high)?;
            let right_product = inner_product(private_high, public_low)?;
            let left_point = (best_multiexp(private_low, value_high)
                + self.product_generator * left_product)
                .to_affine();
            let right_point = (best_multiexp(private_high, value_low)
                + self.product_generator * right_product)
                .to_affine();
            let challenge = round_challenge(&mut transcript, left_point, right_point)?;
            let inverse = Option::<Fp>::from(challenge.invert()).ok_or(IpaError::ZeroChallenge)?;

            private = fold_scalars(private_low, private_high, challenge, inverse)?;
            public = fold_scalars(public_low, public_high, inverse, challenge)?;
            value_generators = fold_generators(value_low, value_high, inverse, challenge)?;
            left.push(left_point);
            right.push(right_point);
        }

        let final_value = private.first().copied().ok_or(IpaError::VectorShape)?;
        transcript.append(b"ipa-final-value", final_value.to_repr().as_ref());
        Ok(IpaOpeningProof {
            left,
            right,
            final_value,
        })
    }

    /// Verifies one opening against only the commitment, point, and claimed value.
    pub fn verify(
        &self,
        commitment: IpaCommitment,
        point: &[Fp],
        claimed_value: Fp,
        proof: &IpaOpeningProof,
    ) -> Result<(), IpaError> {
        self.require_point(point)?;
        if proof.left.len() != point.len() || proof.right.len() != point.len() {
            return Err(IpaError::ProofShape);
        }
        let public = eq_evaluations(point).map_err(|_| IpaError::PointShape)?;
        let transcript = opening_transcript(commitment, point, claimed_value);
        self.verify_with_public(commitment, &public, claimed_value, proof, transcript)
    }

    fn verify_with_public(
        &self,
        commitment: IpaCommitment,
        public: &[Fp],
        claimed_value: Fp,
        proof: &IpaOpeningProof,
        mut transcript: Transcript,
    ) -> Result<(), IpaError> {
        self.require_values(public)?;
        let expected_rounds = self.vector_len().ilog2() as usize;
        if proof.left.len() != expected_rounds || proof.right.len() != expected_rounds {
            return Err(IpaError::ProofShape);
        }
        let mut expected =
            vesta::Point::from(commitment.0) + self.product_generator * claimed_value;
        let mut generator_weights = vec![Fp::ONE];

        for (left, right) in proof.left.iter().copied().zip(proof.right.iter().copied()) {
            let challenge = round_challenge(&mut transcript, left, right)?;
            let inverse = Option::<Fp>::from(challenge.invert()).ok_or(IpaError::ZeroChallenge)?;
            let challenge_squared = challenge.square();
            let inverse_squared = inverse.square();
            expected += left * challenge_squared + right * inverse_squared;
            generator_weights = expand_generator_weights(&generator_weights, inverse, challenge)?;
        }

        if generator_weights.len() != self.value_generators.len() {
            return Err(IpaError::ProofShape);
        }
        let public_final = inner_product(public, &generator_weights)?;
        let value_generator = best_multiexp(&generator_weights, &self.value_generators);
        let actual = value_generator * proof.final_value
            + self.product_generator * (proof.final_value * public_final);
        transcript.append(b"ipa-final-value", proof.final_value.to_repr().as_ref());
        if actual == expected {
            Ok(())
        } else {
            Err(IpaError::OpeningMismatch)
        }
    }

    fn require_values(&self, values: &[Fp]) -> Result<(), IpaError> {
        if values.len() == self.vector_len() {
            Ok(())
        } else {
            Err(IpaError::VectorShape)
        }
    }

    fn require_point(&self, point: &[Fp]) -> Result<(), IpaError> {
        let expected =
            usize::try_from(self.vector_len().ilog2()).map_err(|_| IpaError::PointShape)?;
        if point.len() == expected {
            Ok(())
        } else {
            Err(IpaError::PointShape)
        }
    }
}

impl IpaCommitment {
    /// Returns the canonical compressed Vesta encoding.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl IpaOpeningProof {
    /// Returns the proof size in curve points and scalar field elements.
    #[must_use]
    pub fn element_count(&self) -> (usize, usize) {
        (self.left.len().saturating_add(self.right.len()), 1)
    }
}

impl BatchedIpaOpeningProof {
    /// Returns the ordered claimed MLE evaluations, one per commitment.
    #[must_use]
    pub fn claimed_values(&self) -> &[Fp] {
        &self.claimed_values
    }

    /// Returns the proof size in curve points and scalar field elements.
    #[must_use]
    pub fn element_count(&self) -> (usize, usize) {
        let (points, scalars) = self.opening.element_count();
        (points, scalars.saturating_add(self.claimed_values.len()))
    }
}

impl BatchedIpaLinearOpeningProof {
    /// Returns the ordered claimed linear evaluations, one per commitment.
    #[must_use]
    pub fn claimed_values(&self) -> &[Fp] {
        &self.claimed_values
    }

    /// Returns the proof size in curve points and scalar field elements.
    #[must_use]
    pub fn element_count(&self) -> (usize, usize) {
        let (points, scalars) = self.opening.element_count();
        (points, scalars.saturating_add(self.claimed_values.len()))
    }
}

/// A transparent IPA commitment or opening is malformed or invalid.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum IpaError {
    /// The committed vector must be a non-empty power of two.
    #[error("IPA vector length must be a non-empty power of two")]
    VectorShape,
    /// A batch opening must contain at least one column.
    #[error("IPA batch opening requires at least one column")]
    EmptyBatch,
    /// The verifier received a different number of commitments and claims.
    #[error("IPA batch has {commitments} commitments but {claims} claimed values")]
    BatchLengthMismatch {
        /// Number of committed trace columns.
        commitments: usize,
        /// Number of claimed evaluations in the proof.
        claims: usize,
    },
    /// The evaluation point dimension does not match the vector length.
    #[error("IPA multilinear point dimension does not match the vector length")]
    PointShape,
    /// The opening proof has a non-canonical number of rounds.
    #[error("IPA opening proof has the wrong number of rounds")]
    ProofShape,
    /// A Fiat-Shamir challenge was zero and could not be inverted.
    #[error("IPA Fiat-Shamir challenge is zero")]
    ZeroChallenge,
    /// The claimed multilinear evaluation is not bound by the commitment.
    #[error("IPA opening verification failed")]
    OpeningMismatch,
    /// A sparse commitment update addressed outside the committed vector.
    #[error("IPA update index {index} is outside vector length {vector_len}")]
    UpdateIndexOutOfRange {
        /// Rejected zero-based index.
        index: usize,
        /// Committed vector length.
        vector_len: usize,
    },
}

fn validate_vector_len(vector_len: usize) -> Result<(), IpaError> {
    if vector_len == 0 || !vector_len.is_power_of_two() {
        Err(IpaError::VectorShape)
    } else {
        Ok(())
    }
}

fn evaluate_mle(values: &[Fp], point: &[Fp]) -> Result<Fp, IpaError> {
    if values.is_empty()
        || !values.len().is_power_of_two()
        || values.len().ilog2() as usize != point.len()
    {
        return Err(IpaError::VectorShape);
    }
    let mut folded = values.to_vec();
    for challenge in point {
        let mut next = Vec::with_capacity(folded.len() / 2);
        for pair in folded.chunks_exact(2) {
            let low = pair.first().copied().ok_or(IpaError::VectorShape)?;
            let high = pair.get(1).copied().ok_or(IpaError::VectorShape)?;
            next.push(low + *challenge * (high - low));
        }
        folded = next;
    }
    folded.first().copied().ok_or(IpaError::VectorShape)
}

fn batch_challenge(
    commitments: &[IpaCommitment],
    point: &[Fp],
    claimed_values: &[Fp],
) -> Result<Fp, IpaError> {
    if commitments.is_empty() || commitments.len() != claimed_values.len() {
        return Err(IpaError::BatchLengthMismatch {
            commitments: commitments.len(),
            claims: claimed_values.len(),
        });
    }
    let mut transcript = Sha512::new();
    transcript.update(BATCH_DOMAIN);
    transcript.update((commitments.len() as u64).to_le_bytes());
    for commitment in commitments {
        transcript.update(commitment.to_bytes());
    }
    transcript.update((point.len() as u64).to_le_bytes());
    for coordinate in point {
        transcript.update(coordinate.to_repr().as_ref());
    }
    for value in claimed_values {
        transcript.update(value.to_repr().as_ref());
    }
    let digest = transcript.finalize();
    let mut uniform = [0_u8; 64];
    uniform.copy_from_slice(&digest);
    let challenge = Fp::from_uniform_bytes(&uniform);
    if challenge == Fp::ZERO {
        Err(IpaError::ZeroChallenge)
    } else {
        Ok(challenge)
    }
}

fn linear_batch_challenge(
    commitments: &[IpaCommitment],
    public_weights: &[Fp],
    claimed_values: &[Fp],
) -> Result<Fp, IpaError> {
    if commitments.is_empty() || commitments.len() != claimed_values.len() {
        return Err(IpaError::BatchLengthMismatch {
            commitments: commitments.len(),
            claims: claimed_values.len(),
        });
    }
    if public_weights.is_empty() || !public_weights.len().is_power_of_two() {
        return Err(IpaError::VectorShape);
    }
    let mut transcript = Sha512::new();
    transcript.update(LINEAR_BATCH_DOMAIN);
    transcript.update((commitments.len() as u64).to_le_bytes());
    for commitment in commitments {
        transcript.update(commitment.to_bytes());
    }
    transcript.update(linear_weights_digest(public_weights));
    for value in claimed_values {
        transcript.update(value.to_repr().as_ref());
    }
    nonzero_challenge(transcript.finalize())
}

fn nonzero_challenge(digest: impl AsRef<[u8]>) -> Result<Fp, IpaError> {
    let bytes = digest.as_ref();
    if bytes.len() != 64 {
        return Err(IpaError::ProofShape);
    }
    let mut uniform = [0_u8; 64];
    uniform.copy_from_slice(bytes);
    let challenge = Fp::from_uniform_bytes(&uniform);
    if challenge == Fp::ZERO {
        Err(IpaError::ZeroChallenge)
    } else {
        Ok(challenge)
    }
}

fn linear_weights_digest(public_weights: &[Fp]) -> [u8; 64] {
    let mut digest = Sha512::new();
    digest.update((public_weights.len() as u64).to_le_bytes());
    for weight in public_weights {
        digest.update(weight.to_repr().as_ref());
    }
    digest.finalize().into()
}

fn powers(challenge: Fp, count: usize) -> Vec<Fp> {
    let mut current = Fp::ONE;
    (0..count)
        .map(|_| {
            let coefficient = current;
            current *= challenge;
            coefficient
        })
        .collect()
}

fn aggregate_columns(
    columns: &[Vec<Fp>],
    coefficients: &[Fp],
    vector_len: usize,
) -> Result<Vec<Fp>, IpaError> {
    if columns.is_empty() || columns.len() != coefficients.len() {
        return Err(IpaError::BatchLengthMismatch {
            commitments: columns.len(),
            claims: coefficients.len(),
        });
    }
    let mut aggregate = vec![Fp::ZERO; vector_len];
    for (column, coefficient) in columns.iter().zip(coefficients) {
        if column.len() != vector_len {
            return Err(IpaError::VectorShape);
        }
        for (target, value) in aggregate.iter_mut().zip(column) {
            *target += *value * coefficient;
        }
    }
    Ok(aggregate)
}

fn aggregate_commitments(
    commitments: &[IpaCommitment],
    coefficients: &[Fp],
) -> Result<IpaCommitment, IpaError> {
    if commitments.is_empty() || commitments.len() != coefficients.len() {
        return Err(IpaError::BatchLengthMismatch {
            commitments: commitments.len(),
            claims: coefficients.len(),
        });
    }
    let points = commitments
        .iter()
        .map(|commitment| commitment.0)
        .collect::<Vec<_>>();
    Ok(IpaCommitment(
        best_multiexp(coefficients, &points).to_affine(),
    ))
}

fn derive_generators(label: &[u8], count: usize) -> Vec<vesta::Affine> {
    let workers = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let chunk_len = count.div_ceil(workers);
    let mut projective = vec![vesta::Point::default(); count];
    std::thread::scope(|scope| {
        for (chunk_index, output) in projective.chunks_mut(chunk_len).enumerate() {
            scope.spawn(move || {
                let hasher = vesta::Point::hash_to_curve("zksm83-mle-ipa-generator/v1");
                let start = chunk_index.saturating_mul(chunk_len);
                for (offset, target) in output.iter_mut().enumerate() {
                    *target = hasher(&generator_input(label, start.saturating_add(offset)));
                }
            });
        }
    });
    let mut affine = vec![vesta::Affine::default(); count];
    vesta::Point::batch_normalize(&projective, &mut affine);
    affine
}

fn derive_generator(label: &[u8], index: usize) -> vesta::Point {
    let hasher = vesta::Point::hash_to_curve("zksm83-mle-ipa-generator/v1");
    hasher(&generator_input(label, index))
}

fn generator_input(label: &[u8], index: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(label.len().saturating_add(16));
    input.extend_from_slice(&(label.len() as u64).to_le_bytes());
    input.extend_from_slice(label);
    input.extend_from_slice(&(index as u64).to_le_bytes());
    input
}

fn opening_transcript(commitment: IpaCommitment, point: &[Fp], claimed_value: Fp) -> Transcript {
    let mut statement = Vec::with_capacity(80_usize.saturating_add(point.len().saturating_mul(32)));
    statement.extend_from_slice(&commitment.to_bytes());
    statement.extend_from_slice(&(point.len() as u64).to_le_bytes());
    for coordinate in point {
        statement.extend_from_slice(coordinate.to_repr().as_ref());
    }
    statement.extend_from_slice(claimed_value.to_repr().as_ref());
    Transcript::new(PCS_DOMAIN, &statement)
}

fn linear_opening_transcript(
    commitment: IpaCommitment,
    public_weights: &[Fp],
    claimed_value: Fp,
) -> Transcript {
    let mut statement = Vec::with_capacity(128);
    statement.extend_from_slice(&commitment.to_bytes());
    statement.extend_from_slice(&linear_weights_digest(public_weights));
    statement.extend_from_slice(claimed_value.to_repr().as_ref());
    Transcript::new(LINEAR_PCS_DOMAIN, &statement)
}

fn round_challenge(
    transcript: &mut Transcript,
    left: vesta::Affine,
    right: vesta::Affine,
) -> Result<Fp, IpaError> {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(left.to_bytes().as_ref());
    payload.extend_from_slice(right.to_bytes().as_ref());
    let challenge = transcript.challenge(b"ipa-round", &payload);
    if challenge == Fp::ZERO {
        Err(IpaError::ZeroChallenge)
    } else {
        Ok(challenge)
    }
}

fn inner_product(left: &[Fp], right: &[Fp]) -> Result<Fp, IpaError> {
    if left.len() != right.len() || left.is_empty() {
        return Err(IpaError::VectorShape);
    }
    Ok(left
        .iter()
        .zip(right)
        .fold(Fp::ZERO, |sum, (left, right)| sum + left * right))
}

fn fold_scalars(
    low: &[Fp],
    high: &[Fp],
    low_weight: Fp,
    high_weight: Fp,
) -> Result<Vec<Fp>, IpaError> {
    if low.len() != high.len() || low.is_empty() {
        return Err(IpaError::ProofShape);
    }
    Ok(low
        .iter()
        .zip(high)
        .map(|(low, high)| *low * low_weight + *high * high_weight)
        .collect())
}

fn fold_generators(
    low: &[vesta::Affine],
    high: &[vesta::Affine],
    low_weight: Fp,
    high_weight: Fp,
) -> Result<Vec<vesta::Affine>, IpaError> {
    if low.len() != high.len() || low.is_empty() {
        return Err(IpaError::ProofShape);
    }
    let workers = worker_count(low.len());
    let chunk_len = low.len().div_ceil(workers);
    let mut projective = vec![vesta::Point::default(); low.len()];
    std::thread::scope(|scope| {
        for ((output, low_chunk), high_chunk) in projective
            .chunks_mut(chunk_len)
            .zip(low.chunks(chunk_len))
            .zip(high.chunks(chunk_len))
        {
            scope.spawn(move || {
                for ((target, low), high) in output.iter_mut().zip(low_chunk).zip(high_chunk) {
                    *target = *low * low_weight + *high * high_weight;
                }
            });
        }
    });
    let mut affine = vec![vesta::Affine::default(); low.len()];
    std::thread::scope(|scope| {
        for (output, projective_chunk) in affine
            .chunks_mut(chunk_len)
            .zip(projective.chunks(chunk_len))
        {
            scope.spawn(move || vesta::Point::batch_normalize(projective_chunk, output));
        }
    });
    Ok(affine)
}

fn expand_generator_weights(
    weights: &[Fp],
    low_weight: Fp,
    high_weight: Fp,
) -> Result<Vec<Fp>, IpaError> {
    if weights.is_empty() {
        return Err(IpaError::ProofShape);
    }
    let capacity = weights.len().checked_mul(2).ok_or(IpaError::ProofShape)?;
    let mut expanded = Vec::with_capacity(capacity);
    for weight in weights {
        expanded.push(*weight * low_weight);
        expanded.push(*weight * high_weight);
    }
    Ok(expanded)
}

fn worker_count(item_count: usize) -> usize {
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .min(item_count.max(1))
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use pasta_curves::Fp;

    use super::{IpaError, IpaParameters};

    #[test]
    fn ipa_opens_mle_and_rejects_wrong_statement() -> Result<(), Box<dyn std::error::Error>> {
        let values = [2_u64, 3, 5, 7, 11, 13, 17, 19].map(Fp::from);
        let point = [Fp::from(23), Fp::from(29), Fp::from(31)];
        let parameters = IpaParameters::new(values.len())?;
        let commitment = parameters.commit(&values)?;
        let proof = parameters.open(&values, &point)?;
        let weights = crate::shout::eq_evaluations(&point)?;
        let claimed = values
            .iter()
            .zip(weights)
            .fold(Fp::ZERO, |sum, (value, weight)| sum + value * weight);
        parameters.verify(commitment, &point, claimed, &proof)?;
        assert_eq!(proof.element_count(), (6, 1));

        assert!(
            parameters
                .verify(commitment, &point, claimed + Fp::ONE, &proof)
                .is_err()
        );
        let mut wrong_point = point;
        let coordinate = wrong_point
            .get_mut(1)
            .ok_or_else(|| std::io::Error::other("missing IPA point coordinate"))?;
        *coordinate += Fp::ONE;
        assert!(
            parameters
                .verify(commitment, &wrong_point, claimed, &proof)
                .is_err()
        );
        let other = [3_u64, 5, 8, 13, 21, 34, 55, 89].map(Fp::from);
        let wrong_commitment = parameters.commit(&other)?;
        assert!(
            parameters
                .verify(wrong_commitment, &point, claimed, &proof)
                .is_err()
        );

        let updates = [(2, Fp::from(7)), (5, -Fp::from(9))];
        let updated_commitment = parameters.apply_updates(commitment, &updates)?;
        let mut updated_values = values;
        let third = updated_values
            .get_mut(2)
            .ok_or_else(|| std::io::Error::other("missing third IPA value"))?;
        *third += Fp::from(7);
        let sixth = updated_values
            .get_mut(5)
            .ok_or_else(|| std::io::Error::other("missing sixth IPA value"))?;
        *sixth -= Fp::from(9);
        assert_eq!(updated_commitment, parameters.commit(&updated_values)?);
        Ok(())
    }

    #[test]
    fn batch_ipa_binds_each_claim_and_commitment_with_one_opening()
    -> Result<(), Box<dyn std::error::Error>> {
        let columns = vec![
            [2_u64, 3, 5, 7, 11, 13, 17, 19].map(Fp::from).to_vec(),
            [23_u64, 29, 31, 37, 41, 43, 47, 53].map(Fp::from).to_vec(),
            [59_u64, 61, 67, 71, 73, 79, 83, 89].map(Fp::from).to_vec(),
        ];
        let point = [Fp::from(97), Fp::from(101), Fp::from(103)];
        let parameters = IpaParameters::new(8)?;
        let (commitments, proof) = parameters.open_batch(&columns, &point)?;
        parameters.verify_batch(&commitments, &point, &proof)?;
        assert_eq!(proof.claimed_values().len(), 3);
        assert_eq!(proof.element_count(), (6, 4));

        let mut wrong_claim = proof.clone();
        let claim = wrong_claim
            .claimed_values
            .get_mut(1)
            .ok_or_else(|| std::io::Error::other("missing second batch claim"))?;
        *claim += Fp::ONE;
        assert_eq!(
            parameters.verify_batch(&commitments, &point, &wrong_claim),
            Err(IpaError::OpeningMismatch)
        );
        let mut wrong_commitments = commitments.clone();
        wrong_commitments.swap(0, 1);
        assert_eq!(
            parameters.verify_batch(&wrong_commitments, &point, &proof),
            Err(IpaError::OpeningMismatch)
        );
        assert!(
            parameters
                .verify_batch(&commitments, &[Fp::from(107), point[1], point[2]], &proof)
                .is_err()
        );
        Ok(())
    }
}
