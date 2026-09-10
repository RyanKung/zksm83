//! Shout read-only batch evaluation with explicit query and table oracles.
//!
//! The sumcheck proof is logarithmic, but the current verifier receives the
//! complete query vector and table to check the two terminal MLE evaluations.
//! Polynomial opening proofs will replace those explicit oracles before this
//! module can produce a standalone succinct receipt.

use ff::{Field, FromUniformBytes, PrimeField};
use pasta_curves::Fp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use thiserror::Error;

use crate::{
    ipa::{BatchedIpaOpeningProof, IpaCommitment, IpaError, IpaOpeningProof, IpaParameters},
    sumcheck::{MultiProductSumcheckProof, ProductSumcheckError, ProductSumcheckProof, Transcript},
};

/// One address and claimed value in a read-only batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadOnlyQuery {
    /// Zero-based table address.
    pub address: usize,
    /// Claimed table value.
    pub value: Fp,
}

/// Logarithmic Shout sumcheck proof with explicit terminal oracles.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExplicitShoutProof {
    query_count: usize,
    padded_query_count: usize,
    sumcheck: ProductSumcheckProof,
}

/// Shout proof whose read-only table terminal is bound by an IPA commitment.
///
/// The verifier still receives the ordered query vector. The segment-to-lookup
/// bridge must bind that vector before this can be used as a standalone receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommittedShoutProof {
    table_size: usize,
    query_count: usize,
    padded_query_count: usize,
    table_commitment: IpaCommitment,
    sumcheck: ProductSumcheckProof,
    table_opening: IpaOpeningProof,
}

/// Shout proof with PCS-bound query-address bits, query values, and table.
///
/// The address-bit commitments are intended to be the exact same commitments
/// consumed by a low-degree VM glue proof. That glue proof must enforce bitness
/// and reconstruct the canonical address from these columns. This proof then
/// establishes that every committed query value equals the committed table at
/// that address without exposing the query vector to the verifier.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommittedQueryShoutProof {
    table_size: usize,
    query_count: usize,
    table_commitment: IpaCommitment,
    address_bit_commitments: Vec<IpaCommitment>,
    value_commitment: IpaCommitment,
    claimed_output: Fp,
    table_sumcheck: ProductSumcheckProof,
    address_sumcheck: MultiProductSumcheckProof,
    table_opening: IpaOpeningProof,
    value_opening: IpaOpeningProof,
    address_bits_opening: BatchedIpaOpeningProof,
}

/// Random-linear-combination batching of many output columns sharing one
/// committed Shout query-address vector.
///
/// The batching challenge is derived after every table and query-output
/// commitment is fixed, so one inner lookup binds all columns except with
/// negligible field soundness error.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommittedMultiQueryShoutProof {
    column_count: usize,
    inner: CommittedQueryShoutProof,
}

impl ExplicitShoutProof {
    /// Proves the batch-evaluation relation against an explicit power-of-two table.
    pub fn prove(table: &[Fp], queries: &[ReadOnlyQuery]) -> Result<Self, ExplicitShoutError> {
        validate_instance(table, queries)?;
        let padded_query_count = queries
            .len()
            .checked_next_power_of_two()
            .ok_or(ExplicitShoutError::QueryCountOverflow)?;
        let padded = padded_queries(table, queries, padded_query_count)?;
        let statement = statement_digest(table, queries);
        let mut transcript = Transcript::new(b"zksm83-explicit-shout/v1", &statement);
        let cycle_challenges = challenges(&mut transcript, b"cycle-variable", padded.len().ilog2());
        let cycle_weights = eq_evaluations(&cycle_challenges)?;
        let mut read_address = vec![Fp::ZERO; table.len()];
        for (query, weight) in padded.iter().zip(&cycle_weights) {
            let target = read_address.get_mut(query.address).ok_or(
                ExplicitShoutError::AddressOutOfRange {
                    address: query.address,
                    table_size: table.len(),
                },
            )?;
            *target += weight;
        }
        let (sumcheck, _actual_claim) =
            ProductSumcheckProof::prove(&read_address, table, &mut transcript)?;
        Ok(Self {
            query_count: queries.len(),
            padded_query_count,
            sumcheck,
        })
    }

    /// Verifies the batch against explicit query and table vectors.
    pub fn verify(
        &self,
        table: &[Fp],
        queries: &[ReadOnlyQuery],
    ) -> Result<(), ExplicitShoutError> {
        validate_instance(table, queries)?;
        if self.query_count != queries.len() {
            return Err(ExplicitShoutError::QueryCountMismatch {
                proof: self.query_count,
                instance: queries.len(),
            });
        }
        let expected_padded = queries
            .len()
            .checked_next_power_of_two()
            .ok_or(ExplicitShoutError::QueryCountOverflow)?;
        if self.padded_query_count != expected_padded {
            return Err(ExplicitShoutError::PaddedQueryCountMismatch {
                proof: self.padded_query_count,
                expected: expected_padded,
            });
        }
        let padded = padded_queries(table, queries, expected_padded)?;
        let statement = statement_digest(table, queries);
        let mut transcript = Transcript::new(b"zksm83-explicit-shout/v1", &statement);
        let cycle_challenges = challenges(&mut transcript, b"cycle-variable", padded.len().ilog2());
        let cycle_weights = eq_evaluations(&cycle_challenges)?;
        let claimed_output = padded
            .iter()
            .zip(&cycle_weights)
            .fold(Fp::ZERO, |sum, (query, weight)| sum + query.value * weight);
        let address_challenges = self.sumcheck.verify(
            claimed_output,
            table.len().ilog2() as usize,
            &mut transcript,
        )?;
        let expected_read_address = padded.iter().zip(&cycle_weights).try_fold(
            Fp::ZERO,
            |sum, (query, cycle_weight)| {
                Ok::<_, ExplicitShoutError>(
                    sum + cycle_weight * eq_index(query.address, &address_challenges)?,
                )
            },
        )?;
        if self.sumcheck.final_left() != expected_read_address {
            return Err(ExplicitShoutError::ReadAddressOpeningMismatch);
        }
        let expected_table = evaluate_mle(table, &address_challenges)?;
        if self.sumcheck.final_right() != expected_table {
            return Err(ExplicitShoutError::TableOpeningMismatch);
        }
        Ok(())
    }

    /// Returns the number of sumcheck field elements, excluding terminal openings.
    #[must_use]
    pub fn sumcheck_field_elements(&self) -> usize {
        self.sumcheck.round_count().saturating_mul(3)
    }
}

impl CommittedShoutProof {
    /// Proves a read-only batch while committing the table terminal.
    pub fn prove(
        parameters: &IpaParameters,
        table: &[Fp],
        queries: &[ReadOnlyQuery],
    ) -> Result<Self, ExplicitShoutError> {
        validate_instance(table, queries)?;
        if parameters.vector_len() != table.len() {
            return Err(ExplicitShoutError::CommitmentShape);
        }
        let table_commitment = parameters.commit(table)?;
        let padded_query_count = queries
            .len()
            .checked_next_power_of_two()
            .ok_or(ExplicitShoutError::QueryCountOverflow)?;
        let padded = padded_queries_from_first(queries, padded_query_count)?;
        let statement = committed_statement_digest(table.len(), table_commitment, queries);
        let mut transcript = Transcript::new(b"zksm83-committed-shout/v1", &statement);
        let cycle_challenges = challenges(&mut transcript, b"cycle-variable", padded.len().ilog2());
        let cycle_weights = eq_evaluations(&cycle_challenges)?;
        let mut read_address = vec![Fp::ZERO; table.len()];
        for (query, weight) in padded.iter().zip(&cycle_weights) {
            let target = read_address.get_mut(query.address).ok_or(
                ExplicitShoutError::AddressOutOfRange {
                    address: query.address,
                    table_size: table.len(),
                },
            )?;
            *target += weight;
        }
        let mut verifier_transcript = transcript.clone();
        let (sumcheck, actual_claim) =
            ProductSumcheckProof::prove(&read_address, table, &mut transcript)?;
        let claimed_output = padded
            .iter()
            .zip(&cycle_weights)
            .fold(Fp::ZERO, |sum, (query, weight)| sum + query.value * weight);
        if actual_claim != claimed_output {
            return Err(ExplicitShoutError::ClaimMismatch);
        }
        let address_challenges = sumcheck.verify(
            claimed_output,
            table.len().ilog2() as usize,
            &mut verifier_transcript,
        )?;
        let table_opening =
            parameters.open_precommitted(table, &address_challenges, table_commitment)?;
        Ok(Self {
            table_size: table.len(),
            query_count: queries.len(),
            padded_query_count,
            table_commitment,
            sumcheck,
            table_opening,
        })
    }

    /// Verifies the batch without receiving the committed read-only table.
    pub fn verify(
        &self,
        parameters: &IpaParameters,
        expected_commitment: IpaCommitment,
        queries: &[ReadOnlyQuery],
    ) -> Result<(), ExplicitShoutError> {
        validate_queries(self.table_size, queries)?;
        if parameters.vector_len() != self.table_size {
            return Err(ExplicitShoutError::CommitmentShape);
        }
        if self.table_commitment != expected_commitment {
            return Err(ExplicitShoutError::CommitmentMismatch);
        }
        if self.query_count != queries.len() {
            return Err(ExplicitShoutError::QueryCountMismatch {
                proof: self.query_count,
                instance: queries.len(),
            });
        }
        let expected_padded = queries
            .len()
            .checked_next_power_of_two()
            .ok_or(ExplicitShoutError::QueryCountOverflow)?;
        if self.padded_query_count != expected_padded {
            return Err(ExplicitShoutError::PaddedQueryCountMismatch {
                proof: self.padded_query_count,
                expected: expected_padded,
            });
        }
        let padded = padded_queries_from_first(queries, expected_padded)?;
        let statement = committed_statement_digest(self.table_size, self.table_commitment, queries);
        let mut transcript = Transcript::new(b"zksm83-committed-shout/v1", &statement);
        let cycle_challenges = challenges(&mut transcript, b"cycle-variable", padded.len().ilog2());
        let cycle_weights = eq_evaluations(&cycle_challenges)?;
        let claimed_output = padded
            .iter()
            .zip(&cycle_weights)
            .fold(Fp::ZERO, |sum, (query, weight)| sum + query.value * weight);
        let address_challenges = self.sumcheck.verify(
            claimed_output,
            self.table_size.ilog2() as usize,
            &mut transcript,
        )?;
        let expected_read_address = padded.iter().zip(&cycle_weights).try_fold(
            Fp::ZERO,
            |sum, (query, cycle_weight)| {
                Ok::<_, ExplicitShoutError>(
                    sum + cycle_weight * eq_index(query.address, &address_challenges)?,
                )
            },
        )?;
        if self.sumcheck.final_left() != expected_read_address {
            return Err(ExplicitShoutError::ReadAddressOpeningMismatch);
        }
        parameters.verify(
            self.table_commitment,
            &address_challenges,
            self.sumcheck.final_right(),
            &self.table_opening,
        )?;
        Ok(())
    }

    /// Returns the table commitment bound into the Shout transcript.
    #[must_use]
    pub const fn table_commitment(&self) -> IpaCommitment {
        self.table_commitment
    }

    /// Returns the proof size excluding the explicit query vector.
    #[must_use]
    pub fn element_count(&self) -> (usize, usize) {
        let (points, opening_scalars) = self.table_opening.element_count();
        (
            points,
            self.sumcheck
                .field_elements()
                .saturating_add(opening_scalars),
        )
    }
}

impl CommittedQueryShoutProof {
    /// Proves a power-of-two committed query batch against a committed table.
    pub fn prove(
        table_parameters: &IpaParameters,
        query_parameters: &IpaParameters,
        table: &[Fp],
        addresses: &[usize],
        values: &[Fp],
    ) -> Result<Self, CommittedQueryShoutError> {
        validate_committed_query_instance(
            table_parameters,
            query_parameters,
            table,
            addresses,
            values,
        )?;
        let address_bits = address_bit_columns(addresses, table.len())?;
        let table_commitment = table_parameters.commit(table)?;
        let address_bit_commitments = query_parameters.commit_batch(&address_bits)?;
        let value_commitment = query_parameters.commit(values)?;
        let mut transcript = committed_query_transcript(
            table.len(),
            addresses.len(),
            table_commitment,
            &address_bit_commitments,
            value_commitment,
        );
        let cycle_point = challenges(
            &mut transcript,
            b"committed-query-cycle-variable",
            addresses.len().ilog2(),
        );
        let cycle_weights = eq_evaluations(&cycle_point)?;
        let claimed_output = evaluate_mle(values, &cycle_point)?;
        transcript.append(
            b"committed-query-claimed-output",
            claimed_output.to_repr().as_ref(),
        );
        let mut read_address = vec![Fp::ZERO; table.len()];
        for (address, weight) in addresses.iter().zip(&cycle_weights) {
            let target = read_address.get_mut(*address).ok_or(
                CommittedQueryShoutError::AddressOutOfRange {
                    address: *address,
                    table_size: table.len(),
                },
            )?;
            *target += weight;
        }
        let mut verifier_transcript = transcript.clone();
        let (table_sumcheck, actual_claim) =
            ProductSumcheckProof::prove(&read_address, table, &mut transcript)?;
        if actual_claim != claimed_output {
            return Err(CommittedQueryShoutError::ClaimMismatch);
        }
        let table_point = table_sumcheck.verify(
            claimed_output,
            table.len().ilog2() as usize,
            &mut verifier_transcript,
        )?;
        let table_opening =
            table_parameters.open_precommitted(table, &table_point, table_commitment)?;
        let value_opening =
            query_parameters.open_precommitted(values, &cycle_point, value_commitment)?;
        let address_factors = address_binding_factors(&cycle_weights, &address_bits, &table_point)?;
        let mut address_verifier_transcript = verifier_transcript.clone();
        let (address_sumcheck, address_claim) =
            MultiProductSumcheckProof::prove(&address_factors, &mut verifier_transcript)?;
        if address_claim != table_sumcheck.final_left() {
            return Err(CommittedQueryShoutError::AddressBindingMismatch);
        }
        let address_point = address_sumcheck.verify(
            table_sumcheck.final_left(),
            addresses.len().ilog2() as usize,
            address_bits.len().saturating_add(1),
            &mut address_verifier_transcript,
        )?;
        let address_bits_opening = query_parameters.open_batch_precommitted(
            &address_bits,
            &address_point,
            &address_bit_commitments,
        )?;
        Ok(Self {
            table_size: table.len(),
            query_count: addresses.len(),
            table_commitment,
            address_bit_commitments,
            value_commitment,
            claimed_output,
            table_sumcheck,
            address_sumcheck,
            table_opening,
            value_opening,
            address_bits_opening,
        })
    }

    /// Verifies the lookup relation against externally supplied commitments to
    /// the table and query columns.
    pub fn verify(
        &self,
        table_parameters: &IpaParameters,
        query_parameters: &IpaParameters,
        expected_table_commitment: IpaCommitment,
        expected_address_bit_commitments: &[IpaCommitment],
        expected_value_commitment: IpaCommitment,
    ) -> Result<(), CommittedQueryShoutError> {
        let bit_width = committed_query_shape(
            table_parameters,
            query_parameters,
            self.table_size,
            self.query_count,
        )?;
        if self.table_commitment != expected_table_commitment
            || self.address_bit_commitments != expected_address_bit_commitments
            || self.value_commitment != expected_value_commitment
        {
            return Err(CommittedQueryShoutError::CommitmentMismatch);
        }
        if self.address_bit_commitments.len() != bit_width {
            return Err(CommittedQueryShoutError::BitWidthMismatch {
                actual: self.address_bit_commitments.len(),
                expected: bit_width,
            });
        }
        let mut transcript = committed_query_transcript(
            self.table_size,
            self.query_count,
            self.table_commitment,
            &self.address_bit_commitments,
            self.value_commitment,
        );
        let cycle_point = challenges(
            &mut transcript,
            b"committed-query-cycle-variable",
            self.query_count.ilog2(),
        );
        transcript.append(
            b"committed-query-claimed-output",
            self.claimed_output.to_repr().as_ref(),
        );
        query_parameters.verify(
            self.value_commitment,
            &cycle_point,
            self.claimed_output,
            &self.value_opening,
        )?;
        let table_point = self.table_sumcheck.verify(
            self.claimed_output,
            self.table_size.ilog2() as usize,
            &mut transcript,
        )?;
        table_parameters.verify(
            self.table_commitment,
            &table_point,
            self.table_sumcheck.final_right(),
            &self.table_opening,
        )?;
        let address_point = self.address_sumcheck.verify(
            self.table_sumcheck.final_left(),
            self.query_count.ilog2() as usize,
            bit_width.saturating_add(1),
            &mut transcript,
        )?;
        query_parameters.verify_batch(
            &self.address_bit_commitments,
            &address_point,
            &self.address_bits_opening,
        )?;
        verify_address_binding_terminal(
            &self.address_sumcheck,
            &cycle_point,
            &table_point,
            &address_point,
            self.address_bits_opening.claimed_values(),
        )?;
        Ok(())
    }

    /// Returns the table commitment bound into the proof transcript.
    #[must_use]
    pub const fn table_commitment(&self) -> IpaCommitment {
        self.table_commitment
    }

    /// Returns the ordered least-significant-bit-first query-address commitments.
    #[must_use]
    pub fn address_bit_commitments(&self) -> &[IpaCommitment] {
        &self.address_bit_commitments
    }

    /// Returns the committed query-value column.
    #[must_use]
    pub const fn value_commitment(&self) -> IpaCommitment {
        self.value_commitment
    }

    /// Returns proof size in curve points and scalar field elements, including
    /// commitments carried by this standalone proof.
    #[must_use]
    pub fn element_count(&self) -> (usize, usize) {
        let (table_points, table_scalars) = self.table_opening.element_count();
        let (value_points, value_scalars) = self.value_opening.element_count();
        let (address_points, address_scalars) = self.address_bits_opening.element_count();
        (
            2_usize
                .saturating_add(self.address_bit_commitments.len())
                .saturating_add(table_points)
                .saturating_add(value_points)
                .saturating_add(address_points),
            1_usize
                .saturating_add(self.table_sumcheck.field_elements())
                .saturating_add(self.address_sumcheck.field_elements())
                .saturating_add(table_scalars)
                .saturating_add(value_scalars)
                .saturating_add(address_scalars),
        )
    }
}

impl CommittedMultiQueryShoutProof {
    /// Proves multiple fixed-table outputs at one shared committed address per
    /// query row.
    pub fn prove(
        table_parameters: &IpaParameters,
        query_parameters: &IpaParameters,
        tables: &[Vec<Fp>],
        addresses: &[usize],
        values: &[Vec<Fp>],
    ) -> Result<Self, CommittedMultiQueryShoutError> {
        validate_multi_query_columns(
            table_parameters,
            query_parameters,
            tables,
            addresses.len(),
            values,
        )?;
        for address in addresses {
            if *address >= table_parameters.vector_len() {
                return Err(CommittedMultiQueryShoutError::AddressOutOfRange {
                    address: *address,
                    table_size: table_parameters.vector_len(),
                });
            }
        }
        let table_commitments = table_parameters.commit_batch(tables)?;
        let value_commitments = query_parameters.commit_batch(values)?;
        let address_bits = address_bit_columns(addresses, table_parameters.vector_len())?;
        let address_commitments = query_parameters.commit_batch(&address_bits)?;
        let challenge =
            multi_query_challenge(&table_commitments, &address_commitments, &value_commitments)?;
        let coefficients = challenge_powers(challenge, tables.len());
        let mixed_table =
            linear_combination_columns(tables, &coefficients, table_parameters.vector_len())?;
        let mixed_values =
            linear_combination_columns(values, &coefficients, query_parameters.vector_len())?;
        let inner = CommittedQueryShoutProof::prove(
            table_parameters,
            query_parameters,
            &mixed_table,
            addresses,
            &mixed_values,
        )?;
        let expected_table = IpaParameters::combine_commitments(&table_commitments, &coefficients)?;
        let expected_values =
            IpaParameters::combine_commitments(&value_commitments, &coefficients)?;
        if inner.table_commitment() != expected_table
            || inner.address_bit_commitments() != address_commitments
            || inner.value_commitment() != expected_values
        {
            return Err(CommittedMultiQueryShoutError::CombinationMismatch);
        }
        Ok(Self {
            column_count: tables.len(),
            inner,
        })
    }

    /// Verifies every batched output against externally supplied table,
    /// address-bit, and query-output commitments.
    pub fn verify(
        &self,
        table_parameters: &IpaParameters,
        query_parameters: &IpaParameters,
        expected_table_commitments: &[IpaCommitment],
        expected_address_bit_commitments: &[IpaCommitment],
        expected_value_commitments: &[IpaCommitment],
    ) -> Result<(), CommittedMultiQueryShoutError> {
        if self.column_count == 0
            || expected_table_commitments.len() != self.column_count
            || expected_value_commitments.len() != self.column_count
        {
            return Err(CommittedMultiQueryShoutError::ColumnCountMismatch);
        }
        let challenge = multi_query_challenge(
            expected_table_commitments,
            expected_address_bit_commitments,
            expected_value_commitments,
        )?;
        let coefficients = challenge_powers(challenge, self.column_count);
        let table_commitment =
            IpaParameters::combine_commitments(expected_table_commitments, &coefficients)?;
        let value_commitment =
            IpaParameters::combine_commitments(expected_value_commitments, &coefficients)?;
        self.inner.verify(
            table_parameters,
            query_parameters,
            table_commitment,
            expected_address_bit_commitments,
            value_commitment,
        )?;
        Ok(())
    }

    /// Returns the number of jointly looked-up output columns.
    #[must_use]
    pub const fn column_count(&self) -> usize {
        self.column_count
    }

    /// Returns proof size in curve points and scalar field elements.
    #[must_use]
    pub fn element_count(&self) -> (usize, usize) {
        self.inner.element_count()
    }
}

/// A multi-output committed-query Shout proof is malformed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CommittedMultiQueryShoutError {
    /// Table and query output column lists are empty or differ in count.
    #[error("multi-query Shout column shape is invalid")]
    ColumnCountMismatch,
    /// A table or query column has the wrong vector length.
    #[error("multi-query Shout vector shape is invalid")]
    VectorShape,
    /// A query address is outside the fixed table.
    #[error("Shout address {address} is outside table size {table_size}")]
    AddressOutOfRange {
        /// Rejected address.
        address: usize,
        /// Fixed table size.
        table_size: usize,
    },
    /// The Fiat-Shamir output-column batching challenge was zero.
    #[error("multi-query Shout batching challenge is zero")]
    ZeroChallenge,
    /// Mixed vectors and their homomorphic commitments disagree.
    #[error("multi-query Shout linear combination mismatch")]
    CombinationMismatch,
    /// The inner committed-query Shout proof failed.
    #[error(transparent)]
    Shout(#[from] CommittedQueryShoutError),
    /// A polynomial commitment operation failed.
    #[error("multi-query Shout polynomial commitment failed")]
    Ipa,
}

impl From<IpaError> for CommittedMultiQueryShoutError {
    fn from(_: IpaError) -> Self {
        Self::Ipa
    }
}

/// A PCS-bound query Shout instance or proof is malformed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CommittedQueryShoutError {
    /// The table or query vector is empty or not a power of two.
    #[error("committed-query Shout table or query shape is invalid")]
    Shape,
    /// Table or query PCS parameters have the wrong vector length.
    #[error("committed-query Shout PCS parameters have the wrong shape")]
    CommitmentShape,
    /// Query address and value vectors differ in length.
    #[error("committed-query Shout address and value lengths differ")]
    QueryLengthMismatch,
    /// A query address is outside the table.
    #[error("Shout address {address} is outside table size {table_size}")]
    AddressOutOfRange {
        /// Rejected address.
        address: usize,
        /// Committed table size.
        table_size: usize,
    },
    /// The proof carries the wrong number of address-bit columns.
    #[error("Shout proof has {actual} address bits, expected {expected}")]
    BitWidthMismatch {
        /// Address-bit columns in the proof.
        actual: usize,
        /// Binary width of the table address space.
        expected: usize,
    },
    /// Proof commitments differ from the glue or table statement.
    #[error("committed-query Shout commitment mismatch")]
    CommitmentMismatch,
    /// The table dot product does not equal the committed query-value opening.
    #[error("committed-query Shout output claim mismatch")]
    ClaimMismatch,
    /// The committed address bits do not reproduce the Shout read-address terminal.
    #[error("committed-query Shout address binding mismatch")]
    AddressBindingMismatch,
    /// A sumcheck proof failed.
    #[error("committed-query Shout sumcheck failed")]
    Sumcheck,
    /// A polynomial commitment or opening failed.
    #[error("committed-query Shout polynomial opening failed")]
    Ipa,
}

impl From<ProductSumcheckError> for CommittedQueryShoutError {
    fn from(_: ProductSumcheckError) -> Self {
        Self::Sumcheck
    }
}

impl From<IpaError> for CommittedQueryShoutError {
    fn from(_: IpaError) -> Self {
        Self::Ipa
    }
}

impl From<ExplicitShoutError> for CommittedQueryShoutError {
    fn from(_: ExplicitShoutError) -> Self {
        Self::Shape
    }
}

/// An explicit-oracle Shout instance or proof is malformed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ExplicitShoutError {
    /// The table must be non-empty.
    #[error("Shout table is empty")]
    EmptyTable,
    /// The table is not a Boolean-hypercube evaluation vector.
    #[error("Shout table length {length} is not a power of two")]
    NonPowerOfTwoTable {
        /// Rejected table length.
        length: usize,
    },
    /// At least one query is required.
    #[error("Shout query batch is empty")]
    EmptyQueries,
    /// Padding the query count overflowed `usize`.
    #[error("Shout query count cannot be padded to a power of two")]
    QueryCountOverflow,
    /// A query addresses outside the fixed table.
    #[error("Shout address {address} is outside table size {table_size}")]
    AddressOutOfRange {
        /// Rejected address.
        address: usize,
        /// Declared table length.
        table_size: usize,
    },
    /// Proof and verifier query counts differ.
    #[error("Shout proof has {proof} queries, instance has {instance}")]
    QueryCountMismatch {
        /// Query count bound by the proof.
        proof: usize,
        /// Query count supplied to verification.
        instance: usize,
    },
    /// Proof carries a non-canonical padded query length.
    #[error("Shout proof padded query count {proof}, expected {expected}")]
    PaddedQueryCountMismatch {
        /// Padded count bound by the proof.
        proof: usize,
        /// Canonical next-power-of-two count.
        expected: usize,
    },
    /// Product sumcheck failed.
    #[error("Shout product sumcheck failed")]
    Sumcheck,
    /// The final read-address MLE does not match the explicit queries.
    #[error("Shout read-address terminal opening mismatch")]
    ReadAddressOpeningMismatch,
    /// The final table MLE does not match the explicit table.
    #[error("Shout table terminal opening mismatch")]
    TableOpeningMismatch,
    /// An MLE evaluation has the wrong variable count.
    #[error("multilinear evaluation length and challenge count disagree")]
    MleShape,
    /// The PCS parameters do not match the Shout table length.
    #[error("Shout table and PCS parameter lengths disagree")]
    CommitmentShape,
    /// The proof is not bound to the externally expected table commitment.
    #[error("Shout table commitment does not match the expected commitment")]
    CommitmentMismatch,
    /// The claimed query outputs do not equal the committed table relation.
    #[error("Shout query outputs do not match the committed table")]
    ClaimMismatch,
    /// The polynomial commitment opening failed.
    #[error("Shout polynomial commitment opening failed")]
    CommitmentOpening,
}

impl From<ProductSumcheckError> for ExplicitShoutError {
    fn from(_: ProductSumcheckError) -> Self {
        Self::Sumcheck
    }
}

impl From<IpaError> for ExplicitShoutError {
    fn from(_: IpaError) -> Self {
        Self::CommitmentOpening
    }
}

fn validate_multi_query_columns(
    table_parameters: &IpaParameters,
    query_parameters: &IpaParameters,
    tables: &[Vec<Fp>],
    query_count: usize,
    values: &[Vec<Fp>],
) -> Result<(), CommittedMultiQueryShoutError> {
    if tables.is_empty() || tables.len() != values.len() {
        return Err(CommittedMultiQueryShoutError::ColumnCountMismatch);
    }
    if query_count == 0
        || !query_count.is_power_of_two()
        || query_parameters.vector_len() != query_count
        || tables
            .iter()
            .any(|table| table.len() != table_parameters.vector_len())
        || values
            .iter()
            .any(|column| column.len() != query_parameters.vector_len())
    {
        return Err(CommittedMultiQueryShoutError::VectorShape);
    }
    Ok(())
}

fn multi_query_challenge(
    table_commitments: &[IpaCommitment],
    address_commitments: &[IpaCommitment],
    value_commitments: &[IpaCommitment],
) -> Result<Fp, CommittedMultiQueryShoutError> {
    if table_commitments.is_empty() || table_commitments.len() != value_commitments.len() {
        return Err(CommittedMultiQueryShoutError::ColumnCountMismatch);
    }
    let mut hasher = Sha512::new();
    hasher.update(b"zksm83-multi-query-shout-mix/v1");
    hasher.update((table_commitments.len() as u64).to_le_bytes());
    for commitment in table_commitments {
        hasher.update(commitment.to_bytes());
    }
    hasher.update((address_commitments.len() as u64).to_le_bytes());
    for commitment in address_commitments {
        hasher.update(commitment.to_bytes());
    }
    for commitment in value_commitments {
        hasher.update(commitment.to_bytes());
    }
    let digest = hasher.finalize();
    let mut uniform = [0_u8; 64];
    uniform.copy_from_slice(&digest);
    let challenge = Fp::from_uniform_bytes(&uniform);
    if challenge == Fp::ZERO {
        return Err(CommittedMultiQueryShoutError::ZeroChallenge);
    }
    Ok(challenge)
}

fn challenge_powers(challenge: Fp, count: usize) -> Vec<Fp> {
    let mut coefficient = Fp::ONE;
    (0..count)
        .map(|_| {
            let current = coefficient;
            coefficient *= challenge;
            current
        })
        .collect()
}

fn linear_combination_columns(
    columns: &[Vec<Fp>],
    coefficients: &[Fp],
    length: usize,
) -> Result<Vec<Fp>, CommittedMultiQueryShoutError> {
    if columns.is_empty()
        || columns.len() != coefficients.len()
        || columns.iter().any(|column| column.len() != length)
    {
        return Err(CommittedMultiQueryShoutError::VectorShape);
    }
    let mut combined = vec![Fp::ZERO; length];
    for (column, coefficient) in columns.iter().zip(coefficients) {
        for (target, value) in combined.iter_mut().zip(column) {
            *target += *coefficient * *value;
        }
    }
    Ok(combined)
}

fn validate_committed_query_instance(
    table_parameters: &IpaParameters,
    query_parameters: &IpaParameters,
    table: &[Fp],
    addresses: &[usize],
    values: &[Fp],
) -> Result<(), CommittedQueryShoutError> {
    let _ = committed_query_shape(
        table_parameters,
        query_parameters,
        table.len(),
        addresses.len(),
    )?;
    if addresses.len() != values.len() {
        return Err(CommittedQueryShoutError::QueryLengthMismatch);
    }
    for address in addresses {
        if *address >= table.len() {
            return Err(CommittedQueryShoutError::AddressOutOfRange {
                address: *address,
                table_size: table.len(),
            });
        }
    }
    Ok(())
}

fn committed_query_shape(
    table_parameters: &IpaParameters,
    query_parameters: &IpaParameters,
    table_size: usize,
    query_count: usize,
) -> Result<usize, CommittedQueryShoutError> {
    if table_size < 2
        || query_count == 0
        || !table_size.is_power_of_two()
        || !query_count.is_power_of_two()
    {
        return Err(CommittedQueryShoutError::Shape);
    }
    if table_parameters.vector_len() != table_size || query_parameters.vector_len() != query_count {
        return Err(CommittedQueryShoutError::CommitmentShape);
    }
    Ok(table_size.ilog2() as usize)
}

fn address_bit_columns(
    addresses: &[usize],
    table_size: usize,
) -> Result<Vec<Vec<Fp>>, CommittedQueryShoutError> {
    if table_size < 2 || !table_size.is_power_of_two() {
        return Err(CommittedQueryShoutError::Shape);
    }
    let bit_width = table_size.ilog2() as usize;
    let mut columns = (0..bit_width)
        .map(|_| Vec::with_capacity(addresses.len()))
        .collect::<Vec<_>>();
    for address in addresses {
        if *address >= table_size {
            return Err(CommittedQueryShoutError::AddressOutOfRange {
                address: *address,
                table_size,
            });
        }
        for (bit, column) in columns.iter_mut().enumerate() {
            column.push(Fp::from(((*address >> bit) & 1) as u64));
        }
    }
    Ok(columns)
}

fn committed_query_transcript(
    table_size: usize,
    query_count: usize,
    table_commitment: IpaCommitment,
    address_bit_commitments: &[IpaCommitment],
    value_commitment: IpaCommitment,
) -> Transcript {
    let mut statement = Vec::new();
    statement.extend_from_slice(&(table_size as u64).to_le_bytes());
    statement.extend_from_slice(&(query_count as u64).to_le_bytes());
    statement.extend_from_slice(&(address_bit_commitments.len() as u64).to_le_bytes());
    statement.extend_from_slice(&table_commitment.to_bytes());
    for commitment in address_bit_commitments {
        statement.extend_from_slice(&commitment.to_bytes());
    }
    statement.extend_from_slice(&value_commitment.to_bytes());
    Transcript::new(b"zksm83-committed-query-shout/v1", &statement)
}

fn address_binding_factors(
    cycle_weights: &[Fp],
    address_bits: &[Vec<Fp>],
    table_point: &[Fp],
) -> Result<Vec<Vec<Fp>>, CommittedQueryShoutError> {
    if address_bits.len() != table_point.len()
        || address_bits
            .iter()
            .any(|column| column.len() != cycle_weights.len())
    {
        return Err(CommittedQueryShoutError::Shape);
    }
    let mut factors = Vec::with_capacity(address_bits.len().saturating_add(1));
    factors.push(cycle_weights.to_vec());
    for (column, point) in address_bits.iter().zip(table_point) {
        factors.push(
            column
                .iter()
                .map(|bit| *bit * *point + (Fp::ONE - *bit) * (Fp::ONE - *point))
                .collect(),
        );
    }
    Ok(factors)
}

fn verify_address_binding_terminal(
    proof: &MultiProductSumcheckProof,
    cycle_point: &[Fp],
    table_point: &[Fp],
    address_point: &[Fp],
    address_bit_claims: &[Fp],
) -> Result<(), CommittedQueryShoutError> {
    if table_point.len() != address_bit_claims.len()
        || proof.final_factors().len() != address_bit_claims.len().saturating_add(1)
    {
        return Err(CommittedQueryShoutError::BitWidthMismatch {
            actual: address_bit_claims.len(),
            expected: table_point.len(),
        });
    }
    let expected_weight = equality_evaluation(cycle_point, address_point)?;
    if proof.final_factors().first().copied() != Some(expected_weight) {
        return Err(CommittedQueryShoutError::AddressBindingMismatch);
    }
    for ((factor, bit), point) in proof
        .final_factors()
        .iter()
        .skip(1)
        .zip(address_bit_claims)
        .zip(table_point)
    {
        let expected = *bit * *point + (Fp::ONE - *bit) * (Fp::ONE - *point);
        if *factor != expected {
            return Err(CommittedQueryShoutError::AddressBindingMismatch);
        }
    }
    Ok(())
}

fn equality_evaluation(left: &[Fp], right: &[Fp]) -> Result<Fp, CommittedQueryShoutError> {
    if left.len() != right.len() {
        return Err(CommittedQueryShoutError::Shape);
    }
    Ok(left
        .iter()
        .zip(right)
        .fold(Fp::ONE, |product, (left, right)| {
            product * (*left * *right + (Fp::ONE - *left) * (Fp::ONE - *right))
        }))
}

fn validate_instance(table: &[Fp], queries: &[ReadOnlyQuery]) -> Result<(), ExplicitShoutError> {
    if table.is_empty() {
        return Err(ExplicitShoutError::EmptyTable);
    }
    if !table.len().is_power_of_two() {
        return Err(ExplicitShoutError::NonPowerOfTwoTable {
            length: table.len(),
        });
    }
    if queries.is_empty() {
        return Err(ExplicitShoutError::EmptyQueries);
    }
    for query in queries {
        if query.address >= table.len() {
            return Err(ExplicitShoutError::AddressOutOfRange {
                address: query.address,
                table_size: table.len(),
            });
        }
    }
    Ok(())
}

fn validate_queries(
    table_size: usize,
    queries: &[ReadOnlyQuery],
) -> Result<(), ExplicitShoutError> {
    if table_size == 0 {
        return Err(ExplicitShoutError::EmptyTable);
    }
    if !table_size.is_power_of_two() {
        return Err(ExplicitShoutError::NonPowerOfTwoTable { length: table_size });
    }
    if queries.is_empty() {
        return Err(ExplicitShoutError::EmptyQueries);
    }
    for query in queries {
        if query.address >= table_size {
            return Err(ExplicitShoutError::AddressOutOfRange {
                address: query.address,
                table_size,
            });
        }
    }
    Ok(())
}

fn padded_queries(
    table: &[Fp],
    queries: &[ReadOnlyQuery],
    padded_len: usize,
) -> Result<Vec<ReadOnlyQuery>, ExplicitShoutError> {
    let padding_value = table
        .first()
        .copied()
        .ok_or(ExplicitShoutError::EmptyTable)?;
    let mut padded = Vec::with_capacity(padded_len);
    padded.extend_from_slice(queries);
    padded.resize(
        padded_len,
        ReadOnlyQuery {
            address: 0,
            value: padding_value,
        },
    );
    Ok(padded)
}

fn padded_queries_from_first(
    queries: &[ReadOnlyQuery],
    padded_len: usize,
) -> Result<Vec<ReadOnlyQuery>, ExplicitShoutError> {
    let padding = queries
        .first()
        .copied()
        .ok_or(ExplicitShoutError::EmptyQueries)?;
    let mut padded = Vec::with_capacity(padded_len);
    padded.extend_from_slice(queries);
    padded.resize(padded_len, padding);
    Ok(padded)
}

fn statement_digest(table: &[Fp], queries: &[ReadOnlyQuery]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update((table.len() as u64).to_le_bytes());
    for value in table {
        hasher.update(value.to_repr().as_ref());
    }
    hasher.update((queries.len() as u64).to_le_bytes());
    for query in queries {
        hasher.update((query.address as u64).to_le_bytes());
        hasher.update(query.value.to_repr().as_ref());
    }
    hasher.finalize().to_vec()
}

fn committed_statement_digest(
    table_size: usize,
    commitment: IpaCommitment,
    queries: &[ReadOnlyQuery],
) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update((table_size as u64).to_le_bytes());
    hasher.update(commitment.to_bytes());
    hasher.update((queries.len() as u64).to_le_bytes());
    for query in queries {
        hasher.update((query.address as u64).to_le_bytes());
        hasher.update(query.value.to_repr().as_ref());
    }
    hasher.finalize().to_vec()
}

fn challenges(transcript: &mut Transcript, label: &[u8], count: u32) -> Vec<Fp> {
    (0..count)
        .map(|index| transcript.challenge(label, &index.to_le_bytes()))
        .collect()
}

pub(crate) fn eq_evaluations(challenges: &[Fp]) -> Result<Vec<Fp>, ExplicitShoutError> {
    let mut evaluations = vec![Fp::ONE];
    for challenge in challenges {
        let prior = evaluations;
        let next_len = prior
            .len()
            .checked_mul(2)
            .ok_or(ExplicitShoutError::MleShape)?;
        let mut next = vec![Fp::ZERO; next_len];
        for (index, value) in prior.iter().enumerate() {
            let low = next.get_mut(index).ok_or(ExplicitShoutError::MleShape)?;
            *low = value * (Fp::ONE - challenge);
            let high_index = index
                .checked_add(prior.len())
                .ok_or(ExplicitShoutError::MleShape)?;
            let high = next
                .get_mut(high_index)
                .ok_or(ExplicitShoutError::MleShape)?;
            *high = value * challenge;
        }
        evaluations = next;
    }
    Ok(evaluations)
}

fn eq_index(index: usize, challenges: &[Fp]) -> Result<Fp, ExplicitShoutError> {
    if index >= 1_usize.checked_shl(challenges.len() as u32).unwrap_or(0) {
        return Err(ExplicitShoutError::MleShape);
    }
    Ok(challenges
        .iter()
        .enumerate()
        .fold(Fp::ONE, |product, (bit, challenge)| {
            if (index >> bit) & 1 == 1 {
                product * challenge
            } else {
                product * (Fp::ONE - challenge)
            }
        }))
}

pub(crate) fn evaluate_mle(values: &[Fp], challenges: &[Fp]) -> Result<Fp, ExplicitShoutError> {
    let expected = 1_usize
        .checked_shl(challenges.len() as u32)
        .ok_or(ExplicitShoutError::MleShape)?;
    if values.len() != expected {
        return Err(ExplicitShoutError::MleShape);
    }
    let mut folded = values.to_vec();
    for challenge in challenges {
        let mut next = Vec::with_capacity(folded.len() / 2);
        for pair in folded.chunks_exact(2) {
            let zero = pair.first().copied().ok_or(ExplicitShoutError::MleShape)?;
            let one = pair.get(1).copied().ok_or(ExplicitShoutError::MleShape)?;
            next.push(zero + challenge * (one - zero));
        }
        folded = next;
    }
    folded.first().copied().ok_or(ExplicitShoutError::MleShape)
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use pasta_curves::Fp;

    use super::{
        CommittedMultiQueryShoutProof, CommittedQueryShoutProof, CommittedShoutProof,
        ExplicitShoutProof, ReadOnlyQuery, address_bit_columns,
    };

    #[test]
    fn explicit_shout_proves_valid_batch_and_rejects_wrong_value()
    -> Result<(), Box<dyn std::error::Error>> {
        let table = [3_u64, 5, 8, 13, 21, 34, 55, 89].map(Fp::from);
        let queries = [
            ReadOnlyQuery {
                address: 6,
                value: Fp::from(55),
            },
            ReadOnlyQuery {
                address: 1,
                value: Fp::from(5),
            },
            ReadOnlyQuery {
                address: 7,
                value: Fp::from(89),
            },
        ];
        let proof = ExplicitShoutProof::prove(&table, &queries)?;
        proof.verify(&table, &queries)?;
        assert_eq!(proof.sumcheck_field_elements(), 9);

        let mut wrong = queries;
        let wrong_value = wrong
            .get_mut(1)
            .ok_or_else(|| std::io::Error::other("missing second Shout query"))?;
        wrong_value.value += Fp::ONE;
        assert!(proof.verify(&table, &wrong).is_err());
        let wrong_proof = ExplicitShoutProof::prove(&table, &wrong)?;
        assert!(wrong_proof.verify(&table, &wrong).is_err());
        Ok(())
    }

    #[test]
    fn committed_shout_opens_table_and_rejects_wrong_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let table = [3_u64, 5, 8, 13, 21, 34, 55, 89].map(Fp::from);
        let queries = [
            ReadOnlyQuery {
                address: 6,
                value: Fp::from(55),
            },
            ReadOnlyQuery {
                address: 1,
                value: Fp::from(5),
            },
            ReadOnlyQuery {
                address: 7,
                value: Fp::from(89),
            },
        ];
        let parameters = crate::IpaParameters::new(table.len())?;
        let expected = parameters.commit(&table)?;
        let proof = CommittedShoutProof::prove(&parameters, &table, &queries)?;
        proof.verify(&parameters, expected, &queries)?;
        assert_eq!(proof.element_count(), (6, 12));

        let other = [2_u64, 3, 5, 7, 11, 13, 17, 19].map(Fp::from);
        let wrong_commitment = parameters.commit(&other)?;
        assert!(
            proof
                .verify(&parameters, wrong_commitment, &queries)
                .is_err()
        );
        let mut wrong_queries = queries;
        let query = wrong_queries
            .get_mut(0)
            .ok_or_else(|| std::io::Error::other("missing first Shout query"))?;
        query.value += Fp::ONE;
        assert!(proof.verify(&parameters, expected, &wrong_queries).is_err());
        assert!(CommittedShoutProof::prove(&parameters, &table, &wrong_queries).is_err());
        Ok(())
    }

    #[test]
    fn committed_query_shout_hides_and_binds_query_columns()
    -> Result<(), Box<dyn std::error::Error>> {
        let table = [3_u64, 5, 8, 13, 21, 34, 55, 89].map(Fp::from);
        let addresses = [6_usize, 1, 7, 0, 3, 5, 2, 4];
        let values = [55_u64, 5, 89, 3, 13, 34, 8, 21].map(Fp::from);
        let table_parameters = crate::IpaParameters::new(table.len())?;
        let query_parameters = crate::IpaParameters::new(addresses.len())?;
        let table_commitment = table_parameters.commit(&table)?;
        let address_columns = address_bit_columns(&addresses, table.len())?;
        let address_commitments = query_parameters.commit_batch(&address_columns)?;
        let value_commitment = query_parameters.commit(&values)?;

        let proof = CommittedQueryShoutProof::prove(
            &table_parameters,
            &query_parameters,
            &table,
            &addresses,
            &values,
        )?;
        proof.verify(
            &table_parameters,
            &query_parameters,
            table_commitment,
            &address_commitments,
            value_commitment,
        )?;
        assert_eq!(proof.address_bit_commitments(), address_commitments);
        assert_eq!(proof.value_commitment(), value_commitment);

        let mut wrong_values = values;
        let value = wrong_values
            .get_mut(4)
            .ok_or_else(|| std::io::Error::other("missing query value"))?;
        *value += Fp::ONE;
        assert!(
            CommittedQueryShoutProof::prove(
                &table_parameters,
                &query_parameters,
                &table,
                &addresses,
                &wrong_values,
            )
            .is_err()
        );
        let wrong_value_commitment = query_parameters.commit(&wrong_values)?;
        assert!(
            proof
                .verify(
                    &table_parameters,
                    &query_parameters,
                    table_commitment,
                    &address_commitments,
                    wrong_value_commitment,
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn multi_query_shout_batches_shared_addresses_and_all_output_commitments()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = [3_u64, 5, 8, 13, 21, 34, 55, 89].map(Fp::from).to_vec();
        let second = [9_u64, 25, 64, 169, 441, 1156, 3025, 7921]
            .map(Fp::from)
            .to_vec();
        let tables = vec![first, second];
        let addresses = [6_usize, 1, 7, 0, 3, 5, 2, 4];
        let first_values = [55_u64, 5, 89, 3, 13, 34, 8, 21].map(Fp::from).to_vec();
        let second_values = [3025_u64, 25, 7921, 9, 169, 1156, 64, 441]
            .map(Fp::from)
            .to_vec();
        let values = vec![first_values, second_values];
        let table_parameters = crate::IpaParameters::new(8)?;
        let query_parameters = crate::IpaParameters::new(8)?;
        let table_commitments = table_parameters.commit_batch(&tables)?;
        let value_commitments = query_parameters.commit_batch(&values)?;
        let address_commitments = query_parameters.commit_batch(&address_bit_columns(
            &addresses,
            table_parameters.vector_len(),
        )?)?;

        let proof = CommittedMultiQueryShoutProof::prove(
            &table_parameters,
            &query_parameters,
            &tables,
            &addresses,
            &values,
        )?;
        proof.verify(
            &table_parameters,
            &query_parameters,
            &table_commitments,
            &address_commitments,
            &value_commitments,
        )?;
        assert_eq!(proof.column_count(), 2);

        let mut wrong_values = value_commitments;
        wrong_values.swap(0, 1);
        assert!(
            proof
                .verify(
                    &table_parameters,
                    &query_parameters,
                    &table_commitments,
                    &address_commitments,
                    &wrong_values,
                )
                .is_err()
        );
        Ok(())
    }
}
