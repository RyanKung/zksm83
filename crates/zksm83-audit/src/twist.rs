//! Dense-reference Twist read/write memory argument with explicit oracles.
//!
//! This implements the three core d=1 relations from Figure 9 of the Twist
//! and Shout paper: read checking, write checking, and virtual `Val`
//! evaluation via `Inc * LT`. The verifier currently receives the initial
//! memory and complete access list, and the prover materializes `K * T`
//! values. It is therefore a correctness reference for the later fast prover,
//! not yet a standalone succinct or full-scale proof.

use ff::Field;
use pasta_curves::Fp;
use sha2::{Digest, Sha512};
use thiserror::Error;

use crate::{
    ExplicitShoutError,
    shout::{eq_evaluations, evaluate_mle},
    sumcheck::{MultiProductSumcheckProof, ProductSumcheckError, ProductSumcheckProof, Transcript},
};

const MAX_DENSE_CELLS: usize = 1 << 20;

/// One active mutable-memory cycle in the explicit Twist statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryCycle {
    /// Read one byte without modifying the addressed cell.
    Read {
        /// Zero-based physical mutable-memory address.
        address: u32,
        /// Claimed value returned by the read.
        value: u8,
    },
    /// Read the prior byte, then write the replacement byte in the same cycle.
    Write {
        /// Zero-based physical mutable-memory address.
        address: u32,
        /// Claimed value present before the write.
        before: u8,
        /// Claimed value present after the write.
        after: u8,
    },
}

impl MemoryCycle {
    pub(crate) fn address(self) -> u32 {
        match self {
            Self::Read { address, .. } | Self::Write { address, .. } => address,
        }
    }
}

/// Core Twist sumchecks using explicit initial-memory and access-list oracles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplicitTwistProof {
    cycle_count: usize,
    padded_cycle_count: usize,
    read_check: MultiProductSumcheckProof,
    write_check: MultiProductSumcheckProof,
    read_val_check: ProductSumcheckProof,
    write_val_check: ProductSumcheckProof,
}

impl ExplicitTwistProof {
    /// Proves read/write consistency from the supplied initial memory.
    pub fn prove(
        initial_memory: &[u8],
        cycles: &[MemoryCycle],
    ) -> Result<Self, ExplicitTwistError> {
        let instance = DenseInstance::new(initial_memory, cycles)?;
        let mut transcript = Transcript::new(
            b"zksm83-explicit-twist/v1",
            &statement_digest(initial_memory, cycles),
        );

        let read_claim_point = challenges(
            &mut transcript,
            b"read-claim-cycle",
            instance.cycle_variables(),
        );
        let read_claim = evaluate_mle(&instance.read_values, &read_claim_point)?;
        let read_factors = instance.read_factors(&read_claim_point)?;
        let mut read_replay = transcript.clone();
        let (read_check, actual_read_claim) =
            MultiProductSumcheckProof::prove(&read_factors, &mut transcript)?;
        if actual_read_claim != read_claim {
            return Err(ExplicitTwistError::ReadRelation);
        }
        let read_point =
            read_check.verify(read_claim, instance.total_variables(), 3, &mut read_replay)?;

        let write_claim_address = challenges(
            &mut transcript,
            b"write-claim-address",
            instance.address_variables(),
        );
        let write_claim_cycle = challenges(
            &mut transcript,
            b"write-claim-cycle",
            instance.cycle_variables(),
        );
        let write_claim_point = joined(&write_claim_address, &write_claim_cycle);
        let write_claim = evaluate_mle(&instance.increments, &write_claim_point)?;
        let write_factors = instance.write_factors(&write_claim_address, &write_claim_cycle)?;
        let mut write_replay = transcript.clone();
        let (write_check, actual_write_claim) =
            MultiProductSumcheckProof::prove(&write_factors, &mut transcript)?;
        if actual_write_claim != write_claim {
            return Err(ExplicitTwistError::WriteRelation);
        }
        let write_point = write_check.verify(
            write_claim,
            instance.total_variables(),
            4,
            &mut write_replay,
        )?;

        let (read_address, read_cycle) = instance.split_point(&read_point)?;
        let read_val_check = prove_val_check(&instance, read_address, read_cycle, &mut transcript)?;
        let (write_address, write_cycle) = instance.split_point(&write_point)?;
        let write_val_check =
            prove_val_check(&instance, write_address, write_cycle, &mut transcript)?;

        Ok(Self {
            cycle_count: cycles.len(),
            padded_cycle_count: instance.padded_cycle_count,
            read_check,
            write_check,
            read_val_check,
            write_val_check,
        })
    }

    /// Verifies all three Twist relations against explicit statement oracles.
    pub fn verify(
        &self,
        initial_memory: &[u8],
        cycles: &[MemoryCycle],
    ) -> Result<(), ExplicitTwistError> {
        let instance = DenseInstance::new(initial_memory, cycles)?;
        if self.cycle_count != cycles.len() {
            return Err(ExplicitTwistError::CycleCountMismatch);
        }
        if self.padded_cycle_count != instance.padded_cycle_count {
            return Err(ExplicitTwistError::PaddedCycleCountMismatch);
        }
        let mut transcript = Transcript::new(
            b"zksm83-explicit-twist/v1",
            &statement_digest(initial_memory, cycles),
        );

        let read_claim_point = challenges(
            &mut transcript,
            b"read-claim-cycle",
            instance.cycle_variables(),
        );
        let read_claim = evaluate_mle(&instance.read_values, &read_claim_point)?;
        let read_factors = instance.read_factors(&read_claim_point)?;
        let read_point =
            self.read_check
                .verify(read_claim, instance.total_variables(), 3, &mut transcript)?;
        verify_factor_openings(&self.read_check, &read_factors, &read_point)?;

        let write_claim_address = challenges(
            &mut transcript,
            b"write-claim-address",
            instance.address_variables(),
        );
        let write_claim_cycle = challenges(
            &mut transcript,
            b"write-claim-cycle",
            instance.cycle_variables(),
        );
        let write_claim_point = joined(&write_claim_address, &write_claim_cycle);
        let write_claim = evaluate_mle(&instance.increments, &write_claim_point)?;
        let write_factors = instance.write_factors(&write_claim_address, &write_claim_cycle)?;
        let write_point =
            self.write_check
                .verify(write_claim, instance.total_variables(), 4, &mut transcript)?;
        verify_factor_openings(&self.write_check, &write_factors, &write_point)?;

        let (read_address, read_cycle) = instance.split_point(&read_point)?;
        verify_val_check(
            &self.read_val_check,
            &instance,
            read_address,
            read_cycle,
            &mut transcript,
        )?;
        let (write_address, write_cycle) = instance.split_point(&write_point)?;
        verify_val_check(
            &self.write_val_check,
            &instance,
            write_address,
            write_cycle,
            &mut transcript,
        )
    }

    /// Returns all sumcheck message and terminal-opening field elements.
    #[must_use]
    pub fn proof_field_elements(&self) -> usize {
        self.read_check
            .field_elements()
            .saturating_add(self.write_check.field_elements())
            .saturating_add(self.read_val_check.field_elements())
            .saturating_add(self.write_val_check.field_elements())
    }
}

/// A dense-reference Twist statement or proof is malformed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ExplicitTwistError {
    /// Initial mutable memory must contain at least one cell.
    #[error("Twist initial memory is empty")]
    EmptyMemory,
    /// Initial memory size must be a power of two.
    #[error("Twist initial memory size is not a power of two")]
    NonPowerOfTwoMemory,
    /// At least one active cycle is required.
    #[error("Twist cycle list is empty")]
    EmptyCycles,
    /// A memory address is outside the supplied initial table.
    #[error("Twist address {address} is outside memory size {memory_size}")]
    AddressOutOfRange {
        /// Rejected address.
        address: u32,
        /// Supplied memory size.
        memory_size: usize,
    },
    /// Dense reference allocation would exceed its deliberate safety cap.
    #[error("dense Twist reference requires {cells} cells, limit is {limit}")]
    DenseReferenceTooLarge {
        /// Requested `K * padded(T)` cells.
        cells: usize,
        /// Reference implementation cap.
        limit: usize,
    },
    /// Cycle count differs from the proof statement.
    #[error("Twist cycle count mismatch")]
    CycleCountMismatch,
    /// Canonical padding differs from the proof statement.
    #[error("Twist padded cycle count mismatch")]
    PaddedCycleCountMismatch,
    /// The read-checking identity is false.
    #[error("Twist read-checking relation is false")]
    ReadRelation,
    /// The write-checking identity is false.
    #[error("Twist write-checking relation is false")]
    WriteRelation,
    /// A sumcheck proof failed.
    #[error("Twist sumcheck failed")]
    Sumcheck,
    /// An explicit terminal oracle does not match its sumcheck opening.
    #[error("Twist terminal opening mismatch")]
    OpeningMismatch,
    /// A multilinear table or point has inconsistent shape.
    #[error("Twist multilinear shape invariant failed")]
    Shape,
}

impl From<ProductSumcheckError> for ExplicitTwistError {
    fn from(_: ProductSumcheckError) -> Self {
        Self::Sumcheck
    }
}

impl From<ExplicitShoutError> for ExplicitTwistError {
    fn from(_: ExplicitShoutError) -> Self {
        Self::Shape
    }
}

struct DenseInstance {
    initial: Vec<Fp>,
    table_size: usize,
    padded_cycle_count: usize,
    read_addresses: Vec<Fp>,
    write_addresses: Vec<Fp>,
    values: Vec<Fp>,
    increments: Vec<Fp>,
    read_values: Vec<Fp>,
    write_values: Vec<Fp>,
}

impl DenseInstance {
    fn new(initial_memory: &[u8], cycles: &[MemoryCycle]) -> Result<Self, ExplicitTwistError> {
        if initial_memory.is_empty() {
            return Err(ExplicitTwistError::EmptyMemory);
        }
        if !initial_memory.len().is_power_of_two() {
            return Err(ExplicitTwistError::NonPowerOfTwoMemory);
        }
        if cycles.is_empty() {
            return Err(ExplicitTwistError::EmptyCycles);
        }
        let padded_cycle_count = cycles
            .len()
            .checked_next_power_of_two()
            .ok_or(ExplicitTwistError::Shape)?;
        let cells = initial_memory
            .len()
            .checked_mul(padded_cycle_count)
            .ok_or(ExplicitTwistError::Shape)?;
        if cells > MAX_DENSE_CELLS {
            return Err(ExplicitTwistError::DenseReferenceTooLarge {
                cells,
                limit: MAX_DENSE_CELLS,
            });
        }
        for cycle in cycles {
            if usize::try_from(cycle.address())
                .map_or(true, |address| address >= initial_memory.len())
            {
                return Err(ExplicitTwistError::AddressOutOfRange {
                    address: cycle.address(),
                    memory_size: initial_memory.len(),
                });
            }
        }

        let initial = initial_memory
            .iter()
            .copied()
            .map(|value| Fp::from(u64::from(value)))
            .collect::<Vec<_>>();
        let mut current = initial.clone();
        let mut read_addresses = vec![Fp::ZERO; cells];
        let mut write_addresses = vec![Fp::ZERO; cells];
        let mut values = vec![Fp::ZERO; cells];
        let mut increments = vec![Fp::ZERO; cells];
        let mut read_values = vec![Fp::ZERO; padded_cycle_count];
        let mut write_values = vec![Fp::ZERO; padded_cycle_count];

        for cycle_index in 0..padded_cycle_count {
            let start = cycle_index
                .checked_mul(initial_memory.len())
                .ok_or(ExplicitTwistError::Shape)?;
            let end = start
                .checked_add(initial_memory.len())
                .ok_or(ExplicitTwistError::Shape)?;
            values
                .get_mut(start..end)
                .ok_or(ExplicitTwistError::Shape)?
                .copy_from_slice(&current);
            let Some(cycle) = cycles.get(cycle_index).copied() else {
                continue;
            };
            let address = usize::try_from(cycle.address()).map_err(|_| {
                ExplicitTwistError::AddressOutOfRange {
                    address: cycle.address(),
                    memory_size: initial_memory.len(),
                }
            })?;
            let cell = start
                .checked_add(address)
                .ok_or(ExplicitTwistError::Shape)?;
            *read_addresses
                .get_mut(cell)
                .ok_or(ExplicitTwistError::Shape)? = Fp::ONE;
            match cycle {
                MemoryCycle::Read { value, .. } => {
                    *read_values
                        .get_mut(cycle_index)
                        .ok_or(ExplicitTwistError::Shape)? = Fp::from(u64::from(value));
                }
                MemoryCycle::Write { before, after, .. } => {
                    *read_values
                        .get_mut(cycle_index)
                        .ok_or(ExplicitTwistError::Shape)? = Fp::from(u64::from(before));
                    *write_values
                        .get_mut(cycle_index)
                        .ok_or(ExplicitTwistError::Shape)? = Fp::from(u64::from(after));
                    *write_addresses
                        .get_mut(cell)
                        .ok_or(ExplicitTwistError::Shape)? = Fp::ONE;
                    *increments.get_mut(cell).ok_or(ExplicitTwistError::Shape)? =
                        Fp::from(u64::from(after)) - Fp::from(u64::from(before));
                    *current.get_mut(address).ok_or(ExplicitTwistError::Shape)? =
                        Fp::from(u64::from(after));
                }
            }
        }
        Ok(Self {
            initial,
            table_size: initial_memory.len(),
            padded_cycle_count,
            read_addresses,
            write_addresses,
            values,
            increments,
            read_values,
            write_values,
        })
    }

    fn address_variables(&self) -> usize {
        self.table_size.ilog2() as usize
    }

    fn cycle_variables(&self) -> usize {
        self.padded_cycle_count.ilog2() as usize
    }

    fn total_variables(&self) -> usize {
        self.address_variables()
            .saturating_add(self.cycle_variables())
    }

    fn read_factors(&self, claim_cycle: &[Fp]) -> Result<Vec<Vec<Fp>>, ExplicitTwistError> {
        let cycle_eq = eq_evaluations(claim_cycle)?;
        Ok(vec![
            expand_cycle_values(&cycle_eq, self.table_size)?,
            self.read_addresses.clone(),
            self.values.clone(),
        ])
    }

    fn write_factors(
        &self,
        claim_address: &[Fp],
        claim_cycle: &[Fp],
    ) -> Result<Vec<Vec<Fp>>, ExplicitTwistError> {
        let address_eq = eq_evaluations(claim_address)?;
        let cycle_eq = eq_evaluations(claim_cycle)?;
        let expanded_address = repeat_address_values(&address_eq, self.padded_cycle_count)?;
        let expanded_cycle = expand_cycle_values(&cycle_eq, self.table_size)?;
        let write_values = expand_cycle_values(&self.write_values, self.table_size)?;
        let write_delta = write_values
            .into_iter()
            .zip(&self.values)
            .map(|(write, value)| write - value)
            .collect::<Vec<_>>();
        Ok(vec![
            expanded_address,
            expanded_cycle,
            self.write_addresses.clone(),
            write_delta,
        ])
    }

    fn split_point<'a>(&self, point: &'a [Fp]) -> Result<(&'a [Fp], &'a [Fp]), ExplicitTwistError> {
        if point.len() != self.total_variables() {
            return Err(ExplicitTwistError::Shape);
        }
        Ok(point.split_at(self.address_variables()))
    }
}

fn prove_val_check(
    instance: &DenseInstance,
    address_point: &[Fp],
    cycle_point: &[Fp],
    transcript: &mut Transcript,
) -> Result<ProductSumcheckProof, ExplicitTwistError> {
    let (claim, inc_at_address, less_than) =
        val_check_instance(instance, address_point, cycle_point)?;
    let (proof, actual) = ProductSumcheckProof::prove(&inc_at_address, &less_than, transcript)?;
    if actual != claim {
        return Err(ExplicitTwistError::WriteRelation);
    }
    Ok(proof)
}

fn verify_val_check(
    proof: &ProductSumcheckProof,
    instance: &DenseInstance,
    address_point: &[Fp],
    cycle_point: &[Fp],
    transcript: &mut Transcript,
) -> Result<(), ExplicitTwistError> {
    let (claim, inc_at_address, less_than) =
        val_check_instance(instance, address_point, cycle_point)?;
    let challenge = proof.verify(claim, instance.cycle_variables(), transcript)?;
    if proof.final_left() != evaluate_mle(&inc_at_address, &challenge)?
        || proof.final_right() != evaluate_mle(&less_than, &challenge)?
    {
        return Err(ExplicitTwistError::OpeningMismatch);
    }
    Ok(())
}

fn val_check_instance(
    instance: &DenseInstance,
    address_point: &[Fp],
    cycle_point: &[Fp],
) -> Result<(Fp, Vec<Fp>, Vec<Fp>), ExplicitTwistError> {
    let point = joined(address_point, cycle_point);
    let value = evaluate_mle(&instance.values, &point)?;
    let initial = evaluate_mle(&instance.initial, address_point)?;
    let inc_at_address = (0..instance.padded_cycle_count)
        .map(|cycle| {
            let start = cycle
                .checked_mul(instance.table_size)
                .ok_or(ExplicitTwistError::Shape)?;
            let end = start
                .checked_add(instance.table_size)
                .ok_or(ExplicitTwistError::Shape)?;
            evaluate_mle(
                instance
                    .increments
                    .get(start..end)
                    .ok_or(ExplicitTwistError::Shape)?,
                address_point,
            )
            .map_err(ExplicitTwistError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let less_than = less_than_evaluations(cycle_point)?;
    Ok((value - initial, inc_at_address, less_than))
}

fn verify_factor_openings(
    proof: &MultiProductSumcheckProof,
    factors: &[Vec<Fp>],
    point: &[Fp],
) -> Result<(), ExplicitTwistError> {
    if proof.final_factors().len() != factors.len() {
        return Err(ExplicitTwistError::OpeningMismatch);
    }
    for (opening, factor) in proof.final_factors().iter().zip(factors) {
        if *opening != evaluate_mle(factor, point)? {
            return Err(ExplicitTwistError::OpeningMismatch);
        }
    }
    Ok(())
}

fn less_than_evaluations(cycle_point: &[Fp]) -> Result<Vec<Fp>, ExplicitTwistError> {
    let target_weights = eq_evaluations(cycle_point)?;
    let mut suffix = Fp::ZERO;
    let mut result = vec![Fp::ZERO; target_weights.len()];
    for index in (0..target_weights.len()).rev() {
        *result.get_mut(index).ok_or(ExplicitTwistError::Shape)? = suffix;
        suffix += target_weights
            .get(index)
            .copied()
            .ok_or(ExplicitTwistError::Shape)?;
    }
    Ok(result)
}

fn expand_cycle_values(values: &[Fp], table_size: usize) -> Result<Vec<Fp>, ExplicitTwistError> {
    let capacity = values
        .len()
        .checked_mul(table_size)
        .ok_or(ExplicitTwistError::Shape)?;
    let mut expanded = Vec::with_capacity(capacity);
    for value in values {
        expanded.resize(expanded.len() + table_size, *value);
    }
    Ok(expanded)
}

fn repeat_address_values(values: &[Fp], cycle_count: usize) -> Result<Vec<Fp>, ExplicitTwistError> {
    let capacity = values
        .len()
        .checked_mul(cycle_count)
        .ok_or(ExplicitTwistError::Shape)?;
    let mut repeated = Vec::with_capacity(capacity);
    for _ in 0..cycle_count {
        repeated.extend_from_slice(values);
    }
    Ok(repeated)
}

fn joined(left: &[Fp], right: &[Fp]) -> Vec<Fp> {
    left.iter().chain(right).copied().collect()
}

fn challenges(transcript: &mut Transcript, label: &[u8], count: usize) -> Vec<Fp> {
    (0..count)
        .map(|index| transcript.challenge(label, &index.to_le_bytes()))
        .collect()
}

fn statement_digest(initial_memory: &[u8], cycles: &[MemoryCycle]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update((initial_memory.len() as u64).to_le_bytes());
    hasher.update(initial_memory);
    hasher.update((cycles.len() as u64).to_le_bytes());
    for cycle in cycles {
        match cycle {
            MemoryCycle::Read { address, value } => {
                hasher.update([0]);
                hasher.update(address.to_le_bytes());
                hasher.update([*value]);
            }
            MemoryCycle::Write {
                address,
                before,
                after,
            } => {
                hasher.update([1]);
                hasher.update(address.to_le_bytes());
                hasher.update([*before, *after]);
            }
        }
    }
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::{ExplicitTwistProof, MemoryCycle};

    #[test]
    fn twist_checks_latest_values_and_rejects_read_write_tampering()
    -> Result<(), Box<dyn std::error::Error>> {
        let initial = [3_u8, 7, 11, 13, 17, 19, 23, 29];
        let cycles = [
            MemoryCycle::Read {
                address: 1,
                value: 7,
            },
            MemoryCycle::Write {
                address: 1,
                before: 7,
                after: 42,
            },
            MemoryCycle::Read {
                address: 1,
                value: 42,
            },
        ];
        let proof = ExplicitTwistProof::prove(&initial, &cycles)?;
        proof.verify(&initial, &cycles)?;
        assert_eq!(proof.proof_field_elements(), 68);

        let mut wrong_read = cycles;
        *wrong_read
            .get_mut(2)
            .ok_or_else(|| std::io::Error::other("missing third memory cycle"))? =
            MemoryCycle::Read {
                address: 1,
                value: 41,
            };
        assert!(proof.verify(&initial, &wrong_read).is_err());
        assert!(ExplicitTwistProof::prove(&initial, &wrong_read).is_err());

        let mut wrong_before = cycles;
        *wrong_before
            .get_mut(1)
            .ok_or_else(|| std::io::Error::other("missing second memory cycle"))? =
            MemoryCycle::Write {
                address: 1,
                before: 6,
                after: 42,
            };
        assert!(proof.verify(&initial, &wrong_before).is_err());
        assert!(ExplicitTwistProof::prove(&initial, &wrong_before).is_err());
        Ok(())
    }
}
