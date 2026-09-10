//! O((K + T) log K)-time d=1 Twist prover with explicit terminal oracles.
//!
//! Unlike the dense reference, this implementation never materializes the
//! `K * T` virtual `Val` table. It folds address variables first and updates
//! only the one folded memory cell affected by each write. Polynomial
//! commitment openings are still pending, so verification currently receives
//! the initial memory and complete access list.

use ff::Field;
use pasta_curves::Fp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use thiserror::Error;

use crate::{
    ExplicitShoutError, IpaCommitment, IpaError, IpaOpeningProof, IpaParameters, MemoryCycle,
    shout::{eq_evaluations, evaluate_mle},
    sumcheck::{
        MultiProductSumcheckProof, ProductSumcheckError, ProductSumcheckProof, Transcript,
        encode_dynamic_round, evaluate_lagrange,
    },
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct AddressPhaseProof {
    rounds: Vec<Vec<Fp>>,
    cycle_sumcheck: MultiProductSumcheckProof,
}

/// Fast core Twist sumchecks using explicit terminal openings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FastExplicitTwistProof {
    cycle_count: usize,
    padded_cycle_count: usize,
    read: AddressPhaseProof,
    write: AddressPhaseProof,
    read_val_check: ProductSumcheckProof,
    write_val_check: ProductSumcheckProof,
}

/// Fast Twist proof with the initial-memory terminal bound by an IPA
/// commitment while the ordered cycle vector remains explicit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommittedInitialTwistProof {
    cycle_count: usize,
    padded_cycle_count: usize,
    initial_commitment: IpaCommitment,
    read: AddressPhaseProof,
    write: AddressPhaseProof,
    read_val_check: ProductSumcheckProof,
    write_val_check: ProductSumcheckProof,
    read_initial_value: Fp,
    write_initial_value: Fp,
    read_initial_opening: IpaOpeningProof,
    write_initial_opening: IpaOpeningProof,
}

impl FastExplicitTwistProof {
    /// Proves the same three Twist identities as the dense reference without
    /// materializing the virtual memory table across cycles.
    pub fn prove(initial_memory: &[u8], cycles: &[MemoryCycle]) -> Result<Self, FastTwistError> {
        let instance = FastInstance::new(initial_memory, cycles)?;
        let mut transcript = Transcript::new(
            b"zksm83-fast-explicit-twist/v1",
            &statement_digest(initial_memory, cycles),
        );
        let read_claim_point = challenges(
            &mut transcript,
            b"read-claim-cycle",
            instance.cycle_variables(),
        );
        let (read, read_address, read_cycle) =
            prove_read(&instance, &read_claim_point, &mut transcript)?;

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
        let (write, write_address, write_cycle) = prove_write(
            &instance,
            &write_claim_address,
            &write_claim_cycle,
            &mut transcript,
        )?;
        let read_val_check =
            prove_val_check(&instance, &read_address, &read_cycle, &mut transcript)?;
        let write_val_check =
            prove_val_check(&instance, &write_address, &write_cycle, &mut transcript)?;
        Ok(Self {
            cycle_count: cycles.len(),
            padded_cycle_count: instance.padded_cycle_count,
            read,
            write,
            read_val_check,
            write_val_check,
        })
    }

    /// Verifies the fast Twist proof against explicit statement oracles.
    pub fn verify(
        &self,
        initial_memory: &[u8],
        cycles: &[MemoryCycle],
    ) -> Result<(), FastTwistError> {
        let instance = FastInstance::new(initial_memory, cycles)?;
        if self.cycle_count != cycles.len()
            || self.padded_cycle_count != instance.padded_cycle_count
        {
            return Err(FastTwistError::StatementMismatch);
        }
        let mut transcript = Transcript::new(
            b"zksm83-fast-explicit-twist/v1",
            &statement_digest(initial_memory, cycles),
        );
        let read_claim_point = challenges(
            &mut transcript,
            b"read-claim-cycle",
            instance.cycle_variables(),
        );
        let (read_address, read_cycle) =
            verify_read(&self.read, &instance, &read_claim_point, &mut transcript)?;

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
        let (write_address, write_cycle) = verify_write(
            &self.write,
            &instance,
            &write_claim_address,
            &write_claim_cycle,
            &mut transcript,
        )?;
        verify_val_check(
            &self.read_val_check,
            &instance,
            &read_address,
            &read_cycle,
            &mut transcript,
        )?;
        verify_val_check(
            &self.write_val_check,
            &instance,
            &write_address,
            &write_cycle,
            &mut transcript,
        )
    }

    /// Returns all sumcheck message and terminal-opening field elements.
    #[must_use]
    pub fn proof_field_elements(&self) -> usize {
        address_phase_field_elements(&self.read)
            .saturating_add(address_phase_field_elements(&self.write))
            .saturating_add(self.read_val_check.field_elements())
            .saturating_add(self.write_val_check.field_elements())
    }
}

impl CommittedInitialTwistProof {
    /// Proves fast Twist while replacing the explicit initial-memory vector
    /// with two IPA openings of one binding commitment.
    pub fn prove(
        memory_parameters: &IpaParameters,
        initial_memory: &[u8],
        cycles: &[MemoryCycle],
    ) -> Result<Self, FastTwistError> {
        let instance = FastInstance::new(initial_memory, cycles)?;
        if memory_parameters.vector_len() != initial_memory.len() {
            return Err(FastTwistError::CommitmentShape);
        }
        let initial_commitment = memory_parameters.commit(&instance.initial)?;
        let mut transcript = Transcript::new(
            b"zksm83-fast-committed-initial-twist/v1",
            &committed_statement_digest(initial_memory.len(), initial_commitment, cycles),
        );
        let read_claim_point = challenges(
            &mut transcript,
            b"read-claim-cycle",
            instance.cycle_variables(),
        );
        let (read, read_address, read_cycle) =
            prove_read(&instance, &read_claim_point, &mut transcript)?;
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
        let (write, write_address, write_cycle) = prove_write(
            &instance,
            &write_claim_address,
            &write_claim_cycle,
            &mut transcript,
        )?;
        let read_val_check =
            prove_val_check(&instance, &read_address, &read_cycle, &mut transcript)?;
        let write_val_check =
            prove_val_check(&instance, &write_address, &write_cycle, &mut transcript)?;
        let read_initial_value = evaluate_mle(&instance.initial, &read_address)?;
        let write_initial_value = evaluate_mle(&instance.initial, &write_address)?;
        let read_initial_opening = memory_parameters.open_precommitted(
            &instance.initial,
            &read_address,
            initial_commitment,
        )?;
        let write_initial_opening = memory_parameters.open_precommitted(
            &instance.initial,
            &write_address,
            initial_commitment,
        )?;
        Ok(Self {
            cycle_count: cycles.len(),
            padded_cycle_count: instance.padded_cycle_count,
            initial_commitment,
            read,
            write,
            read_val_check,
            write_val_check,
            read_initial_value,
            write_initial_value,
            read_initial_opening,
            write_initial_opening,
        })
    }

    /// Verifies Twist without receiving the initial-memory bytes.
    pub fn verify(
        &self,
        memory_parameters: &IpaParameters,
        expected_initial_commitment: IpaCommitment,
        cycles: &[MemoryCycle],
    ) -> Result<(), FastTwistError> {
        if memory_parameters.vector_len() == 0 {
            return Err(FastTwistError::CommitmentShape);
        }
        if self.initial_commitment != expected_initial_commitment {
            return Err(FastTwistError::CommitmentMismatch);
        }
        let zero_memory = vec![0_u8; memory_parameters.vector_len()];
        let instance = FastInstance::new(&zero_memory, cycles)?;
        if self.cycle_count != cycles.len()
            || self.padded_cycle_count != instance.padded_cycle_count
        {
            return Err(FastTwistError::StatementMismatch);
        }
        let mut transcript = Transcript::new(
            b"zksm83-fast-committed-initial-twist/v1",
            &committed_statement_digest(
                memory_parameters.vector_len(),
                self.initial_commitment,
                cycles,
            ),
        );
        let read_claim_point = challenges(
            &mut transcript,
            b"read-claim-cycle",
            instance.cycle_variables(),
        );
        let (read_address, read_cycle) = verify_read_with_initial_value(
            &self.read,
            &instance,
            &read_claim_point,
            self.read_initial_value,
            &mut transcript,
        )?;
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
        let (write_address, write_cycle) = verify_write_with_initial_value(
            &self.write,
            &instance,
            &write_claim_address,
            &write_claim_cycle,
            self.write_initial_value,
            &mut transcript,
        )?;
        verify_val_check_with_initial_value(
            &self.read_val_check,
            &instance,
            &read_address,
            &read_cycle,
            self.read_initial_value,
            &mut transcript,
        )?;
        verify_val_check_with_initial_value(
            &self.write_val_check,
            &instance,
            &write_address,
            &write_cycle,
            self.write_initial_value,
            &mut transcript,
        )?;
        memory_parameters.verify(
            self.initial_commitment,
            &read_address,
            self.read_initial_value,
            &self.read_initial_opening,
        )?;
        memory_parameters.verify(
            self.initial_commitment,
            &write_address,
            self.write_initial_value,
            &self.write_initial_opening,
        )?;
        Ok(())
    }

    /// Returns the bound initial-memory commitment.
    #[must_use]
    pub const fn initial_commitment(&self) -> IpaCommitment {
        self.initial_commitment
    }

    /// Returns curve-point and scalar counts, excluding the explicit cycles.
    #[must_use]
    pub fn proof_element_count(&self) -> (usize, usize) {
        let (read_points, read_scalars) = self.read_initial_opening.element_count();
        let (write_points, write_scalars) = self.write_initial_opening.element_count();
        (
            read_points.saturating_add(write_points),
            address_phase_field_elements(&self.read)
                .saturating_add(address_phase_field_elements(&self.write))
                .saturating_add(self.read_val_check.field_elements())
                .saturating_add(self.write_val_check.field_elements())
                .saturating_add(read_scalars)
                .saturating_add(write_scalars)
                .saturating_add(2),
        )
    }
}

/// A fast explicit Twist statement or proof is malformed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FastTwistError {
    /// Initial memory must be a non-empty power-of-two table.
    #[error("fast Twist requires a non-empty power-of-two memory")]
    MemoryShape,
    /// At least one cycle is required.
    #[error("fast Twist cycle list is empty")]
    EmptyCycles,
    /// A physical address lies outside the supplied memory.
    #[error("fast Twist address {address} is outside memory size {memory_size}")]
    AddressOutOfRange {
        /// Rejected address.
        address: u32,
        /// Supplied memory size.
        memory_size: usize,
    },
    /// Proof counts differ from canonical statement counts.
    #[error("fast Twist statement count mismatch")]
    StatementMismatch,
    /// A read, write, or virtual-value identity is false.
    #[error("fast Twist relation is false")]
    Relation,
    /// A sumcheck proof failed.
    #[error("fast Twist sumcheck failed")]
    Sumcheck,
    /// An explicit terminal opening differs from its polynomial evaluation.
    #[error("fast Twist terminal opening mismatch")]
    OpeningMismatch,
    /// A multilinear vector, point, or folding step has inconsistent shape.
    #[error("fast Twist internal shape invariant failed")]
    Shape,
    /// PCS parameters do not match the mutable-memory address space.
    #[error("fast Twist memory and PCS parameter lengths disagree")]
    CommitmentShape,
    /// The proof is not bound to the externally expected memory commitment.
    #[error("fast Twist initial-memory commitment mismatch")]
    CommitmentMismatch,
    /// A polynomial commitment opening failed.
    #[error("fast Twist polynomial commitment opening failed")]
    CommitmentOpening,
}

impl From<ProductSumcheckError> for FastTwistError {
    fn from(_: ProductSumcheckError) -> Self {
        Self::Sumcheck
    }
}

impl From<ExplicitShoutError> for FastTwistError {
    fn from(_: ExplicitShoutError) -> Self {
        Self::Shape
    }
}

impl From<IpaError> for FastTwistError {
    fn from(_: IpaError) -> Self {
        Self::CommitmentOpening
    }
}

struct FastInstance<'a> {
    initial: Vec<Fp>,
    cycles: &'a [MemoryCycle],
    padded_cycle_count: usize,
}

struct CycleOpeningTables {
    read_address: Vec<Fp>,
    values: Vec<Fp>,
    write_address: Vec<Fp>,
}

impl<'a> FastInstance<'a> {
    fn new(initial_memory: &[u8], cycles: &'a [MemoryCycle]) -> Result<Self, FastTwistError> {
        if initial_memory.is_empty() || !initial_memory.len().is_power_of_two() {
            return Err(FastTwistError::MemoryShape);
        }
        if cycles.is_empty() {
            return Err(FastTwistError::EmptyCycles);
        }
        for cycle in cycles {
            if usize::try_from(cycle.address())
                .map_or(true, |address| address >= initial_memory.len())
            {
                return Err(FastTwistError::AddressOutOfRange {
                    address: cycle.address(),
                    memory_size: initial_memory.len(),
                });
            }
        }
        let padded_cycle_count = cycles
            .len()
            .checked_next_power_of_two()
            .ok_or(FastTwistError::Shape)?;
        Ok(Self {
            initial: initial_memory
                .iter()
                .map(|value| Fp::from(u64::from(*value)))
                .collect(),
            cycles,
            padded_cycle_count,
        })
    }

    fn address_variables(&self) -> usize {
        self.initial.len().ilog2() as usize
    }

    fn cycle_variables(&self) -> usize {
        self.padded_cycle_count.ilog2() as usize
    }

    fn cycle(&self, index: usize) -> Option<MemoryCycle> {
        self.cycles.get(index).copied()
    }
}

fn prove_read(
    instance: &FastInstance<'_>,
    claim_cycle: &[Fp],
    transcript: &mut Transcript,
) -> Result<(AddressPhaseProof, Vec<Fp>, Vec<Fp>), FastTwistError> {
    let cycle_weights = eq_evaluations(claim_cycle)?;
    let mut claim = read_claim(instance, &cycle_weights)?;
    let mut initial_folded = instance.initial.clone();
    let mut address_challenges = Vec::with_capacity(instance.address_variables());
    let mut rounds = Vec::with_capacity(instance.address_variables());
    for round in 0..instance.address_variables() {
        let message = read_address_round(
            instance,
            &cycle_weights,
            &initial_folded,
            &address_challenges,
            round,
        )?;
        require_round_claim(&message, claim)?;
        let challenge = transcript.challenge(
            b"fast-twist-read-address-round",
            &round_payload(round, &message),
        );
        claim = evaluate_lagrange(&message, challenge)?;
        fold_table(&mut initial_folded, challenge)?;
        address_challenges.push(challenge);
        rounds.push(message);
    }
    let factors = read_cycle_factors(instance, &cycle_weights, &address_challenges)?;
    let mut replay = transcript.clone();
    let (cycle_sumcheck, actual_claim) = MultiProductSumcheckProof::prove(&factors, transcript)?;
    if actual_claim != claim {
        return Err(FastTwistError::Relation);
    }
    let cycle_challenges =
        cycle_sumcheck.verify(claim, instance.cycle_variables(), 3, &mut replay)?;
    Ok((
        AddressPhaseProof {
            rounds,
            cycle_sumcheck,
        },
        address_challenges,
        cycle_challenges,
    ))
}

fn verify_read(
    proof: &AddressPhaseProof,
    instance: &FastInstance<'_>,
    claim_cycle: &[Fp],
    transcript: &mut Transcript,
) -> Result<(Vec<Fp>, Vec<Fp>), FastTwistError> {
    if proof.rounds.len() != instance.address_variables() {
        return Err(FastTwistError::StatementMismatch);
    }
    let cycle_weights = eq_evaluations(claim_cycle)?;
    let mut claim = read_claim(instance, &cycle_weights)?;
    let mut address_challenges = Vec::with_capacity(instance.address_variables());
    for (round, message) in proof.rounds.iter().enumerate() {
        if message.len() != 3 {
            return Err(FastTwistError::StatementMismatch);
        }
        require_round_claim(message, claim)?;
        let challenge = transcript.challenge(
            b"fast-twist-read-address-round",
            &round_payload(round, message),
        );
        claim = evaluate_lagrange(message, challenge)?;
        address_challenges.push(challenge);
    }
    let factors = read_cycle_factors(instance, &cycle_weights, &address_challenges)?;
    let cycle_challenges =
        proof
            .cycle_sumcheck
            .verify(claim, instance.cycle_variables(), 3, transcript)?;
    verify_factor_openings(&proof.cycle_sumcheck, &factors, &cycle_challenges)?;
    Ok((address_challenges, cycle_challenges))
}

fn verify_read_with_initial_value(
    proof: &AddressPhaseProof,
    instance: &FastInstance<'_>,
    claim_cycle: &[Fp],
    initial_value: Fp,
    transcript: &mut Transcript,
) -> Result<(Vec<Fp>, Vec<Fp>), FastTwistError> {
    if proof.rounds.len() != instance.address_variables() {
        return Err(FastTwistError::StatementMismatch);
    }
    let cycle_weights = eq_evaluations(claim_cycle)?;
    let mut claim = read_claim(instance, &cycle_weights)?;
    let mut address_challenges = Vec::with_capacity(instance.address_variables());
    for (round, message) in proof.rounds.iter().enumerate() {
        if message.len() != 3 {
            return Err(FastTwistError::StatementMismatch);
        }
        require_round_claim(message, claim)?;
        let challenge = transcript.challenge(
            b"fast-twist-read-address-round",
            &round_payload(round, message),
        );
        claim = evaluate_lagrange(message, challenge)?;
        address_challenges.push(challenge);
    }
    let factors = read_cycle_factors_with_initial_value(
        instance,
        &cycle_weights,
        &address_challenges,
        initial_value,
    )?;
    let cycle_challenges =
        proof
            .cycle_sumcheck
            .verify(claim, instance.cycle_variables(), 3, transcript)?;
    verify_factor_openings(&proof.cycle_sumcheck, &factors, &cycle_challenges)?;
    Ok((address_challenges, cycle_challenges))
}

fn prove_write(
    instance: &FastInstance<'_>,
    claim_address: &[Fp],
    claim_cycle: &[Fp],
    transcript: &mut Transcript,
) -> Result<(AddressPhaseProof, Vec<Fp>, Vec<Fp>), FastTwistError> {
    let cycle_weights = eq_evaluations(claim_cycle)?;
    let mut claim = increment_claim(instance, claim_address, &cycle_weights)?;
    let mut initial_folded = instance.initial.clone();
    let mut address_challenges = Vec::with_capacity(instance.address_variables());
    let mut rounds = Vec::with_capacity(instance.address_variables());
    for round in 0..instance.address_variables() {
        let message = write_address_round(
            instance,
            claim_address,
            &cycle_weights,
            &initial_folded,
            &address_challenges,
            round,
        )?;
        require_round_claim(&message, claim)?;
        let challenge = transcript.challenge(
            b"fast-twist-write-address-round",
            &round_payload(round, &message),
        );
        claim = evaluate_lagrange(&message, challenge)?;
        fold_table(&mut initial_folded, challenge)?;
        address_challenges.push(challenge);
        rounds.push(message);
    }
    let factors =
        write_cycle_factors(instance, claim_address, &cycle_weights, &address_challenges)?;
    let mut replay = transcript.clone();
    let (cycle_sumcheck, actual_claim) = MultiProductSumcheckProof::prove(&factors, transcript)?;
    if actual_claim != claim {
        return Err(FastTwistError::Relation);
    }
    let cycle_challenges =
        cycle_sumcheck.verify(claim, instance.cycle_variables(), 3, &mut replay)?;
    Ok((
        AddressPhaseProof {
            rounds,
            cycle_sumcheck,
        },
        address_challenges,
        cycle_challenges,
    ))
}

fn verify_write(
    proof: &AddressPhaseProof,
    instance: &FastInstance<'_>,
    claim_address: &[Fp],
    claim_cycle: &[Fp],
    transcript: &mut Transcript,
) -> Result<(Vec<Fp>, Vec<Fp>), FastTwistError> {
    if proof.rounds.len() != instance.address_variables() {
        return Err(FastTwistError::StatementMismatch);
    }
    let cycle_weights = eq_evaluations(claim_cycle)?;
    let mut claim = increment_claim(instance, claim_address, &cycle_weights)?;
    let mut address_challenges = Vec::with_capacity(instance.address_variables());
    for (round, message) in proof.rounds.iter().enumerate() {
        if message.len() != 4 {
            return Err(FastTwistError::StatementMismatch);
        }
        require_round_claim(message, claim)?;
        let challenge = transcript.challenge(
            b"fast-twist-write-address-round",
            &round_payload(round, message),
        );
        claim = evaluate_lagrange(message, challenge)?;
        address_challenges.push(challenge);
    }
    let factors =
        write_cycle_factors(instance, claim_address, &cycle_weights, &address_challenges)?;
    let cycle_challenges =
        proof
            .cycle_sumcheck
            .verify(claim, instance.cycle_variables(), 3, transcript)?;
    verify_factor_openings(&proof.cycle_sumcheck, &factors, &cycle_challenges)?;
    Ok((address_challenges, cycle_challenges))
}

fn verify_write_with_initial_value(
    proof: &AddressPhaseProof,
    instance: &FastInstance<'_>,
    claim_address: &[Fp],
    claim_cycle: &[Fp],
    initial_value: Fp,
    transcript: &mut Transcript,
) -> Result<(Vec<Fp>, Vec<Fp>), FastTwistError> {
    if proof.rounds.len() != instance.address_variables() {
        return Err(FastTwistError::StatementMismatch);
    }
    let cycle_weights = eq_evaluations(claim_cycle)?;
    let mut claim = increment_claim(instance, claim_address, &cycle_weights)?;
    let mut address_challenges = Vec::with_capacity(instance.address_variables());
    for (round, message) in proof.rounds.iter().enumerate() {
        if message.len() != 4 {
            return Err(FastTwistError::StatementMismatch);
        }
        require_round_claim(message, claim)?;
        let challenge = transcript.challenge(
            b"fast-twist-write-address-round",
            &round_payload(round, message),
        );
        claim = evaluate_lagrange(message, challenge)?;
        address_challenges.push(challenge);
    }
    let factors = write_cycle_factors_with_initial_value(
        instance,
        claim_address,
        &cycle_weights,
        &address_challenges,
        initial_value,
    )?;
    let cycle_challenges =
        proof
            .cycle_sumcheck
            .verify(claim, instance.cycle_variables(), 3, transcript)?;
    verify_factor_openings(&proof.cycle_sumcheck, &factors, &cycle_challenges)?;
    Ok((address_challenges, cycle_challenges))
}

fn read_address_round(
    instance: &FastInstance<'_>,
    cycle_weights: &[Fp],
    initial_folded: &[Fp],
    bound: &[Fp],
    round: usize,
) -> Result<Vec<Fp>, FastTwistError> {
    let mut memory = initial_folded.to_vec();
    let mut message = vec![Fp::ZERO; 3];
    for cycle_index in 0..instance.padded_cycle_count {
        let Some(cycle) = instance.cycle(cycle_index) else {
            continue;
        };
        let address = usize::try_from(cycle.address()).map_err(|_| FastTwistError::Shape)?;
        let (zero, one) = memory_pair(&memory, address, round)?;
        let prefix = one_hot_weight(address, bound);
        let bit = address_bit(address, round);
        let cycle_weight = cycle_weights
            .get(cycle_index)
            .copied()
            .ok_or(FastTwistError::Shape)?;
        for (candidate, evaluation) in message.iter_mut().enumerate() {
            let point = Fp::from(u64::try_from(candidate).map_err(|_| FastTwistError::Shape)?);
            let ra = prefix * eq_boolean(point, bit);
            let value = zero + point * (one - zero);
            *evaluation += cycle_weight * ra * value;
        }
        apply_folded_write(&mut memory, cycle, address, round, prefix)?;
    }
    Ok(message)
}

fn write_address_round(
    instance: &FastInstance<'_>,
    claim_address: &[Fp],
    cycle_weights: &[Fp],
    initial_folded: &[Fp],
    bound: &[Fp],
    round: usize,
) -> Result<Vec<Fp>, FastTwistError> {
    let mut memory = initial_folded.to_vec();
    let mut message = vec![Fp::ZERO; 4];
    for cycle_index in 0..instance.padded_cycle_count {
        let Some(cycle) = instance.cycle(cycle_index) else {
            continue;
        };
        let address = usize::try_from(cycle.address()).map_err(|_| FastTwistError::Shape)?;
        if let MemoryCycle::Write { after, .. } = cycle {
            let (zero, one) = memory_pair(&memory, address, round)?;
            let prefix = one_hot_weight(address, bound);
            let bit = address_bit(address, round);
            let cycle_weight = cycle_weights
                .get(cycle_index)
                .copied()
                .ok_or(FastTwistError::Shape)?;
            for (candidate, evaluation) in message.iter_mut().enumerate() {
                let point = Fp::from(u64::try_from(candidate).map_err(|_| FastTwistError::Shape)?);
                let address_eq =
                    mixed_target_equality(claim_address, bound, address, round, point)?;
                let wa = prefix * eq_boolean(point, bit);
                let value = zero + point * (one - zero);
                *evaluation +=
                    cycle_weight * address_eq * wa * (Fp::from(u64::from(after)) - value);
            }
        }
        let prefix = one_hot_weight(address, bound);
        apply_folded_write(&mut memory, cycle, address, round, prefix)?;
    }
    Ok(message)
}

fn read_cycle_factors(
    instance: &FastInstance<'_>,
    cycle_weights: &[Fp],
    address_point: &[Fp],
) -> Result<Vec<Vec<Fp>>, FastTwistError> {
    let tables = cycle_opening_tables(instance, address_point)?;
    Ok(vec![
        cycle_weights.to_vec(),
        tables.read_address,
        tables.values,
    ])
}

fn read_cycle_factors_with_initial_value(
    instance: &FastInstance<'_>,
    cycle_weights: &[Fp],
    address_point: &[Fp],
    initial_value: Fp,
) -> Result<Vec<Vec<Fp>>, FastTwistError> {
    let tables = cycle_opening_tables_from_initial_value(instance, address_point, initial_value)?;
    Ok(vec![
        cycle_weights.to_vec(),
        tables.read_address,
        tables.values,
    ])
}

fn write_cycle_factors(
    instance: &FastInstance<'_>,
    claim_address: &[Fp],
    cycle_weights: &[Fp],
    address_point: &[Fp],
) -> Result<Vec<Vec<Fp>>, FastTwistError> {
    let tables = cycle_opening_tables(instance, address_point)?;
    write_cycle_factors_from_tables(
        instance,
        claim_address,
        cycle_weights,
        address_point,
        tables,
    )
}

fn write_cycle_factors_from_tables(
    instance: &FastInstance<'_>,
    claim_address: &[Fp],
    cycle_weights: &[Fp],
    address_point: &[Fp],
    tables: CycleOpeningTables,
) -> Result<Vec<Vec<Fp>>, FastTwistError> {
    let address_eq = equality_points(claim_address, address_point)?;
    let weighted_cycle = cycle_weights
        .iter()
        .map(|weight| address_eq * weight)
        .collect::<Vec<_>>();
    let write_delta = (0..instance.padded_cycle_count)
        .map(|cycle_index| {
            let value = tables
                .values
                .get(cycle_index)
                .copied()
                .ok_or(FastTwistError::Shape)?;
            Ok(match instance.cycle(cycle_index) {
                Some(MemoryCycle::Write { after, .. }) => Fp::from(u64::from(after)) - value,
                _ => -value,
            })
        })
        .collect::<Result<Vec<_>, FastTwistError>>()?;
    Ok(vec![weighted_cycle, tables.write_address, write_delta])
}

fn write_cycle_factors_with_initial_value(
    instance: &FastInstance<'_>,
    claim_address: &[Fp],
    cycle_weights: &[Fp],
    address_point: &[Fp],
    initial_value: Fp,
) -> Result<Vec<Vec<Fp>>, FastTwistError> {
    let tables = cycle_opening_tables_from_initial_value(instance, address_point, initial_value)?;
    write_cycle_factors_from_tables(
        instance,
        claim_address,
        cycle_weights,
        address_point,
        tables,
    )
}

fn cycle_opening_tables(
    instance: &FastInstance<'_>,
    address_point: &[Fp],
) -> Result<CycleOpeningTables, FastTwistError> {
    let initial_value = evaluate_mle(&instance.initial, address_point)?;
    cycle_opening_tables_from_initial_value(instance, address_point, initial_value)
}

fn cycle_opening_tables_from_initial_value(
    instance: &FastInstance<'_>,
    address_point: &[Fp],
    mut current_value: Fp,
) -> Result<CycleOpeningTables, FastTwistError> {
    let mut read_address = vec![Fp::ZERO; instance.padded_cycle_count];
    let mut write_address = vec![Fp::ZERO; instance.padded_cycle_count];
    let mut values = vec![Fp::ZERO; instance.padded_cycle_count];
    for cycle_index in 0..instance.padded_cycle_count {
        *values.get_mut(cycle_index).ok_or(FastTwistError::Shape)? = current_value;
        let Some(cycle) = instance.cycle(cycle_index) else {
            continue;
        };
        let address = usize::try_from(cycle.address()).map_err(|_| FastTwistError::Shape)?;
        let weight = one_hot_weight(address, address_point);
        *read_address
            .get_mut(cycle_index)
            .ok_or(FastTwistError::Shape)? = weight;
        if let MemoryCycle::Write { before, after, .. } = cycle {
            *write_address
                .get_mut(cycle_index)
                .ok_or(FastTwistError::Shape)? = weight;
            current_value += weight * (Fp::from(u64::from(after)) - Fp::from(u64::from(before)));
        }
    }
    Ok(CycleOpeningTables {
        read_address,
        values,
        write_address,
    })
}

fn prove_val_check(
    instance: &FastInstance<'_>,
    address_point: &[Fp],
    cycle_point: &[Fp],
    transcript: &mut Transcript,
) -> Result<ProductSumcheckProof, FastTwistError> {
    let (claim, increments, less_than) = val_check_instance(instance, address_point, cycle_point)?;
    let (proof, actual) = ProductSumcheckProof::prove(&increments, &less_than, transcript)?;
    if actual != claim {
        return Err(FastTwistError::Relation);
    }
    Ok(proof)
}

fn verify_val_check(
    proof: &ProductSumcheckProof,
    instance: &FastInstance<'_>,
    address_point: &[Fp],
    cycle_point: &[Fp],
    transcript: &mut Transcript,
) -> Result<(), FastTwistError> {
    let (claim, increments, less_than) = val_check_instance(instance, address_point, cycle_point)?;
    let challenge = proof.verify(claim, instance.cycle_variables(), transcript)?;
    if proof.final_left() != evaluate_mle(&increments, &challenge)?
        || proof.final_right() != evaluate_mle(&less_than, &challenge)?
    {
        return Err(FastTwistError::OpeningMismatch);
    }
    Ok(())
}

fn verify_val_check_with_initial_value(
    proof: &ProductSumcheckProof,
    instance: &FastInstance<'_>,
    address_point: &[Fp],
    cycle_point: &[Fp],
    initial_value: Fp,
    transcript: &mut Transcript,
) -> Result<(), FastTwistError> {
    let (claim, increments, less_than) =
        val_check_instance_from_initial_value(instance, address_point, cycle_point, initial_value)?;
    let challenge = proof.verify(claim, instance.cycle_variables(), transcript)?;
    if proof.final_left() != evaluate_mle(&increments, &challenge)?
        || proof.final_right() != evaluate_mle(&less_than, &challenge)?
    {
        return Err(FastTwistError::OpeningMismatch);
    }
    Ok(())
}

fn val_check_instance(
    instance: &FastInstance<'_>,
    address_point: &[Fp],
    cycle_point: &[Fp],
) -> Result<(Fp, Vec<Fp>, Vec<Fp>), FastTwistError> {
    let tables = cycle_opening_tables(instance, address_point)?;
    let initial = evaluate_mle(&instance.initial, address_point)?;
    val_check_instance_from_tables(instance, cycle_point, initial, tables)
}

fn val_check_instance_from_initial_value(
    instance: &FastInstance<'_>,
    address_point: &[Fp],
    cycle_point: &[Fp],
    initial_value: Fp,
) -> Result<(Fp, Vec<Fp>, Vec<Fp>), FastTwistError> {
    let tables = cycle_opening_tables_from_initial_value(instance, address_point, initial_value)?;
    val_check_instance_from_tables(instance, cycle_point, initial_value, tables)
}

fn val_check_instance_from_tables(
    instance: &FastInstance<'_>,
    cycle_point: &[Fp],
    initial: Fp,
    tables: CycleOpeningTables,
) -> Result<(Fp, Vec<Fp>, Vec<Fp>), FastTwistError> {
    let value = evaluate_mle(&tables.values, cycle_point)?;
    let increments = (0..instance.padded_cycle_count)
        .map(|cycle_index| {
            let weight = tables
                .write_address
                .get(cycle_index)
                .copied()
                .ok_or(FastTwistError::Shape)?;
            Ok(match instance.cycle(cycle_index) {
                Some(MemoryCycle::Write { before, after, .. }) => {
                    weight * (Fp::from(u64::from(after)) - Fp::from(u64::from(before)))
                }
                _ => Fp::ZERO,
            })
        })
        .collect::<Result<Vec<_>, FastTwistError>>()?;
    Ok((
        value - initial,
        increments,
        less_than_evaluations(cycle_point)?,
    ))
}

fn read_claim(instance: &FastInstance<'_>, cycle_weights: &[Fp]) -> Result<Fp, FastTwistError> {
    (0..instance.padded_cycle_count).try_fold(Fp::ZERO, |claim, cycle_index| {
        let weight = cycle_weights
            .get(cycle_index)
            .copied()
            .ok_or(FastTwistError::Shape)?;
        let value = match instance.cycle(cycle_index) {
            Some(MemoryCycle::Read { value, .. }) => Fp::from(u64::from(value)),
            Some(MemoryCycle::Write { before, .. }) => Fp::from(u64::from(before)),
            None => Fp::ZERO,
        };
        Ok(claim + weight * value)
    })
}

fn increment_claim(
    instance: &FastInstance<'_>,
    address_point: &[Fp],
    cycle_weights: &[Fp],
) -> Result<Fp, FastTwistError> {
    (0..instance.padded_cycle_count).try_fold(Fp::ZERO, |claim, cycle_index| {
        let Some(MemoryCycle::Write {
            address,
            before,
            after,
        }) = instance.cycle(cycle_index)
        else {
            return Ok(claim);
        };
        let address = usize::try_from(address).map_err(|_| FastTwistError::Shape)?;
        let cycle_weight = cycle_weights
            .get(cycle_index)
            .copied()
            .ok_or(FastTwistError::Shape)?;
        Ok(claim
            + cycle_weight
                * one_hot_weight(address, address_point)
                * (Fp::from(u64::from(after)) - Fp::from(u64::from(before))))
    })
}

fn apply_folded_write(
    memory: &mut [Fp],
    cycle: MemoryCycle,
    address: usize,
    round: usize,
    prefix: Fp,
) -> Result<(), FastTwistError> {
    if let MemoryCycle::Write { before, after, .. } = cycle {
        let suffix = address
            .checked_shr(u32::try_from(round).map_err(|_| FastTwistError::Shape)?)
            .ok_or(FastTwistError::Shape)?;
        let target = memory.get_mut(suffix).ok_or(FastTwistError::Shape)?;
        *target += prefix * (Fp::from(u64::from(after)) - Fp::from(u64::from(before)));
    }
    Ok(())
}

fn memory_pair(memory: &[Fp], address: usize, round: usize) -> Result<(Fp, Fp), FastTwistError> {
    let shift = u32::try_from(round.saturating_add(1)).map_err(|_| FastTwistError::Shape)?;
    let pair = address
        .checked_shr(shift)
        .and_then(|suffix| suffix.checked_mul(2))
        .ok_or(FastTwistError::Shape)?;
    Ok((
        memory.get(pair).copied().ok_or(FastTwistError::Shape)?,
        memory
            .get(pair.saturating_add(1))
            .copied()
            .ok_or(FastTwistError::Shape)?,
    ))
}

fn fold_table(table: &mut Vec<Fp>, challenge: Fp) -> Result<(), FastTwistError> {
    if table.len() <= 1 || !table.len().is_power_of_two() {
        return Err(FastTwistError::Shape);
    }
    let mut folded = Vec::with_capacity(table.len() / 2);
    for pair in table.chunks_exact(2) {
        let zero = pair.first().copied().ok_or(FastTwistError::Shape)?;
        let one = pair.get(1).copied().ok_or(FastTwistError::Shape)?;
        folded.push(zero + challenge * (one - zero));
    }
    *table = folded;
    Ok(())
}

fn mixed_target_equality(
    target: &[Fp],
    bound: &[Fp],
    address: usize,
    round: usize,
    candidate: Fp,
) -> Result<Fp, FastTwistError> {
    if round >= target.len() || bound.len() != round {
        return Err(FastTwistError::Shape);
    }
    let mut value = Fp::ONE;
    for (index, target_coordinate) in target.iter().enumerate() {
        let coordinate = if index < round {
            bound.get(index).copied().ok_or(FastTwistError::Shape)?
        } else if index == round {
            candidate
        } else {
            Fp::from(address_bit(address, index))
        };
        value *=
            target_coordinate * coordinate + (Fp::ONE - target_coordinate) * (Fp::ONE - coordinate);
    }
    Ok(value)
}

fn one_hot_weight(address: usize, point: &[Fp]) -> Fp {
    point
        .iter()
        .enumerate()
        .fold(Fp::ONE, |weight, (bit, coordinate)| {
            weight * eq_boolean(*coordinate, address_bit(address, bit))
        })
}

fn equality_points(left: &[Fp], right: &[Fp]) -> Result<Fp, FastTwistError> {
    if left.len() != right.len() {
        return Err(FastTwistError::Shape);
    }
    Ok(left
        .iter()
        .zip(right)
        .fold(Fp::ONE, |value, (left, right)| {
            value * (left * right + (Fp::ONE - left) * (Fp::ONE - right))
        }))
}

fn eq_boolean(point: Fp, bit: u64) -> Fp {
    if bit == 0 { Fp::ONE - point } else { point }
}

fn address_bit(address: usize, bit: usize) -> u64 {
    u64::from(((address >> bit) & 1) != 0)
}

fn less_than_evaluations(cycle_point: &[Fp]) -> Result<Vec<Fp>, FastTwistError> {
    let target_weights = eq_evaluations(cycle_point)?;
    let mut suffix = Fp::ZERO;
    let mut result = vec![Fp::ZERO; target_weights.len()];
    for index in (0..target_weights.len()).rev() {
        *result.get_mut(index).ok_or(FastTwistError::Shape)? = suffix;
        suffix += target_weights
            .get(index)
            .copied()
            .ok_or(FastTwistError::Shape)?;
    }
    Ok(result)
}

fn verify_factor_openings(
    proof: &MultiProductSumcheckProof,
    factors: &[Vec<Fp>],
    point: &[Fp],
) -> Result<(), FastTwistError> {
    if proof.final_factors().len() != factors.len() {
        return Err(FastTwistError::OpeningMismatch);
    }
    for (opening, factor) in proof.final_factors().iter().zip(factors) {
        if *opening != evaluate_mle(factor, point)? {
            return Err(FastTwistError::OpeningMismatch);
        }
    }
    Ok(())
}

fn require_round_claim(message: &[Fp], claim: Fp) -> Result<(), FastTwistError> {
    let zero = message.first().copied().ok_or(FastTwistError::Shape)?;
    let one = message.get(1).copied().ok_or(FastTwistError::Shape)?;
    if zero + one != claim {
        return Err(FastTwistError::Relation);
    }
    Ok(())
}

fn round_payload(round: usize, message: &[Fp]) -> Vec<u8> {
    let mut payload = round.to_le_bytes().to_vec();
    payload.extend_from_slice(&encode_dynamic_round(message));
    payload
}

fn address_phase_field_elements(proof: &AddressPhaseProof) -> usize {
    proof
        .rounds
        .iter()
        .map(Vec::len)
        .sum::<usize>()
        .saturating_add(proof.cycle_sumcheck.field_elements())
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

fn committed_statement_digest(
    memory_size: usize,
    commitment: IpaCommitment,
    cycles: &[MemoryCycle],
) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update((memory_size as u64).to_le_bytes());
    hasher.update(commitment.to_bytes());
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
    use super::{CommittedInitialTwistProof, FastExplicitTwistProof};
    use crate::{ExplicitTwistProof, IpaParameters, MemoryCycle};

    #[test]
    fn fast_twist_matches_dense_reference_and_rejects_tampering()
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
            MemoryCycle::Write {
                address: 6,
                before: 23,
                after: 5,
            },
            MemoryCycle::Read {
                address: 1,
                value: 42,
            },
        ];
        let dense = ExplicitTwistProof::prove(&initial, &cycles)?;
        dense.verify(&initial, &cycles)?;
        let fast = FastExplicitTwistProof::prove(&initial, &cycles)?;
        fast.verify(&initial, &cycles)?;
        assert_eq!(fast.proof_field_elements(), 59);
        assert!(fast.proof_field_elements() < dense.proof_field_elements());

        let mut wrong = cycles;
        *wrong
            .get_mut(3)
            .ok_or_else(|| std::io::Error::other("missing final read"))? = MemoryCycle::Read {
            address: 1,
            value: 41,
        };
        assert!(fast.verify(&initial, &wrong).is_err());
        assert!(FastExplicitTwistProof::prove(&initial, &wrong).is_err());
        Ok(())
    }

    #[test]
    fn committed_initial_twist_rejects_wrong_commitment_and_cycles()
    -> Result<(), Box<dyn std::error::Error>> {
        let initial = [3_u8, 7, 11, 13, 17, 19, 23, 29];
        let cycles = [
            MemoryCycle::Read {
                address: 2,
                value: 11,
            },
            MemoryCycle::Write {
                address: 2,
                before: 11,
                after: 41,
            },
            MemoryCycle::Read {
                address: 2,
                value: 41,
            },
            MemoryCycle::Write {
                address: 6,
                before: 23,
                after: 43,
            },
        ];
        let parameters = IpaParameters::new(initial.len())?;
        let proof = CommittedInitialTwistProof::prove(&parameters, &initial, &cycles)?;
        let expected = proof.initial_commitment();
        proof.verify(&parameters, expected, &cycles)?;
        assert_eq!(proof.proof_element_count().0, 12);

        let wrong_initial = [2_u64, 3, 5, 7, 11, 13, 17, 19].map(pasta_curves::Fp::from);
        let wrong_commitment = parameters.commit(&wrong_initial)?;
        assert!(
            proof
                .verify(&parameters, wrong_commitment, &cycles)
                .is_err()
        );
        let mut wrong_cycles = cycles;
        let read = wrong_cycles
            .get_mut(2)
            .ok_or_else(|| std::io::Error::other("missing third Twist cycle"))?;
        *read = MemoryCycle::Read {
            address: 2,
            value: 40,
        };
        assert!(proof.verify(&parameters, expected, &wrong_cycles).is_err());
        Ok(())
    }
}
