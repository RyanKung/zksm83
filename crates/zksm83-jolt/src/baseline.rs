//! Reproducible Akita opening used to gate the pinned backend.

use akita_config::proof_optimized::fp128;
use akita_pcs::{
    AkitaCommitmentScheme, AkitaDeserialize, AkitaError, AkitaSerialize, AkitaTranscript,
    BasisMode, CanonicalEncoding, ComputeBackendSetup, CpuBackend, OpeningClaims,
    PolynomialGroupClaims, UniformProverStack,
};
use akita_prover::{DensePoly, SelectedProverOpeningData};
use akita_serialization::SerializationError;
use akita_types::{AkitaBatchedProof, GroupBatchStatement};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{AkitaWorkerError, field_fold::fold_binary_layer};

type Config = fp128::DenseBounded;
type Field = fp128::Field;

const NUM_VARIABLES: usize = 14;
const POLYNOMIAL_LENGTH: usize = 1 << NUM_VARIABLES;
const TRANSCRIPT_DOMAIN: &[u8] = b"zksm83-akita-m0-v1";
const LAYOUT_DOMAIN: &[u8] = b"zksm83/akita/m0/dense-column/v1";
const SCHEDULE_ARTIFACT: &[u8] = include_bytes!("../protocol/akita/fp128_dense_bounded.aks");

/// Failure while producing, serializing, or verifying the M0 Akita opening.
#[derive(Debug, Error)]
pub enum BaselineError {
    /// Akita rejected setup, commitment, proof construction, or verification.
    #[error("Akita backend rejected the baseline: {0}")]
    Akita(#[from] AkitaError),
    /// The proof failed canonical serialization or deserialization.
    #[error("Akita proof serialization failed: {0}")]
    Serialization(#[from] SerializationError),
    /// The dense multilinear table did not match the expected M0 shape.
    #[error(
        "invalid M0 evaluation shape: expected {POLYNOMIAL_LENGTH} evaluations and \
         {NUM_VARIABLES} coordinates, got {evaluations} and {coordinates}"
    )]
    InvalidEvaluationShape {
        /// Actual number of evaluations.
        evaluations: usize,
        /// Actual number of evaluation-point coordinates.
        coordinates: usize,
    },
    /// The operating system rejected creation of the bounded prover worker.
    #[error("failed to start Akita prover worker: {0}")]
    WorkerSpawn(#[source] std::io::Error),
    /// The Akita prover worker panicked and its result was rejected.
    #[error("Akita prover worker terminated unexpectedly")]
    WorkerPanicked,
}

/// Evidence returned after the pinned Akita backend verifies one opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct BaselineReport {
    /// Number of variables in the multilinear polynomial.
    pub num_variables: usize,
    /// Number of evaluations committed by the prover.
    pub polynomial_length: usize,
    /// Protocol-owned digest binding the baseline column layout.
    pub layout_digest: [u8; 32],
    /// Serialized proof length accepted by the verifier.
    pub proof_size_bytes: usize,
    /// SHA-256 of the exact proof bytes accepted by the verifier.
    pub proof_sha256: [u8; 32],
}

/// Commits, opens, and verifies one deterministic multilinear polynomial.
///
/// This is a supply-chain and backend gate. It does not prove an SM83
/// transition and must not be presented as an execution receipt.
pub fn verify_transparent_opening() -> Result<BaselineReport, BaselineError> {
    match crate::on_akita_worker(verify_transparent_opening_on_worker) {
        Ok(result) => result,
        Err(AkitaWorkerError::Spawn(error)) => Err(BaselineError::WorkerSpawn(error)),
        Err(AkitaWorkerError::Panicked) => Err(BaselineError::WorkerPanicked),
    }
}

fn verify_transparent_opening_on_worker() -> Result<BaselineReport, BaselineError> {
    let layout_digest = layout_digest();
    let evaluations = baseline_evaluations();
    let polynomial = DensePoly::from_field_evals(NUM_VARIABLES, &evaluations)?;
    let point = baseline_point();
    let evaluation = evaluate_multilinear(&evaluations, &point)?;

    let scheme = AkitaCommitmentScheme::<Config>::from_schedule_artifact(SCHEDULE_ARTIFACT)?;
    let setup = scheme.setup_prover(NUM_VARIABLES, 1)?;
    let backend = CpuBackend::DEFAULT;
    let prepared = backend.prepare_setup(&setup)?;
    let stack = UniformProverStack::uniform(&backend, &prepared, setup.expanded.as_ref())?;
    let commit_output = scheme.commit(
        &setup,
        std::slice::from_ref(&polynomial),
        &stack,
        akita_prover::GroupContext::scheduler_without_precommitted_groups(),
    )?;

    let prover_claims = OpeningClaims::from_groups(vec![PolynomialGroupClaims::new(
        point.clone(),
        vec![evaluation],
        commit_output.committed_group.clone(),
    )?])?;
    let polynomial_group = [&polynomial];
    let prover_data = SelectedProverOpeningData::from_committed_claims::<Config>(
        prover_claims,
        vec![commit_output.hint],
        vec![&polynomial_group],
        scheme.schedules(),
    )?;
    let selection = prover_data.selection();
    let mut prover_transcript = AkitaTranscript::<Field>::unbound_prover(TRANSCRIPT_DOMAIN);
    let proof = scheme.batched_prove(
        &setup,
        prover_data,
        &stack,
        &mut prover_transcript,
        BasisMode::Lagrange,
    )?;

    let proof_shape = proof.shape();
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)?;
    let decoded_proof = AkitaBatchedProof::<Field, Field>::deserialize_compressed(
        &mut std::io::Cursor::new(&proof_bytes),
        &proof_shape,
    )?;

    let verifier_setup = scheme.setup_verifier(&setup)?;
    let verifier_claims = OpeningClaims::from_groups(vec![PolynomialGroupClaims::new(
        point,
        vec![evaluation],
        &commit_output.committed_group,
    )?])?;
    let statement = GroupBatchStatement::new(selection, verifier_claims)?;
    let mut verifier_transcript = AkitaTranscript::<Field>::unbound_verifier(TRANSCRIPT_DOMAIN);
    scheme.batched_verify(
        &decoded_proof,
        &verifier_setup,
        &mut verifier_transcript,
        statement,
        BasisMode::Lagrange,
    )?;

    Ok(BaselineReport {
        num_variables: NUM_VARIABLES,
        polynomial_length: POLYNOMIAL_LENGTH,
        layout_digest,
        proof_size_bytes: proof_bytes.len(),
        proof_sha256: Sha256::digest(&proof_bytes).into(),
    })
}

fn baseline_evaluations() -> Vec<Field> {
    let mut value = 1_u64;
    (0..POLYNOMIAL_LENGTH)
        .map(|_| {
            let evaluation = Field::from_u128_reduced(u128::from(value));
            value = value.wrapping_mul(3).wrapping_add(7);
            evaluation
        })
        .collect()
}

fn baseline_point() -> Vec<Field> {
    (2_u64..16)
        .map(|value| Field::from_u128_reduced(u128::from(value)))
        .collect()
}

fn layout_digest() -> [u8; 32] {
    Sha256::digest(LAYOUT_DOMAIN).into()
}

fn evaluate_multilinear(evaluations: &[Field], point: &[Field]) -> Result<Field, BaselineError> {
    if evaluations.len() != POLYNOMIAL_LENGTH || point.len() != NUM_VARIABLES {
        return Err(BaselineError::InvalidEvaluationShape {
            evaluations: evaluations.len(),
            coordinates: point.len(),
        });
    }
    let mut layer = evaluations.to_vec();
    for &coordinate in point {
        fold_binary_layer(&mut layer, coordinate).map_err(|_| {
            BaselineError::InvalidEvaluationShape {
                evaluations: evaluations.len(),
                coordinates: point.len(),
            }
        })?;
    }
    match layer.as_slice() {
        [evaluation] => Ok(*evaluation),
        _ => Err(BaselineError::InvalidEvaluationShape {
            evaluations: evaluations.len(),
            coordinates: point.len(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::BaselineError;
    use super::{SCHEDULE_ARTIFACT, verify_transparent_opening};
    use crate::AKITA_BASELINE_SCHEDULE_SHA256;
    use sha2::{Digest, Sha256};

    #[test]
    fn embedded_schedule_matches_pinned_digest() {
        assert_eq!(
            format!("{:x}", Sha256::digest(SCHEDULE_ARTIFACT)),
            AKITA_BASELINE_SCHEDULE_SHA256
        );
    }

    #[test]
    #[ignore = "expensive Akita setup and lattice opening gate"]
    fn pinned_transparent_akita_opening_verifies() -> Result<(), BaselineError> {
        let report = verify_transparent_opening()?;
        assert_eq!(report.num_variables, 14);
        assert_eq!(report.polynomial_length, 1 << report.num_variables);
        assert!(report.proof_size_bytes > 0);
        println!("{report:?}");
        Ok(())
    }
}
