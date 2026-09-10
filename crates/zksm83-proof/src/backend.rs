//! Halo2 IPA proof construction and verification over the Pasta cycle.

use halo2_proofs::{
    plonk::{SingleVerifier, create_proof, keygen_pk, keygen_vk, verify_proof},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{EqAffine, Fp};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zksm83_trace::Witness;

use crate::{
    ExecutionShape, PublicInputError, PublicInputs, ShapeError, circuit::ExecutionCircuit,
};

const MIN_K: u32 = 15;
const MAX_K: u32 = 18;
const BASE_ROWS: usize = 8_192;
const ROWS_PER_EVENT: usize = 1_536;

/// Self-contained proof payload plus the public verifier-derived circuit shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofArtifact {
    /// IPA parameter exponent; the circuit uses `2^k` rows.
    pub k: u32,
    /// Public instruction, branch, and bus-event specialization used to derive the key.
    pub shape: ExecutionShape,
    /// Blake2b-transcript Halo2 IPA proof bytes.
    pub proof: Vec<u8>,
}

/// Evidence that the backend accepted a proof under the derived verification key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedProof {
    /// Verified circuit-size exponent.
    pub k: u32,
    /// Verified instruction count.
    pub step_count: u64,
}

/// Proof construction or verification failure.
#[derive(Debug, Error)]
pub enum ProofError {
    /// Public shape is malformed or non-canonical.
    #[error(transparent)]
    Shape(#[from] ShapeError),
    /// Public values do not describe the supplied validated witness.
    #[error(transparent)]
    PublicInputs(#[from] PublicInputError),
    /// Shape row estimate cannot be represented.
    #[error("circuit row estimate overflow")]
    RowEstimateOverflow,
    /// The shape exceeds the supported transparent parameter bound.
    #[error("circuit requires k={required}, maximum supported k is {maximum}")]
    CircuitTooLarge {
        /// Estimated required exponent.
        required: u32,
        /// Configured verifier maximum.
        maximum: u32,
    },
    /// Receipt selected a different circuit exponent from the canonical shape estimate.
    #[error("non-canonical circuit exponent: expected {expected}, found {actual}")]
    NonCanonicalK {
        /// Deterministic exponent for the shape.
        expected: u32,
        /// Supplied artifact exponent.
        actual: u32,
    },
    /// Verification key derivation failed.
    #[error("verification-key derivation failed: {0}")]
    VerificationKey(halo2_proofs::plonk::Error),
    /// Proving key derivation failed.
    #[error("proving-key derivation failed: {0}")]
    ProvingKey(halo2_proofs::plonk::Error),
    /// Proof construction failed.
    #[error("proof construction failed: {0}")]
    Proving(halo2_proofs::plonk::Error),
    /// IPA proof verification failed.
    #[error("proof verification failed: {0}")]
    Verification(halo2_proofs::plonk::Error),
}

/// Constructs a real Halo2 IPA proof for one validated execution witness.
pub fn prove(witness: &Witness, public_inputs: PublicInputs) -> Result<ProofArtifact, ProofError> {
    public_inputs.validate_witness(witness)?;
    let shape = ExecutionShape::from_witness(witness)?;
    shape.validate()?;
    let k = recommended_k(&shape)?;
    let params: Params<EqAffine> = Params::new(k);
    let empty = ExecutionCircuit {
        shape: shape.clone(),
        witness: None,
        public_inputs: None,
    };
    let vk = keygen_vk(&params, &empty).map_err(ProofError::VerificationKey)?;
    let pk = keygen_pk(&params, vk, &empty).map_err(ProofError::ProvingKey)?;
    let circuit = ExecutionCircuit {
        shape: shape.clone(),
        witness: Some(witness),
        public_inputs: Some(public_inputs),
    };
    let instances = public_inputs.instances();
    let instance_columns = [instances.as_slice()];
    let all_instances = [&instance_columns[..]];
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(Vec::new());
    create_proof(
        &params,
        &pk,
        &[circuit],
        &all_instances,
        OsRng,
        &mut transcript,
    )
    .map_err(ProofError::Proving)?;
    let proof = transcript.finalize();
    verify_bytes(&params, pk.get_vk(), &instances, &proof)?;
    Ok(ProofArtifact { k, shape, proof })
}

/// Verifies a proof without a trace, ROM image, memory image, or native executor.
pub fn verify(
    artifact: &ProofArtifact,
    public_inputs: PublicInputs,
) -> Result<VerifiedProof, ProofError> {
    artifact.shape.validate()?;
    let expected_k = recommended_k(&artifact.shape)?;
    if artifact.k != expected_k {
        return Err(ProofError::NonCanonicalK {
            expected: expected_k,
            actual: artifact.k,
        });
    }
    let params: Params<EqAffine> = Params::new(artifact.k);
    let empty = ExecutionCircuit {
        shape: artifact.shape.clone(),
        witness: None,
        public_inputs: None,
    };
    let vk = keygen_vk(&params, &empty).map_err(ProofError::VerificationKey)?;
    let instances = public_inputs.instances();
    verify_bytes(&params, &vk, &instances, &artifact.proof)?;
    let step_count =
        u64::try_from(artifact.shape.len()).map_err(|_| ProofError::RowEstimateOverflow)?;
    Ok(VerifiedProof {
        k: artifact.k,
        step_count,
    })
}

/// Returns the deterministic parameter exponent selected for a public shape.
pub fn recommended_k(shape: &ExecutionShape) -> Result<u32, ProofError> {
    shape.validate()?;
    let events = shape.steps().try_fold(0_usize, |total, step| {
        let occupied = step
            .events()
            .into_iter()
            .filter(|event| *event != crate::BusEventKind::Unused)
            .count();
        total
            .checked_add(occupied)
            .ok_or(ProofError::RowEstimateOverflow)
    })?;
    let event_rows = events
        .checked_mul(ROWS_PER_EVENT)
        .ok_or(ProofError::RowEstimateOverflow)?;
    let estimated = BASE_ROWS
        .checked_add(event_rows)
        .ok_or(ProofError::RowEstimateOverflow)?;
    let rounded = estimated
        .checked_next_power_of_two()
        .ok_or(ProofError::RowEstimateOverflow)?;
    let required = usize::BITS - rounded.leading_zeros() - 1;
    let k = required.max(MIN_K);
    if k > MAX_K {
        Err(ProofError::CircuitTooLarge {
            required: k,
            maximum: MAX_K,
        })
    } else {
        Ok(k)
    }
}

fn verify_bytes(
    params: &Params<EqAffine>,
    vk: &halo2_proofs::plonk::VerifyingKey<EqAffine>,
    instances: &[Fp],
    proof: &[u8],
) -> Result<(), ProofError> {
    let columns = [instances];
    let all_instances = [&columns[..]];
    let strategy = SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof);
    verify_proof(params, vk, strategy, &all_instances, &mut transcript)
        .map_err(ProofError::Verification)
}
