#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Canonical public statements, receipts, and typed verification results.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zksm83_memory::CommitmentRoot;
use zksm83_proof::{
    ExecutionShape, MACHINE_PROFILE_ID, ProofArtifact, ProofError, PublicInputs, VM_VERSION_ID,
};
use zksm83_trace::Witness;

const RECEIPT_DOMAIN: &[u8] = b"zksm83-receipt/v2";

/// Human-readable VM protocol version in the receipt schema.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum VmVersion {
    /// Clean-core protocol with capacity-domain Poseidon commitments.
    #[serde(rename = "zksm83-core/2")]
    V2,
}

/// Human-readable machine-profile identifier in the receipt schema.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MachineProfile {
    /// Core-only SM83 profile with authenticated ROM, RAM, and byte I/O ports.
    #[serde(rename = "sm83-core-v1")]
    CoreV1,
}

/// Fixed proof system selected by the v1 receipt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProofScheme {
    /// Halo2 polynomial IOP with the IPA commitment over Pasta curves.
    #[serde(rename = "halo2-ipa-pasta-v1")]
    Halo2IpaPastaV1,
}

/// Canonical 256-bit deterministic identifier for a public statement.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReceiptId([u8; 32]);

impl ReceiptId {
    /// Returns the raw digest bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns lowercase canonical hexadecimal.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    /// Maps the complete digest injectively into four public 64-bit limbs.
    #[must_use]
    pub fn limbs(self) -> [u64; 4] {
        let mut limbs = [0_u64; 4];
        for (limb, chunk) in limbs.iter_mut().zip(self.0.chunks_exact(8)) {
            let bytes = <[u8; 8]>::try_from(chunk).map_or([0; 8], |value| value);
            *limb = u64::from_le_bytes(bytes);
        }
        limbs
    }
}

impl Serialize for ReceiptId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ReceiptId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(D::Error::custom(
                "receipt ID must be exactly 64 lowercase hexadecimal digits",
            ));
        }
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(encoded, &mut bytes).map_err(D::Error::custom)?;
        Ok(Self(bytes))
    }
}

/// Canonical verifier-visible execution claim.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicStatement {
    /// VM protocol version.
    pub vm_version: VmVersion,
    /// Machine profile.
    pub machine_profile: MachineProfile,
    /// Immutable ROM commitment.
    pub rom_root: CommitmentRoot,
    /// Mutable-memory commitment before execution.
    pub initial_memory_root: CommitmentRoot,
    /// Mutable-memory commitment after execution.
    pub final_memory_root: CommitmentRoot,
    /// Exact consumed private-input commitment.
    pub input_root: CommitmentRoot,
    /// Exact instruction count.
    pub step_count: u64,
    /// Exact M-cycle count.
    pub cycle_count: u64,
    /// Exact public-output commitment.
    pub public_output_root: CommitmentRoot,
    /// SHA-256 identifier of every preceding field.
    pub receipt_id: ReceiptId,
}

impl PublicStatement {
    /// Builds the canonical claim for a validated witness.
    #[must_use]
    pub fn from_witness(witness: &Witness) -> Self {
        let initial = witness.initial_state();
        let final_state = witness.final_state();
        let mut statement = Self {
            vm_version: VmVersion::V2,
            machine_profile: MachineProfile::CoreV1,
            rom_root: initial.rom_root(),
            initial_memory_root: initial.memory_root(),
            final_memory_root: final_state.memory_root(),
            input_root: final_state.input_log().root(),
            step_count: witness.step_count(),
            cycle_count: final_state.cpu().m_cycles(),
            public_output_root: final_state.output_log().root(),
            receipt_id: ReceiptId([0; 32]),
        };
        statement.receipt_id = statement.recompute_id();
        statement
    }

    /// Recomputes the deterministic identifier from canonical binary fields.
    #[must_use]
    pub fn recompute_id(self) -> ReceiptId {
        let mut hasher = Sha256::new();
        hasher.update(RECEIPT_DOMAIN);
        hasher.update([0]);
        hasher.update(VM_VERSION_ID.to_le_bytes());
        hasher.update(MACHINE_PROFILE_ID.to_le_bytes());
        for root in [
            self.rom_root,
            self.initial_memory_root,
            self.final_memory_root,
            self.input_root,
        ] {
            hasher.update(root.to_bytes());
        }
        hasher.update(self.step_count.to_le_bytes());
        hasher.update(self.cycle_count.to_le_bytes());
        hasher.update(self.public_output_root.to_bytes());
        ReceiptId(hasher.finalize().into())
    }

    /// Produces the exact scalar instance mapping consumed by the proof verifier.
    #[must_use]
    pub fn public_inputs(self) -> PublicInputs {
        PublicInputs {
            vm_version: VM_VERSION_ID,
            machine_profile: MACHINE_PROFILE_ID,
            rom_root: self.rom_root,
            initial_memory_root: self.initial_memory_root,
            final_memory_root: self.final_memory_root,
            input_root: self.input_root,
            step_count: self.step_count,
            cycle_count: self.cycle_count,
            output_root: self.public_output_root,
            receipt_id_limbs: self.receipt_id.limbs(),
        }
    }
}

/// Public circuit identity needed to derive parameters and the verification key.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitDescriptor {
    /// Fixed proof scheme.
    pub scheme: ProofScheme,
    /// Transparent IPA parameter exponent.
    pub k: u32,
}

/// Portable receipt containing no execution witness or verification key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    /// Canonical public claim.
    pub statement: PublicStatement,
    /// Versioned circuit-size descriptor.
    pub circuit: CircuitDescriptor,
    /// Public instruction/branch/event shape used to derive the verification key.
    pub shape: ExecutionShape,
    /// Halo2 proof bytes, serialized as lowercase hexadecimal.
    #[serde(with = "hex_bytes")]
    pub proof: Vec<u8>,
}

impl Receipt {
    /// Generates a real proof and packages its public claim.
    pub fn prove(witness: &Witness) -> Result<Self, ReceiptError> {
        let statement = PublicStatement::from_witness(witness);
        let artifact = zksm83_proof::prove(witness, statement.public_inputs())?;
        Ok(Self {
            statement,
            circuit: CircuitDescriptor {
                scheme: ProofScheme::Halo2IpaPastaV1,
                k: artifact.k,
            },
            shape: artifact.shape,
            proof: artifact.proof,
        })
    }

    /// Verifies the canonical identifier and IPA proof without a witness.
    pub fn verify(&self) -> Result<VerifiedReceipt, ReceiptError> {
        if self.statement.receipt_id != self.statement.recompute_id() {
            return Err(ReceiptError::ReceiptIdMismatch);
        }
        let artifact = ProofArtifact {
            k: self.circuit.k,
            shape: self.shape.clone(),
            proof: self.proof.clone(),
        };
        let verified = zksm83_proof::verify(&artifact, self.statement.public_inputs())?;
        if verified.step_count != self.statement.step_count {
            return Err(ReceiptError::StepCountMismatch {
                statement: self.statement.step_count,
                shape: verified.step_count,
            });
        }
        Ok(VerifiedReceipt {
            receipt_id: self.statement.receipt_id,
            k: verified.k,
            step_count: verified.step_count,
            cycle_count: self.statement.cycle_count,
            public_output_root: self.statement.public_output_root,
        })
    }

    /// Verifies this receipt against public inputs supplied independently by the caller.
    pub fn verify_against(
        &self,
        expected: PublicStatement,
    ) -> Result<VerifiedReceipt, ReceiptVerificationError> {
        if self.statement != expected {
            return Err(ReceiptError::PublicStatementMismatch);
        }
        self.verify()
    }

    /// Serializes a stable, human-inspectable JSON receipt.
    pub fn to_json_pretty(&self) -> Result<String, ReceiptError> {
        serde_json::to_string_pretty(self).map_err(ReceiptError::Encoding)
    }

    /// Parses the strict typed JSON receipt schema.
    pub fn from_json(encoded: &str) -> Result<Self, ReceiptError> {
        serde_json::from_str(encoded).map_err(ReceiptError::Encoding)
    }
}

/// Successful receipt-verification summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct VerifiedReceipt {
    /// Verified deterministic receipt ID.
    pub receipt_id: ReceiptId,
    /// Verified circuit exponent.
    pub k: u32,
    /// Verified exact instruction count.
    pub step_count: u64,
    /// Verified exact M-cycle count.
    pub cycle_count: u64,
    /// Verified public-output commitment.
    pub public_output_root: CommitmentRoot,
}

/// Typed receipt generation, encoding, or verification failure.
#[derive(Debug, Error)]
pub enum ReceiptError {
    /// Receipt public inputs differ from independently supplied verifier inputs.
    #[error("receipt public statement does not match the expected public statement")]
    PublicStatementMismatch,
    /// Receipt ID does not match the canonical public statement.
    #[error("receipt ID does not match the canonical public statement")]
    ReceiptIdMismatch,
    /// Shape and public statement disagree about exact instruction count.
    #[error("statement step count {statement} differs from shape step count {shape}")]
    StepCountMismatch {
        /// Statement count.
        statement: u64,
        /// Shape count.
        shape: u64,
    },
    /// Proof backend rejected construction or verification.
    #[error(transparent)]
    Proof(#[from] ProofError),
    /// JSON or hexadecimal receipt encoding is invalid.
    #[error("receipt encoding failed: {0}")]
    Encoding(serde_json::Error),
}

/// Verification-specific name for the typed receipt error surface.
pub type ReceiptVerificationError = ReceiptError;

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as DeError};

    pub(super) fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() % 2 != 0
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(D::Error::custom(
                "proof must be lowercase even-length hexadecimal",
            ));
        }
        hex::decode(encoded).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use zksm83_memory::{MemoryImage, RomImage};
    use zksm83_trace::TraceBuilder;

    use super::{PublicStatement, ReceiptId};

    #[test]
    fn statement_id_is_deterministic_and_field_sensitive() -> Result<(), Box<dyn std::error::Error>>
    {
        let witness = TraceBuilder::new(
            RomImage::new(vec![0x76])?,
            MemoryImage::zeroed()?,
            Vec::new(),
        )
        .run(1)?;
        let statement = PublicStatement::from_witness(&witness);
        assert_eq!(statement.receipt_id, statement.recompute_id());
        let mut changed = statement;
        changed.cycle_count = changed.cycle_count.saturating_add(1);
        assert_ne!(statement.receipt_id, changed.recompute_id());
        assert_ne!(statement.receipt_id, ReceiptId([0; 32]));
        Ok(())
    }

    #[test]
    fn statement_json_round_trip_is_canonical() -> Result<(), Box<dyn std::error::Error>> {
        let witness = TraceBuilder::new(
            RomImage::new(vec![0x76])?,
            MemoryImage::zeroed()?,
            Vec::new(),
        )
        .run(1)?;
        let statement = PublicStatement::from_witness(&witness);
        let encoded = serde_json::to_string(&statement)?;
        let decoded: PublicStatement = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, statement);
        Ok(())
    }
}
