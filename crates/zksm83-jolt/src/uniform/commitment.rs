//! Trace-specific wrapper around dimension-parameterized Akita commitments.

#[cfg(test)]
use akita_config::proof_optimized::fp128;
#[cfg(test)]
use akita_pcs::AkitaCommitmentScheme;

#[cfg(test)]
use crate::pcs::scheme as pcs_scheme;
use crate::pcs::{
    ColumnCommitments, CommittedColumns, OpeningProof as PcsOpeningProof, PcsError, PcsLayout,
    commit_columns as commit_pcs_columns, prove_opening as prove_pcs_opening,
    verify_opening as verify_pcs_opening,
};

use super::{COMMITMENT_GROUP_COLUMNS, NativeField, UNIFORM_NUM_VARIABLES, UniformError};

const PCS_TRANSCRIPT_DOMAIN: &[u8] = b"zksm83-native-shared-opening/v1";
const COMMITMENT_ENCODING_DOMAIN: &[u8] = b"zksm83/native-witness-commitments/v1";
pub(super) const SCHEDULE_ARTIFACT: &[u8] =
    include_bytes!("../../protocol/akita/fp128_dense_bounded_nv14_p128.aks");
const LAYOUT: PcsLayout = PcsLayout::new(
    UNIFORM_NUM_VARIABLES,
    COMMITMENT_GROUP_COLUMNS,
    SCHEDULE_ARTIFACT,
    COMMITMENT_ENCODING_DOMAIN,
    PCS_TRANSCRIPT_DOMAIN,
);

/// Prover-owned committed witness plane.
///
/// The field columns and Akita hints never enter a receipt. Multiple relation
/// provers borrow this value so every claim opens the same commitments.
pub struct CommittedWitness {
    inner: CommittedColumns,
    commitments: WitnessCommitments,
}

/// Verifier-visible identity of one fixed-layout witness plane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessCommitments {
    pub(crate) inner: ColumnCommitments,
}

pub(super) type OpeningProof = PcsOpeningProof;

impl CommittedWitness {
    /// Returns the verifier-visible commitment identity without witness data.
    #[must_use]
    pub const fn commitments(&self) -> &WitnessCommitments {
        &self.commitments
    }

    /// Consumes the prover witness and retains only public commitments.
    #[must_use]
    pub fn into_commitments(self) -> WitnessCommitments {
        self.commitments
    }

    pub(crate) fn field_columns(&self) -> &[Vec<NativeField>] {
        self.inner.field_columns()
    }
}

impl WitnessCommitments {
    /// Returns the number of logical columns before fixed-width zero padding.
    #[must_use]
    pub const fn column_count(&self) -> usize {
        self.inner.column_count()
    }

    /// Returns the number of independently opened Akita commitment groups.
    #[must_use]
    pub fn group_count(&self) -> usize {
        self.inner.group_count()
    }

    /// Returns the canonical protocol encoding of the commitment identity.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, UniformError> {
        self.inner.canonical_bytes(LAYOUT).map_err(map_pcs_error)
    }

    /// Returns SHA-256 of the canonical commitment identity.
    pub fn digest(&self) -> Result<[u8; 32], UniformError> {
        self.inner.digest(LAYOUT).map_err(map_pcs_error)
    }

    pub(super) fn validate(&self) -> Result<(), UniformError> {
        self.inner.validate(LAYOUT).map_err(map_pcs_error)
    }
}

pub(super) fn commit_columns(columns: &[Vec<u64>]) -> Result<CommittedWitness, UniformError> {
    commit_pcs_columns(LAYOUT, columns)
        .map(|inner| CommittedWitness {
            commitments: WitnessCommitments {
                inner: inner.commitments().clone(),
            },
            inner,
        })
        .map_err(map_pcs_error)
}

pub(super) fn prove_opening(
    witness: &CommittedWitness,
    point: &[NativeField],
    logical_values: &[NativeField],
    instance_descriptor: &[u8],
) -> Result<OpeningProof, UniformError> {
    prove_pcs_opening(
        LAYOUT,
        &witness.inner,
        point,
        logical_values,
        instance_descriptor,
    )
    .map_err(map_pcs_error)
}

pub(super) fn verify_opening(
    commitments: &WitnessCommitments,
    point: &[NativeField],
    logical_values: &[NativeField],
    instance_descriptor: &[u8],
    opening: &OpeningProof,
) -> Result<(), UniformError> {
    verify_pcs_opening(
        LAYOUT,
        &commitments.inner,
        point,
        logical_values,
        instance_descriptor,
        opening,
    )
    .map_err(map_pcs_error)
}

#[cfg(test)]
pub(super) fn scheme() -> Result<AkitaCommitmentScheme<fp128::DenseBounded>, UniformError> {
    pcs_scheme(LAYOUT).map_err(map_pcs_error)
}

fn map_pcs_error(error: PcsError) -> UniformError {
    match error {
        PcsError::Shape => UniformError::Shape,
        PcsError::Akita(error) => UniformError::Akita(error),
        PcsError::Serialization(error) => UniformError::Serialization(error),
    }
}
