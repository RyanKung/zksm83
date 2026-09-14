//! Trace-specific wrapper around dimension-parameterized Akita commitments.

#[cfg(test)]
use akita_config::proof_optimized::fp128;
#[cfg(test)]
use akita_pcs::AkitaCommitmentScheme;
use jolt_field::Ring;
use rayon::prelude::*;

#[cfg(test)]
use crate::pcs::scheme as pcs_scheme;
use crate::{
    BLOCK_CPU_COLUMN_COUNT, NATIVE_TRACE_COLUMN_COUNT, NativeProtocolVersion,
    pcs::{
        ColumnCommitments, CommittedColumns, FieldColumnView, OpeningProof as PcsOpeningProof,
        PcsError, PcsLayout, commit_columns as commit_pcs_columns,
        prove_opening as prove_pcs_opening, prove_selected_opening as prove_pcs_selected_opening,
        selected_logical_columns, verify_opening as verify_pcs_opening,
        verify_selected_opening as verify_pcs_selected_opening,
    },
};

use super::{COMMITMENT_GROUP_COLUMNS, NativeField, UNIFORM_NUM_VARIABLES, UniformError};

const PCS_TRANSCRIPT_DOMAIN_V2: &[u8] = b"zksm83-native-shared-opening/v2";
const COMMITMENT_ENCODING_DOMAIN_V2: &[u8] = b"zksm83/native-witness-commitments/v2";
pub(super) const AUXILIARY_SCHEDULE_ARTIFACT: &[u8] =
    include_bytes!("../../protocol/akita/fp128_dense_bounded_nv14_p128.aks");
pub(super) const SCHEDULE_ARTIFACT: &[u8] =
    include_bytes!("../../protocol/akita/fp128_dense_bounded_nv14_p128_pair.aks");
const V2_SINGLE_LAYOUT: PcsLayout = PcsLayout::new(
    UNIFORM_NUM_VARIABLES,
    COMMITMENT_GROUP_COLUMNS,
    AUXILIARY_SCHEDULE_ARTIFACT,
    COMMITMENT_ENCODING_DOMAIN_V2,
    PCS_TRANSCRIPT_DOMAIN_V2,
);
const V2_TRACE_LAYOUT: PcsLayout = PcsLayout::paired(
    UNIFORM_NUM_VARIABLES,
    COMMITMENT_GROUP_COLUMNS,
    SCHEDULE_ARTIFACT,
    COMMITMENT_ENCODING_DOMAIN_V2,
    PCS_TRANSCRIPT_DOMAIN_V2,
);

/// Prover-owned committed witness plane.
///
/// The dense polynomials and Akita hints never enter a receipt. Multiple
/// relation provers borrow this value so every claim opens the same commitments.
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

    pub(crate) fn field_columns(&self) -> Result<FieldColumnView<'_>, UniformError> {
        self.inner.field_columns().map_err(map_pcs_error)
    }
}

impl WitnessCommitments {
    /// Returns the number of logical columns before fixed-width zero padding.
    #[must_use]
    pub const fn column_count(&self) -> usize {
        self.inner.column_count()
    }

    /// Returns the number of fixed-width Akita commitment groups.
    #[must_use]
    pub fn group_count(&self) -> usize {
        self.inner.group_count()
    }

    /// Returns the canonical protocol encoding of the commitment identity.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, UniformError> {
        self.canonical_bytes_for(NativeProtocolVersion::current())
    }

    /// Returns SHA-256 of the canonical commitment identity.
    pub fn digest(&self) -> Result<[u8; 32], UniformError> {
        self.digest_for(NativeProtocolVersion::current())
    }

    pub(crate) fn canonical_bytes_for(
        &self,
        protocol: NativeProtocolVersion,
    ) -> Result<Vec<u8>, UniformError> {
        self.inner
            .canonical_bytes(layout_for(protocol, self.column_count()))
            .map_err(map_pcs_error)
    }

    pub(crate) fn digest_for(
        &self,
        protocol: NativeProtocolVersion,
    ) -> Result<[u8; 32], UniformError> {
        self.inner
            .digest(layout_for(protocol, self.column_count()))
            .map_err(map_pcs_error)
    }

    pub(crate) fn validate_for(&self, protocol: NativeProtocolVersion) -> Result<(), UniformError> {
        self.inner
            .validate(layout_for(protocol, self.column_count()))
            .map_err(map_pcs_error)
    }
}

pub(super) fn commit_columns(columns: &[Vec<u64>]) -> Result<CommittedWitness, UniformError> {
    commit_columns_for(NativeProtocolVersion::current(), columns)
}

pub(super) fn commit_columns_for(
    protocol: NativeProtocolVersion,
    columns: &[Vec<u64>],
) -> Result<CommittedWitness, UniformError> {
    commit_pcs_columns(layout_for(protocol, columns.len()), columns)
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
        witness.inner.layout(),
        &witness.inner,
        point,
        logical_values,
        instance_descriptor,
    )
    .map_err(map_pcs_error)
}

pub(super) fn verify_opening_for_protocol(
    protocol: NativeProtocolVersion,
    commitments: &WitnessCommitments,
    point: &[NativeField],
    logical_values: &[NativeField],
    instance_descriptor: &[u8],
    opening: &OpeningProof,
) -> Result<(), UniformError> {
    verify_pcs_opening(
        layout_for(protocol, commitments.column_count()),
        &commitments.inner,
        point,
        logical_values,
        instance_descriptor,
        opening,
    )
    .map_err(map_pcs_error)
}

pub(super) fn prove_selected_opening(
    witness: &CommittedWitness,
    point: &[NativeField],
    selected_columns: &[usize],
    instance_descriptor: &[u8],
) -> Result<(Vec<NativeField>, OpeningProof), UniformError> {
    let layout = witness.inner.layout();
    let columns = witness.field_columns()?;
    let selected = selected_logical_columns(layout, &witness.commitments.inner, selected_columns)
        .map_err(map_pcs_error)?;
    let evaluated = selected
        .par_iter()
        .copied()
        .map(|index| {
            let column = columns
                .as_slice()
                .get(index)
                .copied()
                .ok_or(UniformError::Shape)?;
            crate::field_fold::evaluate_mle(column, point)
                .map(|value| (index, value))
                .map_err(|_| UniformError::Shape)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut values = vec![NativeField::from_u64(0); witness.commitments.column_count()];
    for (index, value) in evaluated {
        *values.get_mut(index).ok_or(UniformError::Shape)? = value;
    }
    let opening = prove_pcs_selected_opening(
        layout,
        &witness.inner,
        point,
        &values,
        selected_columns,
        instance_descriptor,
    )
    .map_err(map_pcs_error)?;
    Ok((values, opening))
}

pub(super) fn verify_selected_opening_for_protocol(
    protocol: NativeProtocolVersion,
    commitments: &WitnessCommitments,
    point: &[NativeField],
    logical_values: &[NativeField],
    selected_columns: &[usize],
    instance_descriptor: &[u8],
    opening: &OpeningProof,
) -> Result<(), UniformError> {
    verify_pcs_selected_opening(
        layout_for(protocol, commitments.column_count()),
        &commitments.inner,
        point,
        logical_values,
        selected_columns,
        instance_descriptor,
        opening,
    )
    .map_err(map_pcs_error)
}

#[cfg(test)]
pub(super) fn scheme() -> Result<AkitaCommitmentScheme<fp128::DenseBounded>, UniformError> {
    pcs_scheme(V2_TRACE_LAYOUT).map_err(map_pcs_error)
}

const fn layout_for(protocol: NativeProtocolVersion, column_count: usize) -> PcsLayout {
    match protocol {
        NativeProtocolVersion::V2
            if column_count == BLOCK_CPU_COLUMN_COUNT
                || column_count == NATIVE_TRACE_COLUMN_COUNT =>
        {
            V2_TRACE_LAYOUT
        }
        NativeProtocolVersion::V2 => V2_SINGLE_LAYOUT,
    }
}

fn map_pcs_error(error: PcsError) -> UniformError {
    match error {
        PcsError::Shape => UniformError::Shape,
        PcsError::Akita(error) => UniformError::Akita(error),
        PcsError::Serialization(error) => UniformError::Serialization(error),
        PcsError::Context(error) => UniformError::PcsContext(error),
    }
}
