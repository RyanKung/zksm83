//! Dimension-parameterized Akita commitment and opening primitives.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock, Weak},
};

use akita_config::proof_optimized::fp128;
use akita_pcs::{
    AkitaCommitmentScheme, AkitaSerialize, AkitaTranscript, BasisMode, ComputeBackendSetup,
    CpuBackend, CpuPreparedSetup, OpeningClaims, PolynomialGroupClaims, UniformProverStack,
};
use akita_prover::{
    AkitaProverSetup, DensePoly, NttExecutionRequirements, SelectedProverOpeningData,
    prewarm_ntt_requirements,
};
use akita_serialization::SerializationError;
#[cfg(test)]
use akita_types::AkitaScheduleLookupKey;
use akita_types::{
    AkitaBatchedProof, AkitaCommitmentHint, AkitaVerifierSetup, CommittedGroup, FoldSchedule,
    GroupBatchStatement, GroupCommitPhaseParams, OpeningClaimsLayout, OpeningScheduleSelection,
    PolynomialGroupLayout, PrecommittedGroupProfiles,
};
use jolt_field::{CanonicalBytes, Ring};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    NativeField, NativeProverBackend,
    metrics::{self, Phase},
};

type Config = fp128::DenseBounded;

pub(crate) struct SelectedOpeningClaim<'a> {
    point: &'a [NativeField],
    logical_values: &'a [NativeField],
    selected_columns: &'a [usize],
    instance_descriptor: &'a [u8],
}

impl<'a> SelectedOpeningClaim<'a> {
    pub(crate) const fn new(
        point: &'a [NativeField],
        logical_values: &'a [NativeField],
        selected_columns: &'a [usize],
        instance_descriptor: &'a [u8],
    ) -> Self {
        Self {
            point,
            logical_values,
            selected_columns,
            instance_descriptor,
        }
    }
}

/// Frozen PCS geometry and transcript domains for one column family.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct PcsLayout {
    num_variables: usize,
    group_columns: usize,
    schedule_artifact: &'static [u8],
    commitment_domain: &'static [u8],
    opening_domain: &'static [u8],
    opening_mode: PcsOpeningMode,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum PcsOpeningMode {
    Independent,
    Paired,
}

/// Prover-owned columns, commitment hints, and verifier-visible commitments.
pub(crate) struct CommittedColumns {
    commitments: ColumnCommitments,
    batches: Vec<ProverBatch>,
    context: PcsContextLease,
}

/// Borrowed logical field columns in commitment order.
///
/// The slices point into the committed dense polynomials. Physical zero-padding
/// polynomials and each polynomial's backend padding are excluded.
pub(crate) struct FieldColumnView<'a> {
    columns: Vec<&'a [NativeField]>,
}

struct PcsProverContext {
    layout: PcsLayout,
    scheme: AkitaCommitmentScheme<Config>,
    setup: AkitaProverSetup<NativeField>,
    backend: CpuBackend,
    prepared: CpuPreparedSetup<NativeField>,
    schedule: FoldSchedule,
    precommitted_profiles: Vec<GroupCommitPhaseParams>,
}

struct PcsContextLease {
    slot: Arc<PcsContextSlot>,
    layout: PcsLayout,
}

struct ProverBatch {
    hint: AkitaCommitmentHint<NativeField>,
    polynomials: Vec<DensePoly<NativeField>>,
}

/// Verifier-visible identity of fixed-width committed columns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ColumnCommitments {
    pub(crate) num_variables: usize,
    pub(crate) logical_column_count: usize,
    pub(crate) group_columns: usize,
    pub(crate) groups: Vec<CommittedGroup<NativeField>>,
}

/// Akita proofs opening every commitment group at one point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OpeningProof {
    pub(crate) groups: Vec<GroupOpeningProof>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GroupOpeningProof {
    pub(crate) selection: OpeningScheduleSelection,
    pub(crate) opened_values: Vec<NativeField>,
    pub(crate) proof: AkitaBatchedProof<NativeField, NativeField>,
}

/// Invalid fixed-layout Akita commitment or opening operation.
#[derive(Debug, Error)]
pub(crate) enum PcsError {
    /// Column, commitment, or opening dimensions are inconsistent.
    #[error("Akita column commitment shape is invalid")]
    Shape,
    /// Akita rejected setup, commitment, opening construction, or verification.
    #[error("Akita rejected the column commitment operation: {0}")]
    Akita(#[from] akita_pcs::AkitaError),
    /// Canonical Akita serialization failed.
    #[error("Akita commitment serialization failed: {0}")]
    Serialization(#[from] SerializationError),
    /// A process-local layout context could not be initialized or recovered.
    #[error("Akita PCS context is unavailable: {0}")]
    Context(String),
}

type PcsContextSlot = OnceLock<Result<Arc<PcsProverContext>, String>>;
type PcsContextRegistry = Mutex<HashMap<PcsLayout, Weak<PcsContextSlot>>>;

static PCS_CONTEXTS: OnceLock<PcsContextRegistry> = OnceLock::new();

impl PcsLayout {
    pub(crate) const fn new(
        num_variables: usize,
        group_columns: usize,
        schedule_artifact: &'static [u8],
        commitment_domain: &'static [u8],
        opening_domain: &'static [u8],
    ) -> Self {
        Self {
            num_variables,
            group_columns,
            schedule_artifact,
            commitment_domain,
            opening_domain,
            opening_mode: PcsOpeningMode::Independent,
        }
    }

    pub(crate) const fn paired(
        num_variables: usize,
        group_columns: usize,
        schedule_artifact: &'static [u8],
        commitment_domain: &'static [u8],
        opening_domain: &'static [u8],
    ) -> Self {
        Self {
            num_variables,
            group_columns,
            schedule_artifact,
            commitment_domain,
            opening_domain,
            opening_mode: PcsOpeningMode::Paired,
        }
    }

    fn row_count(self) -> Result<usize, PcsError> {
        let shift = u32::try_from(self.num_variables).map_err(|_| PcsError::Shape)?;
        1_usize.checked_shl(shift).ok_or(PcsError::Shape)
    }

    const fn groups_per_opening(self) -> usize {
        match self.opening_mode {
            PcsOpeningMode::Independent => 1,
            PcsOpeningMode::Paired => 2,
        }
    }

    fn setup_capacity(self) -> Result<usize, PcsError> {
        self.group_columns
            .checked_mul(self.groups_per_opening())
            .ok_or(PcsError::Shape)
    }

    fn opening_count(self, group_count: usize) -> Result<usize, PcsError> {
        let groups_per_opening = self.groups_per_opening();
        if group_count == 0 || !group_count.is_multiple_of(groups_per_opening) {
            return Err(PcsError::Shape);
        }
        Ok(group_count / groups_per_opening)
    }
}

impl CommittedColumns {
    pub(crate) const fn commitments(&self) -> &ColumnCommitments {
        &self.commitments
    }

    pub(crate) fn field_columns(&self) -> Result<FieldColumnView<'_>, PcsError> {
        self.commitments.validate(self.context.layout())?;
        field_column_view(
            self.context.layout(),
            self.commitments.logical_column_count,
            self.batches
                .iter()
                .flat_map(|batch| batch.polynomials.iter()),
        )
    }

    pub(crate) fn field_column(&self, index: usize) -> Result<&[NativeField], PcsError> {
        let layout = self.context.layout();
        self.commitments.validate(layout)?;
        if index >= self.commitments.logical_column_count {
            return Err(PcsError::Shape);
        }
        let row_count = layout.row_count()?;
        let batch_index = index / layout.group_columns;
        let polynomial_index = index % layout.group_columns;
        self.batches
            .get(batch_index)
            .and_then(|batch| batch.polynomials.get(polynomial_index))
            .and_then(|polynomial| polynomial.field_coeffs().get(..row_count))
            .ok_or(PcsError::Shape)
    }

    pub(crate) const fn layout(&self) -> PcsLayout {
        self.context.layout()
    }
}

impl<'a> FieldColumnView<'a> {
    pub(crate) fn as_slice(&self) -> &[&'a [NativeField]] {
        &self.columns
    }
}

impl PcsProverContext {
    fn new(layout: PcsLayout) -> Result<Self, PcsError> {
        let _phase = metrics::start(Phase::Setup);
        let scheme = scheme(layout)?;
        let (schedule, precommitted_profiles) = validate_schedule(layout, &scheme)?;
        let setup = scheme.setup_prover(layout.num_variables, layout.setup_capacity()?)?;
        let backend = CpuBackend::DEFAULT;
        let prepared = backend.prepare_setup(&setup)?;
        let context = Self {
            layout,
            scheme,
            setup,
            backend,
            prepared,
            schedule,
            precommitted_profiles,
        };
        let stack = context.stack()?;
        prewarm_root_commit(layout, &context.schedule, &stack)?;
        Ok(context)
    }

    fn stack(&self) -> Result<UniformProverStack<'_, NativeField, CpuBackend>, PcsError> {
        if self.layout.group_columns == 0 {
            return Err(PcsError::Shape);
        }
        UniformProverStack::uniform(&self.backend, &self.prepared, self.setup.expanded.as_ref())
            .map_err(Into::into)
    }
}

impl PcsContextLease {
    const fn layout(&self) -> PcsLayout {
        self.layout
    }

    fn acquire(layout: PcsLayout) -> Result<Self, PcsError> {
        let slot = context_slot(layout)?;
        let initialized = slot.get_or_init(|| {
            PcsProverContext::new(layout)
                .map(Arc::new)
                .map_err(|error| error.to_string())
        });
        if let Err(error) = initialized {
            return Err(PcsError::Context(error.clone()));
        }
        Ok(Self { slot, layout })
    }

    fn context(&self, layout: PcsLayout) -> Result<&PcsProverContext, PcsError> {
        let initialized = self
            .slot
            .get()
            .ok_or_else(|| PcsError::Context("layout context was not initialized".to_owned()))?;
        let context = initialized
            .as_ref()
            .map_err(|error| PcsError::Context(error.clone()))?;
        if context.layout != layout {
            return Err(PcsError::Shape);
        }
        Ok(context)
    }
}

fn context_slot(layout: PcsLayout) -> Result<Arc<PcsContextSlot>, PcsError> {
    let registry = PCS_CONTEXTS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = registry
        .lock()
        .map_err(|_| PcsError::Context("layout registry lock was poisoned".to_owned()))?;
    if let Some(slot) = registry.get(&layout).and_then(Weak::upgrade) {
        return Ok(slot);
    }
    let slot = Arc::new(OnceLock::new());
    registry.insert(layout, Arc::downgrade(&slot));
    Ok(slot)
}

impl ColumnCommitments {
    pub(crate) const fn column_count(&self) -> usize {
        self.logical_column_count
    }

    pub(crate) fn group_count(&self) -> usize {
        self.groups.len()
    }

    pub(crate) fn canonical_bytes(&self, layout: PcsLayout) -> Result<Vec<u8>, PcsError> {
        self.validate(layout)?;
        let mut bytes = Vec::new();
        push_bytes(&mut bytes, layout.commitment_domain)?;
        push_usize(&mut bytes, self.num_variables)?;
        push_usize(&mut bytes, self.logical_column_count)?;
        push_usize(&mut bytes, self.group_columns)?;
        push_usize(&mut bytes, self.groups.len())?;
        for group in &self.groups {
            let mut encoded = Vec::new();
            group.serialize_compressed(&mut encoded)?;
            push_bytes(&mut bytes, &encoded)?;
        }
        Ok(bytes)
    }

    pub(crate) fn digest(&self, layout: PcsLayout) -> Result<[u8; 32], PcsError> {
        Ok(Sha256::digest(self.canonical_bytes(layout)?).into())
    }

    pub(crate) fn validate(&self, layout: PcsLayout) -> Result<(), PcsError> {
        let expected_groups = self.logical_column_count.div_ceil(layout.group_columns);
        if layout.group_columns == 0
            || self.num_variables != layout.num_variables
            || self.group_columns != layout.group_columns
            || self.logical_column_count == 0
            || self.groups.len() != expected_groups
            || self.groups.iter().any(|group| {
                group.profile().group.num_vars() != layout.num_variables
                    || group.profile().group.num_polynomials() != layout.group_columns
            })
        {
            return Err(PcsError::Shape);
        }
        Ok(())
    }
}

pub(crate) fn commit_columns_with_backend<C>(
    layout: PcsLayout,
    columns: &[C],
    backend: &NativeProverBackend,
) -> Result<CommittedColumns, PcsError>
where
    C: AsRef<[u64]> + Sync,
{
    let row_count = validate_column_shape(layout, columns)?;
    let context = PcsContextLease::acquire(layout)?;
    let prover = context.context(layout)?;
    let stack = prover.stack()?;
    let _phase = metrics::start(Phase::Commit);
    let logical_column_count = columns.len();
    let group_count = logical_column_count.div_ceil(layout.group_columns);
    let _opening_count = layout.opening_count(group_count)?;
    let mut groups = Vec::with_capacity(group_count);
    let mut batches = Vec::with_capacity(group_count);
    let polynomial_groups = columns
        .chunks(layout.group_columns)
        .map(|columns| padded_polynomials(layout, columns, row_count))
        .collect::<Result<Vec<_>, _>>()?;
    commit_polynomial_groups(
        layout,
        prover,
        &stack,
        polynomial_groups,
        &mut groups,
        &mut batches,
        backend,
    )?;
    let commitments = ColumnCommitments {
        num_variables: layout.num_variables,
        logical_column_count,
        group_columns: layout.group_columns,
        groups,
    };
    commitments.validate(layout)?;
    Ok(CommittedColumns {
        commitments,
        batches,
        context,
    })
}

fn commit_polynomial_groups(
    layout: PcsLayout,
    prover: &PcsProverContext,
    stack: &UniformProverStack<'_, NativeField, CpuBackend>,
    polynomial_groups: Vec<Vec<DensePoly<NativeField>>>,
    groups: &mut Vec<CommittedGroup<NativeField>>,
    batches: &mut Vec<ProverBatch>,
    backend: &NativeProverBackend,
) -> Result<(), PcsError> {
    backend.run_akita_commitment(|| {
        match layout.opening_mode {
            PcsOpeningMode::Independent => {
                for polynomials in polynomial_groups {
                    let output = prover.scheme.commit::<DensePoly<NativeField>, CpuBackend>(
                        &prover.setup,
                        &polynomials,
                        stack,
                        akita_prover::GroupContext::scheduler_without_precommitted_groups(),
                    )?;
                    groups.push(output.committed_group);
                    batches.push(ProverBatch {
                        hint: output.hint,
                        polynomials,
                    });
                }
            }
            PcsOpeningMode::Paired => {
                let profile = prover
                    .precommitted_profiles
                    .first()
                    .ok_or(PcsError::Shape)?;
                let mut pending = polynomial_groups.into_iter();
                while let Some(precommitted) = pending.next() {
                    let final_group = pending.next().ok_or(PcsError::Shape)?;
                    let pre = prover.scheme.commit::<DensePoly<NativeField>, CpuBackend>(
                        &prover.setup,
                        &precommitted,
                        stack,
                        akita_prover::GroupContext::explicit(profile),
                    )?;
                    let precommitteds = PrecommittedGroupProfiles::from_ordered_groups(
                        std::iter::once(&pre.committed_group),
                    )?;
                    let final_output = prover.scheme.commit::<DensePoly<NativeField>, CpuBackend>(
                        &prover.setup,
                        &final_group,
                        stack,
                        akita_prover::GroupContext::scheduler_with_precommitted_groups(
                            &precommitteds,
                        ),
                    )?;
                    groups.push(pre.committed_group);
                    groups.push(final_output.committed_group);
                    batches.push(ProverBatch {
                        hint: pre.hint,
                        polynomials: precommitted,
                    });
                    batches.push(ProverBatch {
                        hint: final_output.hint,
                        polynomials: final_group,
                    });
                }
            }
        }
        Ok(())
    })
}

fn prewarm_root_commit(
    layout: PcsLayout,
    schedule: &FoldSchedule,
    stack: &UniformProverStack<'_, NativeField, CpuBackend>,
) -> Result<(), PcsError> {
    let requirements = match layout.opening_mode {
        PcsOpeningMode::Independent => root_commit_requirements(schedule)?,
        PcsOpeningMode::Paired => {
            NttExecutionRequirements::from_commit_and_prove_schedule(schedule)?
        }
    };
    prewarm_ntt_requirements::<NativeField, _>(stack, &requirements)?;
    Ok(())
}

fn root_commit_requirements(schedule: &FoldSchedule) -> Result<NttExecutionRequirements, PcsError> {
    let complete = NttExecutionRequirements::from_commit_and_prove_schedule(schedule)?;
    let prove = NttExecutionRequirements::from_prove_schedule(schedule)?;
    let mut root_entries = complete.entries().to_vec();
    for prove_entry in prove.entries() {
        let index = root_entries
            .iter()
            .position(|entry| entry == prove_entry)
            .ok_or(PcsError::Shape)?;
        root_entries.remove(index);
    }
    if root_entries.is_empty() {
        return Err(PcsError::Shape);
    }
    let mut requirements = NttExecutionRequirements::default();
    for entry in root_entries {
        requirements.add_matrix(
            entry.fold_level,
            entry.cluster,
            entry.key,
            entry.routing_extent,
        )?;
    }
    Ok(requirements)
}

pub(crate) fn prove_opening_with_backend(
    layout: PcsLayout,
    columns: &CommittedColumns,
    point: &[NativeField],
    logical_values: &[NativeField],
    instance_descriptor: &[u8],
    backend: &NativeProverBackend,
) -> Result<OpeningProof, PcsError> {
    validate_opening_shape(
        layout,
        &columns.commitments,
        point,
        logical_values,
        columns.batches.len(),
    )?;
    let _phase = metrics::start(Phase::Opening);
    let prover = columns.context.context(layout)?;
    let stack = prover.stack()?;
    let groups = backend.run_akita_opening(|| match layout.opening_mode {
        PcsOpeningMode::Independent => prove_independent_openings(
            layout,
            prover,
            &stack,
            columns,
            point,
            logical_values,
            instance_descriptor,
        ),
        PcsOpeningMode::Paired => prove_paired_openings(
            layout,
            prover,
            &stack,
            columns,
            point,
            logical_values,
            instance_descriptor,
        ),
    })?;
    Ok(OpeningProof { groups })
}

pub(crate) fn prove_selected_opening_with_backend(
    layout: PcsLayout,
    columns: &CommittedColumns,
    point: &[NativeField],
    logical_values: &[NativeField],
    selected_columns: &[usize],
    instance_descriptor: &[u8],
    backend: &NativeProverBackend,
) -> Result<OpeningProof, PcsError> {
    let opening_indices = selected_opening_indices(layout, &columns.commitments, selected_columns)?;
    validate_selected_opening_shape(
        layout,
        &columns.commitments,
        point,
        logical_values,
        &opening_indices,
        opening_indices.len(),
    )?;
    let _phase = metrics::start(Phase::Opening);
    let prover = columns.context.context(layout)?;
    let stack = prover.stack()?;
    let groups = backend.run_akita_opening(|| {
        let mut groups = Vec::with_capacity(opening_indices.len());
        for opening_index in opening_indices {
            let group_start = opening_index
                .checked_mul(layout.groups_per_opening())
                .ok_or(PcsError::Shape)?;
            let group_end = group_start
                .checked_add(layout.groups_per_opening())
                .ok_or(PcsError::Shape)?;
            let commitments = columns
                .commitments
                .groups
                .get(group_start..group_end)
                .ok_or(PcsError::Shape)?;
            let batches = columns
                .batches
                .get(group_start..group_end)
                .ok_or(PcsError::Shape)?;
            let values = (group_start..group_end)
                .map(|group_index| padded_group_values(layout, logical_values, group_index))
                .collect::<Result<Vec<_>, _>>()?;
            groups.push(prove_group_batch(
                layout,
                prover,
                &stack,
                commitments,
                batches,
                point,
                values,
                instance_descriptor,
                opening_index,
            )?);
        }
        Ok::<_, PcsError>(groups)
    })?;
    Ok(OpeningProof { groups })
}

fn prove_independent_openings(
    layout: PcsLayout,
    prover: &PcsProverContext,
    stack: &UniformProverStack<'_, NativeField, CpuBackend>,
    columns: &CommittedColumns,
    point: &[NativeField],
    logical_values: &[NativeField],
    descriptor: &[u8],
) -> Result<Vec<GroupOpeningProof>, PcsError> {
    let mut proofs = Vec::with_capacity(columns.batches.len());
    for (index, (commitment, batch)) in columns
        .commitments
        .groups
        .iter()
        .zip(&columns.batches)
        .enumerate()
    {
        let values = padded_group_values(layout, logical_values, index)?;
        proofs.push(prove_group_batch(
            layout,
            prover,
            stack,
            std::slice::from_ref(commitment),
            std::slice::from_ref(batch),
            point,
            vec![values],
            descriptor,
            index,
        )?);
    }
    Ok(proofs)
}

fn prove_paired_openings(
    layout: PcsLayout,
    prover: &PcsProverContext,
    stack: &UniformProverStack<'_, NativeField, CpuBackend>,
    columns: &CommittedColumns,
    point: &[NativeField],
    logical_values: &[NativeField],
    descriptor: &[u8],
) -> Result<Vec<GroupOpeningProof>, PcsError> {
    let mut proofs = Vec::with_capacity(columns.batches.len() / 2);
    for (pair_index, (commitments, batches)) in columns
        .commitments
        .groups
        .chunks(2)
        .zip(columns.batches.chunks(2))
        .enumerate()
    {
        let first_index = pair_index.checked_mul(2).ok_or(PcsError::Shape)?;
        let second_index = first_index.checked_add(1).ok_or(PcsError::Shape)?;
        let values = vec![
            padded_group_values(layout, logical_values, first_index)?,
            padded_group_values(layout, logical_values, second_index)?,
        ];
        proofs.push(prove_group_batch(
            layout,
            prover,
            stack,
            commitments,
            batches,
            point,
            values,
            descriptor,
            pair_index,
        )?);
    }
    Ok(proofs)
}

#[allow(clippy::too_many_arguments)]
fn prove_group_batch(
    layout: PcsLayout,
    prover: &PcsProverContext,
    stack: &UniformProverStack<'_, NativeField, CpuBackend>,
    commitments: &[CommittedGroup<NativeField>],
    batches: &[ProverBatch],
    point: &[NativeField],
    values: Vec<Vec<NativeField>>,
    descriptor: &[u8],
    opening_index: usize,
) -> Result<GroupOpeningProof, PcsError> {
    if commitments.len() != layout.groups_per_opening()
        || commitments.len() != batches.len()
        || batches.len() != values.len()
    {
        return Err(PcsError::Shape);
    }
    let claims = commitments
        .iter()
        .zip(&values)
        .map(|(commitment, values)| {
            PolynomialGroupClaims::new(point.to_vec(), values.clone(), commitment.clone())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let polynomial_refs = batches
        .iter()
        .map(|batch| batch.polynomials.iter().collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let polynomial_groups = polynomial_refs
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let hints = batches.iter().map(|batch| batch.hint.clone()).collect();
    let prover_data = SelectedProverOpeningData::from_committed_claims::<Config>(
        OpeningClaims::from_groups(claims)?,
        hints,
        polynomial_groups,
        prover.scheme.schedules(),
    )?;
    let selection = prover_data.selection();
    let mut transcript = opening_transcript(
        layout,
        descriptor,
        point,
        opening_index,
        selection,
        TranscriptSide::Prover,
    )?;
    let proof = prover.scheme.batched_prove(
        &prover.setup,
        prover_data,
        stack,
        &mut transcript,
        BasisMode::Lagrange,
    )?;
    Ok(GroupOpeningProof {
        selection,
        opened_values: values.into_iter().flatten().collect(),
        proof,
    })
}

pub(crate) fn verify_opening_with_backend(
    layout: PcsLayout,
    commitments: &ColumnCommitments,
    point: &[NativeField],
    logical_values: &[NativeField],
    instance_descriptor: &[u8],
    opening: &OpeningProof,
    backend: &NativeProverBackend,
) -> Result<(), PcsError> {
    validate_opening_shape(
        layout,
        commitments,
        point,
        logical_values,
        opening.groups.len(),
    )?;
    let scheme = scheme(layout)?;
    let (schedule, _) = validate_schedule(layout, &scheme)?;
    let prover_setup = scheme.setup_prover(layout.num_variables, layout.setup_capacity()?)?;
    let verifier_setup = match layout.opening_mode {
        PcsOpeningMode::Independent => scheme.setup_verifier(&prover_setup)?,
        PcsOpeningMode::Paired => {
            let sizes = vec![layout.group_columns; layout.groups_per_opening()];
            let claims_layout =
                OpeningClaimsLayout::from_group_sizes(layout.num_variables, &sizes)?;
            scheme.setup_verifier_for_schedule(&prover_setup, &schedule, &claims_layout)?
        }
    };
    backend.run_akita_opening(|| {
        for (opening_index, (committed_groups, group_opening)) in commitments
            .groups
            .chunks(layout.groups_per_opening())
            .zip(&opening.groups)
            .enumerate()
        {
            verify_group_batch(
                layout,
                &scheme,
                &verifier_setup,
                committed_groups,
                point,
                logical_values,
                instance_descriptor,
                opening_index,
                group_opening,
            )?;
        }
        Ok(())
    })
}

pub(crate) fn verify_selected_opening_with_backend(
    layout: PcsLayout,
    commitments: &ColumnCommitments,
    claim: SelectedOpeningClaim<'_>,
    opening: &OpeningProof,
    backend: &NativeProverBackend,
) -> Result<(), PcsError> {
    let opening_indices = selected_opening_indices(layout, commitments, claim.selected_columns)?;
    validate_selected_opening_shape(
        layout,
        commitments,
        claim.point,
        claim.logical_values,
        &opening_indices,
        opening.groups.len(),
    )?;
    let scheme = scheme(layout)?;
    let (schedule, _) = validate_schedule(layout, &scheme)?;
    let prover_setup = scheme.setup_prover(layout.num_variables, layout.setup_capacity()?)?;
    let verifier_setup = match layout.opening_mode {
        PcsOpeningMode::Independent => scheme.setup_verifier(&prover_setup)?,
        PcsOpeningMode::Paired => {
            let sizes = vec![layout.group_columns; layout.groups_per_opening()];
            let claims_layout =
                OpeningClaimsLayout::from_group_sizes(layout.num_variables, &sizes)?;
            scheme.setup_verifier_for_schedule(&prover_setup, &schedule, &claims_layout)?
        }
    };
    backend.run_akita_opening(|| {
        for (opening_index, group_opening) in opening_indices.into_iter().zip(&opening.groups) {
            let group_start = opening_index
                .checked_mul(layout.groups_per_opening())
                .ok_or(PcsError::Shape)?;
            let group_end = group_start
                .checked_add(layout.groups_per_opening())
                .ok_or(PcsError::Shape)?;
            let committed_groups = commitments
                .groups
                .get(group_start..group_end)
                .ok_or(PcsError::Shape)?;
            verify_group_batch(
                layout,
                &scheme,
                &verifier_setup,
                committed_groups,
                claim.point,
                claim.logical_values,
                claim.instance_descriptor,
                opening_index,
                group_opening,
            )?;
        }
        Ok(())
    })
}

pub(crate) fn selected_logical_columns(
    layout: PcsLayout,
    commitments: &ColumnCommitments,
    selected_columns: &[usize],
) -> Result<Vec<usize>, PcsError> {
    let opening_indices = selected_opening_indices(layout, commitments, selected_columns)?;
    let columns_per_opening = layout
        .group_columns
        .checked_mul(layout.groups_per_opening())
        .ok_or(PcsError::Shape)?;
    let mut columns = Vec::with_capacity(
        opening_indices
            .len()
            .checked_mul(columns_per_opening)
            .ok_or(PcsError::Shape)?,
    );
    for opening_index in opening_indices {
        let start = opening_index
            .checked_mul(columns_per_opening)
            .ok_or(PcsError::Shape)?;
        let end = start
            .checked_add(columns_per_opening)
            .map(|end| end.min(commitments.logical_column_count))
            .ok_or(PcsError::Shape)?;
        columns.extend(start..end);
    }
    Ok(columns)
}

pub(crate) fn scheme(layout: PcsLayout) -> Result<AkitaCommitmentScheme<Config>, PcsError> {
    AkitaCommitmentScheme::<Config>::from_schedule_artifact(layout.schedule_artifact)
        .map_err(PcsError::Akita)
}

fn validate_schedule(
    layout: PcsLayout,
    scheme: &AkitaCommitmentScheme<Config>,
) -> Result<(FoldSchedule, Vec<GroupCommitPhaseParams>), PcsError> {
    let mut rows = scheme.schedules().catalog().rows();
    let row = rows.next().ok_or(PcsError::Shape)?;
    if rows.next().is_some() {
        return Err(PcsError::Shape);
    }
    let profiles = row.profiles();
    let expected = PolynomialGroupLayout::new(layout.num_variables, layout.group_columns);
    let precommitted_count = match layout.opening_mode {
        PcsOpeningMode::Independent => 0,
        PcsOpeningMode::Paired => 1,
    };
    if profiles.final_group.group != expected
        || profiles.precommitteds.len() != precommitted_count
        || profiles
            .precommitteds
            .iter()
            .any(|profile| profile.group != expected)
    {
        return Err(PcsError::Shape);
    }
    Ok((row.schedule().clone(), profiles.precommitteds.clone()))
}

#[allow(clippy::too_many_arguments)]
fn verify_group_batch(
    layout: PcsLayout,
    scheme: &AkitaCommitmentScheme<Config>,
    verifier_setup: &AkitaVerifierSetup<NativeField>,
    commitments: &[CommittedGroup<NativeField>],
    point: &[NativeField],
    logical_values: &[NativeField],
    descriptor: &[u8],
    opening_index: usize,
    opening: &GroupOpeningProof,
) -> Result<(), PcsError> {
    if commitments.len() != layout.groups_per_opening() {
        return Err(PcsError::Shape);
    }
    let first_group = opening_index
        .checked_mul(layout.groups_per_opening())
        .ok_or(PcsError::Shape)?;
    let values = (0..layout.groups_per_opening())
        .map(|offset| {
            let group_index = first_group.checked_add(offset).ok_or(PcsError::Shape)?;
            padded_group_values(layout, logical_values, group_index)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expected_flat = values.iter().flatten().copied().collect::<Vec<_>>();
    if opening.opened_values != expected_flat {
        return Err(PcsError::Shape);
    }
    let claims = commitments
        .iter()
        .zip(values)
        .map(|(commitment, values)| PolynomialGroupClaims::new(point.to_vec(), values, commitment))
        .collect::<Result<Vec<_>, _>>()?;
    let statement =
        GroupBatchStatement::new(opening.selection, OpeningClaims::from_groups(claims)?)?;
    let mut transcript = opening_transcript(
        layout,
        descriptor,
        point,
        opening_index,
        opening.selection,
        TranscriptSide::Verifier,
    )?;
    scheme.batched_verify(
        &opening.proof,
        verifier_setup,
        &mut transcript,
        statement,
        BasisMode::Lagrange,
    )?;
    Ok(())
}

fn padded_polynomials<C>(
    layout: PcsLayout,
    column_group: &[C],
    row_count: usize,
) -> Result<Vec<DensePoly<NativeField>>, PcsError>
where
    C: AsRef<[u64]> + Sync,
{
    let mut polynomials = column_group
        .par_iter()
        .map(|column| {
            let field_column = column
                .as_ref()
                .iter()
                .copied()
                .map(NativeField::from_u64)
                .collect::<Vec<_>>();
            DensePoly::from_field_evals(layout.num_variables, field_column)
        })
        .collect::<Result<Vec<_>, _>>()?;
    while polynomials.len() < layout.group_columns {
        polynomials.push(DensePoly::from_field_evals(
            layout.num_variables,
            vec![NativeField::from_u64(0); row_count],
        )?);
    }
    Ok(polynomials)
}

fn field_column_view<'a>(
    layout: PcsLayout,
    logical_column_count: usize,
    polynomials: impl IntoIterator<Item = &'a DensePoly<NativeField>>,
) -> Result<FieldColumnView<'a>, PcsError> {
    let row_count = layout.row_count()?;
    let physical_column_count = logical_column_count
        .div_ceil(layout.group_columns)
        .checked_mul(layout.group_columns)
        .ok_or(PcsError::Shape)?;
    let mut columns = polynomials
        .into_iter()
        .map(|polynomial| {
            polynomial
                .field_coeffs()
                .get(..row_count)
                .ok_or(PcsError::Shape)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if logical_column_count == 0 || columns.len() != physical_column_count {
        return Err(PcsError::Shape);
    }
    columns.truncate(logical_column_count);
    Ok(FieldColumnView { columns })
}

fn validate_column_shape<T, C>(layout: PcsLayout, columns: &[C]) -> Result<usize, PcsError>
where
    C: AsRef<[T]>,
{
    if layout.group_columns == 0 {
        return Err(PcsError::Shape);
    }
    let row_count = columns
        .first()
        .map(|column| column.as_ref().len())
        .ok_or(PcsError::Shape)?;
    let expected_row_count = layout.row_count()?;
    if row_count != expected_row_count
        || columns
            .iter()
            .any(|column| column.as_ref().len() != row_count)
    {
        return Err(PcsError::Shape);
    }
    Ok(row_count)
}

fn validate_opening_shape(
    layout: PcsLayout,
    commitments: &ColumnCommitments,
    point: &[NativeField],
    logical_values: &[NativeField],
    opening_count: usize,
) -> Result<(), PcsError> {
    commitments.validate(layout)?;
    let expected_opening_count = layout.opening_count(commitments.groups.len())?;
    if point.len() != layout.num_variables
        || logical_values.len() != commitments.logical_column_count
        || opening_count != expected_opening_count
    {
        return Err(PcsError::Shape);
    }
    Ok(())
}

fn validate_selected_opening_shape(
    layout: PcsLayout,
    commitments: &ColumnCommitments,
    point: &[NativeField],
    logical_values: &[NativeField],
    opening_indices: &[usize],
    opening_count: usize,
) -> Result<(), PcsError> {
    commitments.validate(layout)?;
    if point.len() != layout.num_variables
        || logical_values.len() != commitments.logical_column_count
        || opening_indices.is_empty()
        || opening_count != opening_indices.len()
    {
        return Err(PcsError::Shape);
    }
    let selected = selected_logical_columns_from_indices(layout, commitments, opening_indices)?;
    let zero = NativeField::from_u64(0);
    let mut selected_cursor = selected.into_iter().peekable();
    for (index, value) in logical_values.iter().copied().enumerate() {
        if selected_cursor.peek().copied() == Some(index) {
            let _selected = selected_cursor.next();
        } else if value != zero {
            return Err(PcsError::Shape);
        }
    }
    if selected_cursor.next().is_some() {
        return Err(PcsError::Shape);
    }
    Ok(())
}

fn selected_opening_indices(
    layout: PcsLayout,
    commitments: &ColumnCommitments,
    selected_columns: &[usize],
) -> Result<Vec<usize>, PcsError> {
    commitments.validate(layout)?;
    if selected_columns.is_empty() {
        return Err(PcsError::Shape);
    }
    let opening_count = layout.opening_count(commitments.groups.len())?;
    let columns_per_opening = layout
        .group_columns
        .checked_mul(layout.groups_per_opening())
        .ok_or(PcsError::Shape)?;
    let mut selected = vec![false; opening_count];
    for column in selected_columns {
        if *column >= commitments.logical_column_count {
            return Err(PcsError::Shape);
        }
        let opening_index = column / columns_per_opening;
        *selected.get_mut(opening_index).ok_or(PcsError::Shape)? = true;
    }
    Ok(selected
        .into_iter()
        .enumerate()
        .filter_map(|(index, selected)| selected.then_some(index))
        .collect())
}

fn selected_logical_columns_from_indices(
    layout: PcsLayout,
    commitments: &ColumnCommitments,
    opening_indices: &[usize],
) -> Result<Vec<usize>, PcsError> {
    let columns_per_opening = layout
        .group_columns
        .checked_mul(layout.groups_per_opening())
        .ok_or(PcsError::Shape)?;
    let mut columns = Vec::new();
    for opening_index in opening_indices {
        let start = opening_index
            .checked_mul(columns_per_opening)
            .ok_or(PcsError::Shape)?;
        let end = start
            .checked_add(columns_per_opening)
            .map(|end| end.min(commitments.logical_column_count))
            .ok_or(PcsError::Shape)?;
        columns.extend(start..end);
    }
    Ok(columns)
}

fn padded_group_values(
    layout: PcsLayout,
    logical_values: &[NativeField],
    group_index: usize,
) -> Result<Vec<NativeField>, PcsError> {
    let start = group_index
        .checked_mul(layout.group_columns)
        .ok_or(PcsError::Shape)?;
    let end = start
        .checked_add(layout.group_columns)
        .map(|end| end.min(logical_values.len()))
        .ok_or(PcsError::Shape)?;
    let mut values = logical_values
        .get(start..end)
        .ok_or(PcsError::Shape)?
        .to_vec();
    values.resize(layout.group_columns, NativeField::from_u64(0));
    Ok(values)
}

enum TranscriptSide {
    Prover,
    Verifier,
}

fn opening_transcript(
    layout: PcsLayout,
    instance_descriptor: &[u8],
    point: &[NativeField],
    opening_index: usize,
    selection: OpeningScheduleSelection,
    side: TranscriptSide,
) -> Result<AkitaTranscript<NativeField>, PcsError> {
    let mut descriptor = instance_descriptor.to_vec();
    if layout.opening_mode == PcsOpeningMode::Paired {
        push_bytes(&mut descriptor, b"zksm83/native-pcs-pair/v2")?;
        push_bytes(&mut descriptor, selection.row_digest.as_bytes())?;
        push_usize(&mut descriptor, layout.groups_per_opening())?;
    }
    push_usize(&mut descriptor, opening_index)?;
    push_usize(&mut descriptor, point.len())?;
    for coordinate in point {
        descriptor.extend_from_slice(&coordinate.to_bytes_le_vec());
    }
    let mut transcript = match side {
        TranscriptSide::Prover => {
            AkitaTranscript::<NativeField>::unbound_prover(layout.opening_domain)
        }
        TranscriptSide::Verifier => {
            AkitaTranscript::<NativeField>::unbound_verifier(layout.opening_domain)
        }
    };
    transcript.bind_instance_bytes(&descriptor);
    Ok(transcript)
}

fn push_usize(bytes: &mut Vec<u8>, value: usize) -> Result<(), PcsError> {
    let value = u64::try_from(value).map_err(|_| PcsError::Shape)?;
    bytes.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), PcsError> {
    push_usize(bytes, value.len())?;
    bytes.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests;
