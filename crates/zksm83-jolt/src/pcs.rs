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
use akita_types::{
    AkitaBatchedProof, AkitaCommitmentHint, AkitaScheduleLookupKey, CommittedGroup, FoldSchedule,
    GroupBatchStatement, OpeningScheduleSelection, PolynomialGroupLayout,
};
use jolt_field::{CanonicalBytes, Ring};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    NativeField,
    metrics::{self, Phase},
};

type Config = fp128::DenseBounded;

/// Frozen PCS geometry and transcript domains for one column family.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct PcsLayout {
    num_variables: usize,
    group_columns: usize,
    schedule_artifact: &'static [u8],
    commitment_domain: &'static [u8],
    opening_domain: &'static [u8],
}

/// Prover-owned columns, commitment hints, and verifier-visible commitments.
pub(crate) struct CommittedColumns {
    field_columns: Vec<Vec<NativeField>>,
    commitments: ColumnCommitments,
    batches: Vec<ProverBatch>,
    context: PcsContextLease,
}

struct PcsProverContext {
    layout: PcsLayout,
    scheme: AkitaCommitmentScheme<Config>,
    setup: AkitaProverSetup<NativeField>,
    backend: CpuBackend,
    prepared: CpuPreparedSetup<NativeField>,
}

struct PcsContextLease {
    slot: Arc<PcsContextSlot>,
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
        }
    }

    fn row_count(self) -> Result<usize, PcsError> {
        let shift = u32::try_from(self.num_variables).map_err(|_| PcsError::Shape)?;
        1_usize.checked_shl(shift).ok_or(PcsError::Shape)
    }
}

impl CommittedColumns {
    pub(crate) const fn commitments(&self) -> &ColumnCommitments {
        &self.commitments
    }

    pub(crate) fn field_columns(&self) -> &[Vec<NativeField>] {
        &self.field_columns
    }
}

impl PcsProverContext {
    fn new(layout: PcsLayout) -> Result<Self, PcsError> {
        let _phase = metrics::start(Phase::Setup);
        let scheme = scheme(layout)?;
        let setup = scheme.setup_prover(layout.num_variables, layout.group_columns)?;
        let backend = CpuBackend::DEFAULT;
        let prepared = backend.prepare_setup(&setup)?;
        let context = Self {
            layout,
            scheme,
            setup,
            backend,
            prepared,
        };
        let stack = context.stack()?;
        prewarm_root_commit(layout, &context.scheme, &stack)?;
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
        Ok(Self { slot })
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

pub(crate) fn commit_columns(
    layout: PcsLayout,
    columns: &[Vec<u64>],
) -> Result<CommittedColumns, PcsError> {
    let row_count = validate_column_shape(layout, columns)?;
    let context = PcsContextLease::acquire(layout)?;
    let prover = context.context(layout)?;
    let stack = prover.stack()?;
    let _phase = metrics::start(Phase::Commit);
    let field_columns = columns
        .iter()
        .map(|column| {
            column
                .iter()
                .copied()
                .map(NativeField::from_u64)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let zero_column = vec![NativeField::from_u64(0); row_count];
    let group_count = field_columns.len().div_ceil(layout.group_columns);
    let mut groups = Vec::with_capacity(group_count);
    let mut batches = Vec::with_capacity(group_count);
    for column_group in field_columns.chunks(layout.group_columns) {
        let polynomials = padded_polynomials(layout, column_group, &zero_column)?;
        let output = prover.scheme.commit::<DensePoly<NativeField>, CpuBackend>(
            &prover.setup,
            &polynomials,
            &stack,
            akita_prover::GroupContext::scheduler_without_precommitted_groups(),
        )?;
        groups.push(output.committed_group);
        batches.push(ProverBatch {
            hint: output.hint,
            polynomials,
        });
    }
    let commitments = ColumnCommitments {
        num_variables: layout.num_variables,
        logical_column_count: field_columns.len(),
        group_columns: layout.group_columns,
        groups,
    };
    commitments.validate(layout)?;
    Ok(CommittedColumns {
        field_columns,
        commitments,
        batches,
        context,
    })
}

fn prewarm_root_commit(
    layout: PcsLayout,
    scheme: &AkitaCommitmentScheme<Config>,
    stack: &UniformProverStack<'_, NativeField, CpuBackend>,
) -> Result<(), PcsError> {
    let group = PolynomialGroupLayout::new(layout.num_variables, layout.group_columns);
    let key = AkitaScheduleLookupKey::single(group);
    let schedule = scheme.schedules().resolve_key(&key)?.schedule();
    let requirements = root_commit_requirements(schedule)?;
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

pub(crate) fn prove_opening(
    layout: PcsLayout,
    columns: &CommittedColumns,
    point: &[NativeField],
    logical_values: &[NativeField],
    instance_descriptor: &[u8],
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
    let mut groups = Vec::with_capacity(columns.batches.len());
    for (group_index, (committed_group, batch)) in columns
        .commitments
        .groups
        .iter()
        .zip(&columns.batches)
        .enumerate()
    {
        let opened_values = padded_group_values(layout, logical_values, group_index)?;
        let claims = OpeningClaims::from_groups(vec![PolynomialGroupClaims::new(
            point.to_vec(),
            opened_values.clone(),
            committed_group.clone(),
        )?])?;
        let polynomial_group = batch.polynomials.iter().collect::<Vec<_>>();
        let prover_data = SelectedProverOpeningData::from_committed_claims::<Config>(
            claims,
            vec![batch.hint.clone()],
            vec![polynomial_group.as_slice()],
            prover.scheme.schedules(),
        )?;
        let selection = prover_data.selection();
        let mut transcript = opening_transcript(
            layout,
            instance_descriptor,
            point,
            group_index,
            TranscriptSide::Prover,
        )?;
        let proof = prover.scheme.batched_prove(
            &prover.setup,
            prover_data,
            &stack,
            &mut transcript,
            BasisMode::Lagrange,
        )?;
        groups.push(GroupOpeningProof {
            selection,
            opened_values,
            proof,
        });
    }
    Ok(OpeningProof { groups })
}

pub(crate) fn verify_opening(
    layout: PcsLayout,
    commitments: &ColumnCommitments,
    point: &[NativeField],
    logical_values: &[NativeField],
    instance_descriptor: &[u8],
    opening: &OpeningProof,
) -> Result<(), PcsError> {
    validate_opening_shape(
        layout,
        commitments,
        point,
        logical_values,
        opening.groups.len(),
    )?;
    let scheme = scheme(layout)?;
    let prover_setup = scheme.setup_prover(layout.num_variables, layout.group_columns)?;
    let verifier_setup = scheme.setup_verifier(&prover_setup)?;
    for (group_index, (committed_group, group_opening)) in
        commitments.groups.iter().zip(&opening.groups).enumerate()
    {
        let expected_values = padded_group_values(layout, logical_values, group_index)?;
        if group_opening.opened_values != expected_values {
            return Err(PcsError::Shape);
        }
        let claims = OpeningClaims::from_groups(vec![PolynomialGroupClaims::new(
            point.to_vec(),
            group_opening.opened_values.clone(),
            committed_group,
        )?])?;
        let statement = GroupBatchStatement::new(group_opening.selection, claims)?;
        let mut transcript = opening_transcript(
            layout,
            instance_descriptor,
            point,
            group_index,
            TranscriptSide::Verifier,
        )?;
        scheme.batched_verify(
            &group_opening.proof,
            &verifier_setup,
            &mut transcript,
            statement,
            BasisMode::Lagrange,
        )?;
    }
    Ok(())
}

pub(crate) fn scheme(layout: PcsLayout) -> Result<AkitaCommitmentScheme<Config>, PcsError> {
    AkitaCommitmentScheme::<Config>::from_schedule_artifact(layout.schedule_artifact)
        .map_err(PcsError::Akita)
}

fn padded_polynomials(
    layout: PcsLayout,
    column_group: &[Vec<NativeField>],
    zero_column: &[NativeField],
) -> Result<Vec<DensePoly<NativeField>>, PcsError> {
    let mut polynomials = column_group
        .iter()
        .map(|column| DensePoly::from_field_evals(layout.num_variables, column))
        .collect::<Result<Vec<_>, _>>()?;
    while polynomials.len() < layout.group_columns {
        polynomials.push(DensePoly::from_field_evals(
            layout.num_variables,
            zero_column,
        )?);
    }
    Ok(polynomials)
}

fn validate_column_shape<T>(layout: PcsLayout, columns: &[Vec<T>]) -> Result<usize, PcsError> {
    if layout.group_columns == 0 {
        return Err(PcsError::Shape);
    }
    let row_count = columns.first().map(Vec::len).ok_or(PcsError::Shape)?;
    let expected_row_count = layout.row_count()?;
    if row_count != expected_row_count || columns.iter().any(|column| column.len() != row_count) {
        return Err(PcsError::Shape);
    }
    Ok(row_count)
}

fn validate_opening_shape(
    layout: PcsLayout,
    commitments: &ColumnCommitments,
    point: &[NativeField],
    logical_values: &[NativeField],
    opening_group_count: usize,
) -> Result<(), PcsError> {
    commitments.validate(layout)?;
    if point.len() != layout.num_variables
        || logical_values.len() != commitments.logical_column_count
        || opening_group_count != commitments.groups.len()
    {
        return Err(PcsError::Shape);
    }
    Ok(())
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
    group_index: usize,
    side: TranscriptSide,
) -> Result<AkitaTranscript<NativeField>, PcsError> {
    let mut descriptor = instance_descriptor.to_vec();
    push_usize(&mut descriptor, group_index)?;
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
mod tests {
    use std::sync::Arc;

    use super::{
        AkitaScheduleLookupKey, PcsLayout, PolynomialGroupLayout, context_slot,
        root_commit_requirements, scheme,
    };

    const DOMAIN: &[u8] = b"zksm83/pcs-prewarm-test/v1";
    const ROM_FILE: &[u8] = include_bytes!("../protocol/akita/fp128_dense_bounded_nv20_p1.aks");
    const ROM_SCHEDULE: &[u8] = ROM_FILE.split_at(ROM_FILE.len() - 1).0;
    const MEMORY_FILE: &[u8] = include_bytes!("../protocol/akita/fp128_dense_bounded_nv17_p1.aks");
    const MEMORY_SCHEDULE: &[u8] = MEMORY_FILE.split_at(MEMORY_FILE.len() - 1).0;
    const LOG_FILE: &[u8] = include_bytes!("../protocol/akita/fp128_dense_bounded_nv17_p128.aks");
    const LOG_SCHEDULE: &[u8] = LOG_FILE.split_at(LOG_FILE.len() - 1).0;

    #[test]
    fn every_pinned_layout_has_explicit_root_commit_prewarm_requirements()
    -> Result<(), Box<dyn std::error::Error>> {
        for layout in layouts() {
            let scheme = scheme(layout)?;
            let group = PolynomialGroupLayout::new(layout.num_variables, layout.group_columns);
            let key = AkitaScheduleLookupKey::single(group);
            let schedule = scheme.schedules().resolve_key(&key)?.schedule();
            assert!(!root_commit_requirements(schedule)?.entries().is_empty());
        }
        Ok(())
    }

    #[test]
    fn live_layouts_share_one_initialization_slot() -> Result<(), Box<dyn std::error::Error>> {
        let rom_layout = layout(20, 1, ROM_FILE);
        let first = context_slot(rom_layout)?;
        let second = context_slot(rom_layout)?;
        let different = context_slot(layout(17, 1, MEMORY_FILE))?;
        assert!(Arc::ptr_eq(&first, &second));
        assert!(!Arc::ptr_eq(&first, &different));
        assert!(first.get().is_none());
        Ok(())
    }

    fn layouts() -> [PcsLayout; 6] {
        [
            layout(
                14,
                128,
                include_bytes!("../protocol/akita/fp128_dense_bounded_nv14_p128.aks"),
            ),
            layout(
                9,
                128,
                include_bytes!("../protocol/akita/fp128_dense_bounded_nv9_p128.aks"),
            ),
            layout(20, 1, ROM_SCHEDULE),
            layout(17, 1, MEMORY_SCHEDULE),
            layout(17, 128, LOG_SCHEDULE),
            layout(
                14,
                1,
                include_bytes!("../protocol/akita/fp128_dense_bounded.aks"),
            ),
        ]
    }

    const fn layout(variables: usize, columns: usize, schedule: &'static [u8]) -> PcsLayout {
        PcsLayout::new(variables, columns, schedule, DOMAIN, DOMAIN)
    }
}
