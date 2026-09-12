//! Isolated, non-protocol PCS batching experiment.
//!
//! The version-one receipt never calls this module. Its only caller is the
//! bounded `zksm83-pcs-batch-gate` process, which compares two independent
//! openings with one genuine two-group opening over the same deterministic
//! columns and claims.

use std::time::Instant;

use akita_config::proof_optimized::fp128;
use akita_pcs::{
    AkitaCommitmentScheme, AkitaDeserialize, AkitaSerialize, AkitaTranscript, BasisMode,
    ComputeBackendSetup, CpuBackend, CpuPreparedSetup, OpeningClaims, PolynomialGroupClaims,
    UniformProverStack,
};
use akita_prover::{
    AkitaProverSetup, DensePoly, NttExecutionRequirements, SelectedProverOpeningData,
    prewarm_ntt_requirements,
};
use akita_serialization::SerializationError;
use akita_types::{
    AkitaBatchedProof, AkitaBatchedProofShape, AkitaCommitmentHint, AkitaVerifierSetup,
    CommittedGroup, FoldSchedule, GroupBatchStatement, GroupCommitPhaseParams, OpeningClaimsLayout,
    OpeningScheduleSelection, PrecommittedGroupProfiles, ScheduleRowDigest,
};
use jolt_field::Ring;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{AkitaWorkerError, NativeField};

type Config = fp128::DenseBounded;

const NUM_VARIABLES: usize = 9;
const ROW_COUNT: usize = 1 << NUM_VARIABLES;
const GROUP_COLUMNS: usize = 128;
const GROUP_COUNT: usize = 2;
const TOTAL_COLUMNS: usize = GROUP_COLUMNS * GROUP_COUNT;
const INDEPENDENT_SCHEDULE: &[u8] =
    include_bytes!("../protocol/akita/fp128_dense_bounded_nv9_p128.aks");
const INDEPENDENT_TRANSCRIPT_DOMAIN: &[u8] = b"zksm83/pcs-batch-gate/independent/v1";
const BATCHED_TRANSCRIPT_DOMAIN: &[u8] = b"zksm83/pcs-batch-gate/batched/v1";
const INSTANCE_DOMAIN: &[u8] = b"zksm83-pcs-batch-gate/v1";

/// Opening topology executed by one bounded gate worker.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PcsBatchGateMode {
    /// Two version-one single-group openings with independently bound transcripts.
    Independent,
    /// One candidate opening containing one precommitted and one final group.
    Batched,
}

impl PcsBatchGateMode {
    fn transcript_domain(self) -> &'static [u8] {
        match self {
            Self::Independent => INDEPENDENT_TRANSCRIPT_DOMAIN,
            Self::Batched => BATCHED_TRANSCRIPT_DOMAIN,
        }
    }
}

/// Negative verification checks required before a batched candidate can pass.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PcsBatchTamperReport {
    /// Swapping the two ordered groups was rejected.
    pub swapped_groups_rejected: bool,
    /// Replacing one commitment was rejected.
    pub changed_commitment_rejected: bool,
    /// Changing one claimed opening value was rejected.
    pub changed_value_rejected: bool,
    /// Changing one opening-point coordinate was rejected.
    pub changed_point_rejected: bool,
    /// Changing the selected schedule-row digest was rejected.
    pub changed_schedule_rejected: bool,
}

impl PcsBatchTamperReport {
    /// Returns true only when every required negative check failed closed.
    #[must_use]
    pub const fn all_rejected(self) -> bool {
        self.swapped_groups_rejected
            && self.changed_commitment_rejected
            && self.changed_value_rejected
            && self.changed_point_rejected
            && self.changed_schedule_rejected
    }
}

/// Measurements and verification evidence produced by one worker process.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PcsBatchPathReport {
    /// Stable non-protocol report schema.
    pub schema: String,
    /// Opening topology measured by this worker.
    pub mode: PcsBatchGateMode,
    /// SHA-256 of the locally generated candidate schedule.
    pub candidate_schedule_sha256: String,
    /// First setup, preparation, and NTT-prewarm duration in seconds.
    pub cold_setup_seconds: f64,
    /// Second setup, preparation, and NTT-prewarm duration in seconds.
    pub warm_setup_seconds: f64,
    /// Polynomial conversion and commitment duration in seconds.
    pub commit_seconds: f64,
    /// Opening-proof construction duration in seconds.
    pub opening_seconds: f64,
    /// Canonical proof payload encode/decode duration in seconds.
    pub encode_seconds: f64,
    /// Exact positive verification and required negative checks in seconds.
    pub verify_seconds: f64,
    /// Total child-worker duration, including schedule parsing and fixture construction.
    pub worker_seconds: f64,
    /// Canonically framed schedule selection, values, shape, and proof bytes.
    pub proof_bytes: usize,
    /// Number of groups opened across the measured path.
    pub opened_group_count: usize,
    /// True only after the exact public claims verify.
    pub verified: bool,
    /// Batched-only fail-closed matrix; absent for the independent baseline.
    pub tamper: Option<PcsBatchTamperReport>,
}

/// Failure of the isolated PCS batching experiment.
#[derive(Debug, Error)]
pub enum PcsBatchGateError {
    /// The schedule, columns, claims, or proof topology was not exact.
    #[error("PCS batch gate shape is invalid")]
    Shape,
    /// Akita rejected setup, commitment, opening, or verification.
    #[error("Akita rejected the PCS batch gate: {0}")]
    Akita(#[from] akita_pcs::AkitaError),
    /// Canonical proof serialization or decoding failed.
    #[error("PCS batch gate serialization failed: {0}")]
    Serialization(#[from] SerializationError),
    /// One required tamper case was accepted.
    #[error("PCS batch gate accepted tampering: {0}")]
    TamperAccepted(&'static str),
    /// The operating system rejected the large-stack worker.
    #[error("failed to start PCS batch gate worker: {0}")]
    WorkerSpawn(#[source] std::io::Error),
    /// The large-stack worker panicked and its result was rejected.
    #[error("PCS batch gate worker terminated unexpectedly")]
    WorkerPanicked,
}

struct GateContext {
    setup: AkitaProverSetup<NativeField>,
    verifier_setup: AkitaVerifierSetup<NativeField>,
    backend: CpuBackend,
    prepared: CpuPreparedSetup<NativeField>,
}

impl GateContext {
    fn stack(&self) -> Result<UniformProverStack<'_, NativeField, CpuBackend>, PcsBatchGateError> {
        UniformProverStack::uniform(&self.backend, &self.prepared, self.setup.expanded.as_ref())
            .map_err(Into::into)
    }
}

struct CandidateSchedule {
    precommitted_profile: GroupCommitPhaseParams,
    schedule: FoldSchedule,
}

struct CommittedGateColumns {
    polynomials: Vec<Vec<DensePoly<NativeField>>>,
    commitments: Vec<CommittedGroup<NativeField>>,
    hints: Vec<AkitaCommitmentHint<NativeField>>,
}

struct GateProof {
    selection: OpeningScheduleSelection,
    opened_values: Vec<Vec<NativeField>>,
    proof: AkitaBatchedProof<NativeField, NativeField>,
}

/// Run one experiment path on the repository's bounded Akita worker stack.
///
/// This function performs real PCS work but never proves an SM83 relation. The
/// CLI invokes it only in a child process that the parent kills at its deadline.
/// The candidate bytes are local experimental input and are not admitted into
/// the version-one receipt protocol.
pub fn run_pcs_batch_gate_worker(
    mode: PcsBatchGateMode,
    candidate_schedule: &[u8],
) -> Result<PcsBatchPathReport, PcsBatchGateError> {
    match crate::on_akita_worker(|| run_on_worker(mode, candidate_schedule)) {
        Ok(result) => result,
        Err(AkitaWorkerError::Spawn(error)) => Err(PcsBatchGateError::WorkerSpawn(error)),
        Err(AkitaWorkerError::Panicked) => Err(PcsBatchGateError::WorkerPanicked),
    }
}

fn run_on_worker(
    mode: PcsBatchGateMode,
    candidate_bytes: &[u8],
) -> Result<PcsBatchPathReport, PcsBatchGateError> {
    let worker_started = Instant::now();
    let candidate_digest = hex_digest(candidate_bytes);
    let candidate_scheme =
        AkitaCommitmentScheme::<Config>::from_schedule_artifact(candidate_bytes)?;
    let candidate = validate_candidate_schedule(&candidate_scheme)?;
    let (scheme, schedule, capacity, explicit_precommitted) = match mode {
        PcsBatchGateMode::Independent => {
            let scheme =
                AkitaCommitmentScheme::<Config>::from_schedule_artifact(INDEPENDENT_SCHEDULE)?;
            let schedule = validate_independent_schedule(&scheme)?;
            (scheme, schedule, GROUP_COLUMNS, None)
        }
        PcsBatchGateMode::Batched => (
            candidate_scheme,
            candidate.schedule,
            TOTAL_COLUMNS,
            Some(candidate.precommitted_profile),
        ),
    };

    let cold_started = Instant::now();
    let cold_context = prepare_context(&scheme, &schedule, capacity)?;
    let cold_setup_seconds = cold_started.elapsed().as_secs_f64();
    drop(cold_context);

    let warm_started = Instant::now();
    let context = prepare_context(&scheme, &schedule, capacity)?;
    let warm_setup_seconds = warm_started.elapsed().as_secs_f64();
    let columns = deterministic_columns();
    let point = deterministic_point()?;
    let opened_values = evaluate_groups(&columns, &point)?;

    let commit_started = Instant::now();
    let mut committed = commit_gate_columns(
        mode,
        &scheme,
        &context,
        &columns,
        explicit_precommitted.as_ref(),
    )?;
    let commit_seconds = commit_started.elapsed().as_secs_f64();

    let opening_started = Instant::now();
    let proofs = prove_path(
        mode,
        &scheme,
        &context,
        &mut committed,
        &point,
        &opened_values,
    )?;
    let opening_seconds = opening_started.elapsed().as_secs_f64();

    let encode_started = Instant::now();
    let (proofs, proof_bytes) = round_trip_proofs(proofs)?;
    let encode_seconds = encode_started.elapsed().as_secs_f64();

    let verify_started = Instant::now();
    verify_positive(mode, &scheme, &context, &committed, &point, &proofs)?;
    let tamper = match mode {
        PcsBatchGateMode::Independent => None,
        PcsBatchGateMode::Batched => Some(verify_tamper_matrix(
            &scheme, &context, &committed, &point, &proofs,
        )?),
    };
    let verify_seconds = verify_started.elapsed().as_secs_f64();

    Ok(PcsBatchPathReport {
        schema: "zksm83-pcs-batch-path/v1".to_owned(),
        mode,
        candidate_schedule_sha256: candidate_digest,
        cold_setup_seconds,
        warm_setup_seconds,
        commit_seconds,
        opening_seconds,
        encode_seconds,
        verify_seconds,
        worker_seconds: worker_started.elapsed().as_secs_f64(),
        proof_bytes,
        opened_group_count: GROUP_COUNT,
        verified: true,
        tamper,
    })
}

fn prepare_context(
    scheme: &AkitaCommitmentScheme<Config>,
    schedule: &FoldSchedule,
    capacity: usize,
) -> Result<GateContext, PcsBatchGateError> {
    let setup = scheme.setup_prover(NUM_VARIABLES, capacity)?;
    let group_sizes = if capacity == TOTAL_COLUMNS {
        vec![GROUP_COLUMNS, GROUP_COLUMNS]
    } else {
        vec![GROUP_COLUMNS]
    };
    let opening_layout = OpeningClaimsLayout::from_group_sizes(NUM_VARIABLES, &group_sizes)?;
    let verifier_setup = scheme.setup_verifier_for_schedule(&setup, schedule, &opening_layout)?;
    let backend = CpuBackend::DEFAULT;
    let prepared = backend.prepare_setup(&setup)?;
    {
        let stack = UniformProverStack::uniform(&backend, &prepared, setup.expanded.as_ref())?;
        let requirements = NttExecutionRequirements::from_commit_and_prove_schedule(schedule)?;
        prewarm_ntt_requirements::<NativeField, _>(&stack, &requirements)?;
    }
    Ok(GateContext {
        setup,
        verifier_setup,
        backend,
        prepared,
    })
}

fn validate_candidate_schedule(
    scheme: &AkitaCommitmentScheme<Config>,
) -> Result<CandidateSchedule, PcsBatchGateError> {
    let mut rows = scheme.schedules().catalog().rows();
    let row = rows.next().ok_or(PcsBatchGateError::Shape)?;
    if rows.next().is_some() {
        return Err(PcsBatchGateError::Shape);
    }
    let profiles = row.profiles();
    let precommitted = profiles
        .precommitteds
        .first()
        .copied()
        .ok_or(PcsBatchGateError::Shape)?;
    if profiles.precommitteds.len() != 1
        || !is_gate_group(profiles.final_group.group)
        || !is_gate_group(precommitted.group)
    {
        return Err(PcsBatchGateError::Shape);
    }
    Ok(CandidateSchedule {
        precommitted_profile: precommitted,
        schedule: row.schedule().clone(),
    })
}

fn validate_independent_schedule(
    scheme: &AkitaCommitmentScheme<Config>,
) -> Result<FoldSchedule, PcsBatchGateError> {
    let mut rows = scheme.schedules().catalog().rows();
    let row = rows.next().ok_or(PcsBatchGateError::Shape)?;
    if rows.next().is_some()
        || !row.profiles().precommitteds.is_empty()
        || !is_gate_group(row.profiles().final_group.group)
    {
        return Err(PcsBatchGateError::Shape);
    }
    Ok(row.schedule().clone())
}

fn is_gate_group(group: akita_types::PolynomialGroupLayout) -> bool {
    group.num_vars() == NUM_VARIABLES && group.num_polynomials() == GROUP_COLUMNS
}

fn deterministic_columns() -> Vec<Vec<Vec<NativeField>>> {
    (0..GROUP_COUNT)
        .map(|group| {
            (0..GROUP_COLUMNS)
                .map(|column| {
                    (0..ROW_COUNT)
                        .map(|row| {
                            let bit = (((row >> group) ^ column) & 1) == 1;
                            NativeField::from_u64(u64::from(bit))
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

fn deterministic_point() -> Result<Vec<NativeField>, PcsBatchGateError> {
    (0..NUM_VARIABLES)
        .map(|index| {
            u64::try_from(index + 2)
                .map(NativeField::from_u64)
                .map_err(|_| PcsBatchGateError::Shape)
        })
        .collect()
}

fn evaluate_groups(
    groups: &[Vec<Vec<NativeField>>],
    point: &[NativeField],
) -> Result<Vec<Vec<NativeField>>, PcsBatchGateError> {
    groups
        .iter()
        .map(|columns| {
            columns
                .iter()
                .map(|column| evaluate_mle(column, point))
                .collect()
        })
        .collect()
}

fn evaluate_mle(
    evaluations: &[NativeField],
    point: &[NativeField],
) -> Result<NativeField, PcsBatchGateError> {
    if evaluations.len() != ROW_COUNT || point.len() != NUM_VARIABLES {
        return Err(PcsBatchGateError::Shape);
    }
    let mut folded = evaluations.to_vec();
    for challenge in point {
        let mut next = Vec::with_capacity(folded.len() / 2);
        for pair in folded.chunks_exact(2) {
            let low = pair.first().copied().ok_or(PcsBatchGateError::Shape)?;
            let high = pair.get(1).copied().ok_or(PcsBatchGateError::Shape)?;
            next.push(low + *challenge * (high - low));
        }
        folded = next;
    }
    folded.first().copied().ok_or(PcsBatchGateError::Shape)
}

fn commit_gate_columns(
    mode: PcsBatchGateMode,
    scheme: &AkitaCommitmentScheme<Config>,
    context: &GateContext,
    columns: &[Vec<Vec<NativeField>>],
    explicit_precommitted: Option<&GroupCommitPhaseParams>,
) -> Result<CommittedGateColumns, PcsBatchGateError> {
    let polynomials = columns
        .iter()
        .map(|group| {
            group
                .iter()
                .map(|column| DensePoly::from_field_evals(NUM_VARIABLES, column))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    if polynomials.len() != GROUP_COUNT {
        return Err(PcsBatchGateError::Shape);
    }
    let stack = context.stack()?;
    let mut commitments = Vec::with_capacity(GROUP_COUNT);
    let mut hints = Vec::with_capacity(GROUP_COUNT);
    match mode {
        PcsBatchGateMode::Independent => {
            for group in &polynomials {
                let output = scheme.commit(
                    &context.setup,
                    group,
                    &stack,
                    akita_prover::GroupContext::scheduler_without_precommitted_groups(),
                )?;
                commitments.push(output.committed_group);
                hints.push(output.hint);
            }
        }
        PcsBatchGateMode::Batched => {
            let profile = explicit_precommitted.ok_or(PcsBatchGateError::Shape)?;
            let pre_group = polynomials.first().ok_or(PcsBatchGateError::Shape)?;
            let final_group = polynomials.last().ok_or(PcsBatchGateError::Shape)?;
            let pre = scheme.commit(
                &context.setup,
                pre_group,
                &stack,
                akita_prover::GroupContext::explicit(profile),
            )?;
            let precommitteds = PrecommittedGroupProfiles::from_ordered_groups(std::iter::once(
                &pre.committed_group,
            ))?;
            let final_output = scheme.commit(
                &context.setup,
                final_group,
                &stack,
                akita_prover::GroupContext::scheduler_with_precommitted_groups(&precommitteds),
            )?;
            commitments.push(pre.committed_group);
            commitments.push(final_output.committed_group);
            hints.push(pre.hint);
            hints.push(final_output.hint);
        }
    }
    Ok(CommittedGateColumns {
        polynomials,
        commitments,
        hints,
    })
}

fn prove_path(
    mode: PcsBatchGateMode,
    scheme: &AkitaCommitmentScheme<Config>,
    context: &GateContext,
    committed: &mut CommittedGateColumns,
    point: &[NativeField],
    opened_values: &[Vec<NativeField>],
) -> Result<Vec<GateProof>, PcsBatchGateError> {
    let hints = std::mem::take(&mut committed.hints);
    match mode {
        PcsBatchGateMode::Independent => {
            prove_independent(scheme, context, committed, hints, point, opened_values)
        }
        PcsBatchGateMode::Batched => {
            let polynomial_groups = committed
                .polynomials
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>();
            let commitments = committed.commitments.iter().collect::<Vec<_>>();
            Ok(vec![prove_selected_groups(
                mode,
                scheme,
                context,
                &polynomial_groups,
                &commitments,
                hints,
                point,
                opened_values,
                0,
            )?])
        }
    }
}

fn prove_independent(
    scheme: &AkitaCommitmentScheme<Config>,
    context: &GateContext,
    committed: &CommittedGateColumns,
    hints: Vec<AkitaCommitmentHint<NativeField>>,
    point: &[NativeField],
    opened_values: &[Vec<NativeField>],
) -> Result<Vec<GateProof>, PcsBatchGateError> {
    if hints.len() != GROUP_COUNT {
        return Err(PcsBatchGateError::Shape);
    }
    let mut proofs = Vec::with_capacity(GROUP_COUNT);
    for (group_index, hint) in hints.into_iter().enumerate() {
        let polynomials = committed
            .polynomials
            .get(group_index)
            .ok_or(PcsBatchGateError::Shape)?;
        let commitment = committed
            .commitments
            .get(group_index)
            .ok_or(PcsBatchGateError::Shape)?;
        let values = opened_values
            .get(group_index)
            .ok_or(PcsBatchGateError::Shape)?;
        let polynomial_groups = [polynomials.as_slice()];
        let commitments = [commitment];
        proofs.push(prove_selected_groups(
            PcsBatchGateMode::Independent,
            scheme,
            context,
            &polynomial_groups,
            &commitments,
            vec![hint],
            point,
            std::slice::from_ref(values),
            group_index,
        )?);
    }
    Ok(proofs)
}

#[allow(clippy::too_many_arguments)]
fn prove_selected_groups(
    mode: PcsBatchGateMode,
    scheme: &AkitaCommitmentScheme<Config>,
    context: &GateContext,
    polynomial_groups: &[&[DensePoly<NativeField>]],
    commitments: &[&CommittedGroup<NativeField>],
    hints: Vec<AkitaCommitmentHint<NativeField>>,
    point: &[NativeField],
    opened_values: &[Vec<NativeField>],
    transcript_index: usize,
) -> Result<GateProof, PcsBatchGateError> {
    if polynomial_groups.len() != commitments.len()
        || commitments.len() != hints.len()
        || hints.len() != opened_values.len()
    {
        return Err(PcsBatchGateError::Shape);
    }
    let claims = commitments
        .iter()
        .zip(opened_values)
        .map(|(commitment, values)| {
            PolynomialGroupClaims::new(point.to_vec(), values.clone(), (*commitment).clone())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let refs = polynomial_groups
        .iter()
        .map(|group| group.iter().collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let group_slices = refs.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let prover_data = SelectedProverOpeningData::from_committed_claims::<Config>(
        OpeningClaims::from_groups(claims)?,
        hints,
        group_slices,
        scheme.schedules(),
    )?;
    let selection = prover_data.selection();
    let schedule_digest = selection.row_digest.as_bytes();
    let mut transcript = transcript(mode, schedule_digest, transcript_index, true)?;
    let stack = context.stack()?;
    let proof = scheme.batched_prove(
        &context.setup,
        prover_data,
        &stack,
        &mut transcript,
        BasisMode::Lagrange,
    )?;
    Ok(GateProof {
        selection,
        opened_values: opened_values.to_vec(),
        proof,
    })
}

fn round_trip_proofs(proofs: Vec<GateProof>) -> Result<(Vec<GateProof>, usize), PcsBatchGateError> {
    let mut total = 8_usize;
    let mut decoded = Vec::with_capacity(proofs.len());
    for proof in proofs {
        let mut selection_bytes = Vec::new();
        proof.selection.serialize_compressed(&mut selection_bytes)?;
        total = framed_total(total, selection_bytes.len())?;
        let decoded_selection =
            deserialize_exact::<OpeningScheduleSelection>(&selection_bytes, &())?;
        if decoded_selection != proof.selection {
            return Err(PcsBatchGateError::Shape);
        }
        total = total.checked_add(8).ok_or(PcsBatchGateError::Shape)?;
        let mut decoded_values = Vec::with_capacity(proof.opened_values.len());
        for values in &proof.opened_values {
            total = total.checked_add(8).ok_or(PcsBatchGateError::Shape)?;
            let mut decoded_group = Vec::with_capacity(values.len());
            for value in values {
                let mut value_bytes = Vec::new();
                value.serialize_compressed(&mut value_bytes)?;
                total = framed_total(total, value_bytes.len())?;
                let decoded_value = deserialize_exact::<NativeField>(&value_bytes, &())?;
                if decoded_value != *value {
                    return Err(PcsBatchGateError::Shape);
                }
                decoded_group.push(decoded_value);
            }
            decoded_values.push(decoded_group);
        }
        let shape = proof.proof.shape();
        let mut shape_bytes = Vec::new();
        shape.serialize_compressed(&mut shape_bytes)?;
        total = framed_total(total, shape_bytes.len())?;
        let decoded_shape = deserialize_exact::<AkitaBatchedProofShape>(&shape_bytes, &())?;
        let mut proof_bytes = Vec::new();
        proof.proof.serialize_compressed(&mut proof_bytes)?;
        total = framed_total(total, proof_bytes.len())?;
        let decoded_proof = deserialize_exact::<AkitaBatchedProof<NativeField, NativeField>>(
            &proof_bytes,
            &decoded_shape,
        )?;
        decoded.push(GateProof {
            selection: decoded_selection,
            opened_values: decoded_values,
            proof: decoded_proof,
        });
    }
    Ok((decoded, total))
}

fn deserialize_exact<T: AkitaDeserialize>(
    bytes: &[u8],
    context: &T::Context,
) -> Result<T, PcsBatchGateError> {
    let mut cursor = std::io::Cursor::new(bytes);
    let decoded = T::deserialize_compressed(&mut cursor, context)?;
    if usize::try_from(cursor.position()).map_err(|_| PcsBatchGateError::Shape)? != bytes.len() {
        return Err(PcsBatchGateError::Shape);
    }
    Ok(decoded)
}

fn framed_total(total: usize, payload: usize) -> Result<usize, PcsBatchGateError> {
    total
        .checked_add(8)
        .and_then(|value| value.checked_add(payload))
        .ok_or(PcsBatchGateError::Shape)
}

fn verify_positive(
    mode: PcsBatchGateMode,
    scheme: &AkitaCommitmentScheme<Config>,
    context: &GateContext,
    committed: &CommittedGateColumns,
    point: &[NativeField],
    proofs: &[GateProof],
) -> Result<(), PcsBatchGateError> {
    match mode {
        PcsBatchGateMode::Independent => {
            if proofs.len() != GROUP_COUNT {
                return Err(PcsBatchGateError::Shape);
            }
            for (index, proof) in proofs.iter().enumerate() {
                let commitment = committed
                    .commitments
                    .get(index)
                    .ok_or(PcsBatchGateError::Shape)?;
                let values = proof
                    .opened_values
                    .first()
                    .ok_or(PcsBatchGateError::Shape)?;
                let commitments = [commitment];
                verify_claims(
                    mode,
                    scheme,
                    context,
                    proof,
                    &commitments,
                    std::slice::from_ref(&point),
                    std::slice::from_ref(values),
                    index,
                    proof.selection,
                )?;
            }
            Ok(())
        }
        PcsBatchGateMode::Batched => {
            let proof = proofs.first().ok_or(PcsBatchGateError::Shape)?;
            let points = [point, point];
            let commitments = committed.commitments.iter().collect::<Vec<_>>();
            verify_claims(
                mode,
                scheme,
                context,
                proof,
                &commitments,
                &points,
                &proof.opened_values,
                0,
                proof.selection,
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_claims(
    mode: PcsBatchGateMode,
    scheme: &AkitaCommitmentScheme<Config>,
    context: &GateContext,
    proof: &GateProof,
    commitments: &[&CommittedGroup<NativeField>],
    points: &[&[NativeField]],
    values: &[Vec<NativeField>],
    transcript_index: usize,
    selection: OpeningScheduleSelection,
) -> Result<(), PcsBatchGateError> {
    if commitments.len() != points.len() || points.len() != values.len() {
        return Err(PcsBatchGateError::Shape);
    }
    let claims = commitments
        .iter()
        .zip(points)
        .zip(values)
        .map(|((commitment, point), values)| {
            PolynomialGroupClaims::new(point.to_vec(), values.clone(), *commitment)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let statement = GroupBatchStatement::new(selection, OpeningClaims::from_groups(claims)?)?;
    let mut transcript = transcript(
        mode,
        proof.selection.row_digest.as_bytes(),
        transcript_index,
        false,
    )?;
    scheme.batched_verify(
        &proof.proof,
        &context.verifier_setup,
        &mut transcript,
        statement,
        BasisMode::Lagrange,
    )?;
    Ok(())
}

fn verify_tamper_matrix(
    scheme: &AkitaCommitmentScheme<Config>,
    context: &GateContext,
    committed: &CommittedGateColumns,
    point: &[NativeField],
    proofs: &[GateProof],
) -> Result<PcsBatchTamperReport, PcsBatchGateError> {
    let proof = proofs.first().ok_or(PcsBatchGateError::Shape)?;
    let first = committed
        .commitments
        .first()
        .ok_or(PcsBatchGateError::Shape)?;
    let second = committed
        .commitments
        .last()
        .ok_or(PcsBatchGateError::Shape)?;
    let fixture = TamperFixture {
        scheme,
        context,
        proof,
        first,
        second,
        point,
    };
    let report = PcsBatchTamperReport {
        swapped_groups_rejected: rejects_swapped_groups(&fixture),
        changed_commitment_rejected: rejects_changed_commitment(&fixture),
        changed_value_rejected: rejects_changed_value(&fixture)?,
        changed_point_rejected: rejects_changed_point(&fixture)?,
        changed_schedule_rejected: rejects_changed_schedule(&fixture)?,
    };
    if !report.all_rejected() {
        return Err(PcsBatchGateError::TamperAccepted(
            "required negative matrix",
        ));
    }
    Ok(report)
}

struct TamperFixture<'a> {
    scheme: &'a AkitaCommitmentScheme<Config>,
    context: &'a GateContext,
    proof: &'a GateProof,
    first: &'a CommittedGroup<NativeField>,
    second: &'a CommittedGroup<NativeField>,
    point: &'a [NativeField],
}

fn rejects_swapped_groups(fixture: &TamperFixture<'_>) -> bool {
    let commitments = [fixture.second, fixture.first];
    let points = [fixture.point, fixture.point];
    let values = fixture
        .proof
        .opened_values
        .iter()
        .rev()
        .cloned()
        .collect::<Vec<_>>();
    verify_tampered(
        fixture,
        &commitments,
        &points,
        &values,
        fixture.proof.selection,
    )
}

fn rejects_changed_commitment(fixture: &TamperFixture<'_>) -> bool {
    let commitments = [fixture.second, fixture.second];
    let points = [fixture.point, fixture.point];
    verify_tampered(
        fixture,
        &commitments,
        &points,
        &fixture.proof.opened_values,
        fixture.proof.selection,
    )
}

fn rejects_changed_value(fixture: &TamperFixture<'_>) -> Result<bool, PcsBatchGateError> {
    let mut values = fixture.proof.opened_values.clone();
    let changed = values
        .first_mut()
        .and_then(|group| group.first_mut())
        .ok_or(PcsBatchGateError::Shape)?;
    *changed += NativeField::from_u64(1);
    let commitments = [fixture.first, fixture.second];
    let points = [fixture.point, fixture.point];
    Ok(verify_tampered(
        fixture,
        &commitments,
        &points,
        &values,
        fixture.proof.selection,
    ))
}

fn rejects_changed_point(fixture: &TamperFixture<'_>) -> Result<bool, PcsBatchGateError> {
    let mut point = fixture.point.to_vec();
    let coordinate = point.first_mut().ok_or(PcsBatchGateError::Shape)?;
    *coordinate += NativeField::from_u64(1);
    let commitments = [fixture.first, fixture.second];
    let points = [point.as_slice(), fixture.point];
    Ok(verify_tampered(
        fixture,
        &commitments,
        &points,
        &fixture.proof.opened_values,
        fixture.proof.selection,
    ))
}

fn rejects_changed_schedule(fixture: &TamperFixture<'_>) -> Result<bool, PcsBatchGateError> {
    let mut bytes = *fixture.proof.selection.row_digest.as_bytes();
    let first = bytes.first_mut().ok_or(PcsBatchGateError::Shape)?;
    *first ^= 1;
    let selection = OpeningScheduleSelection {
        row_digest: ScheduleRowDigest::from_bytes(bytes),
    };
    let commitments = [fixture.first, fixture.second];
    let points = [fixture.point, fixture.point];
    Ok(verify_tampered(
        fixture,
        &commitments,
        &points,
        &fixture.proof.opened_values,
        selection,
    ))
}

fn verify_tampered(
    fixture: &TamperFixture<'_>,
    commitments: &[&CommittedGroup<NativeField>],
    points: &[&[NativeField]],
    values: &[Vec<NativeField>],
    selection: OpeningScheduleSelection,
) -> bool {
    verify_claims(
        PcsBatchGateMode::Batched,
        fixture.scheme,
        fixture.context,
        fixture.proof,
        commitments,
        points,
        values,
        0,
        selection,
    )
    .is_err()
}

fn transcript(
    mode: PcsBatchGateMode,
    schedule_digest: &[u8; 32],
    transcript_index: usize,
    prover: bool,
) -> Result<AkitaTranscript<NativeField>, PcsBatchGateError> {
    let mut instance = Vec::new();
    instance.extend_from_slice(INSTANCE_DOMAIN);
    instance.extend_from_slice(schedule_digest);
    instance.extend_from_slice(
        &u64::try_from(transcript_index)
            .map_err(|_| PcsBatchGateError::Shape)?
            .to_le_bytes(),
    );
    let mut transcript = if prover {
        AkitaTranscript::unbound_prover(mode.transcript_domain())
    } else {
        AkitaTranscript::unbound_verifier(mode.transcript_domain())
    };
    transcript.bind_instance_bytes(&instance);
    Ok(transcript)
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::{PcsBatchGateMode, PcsBatchTamperReport, deterministic_columns};

    #[test]
    fn deterministic_fixture_has_exact_two_group_shape() {
        let groups = deterministic_columns();
        assert_eq!(groups.len(), 2);
        assert!(groups.iter().all(|group| group.len() == 128));
        assert!(groups.iter().flatten().all(|column| column.len() == 512));
    }

    #[test]
    fn tamper_report_requires_every_rejection() {
        let complete = PcsBatchTamperReport {
            swapped_groups_rejected: true,
            changed_commitment_rejected: true,
            changed_value_rejected: true,
            changed_point_rejected: true,
            changed_schedule_rejected: true,
        };
        assert!(complete.all_rejected());
        assert!(
            !PcsBatchTamperReport {
                changed_point_rejected: false,
                ..complete
            }
            .all_rejected()
        );
        assert_ne!(PcsBatchGateMode::Independent, PcsBatchGateMode::Batched);
    }
}
