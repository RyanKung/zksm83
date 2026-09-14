//! Ordered mutable-memory proof over the fixed 128-KiB checkpoint table.

mod block_event;
pub(crate) mod boundary;
pub(crate) mod clock;
pub(crate) mod sum;
#[cfg(test)]
mod tests;

use akita_pcs::{AkitaTranscript, Ring, Transcript};
use jolt_field::CanonicalBytes;
use thiserror::Error;

use crate::{
    AKITA_MEMORY_SCHEDULE_SHA256, AkitaWorkerError, BLOCK_CPU_COLUMN_COUNT, BlockCpuWitness,
    NativeField, NativeProtocolVersion, TRACE_MEMORY_TIMESTAMP_BITS, UniformError,
    WitnessCommitments,
    block_memory::BLOCK_MEMORY_ROW_BITS_START,
    pcs::{ColumnCommitments, CommittedColumns, PcsError, PcsLayout, commit_columns},
    sumcheck::ProductSumcheckError,
    uniform::{
        CommittedWitness, CompositeUniformRelationProof, ProjectedRelation,
        prove_uniform_composite, verify_uniform_composite_for_protocol,
    },
};

/// Number of address variables in the frozen mutable-memory table.
pub const MEMORY_TABLE_NUM_VARIABLES: usize = TRACE_MEMORY_TIMESTAMP_BITS;
/// Number of committed mutable bytes, including four physical MBC3 SRAM banks.
pub const MEMORY_IMAGE_BYTES: usize = 1 << MEMORY_TABLE_NUM_VARIABLES;

const MEMORY_SCHEDULE_FILE: &[u8] =
    include_bytes!("../protocol/akita/fp128_dense_bounded_nv17_p1.aks");
const MEMORY_SCHEDULE_ARTIFACT: &[u8] = MEMORY_SCHEDULE_FILE
    .split_at(MEMORY_SCHEDULE_FILE.len() - 1)
    .0;
const MEMORY_LAYOUT: PcsLayout = PcsLayout::new(
    MEMORY_TABLE_NUM_VARIABLES,
    1,
    MEMORY_SCHEDULE_ARTIFACT,
    b"zksm83/native-memory-column/v1",
    b"zksm83-native-memory-opening/v1",
);
const CHALLENGE_DOMAIN: &[u8] = b"zksm83-native-memory-challenges/v1";
const PACKED_TRACE_DOMAIN: &[u8] = b"zksm83/native-packed-memory-trace/v2";

/// Prover-owned mutable-memory image and its verifier-visible commitment.
pub struct CommittedMemory {
    inner: CommittedColumns,
    commitment: MemoryCommitment,
}

/// Verifier-visible Akita commitment to one exact 128-KiB memory image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryCommitment {
    pub(crate) inner: ColumnCommitments,
}

struct CommittedMemoryColumns {
    inner: CommittedColumns,
}

/// Transparent packed-block proof of the same mutable-memory boundary law.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackedMutableMemoryProof {
    pub(crate) final_timestamps: ColumnCommitments,
    pub(crate) trace_inverses: WitnessCommitments,
    pub(crate) initial_inverses: ColumnCommitments,
    pub(crate) final_inverses: ColumnCommitments,
    pub(crate) event_relation: CompositeUniformRelationProof,
    pub(crate) clock: clock::ClockProof,
    pub(crate) boundary: boundary::BoundaryProof,
    pub(crate) multiset_sum: sum::MultisetSumProof,
}

pub(crate) struct PreparedPackedMutableMemory {
    final_timestamps: CommittedMemoryColumns,
    trace_inverses: CommittedWitness,
    initial_inverses: CommittedMemoryColumns,
    final_inverses: CommittedMemoryColumns,
    phase_one: Vec<u8>,
    challenges: MemoryChallenges,
}

/// Invalid mutable-memory image, ordered trace, proof, or backend operation.
#[derive(Debug, Error)]
pub enum MutableMemoryError {
    /// A memory image is not the fixed 128-KiB checkpoint length.
    #[error("mutable-memory image has {actual} bytes, expected {expected}")]
    InvalidMemoryLength {
        /// Supplied byte length.
        actual: usize,
        /// Required byte length.
        expected: usize,
    },
    /// A proof vector, commitment, or column layout is malformed.
    #[error("native mutable-memory proof shape is invalid")]
    Shape,
    /// Tuple compression produced a zero denominator and must be retried in a new statement.
    #[error("native mutable-memory inverse denominator is zero")]
    ZeroDenominator,
    /// A required Fiat-Shamir mixing challenge was zero.
    #[error("native mutable-memory Fiat-Shamir challenge is zero")]
    ZeroChallenge,
    /// Boundary inverse identities or the global multiset equality do not hold.
    #[error("native mutable-memory relation is unsatisfied")]
    Unsatisfied,
    /// A sumcheck transcript was rejected.
    #[error("native mutable-memory sumcheck failed")]
    Sumcheck,
    /// Shared trace relation or opening verification failed.
    #[error(transparent)]
    Uniform(#[from] UniformError),
    /// Akita rejected a memory commitment or opening.
    #[error("native mutable-memory Akita operation failed: {0}")]
    Pcs(String),
    /// The operating system rejected creation of the bounded proof worker.
    #[error("failed to start native mutable-memory worker: {0}")]
    WorkerSpawn(#[source] std::io::Error),
    /// The bounded proof worker panicked and its result was rejected.
    #[error("native mutable-memory worker terminated unexpectedly")]
    WorkerPanicked,
}

#[derive(Clone, Copy)]
struct MemoryChallenges {
    alpha: NativeField,
    beta: NativeField,
}

impl From<PcsError> for MutableMemoryError {
    fn from(error: PcsError) -> Self {
        Self::Pcs(error.to_string())
    }
}

impl From<ProductSumcheckError> for MutableMemoryError {
    fn from(_: ProductSumcheckError) -> Self {
        Self::Sumcheck
    }
}

impl CommittedMemory {
    /// Returns the verifier-visible commitment to this exact image.
    #[must_use]
    pub const fn commitment(&self) -> &MemoryCommitment {
        &self.commitment
    }
}

impl MemoryCommitment {
    /// Returns the canonical protocol encoding of this memory commitment.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MutableMemoryError> {
        self.inner
            .canonical_bytes(MEMORY_LAYOUT)
            .map_err(Into::into)
    }

    /// Returns SHA-256 of the canonical memory commitment encoding.
    pub fn digest(&self) -> Result<[u8; 32], MutableMemoryError> {
        self.inner.digest(MEMORY_LAYOUT).map_err(Into::into)
    }

    fn validate(&self) -> Result<(), MutableMemoryError> {
        self.inner.validate(MEMORY_LAYOUT).map_err(Into::into)
    }
}

/// Commits one exact 128-KiB mutable-memory checkpoint image.
pub fn commit_memory(image: &[u8]) -> Result<CommittedMemory, MutableMemoryError> {
    if image.len() != MEMORY_IMAGE_BYTES {
        return Err(MutableMemoryError::InvalidMemoryLength {
            actual: image.len(),
            expected: MEMORY_IMAGE_BYTES,
        });
    }
    let column = image.iter().copied().map(u64::from).collect::<Vec<_>>();
    on_worker(|| {
        let inner = commit_columns(MEMORY_LAYOUT, &[column])?;
        let commitment = MemoryCommitment {
            inner: inner.commitments().clone(),
        };
        Ok(CommittedMemory { inner, commitment })
    })
}

/// Proves packed-block latest-value ordering and exact memory boundaries.
pub fn prove_packed_mutable_memory(
    trace: &BlockCpuWitness,
    trace_witness: &CommittedWitness,
    initial: &CommittedMemory,
    final_memory: &CommittedMemory,
) -> Result<PackedMutableMemoryProof, MutableMemoryError> {
    let prepared = prepare_packed_mutable_memory(trace, trace_witness, initial, final_memory)?;
    prove_prepared_packed_mutable_memory(prepared, trace_witness, initial, final_memory)
}

pub(crate) fn prepare_packed_mutable_memory(
    trace: &BlockCpuWitness,
    trace_witness: &CommittedWitness,
    initial: &CommittedMemory,
    final_memory: &CommittedMemory,
) -> Result<PreparedPackedMutableMemory, MutableMemoryError> {
    let protocol = NativeProtocolVersion::current();
    if trace.columns().len() != BLOCK_CPU_COLUMN_COUNT {
        return Err(MutableMemoryError::Shape);
    }
    initial.commitment.validate()?;
    final_memory.commitment.validate()?;
    let final_timestamps = commit_u64_column(trace.final_memory_timestamps())?;
    let phase_one = phase_one_descriptor(
        protocol,
        trace_witness.commitments(),
        &initial.commitment,
        &final_memory.commitment,
        final_timestamps.commitments(),
    )?;
    let challenges = challenges(&phase_one)?;
    let trace_inverse_columns = block_event::inverse_columns(trace, challenges)?;
    let trace_inverses = crate::commit_witness(&trace_inverse_columns)?;
    let (initial_inverse_values, final_inverse_values) =
        boundary::inverse_columns(initial, final_memory, &final_timestamps, challenges)?;
    let initial_inverses = commit_u64_columns(&initial_inverse_values)?;
    let final_inverses = commit_u64_columns(&final_inverse_values)?;
    Ok(PreparedPackedMutableMemory {
        final_timestamps,
        trace_inverses,
        initial_inverses,
        final_inverses,
        phase_one,
        challenges,
    })
}

pub(crate) fn prove_prepared_packed_mutable_memory(
    prepared: PreparedPackedMutableMemory,
    trace_witness: &CommittedWitness,
    initial: &CommittedMemory,
    final_memory: &CommittedMemory,
) -> Result<PackedMutableMemoryProof, MutableMemoryError> {
    let protocol = NativeProtocolVersion::current();
    let PreparedPackedMutableMemory {
        final_timestamps,
        trace_inverses,
        initial_inverses,
        final_inverses,
        phase_one,
        challenges,
    } = prepared;
    let relation = ProjectedRelation::new(
        block_event::BlockMemoryEventRelation::new(challenges),
        BLOCK_CPU_COLUMN_COUNT,
        block_event::trace_columns()?,
    )?;
    let event_relation = prove_uniform_composite(&relation, trace_witness, &trace_inverses)?;
    let clock = clock::prove_at(trace_witness, &phase_one, BLOCK_MEMORY_ROW_BITS_START)?;
    let full = full_descriptor(
        protocol,
        &phase_one,
        trace_inverses.commitments(),
        initial_inverses.commitments(),
        final_inverses.commitments(),
    )?;
    let boundary = boundary::prove(
        initial,
        final_memory,
        &final_timestamps,
        &initial_inverses,
        &final_inverses,
        challenges,
        &full,
    )?;
    let multiset_sum = sum::prove(&trace_inverses, &initial_inverses, &final_inverses, &full)?;
    Ok(PackedMutableMemoryProof {
        final_timestamps: final_timestamps.into_commitments(),
        trace_inverses: trace_inverses.into_commitments(),
        initial_inverses: initial_inverses.into_commitments(),
        final_inverses: final_inverses.into_commitments(),
        event_relation,
        clock,
        boundary,
        multiset_sum,
    })
}

/// Verifies packed-block mutable-memory consistency without execution replay.
pub fn verify_packed_mutable_memory(
    proof: &PackedMutableMemoryProof,
    trace: &WitnessCommitments,
    initial: &MemoryCommitment,
    final_memory: &MemoryCommitment,
) -> Result<(), MutableMemoryError> {
    verify_packed_mutable_memory_for_protocol(
        NativeProtocolVersion::current(),
        proof,
        trace,
        initial,
        final_memory,
    )
}

pub(crate) fn verify_packed_mutable_memory_for_protocol(
    protocol: NativeProtocolVersion,
    proof: &PackedMutableMemoryProof,
    trace: &WitnessCommitments,
    initial: &MemoryCommitment,
    final_memory: &MemoryCommitment,
) -> Result<(), MutableMemoryError> {
    initial.validate()?;
    final_memory.validate()?;
    proof.final_timestamps.validate(MEMORY_LAYOUT)?;
    proof.initial_inverses.validate(MEMORY_LAYOUT)?;
    proof.final_inverses.validate(MEMORY_LAYOUT)?;
    let phase_one = phase_one_descriptor(
        protocol,
        trace,
        initial,
        final_memory,
        &proof.final_timestamps,
    )?;
    let challenges = challenges(&phase_one)?;
    let relation = ProjectedRelation::new(
        block_event::BlockMemoryEventRelation::new(challenges),
        BLOCK_CPU_COLUMN_COUNT,
        block_event::trace_columns()?,
    )?;
    verify_uniform_composite_for_protocol(
        protocol,
        &relation,
        trace,
        &proof.trace_inverses,
        &proof.event_relation,
    )?;
    clock::verify_at(
        protocol,
        trace,
        &phase_one,
        &proof.clock,
        BLOCK_MEMORY_ROW_BITS_START,
    )?;
    let full = full_descriptor(
        protocol,
        &phase_one,
        &proof.trace_inverses,
        &proof.initial_inverses,
        &proof.final_inverses,
    )?;
    boundary::verify(
        initial,
        final_memory,
        &proof.final_timestamps,
        &proof.initial_inverses,
        &proof.final_inverses,
        challenges,
        &full,
        &proof.boundary,
    )?;
    sum::verify(
        protocol,
        &proof.trace_inverses,
        &proof.initial_inverses,
        &proof.final_inverses,
        &full,
        &proof.multiset_sum,
    )
}

impl CommittedMemoryColumns {
    fn commitments(&self) -> &ColumnCommitments {
        self.inner.commitments()
    }

    fn into_commitments(self) -> ColumnCommitments {
        self.inner.commitments().clone()
    }
}

fn commit_u64_columns(values: &[Vec<u64>]) -> Result<CommittedMemoryColumns, MutableMemoryError> {
    if values.is_empty()
        || values
            .iter()
            .any(|column| column.len() != MEMORY_IMAGE_BYTES)
    {
        return Err(MutableMemoryError::Shape);
    }
    on_worker(|| {
        Ok(CommittedMemoryColumns {
            inner: commit_columns(MEMORY_LAYOUT, values)?,
        })
    })
}

fn commit_u64_column(value: &[u64]) -> Result<CommittedMemoryColumns, MutableMemoryError> {
    if value.len() != MEMORY_IMAGE_BYTES {
        return Err(MutableMemoryError::Shape);
    }
    on_worker(|| {
        Ok(CommittedMemoryColumns {
            inner: commit_columns(MEMORY_LAYOUT, &[value])?,
        })
    })
}

fn phase_one_descriptor(
    protocol: NativeProtocolVersion,
    trace: &WitnessCommitments,
    initial: &MemoryCommitment,
    final_memory: &MemoryCommitment,
    timestamps: &ColumnCommitments,
) -> Result<Vec<u8>, MutableMemoryError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, protocol.protocol_id().as_bytes())?;
    push_bytes(&mut descriptor, AKITA_MEMORY_SCHEDULE_SHA256.as_bytes())?;
    push_bytes(&mut descriptor, PACKED_TRACE_DOMAIN)?;
    push_bytes(&mut descriptor, &trace.canonical_bytes_for(protocol)?)?;
    push_bytes(&mut descriptor, &initial.canonical_bytes()?)?;
    push_bytes(&mut descriptor, &final_memory.canonical_bytes()?)?;
    push_bytes(&mut descriptor, &timestamps.canonical_bytes(MEMORY_LAYOUT)?)?;
    Ok(descriptor)
}

fn full_descriptor(
    protocol: NativeProtocolVersion,
    phase_one: &[u8],
    trace_inverses: &WitnessCommitments,
    initial_inverses: &ColumnCommitments,
    final_inverses: &ColumnCommitments,
) -> Result<Vec<u8>, MutableMemoryError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, phase_one)?;
    push_bytes(
        &mut descriptor,
        &trace_inverses.canonical_bytes_for(protocol)?,
    )?;
    push_bytes(
        &mut descriptor,
        &initial_inverses.canonical_bytes(MEMORY_LAYOUT)?,
    )?;
    push_bytes(
        &mut descriptor,
        &final_inverses.canonical_bytes(MEMORY_LAYOUT)?,
    )?;
    Ok(descriptor)
}

fn challenges(descriptor: &[u8]) -> Result<MemoryChallenges, MutableMemoryError> {
    let mut transcript = AkitaTranscript::<NativeField>::unbound_verifier(CHALLENGE_DOMAIN);
    transcript.bind_instance_bytes(descriptor);
    let alpha = transcript.challenge_scalar(b"memory-tuple-alpha");
    if alpha == NativeField::from_u64(0) {
        return Err(MutableMemoryError::ZeroChallenge);
    }
    let beta = transcript.challenge_scalar(b"memory-log-derivative-beta");
    Ok(MemoryChallenges { alpha, beta })
}

fn split_field(value: NativeField) -> Result<[u64; 2], MutableMemoryError> {
    let bytes = value.to_bytes_le_vec();
    let low = <[u8; 8]>::try_from(bytes.get(..8).ok_or(MutableMemoryError::Shape)?)
        .map_err(|_| MutableMemoryError::Shape)?;
    let high = <[u8; 8]>::try_from(bytes.get(8..16).ok_or(MutableMemoryError::Shape)?)
        .map_err(|_| MutableMemoryError::Shape)?;
    Ok([u64::from_le_bytes(low), u64::from_le_bytes(high)])
}

fn join_limbs(low: NativeField, high: NativeField) -> NativeField {
    low + two_to_64() * high
}

fn two_to_64() -> NativeField {
    NativeField::from_u64(u64::MAX) + NativeField::from_u64(1)
}

fn address_evaluation(point: &[NativeField]) -> Result<NativeField, MutableMemoryError> {
    if point.len() != MEMORY_TABLE_NUM_VARIABLES {
        return Err(MutableMemoryError::Shape);
    }
    let mut power = NativeField::from_u64(1);
    let mut value = NativeField::from_u64(0);
    for coordinate in point {
        value += power * *coordinate;
        power += power;
    }
    Ok(value)
}

fn equality_evaluation(
    left: &[NativeField],
    right: &[NativeField],
) -> Result<NativeField, MutableMemoryError> {
    if left.len() != right.len() {
        return Err(MutableMemoryError::Shape);
    }
    let one = NativeField::from_u64(1);
    Ok(left.iter().zip(right).fold(one, |product, (left, right)| {
        product * (*left * *right + (one - *left) * (one - *right))
    }))
}

fn equality_evaluations(point: &[NativeField]) -> Vec<NativeField> {
    let one = NativeField::from_u64(1);
    let mut values = vec![one];
    for coordinate in point {
        let complement = one - *coordinate;
        let mut next = Vec::with_capacity(values.len().saturating_mul(2));
        next.extend(values.iter().map(|value| *value * complement));
        next.extend(values.iter().map(|value| *value * *coordinate));
        values = next;
    }
    values
}

fn evaluate_field_column(
    values: &[NativeField],
    point: &[NativeField],
) -> Result<NativeField, MutableMemoryError> {
    crate::field_fold::evaluate_mle(values, point).map_err(|_| MutableMemoryError::Shape)
}

fn push_bytes(target: &mut Vec<u8>, value: &[u8]) -> Result<(), MutableMemoryError> {
    let length = u64::try_from(value.len()).map_err(|_| MutableMemoryError::Shape)?;
    target.extend_from_slice(&length.to_le_bytes());
    target.extend_from_slice(value);
    Ok(())
}

fn transcript(domain: &'static [u8], descriptor: &[u8]) -> AkitaTranscript<NativeField> {
    let mut transcript = AkitaTranscript::<NativeField>::unbound_verifier(domain);
    transcript.bind_instance_bytes(descriptor);
    transcript
}

fn field_bytes(value: NativeField) -> Vec<u8> {
    value.to_bytes_le_vec()
}

fn on_worker<T: Send>(
    operation: impl FnOnce() -> Result<T, MutableMemoryError> + Send,
) -> Result<T, MutableMemoryError> {
    match crate::on_akita_worker(operation) {
        Ok(result) => result,
        Err(AkitaWorkerError::Spawn(error)) => Err(MutableMemoryError::WorkerSpawn(error)),
        Err(AkitaWorkerError::Panicked) => Err(MutableMemoryError::WorkerPanicked),
    }
}
