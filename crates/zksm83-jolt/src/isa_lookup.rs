//! PCS-bound Shout lookup for the verifier-fixed SM83 ISA table.

use akita_pcs::{AkitaTranscript, Ring, Transcript};
use thiserror::Error;

use crate::{
    AKITA_ISA_TABLE_SCHEDULE_SHA256, AkitaWorkerError, COMMITMENT_GROUP_COLUMNS, ISA_OUTPUT_COUNT,
    ISA_TABLE_ROW_COUNT, IsaTableError, NativeField, NativeProtocolVersion, UNIFORM_NUM_VARIABLES,
    UniformError, fixed_isa_table, fixed_isa_table_digest,
    pcs::{
        ColumnCommitments, CommittedColumns, OpeningProof, PcsError, PcsLayout, commit_columns,
        prove_opening, verify_opening,
    },
    sumcheck::{MultiProductSumcheckProof, ProductSumcheckError, ProductSumcheckProof},
    uniform::{
        CommittedWitness, WitnessCommitments, prove_witness_opening,
        verify_witness_opening_for_protocol,
    },
};

/// Number of least-significant-bit-first address columns consumed by ISA lookup.
pub const ISA_ADDRESS_BIT_COUNT: usize = 9;

/// SHA-256 of the canonical Akita commitment to all fixed ISA output columns.
pub const FIXED_ISA_TABLE_COMMITMENT_SHA256: &str =
    "fc4afaeb9c3d6a7dc063e2927caee773ae4a29f3c16e7d3f1aa5f266ea3f9c9a";

const ISA_TABLE_NUM_VARIABLES: usize = 9;
const ISA_LOOKUP_TRANSCRIPT_DOMAIN_V2: &[u8] = b"zksm83-native-isa-shout/v2";
const ISA_TABLE_COMMITMENT_DOMAIN: &[u8] = b"zksm83/native-isa-table-commitment/v1";
const ISA_TABLE_OPENING_DOMAIN: &[u8] = b"zksm83-native-isa-table-opening/v1";
const ISA_SCHEDULE_ARTIFACT: &[u8] =
    include_bytes!("../protocol/akita/fp128_dense_bounded_nv9_p128.aks");
const ISA_TABLE_LAYOUT: PcsLayout = PcsLayout::new(
    ISA_TABLE_NUM_VARIABLES,
    COMMITMENT_GROUP_COLUMNS,
    ISA_SCHEDULE_ARTIFACT,
    ISA_TABLE_COMMITMENT_DOMAIN,
    ISA_TABLE_OPENING_DOMAIN,
);

/// Canonical positions of ISA address bits and lookup outputs in shared trace columns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IsaLookupColumns {
    address_bits: [usize; ISA_ADDRESS_BIT_COUNT],
    outputs: [usize; ISA_OUTPUT_COUNT],
}

/// Verifier-visible commitment to all 49 fixed ISA table outputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedIsaCommitments {
    pub(crate) inner: ColumnCommitments,
}

/// Shout proof that committed trace outputs equal the fixed table at committed addresses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IsaLookupProof {
    pub(crate) table_commitments: FixedIsaCommitments,
    pub(crate) claimed_output: NativeField,
    pub(crate) table_sumcheck: ProductSumcheckProof,
    pub(crate) address_sumcheck: MultiProductSumcheckProof,
    pub(crate) table_values: Vec<NativeField>,
    pub(crate) trace_cycle_values: Vec<NativeField>,
    pub(crate) trace_address_values: Vec<NativeField>,
    pub(crate) table_opening: OpeningProof,
    pub(crate) trace_cycle_opening: OpeningProof,
    pub(crate) trace_address_opening: OpeningProof,
}

/// Invalid ISA lookup layout, witness, proof, or backend operation.
#[derive(Debug, Error)]
pub enum IsaLookupError {
    /// Address and output columns are out of range or overlap.
    #[error("native ISA lookup column layout is invalid")]
    InvalidColumnLayout,
    /// A trace address column contains a value other than zero or one.
    #[error("native ISA lookup address column is not Boolean")]
    NonBooleanAddress,
    /// A reconstructed address exceeds the fixed 512-row ISA table.
    #[error("native ISA lookup address exceeds the fixed table")]
    AddressOutOfRange,
    /// Proof vectors or commitment dimensions are malformed.
    #[error("native ISA lookup proof shape is invalid")]
    Shape,
    /// The proof table commitment is not the commitment of the fixed ISA table.
    #[error("native ISA lookup table commitment is not canonical")]
    TableCommitmentMismatch,
    /// The table inner product does not equal the committed trace output opening.
    #[error("native ISA lookup output claim is inconsistent")]
    OutputClaimMismatch,
    /// The table opening does not match the reduced table sumcheck terminal.
    #[error("native ISA lookup table opening is inconsistent")]
    TableOpeningMismatch,
    /// The address-bit opening does not match the reduced address sumcheck terminal.
    #[error("native ISA lookup address binding is inconsistent")]
    AddressBindingMismatch,
    /// A required Fiat-Shamir challenge was zero.
    #[error("native ISA lookup Fiat-Shamir challenge is zero")]
    ZeroChallenge,
    /// Construction of the canonical SM83 ISA table failed.
    #[error(transparent)]
    IsaTable(#[from] IsaTableError),
    /// A native-field product sumcheck failed.
    #[error("native ISA lookup sumcheck failed")]
    Sumcheck,
    /// An Akita commitment or opening operation failed.
    #[error("native ISA lookup Akita operation failed")]
    Pcs,
    /// A shared-witness opening operation failed.
    #[error("native ISA lookup shared witness opening failed: {0}")]
    SharedOpening(#[from] UniformError),
    /// The operating system rejected creation of the bounded proof worker.
    #[error("failed to start native ISA lookup worker: {0}")]
    WorkerSpawn(#[source] std::io::Error),
    /// The bounded proof worker panicked and its result was rejected.
    #[error("native ISA lookup worker terminated unexpectedly")]
    WorkerPanicked,
}

impl From<ProductSumcheckError> for IsaLookupError {
    fn from(_: ProductSumcheckError) -> Self {
        Self::Sumcheck
    }
}

impl From<PcsError> for IsaLookupError {
    fn from(_: PcsError) -> Self {
        Self::Pcs
    }
}

impl IsaLookupColumns {
    /// Creates a layout with address bits in least-significant-bit-first order.
    pub fn new(
        address_bits: [usize; ISA_ADDRESS_BIT_COUNT],
        outputs: [usize; ISA_OUTPUT_COUNT],
    ) -> Result<Self, IsaLookupError> {
        let layout = Self {
            address_bits,
            outputs,
        };
        layout.validate(usize::MAX)?;
        Ok(layout)
    }

    /// Returns least-significant-bit-first trace address columns.
    #[must_use]
    pub const fn address_bits(self) -> [usize; ISA_ADDRESS_BIT_COUNT] {
        self.address_bits
    }

    /// Returns trace columns containing all fixed-table outputs in canonical order.
    #[must_use]
    pub const fn outputs(self) -> [usize; ISA_OUTPUT_COUNT] {
        self.outputs
    }

    fn validate(self, column_count: usize) -> Result<(), IsaLookupError> {
        let mut indices = Vec::with_capacity(ISA_ADDRESS_BIT_COUNT + ISA_OUTPUT_COUNT);
        indices.extend_from_slice(&self.address_bits);
        indices.extend_from_slice(&self.outputs);
        indices.sort_unstable();
        if indices.iter().any(|index| *index >= column_count)
            || indices
                .windows(2)
                .any(|pair| matches!(pair, [left, right] if left == right))
        {
            return Err(IsaLookupError::InvalidColumnLayout);
        }
        Ok(())
    }
}

impl FixedIsaCommitments {
    /// Returns the canonical verifier-facing commitment encoding.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IsaLookupError> {
        self.inner
            .canonical_bytes(ISA_TABLE_LAYOUT)
            .map_err(Into::into)
    }

    /// Returns SHA-256 of the canonical fixed-table commitment encoding.
    pub fn digest(&self) -> Result<[u8; 32], IsaLookupError> {
        self.inner.digest(ISA_TABLE_LAYOUT).map_err(Into::into)
    }
}

impl IsaLookupProof {
    /// Returns the fixed-table commitment carried by this proof.
    #[must_use]
    pub const fn table_commitments(&self) -> &FixedIsaCommitments {
        &self.table_commitments
    }
}

/// Proves all 49 fixed-ISA outputs against one shared trace commitment plane.
pub fn prove_isa_lookup(
    layout: IsaLookupColumns,
    witness: &CommittedWitness,
) -> Result<IsaLookupProof, IsaLookupError> {
    on_worker(|| prove_isa_lookup_on_worker(layout, witness))
}

/// Verifies an ISA lookup without receiving trace addresses or output columns.
pub fn verify_isa_lookup(
    layout: IsaLookupColumns,
    trace_commitments: &WitnessCommitments,
    proof: &IsaLookupProof,
) -> Result<(), IsaLookupError> {
    verify_isa_lookup_for_protocol(
        NativeProtocolVersion::current(),
        layout,
        trace_commitments,
        proof,
    )
}

pub(crate) fn verify_isa_lookup_for_protocol(
    protocol: NativeProtocolVersion,
    layout: IsaLookupColumns,
    trace_commitments: &WitnessCommitments,
    proof: &IsaLookupProof,
) -> Result<(), IsaLookupError> {
    on_worker(|| verify_isa_lookup_on_worker(protocol, layout, trace_commitments, proof))
}

fn prove_isa_lookup_on_worker(
    layout: IsaLookupColumns,
    witness: &CommittedWitness,
) -> Result<IsaLookupProof, IsaLookupError> {
    layout.validate(witness.commitments().column_count())?;
    let table = commit_fixed_table()?;
    let table_commitments = FixedIsaCommitments {
        inner: table.commitments().clone(),
    };
    let protocol = NativeProtocolVersion::current();
    let descriptor =
        instance_descriptor(protocol, layout, &table_commitments, witness.commitments())?;
    let mut transcript = lookup_transcript(protocol, &descriptor, TranscriptSide::Prover);
    let output_mix = nonzero_challenge(&mut transcript, b"isa-output-mix")?;
    let coefficients = challenge_powers(output_mix, ISA_OUTPUT_COUNT);
    let cycle_point = sample_point(&mut transcript, UNIFORM_NUM_VARIABLES, b"isa-cycle-point");
    let table_columns = table.field_columns()?;
    let trace_columns = witness.field_columns()?;
    let mixed_table = mix_columns(
        table_columns.as_slice(),
        &canonical_indices(),
        &coefficients,
    )?;
    let mixed_trace = mix_columns(trace_columns.as_slice(), &layout.outputs, &coefficients)?;
    let claimed_output = evaluate_mle(&mixed_trace, &cycle_point)?;
    transcript.append_field(b"isa-claimed-output", &claimed_output);
    let addresses = trace_addresses(trace_columns.as_slice(), &layout.address_bits)?;
    let cycle_weights = equality_evaluations(&cycle_point);
    let read_address = read_address_table(&addresses, &cycle_weights)?;
    let (table_sumcheck, actual_claim, table_point) =
        ProductSumcheckProof::prove(&read_address, &mixed_table, &mut transcript)?;
    if actual_claim != claimed_output {
        return Err(IsaLookupError::OutputClaimMismatch);
    }
    let table_values = evaluate_columns(table_columns.as_slice(), &table_point)?;
    require_mixed_value(
        &table_values,
        &canonical_indices(),
        &coefficients,
        table_sumcheck.final_right(),
        IsaLookupError::TableOpeningMismatch,
    )?;
    let address_factors = address_binding_factors(
        &cycle_weights,
        trace_columns.as_slice(),
        &layout.address_bits,
        &table_point,
    )?;
    let (address_sumcheck, address_claim, address_point) =
        MultiProductSumcheckProof::prove(&address_factors, &mut transcript)?;
    if address_claim != table_sumcheck.final_left() {
        return Err(IsaLookupError::AddressBindingMismatch);
    }
    let trace_cycle_values = evaluate_columns(trace_columns.as_slice(), &cycle_point)?;
    require_mixed_value(
        &trace_cycle_values,
        &layout.outputs,
        &coefficients,
        claimed_output,
        IsaLookupError::OutputClaimMismatch,
    )?;
    let trace_address_values = evaluate_columns(trace_columns.as_slice(), &address_point)?;
    verify_address_terminal(
        &address_sumcheck,
        &cycle_point,
        &table_point,
        &address_point,
        &trace_address_values,
        &layout.address_bits,
    )?;
    let table_opening = prove_opening(
        ISA_TABLE_LAYOUT,
        &table,
        &table_point,
        &table_values,
        &descriptor,
    )?;
    let trace_cycle_opening =
        prove_witness_opening(witness, &cycle_point, &trace_cycle_values, &descriptor)?;
    let trace_address_opening =
        prove_witness_opening(witness, &address_point, &trace_address_values, &descriptor)?;
    Ok(IsaLookupProof {
        table_commitments,
        claimed_output,
        table_sumcheck,
        address_sumcheck,
        table_values,
        trace_cycle_values,
        trace_address_values,
        table_opening,
        trace_cycle_opening,
        trace_address_opening,
    })
}

fn verify_isa_lookup_on_worker(
    protocol: NativeProtocolVersion,
    layout: IsaLookupColumns,
    trace_commitments: &WitnessCommitments,
    proof: &IsaLookupProof,
) -> Result<(), IsaLookupError> {
    layout.validate(trace_commitments.column_count())?;
    validate_fixed_commitments(&proof.table_commitments)?;
    let descriptor = instance_descriptor(
        protocol,
        layout,
        &proof.table_commitments,
        trace_commitments,
    )?;
    let mut transcript = lookup_transcript(protocol, &descriptor, TranscriptSide::Verifier);
    let output_mix = nonzero_challenge(&mut transcript, b"isa-output-mix")?;
    let coefficients = challenge_powers(output_mix, ISA_OUTPUT_COUNT);
    let cycle_point = sample_point(&mut transcript, UNIFORM_NUM_VARIABLES, b"isa-cycle-point");
    transcript.append_field(b"isa-claimed-output", &proof.claimed_output);
    let table_point = proof.table_sumcheck.verify(
        proof.claimed_output,
        ISA_TABLE_NUM_VARIABLES,
        &mut transcript,
    )?;
    verify_opening(
        ISA_TABLE_LAYOUT,
        &proof.table_commitments.inner,
        &table_point,
        &proof.table_values,
        &descriptor,
        &proof.table_opening,
    )?;
    require_mixed_value(
        &proof.table_values,
        &canonical_indices(),
        &coefficients,
        proof.table_sumcheck.final_right(),
        IsaLookupError::TableOpeningMismatch,
    )?;
    let address_point = proof.address_sumcheck.verify(
        proof.table_sumcheck.final_left(),
        UNIFORM_NUM_VARIABLES,
        ISA_ADDRESS_BIT_COUNT + 1,
        &mut transcript,
    )?;
    verify_witness_opening_for_protocol(
        protocol,
        trace_commitments,
        &cycle_point,
        &proof.trace_cycle_values,
        &descriptor,
        &proof.trace_cycle_opening,
    )?;
    require_mixed_value(
        &proof.trace_cycle_values,
        &layout.outputs,
        &coefficients,
        proof.claimed_output,
        IsaLookupError::OutputClaimMismatch,
    )?;
    verify_witness_opening_for_protocol(
        protocol,
        trace_commitments,
        &address_point,
        &proof.trace_address_values,
        &descriptor,
        &proof.trace_address_opening,
    )?;
    verify_address_terminal(
        &proof.address_sumcheck,
        &cycle_point,
        &table_point,
        &address_point,
        &proof.trace_address_values,
        &layout.address_bits,
    )
}

fn commit_fixed_table() -> Result<CommittedColumns, IsaLookupError> {
    commit_columns(ISA_TABLE_LAYOUT, &fixed_table_columns()?).map_err(Into::into)
}

fn validate_fixed_commitments(commitments: &FixedIsaCommitments) -> Result<(), IsaLookupError> {
    commitments.inner.validate(ISA_TABLE_LAYOUT)?;
    if hex_digest(commitments.digest()?) != FIXED_ISA_TABLE_COMMITMENT_SHA256 {
        return Err(IsaLookupError::TableCommitmentMismatch);
    }
    Ok(())
}

fn hex_digest(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn fixed_table_columns() -> Result<Vec<Vec<u64>>, IsaLookupError> {
    let rows = fixed_isa_table()?;
    let mut columns = (0..ISA_OUTPUT_COUNT)
        .map(|_| Vec::with_capacity(ISA_TABLE_ROW_COUNT))
        .collect::<Vec<_>>();
    for row in rows {
        for (column, value) in columns.iter_mut().zip(row.outputs()) {
            column.push(value);
        }
    }
    if columns
        .iter()
        .any(|column| column.len() != ISA_TABLE_ROW_COUNT)
    {
        return Err(IsaLookupError::Shape);
    }
    Ok(columns)
}

fn trace_addresses(
    columns: &[impl AsRef<[NativeField]>],
    address_bits: &[usize; ISA_ADDRESS_BIT_COUNT],
) -> Result<Vec<usize>, IsaLookupError> {
    let row_count = columns
        .first()
        .map(|column| column.as_ref().len())
        .ok_or(IsaLookupError::Shape)?;
    let zero = NativeField::from_u64(0);
    let one = NativeField::from_u64(1);
    let mut addresses = vec![0_usize; row_count];
    for (bit, column_index) in address_bits.iter().copied().enumerate() {
        let column = columns
            .get(column_index)
            .map(AsRef::as_ref)
            .ok_or(IsaLookupError::Shape)?;
        if column.len() != row_count {
            return Err(IsaLookupError::Shape);
        }
        for (address, value) in addresses.iter_mut().zip(column) {
            if *value != zero && *value != one {
                return Err(IsaLookupError::NonBooleanAddress);
            }
            if *value == one {
                *address = address
                    .checked_add(
                        1_usize
                            .checked_shl(bit as u32)
                            .ok_or(IsaLookupError::AddressOutOfRange)?,
                    )
                    .ok_or(IsaLookupError::AddressOutOfRange)?;
            }
        }
    }
    if addresses
        .iter()
        .any(|address| *address >= ISA_TABLE_ROW_COUNT)
    {
        return Err(IsaLookupError::AddressOutOfRange);
    }
    Ok(addresses)
}

fn read_address_table(
    addresses: &[usize],
    cycle_weights: &[NativeField],
) -> Result<Vec<NativeField>, IsaLookupError> {
    if addresses.len() != cycle_weights.len() {
        return Err(IsaLookupError::Shape);
    }
    let mut read_address = vec![NativeField::from_u64(0); ISA_TABLE_ROW_COUNT];
    for (address, weight) in addresses.iter().copied().zip(cycle_weights) {
        let target = read_address
            .get_mut(address)
            .ok_or(IsaLookupError::AddressOutOfRange)?;
        *target += *weight;
    }
    Ok(read_address)
}

fn address_binding_factors(
    cycle_weights: &[NativeField],
    columns: &[impl AsRef<[NativeField]>],
    address_bits: &[usize; ISA_ADDRESS_BIT_COUNT],
    table_point: &[NativeField],
) -> Result<Vec<Vec<NativeField>>, IsaLookupError> {
    if table_point.len() != ISA_ADDRESS_BIT_COUNT {
        return Err(IsaLookupError::Shape);
    }
    let one = NativeField::from_u64(1);
    let mut factors = Vec::with_capacity(ISA_ADDRESS_BIT_COUNT + 1);
    factors.push(cycle_weights.to_vec());
    for (column_index, point) in address_bits.iter().copied().zip(table_point) {
        let column = columns
            .get(column_index)
            .map(AsRef::as_ref)
            .ok_or(IsaLookupError::Shape)?;
        if column.len() != cycle_weights.len() {
            return Err(IsaLookupError::Shape);
        }
        factors.push(
            column
                .iter()
                .map(|bit| *bit * *point + (one - *bit) * (one - *point))
                .collect(),
        );
    }
    Ok(factors)
}

fn verify_address_terminal(
    proof: &MultiProductSumcheckProof,
    cycle_point: &[NativeField],
    table_point: &[NativeField],
    address_point: &[NativeField],
    trace_values: &[NativeField],
    address_bits: &[usize; ISA_ADDRESS_BIT_COUNT],
) -> Result<(), IsaLookupError> {
    let factors = proof.final_factors();
    if factors.len() != ISA_ADDRESS_BIT_COUNT + 1 || table_point.len() != ISA_ADDRESS_BIT_COUNT {
        return Err(IsaLookupError::Shape);
    }
    let expected_weight = equality_evaluation(cycle_point, address_point)?;
    if factors.first().copied() != Some(expected_weight) {
        return Err(IsaLookupError::AddressBindingMismatch);
    }
    let one = NativeField::from_u64(1);
    for ((factor, column_index), point) in factors.iter().skip(1).zip(address_bits).zip(table_point)
    {
        let bit = trace_values
            .get(*column_index)
            .copied()
            .ok_or(IsaLookupError::Shape)?;
        let expected = bit * *point + (one - bit) * (one - *point);
        if *factor != expected {
            return Err(IsaLookupError::AddressBindingMismatch);
        }
    }
    Ok(())
}

fn instance_descriptor(
    protocol: NativeProtocolVersion,
    layout: IsaLookupColumns,
    table_commitments: &FixedIsaCommitments,
    trace_commitments: &WitnessCommitments,
) -> Result<Vec<u8>, IsaLookupError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, protocol.protocol_id().as_bytes())?;
    push_bytes(&mut descriptor, AKITA_ISA_TABLE_SCHEDULE_SHA256.as_bytes())?;
    push_bytes(&mut descriptor, &fixed_isa_table_digest()?)?;
    push_usize(&mut descriptor, ISA_TABLE_ROW_COUNT)?;
    push_usize(&mut descriptor, ISA_OUTPUT_COUNT)?;
    push_indices(&mut descriptor, &layout.address_bits)?;
    push_indices(&mut descriptor, &layout.outputs)?;
    push_bytes(&mut descriptor, &table_commitments.canonical_bytes()?)?;
    push_bytes(
        &mut descriptor,
        &trace_commitments.canonical_bytes_for(protocol)?,
    )?;
    Ok(descriptor)
}

enum TranscriptSide {
    Prover,
    Verifier,
}

fn lookup_transcript(
    protocol: NativeProtocolVersion,
    descriptor: &[u8],
    side: TranscriptSide,
) -> AkitaTranscript<NativeField> {
    let domain = match protocol {
        NativeProtocolVersion::V2 => ISA_LOOKUP_TRANSCRIPT_DOMAIN_V2,
    };
    let mut transcript = match side {
        TranscriptSide::Prover => AkitaTranscript::unbound_prover(domain),
        TranscriptSide::Verifier => AkitaTranscript::unbound_verifier(domain),
    };
    transcript.bind_instance_bytes(descriptor);
    transcript
}

fn nonzero_challenge(
    transcript: &mut AkitaTranscript<NativeField>,
    label: &[u8],
) -> Result<NativeField, IsaLookupError> {
    let challenge = transcript.challenge_scalar(label);
    if challenge == NativeField::from_u64(0) {
        return Err(IsaLookupError::ZeroChallenge);
    }
    Ok(challenge)
}

fn sample_point(
    transcript: &mut AkitaTranscript<NativeField>,
    count: usize,
    label: &[u8],
) -> Vec<NativeField> {
    (0..count)
        .map(|_| transcript.challenge_scalar(label))
        .collect()
}

fn challenge_powers(challenge: NativeField, count: usize) -> Vec<NativeField> {
    let mut power = NativeField::from_u64(1);
    (0..count)
        .map(|_| {
            let coefficient = power;
            power *= challenge;
            coefficient
        })
        .collect()
}

fn canonical_indices() -> [usize; ISA_OUTPUT_COUNT] {
    std::array::from_fn(|index| index)
}

fn mix_columns(
    columns: &[impl AsRef<[NativeField]>],
    indices: &[usize],
    coefficients: &[NativeField],
) -> Result<Vec<NativeField>, IsaLookupError> {
    if indices.is_empty() || indices.len() != coefficients.len() {
        return Err(IsaLookupError::Shape);
    }
    let row_count = columns
        .first()
        .map(|column| column.as_ref().len())
        .ok_or(IsaLookupError::Shape)?;
    let mut mixed = vec![NativeField::from_u64(0); row_count];
    for (column_index, coefficient) in indices.iter().copied().zip(coefficients) {
        let column = columns
            .get(column_index)
            .map(AsRef::as_ref)
            .ok_or(IsaLookupError::Shape)?;
        if column.len() != row_count {
            return Err(IsaLookupError::Shape);
        }
        for (target, value) in mixed.iter_mut().zip(column) {
            *target += *coefficient * *value;
        }
    }
    Ok(mixed)
}

fn require_mixed_value(
    values: &[NativeField],
    indices: &[usize],
    coefficients: &[NativeField],
    expected: NativeField,
    error: IsaLookupError,
) -> Result<(), IsaLookupError> {
    if indices.len() != coefficients.len() {
        return Err(IsaLookupError::Shape);
    }
    let actual = indices.iter().copied().zip(coefficients).try_fold(
        NativeField::from_u64(0),
        |sum, (index, coefficient)| {
            values
                .get(index)
                .copied()
                .map(|value| sum + *coefficient * value)
                .ok_or(IsaLookupError::Shape)
        },
    )?;
    if actual != expected {
        return Err(error);
    }
    Ok(())
}

fn evaluate_columns(
    columns: &[impl AsRef<[NativeField]>],
    point: &[NativeField],
) -> Result<Vec<NativeField>, IsaLookupError> {
    columns
        .iter()
        .map(|column| evaluate_mle(column.as_ref(), point))
        .collect()
}

fn evaluate_mle(
    evaluations: &[NativeField],
    point: &[NativeField],
) -> Result<NativeField, IsaLookupError> {
    let expected_len = 1_usize
        .checked_shl(u32::try_from(point.len()).map_err(|_| IsaLookupError::Shape)?)
        .ok_or(IsaLookupError::Shape)?;
    if evaluations.len() != expected_len {
        return Err(IsaLookupError::Shape);
    }
    let mut folded = evaluations.to_vec();
    for challenge in point {
        fold(&mut folded, *challenge)?;
    }
    folded.first().copied().ok_or(IsaLookupError::Shape)
}

fn fold(values: &mut Vec<NativeField>, challenge: NativeField) -> Result<(), IsaLookupError> {
    if values.len() <= 1 || !values.len().is_multiple_of(2) {
        return Err(IsaLookupError::Shape);
    }
    crate::field_fold::fold_binary_layer(values, challenge).map_err(|_| IsaLookupError::Shape)
}

fn equality_evaluations(point: &[NativeField]) -> Vec<NativeField> {
    let one = NativeField::from_u64(1);
    let mut evaluations = vec![one];
    for coordinate in point {
        let complement = one - *coordinate;
        let mut next = Vec::with_capacity(evaluations.len().saturating_mul(2));
        next.extend(evaluations.iter().map(|value| *value * complement));
        next.extend(evaluations.iter().map(|value| *value * *coordinate));
        evaluations = next;
    }
    evaluations
}

fn equality_evaluation(
    left: &[NativeField],
    right: &[NativeField],
) -> Result<NativeField, IsaLookupError> {
    if left.len() != right.len() {
        return Err(IsaLookupError::Shape);
    }
    let one = NativeField::from_u64(1);
    Ok(left
        .iter()
        .copied()
        .zip(right.iter().copied())
        .fold(one, |product, (left, right)| {
            product * (left * right + (one - left) * (one - right))
        }))
}

fn push_indices(bytes: &mut Vec<u8>, indices: &[usize]) -> Result<(), IsaLookupError> {
    push_usize(bytes, indices.len())?;
    for index in indices {
        push_usize(bytes, *index)?;
    }
    Ok(())
}

fn push_usize(bytes: &mut Vec<u8>, value: usize) -> Result<(), IsaLookupError> {
    let value = u64::try_from(value).map_err(|_| IsaLookupError::Shape)?;
    bytes.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), IsaLookupError> {
    push_usize(bytes, value.len())?;
    bytes.extend_from_slice(value);
    Ok(())
}

fn on_worker<T: Send>(
    operation: impl FnOnce() -> Result<T, IsaLookupError> + Send,
) -> Result<T, IsaLookupError> {
    match crate::on_akita_worker(operation) {
        Ok(result) => result,
        Err(AkitaWorkerError::Spawn(error)) => Err(IsaLookupError::WorkerSpawn(error)),
        Err(AkitaWorkerError::Panicked) => Err(IsaLookupError::WorkerPanicked),
    }
}

#[cfg(test)]
mod tests {
    use akita_pcs::Ring;
    use sha2::{Digest, Sha256};

    use super::{
        FIXED_ISA_TABLE_COMMITMENT_SHA256, ISA_OUTPUT_COUNT, ISA_SCHEDULE_ARTIFACT,
        ISA_TABLE_LAYOUT, IsaLookupColumns, IsaLookupError, canonical_indices, fixed_table_columns,
        hex_digest, prove_isa_lookup, verify_isa_lookup,
    };
    use crate::{
        AKITA_ISA_TABLE_SCHEDULE_SHA256, ISA_ADDRESS_BIT_COUNT, UNIFORM_ROW_COUNT, commit_witness,
        fixed_isa_table, pcs::scheme,
    };

    #[test]
    fn pinned_isa_schedule_has_only_the_frozen_shape() -> Result<(), IsaLookupError> {
        let scheme = scheme(ISA_TABLE_LAYOUT)?;
        let rows = scheme.schedules().catalog().rows().collect::<Vec<_>>();
        let row = rows.first().ok_or(IsaLookupError::Shape)?;
        assert_eq!(rows.len(), 1);
        assert_eq!(row.profiles().final_group.group.num_vars(), 9);
        assert_eq!(
            row.profiles().final_group.group.num_polynomials(),
            crate::COMMITMENT_GROUP_COLUMNS
        );
        assert!(row.profiles().precommitteds.is_empty());
        assert_eq!(
            format!("{:x}", Sha256::digest(ISA_SCHEDULE_ARTIFACT)),
            AKITA_ISA_TABLE_SCHEDULE_SHA256
        );
        Ok(())
    }

    #[test]
    fn fixed_table_columns_preserve_all_outputs() -> Result<(), IsaLookupError> {
        let columns = fixed_table_columns()?;
        assert_eq!(columns.len(), ISA_OUTPUT_COUNT);
        assert!(columns.iter().all(|column| column.len() == 512));
        Ok(())
    }

    #[test]
    fn overlapping_or_repeated_layout_is_rejected() {
        let address = std::array::from_fn(|index| index);
        let repeated_outputs = [0; ISA_OUTPUT_COUNT];
        assert!(IsaLookupColumns::new(address, repeated_outputs).is_err());
        assert_eq!(canonical_indices().len(), ISA_OUTPUT_COUNT);
    }

    #[test]
    #[ignore = "expensive shared-trace and fixed-table Akita Shout gate"]
    fn committed_isa_lookup_verifies_and_rejects_tampering() -> Result<(), IsaLookupError> {
        let address_bits = std::array::from_fn(|index| index);
        let outputs = std::array::from_fn(|index| ISA_ADDRESS_BIT_COUNT + index);
        let layout = IsaLookupColumns::new(address_bits, outputs)?;
        let table = fixed_isa_table()?;
        let mut columns = (0..(ISA_ADDRESS_BIT_COUNT + ISA_OUTPUT_COUNT))
            .map(|_| vec![0_u64; UNIFORM_ROW_COUNT])
            .collect::<Vec<_>>();
        for row_index in 0..UNIFORM_ROW_COUNT {
            let address = row_index % table.len();
            for (bit, column_index) in address_bits.iter().copied().enumerate() {
                let value = u64::from(((address >> bit) & 1) != 0);
                let column = columns.get_mut(column_index).ok_or(IsaLookupError::Shape)?;
                *column.get_mut(row_index).ok_or(IsaLookupError::Shape)? = value;
            }
            let table_outputs = table
                .get(address)
                .copied()
                .ok_or(IsaLookupError::Shape)?
                .outputs();
            for (column_index, value) in outputs.iter().copied().zip(table_outputs) {
                let column = columns.get_mut(column_index).ok_or(IsaLookupError::Shape)?;
                *column.get_mut(row_index).ok_or(IsaLookupError::Shape)? = value;
            }
        }
        let witness = commit_witness(&columns)?;
        let proof = prove_isa_lookup(layout, &witness)?;
        verify_isa_lookup(layout, witness.commitments(), &proof)?;
        assert_eq!(
            hex_digest(proof.table_commitments().digest()?),
            FIXED_ISA_TABLE_COMMITMENT_SHA256
        );

        let mut tampered = proof.clone();
        let first_round = tampered
            .table_sumcheck
            .rounds
            .first_mut()
            .ok_or(IsaLookupError::Shape)?;
        let first_value = first_round.first_mut().ok_or(IsaLookupError::Shape)?;
        *first_value += crate::NativeField::from_u64(1);
        assert!(verify_isa_lookup(layout, witness.commitments(), &tampered).is_err());

        let mut reordered_outputs = outputs;
        reordered_outputs.swap(0, 1);
        let reordered_layout = IsaLookupColumns::new(address_bits, reordered_outputs)?;
        assert!(verify_isa_lookup(reordered_layout, witness.commitments(), &proof).is_err());
        Ok(())
    }
}
