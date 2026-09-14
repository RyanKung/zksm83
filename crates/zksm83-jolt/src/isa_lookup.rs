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
    sumcheck::{
        ProductSumcheckError, ProductSumcheckProof, SumOfProductsSumcheckProof, SumcheckFactor,
    },
    uniform::{
        CommittedWitness, WitnessCommitments, prove_witness_selected_opening,
        verify_witness_selected_opening_for_protocol,
    },
};

/// Number of least-significant-bit-first address columns consumed by ISA lookup.
pub const ISA_ADDRESS_BIT_COUNT: usize = 9;

/// SHA-256 of the canonical Akita commitment to all fixed ISA output columns.
pub const FIXED_ISA_TABLE_COMMITMENT_SHA256: &str =
    "fc4afaeb9c3d6a7dc063e2927caee773ae4a29f3c16e7d3f1aa5f266ea3f9c9a";

const ISA_TABLE_NUM_VARIABLES: usize = 9;
const MAX_BATCHED_ISA_LOOKUPS: usize = 4;
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

/// Verifier-visible commitment to all fixed ISA table outputs.
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
    pub(crate) address_sumcheck: SumOfProductsSumcheckProof,
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

fn validate_layouts(
    layouts: &[IsaLookupColumns],
    column_count: usize,
) -> Result<(), IsaLookupError> {
    if layouts.is_empty() || layouts.len() > MAX_BATCHED_ISA_LOOKUPS {
        return Err(IsaLookupError::Shape);
    }
    let columns_per_layout = ISA_ADDRESS_BIT_COUNT
        .checked_add(ISA_OUTPUT_COUNT)
        .ok_or(IsaLookupError::Shape)?;
    let capacity = layouts
        .len()
        .checked_mul(columns_per_layout)
        .ok_or(IsaLookupError::Shape)?;
    let mut columns = Vec::with_capacity(capacity);
    for layout in layouts.iter().copied() {
        layout.validate(column_count)?;
        columns.extend_from_slice(&layout.address_bits);
        columns.extend_from_slice(&layout.outputs);
    }
    columns.sort_unstable();
    if columns
        .windows(2)
        .any(|pair| matches!(pair, [left, right] if left == right))
    {
        return Err(IsaLookupError::InvalidColumnLayout);
    }
    Ok(())
}

fn selected_output_columns(layouts: &[IsaLookupColumns]) -> Result<Vec<usize>, IsaLookupError> {
    let expected = layouts
        .len()
        .checked_mul(ISA_OUTPUT_COUNT)
        .ok_or(IsaLookupError::Shape)?;
    let mut columns = Vec::with_capacity(expected);
    for layout in layouts {
        columns.extend_from_slice(&layout.outputs);
    }
    canonical_selected_columns(columns, expected)
}

fn selected_address_columns(layouts: &[IsaLookupColumns]) -> Result<Vec<usize>, IsaLookupError> {
    let expected = layouts
        .len()
        .checked_mul(ISA_ADDRESS_BIT_COUNT)
        .ok_or(IsaLookupError::Shape)?;
    let mut columns = Vec::with_capacity(expected);
    for layout in layouts {
        columns.extend_from_slice(&layout.address_bits);
    }
    canonical_selected_columns(columns, expected)
}

fn canonical_selected_columns(
    mut columns: Vec<usize>,
    expected: usize,
) -> Result<Vec<usize>, IsaLookupError> {
    columns.sort_unstable();
    columns.dedup();
    if columns.len() != expected {
        return Err(IsaLookupError::InvalidColumnLayout);
    }
    Ok(columns)
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

/// Proves all fixed-ISA outputs against one shared trace commitment plane.
pub fn prove_isa_lookup(
    layout: IsaLookupColumns,
    witness: &CommittedWitness,
) -> Result<IsaLookupProof, IsaLookupError> {
    on_worker(|| {
        let table = commit_fixed_table()?;
        prove_isa_lookups_on_worker(std::slice::from_ref(&layout), witness, &table)
    })
}

pub(crate) fn prove_isa_lookups<const N: usize>(
    layouts: [IsaLookupColumns; N],
    witness: &CommittedWitness,
) -> Result<IsaLookupProof, IsaLookupError> {
    on_worker(|| {
        let table = commit_fixed_table()?;
        prove_isa_lookups_on_worker(&layouts, witness, &table)
    })
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
    on_worker(|| {
        verify_isa_lookups_on_worker(
            protocol,
            std::slice::from_ref(&layout),
            trace_commitments,
            proof,
        )
    })
}

pub(crate) fn verify_isa_lookups_for_protocol<const N: usize>(
    protocol: NativeProtocolVersion,
    layouts: [IsaLookupColumns; N],
    trace_commitments: &WitnessCommitments,
    proof: &IsaLookupProof,
) -> Result<(), IsaLookupError> {
    on_worker(|| verify_isa_lookups_on_worker(protocol, &layouts, trace_commitments, proof))
}

fn prove_isa_lookups_on_worker(
    layouts: &[IsaLookupColumns],
    witness: &CommittedWitness,
    table: &CommittedColumns,
) -> Result<IsaLookupProof, IsaLookupError> {
    validate_layouts(layouts, witness.commitments().column_count())?;
    let table_commitments = FixedIsaCommitments {
        inner: table.commitments().clone(),
    };
    let protocol = NativeProtocolVersion::current();
    let descriptor =
        instance_descriptor(protocol, layouts, &table_commitments, witness.commitments())?;
    let mut transcript = lookup_transcript(protocol, &descriptor, TranscriptSide::Prover);
    let output_mix = nonzero_challenge(&mut transcript, b"isa-output-mix")?;
    let coefficients = challenge_powers(output_mix, ISA_OUTPUT_COUNT);
    let lane_mix = nonzero_challenge(&mut transcript, b"isa-lane-mix")?;
    let lane_coefficients = challenge_powers(lane_mix, layouts.len());
    let cycle_point = sample_point(&mut transcript, UNIFORM_NUM_VARIABLES, b"isa-cycle-point");
    let table_columns = table.field_columns()?;
    let trace_columns = witness.field_columns()?;
    let mixed_table = mix_columns(
        table_columns.as_slice(),
        &canonical_indices(),
        &coefficients,
    )?;
    let mixed_trace = mix_trace_outputs(
        trace_columns.as_slice(),
        layouts,
        &lane_coefficients,
        &coefficients,
    )?;
    let claimed_output = evaluate_mle(&mixed_trace, &cycle_point)?;
    transcript.append_field(b"isa-claimed-output", &claimed_output);
    let cycle_weights = equality_evaluations(&cycle_point);
    let read_address = read_address_table(
        trace_columns.as_slice(),
        layouts,
        &lane_coefficients,
        &cycle_weights,
    )?;
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
    let address_terms = address_binding_terms(
        &cycle_weights,
        trace_columns.as_slice(),
        layouts,
        &lane_coefficients,
        &table_point,
    )?;
    let (address_sumcheck, address_claim, address_point) =
        SumOfProductsSumcheckProof::prove_shared_first(address_terms, &mut transcript)?;
    if address_claim != table_sumcheck.final_left() {
        return Err(IsaLookupError::AddressBindingMismatch);
    }
    let cycle_columns = selected_output_columns(layouts)?;
    let (trace_cycle_values, trace_cycle_opening) =
        prove_witness_selected_opening(witness, &cycle_point, &cycle_columns, &descriptor)?;
    require_batched_mixed_value(
        &trace_cycle_values,
        layouts,
        &lane_coefficients,
        &coefficients,
        claimed_output,
    )?;
    let address_columns = selected_address_columns(layouts)?;
    let (trace_address_values, trace_address_opening) =
        prove_witness_selected_opening(witness, &address_point, &address_columns, &descriptor)?;
    verify_address_terminal(
        &address_sumcheck,
        layouts,
        &lane_coefficients,
        &cycle_point,
        &table_point,
        &address_point,
        &trace_address_values,
    )?;
    let table_opening = prove_opening(
        ISA_TABLE_LAYOUT,
        table,
        &table_point,
        &table_values,
        &descriptor,
    )?;
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

fn verify_isa_lookups_on_worker(
    protocol: NativeProtocolVersion,
    layouts: &[IsaLookupColumns],
    trace_commitments: &WitnessCommitments,
    proof: &IsaLookupProof,
) -> Result<(), IsaLookupError> {
    validate_layouts(layouts, trace_commitments.column_count())?;
    validate_fixed_commitments(&proof.table_commitments)?;
    let descriptor = instance_descriptor(
        protocol,
        layouts,
        &proof.table_commitments,
        trace_commitments,
    )?;
    let mut transcript = lookup_transcript(protocol, &descriptor, TranscriptSide::Verifier);
    let output_mix = nonzero_challenge(&mut transcript, b"isa-output-mix")?;
    let coefficients = challenge_powers(output_mix, ISA_OUTPUT_COUNT);
    let lane_mix = nonzero_challenge(&mut transcript, b"isa-lane-mix")?;
    let lane_coefficients = challenge_powers(lane_mix, layouts.len());
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
        layouts.len(),
        ISA_ADDRESS_BIT_COUNT + 1,
        &mut transcript,
    )?;
    let cycle_columns = selected_output_columns(layouts)?;
    verify_witness_selected_opening_for_protocol(
        protocol,
        trace_commitments,
        &cycle_point,
        &proof.trace_cycle_values,
        &cycle_columns,
        &descriptor,
        &proof.trace_cycle_opening,
    )?;
    require_batched_mixed_value(
        &proof.trace_cycle_values,
        layouts,
        &lane_coefficients,
        &coefficients,
        proof.claimed_output,
    )?;
    let address_columns = selected_address_columns(layouts)?;
    verify_witness_selected_opening_for_protocol(
        protocol,
        trace_commitments,
        &address_point,
        &proof.trace_address_values,
        &address_columns,
        &descriptor,
        &proof.trace_address_opening,
    )?;
    verify_address_terminal(
        &proof.address_sumcheck,
        layouts,
        &lane_coefficients,
        &cycle_point,
        &table_point,
        &address_point,
        &proof.trace_address_values,
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
    columns: &[impl AsRef<[NativeField]>],
    layouts: &[IsaLookupColumns],
    lane_coefficients: &[NativeField],
    cycle_weights: &[NativeField],
) -> Result<Vec<NativeField>, IsaLookupError> {
    if layouts.len() != lane_coefficients.len() {
        return Err(IsaLookupError::Shape);
    }
    let mut read_address = vec![NativeField::from_u64(0); ISA_TABLE_ROW_COUNT];
    for (layout, lane_coefficient) in layouts.iter().zip(lane_coefficients) {
        let addresses = trace_addresses(columns, &layout.address_bits)?;
        if addresses.len() != cycle_weights.len() {
            return Err(IsaLookupError::Shape);
        }
        for (address, weight) in addresses.into_iter().zip(cycle_weights) {
            let target = read_address
                .get_mut(address)
                .ok_or(IsaLookupError::AddressOutOfRange)?;
            *target += *lane_coefficient * *weight;
        }
    }
    Ok(read_address)
}

fn address_binding_terms<'a>(
    cycle_weights: &'a [NativeField],
    columns: &'a [impl AsRef<[NativeField]>],
    layouts: &[IsaLookupColumns],
    lane_coefficients: &[NativeField],
    table_point: &[NativeField],
) -> Result<Vec<Vec<SumcheckFactor<'a>>>, IsaLookupError> {
    if table_point.len() != ISA_ADDRESS_BIT_COUNT || layouts.len() != lane_coefficients.len() {
        return Err(IsaLookupError::Shape);
    }
    let one = NativeField::from_u64(1);
    layouts
        .iter()
        .zip(lane_coefficients)
        .map(|(layout, lane_coefficient)| {
            let mut factors = Vec::with_capacity(ISA_ADDRESS_BIT_COUNT + 1);
            factors.push(SumcheckFactor::borrowed(cycle_weights));
            for (bit, (column_index, point)) in layout
                .address_bits
                .iter()
                .copied()
                .zip(table_point)
                .enumerate()
            {
                let column = columns
                    .get(column_index)
                    .map(AsRef::as_ref)
                    .ok_or(IsaLookupError::Shape)?;
                if column.len() != cycle_weights.len() {
                    return Err(IsaLookupError::Shape);
                }
                let coefficient = if bit == 0 { *lane_coefficient } else { one };
                factors.push(SumcheckFactor::affine(
                    column,
                    coefficient * (NativeField::from_u64(2) * *point - one),
                    coefficient * (one - *point),
                ));
            }
            Ok(factors)
        })
        .collect()
}

fn verify_address_terminal(
    proof: &SumOfProductsSumcheckProof,
    layouts: &[IsaLookupColumns],
    lane_coefficients: &[NativeField],
    cycle_point: &[NativeField],
    table_point: &[NativeField],
    address_point: &[NativeField],
    trace_values: &[NativeField],
) -> Result<(), IsaLookupError> {
    if proof.final_terms().len() != layouts.len()
        || layouts.len() != lane_coefficients.len()
        || table_point.len() != ISA_ADDRESS_BIT_COUNT
    {
        return Err(IsaLookupError::Shape);
    }
    let expected_weight = equality_evaluation(cycle_point, address_point)?;
    let one = NativeField::from_u64(1);
    for ((factors, layout), lane_coefficient) in proof
        .final_terms()
        .iter()
        .zip(layouts)
        .zip(lane_coefficients)
    {
        if factors.len() != ISA_ADDRESS_BIT_COUNT + 1
            || factors.first().copied() != Some(expected_weight)
        {
            return Err(IsaLookupError::AddressBindingMismatch);
        }
        for (bit_index, ((factor, column_index), point)) in factors
            .iter()
            .skip(1)
            .zip(layout.address_bits)
            .zip(table_point)
            .enumerate()
        {
            let address_bit = trace_values
                .get(column_index)
                .copied()
                .ok_or(IsaLookupError::Shape)?;
            let equality = address_bit * *point + (one - address_bit) * (one - *point);
            let expected = if bit_index == 0 {
                *lane_coefficient * equality
            } else {
                equality
            };
            if *factor != expected {
                return Err(IsaLookupError::AddressBindingMismatch);
            }
        }
    }
    Ok(())
}

fn instance_descriptor(
    protocol: NativeProtocolVersion,
    layouts: &[IsaLookupColumns],
    table_commitments: &FixedIsaCommitments,
    trace_commitments: &WitnessCommitments,
) -> Result<Vec<u8>, IsaLookupError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, protocol.protocol_id().as_bytes())?;
    push_bytes(&mut descriptor, AKITA_ISA_TABLE_SCHEDULE_SHA256.as_bytes())?;
    push_bytes(&mut descriptor, &fixed_isa_table_digest()?)?;
    push_usize(&mut descriptor, ISA_TABLE_ROW_COUNT)?;
    push_usize(&mut descriptor, ISA_OUTPUT_COUNT)?;
    push_usize(&mut descriptor, layouts.len())?;
    for layout in layouts {
        push_indices(&mut descriptor, &layout.address_bits)?;
        push_indices(&mut descriptor, &layout.outputs)?;
    }
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

fn mix_trace_outputs(
    columns: &[impl AsRef<[NativeField]>],
    layouts: &[IsaLookupColumns],
    lane_coefficients: &[NativeField],
    output_coefficients: &[NativeField],
) -> Result<Vec<NativeField>, IsaLookupError> {
    if layouts.len() != lane_coefficients.len() || output_coefficients.len() != ISA_OUTPUT_COUNT {
        return Err(IsaLookupError::Shape);
    }
    let row_count = columns
        .first()
        .map(|column| column.as_ref().len())
        .ok_or(IsaLookupError::Shape)?;
    let mut mixed = vec![NativeField::from_u64(0); row_count];
    for (layout, lane_coefficient) in layouts.iter().zip(lane_coefficients) {
        for (column_index, output_coefficient) in
            layout.outputs.iter().copied().zip(output_coefficients)
        {
            let column = columns
                .get(column_index)
                .map(AsRef::as_ref)
                .ok_or(IsaLookupError::Shape)?;
            if column.len() != row_count {
                return Err(IsaLookupError::Shape);
            }
            let coefficient = *lane_coefficient * *output_coefficient;
            for (target, value) in mixed.iter_mut().zip(column) {
                *target += coefficient * *value;
            }
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

fn require_batched_mixed_value(
    values: &[NativeField],
    layouts: &[IsaLookupColumns],
    lane_coefficients: &[NativeField],
    output_coefficients: &[NativeField],
    expected: NativeField,
) -> Result<(), IsaLookupError> {
    if layouts.len() != lane_coefficients.len() || output_coefficients.len() != ISA_OUTPUT_COUNT {
        return Err(IsaLookupError::Shape);
    }
    let actual = layouts.iter().zip(lane_coefficients).try_fold(
        NativeField::from_u64(0),
        |sum, (layout, lane_coefficient)| {
            layout
                .outputs
                .iter()
                .copied()
                .zip(output_coefficients)
                .try_fold(sum, |sum, (column, output_coefficient)| {
                    values
                        .get(column)
                        .copied()
                        .map(|value| sum + *lane_coefficient * *output_coefficient * value)
                        .ok_or(IsaLookupError::Shape)
                })
        },
    )?;
    if actual != expected {
        return Err(IsaLookupError::OutputClaimMismatch);
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
    crate::field_fold::evaluate_mle(evaluations, point).map_err(|_| IsaLookupError::Shape)
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
mod tests;
