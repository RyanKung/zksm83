//! Selector-aware Shout argument for the fixed SM83 execution tables.

use std::sync::OnceLock;

use akita_pcs::{AkitaTranscript, Ring, Transcript};
use thiserror::Error;
use zksm83_core::{ExecutionLookupError, evaluate_execution_table_entry};
use zksm83_isa::ExecutionLookupTable;

use super::{
    EXECUTION_LOOKUP_ADDRESS_BIT_COUNT, EXECUTION_LOOKUP_OUTPUT_BIT_COUNT,
    EXECUTION_LOOKUP_OUTPUT_BIT_SHIFTS, EXECUTION_LOOKUPS_PER_BLOCK, ExecutionLookupColumns,
};
use crate::{
    AkitaWorkerError, BlockCpuWitness, CommittedWitness, FieldFoldError, NativeField,
    NativeProtocolVersion, NativeProverBackend, UNIFORM_NUM_VARIABLES, UniformError,
    WitnessCommitments,
    prover_backend::NativeVerificationContext,
    sumcheck::{
        ProductSumcheckError, ProductSumcheckProof, SumOfProductsSumcheckProof, SumcheckFactor,
    },
    uniform::{
        prove_witness_selected_opening_with_backend,
        verify_witness_selected_opening_for_protocol_with_backend,
    },
};

const PACKED_TABLE_NUM_VARIABLES: usize = EXECUTION_LOOKUP_ADDRESS_BIT_COUNT;
const PACKED_TABLE_ROW_COUNT: usize = 1 << PACKED_TABLE_NUM_VARIABLES;
const EXECUTION_LOOKUP_TRANSCRIPT_DOMAIN_V2: &[u8] = b"zksm83-native-execution-shout/v2";
const EXECUTION_TABLE_SPEC_DOMAIN: &[u8] =
    b"zksm83/sm83-execution-tables/byte-decomposed-packed/v2";
static FIXED_PACKED_TABLE: OnceLock<Result<Vec<NativeField>, ExecutionLookupError>> =
    OnceLock::new();

/// Shout proof that committed dynamic outputs equal fixed SM83 table entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionLookupProof {
    pub(crate) claimed_output: NativeField,
    pub(crate) table_sumcheck: ProductSumcheckProof,
    pub(crate) address_sumcheck: SumOfProductsSumcheckProof,
    pub(crate) trace_cycle_values: Vec<NativeField>,
    pub(crate) trace_address_values: Vec<NativeField>,
    pub(crate) trace_cycle_opening: crate::pcs::OpeningProof,
    pub(crate) trace_address_opening: crate::pcs::OpeningProof,
}

/// Invalid execution-lookup layout, witness, proof, or backend operation.
#[derive(Debug, Error)]
pub enum ExecutionLookupProofError {
    /// A packed execution-lookup column layout was malformed or overlapping.
    #[error("native execution lookup column layout is invalid")]
    InvalidColumnLayout,
    /// A committed selector or address bit was not Boolean.
    #[error("native execution lookup selector or address is not Boolean")]
    NonBooleanAddress,
    /// A reconstructed address exceeded the fixed compact table.
    #[error("native execution lookup address exceeds the fixed compact table")]
    AddressOutOfRange,
    /// Proof vectors or fixed dimensions were malformed.
    #[error("native execution lookup proof shape is invalid")]
    Shape,
    /// The table inner product disagreed with the committed trace output.
    #[error("native execution lookup output claim is inconsistent")]
    OutputClaimMismatch,
    /// The reduced table value disagreed with the verifier-fixed SM83 table MLE.
    #[error("native execution lookup table terminal is inconsistent")]
    TableTerminalMismatch,
    /// The address reduction was not bound to committed selector and address columns.
    #[error("native execution lookup address binding is inconsistent")]
    AddressBindingMismatch,
    /// A required Fiat-Shamir challenge was zero.
    #[error("native execution lookup Fiat-Shamir challenge is zero")]
    ZeroChallenge,
    /// One fixed execution-table entry could not be evaluated.
    #[error(transparent)]
    Table(#[from] ExecutionLookupError),
    /// A native-field product sumcheck failed.
    #[error("native execution lookup sumcheck failed")]
    Sumcheck,
    /// The selected prover backend could not fold an evaluation table.
    #[error(transparent)]
    FieldFold(#[from] FieldFoldError),
    /// A shared-witness opening operation failed.
    #[error("native execution lookup shared witness opening failed: {0}")]
    SharedOpening(#[from] UniformError),
    /// The operating system rejected creation of the bounded proof worker.
    #[error("failed to start native execution lookup worker: {0}")]
    WorkerSpawn(#[source] std::io::Error),
    /// The bounded proof worker panicked and its result was rejected.
    #[error("native execution lookup worker terminated unexpectedly")]
    WorkerPanicked,
}

impl From<ProductSumcheckError> for ExecutionLookupProofError {
    fn from(error: ProductSumcheckError) -> Self {
        match error {
            ProductSumcheckError::FieldFold(source) => Self::FieldFold(source),
            _ => Self::Sumcheck,
        }
    }
}

pub(crate) fn prove_execution_lookups_with_backend(
    witness: &CommittedWitness,
    backend: &NativeProverBackend,
) -> Result<ExecutionLookupProof, ExecutionLookupProofError> {
    on_worker(|| prove_execution_lookups_on_worker(witness, backend))
}

pub(crate) fn verify_execution_lookups_for_protocol_with_backend(
    protocol: NativeProtocolVersion,
    trace_commitments: &WitnessCommitments,
    proof: &ExecutionLookupProof,
    backend: &NativeProverBackend,
) -> Result<(), ExecutionLookupProofError> {
    on_worker(|| verify_execution_lookups_on_worker(protocol, trace_commitments, proof, backend))
}

fn prove_execution_lookups_on_worker(
    witness: &CommittedWitness,
    backend: &NativeProverBackend,
) -> Result<ExecutionLookupProof, ExecutionLookupProofError> {
    let layouts = canonical_layouts()?;
    validate_layouts(&layouts, witness.commitments().column_count())?;
    let protocol = NativeProtocolVersion::current();
    let descriptor = instance_descriptor(protocol, &layouts, witness.commitments())?;
    let mut transcript = lookup_transcript(protocol, &descriptor, TranscriptSide::Prover);
    let slot_mix = nonzero_challenge(&mut transcript, b"execution-slot-mix")?;
    let slot_coefficients = challenge_powers(slot_mix, layouts.len());
    let cycle_point = sample_point(
        &mut transcript,
        UNIFORM_NUM_VARIABLES,
        b"execution-cycle-point",
    );
    let trace_columns = witness.field_columns()?;
    let mixed_trace = mix_trace_outputs(trace_columns.as_slice(), &layouts, &slot_coefficients)?;
    let claimed_output = evaluate_mle(&mixed_trace, &cycle_point)?;
    transcript.append_field(b"execution-claimed-output", &claimed_output);
    let cycle_weights = equality_evaluations(&cycle_point);
    let read_address = read_address_table(
        trace_columns.as_slice(),
        &layouts,
        &slot_coefficients,
        &cycle_weights,
    )?;
    let fixed_table = fixed_packed_table()?;
    let (table_sumcheck, actual_claim, table_point) =
        ProductSumcheckProof::prove(&read_address, fixed_table, backend, &mut transcript)?;
    if actual_claim != claimed_output {
        return Err(ExecutionLookupProofError::OutputClaimMismatch);
    }
    let expected_table = fixed_packed_table_mle(&table_point)?;
    if table_sumcheck.final_right() != expected_table {
        return Err(ExecutionLookupProofError::TableTerminalMismatch);
    }
    let address_terms = address_binding_terms(
        &cycle_weights,
        trace_columns.as_slice(),
        &layouts,
        &slot_coefficients,
        &table_point,
    )?;
    let (address_sumcheck, address_claim, address_point) =
        SumOfProductsSumcheckProof::prove_shared_first(address_terms, backend, &mut transcript)?;
    if address_claim != table_sumcheck.final_left() {
        return Err(ExecutionLookupProofError::AddressBindingMismatch);
    }
    let cycle_columns = selected_output_columns(&layouts)?;
    let (trace_cycle_values, trace_cycle_opening) = prove_witness_selected_opening_with_backend(
        witness,
        &cycle_point,
        &cycle_columns,
        &descriptor,
        backend,
    )?;
    require_mixed_trace_output(
        &trace_cycle_values,
        &layouts,
        &slot_coefficients,
        claimed_output,
    )?;
    let address_columns = selected_address_columns(&layouts)?;
    let (trace_address_values, trace_address_opening) =
        prove_witness_selected_opening_with_backend(
            witness,
            &address_point,
            &address_columns,
            &descriptor,
            backend,
        )?;
    verify_address_terminal(
        &address_sumcheck,
        &layouts,
        &slot_coefficients,
        &cycle_point,
        &table_point,
        &address_point,
        &trace_address_values,
    )?;
    Ok(ExecutionLookupProof {
        claimed_output,
        table_sumcheck,
        address_sumcheck,
        trace_cycle_values,
        trace_address_values,
        trace_cycle_opening,
        trace_address_opening,
    })
}

fn verify_execution_lookups_on_worker(
    protocol: NativeProtocolVersion,
    trace_commitments: &WitnessCommitments,
    proof: &ExecutionLookupProof,
    backend: &NativeProverBackend,
) -> Result<(), ExecutionLookupProofError> {
    let layouts = canonical_layouts()?;
    validate_layouts(&layouts, trace_commitments.column_count())?;
    let descriptor = instance_descriptor(protocol, &layouts, trace_commitments)?;
    let mut transcript = lookup_transcript(protocol, &descriptor, TranscriptSide::Verifier);
    let slot_mix = nonzero_challenge(&mut transcript, b"execution-slot-mix")?;
    let slot_coefficients = challenge_powers(slot_mix, layouts.len());
    let cycle_point = sample_point(
        &mut transcript,
        UNIFORM_NUM_VARIABLES,
        b"execution-cycle-point",
    );
    transcript.append_field(b"execution-claimed-output", &proof.claimed_output);
    let table_point = proof.table_sumcheck.verify(
        proof.claimed_output,
        PACKED_TABLE_NUM_VARIABLES,
        &mut transcript,
    )?;
    if proof.table_sumcheck.final_right() != fixed_packed_table_mle(&table_point)? {
        return Err(ExecutionLookupProofError::TableTerminalMismatch);
    }
    let address_point = proof.address_sumcheck.verify(
        proof.table_sumcheck.final_left(),
        UNIFORM_NUM_VARIABLES,
        layouts.len(),
        EXECUTION_LOOKUP_ADDRESS_BIT_COUNT + 2,
        &mut transcript,
    )?;
    let cycle_columns = selected_output_columns(&layouts)?;
    verify_witness_selected_opening_for_protocol_with_backend(
        NativeVerificationContext::new(protocol, backend),
        trace_commitments,
        &cycle_point,
        &proof.trace_cycle_values,
        &cycle_columns,
        &descriptor,
        &proof.trace_cycle_opening,
    )?;
    require_mixed_trace_output(
        &proof.trace_cycle_values,
        &layouts,
        &slot_coefficients,
        proof.claimed_output,
    )?;
    let address_columns = selected_address_columns(&layouts)?;
    verify_witness_selected_opening_for_protocol_with_backend(
        NativeVerificationContext::new(protocol, backend),
        trace_commitments,
        &address_point,
        &proof.trace_address_values,
        &address_columns,
        &descriptor,
        &proof.trace_address_opening,
    )?;
    verify_address_terminal(
        &proof.address_sumcheck,
        &layouts,
        &slot_coefficients,
        &cycle_point,
        &table_point,
        &address_point,
        &proof.trace_address_values,
    )
}

fn canonical_layouts()
-> Result<[ExecutionLookupColumns; EXECUTION_LOOKUPS_PER_BLOCK], ExecutionLookupProofError> {
    let mut layouts = Vec::with_capacity(EXECUTION_LOOKUPS_PER_BLOCK);
    for lane in 0..zksm83_trace::BASIC_BLOCK_INSTRUCTION_BOUND {
        for query in 0..super::EXECUTION_LOOKUPS_PER_INSTRUCTION {
            layouts.push(
                BlockCpuWitness::execution_lookup_columns(lane, query)
                    .map_err(|_| ExecutionLookupProofError::InvalidColumnLayout)?,
            );
        }
    }
    layouts
        .try_into()
        .map_err(|_| ExecutionLookupProofError::Shape)
}

fn validate_layouts(
    layouts: &[ExecutionLookupColumns],
    column_count: usize,
) -> Result<(), ExecutionLookupProofError> {
    if layouts.len() != EXECUTION_LOOKUPS_PER_BLOCK {
        return Err(ExecutionLookupProofError::Shape);
    }
    let mut columns = Vec::with_capacity(
        layouts.len()
            * (EXECUTION_LOOKUP_ADDRESS_BIT_COUNT + EXECUTION_LOOKUP_OUTPUT_BIT_COUNT + 1),
    );
    for layout in layouts {
        columns.push(layout.selector());
        columns.extend_from_slice(&layout.address_bits());
        columns.extend_from_slice(&layout.output_bits());
    }
    columns.sort_unstable();
    if columns.iter().any(|column| *column >= column_count)
        || columns
            .windows(2)
            .any(|pair| matches!(pair, [left, right] if left == right))
    {
        return Err(ExecutionLookupProofError::InvalidColumnLayout);
    }
    Ok(())
}

fn fixed_packed_table() -> Result<&'static [NativeField], ExecutionLookupProofError> {
    match FIXED_PACKED_TABLE.get_or_init(build_fixed_packed_table) {
        Ok(table) => Ok(table),
        Err(error) => Err(ExecutionLookupProofError::Table(*error)),
    }
}

fn build_fixed_packed_table() -> Result<Vec<NativeField>, ExecutionLookupError> {
    let mut evaluations = vec![NativeField::from_u64(0); PACKED_TABLE_ROW_COUNT];
    for table in ExecutionLookupTable::ALL {
        let bounds_error = || ExecutionLookupError::AddressOutOfRange {
            table,
            index: u64::from(table.row_count()),
        };
        let start = usize::try_from(table.packed_offset()).map_err(|_| bounds_error())?;
        let count = usize::try_from(table.row_count()).map_err(|_| bounds_error())?;
        let target = evaluations
            .get_mut(start..start.checked_add(count).ok_or_else(bounds_error)?)
            .ok_or_else(bounds_error)?;
        for (index, value) in target.iter_mut().enumerate() {
            *value = NativeField::from_u64(u64::from(evaluate_execution_table_entry(
                table,
                u64::try_from(index).map_err(|_| bounds_error())?,
            )?));
        }
    }
    Ok(evaluations)
}

fn fixed_packed_table_mle(point: &[NativeField]) -> Result<NativeField, ExecutionLookupProofError> {
    if point.len() != PACKED_TABLE_NUM_VARIABLES {
        return Err(ExecutionLookupProofError::Shape);
    }
    evaluate_mle(fixed_packed_table()?, point)
}

fn trace_addresses(
    columns: &[impl AsRef<[NativeField]>],
    layout: ExecutionLookupColumns,
) -> Result<(Vec<usize>, Vec<NativeField>), ExecutionLookupProofError> {
    let row_count = columns
        .first()
        .map(|column| column.as_ref().len())
        .ok_or(ExecutionLookupProofError::Shape)?;
    let zero = NativeField::from_u64(0);
    let one = NativeField::from_u64(1);
    let selector = columns
        .get(layout.selector())
        .map(AsRef::as_ref)
        .ok_or(ExecutionLookupProofError::Shape)?;
    if selector.len() != row_count || selector.iter().any(|value| *value != zero && *value != one) {
        return Err(ExecutionLookupProofError::NonBooleanAddress);
    }
    let mut addresses = vec![0_usize; row_count];
    for (bit, column_index) in layout.address_bits().into_iter().enumerate() {
        let column = columns
            .get(column_index)
            .map(AsRef::as_ref)
            .ok_or(ExecutionLookupProofError::Shape)?;
        if column.len() != row_count {
            return Err(ExecutionLookupProofError::Shape);
        }
        for (address, value) in addresses.iter_mut().zip(column) {
            if *value != zero && *value != one {
                return Err(ExecutionLookupProofError::NonBooleanAddress);
            }
            if *value == one {
                *address = address
                    .checked_add(
                        1_usize
                            .checked_shl(
                                u32::try_from(bit)
                                    .map_err(|_| ExecutionLookupProofError::AddressOutOfRange)?,
                            )
                            .ok_or(ExecutionLookupProofError::AddressOutOfRange)?,
                    )
                    .ok_or(ExecutionLookupProofError::AddressOutOfRange)?;
            }
        }
    }
    if addresses
        .iter()
        .any(|address| *address >= PACKED_TABLE_ROW_COUNT)
    {
        return Err(ExecutionLookupProofError::AddressOutOfRange);
    }
    Ok((addresses, selector.to_vec()))
}

fn read_address_table(
    columns: &[impl AsRef<[NativeField]>],
    layouts: &[ExecutionLookupColumns],
    slot_coefficients: &[NativeField],
    cycle_weights: &[NativeField],
) -> Result<Vec<NativeField>, ExecutionLookupProofError> {
    if layouts.len() != slot_coefficients.len() {
        return Err(ExecutionLookupProofError::Shape);
    }
    let mut read_address = vec![NativeField::from_u64(0); PACKED_TABLE_ROW_COUNT];
    for (layout, coefficient) in layouts.iter().copied().zip(slot_coefficients) {
        let (addresses, selectors) = trace_addresses(columns, layout)?;
        if addresses.len() != cycle_weights.len() || selectors.len() != cycle_weights.len() {
            return Err(ExecutionLookupProofError::Shape);
        }
        for ((address, selector), weight) in addresses.into_iter().zip(selectors).zip(cycle_weights)
        {
            let target = read_address
                .get_mut(address)
                .ok_or(ExecutionLookupProofError::AddressOutOfRange)?;
            *target += *coefficient * selector * *weight;
        }
    }
    Ok(read_address)
}

fn address_binding_terms<'a>(
    cycle_weights: &'a [NativeField],
    columns: &'a [impl AsRef<[NativeField]>],
    layouts: &[ExecutionLookupColumns],
    slot_coefficients: &[NativeField],
    table_point: &[NativeField],
) -> Result<Vec<Vec<SumcheckFactor<'a>>>, ExecutionLookupProofError> {
    if table_point.len() != PACKED_TABLE_NUM_VARIABLES || layouts.len() != slot_coefficients.len() {
        return Err(ExecutionLookupProofError::Shape);
    }
    let one = NativeField::from_u64(1);
    layouts
        .iter()
        .copied()
        .zip(slot_coefficients)
        .map(|(layout, coefficient)| {
            let mut factors = Vec::with_capacity(EXECUTION_LOOKUP_ADDRESS_BIT_COUNT + 2);
            factors.push(SumcheckFactor::borrowed(cycle_weights));
            let selector = columns
                .get(layout.selector())
                .map(AsRef::as_ref)
                .ok_or(ExecutionLookupProofError::Shape)?;
            factors.push(SumcheckFactor::affine(
                selector,
                *coefficient,
                NativeField::from_u64(0),
            ));
            for (column_index, point) in layout.address_bits().into_iter().zip(table_point) {
                let column = columns
                    .get(column_index)
                    .map(AsRef::as_ref)
                    .ok_or(ExecutionLookupProofError::Shape)?;
                if column.len() != cycle_weights.len() {
                    return Err(ExecutionLookupProofError::Shape);
                }
                factors.push(SumcheckFactor::affine(
                    column,
                    NativeField::from_u64(2) * *point - one,
                    one - *point,
                ));
            }
            Ok(factors)
        })
        .collect()
}

fn mix_trace_outputs(
    columns: &[impl AsRef<[NativeField]>],
    layouts: &[ExecutionLookupColumns],
    coefficients: &[NativeField],
) -> Result<Vec<NativeField>, ExecutionLookupProofError> {
    if layouts.len() != coefficients.len() {
        return Err(ExecutionLookupProofError::Shape);
    }
    let row_count = columns
        .first()
        .map(|column| column.as_ref().len())
        .ok_or(ExecutionLookupProofError::Shape)?;
    let mut mixed = vec![NativeField::from_u64(0); row_count];
    for (layout, coefficient) in layouts.iter().copied().zip(coefficients) {
        for (column_index, shift) in layout
            .output_bits()
            .into_iter()
            .zip(EXECUTION_LOOKUP_OUTPUT_BIT_SHIFTS)
        {
            let output = columns
                .get(column_index)
                .map(AsRef::as_ref)
                .ok_or(ExecutionLookupProofError::Shape)?;
            if output.len() != row_count {
                return Err(ExecutionLookupProofError::Shape);
            }
            let bit_coefficient = *coefficient * NativeField::from_u64(1_u64 << shift);
            for (target, value) in mixed.iter_mut().zip(output) {
                *target += bit_coefficient * *value;
            }
        }
    }
    Ok(mixed)
}

fn selected_output_columns(
    layouts: &[ExecutionLookupColumns],
) -> Result<Vec<usize>, ExecutionLookupProofError> {
    canonical_selected_columns(
        layouts
            .iter()
            .flat_map(|layout| layout.output_bits())
            .collect(),
    )
}

fn selected_address_columns(
    layouts: &[ExecutionLookupColumns],
) -> Result<Vec<usize>, ExecutionLookupProofError> {
    let mut columns = Vec::with_capacity(layouts.len() * (EXECUTION_LOOKUP_ADDRESS_BIT_COUNT + 1));
    for layout in layouts {
        columns.push(layout.selector());
        columns.extend_from_slice(&layout.address_bits());
    }
    canonical_selected_columns(columns)
}

fn canonical_selected_columns(
    mut columns: Vec<usize>,
) -> Result<Vec<usize>, ExecutionLookupProofError> {
    let expected = columns.len();
    columns.sort_unstable();
    columns.dedup();
    if columns.len() != expected {
        return Err(ExecutionLookupProofError::InvalidColumnLayout);
    }
    Ok(columns)
}

fn require_mixed_trace_output(
    values: &[NativeField],
    layouts: &[ExecutionLookupColumns],
    coefficients: &[NativeField],
    expected: NativeField,
) -> Result<(), ExecutionLookupProofError> {
    if layouts.len() != coefficients.len() {
        return Err(ExecutionLookupProofError::Shape);
    }
    let mut actual = NativeField::from_u64(0);
    for (layout, coefficient) in layouts.iter().copied().zip(coefficients) {
        for (column, shift) in layout
            .output_bits()
            .into_iter()
            .zip(EXECUTION_LOOKUP_OUTPUT_BIT_SHIFTS)
        {
            let value = values
                .get(column)
                .copied()
                .ok_or(ExecutionLookupProofError::Shape)?;
            actual += *coefficient * NativeField::from_u64(1_u64 << shift) * value;
        }
    }
    if actual != expected {
        return Err(ExecutionLookupProofError::OutputClaimMismatch);
    }
    Ok(())
}

fn verify_address_terminal(
    proof: &SumOfProductsSumcheckProof,
    layouts: &[ExecutionLookupColumns],
    slot_coefficients: &[NativeField],
    cycle_point: &[NativeField],
    table_point: &[NativeField],
    address_point: &[NativeField],
    trace_values: &[NativeField],
) -> Result<(), ExecutionLookupProofError> {
    if proof.final_terms().len() != layouts.len()
        || layouts.len() != slot_coefficients.len()
        || table_point.len() != PACKED_TABLE_NUM_VARIABLES
    {
        return Err(ExecutionLookupProofError::Shape);
    }
    let expected_weight = equality_evaluation(cycle_point, address_point)?;
    let one = NativeField::from_u64(1);
    for ((factors, layout), coefficient) in proof
        .final_terms()
        .iter()
        .zip(layouts)
        .zip(slot_coefficients)
    {
        if factors.len() != EXECUTION_LOOKUP_ADDRESS_BIT_COUNT + 2
            || factors.first().copied() != Some(expected_weight)
        {
            return Err(ExecutionLookupProofError::AddressBindingMismatch);
        }
        let selector = trace_values
            .get(layout.selector())
            .copied()
            .ok_or(ExecutionLookupProofError::Shape)?;
        if factors.get(1).copied() != Some(*coefficient * selector) {
            return Err(ExecutionLookupProofError::AddressBindingMismatch);
        }
        for ((factor, column), point) in factors
            .iter()
            .skip(2)
            .zip(layout.address_bits())
            .zip(table_point)
        {
            let address_bit = trace_values
                .get(column)
                .copied()
                .ok_or(ExecutionLookupProofError::Shape)?;
            let equality = address_bit * *point + (one - address_bit) * (one - *point);
            if *factor != equality {
                return Err(ExecutionLookupProofError::AddressBindingMismatch);
            }
        }
    }
    Ok(())
}

fn instance_descriptor(
    protocol: NativeProtocolVersion,
    layouts: &[ExecutionLookupColumns],
    trace_commitments: &WitnessCommitments,
) -> Result<Vec<u8>, ExecutionLookupProofError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, protocol.protocol_id().as_bytes())?;
    push_bytes(&mut descriptor, EXECUTION_TABLE_SPEC_DOMAIN)?;
    push_usize(&mut descriptor, PACKED_TABLE_NUM_VARIABLES)?;
    push_usize(&mut descriptor, ExecutionLookupTable::ALL.len())?;
    for table in ExecutionLookupTable::ALL {
        descriptor.push(table.code());
        push_usize(&mut descriptor, table.input_bit_count())?;
        descriptor.extend_from_slice(&table.packed_offset().to_le_bytes());
    }
    push_usize(&mut descriptor, layouts.len())?;
    for layout in layouts {
        push_usize(&mut descriptor, layout.selector())?;
        push_indices(&mut descriptor, &layout.address_bits())?;
        push_indices(&mut descriptor, &layout.output_bits())?;
    }
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
        NativeProtocolVersion::V2 => EXECUTION_LOOKUP_TRANSCRIPT_DOMAIN_V2,
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
) -> Result<NativeField, ExecutionLookupProofError> {
    let challenge = transcript.challenge_scalar(label);
    if challenge == NativeField::from_u64(0) {
        return Err(ExecutionLookupProofError::ZeroChallenge);
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

fn evaluate_mle(
    evaluations: &[NativeField],
    point: &[NativeField],
) -> Result<NativeField, ExecutionLookupProofError> {
    crate::field_fold::evaluate_mle(evaluations, point)
        .map_err(|_| ExecutionLookupProofError::Shape)
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
) -> Result<NativeField, ExecutionLookupProofError> {
    if left.len() != right.len() {
        return Err(ExecutionLookupProofError::Shape);
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

fn push_indices(bytes: &mut Vec<u8>, indices: &[usize]) -> Result<(), ExecutionLookupProofError> {
    push_usize(bytes, indices.len())?;
    for index in indices {
        push_usize(bytes, *index)?;
    }
    Ok(())
}

fn push_usize(bytes: &mut Vec<u8>, value: usize) -> Result<(), ExecutionLookupProofError> {
    let value = u64::try_from(value).map_err(|_| ExecutionLookupProofError::Shape)?;
    bytes.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), ExecutionLookupProofError> {
    push_usize(bytes, value.len())?;
    bytes.extend_from_slice(value);
    Ok(())
}

fn on_worker<T: Send>(
    operation: impl FnOnce() -> Result<T, ExecutionLookupProofError> + Send,
) -> Result<T, ExecutionLookupProofError> {
    match crate::on_akita_worker(operation) {
        Ok(result) => result,
        Err(AkitaWorkerError::Spawn(error)) => Err(ExecutionLookupProofError::WorkerSpawn(error)),
        Err(AkitaWorkerError::Panicked) => Err(ExecutionLookupProofError::WorkerPanicked),
    }
}
