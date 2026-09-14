use akita_pcs::Transcript;

use crate::{
    NativeField, NativeProtocolVersion, NativeProverBackend, TRACE_ROW_BIT_COUNT,
    UNIFORM_NUM_VARIABLES, WitnessCommitments,
    pcs::OpeningProof,
    uniform::{
        CommittedWitness, prove_witness_selected_opening_with_backend,
        verify_witness_selected_opening_for_protocol_with_backend,
    },
};

use super::{MutableMemoryError, push_bytes, transcript};

const CLOCK_DOMAIN: &[u8] = b"zksm83-native-memory-fixed-clock/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClockProof {
    pub(crate) values: Vec<NativeField>,
    pub(crate) opening: OpeningProof,
}

pub(super) fn prove_at(
    trace: &CommittedWitness,
    phase_one: &[u8],
    row_bits_start: usize,
    backend: &NativeProverBackend,
) -> Result<ClockProof, MutableMemoryError> {
    let descriptor = descriptor(phase_one)?;
    let point = point(&descriptor);
    let selected_columns = row_bit_columns(row_bits_start)?;
    let (values, opening) = prove_witness_selected_opening_with_backend(
        trace,
        &point,
        &selected_columns,
        &descriptor,
        backend,
    )?;
    check_row_bits(&values, &point, row_bits_start)?;
    Ok(ClockProof { values, opening })
}

pub(super) fn verify_at(
    protocol: NativeProtocolVersion,
    trace: &WitnessCommitments,
    phase_one: &[u8],
    proof: &ClockProof,
    row_bits_start: usize,
    backend: &NativeProverBackend,
) -> Result<(), MutableMemoryError> {
    let descriptor = descriptor(phase_one)?;
    let point = point(&descriptor);
    let selected_columns = row_bit_columns(row_bits_start)?;
    verify_witness_selected_opening_for_protocol_with_backend(
        protocol,
        trace,
        &point,
        &proof.values,
        &selected_columns,
        &descriptor,
        &proof.opening,
        backend,
    )?;
    check_row_bits(&proof.values, &point, row_bits_start)
}

fn row_bit_columns(row_bits_start: usize) -> Result<Vec<usize>, MutableMemoryError> {
    let end = row_bits_start
        .checked_add(TRACE_ROW_BIT_COUNT)
        .ok_or(MutableMemoryError::Shape)?;
    Ok((row_bits_start..end).collect())
}

fn descriptor(phase_one: &[u8]) -> Result<Vec<u8>, MutableMemoryError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, CLOCK_DOMAIN)?;
    push_bytes(&mut descriptor, phase_one)?;
    Ok(descriptor)
}

fn point(descriptor: &[u8]) -> Vec<NativeField> {
    let mut transcript = transcript(CLOCK_DOMAIN, descriptor);
    (0..UNIFORM_NUM_VARIABLES)
        .map(|_| transcript.challenge_scalar(b"fixed-clock-point"))
        .collect()
}

fn check_row_bits(
    values: &[NativeField],
    point: &[NativeField],
    row_bits_start: usize,
) -> Result<(), MutableMemoryError> {
    if point.len() != TRACE_ROW_BIT_COUNT {
        return Err(MutableMemoryError::Shape);
    }
    for (bit, expected) in point.iter().copied().enumerate() {
        let actual = values
            .get(
                row_bits_start
                    .checked_add(bit)
                    .ok_or(MutableMemoryError::Shape)?,
            )
            .copied()
            .ok_or(MutableMemoryError::Shape)?;
        if actual != expected {
            return Err(MutableMemoryError::Unsatisfied);
        }
    }
    Ok(())
}
