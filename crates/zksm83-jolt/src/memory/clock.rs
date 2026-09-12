use akita_pcs::Transcript;

use crate::{
    NativeField, TRACE_ROW_BIT_COUNT, TRACE_ROW_BITS_START, UNIFORM_NUM_VARIABLES,
    WitnessCommitments,
    pcs::OpeningProof,
    uniform::{CommittedWitness, prove_witness_opening, verify_witness_opening},
};

use super::{MutableMemoryError, push_bytes, transcript};

const CLOCK_DOMAIN: &[u8] = b"zksm83-native-memory-fixed-clock/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClockProof {
    pub(crate) values: Vec<NativeField>,
    pub(crate) opening: OpeningProof,
}

pub(super) fn prove(
    trace: &CommittedWitness,
    phase_one: &[u8],
) -> Result<ClockProof, MutableMemoryError> {
    let descriptor = descriptor(phase_one)?;
    let point = point(&descriptor);
    let values = trace
        .field_columns()
        .iter()
        .map(|column| super::evaluate_field_column(column, &point))
        .collect::<Result<Vec<_>, _>>()?;
    check_row_bits(&values, &point)?;
    let opening = prove_witness_opening(trace, &point, &values, &descriptor)?;
    Ok(ClockProof { values, opening })
}

pub(super) fn verify(
    trace: &WitnessCommitments,
    phase_one: &[u8],
    proof: &ClockProof,
) -> Result<(), MutableMemoryError> {
    let descriptor = descriptor(phase_one)?;
    let point = point(&descriptor);
    verify_witness_opening(trace, &point, &proof.values, &descriptor, &proof.opening)?;
    check_row_bits(&proof.values, &point)
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

fn check_row_bits(values: &[NativeField], point: &[NativeField]) -> Result<(), MutableMemoryError> {
    if point.len() != TRACE_ROW_BIT_COUNT {
        return Err(MutableMemoryError::Shape);
    }
    for (bit, expected) in point.iter().copied().enumerate() {
        let actual = values
            .get(TRACE_ROW_BITS_START + bit)
            .copied()
            .ok_or(MutableMemoryError::Shape)?;
        if actual != expected {
            return Err(MutableMemoryError::Unsatisfied);
        }
    }
    Ok(())
}
