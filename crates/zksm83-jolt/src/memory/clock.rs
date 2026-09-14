use akita_pcs::Transcript;

use crate::{
    NativeField, NativeProtocolVersion, TRACE_ROW_BIT_COUNT, UNIFORM_NUM_VARIABLES,
    WitnessCommitments,
    pcs::OpeningProof,
    uniform::{CommittedWitness, prove_witness_opening, verify_witness_opening_for_protocol},
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
) -> Result<ClockProof, MutableMemoryError> {
    let descriptor = descriptor(phase_one)?;
    let point = point(&descriptor);
    let columns = trace.field_columns()?;
    let values = columns
        .as_slice()
        .iter()
        .map(|column| super::evaluate_field_column(column, &point))
        .collect::<Result<Vec<_>, _>>()?;
    check_row_bits(&values, &point, row_bits_start)?;
    let opening = prove_witness_opening(trace, &point, &values, &descriptor)?;
    Ok(ClockProof { values, opening })
}

pub(super) fn verify_at(
    protocol: NativeProtocolVersion,
    trace: &WitnessCommitments,
    phase_one: &[u8],
    proof: &ClockProof,
    row_bits_start: usize,
) -> Result<(), MutableMemoryError> {
    let descriptor = descriptor(phase_one)?;
    let point = point(&descriptor);
    verify_witness_opening_for_protocol(
        protocol,
        trace,
        &point,
        &proof.values,
        &descriptor,
        &proof.opening,
    )?;
    check_row_bits(&proof.values, &point, row_bits_start)
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
