use akita_pcs::{AkitaTranscript, Ring, Transcript};

use crate::{
    NativeField,
    pcs::{ColumnCommitments, CommittedColumns, OpeningProof, prove_opening, verify_opening},
    sumcheck::SumOfProductsSumcheckProof,
};

use super::{
    CommittedMemory, CommittedMemoryColumns, MEMORY_IMAGE_BYTES, MEMORY_LAYOUT,
    MEMORY_TABLE_NUM_VARIABLES, MemoryChallenges, MemoryCommitment, MutableMemoryError,
    address_evaluation, equality_evaluation, equality_evaluations, join_limbs, push_bytes,
    split_field,
};

const BOUNDARY_DOMAIN: &[u8] = b"zksm83-native-memory-boundary-inverses/v1";
const TERM_COUNT: usize = 9;
const FACTOR_COUNT: usize = 3;

type LimbColumns = Vec<Vec<u64>>;
type InverseColumns = (LimbColumns, LimbColumns);
type SumcheckTerms = Vec<Vec<Vec<NativeField>>>;

struct RelationColumns<'a> {
    initial: &'a [NativeField],
    final_memory: &'a [NativeField],
    timestamps: &'a [NativeField],
    initial_inverse: &'a [NativeField],
    final_inverse: &'a [NativeField],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BoundaryProof {
    pub(crate) sumcheck: SumOfProductsSumcheckProof,
    pub(crate) initial_value: ColumnOpening,
    pub(crate) final_value: ColumnOpening,
    pub(crate) final_timestamp: ColumnOpening,
    pub(crate) initial_inverse: ColumnOpening,
    pub(crate) final_inverse: ColumnOpening,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ColumnOpening {
    pub(crate) values: Vec<NativeField>,
    pub(crate) proof: OpeningProof,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn prove(
    initial: &CommittedMemory,
    final_memory: &CommittedMemory,
    timestamps: &CommittedMemoryColumns,
    initial_inverse: &CommittedMemoryColumns,
    final_inverse: &CommittedMemoryColumns,
    challenges: MemoryChallenges,
    full_descriptor: &[u8],
) -> Result<BoundaryProof, MutableMemoryError> {
    let descriptor = descriptor(full_descriptor)?;
    let mut transcript = relation_transcript(&descriptor, TranscriptSide::Prover);
    let row_point = sample_point(&mut transcript);
    let mix = transcript.challenge_scalar(b"boundary-constraint-mix");
    if mix == NativeField::from_u64(0) {
        return Err(MutableMemoryError::ZeroChallenge);
    }
    let initial_inverse_values = joined_columns(&initial_inverse.inner)?;
    let final_inverse_values = joined_columns(&final_inverse.inner)?;
    let terms = relation_terms(
        RelationColumns {
            initial: one_column(&initial.inner)?,
            final_memory: one_column(&final_memory.inner)?,
            timestamps: one_column(&timestamps.inner)?,
            initial_inverse: &initial_inverse_values,
            final_inverse: &final_inverse_values,
        },
        challenges,
        &row_point,
        mix,
    )?;
    let (sumcheck, claim, opening_point) =
        SumOfProductsSumcheckProof::prove(&terms, &mut transcript)?;
    if claim != NativeField::from_u64(0) {
        return Err(MutableMemoryError::Unsatisfied);
    }
    let initial_value = open_columns(&initial.inner, &opening_point, &descriptor)?;
    let final_value = open_columns(&final_memory.inner, &opening_point, &descriptor)?;
    let final_timestamp = open_columns(&timestamps.inner, &opening_point, &descriptor)?;
    let initial_inverse = open_columns(&initial_inverse.inner, &opening_point, &descriptor)?;
    let final_inverse = open_columns(&final_inverse.inner, &opening_point, &descriptor)?;
    check_terminal(
        &sumcheck,
        &row_point,
        &opening_point,
        challenges,
        mix,
        opened_values(
            &initial_value,
            &final_value,
            &final_timestamp,
            &initial_inverse,
            &final_inverse,
        )?,
    )?;
    Ok(BoundaryProof {
        sumcheck,
        initial_value,
        final_value,
        final_timestamp,
        initial_inverse,
        final_inverse,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify(
    initial: &MemoryCommitment,
    final_memory: &MemoryCommitment,
    timestamps: &ColumnCommitments,
    initial_inverse: &ColumnCommitments,
    final_inverse: &ColumnCommitments,
    challenges: MemoryChallenges,
    full_descriptor: &[u8],
    proof: &BoundaryProof,
) -> Result<(), MutableMemoryError> {
    let descriptor = descriptor(full_descriptor)?;
    let mut transcript = relation_transcript(&descriptor, TranscriptSide::Verifier);
    let row_point = sample_point(&mut transcript);
    let mix = transcript.challenge_scalar(b"boundary-constraint-mix");
    if mix == NativeField::from_u64(0) {
        return Err(MutableMemoryError::ZeroChallenge);
    }
    let opening_point = proof.sumcheck.verify(
        NativeField::from_u64(0),
        MEMORY_TABLE_NUM_VARIABLES,
        TERM_COUNT,
        FACTOR_COUNT,
        &mut transcript,
    )?;
    verify_columns(
        &initial.inner,
        &opening_point,
        &descriptor,
        &proof.initial_value,
    )?;
    verify_columns(
        &final_memory.inner,
        &opening_point,
        &descriptor,
        &proof.final_value,
    )?;
    verify_columns(
        timestamps,
        &opening_point,
        &descriptor,
        &proof.final_timestamp,
    )?;
    verify_columns(
        initial_inverse,
        &opening_point,
        &descriptor,
        &proof.initial_inverse,
    )?;
    verify_columns(
        final_inverse,
        &opening_point,
        &descriptor,
        &proof.final_inverse,
    )?;
    check_terminal(
        &proof.sumcheck,
        &row_point,
        &opening_point,
        challenges,
        mix,
        opened_values(
            &proof.initial_value,
            &proof.final_value,
            &proof.final_timestamp,
            &proof.initial_inverse,
            &proof.final_inverse,
        )?,
    )
}

pub(super) fn inverse_columns(
    initial: &CommittedMemory,
    final_memory: &CommittedMemory,
    timestamps: &CommittedMemoryColumns,
    challenges: MemoryChallenges,
) -> Result<InverseColumns, MutableMemoryError> {
    let initial_values = one_column(&initial.inner)?;
    let final_values = one_column(&final_memory.inner)?;
    let final_timestamps = one_column(&timestamps.inner)?;
    let alpha_squared = challenges.alpha * challenges.alpha;
    let mut initial_limbs = (0..2)
        .map(|_| Vec::with_capacity(MEMORY_IMAGE_BYTES))
        .collect::<Vec<_>>();
    let mut final_limbs = (0..2)
        .map(|_| Vec::with_capacity(MEMORY_IMAGE_BYTES))
        .collect::<Vec<_>>();
    for address in 0..MEMORY_IMAGE_BYTES {
        let address_field =
            NativeField::from_u64(u64::try_from(address).map_err(|_| MutableMemoryError::Shape)?);
        let initial_token = address_field + challenges.alpha * at(initial_values, address)?;
        let final_token = address_field
            + challenges.alpha * at(final_values, address)?
            + alpha_squared * at(final_timestamps, address)?;
        push_limbs(
            &mut initial_limbs,
            split_field(super::inverse(challenges.beta - initial_token)?)?,
        )?;
        push_limbs(
            &mut final_limbs,
            split_field(super::inverse(challenges.beta - final_token)?)?,
        )?;
    }
    Ok((initial_limbs, final_limbs))
}

fn relation_terms(
    columns: RelationColumns<'_>,
    challenges: MemoryChallenges,
    row_point: &[NativeField],
    mix: NativeField,
) -> Result<SumcheckTerms, MutableMemoryError> {
    for column in [
        columns.initial,
        columns.final_memory,
        columns.timestamps,
        columns.initial_inverse,
        columns.final_inverse,
    ] {
        if column.len() != MEMORY_IMAGE_BYTES {
            return Err(MutableMemoryError::Shape);
        }
    }
    let weight = equality_evaluations(row_point);
    let address = (0..MEMORY_IMAGE_BYTES)
        .map(|value| {
            u64::try_from(value)
                .map(NativeField::from_u64)
                .map_err(|_| MutableMemoryError::Shape)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let one = vec![NativeField::from_u64(1); MEMORY_IMAGE_BYTES];
    let alpha_squared = challenges.alpha * challenges.alpha;
    Ok(vec![
        term(&weight, constant(challenges.beta), columns.initial_inverse),
        term(
            &weight,
            scaled(&address, -NativeField::from_u64(1)),
            columns.initial_inverse,
        ),
        term(
            &weight,
            scaled(columns.initial, -challenges.alpha),
            columns.initial_inverse,
        ),
        term(&weight, constant(-NativeField::from_u64(1)), &one),
        term(
            &weight,
            constant(mix * challenges.beta),
            columns.final_inverse,
        ),
        term(&weight, scaled(&address, -mix), columns.final_inverse),
        term(
            &weight,
            scaled(columns.final_memory, -(mix * challenges.alpha)),
            columns.final_inverse,
        ),
        term(
            &weight,
            scaled(columns.timestamps, -(mix * alpha_squared)),
            columns.final_inverse,
        ),
        term(&weight, constant(-mix), &one),
    ])
}

fn term(
    weight: &[NativeField],
    middle: Vec<NativeField>,
    right: &[NativeField],
) -> Vec<Vec<NativeField>> {
    vec![weight.to_vec(), middle, right.to_vec()]
}

fn constant(value: NativeField) -> Vec<NativeField> {
    vec![value; MEMORY_IMAGE_BYTES]
}

fn scaled(values: &[NativeField], scale: NativeField) -> Vec<NativeField> {
    values.iter().map(|value| scale * *value).collect()
}

fn check_terminal(
    proof: &SumOfProductsSumcheckProof,
    row_point: &[NativeField],
    opening_point: &[NativeField],
    challenges: MemoryChallenges,
    mix: NativeField,
    values: [NativeField; 5],
) -> Result<(), MutableMemoryError> {
    let [
        initial,
        final_memory,
        timestamp,
        initial_inverse,
        final_inverse,
    ] = values;
    let weight = equality_evaluation(row_point, opening_point)?;
    let address = address_evaluation(opening_point)?;
    let one = NativeField::from_u64(1);
    let alpha_squared = challenges.alpha * challenges.alpha;
    let expected = vec![
        vec![weight, challenges.beta, initial_inverse],
        vec![weight, -address, initial_inverse],
        vec![weight, -challenges.alpha * initial, initial_inverse],
        vec![weight, -one, one],
        vec![weight, mix * challenges.beta, final_inverse],
        vec![weight, -mix * address, final_inverse],
        vec![
            weight,
            -mix * challenges.alpha * final_memory,
            final_inverse,
        ],
        vec![weight, -mix * alpha_squared * timestamp, final_inverse],
        vec![weight, -mix, one],
    ];
    if proof.final_terms() != expected {
        return Err(MutableMemoryError::Unsatisfied);
    }
    Ok(())
}

fn opened_values(
    initial: &ColumnOpening,
    final_memory: &ColumnOpening,
    timestamp: &ColumnOpening,
    initial_inverse: &ColumnOpening,
    final_inverse: &ColumnOpening,
) -> Result<[NativeField; 5], MutableMemoryError> {
    Ok([
        single(initial)?,
        single(final_memory)?,
        single(timestamp)?,
        joined_opening(initial_inverse)?,
        joined_opening(final_inverse)?,
    ])
}

fn open_columns(
    columns: &CommittedColumns,
    point: &[NativeField],
    descriptor: &[u8],
) -> Result<ColumnOpening, MutableMemoryError> {
    let values = columns
        .field_columns()
        .iter()
        .map(|column| super::evaluate_field_column(column, point))
        .collect::<Result<Vec<_>, _>>()?;
    let proof = prove_opening(MEMORY_LAYOUT, columns, point, &values, descriptor)?;
    Ok(ColumnOpening { values, proof })
}

fn verify_columns(
    commitment: &ColumnCommitments,
    point: &[NativeField],
    descriptor: &[u8],
    opening: &ColumnOpening,
) -> Result<(), MutableMemoryError> {
    verify_opening(
        MEMORY_LAYOUT,
        commitment,
        point,
        &opening.values,
        descriptor,
        &opening.proof,
    )?;
    Ok(())
}

fn one_column(columns: &CommittedColumns) -> Result<&[NativeField], MutableMemoryError> {
    if columns.field_columns().len() != 1 {
        return Err(MutableMemoryError::Shape);
    }
    columns
        .field_columns()
        .first()
        .map(Vec::as_slice)
        .ok_or(MutableMemoryError::Shape)
}

fn joined_columns(columns: &CommittedColumns) -> Result<Vec<NativeField>, MutableMemoryError> {
    if columns.field_columns().len() != 2 {
        return Err(MutableMemoryError::Shape);
    }
    let low = columns
        .field_columns()
        .first()
        .ok_or(MutableMemoryError::Shape)?;
    let high = columns
        .field_columns()
        .get(1)
        .ok_or(MutableMemoryError::Shape)?;
    if low.len() != high.len() {
        return Err(MutableMemoryError::Shape);
    }
    Ok(low
        .iter()
        .copied()
        .zip(high.iter().copied())
        .map(|(low, high)| join_limbs(low, high))
        .collect())
}

fn single(opening: &ColumnOpening) -> Result<NativeField, MutableMemoryError> {
    if opening.values.len() != 1 {
        return Err(MutableMemoryError::Shape);
    }
    opening
        .values
        .first()
        .copied()
        .ok_or(MutableMemoryError::Shape)
}

fn joined_opening(opening: &ColumnOpening) -> Result<NativeField, MutableMemoryError> {
    if opening.values.len() != 2 {
        return Err(MutableMemoryError::Shape);
    }
    Ok(join_limbs(
        opening
            .values
            .first()
            .copied()
            .ok_or(MutableMemoryError::Shape)?,
        opening
            .values
            .get(1)
            .copied()
            .ok_or(MutableMemoryError::Shape)?,
    ))
}

fn push_limbs(columns: &mut [Vec<u64>], limbs: [u64; 2]) -> Result<(), MutableMemoryError> {
    for (column, limb) in columns.iter_mut().zip(limbs) {
        column.push(limb);
    }
    if columns.len() != 2 {
        return Err(MutableMemoryError::Shape);
    }
    Ok(())
}

fn at(values: &[NativeField], index: usize) -> Result<NativeField, MutableMemoryError> {
    values.get(index).copied().ok_or(MutableMemoryError::Shape)
}

fn descriptor(full: &[u8]) -> Result<Vec<u8>, MutableMemoryError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, BOUNDARY_DOMAIN)?;
    push_bytes(&mut descriptor, full)?;
    Ok(descriptor)
}

enum TranscriptSide {
    Prover,
    Verifier,
}

fn relation_transcript(descriptor: &[u8], side: TranscriptSide) -> AkitaTranscript<NativeField> {
    let mut transcript = match side {
        TranscriptSide::Prover => AkitaTranscript::unbound_prover(BOUNDARY_DOMAIN),
        TranscriptSide::Verifier => AkitaTranscript::unbound_verifier(BOUNDARY_DOMAIN),
    };
    transcript.bind_instance_bytes(descriptor);
    transcript
}

fn sample_point(transcript: &mut AkitaTranscript<NativeField>) -> Vec<NativeField> {
    (0..MEMORY_TABLE_NUM_VARIABLES)
        .map(|_| transcript.challenge_scalar(b"boundary-row-point"))
        .collect()
}
