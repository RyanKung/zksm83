use std::sync::Arc;

use akita_pcs::{AkitaTranscript, Ring, Transcript};

use crate::{
    NativeField, NativeProverBackend,
    field_batch::{FieldBatchError, SelectedDenominator, selected_inverse_columns},
    pcs::{
        ColumnCommitments, CommittedColumns, OpeningProof, prove_opening_with_backend,
        verify_opening_with_backend,
    },
    sumcheck::{SumOfProductsSumcheckProof, SumcheckFactor},
};

use super::{
    CommittedMemory, CommittedMemoryColumns, MEMORY_IMAGE_BYTES, MEMORY_LAYOUT,
    MEMORY_TABLE_NUM_VARIABLES, MemoryChallenges, MemoryCommitment, MutableMemoryError,
    address_evaluation, equality_evaluation, equality_evaluations, join_limbs, push_bytes,
    split_field,
};

const BOUNDARY_DOMAIN: &[u8] = b"zksm83-native-memory-boundary-inverses/v1";
const TERM_COUNT: usize = 4;
const FACTOR_COUNT: usize = 3;

type LimbColumns = Vec<Vec<u64>>;
type InverseColumns = (LimbColumns, LimbColumns);
type SumcheckTerms<'a> = Vec<Vec<SumcheckFactor<'a>>>;

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
    backend: &NativeProverBackend,
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
        SumOfProductsSumcheckProof::prove_shared_first(terms, backend, &mut transcript)?;
    if claim != NativeField::from_u64(0) {
        return Err(MutableMemoryError::Unsatisfied);
    }
    let initial_value = open_columns(&initial.inner, &opening_point, &descriptor, backend)?;
    let final_value = open_columns(&final_memory.inner, &opening_point, &descriptor, backend)?;
    let final_timestamp = open_columns(&timestamps.inner, &opening_point, &descriptor, backend)?;
    let initial_inverse =
        open_columns(&initial_inverse.inner, &opening_point, &descriptor, backend)?;
    let final_inverse = open_columns(&final_inverse.inner, &opening_point, &descriptor, backend)?;
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
    backend: &NativeProverBackend,
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
        backend,
    )?;
    verify_columns(
        &final_memory.inner,
        &opening_point,
        &descriptor,
        &proof.final_value,
        backend,
    )?;
    verify_columns(
        timestamps,
        &opening_point,
        &descriptor,
        &proof.final_timestamp,
        backend,
    )?;
    verify_columns(
        initial_inverse,
        &opening_point,
        &descriptor,
        &proof.initial_inverse,
        backend,
    )?;
    verify_columns(
        final_inverse,
        &opening_point,
        &descriptor,
        &proof.final_inverse,
        backend,
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
    let one = NativeField::from_u64(1);
    let columns = selected_inverse_columns(
        MEMORY_IMAGE_BYTES,
        |address| {
            let address_field = NativeField::from_u64(
                u64::try_from(address).map_err(|_| MutableMemoryError::Shape)?,
            );
            let initial_token = address_field + challenges.alpha * at(initial_values, address)?;
            let final_token = address_field
                + challenges.alpha * at(final_values, address)?
                + alpha_squared * at(final_timestamps, address)?;
            Ok::<_, MutableMemoryError>((
                [
                    SelectedDenominator::new(one, challenges.beta - initial_token),
                    SelectedDenominator::new(one, challenges.beta - final_token),
                ],
                (),
            ))
        },
        |[initial_inverse, final_inverse], ()| {
            let [initial_low, initial_high] = split_field(initial_inverse.value())?;
            let [final_low, final_high] = split_field(final_inverse.value())?;
            Ok::<_, MutableMemoryError>([initial_low, initial_high, final_low, final_high])
        },
        map_batch_error,
    )?;
    let mut columns = columns.into_iter();
    let initial = vec![
        columns.next().ok_or(MutableMemoryError::Shape)?,
        columns.next().ok_or(MutableMemoryError::Shape)?,
    ];
    let final_memory = vec![
        columns.next().ok_or(MutableMemoryError::Shape)?,
        columns.next().ok_or(MutableMemoryError::Shape)?,
    ];
    if columns.next().is_some() {
        return Err(MutableMemoryError::Shape);
    }
    Ok((initial, final_memory))
}

fn map_batch_error(error: FieldBatchError) -> MutableMemoryError {
    match error {
        FieldBatchError::Shape => MutableMemoryError::Shape,
        FieldBatchError::ZeroDenominator => MutableMemoryError::ZeroDenominator,
    }
}

fn relation_terms<'a>(
    columns: RelationColumns<'a>,
    challenges: MemoryChallenges,
    row_point: &[NativeField],
    mix: NativeField,
) -> Result<SumcheckTerms<'a>, MutableMemoryError> {
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
    let weight = Arc::from(equality_evaluations(row_point));
    let one = NativeField::from_u64(1);
    let alpha_squared = challenges.alpha * challenges.alpha;
    Ok(vec![
        term(
            &weight,
            SumcheckFactor::linear_combination(
                vec![(columns.initial, -challenges.alpha)],
                -one,
                challenges.beta,
                MEMORY_IMAGE_BYTES,
            ),
            SumcheckFactor::borrowed(columns.initial_inverse),
        ),
        term(
            &weight,
            SumcheckFactor::constant(-one, MEMORY_IMAGE_BYTES),
            SumcheckFactor::constant(one, MEMORY_IMAGE_BYTES),
        ),
        term(
            &weight,
            SumcheckFactor::linear_combination(
                vec![
                    (columns.final_memory, -(mix * challenges.alpha)),
                    (columns.timestamps, -(mix * alpha_squared)),
                ],
                -mix,
                mix * challenges.beta,
                MEMORY_IMAGE_BYTES,
            ),
            SumcheckFactor::borrowed(columns.final_inverse),
        ),
        term(
            &weight,
            SumcheckFactor::constant(-mix, MEMORY_IMAGE_BYTES),
            SumcheckFactor::constant(one, MEMORY_IMAGE_BYTES),
        ),
    ])
}

fn term<'a>(
    weight: &Arc<[NativeField]>,
    middle: SumcheckFactor<'a>,
    right: SumcheckFactor<'a>,
) -> Vec<SumcheckFactor<'a>> {
    vec![SumcheckFactor::shared(Arc::clone(weight)), middle, right]
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
        vec![
            weight,
            challenges.beta - address - challenges.alpha * initial,
            initial_inverse,
        ],
        vec![weight, -one, one],
        vec![
            weight,
            mix * (challenges.beta
                - address
                - challenges.alpha * final_memory
                - alpha_squared * timestamp),
            final_inverse,
        ],
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
    backend: &NativeProverBackend,
) -> Result<ColumnOpening, MutableMemoryError> {
    let field_columns = columns.field_columns()?;
    let values = field_columns
        .as_slice()
        .iter()
        .map(|column| super::evaluate_field_column(column, point))
        .collect::<Result<Vec<_>, _>>()?;
    let proof =
        prove_opening_with_backend(MEMORY_LAYOUT, columns, point, &values, descriptor, backend)?;
    Ok(ColumnOpening { values, proof })
}

fn verify_columns(
    commitment: &ColumnCommitments,
    point: &[NativeField],
    descriptor: &[u8],
    opening: &ColumnOpening,
    backend: &NativeProverBackend,
) -> Result<(), MutableMemoryError> {
    verify_opening_with_backend(
        MEMORY_LAYOUT,
        commitment,
        point,
        &opening.values,
        descriptor,
        &opening.proof,
        backend,
    )?;
    Ok(())
}

fn one_column(columns: &CommittedColumns) -> Result<&[NativeField], MutableMemoryError> {
    if columns.commitments().column_count() != 1 {
        return Err(MutableMemoryError::Shape);
    }
    columns.field_column(0).map_err(Into::into)
}

fn joined_columns(columns: &CommittedColumns) -> Result<Vec<NativeField>, MutableMemoryError> {
    if columns.commitments().column_count() != 2 {
        return Err(MutableMemoryError::Shape);
    }
    let low = columns.field_column(0)?;
    let high = columns.field_column(1)?;
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
