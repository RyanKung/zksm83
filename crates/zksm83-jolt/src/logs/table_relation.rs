use std::sync::Arc;

use akita_pcs::{Ring, Transcript};

use crate::{
    NativeField,
    field_batch::{FieldBatchError, SelectedDenominator, selected_inverse_columns},
    pcs::{ColumnCommitments, CommittedColumns, OpeningProof, prove_opening, verify_opening},
    sumcheck::{SumOfProductsSumcheckProof, SumcheckFactor},
};

use super::{
    BUS_START, BUS_WIDTH, BYTE_LOG_WIDTH, CommittedLogColumns, INPUT_START, ISA_START, ISA_WIDTH,
    LOG_COLUMN_COUNT, LOG_KIND_COUNT, LOG_LAYOUT, LogChallenges, LogKind, OUTPUT_START,
    PROTOCOL_LOG_NUM_VARIABLES, PROTOCOL_LOG_ROW_COUNT, ProtocolLogError,
    TABLE_INVERSE_COLUMN_COUNT, equality_evaluation, equality_evaluations, field_column,
    join_limbs, push_bytes, split_field, transcript,
};

const RELATION_DOMAIN: &[u8] = b"zksm83-native-protocol-log-table-relation/v1";
const TERM_COUNT: usize = 27;
const FACTOR_COUNT: usize = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TableRelationProof {
    pub(crate) sumcheck: SumOfProductsSumcheckProof,
    pub(crate) logs: ColumnOpening,
    pub(crate) inverses: ColumnOpening,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ColumnOpening {
    pub(crate) values: Vec<NativeField>,
    pub(crate) proof: OpeningProof,
}

pub(super) fn prove(
    logs: &CommittedColumns,
    inverses: &CommittedLogColumns,
    challenges: LogChallenges,
    full_descriptor: &[u8],
) -> Result<TableRelationProof, ProtocolLogError> {
    let descriptor = descriptor(full_descriptor)?;
    let mut transcript = transcript(RELATION_DOMAIN, &descriptor);
    let row_point = sample_point(&mut transcript);
    let mix = transcript.challenge_scalar(b"constraint-mix");
    if mix == NativeField::from_u64(0) {
        return Err(ProtocolLogError::ZeroChallenge);
    }
    let terms = relation_terms(logs, &inverses.inner, challenges, &row_point, mix)?;
    let (sumcheck, claim, opening_point) =
        SumOfProductsSumcheckProof::prove_shared_first(terms, &mut transcript)?;
    if claim != NativeField::from_u64(0) {
        return Err(ProtocolLogError::Unsatisfied);
    }
    let logs = open_columns(logs, &opening_point, &descriptor)?;
    let inverses = open_columns(&inverses.inner, &opening_point, &descriptor)?;
    check_terminal(
        &sumcheck,
        &row_point,
        &opening_point,
        &logs.values,
        &inverses.values,
        challenges,
        mix,
    )?;
    Ok(TableRelationProof {
        sumcheck,
        logs,
        inverses,
    })
}

pub(super) fn verify(
    logs: &ColumnCommitments,
    inverses: &ColumnCommitments,
    challenges: LogChallenges,
    full_descriptor: &[u8],
    proof: &TableRelationProof,
) -> Result<(), ProtocolLogError> {
    let descriptor = descriptor(full_descriptor)?;
    let mut transcript = transcript(RELATION_DOMAIN, &descriptor);
    let row_point = sample_point(&mut transcript);
    let mix = transcript.challenge_scalar(b"constraint-mix");
    if mix == NativeField::from_u64(0) {
        return Err(ProtocolLogError::ZeroChallenge);
    }
    let opening_point = proof.sumcheck.verify(
        NativeField::from_u64(0),
        PROTOCOL_LOG_NUM_VARIABLES,
        TERM_COUNT,
        FACTOR_COUNT,
        &mut transcript,
    )?;
    verify_columns(logs, &opening_point, &descriptor, &proof.logs)?;
    verify_columns(inverses, &opening_point, &descriptor, &proof.inverses)?;
    check_terminal(
        &proof.sumcheck,
        &row_point,
        &opening_point,
        &proof.logs.values,
        &proof.inverses.values,
        challenges,
        mix,
    )
}

pub(super) fn inverse_columns(
    logs: &CommittedColumns,
    challenges: LogChallenges,
) -> Result<Vec<Vec<u64>>, ProtocolLogError> {
    if logs.commitments().column_count() != LOG_COLUMN_COUNT {
        return Err(ProtocolLogError::Shape);
    }
    selected_inverse_columns(
        PROTOCOL_LOG_ROW_COUNT,
        |row| Ok((table_inverse_row(logs, challenges, row)?, ())),
        |inverses, ()| table_inverse_limb_row(inverses),
        map_batch_error,
    )
}

fn table_inverse_row(
    logs: &CommittedColumns,
    challenges: LogChallenges,
    row: usize,
) -> Result<[SelectedDenominator; LOG_KIND_COUNT], ProtocolLogError> {
    let zero = NativeField::from_u64(0);
    let mut entries = [SelectedDenominator::new(zero, zero); LOG_KIND_COUNT];
    for (entry, (kind, start, width)) in layouts().into_iter().enumerate() {
        let selector = field_value(logs, start, row)?;
        let token = compress_table(logs, start, width, row, challenges.mix(kind))?;
        *entries.get_mut(entry).ok_or(ProtocolLogError::Shape)? =
            SelectedDenominator::new(selector, challenges.point(kind) - token);
    }
    Ok(entries)
}

fn table_inverse_limb_row(
    inverses: [SelectedDenominator; LOG_KIND_COUNT],
) -> Result<[u64; TABLE_INVERSE_COLUMN_COUNT], ProtocolLogError> {
    let mut limbs = [0_u64; TABLE_INVERSE_COLUMN_COUNT];
    for (kind, inverse) in inverses.into_iter().enumerate() {
        let [low, high] = split_field(inverse.value())?;
        let offset = kind.checked_mul(2).ok_or(ProtocolLogError::Shape)?;
        *limbs.get_mut(offset).ok_or(ProtocolLogError::Shape)? = low;
        *limbs.get_mut(offset + 1).ok_or(ProtocolLogError::Shape)? = high;
    }
    Ok(limbs)
}

fn map_batch_error(error: FieldBatchError) -> ProtocolLogError {
    match error {
        FieldBatchError::Shape => ProtocolLogError::Shape,
        FieldBatchError::ZeroDenominator => ProtocolLogError::ZeroDenominator,
    }
}

fn relation_terms<'a>(
    logs: &'a CommittedColumns,
    inverses: &'a CommittedColumns,
    challenges: LogChallenges,
    row_point: &[NativeField],
    mix: NativeField,
) -> Result<Vec<Vec<SumcheckFactor<'a>>>, ProtocolLogError> {
    if logs.commitments().column_count() != LOG_COLUMN_COUNT
        || inverses.commitments().column_count() != TABLE_INVERSE_COLUMN_COUNT
    {
        return Err(ProtocolLogError::Shape);
    }
    let weight = Arc::from(equality_evaluations(row_point));
    let mut terms = Vec::with_capacity(TERM_COUNT);
    let mut scale = NativeField::from_u64(1);
    for (kind, start, width) in layouts() {
        let selector = field_column(logs, start)?;
        let inverse = Arc::from(joined_inverse_columns(inverses, kind)?);
        push_boolean_terms(&mut terms, &weight, selector, scale);
        scale *= mix;
        for column in start + 1..start + width {
            let data = field_column(logs, column)?;
            push_inactive_terms(&mut terms, &weight, selector, data, scale);
            scale *= mix;
        }
        push_inverse_terms(
            &mut terms,
            RelationVectors {
                weight: Arc::clone(&weight),
                selector,
                data: table_data(logs, start, width)?,
                inverse,
            },
            challenges,
            kind,
            scale,
        );
        scale *= mix;
    }
    if terms.len() != TERM_COUNT {
        return Err(ProtocolLogError::Shape);
    }
    Ok(terms)
}

struct RelationVectors<'a> {
    weight: Arc<[NativeField]>,
    selector: &'a [NativeField],
    data: Vec<&'a [NativeField]>,
    inverse: Arc<[NativeField]>,
}

fn push_boolean_terms<'a>(
    terms: &mut Vec<Vec<SumcheckFactor<'a>>>,
    weight: &Arc<[NativeField]>,
    selector: &'a [NativeField],
    scale: NativeField,
) {
    terms.push(term(
        weight,
        SumcheckFactor::scaled(selector, scale),
        SumcheckFactor::affine(
            selector,
            NativeField::from_u64(1),
            -NativeField::from_u64(1),
        ),
    ));
}

fn push_inactive_terms<'a>(
    terms: &mut Vec<Vec<SumcheckFactor<'a>>>,
    weight: &Arc<[NativeField]>,
    selector: &'a [NativeField],
    data: &'a [NativeField],
    scale: NativeField,
) {
    terms.push(term(
        weight,
        SumcheckFactor::scaled(data, scale),
        SumcheckFactor::affine(
            selector,
            -NativeField::from_u64(1),
            NativeField::from_u64(1),
        ),
    ));
}

fn push_inverse_terms<'a>(
    terms: &mut Vec<Vec<SumcheckFactor<'a>>>,
    vectors: RelationVectors<'a>,
    challenges: LogChallenges,
    kind: LogKind,
    scale: NativeField,
) {
    let mut sources = Vec::with_capacity(vectors.data.len());
    let mut power = NativeField::from_u64(1);
    for data in vectors.data {
        sources.push((data, -(scale * power)));
        power *= challenges.mix(kind);
    }
    terms.push(term(
        &vectors.weight,
        SumcheckFactor::linear_combination(
            sources,
            NativeField::from_u64(0),
            scale * challenges.point(kind),
            PROTOCOL_LOG_ROW_COUNT,
        ),
        SumcheckFactor::shared(Arc::clone(&vectors.inverse)),
    ));
    terms.push(term(
        &vectors.weight,
        SumcheckFactor::scaled(vectors.selector, -scale),
        SumcheckFactor::constant(NativeField::from_u64(1), PROTOCOL_LOG_ROW_COUNT),
    ));
}

#[allow(clippy::too_many_arguments)]
fn check_terminal(
    proof: &SumOfProductsSumcheckProof,
    row_point: &[NativeField],
    opening_point: &[NativeField],
    logs: &[NativeField],
    inverses: &[NativeField],
    challenges: LogChallenges,
    mix: NativeField,
) -> Result<(), ProtocolLogError> {
    if logs.len() != LOG_COLUMN_COUNT || inverses.len() != TABLE_INVERSE_COLUMN_COUNT {
        return Err(ProtocolLogError::Shape);
    }
    let weight = equality_evaluation(row_point, opening_point)?;
    let one = NativeField::from_u64(1);
    let mut terms = Vec::with_capacity(TERM_COUNT);
    let mut scale = one;
    for (kind, start, width) in layouts() {
        let selector = scalar(logs, start)?;
        let inverse = joined_inverse_values(inverses, kind)?;
        terms.push(vec![weight, scale * selector, selector - one]);
        for column in start + 1..start + width {
            let data = scalar(logs, column)?;
            scale *= mix;
            terms.push(vec![weight, scale * data, one - selector]);
        }
        scale *= mix;
        let mut token = NativeField::from_u64(0);
        let mut power = one;
        for column in start + 1..start + width {
            token += power * scalar(logs, column)?;
            power *= challenges.mix(kind);
        }
        terms.push(vec![
            weight,
            scale * (challenges.point(kind) - token),
            inverse,
        ]);
        terms.push(vec![weight, -scale * selector, one]);
        scale *= mix;
    }
    if terms.len() != TERM_COUNT || proof.final_terms() != terms {
        return Err(ProtocolLogError::Unsatisfied);
    }
    Ok(())
}

fn joined_inverse_columns(
    inverses: &CommittedColumns,
    kind: LogKind,
) -> Result<Vec<NativeField>, ProtocolLogError> {
    let low = field_column(inverses, kind.index() * 2)?;
    let high = field_column(inverses, kind.index() * 2 + 1)?;
    if low.len() != high.len() {
        return Err(ProtocolLogError::Shape);
    }
    Ok(low
        .iter()
        .copied()
        .zip(high.iter().copied())
        .map(|(low, high)| join_limbs(low, high))
        .collect())
}

fn joined_inverse_values(
    inverses: &[NativeField],
    kind: LogKind,
) -> Result<NativeField, ProtocolLogError> {
    Ok(join_limbs(
        scalar(inverses, kind.index() * 2)?,
        scalar(inverses, kind.index() * 2 + 1)?,
    ))
}

fn compress_table(
    logs: &CommittedColumns,
    start: usize,
    width: usize,
    row: usize,
    mix: NativeField,
) -> Result<NativeField, ProtocolLogError> {
    let first = start.checked_add(1).ok_or(ProtocolLogError::Shape)?;
    let end = start.checked_add(width).ok_or(ProtocolLogError::Shape)?;
    let mut sum = NativeField::from_u64(0);
    let mut power = NativeField::from_u64(1);
    for column in first..end {
        sum += power * field_value(logs, column, row)?;
        power *= mix;
    }
    Ok(sum)
}

fn table_data(
    logs: &CommittedColumns,
    start: usize,
    width: usize,
) -> Result<Vec<&[NativeField]>, ProtocolLogError> {
    (start + 1..start + width)
        .map(|column| field_column(logs, column))
        .collect()
}

fn field_value(
    columns: &CommittedColumns,
    column: usize,
    row: usize,
) -> Result<NativeField, ProtocolLogError> {
    field_column(columns, column)?
        .get(row)
        .copied()
        .ok_or(ProtocolLogError::Shape)
}

fn open_columns(
    columns: &CommittedColumns,
    point: &[NativeField],
    descriptor: &[u8],
) -> Result<ColumnOpening, ProtocolLogError> {
    let field_columns = columns.field_columns()?;
    let values = field_columns
        .as_slice()
        .iter()
        .map(|column| super::evaluate_field_column(column, point))
        .collect::<Result<Vec<_>, _>>()?;
    let proof = prove_opening(LOG_LAYOUT, columns, point, &values, descriptor)?;
    Ok(ColumnOpening { values, proof })
}

fn verify_columns(
    commitment: &ColumnCommitments,
    point: &[NativeField],
    descriptor: &[u8],
    opening: &ColumnOpening,
) -> Result<(), ProtocolLogError> {
    verify_opening(
        LOG_LAYOUT,
        commitment,
        point,
        &opening.values,
        descriptor,
        &opening.proof,
    )?;
    Ok(())
}

fn sample_point(transcript: &mut akita_pcs::AkitaTranscript<NativeField>) -> Vec<NativeField> {
    (0..PROTOCOL_LOG_NUM_VARIABLES)
        .map(|_| transcript.challenge_scalar(b"row-point"))
        .collect()
}

fn descriptor(full: &[u8]) -> Result<Vec<u8>, ProtocolLogError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, RELATION_DOMAIN)?;
    push_bytes(&mut descriptor, full)?;
    Ok(descriptor)
}

fn term<'a>(
    weight: &Arc<[NativeField]>,
    middle: SumcheckFactor<'a>,
    right: SumcheckFactor<'a>,
) -> Vec<SumcheckFactor<'a>> {
    vec![SumcheckFactor::shared(Arc::clone(weight)), middle, right]
}

fn scalar(values: &[NativeField], index: usize) -> Result<NativeField, ProtocolLogError> {
    values.get(index).copied().ok_or(ProtocolLogError::Shape)
}

const fn layouts() -> [(LogKind, usize, usize); LOG_KIND_COUNT] {
    [
        (LogKind::Bus, BUS_START, BUS_WIDTH),
        (LogKind::Input, INPUT_START, BYTE_LOG_WIDTH),
        (LogKind::Output, OUTPUT_START, BYTE_LOG_WIDTH),
        (LogKind::Isa, ISA_START, ISA_WIDTH),
    ]
}

impl LogKind {
    const fn index(self) -> usize {
        match self {
            Self::Bus => 0,
            Self::Input => 1,
            Self::Output => 2,
            Self::Isa => 3,
        }
    }
}
