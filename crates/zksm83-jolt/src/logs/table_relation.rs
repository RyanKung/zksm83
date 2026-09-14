use akita_pcs::{Ring, Transcript};

use crate::{
    NativeField,
    pcs::{ColumnCommitments, CommittedColumns, OpeningProof, prove_opening, verify_opening},
    sumcheck::SumOfProductsSumcheckProof,
};

use super::{
    BUS_START, BUS_WIDTH, BYTE_LOG_WIDTH, CommittedLogColumns, INPUT_START, ISA_START, ISA_WIDTH,
    LOG_COLUMN_COUNT, LOG_KIND_COUNT, LOG_LAYOUT, LogChallenges, LogKind, OUTPUT_START,
    PROTOCOL_LOG_NUM_VARIABLES, PROTOCOL_LOG_ROW_COUNT, ProtocolLogError,
    TABLE_INVERSE_COLUMN_COUNT, equality_evaluation, equality_evaluations, field_column,
    join_limbs, push_bytes, push_inverse, transcript,
};

const RELATION_DOMAIN: &[u8] = b"zksm83-native-protocol-log-table-relation/v1";
const TERM_COUNT: usize = 61;
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
        SumOfProductsSumcheckProof::prove(&terms, &mut transcript)?;
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
    let mut columns = (0..TABLE_INVERSE_COLUMN_COUNT)
        .map(|_| Vec::with_capacity(PROTOCOL_LOG_ROW_COUNT))
        .collect::<Vec<_>>();
    for row in 0..PROTOCOL_LOG_ROW_COUNT {
        for (kind, start, width) in layouts() {
            let selector = field_value(logs, start, row)?;
            let token = compress_table(logs, start, width, row, challenges.mix(kind))?;
            let selected = if selector == NativeField::from_u64(0) {
                NativeField::from_u64(0)
            } else {
                selector * super::inverse(challenges.point(kind) - token)?
            };
            push_inverse(&mut columns, kind.index() * 2, selected)?;
        }
    }
    Ok(columns)
}

fn relation_terms(
    logs: &CommittedColumns,
    inverses: &CommittedColumns,
    challenges: LogChallenges,
    row_point: &[NativeField],
    mix: NativeField,
) -> Result<Vec<Vec<Vec<NativeField>>>, ProtocolLogError> {
    if logs.commitments().column_count() != LOG_COLUMN_COUNT
        || inverses.commitments().column_count() != TABLE_INVERSE_COLUMN_COUNT
    {
        return Err(ProtocolLogError::Shape);
    }
    let weight = equality_evaluations(row_point);
    let one = vec![NativeField::from_u64(1); PROTOCOL_LOG_ROW_COUNT];
    let mut terms = Vec::with_capacity(TERM_COUNT);
    let mut scale = NativeField::from_u64(1);
    for (kind, start, width) in layouts() {
        let selector = field_column(logs, start)?;
        let inverse = joined_inverse_columns(inverses, kind)?;
        push_boolean_terms(&mut terms, &weight, selector, &one, scale);
        scale *= mix;
        for column in start + 1..start + width {
            let data = field_column(logs, column)?;
            push_inactive_terms(&mut terms, &weight, selector, data, &one, scale);
            scale *= mix;
        }
        push_inverse_terms(
            &mut terms,
            RelationVectors {
                weight: &weight,
                selector,
                data: table_data(logs, start, width)?,
                inverse: &inverse,
                one: &one,
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
    weight: &'a [NativeField],
    selector: &'a [NativeField],
    data: Vec<&'a [NativeField]>,
    inverse: &'a [NativeField],
    one: &'a [NativeField],
}

fn push_boolean_terms(
    terms: &mut Vec<Vec<Vec<NativeField>>>,
    weight: &[NativeField],
    selector: &[NativeField],
    one: &[NativeField],
    scale: NativeField,
) {
    terms.push(term(weight, scaled(selector, scale), selector));
    terms.push(term(weight, scaled(selector, -scale), one));
}

fn push_inactive_terms(
    terms: &mut Vec<Vec<Vec<NativeField>>>,
    weight: &[NativeField],
    selector: &[NativeField],
    data: &[NativeField],
    one: &[NativeField],
    scale: NativeField,
) {
    terms.push(term(weight, scaled(data, scale), one));
    terms.push(term(weight, scaled(selector, -scale), data));
}

fn push_inverse_terms(
    terms: &mut Vec<Vec<Vec<NativeField>>>,
    vectors: RelationVectors<'_>,
    challenges: LogChallenges,
    kind: LogKind,
    scale: NativeField,
) {
    terms.push(term(
        vectors.weight,
        constant(scale * challenges.point(kind)),
        vectors.inverse,
    ));
    let mut power = NativeField::from_u64(1);
    for data in vectors.data {
        terms.push(term(
            vectors.weight,
            scaled(data, -(scale * power)),
            vectors.inverse,
        ));
        power *= challenges.mix(kind);
    }
    terms.push(term(
        vectors.weight,
        scaled(vectors.selector, -scale),
        vectors.one,
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
        terms.push(vec![weight, scale * selector, selector]);
        terms.push(vec![weight, -scale * selector, one]);
        for column in start + 1..start + width {
            let data = scalar(logs, column)?;
            scale *= mix;
            terms.push(vec![weight, scale * data, one]);
            terms.push(vec![weight, -scale * selector, data]);
        }
        scale *= mix;
        terms.push(vec![weight, scale * challenges.point(kind), inverse]);
        let mut power = one;
        for column in start + 1..start + width {
            terms.push(vec![
                weight,
                -(scale * power) * scalar(logs, column)?,
                inverse,
            ]);
            power *= challenges.mix(kind);
        }
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

fn term(
    weight: &[NativeField],
    middle: Vec<NativeField>,
    right: &[NativeField],
) -> Vec<Vec<NativeField>> {
    vec![weight.to_vec(), middle, right.to_vec()]
}

fn constant(value: NativeField) -> Vec<NativeField> {
    vec![value; PROTOCOL_LOG_ROW_COUNT]
}

fn scaled(values: &[NativeField], scale: NativeField) -> Vec<NativeField> {
    values.iter().map(|value| scale * *value).collect()
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
