use std::{cell::RefCell, mem};

use akita_pcs::{Ring, Transcript};

use super::{
    CommittedWitness, ConstraintOutput, NativeField, OpeningProof, UNIFORM_NUM_VARIABLES,
    UNIFORM_ROW_COUNT, UniformError, UniformRelation, WitnessCommitments, ensure_relation_holds,
    outer_transcript, prove_opening, prove_selected_opening, prove_sumcheck, push_bytes,
    push_usize, replay_sumcheck, sample_point, validate_relation, verify_opening_for_protocol,
    verify_selected_opening_for_protocol,
};
use crate::NativeProtocolVersion;

const PROJECTED_RELATION_DOMAIN: &[u8] = b"zksm83/native-projected-relation/v2";

/// Uniform relation evaluated from a canonical projection of its left trace plane.
pub(crate) struct ProjectedRelation<R> {
    inner: R,
    trace_column_count: usize,
    auxiliary_column_count: usize,
    trace_columns: Vec<usize>,
    statement: Vec<u8>,
}

impl<R: UniformRelation> ProjectedRelation<R> {
    /// Creates a relation whose compact rows contain selected trace columns then all auxiliaries.
    pub(crate) fn new(
        inner: R,
        trace_column_count: usize,
        trace_columns: Vec<usize>,
    ) -> Result<Self, UniformError> {
        validate_relation(&inner)?;
        let auxiliary_column_count = inner
            .column_count()
            .checked_sub(trace_column_count)
            .ok_or(UniformError::Shape)?;
        if trace_column_count == 0
            || auxiliary_column_count == 0
            || trace_columns.is_empty()
            || trace_columns
                .iter()
                .any(|column| *column >= trace_column_count)
            || trace_columns
                .windows(2)
                .any(|pair| matches!(pair, [left, right] if left >= right))
        {
            return Err(UniformError::Shape);
        }
        let statement = projected_statement(&inner, trace_column_count, &trace_columns)?;
        Ok(Self {
            inner,
            trace_column_count,
            auxiliary_column_count,
            trace_columns,
            statement,
        })
    }

    fn trace_columns(&self) -> &[usize] {
        &self.trace_columns
    }

    fn trace_column_count(&self) -> usize {
        self.trace_column_count
    }

    fn auxiliary_column_count(&self) -> usize {
        self.auxiliary_column_count
    }
}

impl<R: UniformRelation> UniformRelation for ProjectedRelation<R> {
    fn domain(&self) -> &'static [u8] {
        PROJECTED_RELATION_DOMAIN
    }

    fn statement_bytes(&self) -> Vec<u8> {
        self.statement.clone()
    }

    fn column_count(&self) -> usize {
        self.trace_columns.len() + self.auxiliary_column_count
    }

    fn constraint_count(&self) -> usize {
        self.inner.constraint_count()
    }

    fn max_constraint_degree(&self) -> usize {
        self.inner.max_constraint_degree()
    }

    fn constraint_output(&self) -> ConstraintOutput {
        self.inner.constraint_output()
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        PROJECTED_ROW_SCRATCH.with(|scratch| {
            let mut scratch = scratch.try_borrow_mut().map_err(|_| UniformError::Shape)?;
            scratch.prepare(
                self.inner.column_count(),
                self.trace_column_count,
                &self.trace_columns,
                row,
            )?;
            self.inner.evaluate(&scratch.row, constraints)
        })
    }
}

#[derive(Default)]
struct ProjectedRowScratch {
    row: Vec<NativeField>,
    touched: Vec<usize>,
}

impl ProjectedRowScratch {
    fn prepare(
        &mut self,
        full_column_count: usize,
        trace_column_count: usize,
        trace_columns: &[usize],
        compact_row: &[NativeField],
    ) -> Result<(), UniformError> {
        let auxiliary_column_count = full_column_count
            .checked_sub(trace_column_count)
            .ok_or(UniformError::Shape)?;
        let compact_column_count = trace_columns
            .len()
            .checked_add(auxiliary_column_count)
            .ok_or(UniformError::Shape)?;
        if compact_row.len() != compact_column_count {
            return Err(UniformError::Shape);
        }
        let zero = NativeField::from_u64(0);
        let mut touched = mem::take(&mut self.touched);
        if self.row.len() == full_column_count {
            let mut invalid_index = false;
            for index in touched.drain(..) {
                if let Some(value) = self.row.get_mut(index) {
                    *value = zero;
                } else {
                    invalid_index = true;
                }
            }
            if invalid_index {
                self.row.fill(zero);
                self.touched = touched;
                return Err(UniformError::Shape);
            }
        } else {
            self.row = vec![zero; full_column_count];
            touched.clear();
        }
        let result = self.populate(
            trace_column_count,
            trace_columns,
            compact_row,
            auxiliary_column_count,
            &mut touched,
        );
        self.touched = touched;
        result
    }

    fn populate(
        &mut self,
        trace_column_count: usize,
        trace_columns: &[usize],
        compact_row: &[NativeField],
        auxiliary_column_count: usize,
        touched: &mut Vec<usize>,
    ) -> Result<(), UniformError> {
        for (compact_index, full_index) in trace_columns.iter().copied().enumerate() {
            let value = compact_row
                .get(compact_index)
                .copied()
                .ok_or(UniformError::Shape)?;
            *self.row.get_mut(full_index).ok_or(UniformError::Shape)? = value;
            touched.push(full_index);
        }
        for auxiliary_index in 0..auxiliary_column_count {
            let full_index = trace_column_count
                .checked_add(auxiliary_index)
                .ok_or(UniformError::Shape)?;
            let compact_index = trace_columns
                .len()
                .checked_add(auxiliary_index)
                .ok_or(UniformError::Shape)?;
            let value = compact_row
                .get(compact_index)
                .copied()
                .ok_or(UniformError::Shape)?;
            *self.row.get_mut(full_index).ok_or(UniformError::Shape)? = value;
            touched.push(full_index);
        }
        Ok(())
    }
}

thread_local! {
    static PROJECTED_ROW_SCRATCH: RefCell<ProjectedRowScratch> =
        RefCell::new(ProjectedRowScratch::default());
}

/// Uniform-relation proof spanning two separately committed trace planes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompositeUniformRelationProof {
    pub(crate) rounds: Vec<Vec<NativeField>>,
    pub(crate) left_values: Vec<NativeField>,
    pub(crate) right_values: Vec<NativeField>,
    pub(crate) left_opening: OpeningProof,
    pub(crate) right_opening: OpeningProof,
}

pub(crate) fn prove_uniform_composite<R: UniformRelation>(
    relation: &ProjectedRelation<R>,
    left: &CommittedWitness,
    right: &CommittedWitness,
) -> Result<CompositeUniformRelationProof, UniformError> {
    super::on_worker(|| prove_on_worker(NativeProtocolVersion::current(), relation, left, right))
}

pub(crate) fn verify_uniform_composite_for_protocol<R: UniformRelation>(
    protocol: NativeProtocolVersion,
    relation: &ProjectedRelation<R>,
    left: &WitnessCommitments,
    right: &WitnessCommitments,
    proof: &CompositeUniformRelationProof,
) -> Result<(), UniformError> {
    super::on_worker(|| verify_on_worker(protocol, relation, left, right, proof))
}

fn prove_on_worker<R: UniformRelation>(
    protocol: NativeProtocolVersion,
    relation: &ProjectedRelation<R>,
    left: &CommittedWitness,
    right: &CommittedWitness,
) -> Result<CompositeUniformRelationProof, UniformError> {
    validate_shapes(protocol, relation, left.commitments(), right.commitments())?;
    let left_columns = left.field_columns()?;
    let right_columns = right.field_columns()?;
    let mut columns = Vec::with_capacity(relation.column_count());
    for index in relation.trace_columns().iter().copied() {
        columns.push(
            left_columns
                .as_slice()
                .get(index)
                .copied()
                .ok_or(UniformError::Shape)?,
        );
    }
    columns.extend_from_slice(right_columns.as_slice());
    ensure_relation_holds(relation, &columns, UNIFORM_ROW_COUNT)?;
    let descriptor = descriptor(protocol, relation, left.commitments(), right.commitments())?;
    let mut transcript = outer_transcript(protocol, &descriptor, super::TranscriptSide::Prover);
    let row_point = sample_point(&mut transcript, UNIFORM_NUM_VARIABLES);
    let constraint_mix = transcript.challenge_scalar(b"constraint-mix");
    if constraint_mix == NativeField::from_u64(0) {
        return Err(UniformError::ZeroChallenge);
    }
    let weights = super::equality_evaluations(&row_point);
    let (rounds, opening_point, opened_values) =
        prove_sumcheck(relation, &columns, weights, constraint_mix, &mut transcript)?;
    let split = relation.trace_columns().len();
    let selected_values = opened_values.get(..split).ok_or(UniformError::Shape)?;
    let right_values = opened_values
        .get(split..)
        .ok_or(UniformError::Shape)?
        .to_vec();
    let (left_values, left_opening) =
        prove_selected_opening(left, &opening_point, relation.trace_columns(), &descriptor)?;
    ensure_selected_values_match(relation.trace_columns(), selected_values, &left_values)?;
    let right_opening = prove_opening(right, &opening_point, &right_values, &descriptor)?;
    Ok(CompositeUniformRelationProof {
        rounds,
        left_values,
        right_values,
        left_opening,
        right_opening,
    })
}

fn verify_on_worker<R: UniformRelation>(
    protocol: NativeProtocolVersion,
    relation: &ProjectedRelation<R>,
    left: &WitnessCommitments,
    right: &WitnessCommitments,
    proof: &CompositeUniformRelationProof,
) -> Result<(), UniformError> {
    validate_shapes(protocol, relation, left, right)?;
    if proof.rounds.len() != UNIFORM_NUM_VARIABLES
        || proof.left_values.len() != left.column_count()
        || proof.right_values.len() != right.column_count()
    {
        return Err(UniformError::Shape);
    }
    let descriptor = descriptor(protocol, relation, left, right)?;
    let mut transcript = outer_transcript(protocol, &descriptor, super::TranscriptSide::Verifier);
    let row_point = sample_point(&mut transcript, UNIFORM_NUM_VARIABLES);
    let constraint_mix = transcript.challenge_scalar(b"constraint-mix");
    if constraint_mix == NativeField::from_u64(0) {
        return Err(UniformError::ZeroChallenge);
    }
    let mut opened_values = selected_values(relation.trace_columns(), &proof.left_values)?;
    opened_values.extend_from_slice(&proof.right_values);
    let opening_point = replay_sumcheck(
        relation,
        &proof.rounds,
        &opened_values,
        &row_point,
        constraint_mix,
        &mut transcript,
    )?;
    verify_selected_opening_for_protocol(
        protocol,
        left,
        &opening_point,
        &proof.left_values,
        relation.trace_columns(),
        &descriptor,
        &proof.left_opening,
    )?;
    verify_opening_for_protocol(
        protocol,
        right,
        &opening_point,
        &proof.right_values,
        &descriptor,
        &proof.right_opening,
    )
}

fn validate_shapes<R: UniformRelation>(
    protocol: NativeProtocolVersion,
    relation: &ProjectedRelation<R>,
    left: &WitnessCommitments,
    right: &WitnessCommitments,
) -> Result<(), UniformError> {
    validate_relation(relation)?;
    left.validate_for(protocol)?;
    right.validate_for(protocol)?;
    if left.column_count() != relation.trace_column_count()
        || right.column_count() != relation.auxiliary_column_count()
    {
        return Err(UniformError::Shape);
    }
    Ok(())
}

fn descriptor<R: UniformRelation>(
    protocol: NativeProtocolVersion,
    relation: &ProjectedRelation<R>,
    left: &WitnessCommitments,
    right: &WitnessCommitments,
) -> Result<Vec<u8>, UniformError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, protocol.protocol_id().as_bytes())?;
    push_bytes(&mut descriptor, protocol.trace_schedule_sha256().as_bytes())?;
    let domain = match protocol {
        NativeProtocolVersion::V2 => b"zksm83/native-uniform-projected-composite/v2".as_slice(),
    };
    push_bytes(&mut descriptor, domain)?;
    push_bytes(&mut descriptor, relation.domain())?;
    push_bytes(&mut descriptor, &relation.statement_bytes())?;
    push_usize(&mut descriptor, relation.column_count())?;
    push_usize(&mut descriptor, relation.constraint_count())?;
    push_usize(&mut descriptor, relation.max_constraint_degree())?;
    push_bytes(&mut descriptor, &left.canonical_bytes_for(protocol)?)?;
    push_bytes(&mut descriptor, &right.canonical_bytes_for(protocol)?)?;
    Ok(descriptor)
}

fn projected_statement(
    relation: &impl UniformRelation,
    trace_column_count: usize,
    trace_columns: &[usize],
) -> Result<Vec<u8>, UniformError> {
    let mut statement = Vec::new();
    push_bytes(&mut statement, relation.domain())?;
    push_bytes(&mut statement, &relation.statement_bytes())?;
    push_usize(&mut statement, relation.column_count())?;
    push_usize(&mut statement, trace_column_count)?;
    push_usize(&mut statement, trace_columns.len())?;
    for column in trace_columns.iter().copied() {
        push_usize(&mut statement, column)?;
    }
    Ok(statement)
}

fn selected_values(
    selected_columns: &[usize],
    full_values: &[NativeField],
) -> Result<Vec<NativeField>, UniformError> {
    selected_columns
        .iter()
        .copied()
        .map(|column| full_values.get(column).copied().ok_or(UniformError::Shape))
        .collect()
}

fn ensure_selected_values_match(
    selected_columns: &[usize],
    selected: &[NativeField],
    full_values: &[NativeField],
) -> Result<(), UniformError> {
    if selected.len() != selected_columns.len() {
        return Err(UniformError::Shape);
    }
    for (value, column) in selected.iter().zip(selected_columns.iter().copied()) {
        if full_values.get(column) != Some(value) {
            return Err(UniformError::TerminalMismatch);
        }
    }
    Ok(())
}
