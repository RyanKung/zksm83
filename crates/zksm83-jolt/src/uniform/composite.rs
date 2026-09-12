use akita_pcs::{Ring, Transcript};

use super::{
    CommittedWitness, NativeField, OpeningProof, UNIFORM_NUM_VARIABLES, UNIFORM_ROW_COUNT,
    UniformError, UniformRelation, WitnessCommitments, ensure_relation_holds, outer_transcript,
    prove_opening, prove_sumcheck, push_bytes, push_usize, replay_sumcheck, sample_point,
    validate_relation, verify_opening,
};

/// Uniform-relation proof spanning two separately committed trace planes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompositeUniformRelationProof {
    pub(crate) rounds: Vec<Vec<NativeField>>,
    pub(crate) left_values: Vec<NativeField>,
    pub(crate) right_values: Vec<NativeField>,
    pub(crate) left_opening: OpeningProof,
    pub(crate) right_opening: OpeningProof,
}

pub(crate) fn prove_uniform_composite(
    relation: &impl UniformRelation,
    left: &CommittedWitness,
    right: &CommittedWitness,
) -> Result<CompositeUniformRelationProof, UniformError> {
    super::on_worker(|| prove_on_worker(relation, left, right))
}

pub(crate) fn verify_uniform_composite(
    relation: &impl UniformRelation,
    left: &WitnessCommitments,
    right: &WitnessCommitments,
    proof: &CompositeUniformRelationProof,
) -> Result<(), UniformError> {
    super::on_worker(|| verify_on_worker(relation, left, right, proof))
}

fn prove_on_worker(
    relation: &impl UniformRelation,
    left: &CommittedWitness,
    right: &CommittedWitness,
) -> Result<CompositeUniformRelationProof, UniformError> {
    validate_shapes(relation, left.commitments(), right.commitments())?;
    let mut columns = left.field_columns().to_vec();
    columns.extend_from_slice(right.field_columns());
    ensure_relation_holds(relation, &columns, UNIFORM_ROW_COUNT)?;
    let descriptor = descriptor(relation, left.commitments(), right.commitments())?;
    let mut transcript = outer_transcript(&descriptor, super::TranscriptSide::Prover);
    let row_point = sample_point(&mut transcript, UNIFORM_NUM_VARIABLES);
    let constraint_mix = transcript.challenge_scalar(b"constraint-mix");
    if constraint_mix == NativeField::from_u64(0) {
        return Err(UniformError::ZeroChallenge);
    }
    let weights = super::equality_evaluations(&row_point);
    let (rounds, opening_point, opened_values) =
        prove_sumcheck(relation, columns, weights, constraint_mix, &mut transcript)?;
    let split = left.commitments().column_count();
    let left_values = opened_values
        .get(..split)
        .ok_or(UniformError::Shape)?
        .to_vec();
    let right_values = opened_values
        .get(split..)
        .ok_or(UniformError::Shape)?
        .to_vec();
    let left_opening = prove_opening(left, &opening_point, &left_values, &descriptor)?;
    let right_opening = prove_opening(right, &opening_point, &right_values, &descriptor)?;
    Ok(CompositeUniformRelationProof {
        rounds,
        left_values,
        right_values,
        left_opening,
        right_opening,
    })
}

fn verify_on_worker(
    relation: &impl UniformRelation,
    left: &WitnessCommitments,
    right: &WitnessCommitments,
    proof: &CompositeUniformRelationProof,
) -> Result<(), UniformError> {
    validate_shapes(relation, left, right)?;
    if proof.rounds.len() != UNIFORM_NUM_VARIABLES
        || proof.left_values.len() != left.column_count()
        || proof.right_values.len() != right.column_count()
    {
        return Err(UniformError::Shape);
    }
    let descriptor = descriptor(relation, left, right)?;
    let mut transcript = outer_transcript(&descriptor, super::TranscriptSide::Verifier);
    let row_point = sample_point(&mut transcript, UNIFORM_NUM_VARIABLES);
    let constraint_mix = transcript.challenge_scalar(b"constraint-mix");
    if constraint_mix == NativeField::from_u64(0) {
        return Err(UniformError::ZeroChallenge);
    }
    let mut opened_values = proof.left_values.clone();
    opened_values.extend_from_slice(&proof.right_values);
    let opening_point = replay_sumcheck(
        relation,
        &proof.rounds,
        &opened_values,
        &row_point,
        constraint_mix,
        &mut transcript,
    )?;
    verify_opening(
        left,
        &opening_point,
        &proof.left_values,
        &descriptor,
        &proof.left_opening,
    )?;
    verify_opening(
        right,
        &opening_point,
        &proof.right_values,
        &descriptor,
        &proof.right_opening,
    )
}

fn validate_shapes(
    relation: &impl UniformRelation,
    left: &WitnessCommitments,
    right: &WitnessCommitments,
) -> Result<(), UniformError> {
    validate_relation(relation)?;
    left.validate()?;
    right.validate()?;
    let combined = left
        .column_count()
        .checked_add(right.column_count())
        .ok_or(UniformError::Shape)?;
    if relation.column_count() != combined {
        return Err(UniformError::Shape);
    }
    Ok(())
}

fn descriptor(
    relation: &impl UniformRelation,
    left: &WitnessCommitments,
    right: &WitnessCommitments,
) -> Result<Vec<u8>, UniformError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, super::PROTOCOL_ID.as_bytes())?;
    push_bytes(&mut descriptor, super::AKITA_SCHEDULE_SHA256.as_bytes())?;
    push_bytes(&mut descriptor, b"zksm83/native-uniform-composite/v1")?;
    push_bytes(&mut descriptor, relation.domain())?;
    push_bytes(&mut descriptor, &relation.statement_bytes())?;
    push_usize(&mut descriptor, relation.column_count())?;
    push_usize(&mut descriptor, relation.constraint_count())?;
    push_usize(&mut descriptor, relation.max_constraint_degree())?;
    push_bytes(&mut descriptor, &left.canonical_bytes()?)?;
    push_bytes(&mut descriptor, &right.canonical_bytes()?)?;
    Ok(descriptor)
}
