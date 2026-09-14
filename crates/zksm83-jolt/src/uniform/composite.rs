use akita_pcs::{Ring, Transcript};

use super::{
    CommittedWitness, NativeField, OpeningProof, UNIFORM_NUM_VARIABLES, UNIFORM_ROW_COUNT,
    UniformError, UniformRelation, WitnessCommitments, ensure_relation_holds, outer_transcript,
    prove_opening, prove_sumcheck, push_bytes, push_usize, replay_sumcheck, sample_point,
    validate_relation, verify_opening_for_protocol,
};
use crate::NativeProtocolVersion;

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
    super::on_worker(|| prove_on_worker(NativeProtocolVersion::current(), relation, left, right))
}

pub(crate) fn verify_uniform_composite_for_protocol(
    protocol: NativeProtocolVersion,
    relation: &impl UniformRelation,
    left: &WitnessCommitments,
    right: &WitnessCommitments,
    proof: &CompositeUniformRelationProof,
) -> Result<(), UniformError> {
    super::on_worker(|| verify_on_worker(protocol, relation, left, right, proof))
}

fn prove_on_worker(
    protocol: NativeProtocolVersion,
    relation: &impl UniformRelation,
    left: &CommittedWitness,
    right: &CommittedWitness,
) -> Result<CompositeUniformRelationProof, UniformError> {
    validate_shapes(protocol, relation, left.commitments(), right.commitments())?;
    let left_columns = left.field_columns()?;
    let right_columns = right.field_columns()?;
    let mut columns = left_columns.into_owned_columns();
    columns.extend(right_columns.into_owned_columns());
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
    protocol: NativeProtocolVersion,
    relation: &impl UniformRelation,
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
    verify_opening_for_protocol(
        protocol,
        left,
        &opening_point,
        &proof.left_values,
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

fn validate_shapes(
    protocol: NativeProtocolVersion,
    relation: &impl UniformRelation,
    left: &WitnessCommitments,
    right: &WitnessCommitments,
) -> Result<(), UniformError> {
    validate_relation(relation)?;
    left.validate_for(protocol)?;
    right.validate_for(protocol)?;
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
    protocol: NativeProtocolVersion,
    relation: &impl UniformRelation,
    left: &WitnessCommitments,
    right: &WitnessCommitments,
) -> Result<Vec<u8>, UniformError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, protocol.protocol_id().as_bytes())?;
    push_bytes(&mut descriptor, protocol.trace_schedule_sha256().as_bytes())?;
    let domain = match protocol {
        NativeProtocolVersion::V2 => b"zksm83/native-uniform-composite/v2".as_slice(),
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
