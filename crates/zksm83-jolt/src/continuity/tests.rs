use akita_pcs::Ring;
use zksm83_memory::{MemoryImage, RomImage};
use zksm83_trace::{LookupTraceBuilder, pack_witness_basic_blocks};

use super::{
    ContinuityChallenges, ContinuityError, ContinuityLayout, ContinuityRelation,
    NativeExecutionClaim, check_sum, evaluate_field_column, half_point, inverse_columns,
};
use crate::{BlockCpuWitness, NativeField, UNIFORM_ROW_COUNT, UniformRelation};

fn packed_trace(step_count: usize) -> Result<BlockCpuWitness, Box<dyn std::error::Error>> {
    let bytes = vec![0x00_u8; 0x106];
    let rom = RomImage::new(bytes.clone())?;
    let memory = MemoryImage::zeroed()?;
    let mut builder = LookupTraceBuilder::new_dmg_post_boot_mbc3(
        bytes,
        memory.checkpoint_bytes(),
        Vec::new(),
        rom.root(),
        memory.root(),
    )?;
    let steps = u64::try_from(step_count)?;
    let blocks = pack_witness_basic_blocks(builder.run_exact_steps(steps)?)?;
    BlockCpuWitness::from_blocks(&blocks).map_err(Into::into)
}

fn fixed_challenges() -> ContinuityChallenges {
    ContinuityChallenges {
        state_mix: NativeField::from_u64(7),
        inverse_point: NativeField::from_u64(11),
    }
}

fn inverse_sum_values(columns: &[Vec<u64>]) -> Result<Vec<NativeField>, ContinuityError> {
    let point = half_point()?;
    columns
        .iter()
        .map(|column| {
            let field = column
                .iter()
                .copied()
                .map(NativeField::from_u64)
                .collect::<Vec<_>>();
            evaluate_field_column(&field, &point)
        })
        .collect()
}

fn relation_row(
    trace: &[Vec<u64>],
    inverses: &[Vec<u64>],
    row_index: usize,
) -> Result<Vec<NativeField>, ContinuityError> {
    trace
        .iter()
        .chain(inverses)
        .map(|column| {
            column
                .get(row_index)
                .copied()
                .map(NativeField::from_u64)
                .ok_or(ContinuityError::Shape)
        })
        .collect()
}

#[test]
fn execution_claim_has_stable_encoding_and_checked_count() -> Result<(), Box<dyn std::error::Error>>
{
    let trace = packed_trace(2)?;
    let claim = NativeExecutionClaim::from_packed_trace(&trace)?;
    assert_eq!(claim.transition_count(), 2);
    assert_eq!(claim.canonical_bytes(), claim.canonical_bytes());
    assert!(NativeExecutionClaim::new(0, 0, claim.initial_state(), claim.final_state()).is_err());
    assert!(
        NativeExecutionClaim::new(
            u64::try_from(UNIFORM_ROW_COUNT)? + 1,
            u64::try_from(UNIFORM_ROW_COUNT)? + 1,
            claim.initial_state(),
            claim.final_state(),
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn packed_continuity_uses_outer_block_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    let trace = packed_trace(5)?;
    let claim = NativeExecutionClaim::from_packed_trace(&trace)?;
    let challenges = fixed_challenges();
    let inverses = inverse_columns(trace.columns(), ContinuityLayout::Packed, challenges)?;
    let relation = ContinuityRelation::new(ContinuityLayout::Packed, challenges);
    for row_index in 0..=trace.active_block_count() {
        let row = relation_row(trace.columns(), &inverses, row_index)?;
        let mut constraints = vec![NativeField::from_u64(0); relation.constraint_count()];
        relation.evaluate(&row, &mut constraints)?;
        assert!(
            constraints
                .iter()
                .all(|value| *value == NativeField::from_u64(0))
        );
    }
    check_sum(
        ContinuityLayout::Packed,
        &inverse_sum_values(&inverses)?,
        &claim,
        challenges,
    )?;
    let wrong_transition_count = claim
        .transition_count()
        .checked_sub(1)
        .ok_or(ContinuityError::Shape)?;
    let wrong_count = NativeExecutionClaim::new(
        claim.active_row_count(),
        wrong_transition_count,
        claim.initial_state(),
        claim.final_state(),
    )?;
    assert!(
        check_sum(
            ContinuityLayout::Packed,
            &inverse_sum_values(&inverses)?,
            &wrong_count,
            challenges,
        )
        .is_err()
    );

    let mut discontinuous = trace.columns().to_vec();
    let state_column = ContinuityLayout::Packed
        .state_column(false, 0)
        .ok_or(ContinuityError::Shape)?;
    let scalar = discontinuous
        .get_mut(state_column)
        .and_then(|column| column.get_mut(1))
        .ok_or(ContinuityError::Shape)?;
    *scalar ^= 1;
    let bad_inverses = inverse_columns(&discontinuous, ContinuityLayout::Packed, challenges)?;
    assert!(
        check_sum(
            ContinuityLayout::Packed,
            &inverse_sum_values(&bad_inverses)?,
            &claim,
            challenges,
        )
        .is_err()
    );
    Ok(())
}
