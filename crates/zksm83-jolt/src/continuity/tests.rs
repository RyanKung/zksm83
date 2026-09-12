use akita_pcs::Ring;
use zksm83_memory::{MemoryImage, RomImage};
use zksm83_trace::{TraceBuilder, TraceRow};

use super::{
    ContinuityChallenges, ContinuityError, ContinuityRelation, NativeExecutionClaim, check_sum,
    evaluate_field_column, half_point, inverse_columns,
};
use crate::{
    NATIVE_TRACE_COLUMN_COUNT, NativeField, NativeStateBoundary, NativeTraceWitness,
    TRACE_BEFORE_STATE_START, UNIFORM_ROW_COUNT, UniformRelation,
};

fn two_row_trace() -> Result<NativeTraceWitness, Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0x00, 0x00, 0x76])?;
    let memory = MemoryImage::zeroed()?;
    let mut builder = TraceBuilder::new(rom, memory, Vec::new());
    let rows = [builder.step()?, builder.step()?];
    let references = rows.iter().collect::<Vec<&TraceRow>>();
    NativeTraceWitness::from_rows(&references).map_err(Into::into)
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

#[test]
fn execution_claim_has_stable_encoding_and_checked_count() -> Result<(), Box<dyn std::error::Error>>
{
    let trace = two_row_trace()?;
    let claim = NativeExecutionClaim::from_trace(&trace)?;
    assert_eq!(claim.active_row_count(), 2);
    assert_eq!(claim.canonical_bytes(), claim.canonical_bytes());
    assert!(NativeExecutionClaim::new(0, claim.initial_state(), claim.final_state()).is_err());
    assert!(
        NativeExecutionClaim::new(
            u64::try_from(UNIFORM_ROW_COUNT)? + 1,
            claim.initial_state(),
            claim.final_state(),
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn inverse_relation_and_global_sum_accept_exact_chain() -> Result<(), Box<dyn std::error::Error>> {
    let trace = two_row_trace()?;
    let claim = NativeExecutionClaim::from_trace(&trace)?;
    let challenges = fixed_challenges();
    let inverses = inverse_columns(trace.columns(), challenges)?;
    let relation = ContinuityRelation { challenges };
    for row_index in [0, 1, 2] {
        let mut row = trace
            .columns()
            .iter()
            .chain(&inverses)
            .map(|column| {
                column
                    .get(row_index)
                    .copied()
                    .map(NativeField::from_u64)
                    .ok_or(ContinuityError::Shape)
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(row.len(), relation.column_count());
        let mut constraints = vec![NativeField::from_u64(0); relation.constraint_count()];
        relation.evaluate(&row, &mut constraints)?;
        assert!(
            constraints
                .iter()
                .all(|value| *value == NativeField::from_u64(0))
        );
        row.clear();
    }
    check_sum(&inverse_sum_values(&inverses)?, &claim, challenges)?;
    Ok(())
}

#[test]
fn global_sum_rejects_discontinuous_row_and_wrong_public_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let trace = two_row_trace()?;
    let claim = NativeExecutionClaim::from_trace(&trace)?;
    let challenges = fixed_challenges();
    let mut discontinuous = trace.columns().to_vec();
    let scalar = discontinuous
        .get_mut(TRACE_BEFORE_STATE_START)
        .and_then(|column| column.get_mut(1))
        .ok_or(ContinuityError::Shape)?;
    *scalar ^= 1;
    let inverses = inverse_columns(&discontinuous, challenges)?;
    assert!(check_sum(&inverse_sum_values(&inverses)?, &claim, challenges).is_err());

    let exact_inverses = inverse_columns(trace.columns(), challenges)?;
    let wrong = NativeExecutionClaim::new(
        1,
        claim.initial_state(),
        NativeStateBoundary::from_vm_state(trace.final_state()),
    )?;
    assert!(check_sum(&inverse_sum_values(&exact_inverses)?, &wrong, challenges).is_err());
    assert_eq!(trace.columns().len(), NATIVE_TRACE_COLUMN_COUNT);
    Ok(())
}
