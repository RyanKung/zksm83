use akita_pcs::Ring;

use super::{
    ConstraintOutput, NativeField, UNIFORM_ROW_COUNT, UniformError, UniformRelation,
    combined_relation_with_scratch, parallel_sumcheck_round, prove_uniform,
    relation::trim_zero_suffix, sumcheck_round,
};

struct BooleanColumn;
struct ZeroInitializedPartial;

impl UniformRelation for BooleanColumn {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/test/sumcheck-scratch/v1"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        b"scratch reuse".to_vec()
    }

    fn column_count(&self) -> usize {
        1
    }

    fn constraint_count(&self) -> usize {
        1
    }

    fn max_constraint_degree(&self) -> usize {
        2
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        let value = row.first().copied().ok_or(UniformError::Shape)?;
        let constraint = constraints.first_mut().ok_or(UniformError::Shape)?;
        *constraint = value * (value - NativeField::from_u64(1));
        Ok(())
    }
}

impl UniformRelation for ZeroInitializedPartial {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/test/zero-initialized-partial/v1"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        b"partial output".to_vec()
    }

    fn column_count(&self) -> usize {
        1
    }

    fn constraint_count(&self) -> usize {
        2
    }

    fn max_constraint_degree(&self) -> usize {
        1
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        let value = row.first().copied().ok_or(UniformError::Shape)?;
        *constraints.first_mut().ok_or(UniformError::Shape)? = value;
        Ok(())
    }
}

#[test]
fn sumcheck_round_reuses_relation_scratch() -> Result<(), UniformError> {
    let columns = vec![
        [0, 1, 1, 0]
            .into_iter()
            .map(NativeField::from_u64)
            .collect::<Vec<_>>(),
    ];
    let weights = [1, 2, 3, 4]
        .into_iter()
        .map(NativeField::from_u64)
        .collect::<Vec<_>>();
    let mut row_scratch = vec![NativeField::from_u64(0); 1];
    let mut constraint_scratch = vec![NativeField::from_u64(0); 1];
    let row_allocation = row_scratch.as_ptr();
    let constraint_allocation = constraint_scratch.as_ptr();
    let message = sumcheck_round(
        &BooleanColumn,
        &columns,
        &weights,
        NativeField::from_u64(7),
        4,
        &mut row_scratch,
        &mut constraint_scratch,
    )?;
    let one = NativeField::from_u64(1);
    let column = columns.first().ok_or(UniformError::Shape)?;
    let mut expected = Vec::with_capacity(4);
    for point in 0..4 {
        let point = NativeField::from_u64(point);
        let mut sum = NativeField::from_u64(0);
        for (values, pair_weights) in column.chunks_exact(2).zip(weights.chunks_exact(2)) {
            let [low, high] = values else {
                return Err(UniformError::Shape);
            };
            let [low_weight, high_weight] = pair_weights else {
                return Err(UniformError::Shape);
            };
            let value = *low + point * (*high - *low);
            let weight = *low_weight + point * (*high_weight - *low_weight);
            sum += weight * value * (value - one);
        }
        expected.push(sum);
    }
    assert_eq!(message, expected);
    assert_eq!(row_scratch.as_ptr(), row_allocation);
    assert_eq!(constraint_scratch.as_ptr(), constraint_allocation);
    Ok(())
}

#[test]
fn parallel_sumcheck_round_matches_sequential_message() -> Result<(), UniformError> {
    let columns = vec![
        (0..256)
            .map(|value| NativeField::from_u64(value % 2))
            .collect::<Vec<_>>(),
    ];
    let weights = (0..256)
        .map(|value| NativeField::from_u64(value + 1))
        .collect::<Vec<_>>();
    let zero = NativeField::from_u64(0);
    let mut row = vec![zero; 1];
    let mut constraints = vec![zero; 1];
    let sequential = sumcheck_round(
        &BooleanColumn,
        &columns,
        &weights,
        NativeField::from_u64(7),
        4,
        &mut row,
        &mut constraints,
    )?;
    let parallel = parallel_sumcheck_round(
        &BooleanColumn,
        &columns,
        &weights,
        NativeField::from_u64(7),
        4,
    )?;
    assert_eq!(parallel, sequential);
    Ok(())
}

#[test]
fn malformed_or_unsatisfied_witness_fails_before_commitment() -> Result<(), UniformError> {
    assert!(matches!(
        prove_uniform(&BooleanColumn, &[vec![0, 1, 0]]),
        Err(UniformError::Shape)
    ));
    let mut unsatisfied = vec![0; UNIFORM_ROW_COUNT];
    *unsatisfied.get_mut(2).ok_or(UniformError::Shape)? = 2;
    assert!(matches!(
        prove_uniform(&BooleanColumn, &[unsatisfied]),
        Err(UniformError::WitnessUnsatisfied {
            row: 2,
            constraint: 0
        })
    ));
    Ok(())
}

#[test]
fn default_relation_contract_clears_partial_output() -> Result<(), UniformError> {
    let mut constraints = vec![NativeField::from_u64(9); 2];
    let combined = combined_relation_with_scratch(
        &ZeroInitializedPartial,
        &[NativeField::from_u64(0)],
        NativeField::from_u64(7),
        &mut constraints,
    )?;
    assert_eq!(combined, NativeField::from_u64(0));
    assert_eq!(constraints, vec![NativeField::from_u64(0); 2]);
    Ok(())
}

#[test]
fn zero_suffix_trim_preserves_the_last_nonzero_constraint() {
    let zero = NativeField::from_u64(0);
    let one = NativeField::from_u64(1);
    assert!(trim_zero_suffix(&[zero, zero]).is_empty());
    assert_eq!(trim_zero_suffix(&[one, zero, one, zero, zero]).len(), 3);
    assert_eq!(trim_zero_suffix(&[one, one]).len(), 2);
}
