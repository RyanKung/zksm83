use akita_pcs::Ring;

use super::{NativeField, UniformRelation};

/// Initialization contract for one relation's constraint output buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConstraintOutput {
    /// The framework clears every slot before calling the relation.
    ZeroInitialized,
    /// The relation overwrites every declared slot on each successful call.
    Overwritten,
}

pub(super) fn initialize_constraint_output(
    relation: &impl UniformRelation,
    constraints: &mut [NativeField],
) {
    if relation.constraint_output() == ConstraintOutput::ZeroInitialized {
        constraints.fill(NativeField::from_u64(0));
    }
}

pub(super) fn trim_zero_suffix(values: &[NativeField]) -> &[NativeField] {
    let zero = NativeField::from_u64(0);
    let retained = values
        .iter()
        .rposition(|value| *value != zero)
        .map_or(0, |index| index.saturating_add(1));
    values.get(..retained).unwrap_or(&[])
}
