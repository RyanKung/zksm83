//! Boolean decomposition of the SM83 flag register before and after each step.

use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::Fp;
use zksm83_core::VmState;

use crate::state::StateTraceConfig;

#[derive(Clone, Copy, Debug)]
pub(crate) struct FlagBits {
    pub(crate) zero: Column<Advice>,
    pub(crate) subtract: Column<Advice>,
    pub(crate) half_carry: Column<Advice>,
    pub(crate) carry: Column<Advice>,
}

impl FlagBits {
    fn create(meta: &mut ConstraintSystem<Fp>) -> Self {
        Self {
            zero: meta.advice_column(),
            subtract: meta.advice_column(),
            half_carry: meta.advice_column(),
            carry: meta.advice_column(),
        }
    }

    fn all(self) -> [Column<Advice>; 4] {
        [self.zero, self.subtract, self.half_carry, self.carry]
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FlagConfig {
    pub(crate) before: FlagBits,
    pub(crate) after: FlagBits,
    q_row: Selector,
}

impl FlagConfig {
    pub(crate) fn configure(meta: &mut ConstraintSystem<Fp>, state: &StateTraceConfig) -> Self {
        let before = FlagBits::create(meta);
        let after = FlagBits::create(meta);
        let q_row = meta.selector();
        meta.create_gate("SM83 flag bit decomposition", |meta| {
            let enabled = meta.query_selector(q_row);
            let mut constraints = Vec::new();
            for (bits, flags) in [(before, state.before.flags), (after, state.after.flags)] {
                let [zero, subtract, half, carry] = bits
                    .all()
                    .map(|column| meta.query_advice(column, Rotation::cur()));
                let encoded = Expression::Constant(Fp::from(128)) * zero.clone()
                    + Expression::Constant(Fp::from(64)) * subtract.clone()
                    + Expression::Constant(Fp::from(32)) * half.clone()
                    + Expression::Constant(Fp::from(16)) * carry.clone();
                let register = meta.query_advice(flags, Rotation::cur());
                constraints.push(enabled.clone() * (register - encoded));
                for bit in [zero, subtract, half, carry] {
                    constraints.push(
                        enabled.clone() * bit.clone() * (Expression::Constant(Fp::one()) - bit),
                    );
                }
            }
            constraints
        });
        Self {
            before,
            after,
            q_row,
        }
    }

    pub(crate) fn assign_row(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        transition: Option<(VmState, VmState)>,
    ) -> Result<(), Error> {
        self.q_row.enable(region, offset)?;
        let (before, after) = transition.map_or((None, None), |(before, after)| {
            (Some(before.cpu().flags()), Some(after.cpu().flags()))
        });
        assign_bits(region, offset, self.before, before)?;
        assign_bits(region, offset, self.after, after)
    }
}

fn assign_bits(
    region: &mut Region<'_, Fp>,
    offset: usize,
    columns: FlagBits,
    flags: Option<zksm83_core::Flags>,
) -> Result<(), Error> {
    let values = flags.map(|flags| {
        [
            flags.zero(),
            flags.subtract(),
            flags.half_carry(),
            flags.carry(),
        ]
    });
    for (index, column) in columns.all().iter().enumerate() {
        let value = values.and_then(|bits| bits.get(index).copied());
        region.assign_advice(
            || "flag bit",
            *column,
            offset,
            || {
                value.map_or(Value::unknown(), |bit| {
                    Value::known(Fp::from(u64::from(bit)))
                })
            },
        )?;
    }
    Ok(())
}
