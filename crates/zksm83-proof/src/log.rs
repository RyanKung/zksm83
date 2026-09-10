//! Ordered input/output accumulator extensions constrained with Poseidon.

use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::Fp;
use zksm83_memory::HashDomain;

use crate::merkle::MerkleConfig;

#[derive(Clone, Copy, Debug)]
pub(crate) struct LogConfig {
    current: Column<Advice>,
    index: Column<Advice>,
    value: Column<Advice>,
    packed: Column<Advice>,
    q_append: Selector,
}

impl LogConfig {
    pub(crate) fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let current = meta.advice_column();
        let index = meta.advice_column();
        let value = meta.advice_column();
        let packed = meta.advice_column();
        let q_append = meta.selector();
        for column in [current, index, value, packed] {
            meta.enable_equality(column);
        }
        meta.create_gate("ordered byte-log packing", |meta| {
            let enabled = meta.query_selector(q_append);
            let index = meta.query_advice(index, Rotation::cur());
            let value = meta.query_advice(value, Rotation::cur());
            let packed = meta.query_advice(packed, Rotation::cur());
            vec![enabled * (packed - index * Expression::Constant(Fp::from(256)) - value)]
        });
        Self {
            current,
            index,
            value,
            packed,
            q_append,
        }
    }

    pub(crate) fn append(
        &self,
        mut layouter: impl Layouter<Fp>,
        hash: &MerkleConfig,
        domain: HashDomain,
        current: &AssignedCell<Fp, Fp>,
        index: &AssignedCell<Fp, Fp>,
        value: &AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let packed = layouter.assign_region(
            || "ordered log element",
            |mut region| {
                self.q_append.enable(&mut region, 0)?;
                current.copy_advice(|| "current log root", &mut region, self.current, 0)?;
                index.copy_advice(|| "log index", &mut region, self.index, 0)?;
                value.copy_advice(|| "log byte", &mut region, self.value, 0)?;
                let packed_value = index
                    .value()
                    .copied()
                    .zip(value.value().copied())
                    .map(|(position, byte)| position * Fp::from(256) + byte);
                region.assign_advice(|| "packed log element", self.packed, 0, || packed_value)
            },
        )?;
        hash.hash3(
            layouter.namespace(|| "log accumulator hash"),
            domain.field(),
            current,
            &packed,
        )
    }
}
