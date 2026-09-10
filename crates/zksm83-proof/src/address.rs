//! In-circuit address-ownership checks for ROM and mutable memory.

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn},
    poly::Rotation,
};
use pasta_curves::Fp;

const ADDRESS_BITS: usize = 16;
const PREFIX_BITS: usize = 12;

#[derive(Clone, Debug)]
pub(crate) struct AddressConfig {
    bits: [Column<Advice>; PREFIX_BITS],
    prefix: Column<Advice>,
    prefix_table: TableColumn,
    q_prefix: Selector,
    constant: Column<Advice>,
}

impl AddressConfig {
    pub(crate) fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let bits = std::array::from_fn(|_| meta.advice_column());
        let prefix = meta.advice_column();
        let prefix_table = meta.lookup_table_column();
        let q_prefix = meta.complex_selector();
        let constant = meta.advice_column();
        let constant_values = meta.fixed_column();
        for column in bits.into_iter().chain([prefix, constant]) {
            meta.enable_equality(column);
        }
        meta.enable_constant(constant_values);
        meta.create_gate("mutable address prefix", |meta| {
            let enabled = meta.query_selector(q_prefix);
            let prefix = meta.query_advice(prefix, Rotation::cur());
            let mut reconstructed = Expression::Constant(Fp::zero());
            let mut power = Fp::one();
            for column in bits {
                reconstructed = reconstructed
                    + Expression::Constant(power) * meta.query_advice(column, Rotation::cur());
                power = power.double();
            }
            vec![enabled * (prefix - reconstructed)]
        });
        meta.lookup(|meta| {
            let enabled = meta.query_selector(q_prefix);
            let prefix = meta.query_advice(prefix, Rotation::cur());
            vec![(enabled * prefix, prefix_table)]
        });
        Self {
            bits,
            prefix,
            prefix_table,
            q_prefix,
            constant,
        }
    }

    pub(crate) fn load(&self, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        layouter.assign_table(
            || "mutable address high-12 prefixes",
            |mut table| {
                table.assign_cell(
                    || "disabled prefix",
                    self.prefix_table,
                    0,
                    || Value::known(Fp::zero()),
                )?;
                for (offset, prefix) in (0x800_u16..=0xffe).enumerate() {
                    table.assign_cell(
                        || "mutable prefix",
                        self.prefix_table,
                        offset + 1,
                        || Value::known(Fp::from(u64::from(prefix))),
                    )?;
                }
                Ok(())
            },
        )
    }

    pub(crate) fn constrain_rom(
        &self,
        mut layouter: impl Layouter<Fp>,
        bits: &[AssignedCell<Fp, Fp>],
    ) -> Result<(), Error> {
        let high = bits.get(ADDRESS_BITS - 1).ok_or(Error::Synthesis)?;
        layouter.assign_region(
            || "ROM address high bit",
            |mut region| {
                let copied = high.copy_advice(|| "bit 15", &mut region, self.constant, 0)?;
                region.constrain_constant(copied.cell(), Fp::zero())
            },
        )
    }

    pub(crate) fn constrain_memory(
        &self,
        mut layouter: impl Layouter<Fp>,
        bits: &[AssignedCell<Fp, Fp>],
    ) -> Result<(), Error> {
        let high_bits = bits.get(4..ADDRESS_BITS).ok_or(Error::Synthesis)?;
        layouter.assign_region(
            || "mutable address owner",
            |mut region| {
                self.q_prefix.enable(&mut region, 0)?;
                for (source, target) in high_bits.iter().zip(self.bits) {
                    source.copy_advice(|| "address prefix bit", &mut region, target, 0)?;
                }
                let prefix_value = high_bits.iter().enumerate().fold(
                    Value::known(Fp::zero()),
                    |sum, (bit, cell)| {
                        let power = Fp::from(1_u64 << bit);
                        sum + cell.value().copied() * Value::known(power)
                    },
                );
                region.assign_advice(
                    || "address high-12 prefix",
                    self.prefix,
                    0,
                    || prefix_value,
                )?;
                Ok(())
            },
        )
    }
}
