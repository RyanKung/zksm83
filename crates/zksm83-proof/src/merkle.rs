//! Poseidon Merkle authentication constrained inside Halo2.

use halo2_gadgets::poseidon::{
    PoseidonInstructions, Pow5Chip, Pow5Config, StateWord, primitives::P128Pow5T3,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};
use pasta_curves::Fp;
use zksm83_memory::{HashDomain, MerklePath};

const WIDTH: usize = 3;
const RATE: usize = 2;
const TREE_DEPTH: usize = 20;

type AssignedScalar = AssignedCell<Fp, Fp>;
type AssignedScalars = Vec<AssignedScalar>;
type AssignedPair = (AssignedScalar, AssignedScalar);

#[derive(Clone, Debug)]
pub(crate) struct MerkleConfig {
    poseidon: Pow5Config<Fp, WIDTH, RATE>,
    message: [Column<Advice>; 3],
    address: Column<Advice>,
    address_bits: [Column<Advice>; TREE_DEPTH],
    mux: [Column<Advice>; 5],
    q_address: Selector,
    q_mux: Selector,
    instance: Column<Instance>,
}

pub(crate) struct AuthenticatedPath {
    pub(crate) root: AssignedCell<Fp, Fp>,
    pub(crate) address: AssignedCell<Fp, Fp>,
    pub(crate) value: AssignedCell<Fp, Fp>,
    pub(crate) address_bits: Vec<AssignedCell<Fp, Fp>>,
}

impl MerkleConfig {
    pub(crate) fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let state = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let partial_sbox = meta.advice_column();
        let rc_a = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let rc_b = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b);
        let message = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let address = meta.advice_column();
        let address_bits = std::array::from_fn(|_| meta.advice_column());
        let mux = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let q_address = meta.selector();
        let q_mux = meta.selector();
        let instance = meta.instance_column();
        for column in message
            .iter()
            .chain(address_bits.iter())
            .chain(mux.iter())
            .copied()
        {
            meta.enable_equality(column);
        }
        meta.enable_equality(address);
        meta.enable_equality(instance);
        configure_address_gate(meta, q_address, address, address_bits);
        configure_mux_gate(meta, q_mux, mux);
        Self {
            poseidon,
            message,
            address,
            address_bits,
            mux,
            q_address,
            q_mux,
            instance,
        }
    }

    pub(crate) fn authenticate(
        &self,
        mut layouter: impl Layouter<Fp>,
        leaf_domain: HashDomain,
        node_domain: fn(u8) -> HashDomain,
        address: Value<u16>,
        value: Value<u8>,
        path: Option<MerklePath>,
    ) -> Result<AuthenticatedPath, Error> {
        let (address_cell, bit_cells) =
            self.assign_address(layouter.namespace(|| "address"), address)?;
        let leaf_value = self.assign_scalar(
            layouter.namespace(|| "leaf value"),
            value.map(|byte| Fp::from(u64::from(byte))),
        )?;
        let zero = self.assign_scalar(
            layouter.namespace(|| "leaf zero padding"),
            Value::known(Fp::zero()),
        )?;
        let mut current = self.hash3(
            layouter.namespace(|| "leaf hash"),
            leaf_domain.field(),
            &leaf_value,
            &zero,
        )?;
        let siblings = path.map(|authentication| authentication.siblings().collect::<Vec<_>>());
        for (level, bit) in (0_u8..20).zip(bit_cells.iter()) {
            let sibling_value = siblings
                .as_ref()
                .and_then(|nodes| nodes.get(usize::from(level)))
                .map_or(Value::unknown(), |node| Value::known(node.field()));
            let sibling = self.assign_scalar(
                layouter.namespace(|| format!("sibling {level}")),
                sibling_value,
            )?;
            let (left, right) = self.select_order(
                layouter.namespace(|| format!("path order {level}")),
                bit,
                &current,
                &sibling,
            )?;
            current = self.hash3(
                layouter.namespace(|| format!("node hash {level}")),
                node_domain(level).field(),
                &left,
                &right,
            )?;
        }
        Ok(AuthenticatedPath {
            root: current,
            address: address_cell,
            value: leaf_value,
            address_bits: bit_cells,
        })
    }

    pub(crate) const fn instance(&self) -> Column<Instance> {
        self.instance
    }

    fn assign_address(
        &self,
        mut layouter: impl Layouter<Fp>,
        address: Value<u16>,
    ) -> Result<(AssignedScalar, AssignedScalars), Error> {
        layouter.assign_region(
            || "decompose address in one-MiB commitment",
            |mut region| {
                self.q_address.enable(&mut region, 0)?;
                let address_cell = region.assign_advice(
                    || "address",
                    self.address,
                    0,
                    || address.map(|word| Fp::from(u64::from(word))),
                )?;
                let bits = self
                    .address_bits
                    .iter()
                    .zip(0_u32..20)
                    .map(|(column, bit)| {
                        region.assign_advice(
                            || format!("address bit {bit}"),
                            *column,
                            0,
                            || {
                                address
                                    .map(|word| Fp::from(u64::from((u32::from(word) >> bit) & 1)))
                            },
                        )
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                Ok((address_cell, bits))
            },
        )
    }

    pub(crate) fn assign_scalar(
        &self,
        mut layouter: impl Layouter<Fp>,
        value: Value<Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || "assign scalar",
            |mut region| region.assign_advice(|| "scalar", self.message[0], 0, || value),
        )
    }

    fn select_order(
        &self,
        mut layouter: impl Layouter<Fp>,
        bit: &AssignedCell<Fp, Fp>,
        current: &AssignedCell<Fp, Fp>,
        sibling: &AssignedCell<Fp, Fp>,
    ) -> Result<AssignedPair, Error> {
        layouter.assign_region(
            || "select Merkle child order",
            |mut region| self.assign_mux(&mut region, bit, current, sibling),
        )
    }

    fn assign_mux(
        &self,
        region: &mut Region<'_, Fp>,
        bit: &AssignedCell<Fp, Fp>,
        current: &AssignedCell<Fp, Fp>,
        sibling: &AssignedCell<Fp, Fp>,
    ) -> Result<AssignedPair, Error> {
        self.q_mux.enable(region, 0)?;
        bit.copy_advice(|| "bit", region, self.mux[0], 0)?;
        current.copy_advice(|| "current", region, self.mux[1], 0)?;
        sibling.copy_advice(|| "sibling", region, self.mux[2], 0)?;
        let combined = bit
            .value()
            .copied()
            .zip(current.value().copied())
            .zip(sibling.value().copied());
        let left = region.assign_advice(
            || "left",
            self.mux[3],
            0,
            || combined.map(|((choice, own), other)| own + choice * (other - own)),
        )?;
        let right = region.assign_advice(
            || "right",
            self.mux[4],
            0,
            || combined.map(|((choice, own), other)| other + choice * (own - other)),
        )?;
        Ok((left, right))
    }

    pub(crate) fn hash3(
        &self,
        mut layouter: impl Layouter<Fp>,
        domain: Fp,
        left: &AssignedCell<Fp, Fp>,
        right: &AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let message = layouter.assign_region(
            || "load Poseidon message",
            |mut region| {
                let left = left.copy_advice(|| "left", &mut region, self.message[0], 0)?;
                let right = right.copy_advice(|| "right", &mut region, self.message[1], 0)?;
                let capacity = region.assign_advice(
                    || "domain-separated capacity",
                    self.message[2],
                    0,
                    || {
                        Value::known(
                            Fp::from(2_u64) * Fp::from(1_u64 << 32) * Fp::from(1_u64 << 32)
                                + domain,
                        )
                    },
                )?;
                Ok([left, right, capacity])
            },
        )?;
        let chip = Pow5Chip::construct(self.poseidon.clone());
        let initial = message.map(StateWord::from);
        let output = <Pow5Chip<Fp, WIDTH, RATE> as PoseidonInstructions<
            Fp,
            P128Pow5T3,
            WIDTH,
            RATE,
        >>::permute(&chip, &mut layouter, &initial)?;
        Ok(output[0].clone().into())
    }
}

fn configure_address_gate(
    meta: &mut ConstraintSystem<Fp>,
    selector: Selector,
    address: Column<Advice>,
    bits: [Column<Advice>; TREE_DEPTH],
) {
    meta.create_gate("20-bit commitment address decomposition", |meta| {
        let enabled = meta.query_selector(selector);
        let address = meta.query_advice(address, Rotation::cur());
        let mut reconstructed = Expression::Constant(Fp::zero());
        let mut power = Fp::one();
        let mut constraints = Vec::with_capacity(TREE_DEPTH + 1);
        for column in bits {
            let bit = meta.query_advice(column, Rotation::cur());
            constraints.push(
                enabled.clone() * bit.clone() * (Expression::Constant(Fp::one()) - bit.clone()),
            );
            reconstructed = reconstructed + Expression::Constant(power) * bit;
            power = power.double();
        }
        constraints.push(enabled * (address - reconstructed));
        constraints
    });
}

fn configure_mux_gate(
    meta: &mut ConstraintSystem<Fp>,
    selector: Selector,
    mux: [Column<Advice>; 5],
) {
    meta.create_gate("Merkle path child order", |meta| {
        let enabled = meta.query_selector(selector);
        let bit = meta.query_advice(mux[0], Rotation::cur());
        let current = meta.query_advice(mux[1], Rotation::cur());
        let sibling = meta.query_advice(mux[2], Rotation::cur());
        let left = meta.query_advice(mux[3], Rotation::cur());
        let right = meta.query_advice(mux[4], Rotation::cur());
        let one = Expression::Constant(Fp::one());
        vec![
            enabled.clone() * bit.clone() * (one - bit.clone()),
            enabled.clone()
                * (left - (current.clone() + bit.clone() * (sibling.clone() - current.clone()))),
            enabled * (right - (sibling.clone() + bit * (current - sibling))),
        ]
    });
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use pasta_curves::Fp;
    use zksm83_memory::{HashDomain, RomImage, RomRead};

    use super::MerkleConfig;

    const K: u32 = 12;

    #[derive(Default)]
    struct RomAuthenticationCircuit {
        read: Option<RomRead>,
    }

    impl Circuit<Fp> for RomAuthenticationCircuit {
        type Config = MerkleConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            MerkleConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let root = config.authenticate(
                layouter.namespace(|| "ROM authentication"),
                HashDomain::RomLeaf,
                HashDomain::RomNode,
                self.read
                    .map_or(Value::unknown(), |read| Value::known(read.address)),
                self.read
                    .map_or(Value::unknown(), |read| Value::known(read.value)),
                self.read.map(|read| read.path),
            )?;
            layouter.constrain_instance(root.root.cell(), config.instance(), 0)
        }
    }

    #[test]
    fn rom_path_authentication_is_constrained() -> Result<(), Box<dyn std::error::Error>> {
        let image = RomImage::new(vec![0x00, 0x3e, 0x42, 0x76])?;
        let read = image.read(2)?;
        let circuit = RomAuthenticationCircuit { read: Some(read) };
        let prover = MockProver::run(K, &circuit, vec![vec![image.root().field()]])?;
        assert!(prover.verify().is_ok());
        Ok(())
    }

    #[test]
    fn rom_path_rejects_changed_root() -> Result<(), Box<dyn std::error::Error>> {
        let image = RomImage::new(vec![0x00, 0x3e, 0x42, 0x76])?;
        let changed = RomImage::new(vec![0x00, 0x3e, 0x43, 0x76])?;
        let circuit = RomAuthenticationCircuit {
            read: Some(image.read(2)?),
        };
        let prover = MockProver::run(K, &circuit, vec![vec![changed.root().field()]])?;
        assert!(prover.verify().is_err());
        Ok(())
    }
}
