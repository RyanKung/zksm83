//! Fixed complete opcode lookup constrained inside Halo2.

use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, TableColumn},
    poly::Rotation,
};
use pasta_curves::Fp;
use zksm83_isa::{
    DecodedInstruction, InstructionEncoding, OPCODE_TABLE, OpcodeClassification, StateComponent,
};

const STATE_COMPONENTS: usize = 13;
const METADATA_COLUMNS: usize = 29;

#[derive(Clone, Debug)]
pub(crate) struct OpcodeTableConfig {
    advice: Vec<Column<Advice>>,
    table: Vec<TableColumn>,
    pub(crate) active: Column<Advice>,
    pub(crate) encoding_kind: Column<Advice>,
    pub(crate) opcode: Column<Advice>,
    pub(crate) operation: Column<Advice>,
    pub(crate) argument_zero: Column<Advice>,
    pub(crate) argument_one: Column<Advice>,
    pub(crate) byte_len: Column<Advice>,
    pub(crate) base_m_cycles: Column<Advice>,
    pub(crate) taken_m_cycles: Column<Advice>,
    pub(crate) opcode_fetches: Column<Advice>,
    pub(crate) immediate_reads: Column<Advice>,
    pub(crate) data_reads: Column<Advice>,
    pub(crate) data_writes: Column<Advice>,
    pub(crate) taken_data_reads: Column<Advice>,
    pub(crate) taken_data_writes: Column<Advice>,
    pub(crate) write_bits: [Column<Advice>; STATE_COMPONENTS],
}

impl OpcodeTableConfig {
    pub(crate) fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let mut advice = Vec::with_capacity(METADATA_COLUMNS);
        let mut add_advice = || {
            let column = meta.advice_column();
            advice.push(column);
            column
        };
        let active = add_advice();
        let encoding_kind = add_advice();
        let opcode = add_advice();
        let _class = add_advice();
        let operation = add_advice();
        let argument_zero = add_advice();
        let argument_one = add_advice();
        let byte_len = add_advice();
        let base_m_cycles = add_advice();
        let taken_m_cycles = add_advice();
        let opcode_fetches = add_advice();
        let immediate_reads = add_advice();
        let data_reads = add_advice();
        let data_writes = add_advice();
        let taken_data_reads = add_advice();
        let taken_data_writes = add_advice();
        let write_bits = std::array::from_fn(|_| add_advice());
        let table = (0..METADATA_COLUMNS)
            .map(|_| meta.lookup_table_column())
            .collect::<Vec<_>>();
        meta.lookup(|meta| {
            advice
                .iter()
                .zip(table.iter())
                .map(|(advice, table)| (meta.query_advice(*advice, Rotation::cur()), *table))
                .collect::<Vec<(Expression<Fp>, TableColumn)>>()
        });
        Self {
            advice,
            table,
            active,
            encoding_kind,
            opcode,
            operation,
            argument_zero,
            argument_one,
            byte_len,
            base_m_cycles,
            taken_m_cycles,
            opcode_fetches,
            immediate_reads,
            data_reads,
            data_writes,
            taken_data_reads,
            taken_data_writes,
            write_bits,
        }
    }

    pub(crate) fn load(&self, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        layouter.assign_table(
            || "complete SM83 opcode table",
            |mut table| {
                self.assign_table_row(&mut table, 0, [Fp::zero(); METADATA_COLUMNS])?;
                let primary = OPCODE_TABLE
                    .primary_entries()
                    .filter_map(|entry| match entry {
                        OpcodeClassification::Defined(decoded) => Some(decoded),
                        OpcodeClassification::Undefined(_) => None,
                    });
                let cb = OPCODE_TABLE.cb_entries();
                for (offset, decoded) in (1_usize..).zip(primary.chain(cb)) {
                    self.assign_table_row(&mut table, offset, metadata_values(decoded))?;
                }
                Ok(())
            },
        )
    }

    pub(crate) fn assign_instruction(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        instruction: Option<DecodedInstruction>,
    ) -> Result<(), Error> {
        let values = instruction.map_or([Fp::zero(); METADATA_COLUMNS], metadata_values);
        for (column, value) in self.advice.iter().zip(values) {
            region.assign_advice(
                || "opcode metadata",
                *column,
                offset,
                || Value::known(value),
            )?;
        }
        Ok(())
    }

    fn assign_table_row(
        &self,
        table: &mut halo2_proofs::circuit::Table<'_, Fp>,
        offset: usize,
        values: [Fp; METADATA_COLUMNS],
    ) -> Result<(), Error> {
        for (column, value) in self.table.iter().zip(values) {
            table.assign_cell(
                || "opcode metadata value",
                *column,
                offset,
                || Value::known(value),
            )?;
        }
        Ok(())
    }
}

fn metadata_values(instruction: DecodedInstruction) -> [Fp; METADATA_COLUMNS] {
    let (encoding_kind, opcode) = match instruction.encoding() {
        InstructionEncoding::Primary(opcode) => (0_u8, opcode.byte()),
        InstructionEncoding::Cb(opcode) => (1_u8, opcode.byte()),
    };
    let descriptor = instruction.descriptor();
    let timing = instruction.timing();
    let bus = instruction.bus();
    let access = instruction.state_access();
    let writes = |component| Fp::from(u64::from(access.writes(component)));
    [
        Fp::one(),
        Fp::from(u64::from(encoding_kind)),
        Fp::from(u64::from(opcode)),
        Fp::from(u64::from(instruction.class().code())),
        Fp::from(u64::from(descriptor.operation)),
        Fp::from(u64::from(descriptor.argument_zero)),
        Fp::from(u64::from(descriptor.argument_one)),
        Fp::from(u64::from(instruction.byte_len())),
        Fp::from(u64::from(timing.base_m_cycles())),
        Fp::from(u64::from(
            timing.taken_m_cycles().map_or(0, |cycles| cycles),
        )),
        Fp::from(u64::from(bus.opcode_fetches())),
        Fp::from(u64::from(bus.immediate_reads())),
        Fp::from(u64::from(bus.data_reads())),
        Fp::from(u64::from(bus.data_writes())),
        Fp::from(u64::from(bus.taken_data_reads())),
        Fp::from(u64::from(bus.taken_data_writes())),
        writes(StateComponent::A),
        writes(StateComponent::B),
        writes(StateComponent::C),
        writes(StateComponent::D),
        writes(StateComponent::E),
        writes(StateComponent::H),
        writes(StateComponent::L),
        writes(StateComponent::F),
        writes(StateComponent::Pc),
        writes(StateComponent::Sp),
        writes(StateComponent::Ime),
        writes(StateComponent::RunState),
        writes(StateComponent::MCycles),
    ]
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use pasta_curves::Fp;
    use zksm83_isa::{DecodedInstruction, OPCODE_TABLE, OpcodeClassification};

    use super::{METADATA_COLUMNS, OpcodeTableConfig, metadata_values};

    const K: u32 = 10;

    #[derive(Default)]
    struct OpcodeCircuit {
        instructions: Vec<DecodedInstruction>,
        tampered_first: bool,
    }

    impl Circuit<Fp> for OpcodeCircuit {
        type Config = OpcodeTableConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            OpcodeTableConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            config.load(layouter.namespace(|| "load opcodes"))?;
            layouter.assign_region(
                || "execution opcode rows",
                |mut region| {
                    for (offset, instruction) in self.instructions.iter().copied().enumerate() {
                        if self.tampered_first && offset == 0 {
                            let mut values = metadata_values(instruction);
                            let operation = values.get_mut(4).ok_or(Error::Synthesis)?;
                            *operation += Fp::one();
                            for (column, value) in config.advice.iter().zip(values) {
                                region.assign_advice(
                                    || "tampered metadata",
                                    *column,
                                    offset,
                                    || halo2_proofs::circuit::Value::known(value),
                                )?;
                            }
                        } else {
                            config.assign_instruction(&mut region, offset, Some(instruction))?;
                        }
                    }
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn complete_opcode_lookup_accepts_all_defined_encodings() -> Result<(), Error> {
        let primary = OPCODE_TABLE
            .primary_entries()
            .filter_map(|entry| match entry {
                OpcodeClassification::Defined(decoded) => Some(decoded),
                OpcodeClassification::Undefined(_) => None,
            });
        let circuit = OpcodeCircuit {
            instructions: primary.chain(OPCODE_TABLE.cb_entries()).collect(),
            tampered_first: false,
        };
        let prover = MockProver::run(K, &circuit, vec![])?;
        assert!(prover.verify().is_ok());
        Ok(())
    }

    #[test]
    fn opcode_lookup_rejects_changed_semantics() -> Result<(), Error> {
        let instruction = match OPCODE_TABLE.primary(0x00) {
            OpcodeClassification::Defined(decoded) => decoded,
            OpcodeClassification::Undefined(_) => return Err(Error::Synthesis),
        };
        let circuit = OpcodeCircuit {
            instructions: vec![instruction],
            tampered_first: true,
        };
        let prover = MockProver::run(K, &circuit, vec![])?;
        assert!(prover.verify().is_err());
        Ok(())
    }

    #[test]
    fn metadata_column_count_is_stable() {
        assert_eq!(METADATA_COLUMNS, 29);
    }
}
