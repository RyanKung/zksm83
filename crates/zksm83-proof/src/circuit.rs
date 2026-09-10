//! Integrated execution circuit for one public instruction/event shape.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use pasta_curves::Fp;
use zksm83_trace::{TraceRow, Witness};

use crate::{
    alu::AluConfig,
    authentication::AuthenticationConfig,
    bus::{AssignedBusRow, BusConfig},
    control::ControlConfig,
    data::DataConfig,
    decode::DecodeConfig,
    flags::FlagConfig,
    frame::FrameConfig,
    opcode::OpcodeTableConfig,
    public::{BoundaryLocation, PublicConfig, PublicInputs},
    shape::{ExecutionShape, ShapeConfig},
    state::StateTraceConfig,
    word_alu::WordAluConfig,
};

#[derive(Clone, Debug)]
pub(crate) struct ExecutionConfig {
    alu: AluConfig,
    word_alu: WordAluConfig,
    opcode: OpcodeTableConfig,
    shape: ShapeConfig,
    state: StateTraceConfig,
    flags: FlagConfig,
    bus: BusConfig,
    frame: FrameConfig,
    decode: DecodeConfig,
    control: ControlConfig,
    data: DataConfig,
    public: PublicConfig,
    authentication: AuthenticationConfig,
}

pub(crate) struct ExecutionCircuit<'a> {
    pub(crate) shape: ExecutionShape,
    pub(crate) witness: Option<&'a Witness>,
    pub(crate) public_inputs: Option<PublicInputs>,
}

impl Circuit<Fp> for ExecutionCircuit<'_> {
    type Config = ExecutionConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            shape: self.shape.clone(),
            witness: None,
            public_inputs: None,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let opcode = OpcodeTableConfig::configure(meta);
        let shape = ShapeConfig::configure(meta);
        let state = StateTraceConfig::configure(meta);
        let flags = FlagConfig::configure(meta, &state);
        let bus = BusConfig::configure(meta, &shape, &state);
        let frame = FrameConfig::configure(meta, &opcode, &state);
        let decode = DecodeConfig::configure(meta, &opcode, &shape, &state);
        let control = ControlConfig::configure(meta, &shape, &opcode, &state, &flags, &bus);
        let data = DataConfig::configure(meta, &shape, &opcode, &state, &bus);
        let alu = AluConfig::configure(meta, &shape, &state, &flags, &bus);
        let word_alu = WordAluConfig::configure(meta, &shape, &state, &flags, &bus);
        let authentication = AuthenticationConfig::configure(meta);
        let public = PublicConfig::configure(meta, &state, authentication.instance());
        ExecutionConfig {
            alu,
            word_alu,
            opcode,
            shape,
            state,
            flags,
            bus,
            frame,
            decode,
            control,
            data,
            public,
            authentication,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        config.opcode.load(layouter.namespace(|| "opcode table"))?;
        config
            .state
            .load_tables(layouter.namespace(|| "state tables"))?;
        config.alu.load(layouter.namespace(|| "DAA table"))?;
        config
            .authentication
            .load(layouter.namespace(|| "address tables"))?;
        let witness_rows = self
            .witness
            .map(|witness| witness.rows().collect::<Vec<_>>());
        let step_count = u64::try_from(self.shape.len()).map_err(|_| Error::Synthesis)?;
        let (assigned, public_cells) = layouter.assign_region(
            || "execution rows",
            |mut region| {
                let mut rows = Vec::with_capacity(self.shape.len());
                let mut public_cells = Vec::new();
                for (offset, shape) in self.shape.steps().enumerate() {
                    let row = witness_rows
                        .as_ref()
                        .and_then(|witness| witness.get(offset).copied());
                    let transition = row.map(|row| (row.before(), row.after()));
                    config.state.assign_row(&mut region, offset, transition)?;
                    config.flags.assign_row(&mut region, offset, transition)?;
                    config.opcode.assign_instruction(
                        &mut region,
                        offset,
                        Some(shape.instruction()),
                    )?;
                    config.shape.assign_row(&mut region, offset, shape)?;
                    let bus = config.bus.assign_row(&mut region, offset, row)?;
                    config.frame.enable(&mut region, offset)?;
                    config.decode.enable(&mut region, offset)?;
                    config.control.assign_row(&mut region, offset, row)?;
                    config.data.assign_row(&mut region, offset, row)?;
                    config.alu.assign_row(&mut region, offset, row)?;
                    config.word_alu.assign_row(&mut region, offset, row)?;
                    let cells = config.public.assign_row(
                        &mut region,
                        offset,
                        BoundaryLocation {
                            first: offset == 0,
                            last: offset + 1 == self.shape.len(),
                        },
                        step_count,
                        self.public_inputs,
                    )?;
                    if offset == 0 {
                        public_cells = cells;
                    }
                    rows.push(bus);
                }
                config
                    .state
                    .assign_sentinel(&mut region, self.shape.len())?;
                Ok((rows, public_cells))
            },
        )?;
        config
            .public
            .constrain_instances(&mut layouter, &public_cells)?;
        self.constrain_authentication(&config, &assigned, &witness_rows, &mut layouter)
    }
}

impl ExecutionCircuit<'_> {
    fn constrain_authentication(
        &self,
        config: &ExecutionConfig,
        assigned: &[AssignedBusRow],
        witness_rows: &Option<Vec<&TraceRow>>,
        layouter: &mut impl Layouter<Fp>,
    ) -> Result<(), Error> {
        for (offset, (shape, bus)) in self.shape.steps().zip(assigned).enumerate() {
            let row = witness_rows
                .as_ref()
                .and_then(|witness| witness.get(offset).copied());
            config.authentication.constrain_row(
                layouter.namespace(|| format!("authenticate step {offset}")),
                shape,
                row,
                bus,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::dev::MockProver;
    use zksm83_memory::{MemoryImage, RomImage};
    use zksm83_trace::TraceBuilder;

    use super::ExecutionCircuit;
    use crate::ExecutionShape;

    const K: u32 = 15;

    #[test]
    fn integrated_authenticated_trace_accepts() -> Result<(), Box<dyn std::error::Error>> {
        let program = vec![
            0x21, 0x00, 0x80, // LD HL, 0x8000
            0x36, 0x2a, // LD (HL), 0x2a
            0x7e, // LD A, (HL)
            0xc6, 0x10, // ADD A, 0x10
            0xe0, 0xf1, // LDH (0xff00 + 0xf1), A
            0x76, // HALT
        ];
        let rom = RomImage::new(program)?;
        let memory = MemoryImage::zeroed()?;
        let witness = TraceBuilder::new(rom, memory, Vec::new()).run(20)?;
        let shape = ExecutionShape::from_witness(&witness)?;
        let circuit = ExecutionCircuit {
            shape,
            witness: Some(&witness),
            public_inputs: Some(crate::PublicInputs::from_witness(&witness, [0; 4])),
        };
        let instances = crate::PublicInputs::from_witness(&witness, [0; 4]).instances();
        let prover = MockProver::run(K, &circuit, vec![instances])?;
        prover.assert_satisfied();
        Ok(())
    }
}
