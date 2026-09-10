//! Instruction metadata frame constraints for CPU state components.

use halo2_proofs::{
    circuit::Region,
    plonk::{ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::Fp;

use crate::{opcode::OpcodeTableConfig, state::StateTraceConfig};

#[derive(Clone, Copy, Debug)]
pub(crate) struct FrameConfig {
    selector: Selector,
}

impl FrameConfig {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<Fp>,
        opcode: &OpcodeTableConfig,
        state: &StateTraceConfig,
    ) -> Self {
        let selector = meta.selector();
        meta.create_gate("opcode frame and activity", |meta| {
            let enabled = meta.query_selector(selector);
            let state_active = meta.query_advice(state.active, Rotation::cur());
            let opcode_active = meta.query_advice(opcode.active, Rotation::cur());
            let one = Expression::Constant(Fp::one());
            let mut constraints = vec![enabled.clone() * (state_active.clone() - opcode_active)];
            let pairs = component_column_pairs(state, opcode);
            for (before, after, write) in pairs {
                let before = meta.query_advice(before, Rotation::cur());
                let after = meta.query_advice(after, Rotation::cur());
                let writable = meta.query_advice(write, Rotation::cur());
                constraints.push(enabled.clone() * (one.clone() - writable) * (after - before));
            }
            constraints
        });
        Self { selector }
    }

    pub(crate) fn enable(&self, region: &mut Region<'_, Fp>, offset: usize) -> Result<(), Error> {
        self.selector.enable(region, offset)
    }
}

fn component_column_pairs(
    state: &StateTraceConfig,
    opcode: &OpcodeTableConfig,
) -> Vec<(
    halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
)> {
    let before = state.before;
    let after = state.after;
    let [
        write_a,
        write_b,
        write_c,
        write_d,
        write_e,
        write_h,
        write_l,
        write_f,
        write_pc,
        write_sp,
        write_ime,
        write_run,
        write_cycles,
    ] = opcode.write_bits;
    vec![
        (before.a, after.a, write_a),
        (before.b, after.b, write_b),
        (before.c, after.c, write_c),
        (before.d, after.d, write_d),
        (before.e, after.e, write_e),
        (before.h, after.h, write_h),
        (before.l, after.l, write_l),
        (before.flags, after.flags, write_f),
        (before.pc_low, after.pc_low, write_pc),
        (before.pc_high, after.pc_high, write_pc),
        (before.sp_low, after.sp_low, write_sp),
        (before.sp_high, after.sp_high, write_sp),
        (before.ime, after.ime, write_ime),
        (before.run_state, after.run_state, write_run),
        (before.m_cycles, after.m_cycles, write_cycles),
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
    use zksm83_core::{CpuState, Flags, ImeState, Registers, RunState, VmState};
    use zksm83_isa::{OPCODE_TABLE, OpcodeClassification};
    use zksm83_memory::{MemoryImage, RomImage};

    use super::FrameConfig;
    use crate::{opcode::OpcodeTableConfig, state::StateTraceConfig};

    #[derive(Clone, Debug)]
    struct TestConfig {
        opcode: OpcodeTableConfig,
        state: StateTraceConfig,
        frame: FrameConfig,
    }

    struct FrameCircuit {
        mutate_a: bool,
    }

    impl Circuit<Fp> for FrameCircuit {
        type Config = TestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self { mutate_a: false }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let opcode = OpcodeTableConfig::configure(meta);
            let state = StateTraceConfig::configure(meta);
            let frame = FrameConfig::configure(meta, &opcode, &state);
            TestConfig {
                opcode,
                state,
                frame,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            config.opcode.load(layouter.namespace(|| "opcodes"))?;
            config
                .state
                .load_tables(layouter.namespace(|| "state ranges"))?;
            let before = initial_state()?;
            let after = after_nop(before, self.mutate_a)?;
            let instruction = match OPCODE_TABLE.primary(0x00) {
                OpcodeClassification::Defined(instruction) => instruction,
                OpcodeClassification::Undefined(_) => return Err(Error::Synthesis),
            };
            layouter.assign_region(
                || "framed instruction",
                |mut region| {
                    config
                        .state
                        .assign_row(&mut region, 0, Some((before, after)))?;
                    config.state.assign_sentinel(&mut region, 1)?;
                    config
                        .opcode
                        .assign_instruction(&mut region, 0, Some(instruction))?;
                    config.frame.enable(&mut region, 0)
                },
            )?;
            Ok(())
        }
    }

    fn initial_state() -> Result<VmState, Error> {
        let rom = RomImage::new(vec![0]).map_err(|_| Error::Synthesis)?.root();
        let memory = MemoryImage::zeroed().map_err(|_| Error::Synthesis)?.root();
        Ok(VmState::profile_initial(rom, memory))
    }

    fn after_nop(before: VmState, mutate_a: bool) -> Result<VmState, Error> {
        let mut registers = before.cpu().registers();
        registers.a = u8::from(mutate_a);
        let cpu = CpuState::new(
            Registers { ..registers },
            Flags::from_byte(0).map_err(|_| Error::Synthesis)?,
            1,
            before.cpu().sp(),
            ImeState::Disabled,
            RunState::Running,
            1,
        );
        VmState::from_parts(
            cpu,
            before.rom_root(),
            before.memory_root(),
            before.input_log(),
            before.output_log(),
        )
        .map_err(|_| Error::Synthesis)
    }

    #[test]
    fn frame_allows_declared_pc_and_cycle_changes() -> Result<(), Error> {
        let prover = MockProver::run(11, &FrameCircuit { mutate_a: false }, vec![])?;
        assert!(prover.verify().is_ok());
        Ok(())
    }

    #[test]
    fn frame_rejects_hidden_register_mutation() -> Result<(), Error> {
        let prover = MockProver::run(11, &FrameCircuit { mutate_a: true }, vec![])?;
        assert!(prover.verify().is_err());
        Ok(())
    }
}
