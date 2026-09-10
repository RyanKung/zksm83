//! Padded VM state rows, range constraints, and exact continuity.

use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn},
    poly::Rotation,
};
use pasta_curves::Fp;
use zksm83_core::{ImeState, RunState, VmState};

const STATE_COLUMNS: usize = 20;

#[derive(Clone, Copy, Debug)]
pub(crate) struct StateColumns {
    pub(crate) a: Column<Advice>,
    pub(crate) b: Column<Advice>,
    pub(crate) c: Column<Advice>,
    pub(crate) d: Column<Advice>,
    pub(crate) e: Column<Advice>,
    pub(crate) h: Column<Advice>,
    pub(crate) l: Column<Advice>,
    pub(crate) flags: Column<Advice>,
    pub(crate) pc_low: Column<Advice>,
    pub(crate) pc_high: Column<Advice>,
    pub(crate) sp_low: Column<Advice>,
    pub(crate) sp_high: Column<Advice>,
    pub(crate) ime: Column<Advice>,
    pub(crate) run_state: Column<Advice>,
    pub(crate) m_cycles: Column<Advice>,
    pub(crate) memory_root: Column<Advice>,
    pub(crate) input_root: Column<Advice>,
    pub(crate) input_index: Column<Advice>,
    pub(crate) output_root: Column<Advice>,
    pub(crate) output_index: Column<Advice>,
}

impl StateColumns {
    fn create(meta: &mut ConstraintSystem<Fp>) -> Self {
        Self {
            a: meta.advice_column(),
            b: meta.advice_column(),
            c: meta.advice_column(),
            d: meta.advice_column(),
            e: meta.advice_column(),
            h: meta.advice_column(),
            l: meta.advice_column(),
            flags: meta.advice_column(),
            pc_low: meta.advice_column(),
            pc_high: meta.advice_column(),
            sp_low: meta.advice_column(),
            sp_high: meta.advice_column(),
            ime: meta.advice_column(),
            run_state: meta.advice_column(),
            m_cycles: meta.advice_column(),
            memory_root: meta.advice_column(),
            input_root: meta.advice_column(),
            input_index: meta.advice_column(),
            output_root: meta.advice_column(),
            output_index: meta.advice_column(),
        }
    }

    fn all(self) -> [Column<Advice>; STATE_COLUMNS] {
        [
            self.a,
            self.b,
            self.c,
            self.d,
            self.e,
            self.h,
            self.l,
            self.flags,
            self.pc_low,
            self.pc_high,
            self.sp_low,
            self.sp_high,
            self.ime,
            self.run_state,
            self.m_cycles,
            self.memory_root,
            self.input_root,
            self.input_index,
            self.output_root,
            self.output_index,
        ]
    }

    fn bytes(self) -> [Column<Advice>; 12] {
        [
            self.a,
            self.b,
            self.c,
            self.d,
            self.e,
            self.h,
            self.l,
            self.flags,
            self.pc_low,
            self.pc_high,
            self.sp_low,
            self.sp_high,
        ]
    }
}

#[derive(Clone, Debug)]
pub(crate) struct StateTraceConfig {
    pub(crate) active: Column<Advice>,
    pub(crate) before: StateColumns,
    pub(crate) after: StateColumns,
    q_row: Selector,
    pub(crate) byte_table: TableColumn,
    flag_table: TableColumn,
}

impl StateTraceConfig {
    pub(crate) fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let active = meta.advice_column();
        let before = StateColumns::create(meta);
        let after = StateColumns::create(meta);
        let q_row = meta.selector();
        let byte_table = meta.lookup_table_column();
        let flag_table = meta.lookup_table_column();
        for column in before.all().into_iter().chain(after.all()) {
            meta.enable_equality(column);
        }
        configure_range_lookups(meta, active, before, after, byte_table, flag_table);
        configure_row_gate(meta, q_row, active, before, after);
        Self {
            active,
            before,
            after,
            q_row,
            byte_table,
            flag_table,
        }
    }

    pub(crate) fn load_tables(&self, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        layouter.assign_table(
            || "byte range",
            |mut table| {
                for (offset, byte) in (u8::MIN..=u8::MAX).enumerate() {
                    table.assign_cell(
                        || "byte",
                        self.byte_table,
                        offset,
                        || Value::known(Fp::from(u64::from(byte))),
                    )?;
                }
                Ok(())
            },
        )?;
        layouter.assign_table(
            || "valid F register",
            |mut table| {
                for (offset, high_nibble) in (0_u8..=15).enumerate() {
                    table.assign_cell(
                        || "flags",
                        self.flag_table,
                        offset,
                        || Value::known(Fp::from(u64::from(high_nibble << 4))),
                    )?;
                }
                Ok(())
            },
        )
    }

    pub(crate) fn assign_row(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        transition: Option<(VmState, VmState)>,
    ) -> Result<(), Error> {
        self.q_row.enable(region, offset)?;
        let active = transition.is_some();
        region.assign_advice(
            || "active",
            self.active,
            offset,
            || Value::known(Fp::from(u64::from(active))),
        )?;
        let (before, after) = transition.map_or(
            (StateValues::zero(), StateValues::zero()),
            |(before, after)| (StateValues::from_vm(before), StateValues::from_vm(after)),
        );
        before.assign(region, self.before, offset)?;
        after.assign(region, self.after, offset)
    }

    pub(crate) fn assign_sentinel(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
    ) -> Result<(), Error> {
        region.assign_advice(
            || "sentinel active",
            self.active,
            offset,
            || Value::known(Fp::zero()),
        )?;
        StateValues::zero().assign(region, self.before, offset)?;
        StateValues::zero().assign(region, self.after, offset)
    }
}

#[derive(Clone, Copy)]
struct StateValues {
    values: [Fp; STATE_COLUMNS],
}

impl StateValues {
    const fn zero() -> Self {
        Self {
            values: [Fp::zero(); STATE_COLUMNS],
        }
    }

    fn from_vm(state: VmState) -> Self {
        let cpu = state.cpu();
        let registers = cpu.registers();
        let [pc_low, pc_high] = cpu.pc().to_le_bytes();
        let [sp_low, sp_high] = cpu.sp().to_le_bytes();
        Self {
            values: [
                byte(registers.a),
                byte(registers.b),
                byte(registers.c),
                byte(registers.d),
                byte(registers.e),
                byte(registers.h),
                byte(registers.l),
                byte(cpu.flags().byte()),
                byte(pc_low),
                byte(pc_high),
                byte(sp_low),
                byte(sp_high),
                Fp::from(ime_code(cpu.ime())),
                Fp::from(run_state_code(cpu.run_state())),
                Fp::from(cpu.m_cycles()),
                state.memory_root().field(),
                state.input_log().root().field(),
                Fp::from(state.input_log().next_index()),
                state.output_log().root().field(),
                Fp::from(state.output_log().next_index()),
            ],
        }
    }

    fn assign(
        self,
        region: &mut Region<'_, Fp>,
        columns: StateColumns,
        offset: usize,
    ) -> Result<(), Error> {
        for (column, value) in columns.all().iter().zip(self.values) {
            region.assign_advice(
                || "state component",
                *column,
                offset,
                || Value::known(value),
            )?;
        }
        Ok(())
    }
}

fn configure_range_lookups(
    meta: &mut ConstraintSystem<Fp>,
    active: Column<Advice>,
    before: StateColumns,
    after: StateColumns,
    byte_table: TableColumn,
    flag_table: TableColumn,
) {
    for column in before.bytes().into_iter().chain(after.bytes()) {
        meta.lookup(|meta| {
            let active = meta.query_advice(active, Rotation::cur());
            let value = meta.query_advice(column, Rotation::cur());
            vec![(active * value, byte_table)]
        });
    }
    for column in [before.flags, after.flags] {
        meta.lookup(|meta| {
            let active = meta.query_advice(active, Rotation::cur());
            let value = meta.query_advice(column, Rotation::cur());
            vec![(active * value, flag_table)]
        });
    }
}

fn configure_row_gate(
    meta: &mut ConstraintSystem<Fp>,
    selector: Selector,
    active_column: Column<Advice>,
    before: StateColumns,
    after: StateColumns,
) {
    meta.create_gate("padded state rows and continuity", |meta| {
        let enabled = meta.query_selector(selector);
        let active = meta.query_advice(active_column, Rotation::cur());
        let next_active = meta.query_advice(active_column, Rotation::next());
        let one = Expression::Constant(Fp::one());
        let mut constraints = vec![
            enabled.clone() * active.clone() * (one.clone() - active.clone()),
            enabled.clone() * next_active.clone() * (one.clone() - active.clone()),
        ];
        for (before_column, after_column) in before.all().iter().zip(after.all()) {
            let before_current = meta.query_advice(*before_column, Rotation::cur());
            let before_next = meta.query_advice(*before_column, Rotation::next());
            let after_current = meta.query_advice(after_column, Rotation::cur());
            constraints.push(
                enabled.clone() * next_active.clone() * (after_current.clone() - before_next),
            );
            constraints.push(enabled.clone() * (one.clone() - active.clone()) * before_current);
            constraints.push(enabled.clone() * (one.clone() - active.clone()) * after_current);
        }
        for column in [before.ime, after.ime, before.run_state, after.run_state] {
            let value = meta.query_advice(column, Rotation::cur());
            constraints.push(
                enabled.clone()
                    * active.clone()
                    * value.clone()
                    * (value.clone() - Expression::Constant(Fp::one()))
                    * (value - Expression::Constant(Fp::from(2))),
            );
        }
        constraints
    });
}

fn byte(value: u8) -> Fp {
    Fp::from(u64::from(value))
}

const fn ime_code(ime: ImeState) -> u64 {
    match ime {
        ImeState::Disabled => 0,
        ImeState::EnablePending => 1,
        ImeState::Enabled => 2,
    }
}

const fn run_state_code(state: RunState) -> u64 {
    match state {
        RunState::Running => 0,
        RunState::Halted => 1,
        RunState::Stopped => 2,
        RunState::HaltBug => 3,
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use pasta_curves::Fp;
    use zksm83_core::{BusWitness, StepInput, StepRelation, VmState};
    use zksm83_memory::{MemoryImage, RomImage};

    use super::StateTraceConfig;

    const K: u32 = 9;
    const CAPACITY: usize = 4;

    #[derive(Default)]
    struct StateCircuit {
        transitions: Vec<(VmState, VmState)>,
    }

    impl Circuit<Fp> for StateCircuit {
        type Config = StateTraceConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            StateTraceConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            config.load_tables(layouter.namespace(|| "state tables"))?;
            layouter.assign_region(
                || "state rows",
                |mut region| {
                    let mut transitions = self.transitions.iter().copied();
                    for offset in 0..CAPACITY {
                        config.assign_row(&mut region, offset, transitions.next())?;
                    }
                    config.assign_sentinel(&mut region, CAPACITY)
                },
            )
        }
    }

    #[test]
    fn contiguous_state_rows_accept() -> Result<(), Box<dyn std::error::Error>> {
        let rom = RomImage::new(vec![0x00, 0x76])?;
        let memory = MemoryImage::zeroed()?;
        let initial = VmState::profile_initial(rom.root(), memory.root());
        let (after_nop, _) =
            StepRelation::apply(initial, StepInput::new(vec![BusWitness::Rom(rom.read(0)?)]))?;
        let (after_halt, _) = StepRelation::apply(
            after_nop,
            StepInput::new(vec![BusWitness::Rom(rom.read(1)?)]),
        )?;
        let circuit = StateCircuit {
            transitions: vec![(initial, after_nop), (after_nop, after_halt)],
        };
        let prover = MockProver::run(K, &circuit, vec![])?;
        let result = prover.verify();
        assert!(result.is_ok(), "{result:?}");
        Ok(())
    }

    #[test]
    fn discontinuous_state_rows_reject() -> Result<(), Box<dyn std::error::Error>> {
        let rom = RomImage::new(vec![0x00])?;
        let memory = MemoryImage::zeroed()?;
        let initial = VmState::profile_initial(rom.root(), memory.root());
        let (after, _) =
            StepRelation::apply(initial, StepInput::new(vec![BusWitness::Rom(rom.read(0)?)]))?;
        let circuit = StateCircuit {
            transitions: vec![(initial, after), (initial, after)],
        };
        let prover = MockProver::run(K, &circuit, vec![])?;
        assert!(prover.verify().is_err());
        Ok(())
    }
}
