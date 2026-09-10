//! Canonical public-instance mapping and execution-boundary constraints.

use halo2_proofs::{
    circuit::{AssignedCell, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector},
    poly::Rotation,
};
use pasta_curves::Fp;
use thiserror::Error as ThisError;
use zksm83_memory::{CommitmentRoot, LogAccumulator, LogKind};
use zksm83_trace::Witness;

use crate::state::StateTraceConfig;

/// Numeric protocol identifier for `zksm83-core/2` with Poseidon-v2 commitments.
pub const VM_VERSION_ID: u64 = 2;
/// Numeric protocol identifier for `sm83-core-v1`.
pub const MACHINE_PROFILE_ID: u64 = 1;
/// Number of scalar public instances in the v1 statement.
pub const PUBLIC_INSTANCE_COUNT: usize = 13;

/// Public values bound by one execution proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicInputs {
    /// Numeric VM protocol version.
    pub vm_version: u64,
    /// Numeric machine-profile identifier.
    pub machine_profile: u64,
    /// Immutable program commitment.
    pub rom_root: CommitmentRoot,
    /// Mutable-memory commitment before execution.
    pub initial_memory_root: CommitmentRoot,
    /// Mutable-memory commitment after execution.
    pub final_memory_root: CommitmentRoot,
    /// Commitment to the exact consumed private-input sequence.
    pub input_root: CommitmentRoot,
    /// Exact executed instruction count.
    pub step_count: u64,
    /// Exact final M-cycle count.
    pub cycle_count: u64,
    /// Commitment to the exact public-output sequence.
    pub output_root: CommitmentRoot,
    /// Deterministic SHA-256 receipt identifier as four little-endian limbs.
    pub receipt_id_limbs: [u64; 4],
}

impl PublicInputs {
    /// Derives all execution fields from a validated witness and accepts the
    /// externally recomputed receipt identifier limbs.
    #[must_use]
    pub fn from_witness(witness: &Witness, receipt_id_limbs: [u64; 4]) -> Self {
        let initial = witness.initial_state();
        let final_state = witness.final_state();
        Self {
            vm_version: VM_VERSION_ID,
            machine_profile: MACHINE_PROFILE_ID,
            rom_root: initial.rom_root(),
            initial_memory_root: initial.memory_root(),
            final_memory_root: final_state.memory_root(),
            input_root: final_state.input_log().root(),
            step_count: witness.step_count(),
            cycle_count: final_state.cpu().m_cycles(),
            output_root: final_state.output_log().root(),
            receipt_id_limbs,
        }
    }

    /// Returns the ordered Pasta-field instance vector.
    #[must_use]
    pub fn instances(self) -> Vec<Fp> {
        self.values().to_vec()
    }

    /// Rejects public values that do not exactly describe the witness.
    pub fn validate_witness(self, witness: &Witness) -> Result<(), PublicInputError> {
        let expected = Self::from_witness(witness, self.receipt_id_limbs);
        if self == expected {
            Ok(())
        } else {
            Err(PublicInputError::WitnessMismatch)
        }
    }

    pub(crate) fn values(self) -> [Fp; PUBLIC_INSTANCE_COUNT] {
        let [id_zero, id_one, id_two, id_three] = self.receipt_id_limbs;
        [
            Fp::from(self.vm_version),
            Fp::from(self.machine_profile),
            self.rom_root.field(),
            self.initial_memory_root.field(),
            self.final_memory_root.field(),
            self.input_root.field(),
            Fp::from(self.step_count),
            Fp::from(self.cycle_count),
            self.output_root.field(),
            Fp::from(id_zero),
            Fp::from(id_one),
            Fp::from(id_two),
            Fp::from(id_three),
        ]
    }
}

/// Invalid public input supplied to proof construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ThisError)]
pub enum PublicInputError {
    /// At least one execution-derived field differs from the witness.
    #[error("public inputs do not exactly describe the execution witness")]
    WitnessMismatch,
}

#[derive(Clone, Copy, Debug)]
struct PublicColumns {
    vm_version: Column<Advice>,
    machine_profile: Column<Advice>,
    rom_root: Column<Advice>,
    initial_memory_root: Column<Advice>,
    final_memory_root: Column<Advice>,
    input_root: Column<Advice>,
    step_count: Column<Advice>,
    cycle_count: Column<Advice>,
    output_root: Column<Advice>,
    receipt_id: [Column<Advice>; 4],
}

impl PublicColumns {
    fn create(meta: &mut ConstraintSystem<Fp>) -> Self {
        let [
            vm_version,
            machine_profile,
            rom_root,
            initial_memory_root,
            final_memory_root,
            input_root,
            step_count,
            cycle_count,
            output_root,
        ] = std::array::from_fn(|_| meta.advice_column());
        Self {
            vm_version,
            machine_profile,
            rom_root,
            initial_memory_root,
            final_memory_root,
            input_root,
            step_count,
            cycle_count,
            output_root,
            receipt_id: std::array::from_fn(|_| meta.advice_column()),
        }
    }

    fn all(self) -> [Column<Advice>; PUBLIC_INSTANCE_COUNT] {
        let [id_zero, id_one, id_two, id_three] = self.receipt_id;
        [
            self.vm_version,
            self.machine_profile,
            self.rom_root,
            self.initial_memory_root,
            self.final_memory_root,
            self.input_root,
            self.step_count,
            self.cycle_count,
            self.output_root,
            id_zero,
            id_one,
            id_two,
            id_three,
        ]
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PublicConfig {
    columns: PublicColumns,
    declared_steps: Column<Fixed>,
    q_first: Selector,
    q_last: Selector,
    instance: Column<Instance>,
}

impl PublicConfig {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<Fp>,
        state: &StateTraceConfig,
        instance: Column<Instance>,
    ) -> Self {
        let columns = PublicColumns::create(meta);
        let declared_steps = meta.fixed_column();
        let q_first = meta.selector();
        let q_last = meta.selector();
        for column in columns.all() {
            meta.enable_equality(column);
        }
        meta.enable_equality(instance);
        configure_initial_gate(meta, q_first, declared_steps, columns, state);
        configure_final_gate(meta, q_last, columns, state);
        Self {
            columns,
            declared_steps,
            q_first,
            q_last,
            instance,
        }
    }

    pub(crate) fn assign_row(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        location: BoundaryLocation,
        steps: u64,
        inputs: Option<PublicInputs>,
    ) -> Result<Vec<AssignedCell<Fp, Fp>>, Error> {
        if location.first {
            self.q_first.enable(region, offset)?;
        }
        if location.last {
            self.q_last.enable(region, offset)?;
        }
        region.assign_fixed(
            || "shape step count",
            self.declared_steps,
            offset,
            || Value::known(Fp::from(steps)),
        )?;
        let values = inputs.map(PublicInputs::values);
        self.columns
            .all()
            .into_iter()
            .enumerate()
            .map(|(index, column)| {
                region.assign_advice(
                    || "public statement value",
                    column,
                    offset,
                    || {
                        values
                            .and_then(|items| items.get(index).copied())
                            .map_or(Value::unknown(), Value::known)
                    },
                )
            })
            .collect()
    }

    pub(crate) fn constrain_instances(
        &self,
        layouter: &mut impl halo2_proofs::circuit::Layouter<Fp>,
        cells: &[AssignedCell<Fp, Fp>],
    ) -> Result<(), Error> {
        for (index, cell) in cells.iter().enumerate() {
            layouter.constrain_instance(cell.cell(), self.instance, index)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(crate) struct BoundaryLocation {
    pub(crate) first: bool,
    pub(crate) last: bool,
}

fn configure_initial_gate(
    meta: &mut ConstraintSystem<Fp>,
    selector: Selector,
    declared_steps: Column<Fixed>,
    public: PublicColumns,
    state: &StateTraceConfig,
) {
    let empty_input = LogAccumulator::empty(LogKind::Input).root().field();
    let empty_output = LogAccumulator::empty(LogKind::Output).root().field();
    meta.create_gate("fixed v1 initial state and public pre-state", |meta| {
        let q = meta.query_selector(selector);
        let mut constraints = vec![
            query(meta, public.vm_version) - constant(VM_VERSION_ID),
            query(meta, public.machine_profile) - constant(MACHINE_PROFILE_ID),
            query(meta, public.initial_memory_root) - query(meta, state.before.memory_root),
            query(meta, public.step_count) - meta.query_fixed(declared_steps),
            query(meta, state.before.sp_high) - constant(0xff),
            query(meta, state.before.input_root) - Expression::Constant(empty_input),
            query(meta, state.before.output_root) - Expression::Constant(empty_output),
        ];
        for column in [
            state.before.a,
            state.before.b,
            state.before.c,
            state.before.d,
            state.before.e,
            state.before.h,
            state.before.l,
            state.before.flags,
            state.before.pc_low,
            state.before.pc_high,
            state.before.sp_low,
            state.before.ime,
            state.before.run_state,
            state.before.m_cycles,
            state.before.input_index,
            state.before.output_index,
        ] {
            constraints.push(query(meta, column));
        }
        constraints
            .into_iter()
            .map(|constraint| q.clone() * constraint)
            .collect::<Vec<_>>()
    });
}

fn configure_final_gate(
    meta: &mut ConstraintSystem<Fp>,
    selector: Selector,
    public: PublicColumns,
    state: &StateTraceConfig,
) {
    meta.create_gate("public v1 post-state", |meta| {
        let q = meta.query_selector(selector);
        [
            query(meta, public.final_memory_root) - query(meta, state.after.memory_root),
            query(meta, public.input_root) - query(meta, state.after.input_root),
            query(meta, public.cycle_count) - query(meta, state.after.m_cycles),
            query(meta, public.output_root) - query(meta, state.after.output_root),
        ]
        .map(|constraint| q.clone() * constraint)
    });
}

fn query(
    meta: &mut halo2_proofs::plonk::VirtualCells<'_, Fp>,
    column: Column<Advice>,
) -> Expression<Fp> {
    meta.query_advice(column, Rotation::cur())
}

fn constant(value: u64) -> Expression<Fp> {
    Expression::Constant(Fp::from(value))
}
