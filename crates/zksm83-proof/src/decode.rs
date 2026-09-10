//! Linkage from public circuit shape to complete opcode metadata.

use halo2_proofs::{
    circuit::Region,
    plonk::{ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::Fp;

use crate::{
    opcode::OpcodeTableConfig,
    shape::{ARGUMENT_COUNT, BusEventKind, OPERATION_COUNT, ShapeConfig},
    state::StateTraceConfig,
};

#[derive(Clone, Copy, Debug)]
pub(crate) struct DecodeConfig {
    selector: Selector,
}

impl DecodeConfig {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<Fp>,
        opcode: &OpcodeTableConfig,
        shape: &ShapeConfig,
        state: &StateTraceConfig,
    ) -> Self {
        let selector = meta.selector();
        meta.create_gate("shape, opcode, timing, and bus-count linkage", |meta| {
            let enabled = meta.query_selector(selector);
            let one = Expression::Constant(Fp::one());
            let branch = meta.query_fixed(shape.branch_taken);
            let operation = weighted_fixed(meta, &shape.operation);
            let argument_zero = weighted_fixed(meta, &shape.argument_zero);
            let argument_one = weighted_fixed(meta, &shape.argument_one);
            let opcode_operation = meta.query_advice(opcode.operation, Rotation::cur());
            let opcode_argument_zero = meta.query_advice(opcode.argument_zero, Rotation::cur());
            let opcode_argument_one = meta.query_advice(opcode.argument_one, Rotation::cur());
            let base_cycles = meta.query_advice(opcode.base_m_cycles, Rotation::cur());
            let taken_cycles = meta.query_advice(opcode.taken_m_cycles, Rotation::cur());
            let conditional = conditional_timing(meta, shape);
            let cycle_increment =
                base_cycles.clone() + conditional * branch.clone() * (taken_cycles - base_cycles);
            let before_cycles = meta.query_advice(state.before.m_cycles, Rotation::cur());
            let after_cycles = meta.query_advice(state.after.m_cycles, Rotation::cur());
            let opcode_events = event_count(meta, shape, BusEventKind::OpcodeFetch);
            let immediate_events = event_count(meta, shape, BusEventKind::ImmediateRead);
            let data_read_events = event_count(meta, shape, BusEventKind::RomRead)
                + event_count(meta, shape, BusEventKind::MemoryRead)
                + event_count(meta, shape, BusEventKind::InputRead);
            let data_write_events = event_count(meta, shape, BusEventKind::MemoryWrite)
                + event_count(meta, shape, BusEventKind::OutputWrite);
            let base_reads = meta.query_advice(opcode.data_reads, Rotation::cur());
            let taken_reads = meta.query_advice(opcode.taken_data_reads, Rotation::cur());
            let base_writes = meta.query_advice(opcode.data_writes, Rotation::cur());
            let taken_writes = meta.query_advice(opcode.taken_data_writes, Rotation::cur());
            let byte_len = meta.query_advice(opcode.byte_len, Rotation::cur());
            vec![
                enabled.clone() * (meta.query_advice(opcode.active, Rotation::cur()) - one.clone()),
                enabled.clone() * (opcode_operation - operation),
                enabled.clone() * (opcode_argument_zero - argument_zero),
                enabled.clone() * (opcode_argument_one - argument_one),
                enabled.clone() * (after_cycles - before_cycles - cycle_increment),
                enabled.clone()
                    * (meta.query_advice(opcode.opcode_fetches, Rotation::cur())
                        - opcode_events.clone()),
                enabled.clone()
                    * (meta.query_advice(opcode.immediate_reads, Rotation::cur())
                        - immediate_events.clone()),
                enabled.clone() * (byte_len - opcode_events - immediate_events),
                enabled.clone() * (data_read_events - base_reads - branch.clone() * taken_reads),
                enabled.clone() * (data_write_events - base_writes - branch.clone() * taken_writes),
                enabled * branch.clone() * (one - branch),
            ]
        });
        Self { selector }
    }

    pub(crate) fn enable(&self, region: &mut Region<'_, Fp>, offset: usize) -> Result<(), Error> {
        self.selector.enable(region, offset)
    }
}

fn weighted_fixed<const N: usize>(
    meta: &mut halo2_proofs::plonk::VirtualCells<'_, Fp>,
    columns: &[halo2_proofs::plonk::Column<halo2_proofs::plonk::Fixed>; N],
) -> Expression<Fp> {
    columns
        .iter()
        .zip(0_u64..)
        .fold(Expression::Constant(Fp::zero()), |sum, (column, code)| {
            sum + Expression::Constant(Fp::from(code)) * meta.query_fixed(*column)
        })
}

fn conditional_timing(
    meta: &mut halo2_proofs::plonk::VirtualCells<'_, Fp>,
    shape: &ShapeConfig,
) -> Expression<Fp> {
    let conditional_operation = [3_usize, 20, 28, 34]
        .into_iter()
        .filter_map(|index| shape.operation.get(index))
        .fold(Expression::Constant(Fp::zero()), |sum, column| {
            sum + meta.query_fixed(*column)
        });
    let unconditional = shape
        .argument_zero
        .first()
        .map_or(Expression::Constant(Fp::zero()), |column| {
            meta.query_fixed(*column)
        });
    conditional_operation * (Expression::Constant(Fp::one()) - unconditional)
}

fn event_count(
    meta: &mut halo2_proofs::plonk::VirtualCells<'_, Fp>,
    shape: &ShapeConfig,
    kind: BusEventKind,
) -> Expression<Fp> {
    shape
        .event_kinds
        .iter()
        .filter_map(|columns| columns.get(kind_index(kind)))
        .fold(Expression::Constant(Fp::zero()), |sum, column| {
            sum + meta.query_fixed(*column)
        })
}

const fn kind_index(kind: BusEventKind) -> usize {
    match kind {
        BusEventKind::Unused => 0,
        BusEventKind::OpcodeFetch => 1,
        BusEventKind::ImmediateRead => 2,
        BusEventKind::RomRead => 3,
        BusEventKind::MemoryRead => 4,
        BusEventKind::MemoryWrite => 5,
        BusEventKind::InputRead => 6,
        BusEventKind::OutputWrite => 7,
    }
}

const _: [(); OPERATION_COUNT] = [(); 41];
const _: [(); ARGUMENT_COUNT] = [(); 9];
