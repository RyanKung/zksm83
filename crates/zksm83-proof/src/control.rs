//! Fetch, control-flow, IME, and terminal-state constraints.

use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::Fp;
use zksm83_isa::Operation;
use zksm83_trace::TraceRow;

use crate::{
    bus::BusConfig,
    expressions::{
        ROLE_DATA_ONE, ROLE_DATA_ZERO, ROLE_IMMEDIATE_ONE, ROLE_IMMEDIATE_ZERO, ROLE_OPCODE_ONE,
        ROLE_OPCODE_ZERO, argument_zero, event_address, event_value, operation, word,
    },
    flags::FlagConfig,
    opcode::OpcodeTableConfig,
    shape::ShapeConfig,
    state::StateTraceConfig,
};

#[derive(Clone, Copy, Debug)]
pub(crate) struct ControlConfig {
    relative_positive_wrap: Column<Advice>,
    relative_negative_wrap: Column<Advice>,
    relative_bits: [Column<Advice>; 8],
    q_row: Selector,
}

#[derive(Clone, Copy)]
struct ControlGate<'a> {
    relative_positive_wrap: Column<Advice>,
    relative_negative_wrap: Column<Advice>,
    relative_bits: [Column<Advice>; 8],
    q_row: Selector,
    shape: &'a ShapeConfig,
    opcode: &'a OpcodeTableConfig,
    state: &'a StateTraceConfig,
    flags: &'a FlagConfig,
    bus: &'a BusConfig,
}

impl ControlConfig {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<Fp>,
        shape: &ShapeConfig,
        opcode: &OpcodeTableConfig,
        state: &StateTraceConfig,
        flags: &FlagConfig,
        bus: &BusConfig,
    ) -> Self {
        let relative_positive_wrap = meta.advice_column();
        let relative_negative_wrap = meta.advice_column();
        let relative_bits = std::array::from_fn(|_| meta.advice_column());
        let q_row = meta.selector();
        let gate = ControlGate {
            relative_positive_wrap,
            relative_negative_wrap,
            relative_bits,
            q_row,
            shape,
            opcode,
            state,
            flags,
            bus,
        };
        meta.create_gate("fetch and SM83 control semantics", |meta| {
            control_constraints(meta, gate)
        });
        Self {
            relative_positive_wrap,
            relative_negative_wrap,
            relative_bits,
            q_row,
        }
    }

    pub(crate) fn assign_row(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        row: Option<&TraceRow>,
    ) -> Result<(), Error> {
        self.q_row.enable(region, offset)?;
        let mut relative_immediate = None;
        let wraps = row.map_or((None, None), |row| {
            let is_relative = matches!(
                row.effects().instruction().operation(),
                Operation::RelativeJump(_)
            );
            let immediate = row
                .effects()
                .bus_events()
                .find_map(|event| match event {
                    zksm83_core::BusEvent::ImmediateRead(read) => Some(read.value),
                    zksm83_core::BusEvent::MemoryImmediateRead(read) => Some(read.value),
                    _ => None,
                })
                .map_or(0, |value| value);
            relative_immediate = Some(if is_relative { immediate } else { 0 });
            if !is_relative || !row.effects().branch_taken() {
                return (Some(false), Some(false));
            }
            let before = i64::from(row.before().cpu().pc());
            let length = i64::from(row.effects().instruction().byte_len());
            let signed = i64::from(i8::from_ne_bytes([immediate]));
            let target = before + length + signed;
            (Some(target > 65_535), Some(target < 0))
        });
        assign_bool(region, self.relative_positive_wrap, offset, wraps.0)?;
        assign_bool(region, self.relative_negative_wrap, offset, wraps.1)?;
        for (column, bit) in self.relative_bits.iter().zip(0_u32..8) {
            let value = relative_immediate.map(|byte| (byte >> bit) & 1);
            region.assign_advice(
                || "relative offset bit",
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
}

fn control_constraints(
    meta: &mut halo2_proofs::plonk::VirtualCells<'_, Fp>,
    gate: ControlGate<'_>,
) -> Vec<Expression<Fp>> {
    let enabled = meta.query_selector(gate.q_row);
    let mut constraints = fetch_constraints(meta, enabled.clone(), gate);
    constraints.extend(relative_constraints(meta, enabled.clone(), gate));
    constraints.extend(program_counter_constraints(meta, enabled.clone(), gate));
    constraints.extend(condition_constraints(
        meta,
        enabled.clone(),
        gate.shape,
        gate.flags,
    ));
    constraints.extend(ime_constraints(
        meta,
        enabled.clone(),
        gate.shape,
        gate.state,
    ));
    constraints.extend(run_state_constraints(meta, enabled, gate.shape, gate.state));
    constraints
}

fn fetch_constraints(
    meta: &mut halo2_proofs::plonk::VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    gate: ControlGate<'_>,
) -> Vec<Expression<Fp>> {
    let before_pc = word(
        meta.query_advice(gate.state.before.pc_low, Rotation::cur()),
        meta.query_advice(gate.state.before.pc_high, Rotation::cur()),
    );
    let encoding_kind = meta.query_advice(gate.opcode.encoding_kind, Rotation::cur());
    let opcode_byte = meta.query_advice(gate.opcode.opcode, Rotation::cur());
    let opcode_fetches = meta.query_advice(gate.opcode.opcode_fetches, Rotation::cur());
    let immediate_zero = event_value(meta, gate.bus, gate.shape, ROLE_IMMEDIATE_ZERO);
    let relative_positive = meta.query_advice(gate.relative_positive_wrap, Rotation::cur());
    let relative_negative = meta.query_advice(gate.relative_negative_wrap, Rotation::cur());
    vec![
        enabled.clone() * meta.query_advice(gate.state.before.run_state, Rotation::cur()),
        enabled.clone()
            * (event_address(meta, gate.bus, gate.shape, ROLE_OPCODE_ZERO) - before_pc.clone()),
        enabled.clone()
            * (event_value(meta, gate.bus, gate.shape, ROLE_OPCODE_ZERO)
                - (Expression::Constant(Fp::one()) - encoding_kind.clone()) * opcode_byte.clone()
                - encoding_kind.clone() * Expression::Constant(Fp::from(0xcb))),
        enabled.clone()
            * (event_address(meta, gate.bus, gate.shape, ROLE_OPCODE_ONE)
                - encoding_kind.clone() * (before_pc.clone() + Expression::Constant(Fp::one()))),
        enabled.clone()
            * (event_value(meta, gate.bus, gate.shape, ROLE_OPCODE_ONE)
                - encoding_kind * opcode_byte),
        enabled.clone()
            * (event_address(meta, gate.bus, gate.shape, ROLE_IMMEDIATE_ZERO)
                - event_role(meta, gate.shape, ROLE_IMMEDIATE_ZERO)
                    * (before_pc.clone() + opcode_fetches.clone())),
        enabled.clone()
            * (event_address(meta, gate.bus, gate.shape, ROLE_IMMEDIATE_ONE)
                - event_role(meta, gate.shape, ROLE_IMMEDIATE_ONE)
                    * (before_pc + opcode_fetches + Expression::Constant(Fp::one()))),
        enabled.clone()
            * relative_positive.clone()
            * (Expression::Constant(Fp::one()) - relative_positive.clone()),
        enabled.clone()
            * relative_negative.clone()
            * (Expression::Constant(Fp::one()) - relative_negative.clone()),
        enabled.clone() * relative_positive * relative_negative,
        enabled.clone() * operation(meta, gate.shape, 31),
        enabled * operation(meta, gate.shape, 2) * immediate_zero,
    ]
}

fn relative_constraints(
    meta: &mut halo2_proofs::plonk::VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    gate: ControlGate<'_>,
) -> Vec<Expression<Fp>> {
    let mut reconstructed_immediate = Expression::Constant(Fp::zero());
    let mut bit_power = Fp::one();
    let mut constraints = Vec::new();
    for column in gate.relative_bits {
        let bit = meta.query_advice(column, Rotation::cur());
        constraints.push(
            enabled.clone()
                * operation(meta, gate.shape, 3)
                * bit.clone()
                * (Expression::Constant(Fp::one()) - bit.clone()),
        );
        reconstructed_immediate = reconstructed_immediate + Expression::Constant(bit_power) * bit;
        bit_power = bit_power.double();
    }
    constraints.push(
        enabled
            * operation(meta, gate.shape, 3)
            * (event_value(meta, gate.bus, gate.shape, ROLE_IMMEDIATE_ZERO)
                - reconstructed_immediate),
    );
    constraints
}

fn program_counter_constraints(
    meta: &mut halo2_proofs::plonk::VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    gate: ControlGate<'_>,
) -> Vec<Expression<Fp>> {
    let before_pc = word(
        meta.query_advice(gate.state.before.pc_low, Rotation::cur()),
        meta.query_advice(gate.state.before.pc_high, Rotation::cur()),
    );
    let after_pc = word(
        meta.query_advice(gate.state.after.pc_low, Rotation::cur()),
        meta.query_advice(gate.state.after.pc_high, Rotation::cur()),
    );
    let sequential_pc = before_pc + meta.query_advice(gate.opcode.byte_len, Rotation::cur());
    let immediate_zero = event_value(meta, gate.bus, gate.shape, ROLE_IMMEDIATE_ZERO);
    let immediate_word = word(
        immediate_zero.clone(),
        event_value(meta, gate.bus, gate.shape, ROLE_IMMEDIATE_ONE),
    );
    let return_word = word(
        event_value(meta, gate.bus, gate.shape, ROLE_DATA_ZERO),
        event_value(meta, gate.bus, gate.shape, ROLE_DATA_ONE),
    );
    let [_, _, _, _, _, _, _, relative_sign] = gate.relative_bits;
    let relative_target = sequential_pc.clone() + immediate_zero
        - Expression::Constant(Fp::from(256)) * meta.query_advice(relative_sign, Rotation::cur())
        - Expression::Constant(Fp::from(65_536))
            * meta.query_advice(gate.relative_positive_wrap, Rotation::cur())
        + Expression::Constant(Fp::from(65_536))
            * meta.query_advice(gate.relative_negative_wrap, Rotation::cur());
    let branch = meta.query_fixed(gate.shape.branch_taken);
    let exceptional = [3_usize, 20, 25, 26, 28, 34, 36]
        .into_iter()
        .fold(Expression::Constant(Fp::zero()), |sum, code| {
            sum + operation(meta, gate.shape, code)
        });
    vec![
        enabled.clone()
            * (Expression::Constant(Fp::one()) - exceptional)
            * (after_pc.clone() - sequential_pc.clone()),
        enabled.clone()
            * operation(meta, gate.shape, 3)
            * (after_pc.clone()
                - ((Expression::Constant(Fp::one()) - branch.clone()) * sequential_pc.clone()
                    + branch.clone() * relative_target)),
        enabled.clone()
            * operation(meta, gate.shape, 20)
            * (after_pc.clone()
                - ((Expression::Constant(Fp::one()) - branch.clone()) * sequential_pc.clone()
                    + branch.clone() * return_word.clone())),
        enabled.clone() * operation(meta, gate.shape, 25) * (after_pc.clone() - return_word),
        enabled.clone()
            * operation(meta, gate.shape, 26)
            * (after_pc.clone()
                - word(
                    meta.query_advice(gate.state.before.l, Rotation::cur()),
                    meta.query_advice(gate.state.before.h, Rotation::cur()),
                )),
        enabled.clone()
            * operation(meta, gate.shape, 28)
            * (after_pc.clone()
                - ((Expression::Constant(Fp::one()) - branch.clone()) * sequential_pc.clone()
                    + branch.clone() * immediate_word.clone())),
        enabled.clone()
            * operation(meta, gate.shape, 34)
            * (after_pc.clone()
                - ((Expression::Constant(Fp::one()) - branch) * sequential_pc
                    + meta.query_fixed(gate.shape.branch_taken) * immediate_word)),
        enabled
            * operation(meta, gate.shape, 36)
            * (after_pc
                - Expression::Constant(Fp::from(8)) * weighted_argument_zero(meta, gate.shape)),
    ]
}

fn condition_constraints(
    meta: &mut halo2_proofs::plonk::VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    shape: &ShapeConfig,
    flags: &FlagConfig,
) -> Vec<Expression<Fp>> {
    let branch = meta.query_fixed(shape.branch_taken);
    let zero = meta.query_advice(flags.before.zero, Rotation::cur());
    let carry = meta.query_advice(flags.before.carry, Rotation::cur());
    let conditional_op = [3_usize, 20, 28, 34]
        .into_iter()
        .fold(Expression::Constant(Fp::zero()), |sum, code| {
            sum + operation(meta, shape, code)
        });
    let predicate = argument_zero(meta, shape, 0)
        + argument_zero(meta, shape, 1) * (Expression::Constant(Fp::one()) - zero.clone())
        + argument_zero(meta, shape, 2) * zero
        + argument_zero(meta, shape, 3) * (Expression::Constant(Fp::one()) - carry.clone())
        + argument_zero(meta, shape, 4) * carry;
    vec![enabled * conditional_op * (branch - predicate)]
}

fn ime_constraints(
    meta: &mut halo2_proofs::plonk::VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    shape: &ShapeConfig,
    state: &StateTraceConfig,
) -> Vec<Expression<Fp>> {
    let before = meta.query_advice(state.before.ime, Rotation::cur());
    let after = meta.query_advice(state.after.ime, Rotation::cur());
    let pending = before.clone() * (Expression::Constant(Fp::from(2)) - before.clone());
    let promoted = before + pending.clone();
    let disable = operation(meta, shape, 32);
    let enable = operation(meta, shape, 33);
    let reti = operation(meta, shape, 25);
    let ordinary = Expression::Constant(Fp::one()) - disable - enable.clone() - reti.clone();
    let expected = ordinary * promoted
        + enable * (Expression::Constant(Fp::one()) + pending)
        + reti * Expression::Constant(Fp::from(2));
    vec![enabled * (after - expected)]
}

fn run_state_constraints(
    meta: &mut halo2_proofs::plonk::VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    shape: &ShapeConfig,
    state: &StateTraceConfig,
) -> Vec<Expression<Fp>> {
    let after = meta.query_advice(state.after.run_state, Rotation::cur());
    vec![
        enabled.clone()
            * operation(meta, shape, 18)
            * (after.clone() - Expression::Constant(Fp::one())),
        enabled * operation(meta, shape, 2) * (after - Expression::Constant(Fp::from(2))),
    ]
}

fn event_role(
    meta: &mut halo2_proofs::plonk::VirtualCells<'_, Fp>,
    shape: &ShapeConfig,
    role: usize,
) -> Expression<Fp> {
    shape
        .event_roles
        .iter()
        .filter_map(|roles| roles.get(role))
        .fold(Expression::Constant(Fp::zero()), |sum, column| {
            sum + meta.query_fixed(*column)
        })
}

fn weighted_argument_zero(
    meta: &mut halo2_proofs::plonk::VirtualCells<'_, Fp>,
    shape: &ShapeConfig,
) -> Expression<Fp> {
    shape.argument_zero.iter().zip(0_u64..).fold(
        Expression::Constant(Fp::zero()),
        |sum, (column, value)| {
            sum + Expression::Constant(Fp::from(value)) * meta.query_fixed(*column)
        },
    )
}

fn assign_bool(
    region: &mut Region<'_, Fp>,
    column: Column<Advice>,
    offset: usize,
    value: Option<bool>,
) -> Result<(), Error> {
    region.assign_advice(
        || "control boolean",
        column,
        offset,
        || {
            value.map_or(Value::unknown(), |bit| {
                Value::known(Fp::from(u64::from(bit)))
            })
        },
    )?;
    Ok(())
}
