//! Eight-bit arithmetic, logical, rotate, bit, and flag semantics.

use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn, VirtualCells,
    },
    poly::Rotation,
};
use pasta_curves::{Fp, group::ff::Field};
use zksm83_core::{BusEvent, Flags, VmState};
use zksm83_isa::{AluOperation, CbOperation, Operand8, Operation, Register8};
use zksm83_trace::TraceRow;

use crate::{
    bus::BusConfig,
    expressions::{
        ROLE_DATA_ONE, ROLE_DATA_ZERO, ROLE_IMMEDIATE_ZERO, argument_one, argument_zero,
        event_address, event_value, operation,
    },
    flags::FlagConfig,
    shape::ShapeConfig,
    state::{StateColumns, StateTraceConfig},
};

const BYTE_BITS: usize = 8;

#[derive(Clone, Copy, Debug)]
struct DaaTable {
    before_a: TableColumn,
    before_f: TableColumn,
    after_a: TableColumn,
    after_f: TableColumn,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AluConfig {
    left: [Column<Advice>; BYTE_BITS],
    right: [Column<Advice>; BYTE_BITS],
    result: [Column<Advice>; BYTE_BITS],
    inverse: Column<Advice>,
    wrap: Column<Advice>,
    q_row: Selector,
    daa: DaaTable,
}

impl AluConfig {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<Fp>,
        shape: &ShapeConfig,
        state: &StateTraceConfig,
        flags: &FlagConfig,
        bus: &BusConfig,
    ) -> Self {
        let left = std::array::from_fn(|_| meta.advice_column());
        let right = std::array::from_fn(|_| meta.advice_column());
        let result = std::array::from_fn(|_| meta.advice_column());
        let inverse = meta.advice_column();
        let wrap = meta.advice_column();
        let q_row = meta.selector();
        let daa = DaaTable::configure(meta, shape, state);
        meta.create_gate("SM83 byte ALU semantics", |meta| {
            let enabled = meta.query_selector(q_row);
            let values = AluExpressions::query(meta, left, right, result, inverse, wrap);
            let mut constraints = values.decomposition(enabled.clone());
            constraints.extend(link_constraints(
                meta,
                enabled.clone(),
                shape,
                state,
                bus,
                &values,
            ));
            constraints.extend(arithmetic_constraints(
                meta,
                enabled.clone(),
                shape,
                flags,
                &values,
            ));
            constraints.extend(logical_constraints(
                meta,
                enabled.clone(),
                shape,
                flags,
                &values,
            ));
            constraints.extend(rotate_constraints(
                meta,
                enabled.clone(),
                shape,
                flags,
                &values,
            ));
            constraints.extend(bit_constraints(
                meta,
                enabled.clone(),
                shape,
                flags,
                &values,
            ));
            constraints.extend(misc_flag_constraints(meta, enabled, shape, flags, &values));
            constraints
        });
        Self {
            left,
            right,
            result,
            inverse,
            wrap,
            q_row,
            daa,
        }
    }

    pub(crate) fn load(&self, layouter: impl Layouter<Fp>) -> Result<(), Error> {
        self.daa.load(layouter)
    }

    pub(crate) fn assign_row(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        row: Option<&TraceRow>,
    ) -> Result<(), Error> {
        self.q_row.enable(region, offset)?;
        let values = row.map(alu_witness);
        assign_bits(region, offset, self.left, values.map(|value| value.left))?;
        assign_bits(region, offset, self.right, values.map(|value| value.right))?;
        assign_bits(
            region,
            offset,
            self.result,
            values.map(|value| value.result),
        )?;
        assign_auxiliary(region, offset, self.inverse, self.wrap, values)
    }
}

impl DaaTable {
    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        shape: &ShapeConfig,
        state: &StateTraceConfig,
    ) -> Self {
        let table = Self {
            before_a: meta.lookup_table_column(),
            before_f: meta.lookup_table_column(),
            after_a: meta.lookup_table_column(),
            after_f: meta.lookup_table_column(),
        };
        meta.lookup(|meta| {
            let selected = operation(meta, shape, 13);
            vec![
                (
                    selected.clone() * meta.query_advice(state.before.a, Rotation::cur()),
                    table.before_a,
                ),
                (
                    selected.clone() * meta.query_advice(state.before.flags, Rotation::cur()),
                    table.before_f,
                ),
                (
                    selected.clone() * meta.query_advice(state.after.a, Rotation::cur()),
                    table.after_a,
                ),
                (
                    selected * meta.query_advice(state.after.flags, Rotation::cur()),
                    table.after_f,
                ),
            ]
        });
        table
    }

    fn load(&self, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        layouter.assign_table(
            || "SM83 DAA truth table",
            |mut table| {
                for column in [self.before_a, self.before_f, self.after_a, self.after_f] {
                    table.assign_cell(
                        || "disabled DAA tuple",
                        column,
                        0,
                        || Value::known(Fp::zero()),
                    )?;
                }
                for (offset, encoded) in (0_u16..4096).enumerate() {
                    let a = u8::try_from(encoded >> 4).map_err(|_| Error::Synthesis)?;
                    let f = u8::try_from(encoded & 0x0f).map_err(|_| Error::Synthesis)? << 4;
                    let (after_a, after_f) = decimal_adjust(a, f);
                    for (column, value) in [
                        (self.before_a, a),
                        (self.before_f, f),
                        (self.after_a, after_a),
                        (self.after_f, after_f),
                    ] {
                        table.assign_cell(
                            || "DAA tuple",
                            column,
                            offset + 1,
                            || Value::known(Fp::from(u64::from(value))),
                        )?;
                    }
                }
                Ok(())
            },
        )
    }
}

struct AluExpressions {
    left_bits: [Expression<Fp>; BYTE_BITS],
    right_bits: [Expression<Fp>; BYTE_BITS],
    result_bits: [Expression<Fp>; BYTE_BITS],
    left: Expression<Fp>,
    right: Expression<Fp>,
    result: Expression<Fp>,
    inverse: Expression<Fp>,
    wrap: Expression<Fp>,
}

impl AluExpressions {
    fn query(
        meta: &mut VirtualCells<'_, Fp>,
        left: [Column<Advice>; BYTE_BITS],
        right: [Column<Advice>; BYTE_BITS],
        result: [Column<Advice>; BYTE_BITS],
        inverse: Column<Advice>,
        wrap: Column<Advice>,
    ) -> Self {
        let left_bits = left.map(|column| meta.query_advice(column, Rotation::cur()));
        let right_bits = right.map(|column| meta.query_advice(column, Rotation::cur()));
        let result_bits = result.map(|column| meta.query_advice(column, Rotation::cur()));
        Self {
            left: compose_byte(&left_bits),
            right: compose_byte(&right_bits),
            result: compose_byte(&result_bits),
            left_bits,
            right_bits,
            result_bits,
            inverse: meta.query_advice(inverse, Rotation::cur()),
            wrap: meta.query_advice(wrap, Rotation::cur()),
        }
    }

    fn decomposition(&self, enabled: Expression<Fp>) -> Vec<Expression<Fp>> {
        let mut constraints = Vec::new();
        for bit in self
            .left_bits
            .iter()
            .chain(&self.right_bits)
            .chain(&self.result_bits)
        {
            constraints.push(
                enabled.clone() * bit.clone() * (Expression::Constant(Fp::one()) - bit.clone()),
            );
        }
        constraints.push(
            enabled * self.wrap.clone() * (Expression::Constant(Fp::one()) - self.wrap.clone()),
        );
        constraints
    }
}

fn link_constraints(
    meta: &mut VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    shape: &ShapeConfig,
    state: &StateTraceConfig,
    bus: &BusConfig,
    values: &AluExpressions,
) -> Vec<Expression<Fp>> {
    let inc_dec = operation(meta, shape, 9) + operation(meta, shape, 10);
    let alu = operation(meta, shape, 19);
    let accumulator_rotate = operation(meta, shape, 12);
    let cb_write =
        operation(meta, shape, 37) + operation(meta, shape, 39) + operation(meta, shape, 40);
    let cb_any = cb_write.clone() + operation(meta, shape, 38);
    let misc_a = operation(meta, shape, 13) + operation(meta, shape, 14);
    let mut constraints = vec![
        enabled.clone()
            * inc_dec.clone()
            * (values.left.clone() - operand(meta, shape, state.before, bus, true, false)),
        enabled.clone()
            * inc_dec
            * (values.result.clone() - operand(meta, shape, state.after, bus, true, true)),
        enabled.clone()
            * alu.clone()
            * (values.left.clone() - meta.query_advice(state.before.a, Rotation::cur())),
        enabled.clone()
            * alu.clone()
            * (values.right.clone() - operand(meta, shape, state.before, bus, false, false)),
        enabled.clone()
            * alu.clone()
            * (Expression::Constant(Fp::one()) - argument_zero(meta, shape, 7))
            * (values.result.clone() - meta.query_advice(state.after.a, Rotation::cur())),
        enabled.clone()
            * accumulator_rotate.clone()
            * (values.left.clone() - meta.query_advice(state.before.a, Rotation::cur())),
        enabled.clone()
            * accumulator_rotate
            * (values.result.clone() - meta.query_advice(state.after.a, Rotation::cur())),
        enabled.clone()
            * cb_any.clone()
            * (values.left.clone() - operand(meta, shape, state.before, bus, false, false)),
        enabled.clone()
            * cb_write
            * (values.result.clone() - operand(meta, shape, state.after, bus, false, true)),
        enabled.clone()
            * misc_a.clone()
            * (values.left.clone() - meta.query_advice(state.before.a, Rotation::cur())),
        enabled.clone()
            * misc_a
            * (values.result.clone() - meta.query_advice(state.after.a, Rotation::cur())),
    ];
    constraints.extend(indirect_address_constraints(
        meta, enabled, shape, state, bus,
    ));
    constraints
}

fn indirect_address_constraints(
    meta: &mut VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    shape: &ShapeConfig,
    state: &StateTraceConfig,
    bus: &BusConfig,
) -> Vec<Expression<Fp>> {
    let hl = meta.query_advice(state.before.l, Rotation::cur())
        + Expression::Constant(Fp::from(256)) * meta.query_advice(state.before.h, Rotation::cur());
    let first = event_address(meta, bus, shape, ROLE_DATA_ZERO);
    let second = event_address(meta, bus, shape, ROLE_DATA_ONE);
    let inc_dec =
        (operation(meta, shape, 9) + operation(meta, shape, 10)) * argument_zero(meta, shape, 6);
    let alu = operation(meta, shape, 19) * argument_one(meta, shape, 6);
    let cb = (operation(meta, shape, 37)
        + operation(meta, shape, 38)
        + operation(meta, shape, 39)
        + operation(meta, shape, 40))
        * argument_one(meta, shape, 6);
    let writes = inc_dec
        + operation(meta, shape, 37) * argument_one(meta, shape, 6)
        + operation(meta, shape, 39) * argument_one(meta, shape, 6)
        + operation(meta, shape, 40) * argument_one(meta, shape, 6);
    vec![
        enabled.clone() * (alu + cb + writes.clone()) * (first - hl.clone()),
        enabled * writes * (second - hl),
    ]
}

fn arithmetic_constraints(
    meta: &mut VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    shape: &ShapeConfig,
    flags: &FlagConfig,
    values: &AluExpressions,
) -> Vec<Expression<Fp>> {
    let one = Expression::Constant(Fp::one());
    let inc = operation(meta, shape, 9);
    let dec = operation(meta, shape, 10);
    let alu = operation(meta, shape, 19);
    let add = alu.clone() * (argument_zero(meta, shape, 0) + argument_zero(meta, shape, 1));
    let sub = alu.clone()
        * (argument_zero(meta, shape, 2)
            + argument_zero(meta, shape, 3)
            + argument_zero(meta, shape, 7));
    let carry_in = (argument_zero(meta, shape, 1) + argument_zero(meta, shape, 3))
        * meta.query_advice(flags.before.carry, Rotation::cur());
    let after_carry = meta.query_advice(flags.after.carry, Rotation::cur());
    let after_half = meta.query_advice(flags.after.half_carry, Rotation::cur());
    let before_carry = meta.query_advice(flags.before.carry, Rotation::cur());
    let low_left = low_nibble(&values.left_bits);
    let low_right = low_nibble(&values.right_bits);
    let low_result = low_nibble(&values.result_bits);
    let mut constraints = vec![
        enabled.clone()
            * inc.clone()
            * (values.left.clone() + one.clone()
                - values.result.clone()
                - c(256) * values.wrap.clone()),
        enabled.clone()
            * inc.clone()
            * (low_left.clone() + one.clone() - low_result.clone() - c(16) * after_half.clone()),
        enabled.clone() * inc.clone() * meta.query_advice(flags.after.subtract, Rotation::cur()),
        enabled.clone() * inc.clone() * (after_carry.clone() - before_carry.clone()),
        enabled.clone()
            * dec.clone()
            * (values.left.clone() - one.clone() - values.result.clone()
                + c(256) * values.wrap.clone()),
        enabled.clone()
            * dec.clone()
            * (low_left.clone() - one.clone() - low_result.clone() + c(16) * after_half.clone()),
        enabled.clone()
            * dec.clone()
            * (meta.query_advice(flags.after.subtract, Rotation::cur()) - one.clone()),
        enabled.clone() * dec.clone() * (after_carry.clone() - before_carry),
        enabled.clone()
            * add.clone()
            * (values.left.clone() + values.right.clone() + carry_in.clone()
                - values.result.clone()
                - c(256) * after_carry.clone()),
        enabled.clone()
            * add.clone()
            * (low_left.clone() + low_right.clone() + carry_in.clone()
                - low_result.clone()
                - c(16) * after_half.clone()),
        enabled.clone() * add * meta.query_advice(flags.after.subtract, Rotation::cur()),
        enabled.clone()
            * sub.clone()
            * (values.left.clone()
                - values.right.clone()
                - carry_in.clone()
                - values.result.clone()
                + c(256) * after_carry.clone()),
        enabled.clone()
            * sub.clone()
            * (low_left - low_right - carry_in - low_result + c(16) * after_half),
        enabled.clone() * sub * (meta.query_advice(flags.after.subtract, Rotation::cur()) - one),
    ];
    constraints.extend(zero_flag_constraints(
        meta,
        enabled,
        inc + dec + alu,
        flags,
        values,
    ));
    constraints
}

fn logical_constraints(
    meta: &mut VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    shape: &ShapeConfig,
    flags: &FlagConfig,
    values: &AluExpressions,
) -> Vec<Expression<Fp>> {
    let alu = operation(meta, shape, 19);
    let and = alu.clone() * argument_zero(meta, shape, 4);
    let xor = alu.clone() * argument_zero(meta, shape, 5);
    let or = alu * argument_zero(meta, shape, 6);
    let mut constraints = Vec::new();
    for ((left, right), result) in values
        .left_bits
        .iter()
        .zip(&values.right_bits)
        .zip(&values.result_bits)
    {
        constraints
            .push(enabled.clone() * and.clone() * (result.clone() - left.clone() * right.clone()));
        constraints.push(
            enabled.clone()
                * xor.clone()
                * (result.clone() - left.clone() - right.clone()
                    + c(2) * left.clone() * right.clone()),
        );
        constraints.push(
            enabled.clone()
                * or.clone()
                * (result.clone() - left.clone() - right.clone() + left.clone() * right.clone()),
        );
    }
    let selected = and.clone() + xor + or;
    constraints.extend([
        enabled.clone()
            * selected.clone()
            * meta.query_advice(flags.after.subtract, Rotation::cur()),
        enabled.clone() * selected.clone() * meta.query_advice(flags.after.carry, Rotation::cur()),
        enabled.clone()
            * and
            * (meta.query_advice(flags.after.half_carry, Rotation::cur())
                - Expression::Constant(Fp::one())),
        enabled.clone()
            * (selected.clone() - operation(meta, shape, 19) * argument_zero(meta, shape, 4))
            * meta.query_advice(flags.after.half_carry, Rotation::cur()),
    ]);
    constraints.extend(zero_flag_constraints(
        meta, enabled, selected, flags, values,
    ));
    constraints
}

fn rotate_constraints(
    meta: &mut VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    shape: &ShapeConfig,
    flags: &FlagConfig,
    values: &AluExpressions,
) -> Vec<Expression<Fp>> {
    let rotate_a = operation(meta, shape, 12);
    let rotate_cb = operation(meta, shape, 37);
    let selected = rotate_a.clone() + rotate_cb.clone();
    let before_c = meta.query_advice(flags.before.carry, Rotation::cur());
    let after_c = meta.query_advice(flags.after.carry, Rotation::cur());
    let msb = values
        .left_bits
        .get(7)
        .cloned()
        .map_or(Expression::Constant(Fp::zero()), |value| value);
    let mut constraints = vec![
        enabled.clone()
            * selected.clone()
            * argument_zero(meta, shape, 0)
            * (c(2) * values.left.clone() + after_c.clone()
                - values.result.clone()
                - c(256) * after_c.clone()),
        enabled.clone()
            * selected.clone()
            * argument_zero(meta, shape, 1)
            * (values.left.clone() + c(255) * after_c.clone() - c(2) * values.result.clone()),
        enabled.clone()
            * selected.clone()
            * argument_zero(meta, shape, 2)
            * (c(2) * values.left.clone() + before_c.clone()
                - values.result.clone()
                - c(256) * after_c.clone()),
        enabled.clone()
            * selected.clone()
            * argument_zero(meta, shape, 3)
            * (values.left.clone() + c(256) * before_c
                - after_c.clone()
                - c(2) * values.result.clone()),
        enabled.clone()
            * rotate_cb.clone()
            * argument_zero(meta, shape, 4)
            * (c(2) * values.left.clone() - values.result.clone() - c(256) * after_c.clone()),
        enabled.clone()
            * rotate_cb.clone()
            * argument_zero(meta, shape, 5)
            * (values.left.clone() - after_c.clone() + c(256) * msb - c(2) * values.result.clone()),
        enabled.clone()
            * rotate_cb.clone()
            * argument_zero(meta, shape, 7)
            * (values.left.clone() - after_c.clone() - c(2) * values.result.clone()),
        enabled.clone()
            * selected.clone()
            * meta.query_advice(flags.after.subtract, Rotation::cur()),
        enabled.clone()
            * selected.clone()
            * meta.query_advice(flags.after.half_carry, Rotation::cur()),
        enabled.clone() * rotate_cb.clone() * argument_zero(meta, shape, 6) * after_c,
        enabled.clone() * rotate_a * meta.query_advice(flags.after.zero, Rotation::cur()),
    ];
    for bit in 0..BYTE_BITS {
        let result = values
            .result_bits
            .get(bit)
            .cloned()
            .map_or(Expression::Constant(Fp::zero()), |value| value);
        let source = values
            .left_bits
            .get((bit + 4) % BYTE_BITS)
            .cloned()
            .map_or(Expression::Constant(Fp::zero()), |value| value);
        constraints.push(
            enabled.clone() * rotate_cb.clone() * argument_zero(meta, shape, 6) * (result - source),
        );
    }
    constraints.extend(zero_flag_constraints(
        meta, enabled, rotate_cb, flags, values,
    ));
    constraints
}

fn bit_constraints(
    meta: &mut VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    shape: &ShapeConfig,
    flags: &FlagConfig,
    values: &AluExpressions,
) -> Vec<Expression<Fp>> {
    let test = operation(meta, shape, 38);
    let reset = operation(meta, shape, 39);
    let set = operation(meta, shape, 40);
    let mut selected_bit = Expression::Constant(Fp::zero());
    let mut constraints = Vec::new();
    for bit in 0..BYTE_BITS {
        let selector = argument_zero(meta, shape, bit);
        let input = values
            .left_bits
            .get(bit)
            .cloned()
            .map_or(Expression::Constant(Fp::zero()), |value| value);
        let output = values
            .result_bits
            .get(bit)
            .cloned()
            .map_or(Expression::Constant(Fp::zero()), |value| value);
        selected_bit = selected_bit + selector.clone() * input.clone();
        constraints.push(
            enabled.clone()
                * reset.clone()
                * (output.clone()
                    - input.clone() * (Expression::Constant(Fp::one()) - selector.clone())),
        );
        constraints.push(
            enabled.clone()
                * set.clone()
                * (output - input.clone() - selector * (Expression::Constant(Fp::one()) - input)),
        );
    }
    constraints.extend([
        enabled.clone()
            * test.clone()
            * (meta.query_advice(flags.after.zero, Rotation::cur()) + selected_bit
                - Expression::Constant(Fp::one())),
        enabled.clone() * test.clone() * meta.query_advice(flags.after.subtract, Rotation::cur()),
        enabled.clone()
            * test.clone()
            * (meta.query_advice(flags.after.half_carry, Rotation::cur())
                - Expression::Constant(Fp::one())),
        enabled
            * test
            * (meta.query_advice(flags.after.carry, Rotation::cur())
                - meta.query_advice(flags.before.carry, Rotation::cur())),
    ]);
    constraints
}

fn misc_flag_constraints(
    meta: &mut VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    shape: &ShapeConfig,
    flags: &FlagConfig,
    values: &AluExpressions,
) -> Vec<Expression<Fp>> {
    let complement = operation(meta, shape, 14);
    let set_carry = operation(meta, shape, 15);
    let complement_carry = operation(meta, shape, 16);
    let before_z = meta.query_advice(flags.before.zero, Rotation::cur());
    let before_c = meta.query_advice(flags.before.carry, Rotation::cur());
    let after_z = meta.query_advice(flags.after.zero, Rotation::cur());
    let after_n = meta.query_advice(flags.after.subtract, Rotation::cur());
    let after_h = meta.query_advice(flags.after.half_carry, Rotation::cur());
    let after_c = meta.query_advice(flags.after.carry, Rotation::cur());
    vec![
        enabled.clone()
            * complement.clone()
            * (values.result.clone() + values.left.clone() - c(255)),
        enabled.clone() * complement.clone() * (after_z.clone() - before_z.clone()),
        enabled.clone() * complement.clone() * (after_n.clone() - Expression::Constant(Fp::one())),
        enabled.clone() * complement.clone() * (after_h.clone() - Expression::Constant(Fp::one())),
        enabled.clone() * complement * (after_c.clone() - before_c.clone()),
        enabled.clone() * set_carry.clone() * (after_z.clone() - before_z.clone()),
        enabled.clone() * set_carry.clone() * after_n.clone(),
        enabled.clone() * set_carry.clone() * after_h.clone(),
        enabled.clone() * set_carry * (after_c.clone() - Expression::Constant(Fp::one())),
        enabled.clone() * complement_carry.clone() * (after_z - before_z),
        enabled.clone() * complement_carry.clone() * after_n,
        enabled.clone() * complement_carry.clone() * after_h,
        enabled * complement_carry * (after_c + before_c - Expression::Constant(Fp::one())),
    ]
}

fn zero_flag_constraints(
    meta: &mut VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    selected: Expression<Fp>,
    flags: &FlagConfig,
    values: &AluExpressions,
) -> Vec<Expression<Fp>> {
    let zero = meta.query_advice(flags.after.zero, Rotation::cur());
    vec![
        enabled.clone() * selected.clone() * zero.clone() * values.result.clone(),
        enabled
            * selected
            * (values.result.clone() * values.inverse.clone()
                - (Expression::Constant(Fp::one()) - zero)),
    ]
}

fn operand(
    meta: &mut VirtualCells<'_, Fp>,
    shape: &ShapeConfig,
    columns: StateColumns,
    bus: &BusConfig,
    argument_is_zero: bool,
    after_write: bool,
) -> Expression<Fp> {
    let selector = |meta: &mut VirtualCells<'_, Fp>, code| {
        if argument_is_zero {
            argument_zero(meta, shape, code)
        } else {
            argument_one(meta, shape, code)
        }
    };
    let event_role = if after_write {
        ROLE_DATA_ONE
    } else {
        ROLE_DATA_ZERO
    };
    register_columns(columns).into_iter().fold(
        Expression::Constant(Fp::zero()),
        |sum, (code, column)| {
            sum + selector(meta, code) * meta.query_advice(column, Rotation::cur())
        },
    ) + selector(meta, 6) * event_value(meta, bus, shape, event_role)
        + selector(meta, 8) * event_value(meta, bus, shape, ROLE_IMMEDIATE_ZERO)
}

fn register_columns(columns: StateColumns) -> [(usize, Column<Advice>); 7] {
    [
        (0, columns.b),
        (1, columns.c),
        (2, columns.d),
        (3, columns.e),
        (4, columns.h),
        (5, columns.l),
        (7, columns.a),
    ]
}

fn compose_byte(bits: &[Expression<Fp>; BYTE_BITS]) -> Expression<Fp> {
    bits.iter()
        .enumerate()
        .fold(Expression::Constant(Fp::zero()), |sum, (bit, value)| {
            sum + c(1_u64 << bit) * value.clone()
        })
}

fn low_nibble(bits: &[Expression<Fp>; BYTE_BITS]) -> Expression<Fp> {
    bits.iter()
        .take(4)
        .enumerate()
        .fold(Expression::Constant(Fp::zero()), |sum, (bit, value)| {
            sum + c(1_u64 << bit) * value.clone()
        })
}

fn c(value: u64) -> Expression<Fp> {
    Expression::Constant(Fp::from(value))
}

#[derive(Clone, Copy)]
struct AluWitness {
    left: u8,
    right: u8,
    result: u8,
    wrap: bool,
}

fn alu_witness(row: &TraceRow) -> AluWitness {
    let before = row.before();
    let after = row.after();
    match row.effects().instruction().operation() {
        Operation::Increment8(target) => unary_witness(row, target, true),
        Operation::Decrement8(target) => unary_witness(row, target, false),
        Operation::Alu8(operation, source) => alu_operation_witness(row, operation, source),
        Operation::RotateAccumulator(_)
        | Operation::DecimalAdjust
        | Operation::ComplementAccumulator => AluWitness {
            left: before.cpu().registers().a,
            right: 0,
            result: after.cpu().registers().a,
            wrap: false,
        },
        Operation::Cb(operation, target) => cb_witness(row, operation, target),
        _ => AluWitness {
            left: 0,
            right: 0,
            result: 0,
            wrap: false,
        },
    }
}

fn unary_witness(row: &TraceRow, target: Operand8, increment: bool) -> AluWitness {
    let left = operand_value(row, target, false);
    AluWitness {
        left,
        right: 0,
        result: operand_value(row, target, true),
        wrap: if increment {
            left == u8::MAX
        } else {
            left == 0
        },
    }
}

fn alu_operation_witness(row: &TraceRow, operation: AluOperation, source: Operand8) -> AluWitness {
    let left = row.before().cpu().registers().a;
    let right = operand_value(row, source, false);
    let carry = u8::from(row.before().cpu().flags().carry());
    let result = match operation {
        AluOperation::Add => left.wrapping_add(right),
        AluOperation::AddCarry => left.wrapping_add(right).wrapping_add(carry),
        AluOperation::Subtract | AluOperation::Compare => left.wrapping_sub(right),
        AluOperation::SubtractCarry => left.wrapping_sub(right).wrapping_sub(carry),
        AluOperation::And => left & right,
        AluOperation::Xor => left ^ right,
        AluOperation::Or => left | right,
    };
    AluWitness {
        left,
        right,
        result,
        wrap: false,
    }
}

fn cb_witness(row: &TraceRow, operation: CbOperation, target: Operand8) -> AluWitness {
    let left = operand_value(row, target, false);
    let result = if matches!(operation, CbOperation::TestBit(_)) {
        0
    } else {
        operand_value(row, target, true)
    };
    AluWitness {
        left,
        right: 0,
        result,
        wrap: false,
    }
}

fn operand_value(row: &TraceRow, operand: Operand8, after: bool) -> u8 {
    match operand {
        Operand8::Register(register) => {
            register_value(if after { row.after() } else { row.before() }, register)
        }
        Operand8::Immediate => bus_value(row, false, false),
        Operand8::IndirectHl => bus_value(row, true, after),
    }
}

fn register_value(state: VmState, register: Register8) -> u8 {
    let registers = state.cpu().registers();
    match register {
        Register8::A => registers.a,
        Register8::B => registers.b,
        Register8::C => registers.c,
        Register8::D => registers.d,
        Register8::E => registers.e,
        Register8::H => registers.h,
        Register8::L => registers.l,
    }
}

fn bus_value(row: &TraceRow, data: bool, after_write: bool) -> u8 {
    let target = usize::from(after_write);
    let mut seen_data = 0_usize;
    for event in row.effects().bus_events() {
        match event {
            BusEvent::ImmediateRead(read) if !data => {
                return read.value;
            }
            BusEvent::MemoryImmediateRead(read) if !data => {
                return read.value;
            }
            BusEvent::RomRead(read) if data && seen_data == target => return read.value,
            BusEvent::MemoryRead(read) if data && seen_data == target => return read.value,
            BusEvent::MemoryWrite(write) if data && seen_data == target => return write.after,
            BusEvent::InputRead { value, .. } if data && seen_data == target => return *value,
            BusEvent::OutputWrite { value, .. } if data && seen_data == target => return *value,
            BusEvent::RomRead(_)
            | BusEvent::MemoryOpcodeFetch(_)
            | BusEvent::MemoryImmediateRead(_)
            | BusEvent::MemoryRead(_)
            | BusEvent::MemoryWrite(_)
            | BusEvent::InputRead { .. }
            | BusEvent::OutputWrite { .. }
                if data =>
            {
                seen_data += 1
            }
            _ => {}
        }
    }
    0
}

fn assign_bits(
    region: &mut Region<'_, Fp>,
    offset: usize,
    columns: [Column<Advice>; BYTE_BITS],
    value: Option<u8>,
) -> Result<(), Error> {
    for (bit, column) in columns.iter().enumerate() {
        region.assign_advice(
            || "ALU bit",
            *column,
            offset,
            || {
                value.map_or(Value::unknown(), |byte| {
                    Value::known(Fp::from(u64::from((byte >> bit) & 1)))
                })
            },
        )?;
    }
    Ok(())
}

fn assign_auxiliary(
    region: &mut Region<'_, Fp>,
    offset: usize,
    inverse: Column<Advice>,
    wrap: Column<Advice>,
    values: Option<AluWitness>,
) -> Result<(), Error> {
    region.assign_advice(
        || "ALU result inverse",
        inverse,
        offset,
        || {
            values.map_or(Value::unknown(), |value| {
                let field = Fp::from(u64::from(value.result));
                Value::known(Option::<Fp>::from(field.invert()).map_or(Fp::zero(), |value| value))
            })
        },
    )?;
    region.assign_advice(
        || "ALU byte wrap",
        wrap,
        offset,
        || {
            values.map_or(Value::unknown(), |value| {
                Value::known(Fp::from(u64::from(value.wrap)))
            })
        },
    )?;
    Ok(())
}

fn decimal_adjust(accumulator: u8, flags: u8) -> (u8, u8) {
    let subtract = flags & Flags::SUBTRACT_MASK != 0;
    let half = flags & Flags::HALF_CARRY_MASK != 0;
    let before_carry = flags & Flags::CARRY_MASK != 0;
    let mut correction = 0_u8;
    let carry = if subtract {
        if before_carry {
            correction |= 0x60;
        }
        if half {
            correction |= 0x06;
        }
        before_carry
    } else {
        let next_carry = before_carry || accumulator > 0x99;
        if next_carry {
            correction |= 0x60;
        }
        if half || accumulator & 0x0f > 9 {
            correction |= 0x06;
        }
        next_carry
    };
    let value = if subtract {
        accumulator.wrapping_sub(correction)
    } else {
        accumulator.wrapping_add(correction)
    };
    let after = (u8::from(value == 0) * Flags::ZERO_MASK)
        | (u8::from(subtract) * Flags::SUBTRACT_MASK)
        | (u8::from(carry) * Flags::CARRY_MASK);
    (value, after)
}
