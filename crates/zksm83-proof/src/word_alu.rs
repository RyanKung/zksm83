//! Sixteen-bit addition and signed stack-pointer offset semantics.

use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector, VirtualCells},
    poly::Rotation,
};
use pasta_curves::Fp;
use zksm83_core::BusEvent;
use zksm83_isa::{Operation, Register16};
use zksm83_trace::TraceRow;

use crate::{
    bus::BusConfig,
    expressions::{ROLE_IMMEDIATE_ZERO, argument_zero, event_value, operation},
    flags::FlagConfig,
    shape::ShapeConfig,
    state::{StateColumns, StateTraceConfig},
};

const BITS: usize = 8;

#[derive(Clone, Copy, Debug)]
pub(crate) struct WordAluConfig {
    left_low: [Column<Advice>; BITS],
    left_high: [Column<Advice>; BITS],
    right_low: [Column<Advice>; BITS],
    right_high: [Column<Advice>; BITS],
    result_low: [Column<Advice>; BITS],
    result_high: [Column<Advice>; BITS],
    positive_wrap: Column<Advice>,
    negative_wrap: Column<Advice>,
    q_row: Selector,
}

impl WordAluConfig {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<Fp>,
        shape: &ShapeConfig,
        state: &StateTraceConfig,
        flags: &FlagConfig,
        bus: &BusConfig,
    ) -> Self {
        let left_low = std::array::from_fn(|_| meta.advice_column());
        let left_high = std::array::from_fn(|_| meta.advice_column());
        let right_low = std::array::from_fn(|_| meta.advice_column());
        let right_high = std::array::from_fn(|_| meta.advice_column());
        let result_low = std::array::from_fn(|_| meta.advice_column());
        let result_high = std::array::from_fn(|_| meta.advice_column());
        let positive_wrap = meta.advice_column();
        let negative_wrap = meta.advice_column();
        let q_row = meta.selector();
        meta.create_gate("SM83 sixteen-bit ALU semantics", |meta| {
            let enabled = meta.query_selector(q_row);
            let values = WordExpressions::query(
                meta,
                left_low,
                left_high,
                right_low,
                right_high,
                result_low,
                result_high,
                positive_wrap,
                negative_wrap,
            );
            let mut constraints = values.decomposition(enabled.clone());
            constraints.extend(link_constraints(
                meta,
                enabled.clone(),
                shape,
                state,
                bus,
                &values,
            ));
            constraints.extend(add_hl_constraints(
                meta,
                enabled.clone(),
                shape,
                flags,
                &values,
            ));
            constraints.extend(signed_constraints(meta, enabled, shape, flags, &values));
            constraints
        });
        Self {
            left_low,
            left_high,
            right_low,
            right_high,
            result_low,
            result_high,
            positive_wrap,
            negative_wrap,
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
        let witness = row.map(word_witness);
        for (columns, value) in [
            (
                self.left_low,
                witness.map(|item| item.left.to_le_bytes()[0]),
            ),
            (
                self.left_high,
                witness.map(|item| item.left.to_le_bytes()[1]),
            ),
            (
                self.right_low,
                witness.map(|item| item.right.to_le_bytes()[0]),
            ),
            (
                self.right_high,
                witness.map(|item| item.right.to_le_bytes()[1]),
            ),
            (
                self.result_low,
                witness.map(|item| item.result.to_le_bytes()[0]),
            ),
            (
                self.result_high,
                witness.map(|item| item.result.to_le_bytes()[1]),
            ),
        ] {
            assign_bits(region, offset, columns, value)?;
        }
        assign_boolean(
            region,
            offset,
            self.positive_wrap,
            witness.map(|item| item.positive_wrap),
        )?;
        assign_boolean(
            region,
            offset,
            self.negative_wrap,
            witness.map(|item| item.negative_wrap),
        )
    }
}

struct WordExpressions {
    left_low_bits: [Expression<Fp>; BITS],
    left_high_bits: [Expression<Fp>; BITS],
    right_low_bits: [Expression<Fp>; BITS],
    right_high_bits: [Expression<Fp>; BITS],
    result_low_bits: [Expression<Fp>; BITS],
    result_high_bits: [Expression<Fp>; BITS],
    left_low: Expression<Fp>,
    right_low: Expression<Fp>,
    result_low: Expression<Fp>,
    left: Expression<Fp>,
    right: Expression<Fp>,
    result: Expression<Fp>,
    positive_wrap: Expression<Fp>,
    negative_wrap: Expression<Fp>,
}

impl WordExpressions {
    #[allow(clippy::too_many_arguments)]
    fn query(
        meta: &mut VirtualCells<'_, Fp>,
        left_low: [Column<Advice>; BITS],
        left_high: [Column<Advice>; BITS],
        right_low: [Column<Advice>; BITS],
        right_high: [Column<Advice>; BITS],
        result_low: [Column<Advice>; BITS],
        result_high: [Column<Advice>; BITS],
        positive_wrap: Column<Advice>,
        negative_wrap: Column<Advice>,
    ) -> Self {
        let left_low_bits = query_bits(meta, left_low);
        let left_high_bits = query_bits(meta, left_high);
        let right_low_bits = query_bits(meta, right_low);
        let right_high_bits = query_bits(meta, right_high);
        let result_low_bits = query_bits(meta, result_low);
        let result_high_bits = query_bits(meta, result_high);
        let left_low = compose(&left_low_bits);
        let right_low = compose(&right_low_bits);
        let result_low = compose(&result_low_bits);
        Self {
            left: left_low.clone() + c(256) * compose(&left_high_bits),
            right: right_low.clone() + c(256) * compose(&right_high_bits),
            result: result_low.clone() + c(256) * compose(&result_high_bits),
            left_low,
            right_low,
            result_low,
            left_low_bits,
            left_high_bits,
            right_low_bits,
            right_high_bits,
            result_low_bits,
            result_high_bits,
            positive_wrap: meta.query_advice(positive_wrap, Rotation::cur()),
            negative_wrap: meta.query_advice(negative_wrap, Rotation::cur()),
        }
    }

    fn decomposition(&self, enabled: Expression<Fp>) -> Vec<Expression<Fp>> {
        let mut constraints = Vec::new();
        for bit in self
            .left_low_bits
            .iter()
            .chain(&self.left_high_bits)
            .chain(&self.right_low_bits)
            .chain(&self.right_high_bits)
            .chain(&self.result_low_bits)
            .chain(&self.result_high_bits)
        {
            constraints.push(
                enabled.clone() * bit.clone() * (Expression::Constant(Fp::one()) - bit.clone()),
            );
        }
        for wrap in [&self.positive_wrap, &self.negative_wrap] {
            constraints.push(
                enabled.clone() * wrap.clone() * (Expression::Constant(Fp::one()) - wrap.clone()),
            );
        }
        constraints
    }
}

fn link_constraints(
    meta: &mut VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    shape: &ShapeConfig,
    state: &StateTraceConfig,
    bus: &BusConfig,
    values: &WordExpressions,
) -> Vec<Expression<Fp>> {
    let add_hl = operation(meta, shape, 5);
    let signed = operation(meta, shape, 22) + operation(meta, shape, 23);
    let before_hl = pair(meta, state.before.h, state.before.l);
    let after_hl = pair(meta, state.after.h, state.after.l);
    let before_sp = pair(meta, state.before.sp_high, state.before.sp_low);
    let after_sp = pair(meta, state.after.sp_high, state.after.sp_low);
    let signed_result =
        operation(meta, shape, 22) * after_sp + operation(meta, shape, 23) * after_hl.clone();
    vec![
        enabled.clone() * add_hl.clone() * (values.left.clone() - before_hl),
        enabled.clone()
            * add_hl.clone()
            * (values.right.clone() - selected_pair(meta, shape, state.before)),
        enabled.clone() * add_hl * (values.result.clone() - after_hl),
        enabled.clone() * signed.clone() * (values.left.clone() - before_sp),
        enabled.clone()
            * signed.clone()
            * (values.right.clone() - event_value(meta, bus, shape, ROLE_IMMEDIATE_ZERO)),
        enabled * signed * (values.result.clone() - signed_result),
    ]
}

fn add_hl_constraints(
    meta: &mut VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    shape: &ShapeConfig,
    flags: &FlagConfig,
    values: &WordExpressions,
) -> Vec<Expression<Fp>> {
    let selected = operation(meta, shape, 5);
    let carry = meta.query_advice(flags.after.carry, Rotation::cur());
    let half = meta.query_advice(flags.after.half_carry, Rotation::cur());
    let before_zero = meta.query_advice(flags.before.zero, Rotation::cur());
    let after_zero = meta.query_advice(flags.after.zero, Rotation::cur());
    let left_low12 = values.left_low.clone() + c(256) * low_nibble(&values.left_high_bits);
    let right_low12 = values.right_low.clone() + c(256) * low_nibble(&values.right_high_bits);
    let result_low12 = values.result_low.clone() + c(256) * low_nibble(&values.result_high_bits);
    vec![
        enabled.clone()
            * selected.clone()
            * (values.left.clone() + values.right.clone()
                - values.result.clone()
                - c(65_536) * carry),
        enabled.clone()
            * selected.clone()
            * (left_low12 + right_low12 - result_low12 - c(4096) * half),
        enabled.clone() * selected.clone() * (after_zero - before_zero),
        enabled * selected * meta.query_advice(flags.after.subtract, Rotation::cur()),
    ]
}

fn signed_constraints(
    meta: &mut VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    shape: &ShapeConfig,
    flags: &FlagConfig,
    values: &WordExpressions,
) -> Vec<Expression<Fp>> {
    let selected = operation(meta, shape, 22) + operation(meta, shape, 23);
    let sign = values
        .right_low_bits
        .get(7)
        .cloned()
        .map_or(Expression::Constant(Fp::zero()), |value| value);
    let carry = meta.query_advice(flags.after.carry, Rotation::cur());
    let half = meta.query_advice(flags.after.half_carry, Rotation::cur());
    let low_left = low_nibble(&values.left_low_bits);
    let low_right = low_nibble(&values.right_low_bits);
    let low_result = low_nibble(&values.result_low_bits);
    vec![
        enabled.clone()
            * selected.clone()
            * (Expression::Constant(Fp::one()) - sign.clone())
            * (values.left.clone() + values.right.clone()
                - values.result.clone()
                - c(65_536) * values.positive_wrap.clone()),
        enabled.clone()
            * selected.clone()
            * sign
            * (values.left.clone() + values.right.clone() - c(256) - values.result.clone()
                + c(65_536) * values.negative_wrap.clone()),
        enabled.clone()
            * selected.clone()
            * (values.left_low.clone() + values.right_low.clone()
                - values.result_low.clone()
                - c(256) * carry),
        enabled.clone() * selected.clone() * (low_left + low_right - low_result - c(16) * half),
        enabled.clone() * selected.clone() * meta.query_advice(flags.after.zero, Rotation::cur()),
        enabled.clone()
            * selected.clone()
            * meta.query_advice(flags.after.subtract, Rotation::cur()),
        enabled * selected * compose(&values.right_high_bits),
    ]
}

fn selected_pair(
    meta: &mut VirtualCells<'_, Fp>,
    shape: &ShapeConfig,
    columns: StateColumns,
) -> Expression<Fp> {
    argument_zero(meta, shape, 0) * pair(meta, columns.b, columns.c)
        + argument_zero(meta, shape, 1) * pair(meta, columns.d, columns.e)
        + argument_zero(meta, shape, 2) * pair(meta, columns.h, columns.l)
        + argument_zero(meta, shape, 3) * pair(meta, columns.sp_high, columns.sp_low)
}

fn pair(
    meta: &mut VirtualCells<'_, Fp>,
    high: Column<Advice>,
    low: Column<Advice>,
) -> Expression<Fp> {
    meta.query_advice(low, Rotation::cur()) + c(256) * meta.query_advice(high, Rotation::cur())
}

fn query_bits(
    meta: &mut VirtualCells<'_, Fp>,
    columns: [Column<Advice>; BITS],
) -> [Expression<Fp>; BITS] {
    columns.map(|column| meta.query_advice(column, Rotation::cur()))
}

fn compose(bits: &[Expression<Fp>; BITS]) -> Expression<Fp> {
    bits.iter()
        .enumerate()
        .fold(Expression::Constant(Fp::zero()), |sum, (bit, value)| {
            sum + c(1_u64 << bit) * value.clone()
        })
}

fn low_nibble(bits: &[Expression<Fp>; BITS]) -> Expression<Fp> {
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
struct WordWitness {
    left: u16,
    right: u16,
    result: u16,
    positive_wrap: bool,
    negative_wrap: bool,
}

fn word_witness(row: &TraceRow) -> WordWitness {
    let before = row.before().cpu();
    let after = row.after().cpu();
    match row.effects().instruction().operation() {
        Operation::AddHl(source) => {
            let left = register(before, Register16::Hl);
            let right = register(before, source);
            WordWitness {
                left,
                right,
                result: register(after, Register16::Hl),
                positive_wrap: left.overflowing_add(right).1,
                negative_wrap: false,
            }
        }
        Operation::AddSpOffset | Operation::LoadHlSpOffset => signed_witness(row),
        _ => WordWitness {
            left: 0,
            right: 0,
            result: 0,
            positive_wrap: false,
            negative_wrap: false,
        },
    }
}

fn signed_witness(row: &TraceRow) -> WordWitness {
    let left = row.before().cpu().sp();
    let encoded = immediate(row);
    let signed = i8::from_ne_bytes([encoded]);
    let result = match row.effects().instruction().operation() {
        Operation::AddSpOffset => row.after().cpu().sp(),
        Operation::LoadHlSpOffset => register(row.after().cpu(), Register16::Hl),
        _ => 0,
    };
    WordWitness {
        left,
        right: u16::from(encoded),
        result,
        positive_wrap: signed >= 0 && left.checked_add(u16::from(encoded)).is_none(),
        negative_wrap: signed < 0 && left < 256_u16.saturating_sub(u16::from(encoded)),
    }
}

fn register(cpu: zksm83_core::CpuState, register: Register16) -> u16 {
    let registers = cpu.registers();
    match register {
        Register16::Bc => u16::from_be_bytes([registers.b, registers.c]),
        Register16::De => u16::from_be_bytes([registers.d, registers.e]),
        Register16::Hl => u16::from_be_bytes([registers.h, registers.l]),
        Register16::Sp => cpu.sp(),
    }
}

fn immediate(row: &TraceRow) -> u8 {
    row.effects()
        .bus_events()
        .find_map(|event| match event {
            BusEvent::ImmediateRead(read) => Some(read.value),
            BusEvent::MemoryImmediateRead(read) => Some(read.value),
            _ => None,
        })
        .map_or(0, |value| value)
}

fn assign_bits(
    region: &mut Region<'_, Fp>,
    offset: usize,
    columns: [Column<Advice>; BITS],
    value: Option<u8>,
) -> Result<(), Error> {
    for (bit, column) in columns.iter().enumerate() {
        region.assign_advice(
            || "word ALU bit",
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

fn assign_boolean(
    region: &mut Region<'_, Fp>,
    offset: usize,
    column: Column<Advice>,
    value: Option<bool>,
) -> Result<(), Error> {
    region.assign_advice(
        || "word ALU wrap",
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
