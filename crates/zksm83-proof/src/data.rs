//! Data movement, register-pair updates, stack, and bus-address semantics.

use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector, VirtualCells},
    poly::Rotation,
};
use pasta_curves::Fp;
use zksm83_core::BusEvent;
use zksm83_isa::{IndirectAddress, Operation, Register16, StackRegister16};
use zksm83_trace::TraceRow;

use crate::{
    bus::BusConfig,
    expressions::{
        ROLE_DATA_ONE, ROLE_DATA_ZERO, ROLE_IMMEDIATE_ONE, ROLE_IMMEDIATE_ZERO, argument_one,
        argument_zero, event_address, event_value, operation, word,
    },
    opcode::OpcodeTableConfig,
    shape::ShapeConfig,
    state::{StateColumns, StateTraceConfig},
};

#[derive(Clone, Copy, Debug)]
pub(crate) struct DataConfig {
    word_wrap: Column<Advice>,
    return_low: Column<Advice>,
    return_high: Column<Advice>,
    pop_low_bits: [Column<Advice>; 4],
    q_row: Selector,
}

#[derive(Clone, Copy, Debug)]
struct StackColumns {
    pop_low_bits: [Column<Advice>; 4],
    return_low: Column<Advice>,
    return_high: Column<Advice>,
    byte_len: Column<Advice>,
}

impl DataConfig {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<Fp>,
        shape: &ShapeConfig,
        opcode: &OpcodeTableConfig,
        state: &StateTraceConfig,
        bus: &BusConfig,
    ) -> Self {
        let word_wrap = meta.advice_column();
        let return_low = meta.advice_column();
        let return_high = meta.advice_column();
        let pop_low_bits = std::array::from_fn(|_| meta.advice_column());
        for column in [return_low, return_high] {
            meta.lookup(|meta| {
                let value = meta.query_advice(column, Rotation::cur());
                vec![(value, state.byte_table)]
            });
        }
        let q_row = meta.selector();
        meta.create_gate("SM83 data movement and stack semantics", |meta| {
            let enabled = meta.query_selector(q_row);
            let wrap = meta.query_advice(word_wrap, Rotation::cur());
            let mut constraints = vec![
                enabled.clone() * wrap.clone() * (Expression::Constant(Fp::one()) - wrap.clone()),
            ];
            constraints.extend(load16_constraints(meta, enabled.clone(), shape, state, bus));
            constraints.extend(store_sp_constraints(
                meta,
                enabled.clone(),
                shape,
                state,
                bus,
            ));
            constraints.extend(word_update_constraints(
                meta,
                enabled.clone(),
                shape,
                state,
                wrap.clone(),
            ));
            constraints.extend(load8_constraints(meta, enabled.clone(), shape, state, bus));
            constraints.extend(accumulator_transfer_constraints(
                meta,
                enabled.clone(),
                shape,
                state,
                bus,
                wrap,
            ));
            constraints.extend(stack_constraints(
                meta,
                enabled,
                shape,
                state,
                bus,
                StackColumns {
                    pop_low_bits,
                    return_low,
                    return_high,
                    byte_len: opcode.byte_len,
                },
            ));
            constraints
        });
        Self {
            word_wrap,
            return_low,
            return_high,
            pop_low_bits,
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
        let (wrap, low_nibble, return_address) = row.map_or((None, None, None), |row| {
            let operation = row.effects().instruction().operation();
            let before = row.before().cpu();
            let wraps = match operation {
                Operation::Increment16(register) => register16(before, register) == u16::MAX,
                Operation::Decrement16(register) => register16(before, register) == 0,
                Operation::LoadAccumulatorIndirect(IndirectAddress::HlIncrement, _) => {
                    register16(before, Register16::Hl) == u16::MAX
                }
                Operation::LoadAccumulatorIndirect(IndirectAddress::HlDecrement, _) => {
                    register16(before, Register16::Hl) == 0
                }
                _ => false,
            };
            let low = if matches!(operation, Operation::Pop(StackRegister16::Af)) {
                row.effects()
                    .bus_events()
                    .find_map(|event| match event {
                        BusEvent::MemoryRead(read) => Some(read.value & 0x0f),
                        _ => None,
                    })
                    .map_or(0, |value| value)
            } else {
                0
            };
            let return_address = row
                .before()
                .cpu()
                .pc()
                .wrapping_add(u16::from(row.effects().instruction().byte_len()));
            (Some(wraps), Some(low), Some(return_address))
        });
        assign_boolean(region, self.word_wrap, offset, wrap)?;
        let (return_low, return_high) = return_address.map_or((None, None), |address| {
            let [low, high] = address.to_le_bytes();
            (Some(low), Some(high))
        });
        assign_byte(region, self.return_low, offset, return_low)?;
        assign_byte(region, self.return_high, offset, return_high)?;
        for (column, bit) in self.pop_low_bits.iter().zip(0_u32..4) {
            let value = low_nibble.map(|low| (low >> bit) & 1);
            region.assign_advice(
                || "popped AF low-nibble bit",
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

fn load16_constraints(
    meta: &mut VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    shape: &ShapeConfig,
    state: &StateTraceConfig,
    bus: &BusConfig,
) -> Vec<Expression<Fp>> {
    let immediate = word(
        event_value(meta, bus, shape, ROLE_IMMEDIATE_ZERO),
        event_value(meta, bus, shape, ROLE_IMMEDIATE_ONE),
    );
    let load = operation(meta, shape, 4);
    let mut constraints =
        pair_selection_constraints(meta, enabled.clone() * load, shape, state.after, immediate);
    constraints.push(
        enabled
            * operation(meta, shape, 27)
            * (pair(meta, state.after.sp_high, state.after.sp_low)
                - pair(meta, state.before.h, state.before.l)),
    );
    constraints
}

fn store_sp_constraints(
    meta: &mut VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    shape: &ShapeConfig,
    state: &StateTraceConfig,
    bus: &BusConfig,
) -> Vec<Expression<Fp>> {
    let selected = operation(meta, shape, 1);
    let absolute = word(
        event_value(meta, bus, shape, ROLE_IMMEDIATE_ZERO),
        event_value(meta, bus, shape, ROLE_IMMEDIATE_ONE),
    );
    let first_address = event_address(meta, bus, shape, ROLE_DATA_ZERO);
    let second_address = event_address(meta, bus, shape, ROLE_DATA_ONE);
    let first_value = event_value(meta, bus, shape, ROLE_DATA_ZERO);
    let second_value = event_value(meta, bus, shape, ROLE_DATA_ONE);
    vec![
        enabled.clone() * selected.clone() * (first_address - absolute.clone()),
        enabled.clone()
            * selected.clone()
            * (second_address - absolute - Expression::Constant(Fp::one())),
        enabled.clone()
            * selected.clone()
            * (first_value - meta.query_advice(state.before.sp_low, Rotation::cur())),
        enabled
            * selected
            * (second_value - meta.query_advice(state.before.sp_high, Rotation::cur())),
    ]
}

fn word_update_constraints(
    meta: &mut VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    shape: &ShapeConfig,
    state: &StateTraceConfig,
    wrap: Expression<Fp>,
) -> Vec<Expression<Fp>> {
    let increment = operation(meta, shape, 7);
    let decrement = operation(meta, shape, 8);
    let mut constraints = Vec::new();
    for (code, (before, after)) in register_pairs(meta, state).into_iter().enumerate() {
        let selected = argument_zero(meta, shape, code);
        constraints.push(
            enabled.clone()
                * increment.clone()
                * selected.clone()
                * (after.clone() - before.clone() - Expression::Constant(Fp::one())
                    + Expression::Constant(Fp::from(65_536)) * wrap.clone()),
        );
        constraints.push(
            enabled.clone()
                * decrement.clone()
                * selected
                * (after - before + Expression::Constant(Fp::one())
                    - Expression::Constant(Fp::from(65_536)) * wrap.clone()),
        );
    }
    constraints
}

fn load8_constraints(
    meta: &mut VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    shape: &ShapeConfig,
    state: &StateTraceConfig,
    bus: &BusConfig,
) -> Vec<Expression<Fp>> {
    let immediate = event_value(meta, bus, shape, ROLE_IMMEDIATE_ZERO);
    let data_value = event_value(meta, bus, shape, ROLE_DATA_ZERO);
    let data_address = event_address(meta, bus, shape, ROLE_DATA_ZERO);
    let before_hl = pair(meta, state.before.h, state.before.l);
    let load_immediate = operation(meta, shape, 11);
    let load = operation(meta, shape, 17);
    let source = operand_value(meta, shape, state.before, bus, false);
    let mut constraints = Vec::new();
    for (code, column) in register_operands(state.after) {
        let destination_immediate = argument_zero(meta, shape, code);
        let destination_load = argument_zero(meta, shape, code);
        constraints.push(
            enabled.clone()
                * load_immediate.clone()
                * destination_immediate
                * (meta.query_advice(column, Rotation::cur()) - immediate.clone()),
        );
        constraints.push(
            enabled.clone()
                * load.clone()
                * destination_load
                * (meta.query_advice(column, Rotation::cur()) - source.clone()),
        );
    }
    let indirect_destination = argument_zero(meta, shape, 6);
    let indirect_source = argument_one(meta, shape, 6);
    constraints.extend([
        enabled.clone()
            * load_immediate
            * indirect_destination.clone()
            * (data_value.clone() - immediate),
        enabled.clone() * load.clone() * indirect_destination.clone() * (data_value - source),
        enabled.clone()
            * (operation(meta, shape, 11) * indirect_destination.clone()
                + load.clone() * (indirect_destination + indirect_source))
            * (data_address - before_hl),
    ]);
    constraints
}

fn accumulator_transfer_constraints(
    meta: &mut VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    shape: &ShapeConfig,
    state: &StateTraceConfig,
    bus: &BusConfig,
    wrap: Expression<Fp>,
) -> Vec<Expression<Fp>> {
    let data_address = event_address(meta, bus, shape, ROLE_DATA_ZERO);
    let data_value = event_value(meta, bus, shape, ROLE_DATA_ZERO);
    let before_a = meta.query_advice(state.before.a, Rotation::cur());
    let after_a = meta.query_advice(state.after.a, Rotation::cur());
    let before_c = meta.query_advice(state.before.c, Rotation::cur());
    let before_hl = pair(meta, state.before.h, state.before.l);
    let after_hl = pair(meta, state.after.h, state.after.l);
    let immediate = event_value(meta, bus, shape, ROLE_IMMEDIATE_ZERO);
    let absolute = word(
        immediate.clone(),
        event_value(meta, bus, shape, ROLE_IMMEDIATE_ONE),
    );
    let op_indirect = operation(meta, shape, 6);
    let op_high_immediate = operation(meta, shape, 21);
    let op_high_c = operation(meta, shape, 29);
    let op_absolute = operation(meta, shape, 30);
    let mut constraints = Vec::new();
    let indirect_address = argument_zero(meta, shape, 0)
        * pair(meta, state.before.b, state.before.c)
        + argument_zero(meta, shape, 1) * pair(meta, state.before.d, state.before.e)
        + (argument_zero(meta, shape, 2) + argument_zero(meta, shape, 3)) * before_hl.clone();
    constraints
        .push(enabled.clone() * op_indirect.clone() * (data_address.clone() - indirect_address));
    constraints.push(
        enabled.clone()
            * op_indirect.clone()
            * argument_zero(meta, shape, 2)
            * (after_hl.clone() - before_hl.clone() - Expression::Constant(Fp::one())
                + Expression::Constant(Fp::from(65_536)) * wrap.clone()),
    );
    constraints.push(
        enabled.clone()
            * op_indirect.clone()
            * argument_zero(meta, shape, 3)
            * (after_hl - before_hl + Expression::Constant(Fp::one())
                - Expression::Constant(Fp::from(65_536)) * wrap),
    );
    constraints.extend([
        enabled.clone()
            * op_high_immediate.clone()
            * (data_address.clone() - Expression::Constant(Fp::from(0xff00)) - immediate),
        enabled.clone()
            * op_high_c.clone()
            * (data_address.clone() - Expression::Constant(Fp::from(0xff00)) - before_c),
        enabled.clone() * op_absolute.clone() * (data_address - absolute),
    ]);
    let into = op_indirect.clone() * argument_one(meta, shape, 0)
        + (op_high_immediate.clone() + op_high_c.clone() + op_absolute.clone())
            * argument_zero(meta, shape, 0);
    let from = op_indirect * argument_one(meta, shape, 1)
        + (op_high_immediate + op_high_c + op_absolute) * argument_zero(meta, shape, 1);
    constraints.push(enabled.clone() * into * (after_a - data_value.clone()));
    constraints.push(enabled * from * (data_value - before_a));
    constraints
}

fn stack_constraints(
    meta: &mut VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    shape: &ShapeConfig,
    state: &StateTraceConfig,
    bus: &BusConfig,
    columns: StackColumns,
) -> Vec<Expression<Fp>> {
    let before_sp = pair(meta, state.before.sp_high, state.before.sp_low);
    let after_sp = pair(meta, state.after.sp_high, state.after.sp_low);
    let data_zero_address = event_address(meta, bus, shape, ROLE_DATA_ZERO);
    let data_one_address = event_address(meta, bus, shape, ROLE_DATA_ONE);
    let data_zero = event_value(meta, bus, shape, ROLE_DATA_ZERO);
    let data_one = event_value(meta, bus, shape, ROLE_DATA_ONE);
    let branch = meta.query_fixed(shape.branch_taken);
    let pop = operation(meta, shape, 24);
    let return_op = operation(meta, shape, 20);
    let reti = operation(meta, shape, 25);
    let push = operation(meta, shape, 35);
    let call = operation(meta, shape, 34);
    let restart = operation(meta, shape, 36);
    let pop_action = pop.clone() + return_op * branch.clone() + reti;
    let push_action = push.clone() + call * branch + restart;
    let mut constraints = vec![
        enabled.clone() * pop_action.clone() * (data_zero_address.clone() - before_sp.clone()),
        enabled.clone()
            * pop_action.clone()
            * (data_one_address.clone() - before_sp.clone() - Expression::Constant(Fp::one())),
        enabled.clone()
            * pop_action
            * (after_sp.clone() - before_sp.clone() - Expression::Constant(Fp::from(2))),
        enabled.clone()
            * push_action.clone()
            * (data_zero_address.clone() - before_sp.clone() + Expression::Constant(Fp::one())),
        enabled.clone()
            * push_action.clone()
            * (data_one_address.clone() - before_sp.clone() + Expression::Constant(Fp::from(2))),
        enabled.clone()
            * push_action.clone()
            * (after_sp - before_sp + Expression::Constant(Fp::from(2))),
    ];
    constraints.extend(pop_register_constraints(
        meta,
        enabled.clone() * pop,
        shape,
        state,
        data_zero.clone(),
        data_one.clone(),
        columns.pop_low_bits,
    ));
    let return_low_value = meta.query_advice(columns.return_low, Rotation::cur());
    let return_high_value = meta.query_advice(columns.return_high, Rotation::cur());
    let sequential_pc = pair(meta, state.before.pc_high, state.before.pc_low)
        + meta.query_advice(columns.byte_len, Rotation::cur());
    let return_word = word(return_low_value.clone(), return_high_value.clone());
    let call_or_restart = operation(meta, shape, 34) * meta.query_fixed(shape.branch_taken)
        + operation(meta, shape, 36);
    constraints.push(enabled.clone() * call_or_restart.clone() * (return_word - sequential_pc));
    constraints.push(
        enabled.clone()
            * push
            * (data_zero.clone() - high_byte_selection(meta, shape, state.before)),
    );
    constraints.push(
        enabled.clone()
            * operation(meta, shape, 35)
            * (data_one.clone() - low_byte_selection(meta, shape, state.before)),
    );
    constraints.push(enabled.clone() * call_or_restart.clone() * (data_zero - return_high_value));
    constraints.push(enabled * call_or_restart * (data_one - return_low_value));
    constraints
}

fn pair_selection_constraints(
    meta: &mut VirtualCells<'_, Fp>,
    selected_operation: Expression<Fp>,
    shape: &ShapeConfig,
    columns: StateColumns,
    value: Expression<Fp>,
) -> Vec<Expression<Fp>> {
    register_pair_columns(columns)
        .into_iter()
        .enumerate()
        .map(|(code, (high, low))| {
            selected_operation.clone()
                * argument_zero(meta, shape, code)
                * (pair(meta, high, low) - value.clone())
        })
        .collect()
}

fn pop_register_constraints(
    meta: &mut VirtualCells<'_, Fp>,
    selected: Expression<Fp>,
    shape: &ShapeConfig,
    state: &StateTraceConfig,
    low: Expression<Fp>,
    high: Expression<Fp>,
    pop_low_bits: [Column<Advice>; 4],
) -> Vec<Expression<Fp>> {
    let mut constraints = Vec::new();
    for (code, (high_column, low_column)) in register_pair_columns(state.after)
        .into_iter()
        .take(3)
        .enumerate()
    {
        let argument = argument_zero(meta, shape, code);
        constraints.push(
            selected.clone()
                * argument.clone()
                * (meta.query_advice(high_column, Rotation::cur()) - high.clone()),
        );
        constraints.push(
            selected.clone()
                * argument
                * (meta.query_advice(low_column, Rotation::cur()) - low.clone()),
        );
    }
    let af = argument_zero(meta, shape, 3);
    constraints.push(
        selected.clone() * af.clone() * (meta.query_advice(state.after.a, Rotation::cur()) - high),
    );
    let mut low_nibble = Expression::Constant(Fp::zero());
    let mut power = Fp::one();
    for column in pop_low_bits {
        let bit = meta.query_advice(column, Rotation::cur());
        constraints.push(
            selected.clone()
                * af.clone()
                * bit.clone()
                * (Expression::Constant(Fp::one()) - bit.clone()),
        );
        low_nibble = low_nibble + Expression::Constant(power) * bit;
        power = power.double();
    }
    constraints.push(
        selected * af * (low - meta.query_advice(state.after.flags, Rotation::cur()) - low_nibble),
    );
    constraints
}

fn operand_value(
    meta: &mut VirtualCells<'_, Fp>,
    shape: &ShapeConfig,
    columns: StateColumns,
    bus: &BusConfig,
    use_argument_zero: bool,
) -> Expression<Fp> {
    let select = |meta: &mut VirtualCells<'_, Fp>, code| {
        if use_argument_zero {
            argument_zero(meta, shape, code)
        } else {
            argument_one(meta, shape, code)
        }
    };
    register_operands(columns)
        .into_iter()
        .fold(Expression::Constant(Fp::zero()), |sum, (code, column)| {
            sum + select(meta, code) * meta.query_advice(column, Rotation::cur())
        })
        + select(meta, 6) * event_value(meta, bus, shape, ROLE_DATA_ZERO)
        + select(meta, 8) * event_value(meta, bus, shape, ROLE_IMMEDIATE_ZERO)
}

fn register_operands(columns: StateColumns) -> Vec<(usize, Column<Advice>)> {
    vec![
        (0, columns.b),
        (1, columns.c),
        (2, columns.d),
        (3, columns.e),
        (4, columns.h),
        (5, columns.l),
        (7, columns.a),
    ]
}

fn register_pair_columns(columns: StateColumns) -> [(Column<Advice>, Column<Advice>); 4] {
    [
        (columns.b, columns.c),
        (columns.d, columns.e),
        (columns.h, columns.l),
        (columns.sp_high, columns.sp_low),
    ]
}

fn register_pairs(
    meta: &mut VirtualCells<'_, Fp>,
    state: &StateTraceConfig,
) -> Vec<(Expression<Fp>, Expression<Fp>)> {
    register_pair_columns(state.before)
        .into_iter()
        .zip(register_pair_columns(state.after))
        .map(|((before_high, before_low), (after_high, after_low))| {
            (
                pair(meta, before_high, before_low),
                pair(meta, after_high, after_low),
            )
        })
        .collect()
}

fn pair(
    meta: &mut VirtualCells<'_, Fp>,
    high: Column<Advice>,
    low: Column<Advice>,
) -> Expression<Fp> {
    word(
        meta.query_advice(low, Rotation::cur()),
        meta.query_advice(high, Rotation::cur()),
    )
}

fn high_byte_selection(
    meta: &mut VirtualCells<'_, Fp>,
    shape: &ShapeConfig,
    columns: StateColumns,
) -> Expression<Fp> {
    argument_zero(meta, shape, 0) * meta.query_advice(columns.b, Rotation::cur())
        + argument_zero(meta, shape, 1) * meta.query_advice(columns.d, Rotation::cur())
        + argument_zero(meta, shape, 2) * meta.query_advice(columns.h, Rotation::cur())
        + argument_zero(meta, shape, 3) * meta.query_advice(columns.a, Rotation::cur())
}

fn low_byte_selection(
    meta: &mut VirtualCells<'_, Fp>,
    shape: &ShapeConfig,
    columns: StateColumns,
) -> Expression<Fp> {
    argument_zero(meta, shape, 0) * meta.query_advice(columns.c, Rotation::cur())
        + argument_zero(meta, shape, 1) * meta.query_advice(columns.e, Rotation::cur())
        + argument_zero(meta, shape, 2) * meta.query_advice(columns.l, Rotation::cur())
        + argument_zero(meta, shape, 3) * meta.query_advice(columns.flags, Rotation::cur())
}

fn register16(cpu: zksm83_core::CpuState, register: Register16) -> u16 {
    let registers = cpu.registers();
    match register {
        Register16::Bc => u16::from_be_bytes([registers.b, registers.c]),
        Register16::De => u16::from_be_bytes([registers.d, registers.e]),
        Register16::Hl => u16::from_be_bytes([registers.h, registers.l]),
        Register16::Sp => cpu.sp(),
    }
}

fn assign_boolean(
    region: &mut Region<'_, Fp>,
    column: Column<Advice>,
    offset: usize,
    value: Option<bool>,
) -> Result<(), Error> {
    region.assign_advice(
        || "word wrap",
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

fn assign_byte(
    region: &mut Region<'_, Fp>,
    column: Column<Advice>,
    offset: usize,
    value: Option<u8>,
) -> Result<(), Error> {
    region.assign_advice(
        || "data byte",
        column,
        offset,
        || {
            value.map_or(Value::unknown(), |byte| {
                Value::known(Fp::from(u64::from(byte)))
            })
        },
    )?;
    Ok(())
}
