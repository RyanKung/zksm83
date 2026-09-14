//! Linear glue between fixed execution lookups and packed SM83 state.

use akita_pcs::Ring;

use super::{
    ConstraintSink, INSTRUCTION_MODE, RowView, STATE_FLAGS, argument_selector, operation_selector,
};
use crate::{
    ISA_ARGUMENT_ONE_BITS_START, ISA_ARGUMENT_ZERO_BITS_START, NativeField,
    TRACE_AFTER_CPU_BYTE_BITS_START, TRACE_AFTER_SP_BITS_START, TRACE_BEFORE_CPU_BYTE_BITS_START,
    TRACE_BEFORE_SP_BITS_START, TRACE_BRANCH_TAKEN, TRACE_BUS_VALUE_BITS_START,
    TRACE_IMMEDIATE_LOW_BITS_START, UniformError,
    execution_lookup::{ExecutionLookupColumns, absolute_lookup_columns},
};

const BYTE_BITS: usize = 8;
const STATE_A: usize = 0;
const STATE_B: usize = 1;
const STATE_C: usize = 2;
const STATE_D: usize = 3;
const STATE_E: usize = 4;
const STATE_H: usize = 5;
const STATE_L: usize = 6;
const FLAG_CARRY_BIT: usize = 4;
const OUTPUT_CARRY_BIT: usize = 8;
const OUTPUT_HALF_CARRY_BIT: usize = 9;
const OUTPUT_SUBTRACT_BIT: usize = 10;
const OUTPUT_ZERO_BIT: usize = 11;
#[cfg(test)]
const EXECUTION_LOOKUP_GLUE_CONSTRAINT_COUNT: usize = 63;

#[derive(Clone, Copy)]
struct LookupSelectors {
    add_hl: NativeField,
    increment: NativeField,
    decrement: NativeField,
    rotate_accumulator: NativeField,
    decimal_adjust: NativeField,
    alu: NativeField,
    signed_sp: NativeField,
    conditional: NativeField,
    cb_rotate: NativeField,
    test_bit: NativeField,
    reset_bit: NativeField,
    set_bit: NativeField,
}

pub(super) fn constrain_execution_lookup_glue(
    row: &[NativeField],
    lane: usize,
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let selectors = LookupSelectors::new(view)?;
    let first = absolute_lookup_columns(lane, 0)?;
    let second = absolute_lookup_columns(lane, 1)?;

    for bit in 0..17 {
        let first_selected = first_input_selector(view, &selectors, bit)?;
        sink.push(
            first_selected * lookup_address_bit(row, first, bit)?
                - first_input_bit(view, &selectors, bit)?,
        )?;
        let second_selected = selectors.add_hl + selectors.signed_sp;
        sink.push(
            second_selected * lookup_address_bit(row, second, bit)?
                - second_input_bit(row, view, &selectors, first, bit)?,
        )?;
    }
    constrain_result_bytes(row, view, &selectors, first, second, sink)?;
    constrain_result_flags(row, view, &selectors, first, second, sink)?;
    sink.push(
        selectors.conditional
            * (lookup_output_bit(row, first, 0)? - view.value(TRACE_BRANCH_TAKEN)?),
    )?;
    Ok(())
}

fn first_input_selector(
    view: &RowView<'_>,
    selectors: &LookupSelectors,
    bit: usize,
) -> Result<NativeField, UniformError> {
    let alu = if bit < 16 {
        selectors.alu
    } else {
        let arithmetic = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 0)?
            + argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 1)?
            + argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 2)?
            + argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 3)?
            + argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 7)?;
        selectors.alu * arithmetic
    };
    let mut selected = selectors.add_hl + selectors.signed_sp + alu;
    if bit < 13 {
        selected += selectors.rotate_accumulator + selectors.cb_rotate;
    }
    if bit < 12 {
        selected += selectors.decimal_adjust + selectors.test_bit;
    }
    if bit < 11 {
        selected += selectors.reset_bit + selectors.set_bit;
    }
    if bit < 9 {
        selected += selectors.increment + selectors.decrement;
    }
    if bit < 6 {
        selected += selectors.conditional;
    }
    Ok(selected)
}

impl LookupSelectors {
    fn new(view: &RowView<'_>) -> Result<Self, UniformError> {
        let instruction = view.mode(INSTRUCTION_MODE)?;
        let conditional_operation = operation_selector(view, 3)?
            + operation_selector(view, 20)?
            + operation_selector(view, 28)?
            + operation_selector(view, 34)?;
        let conditional_argument = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 1)?
            + argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 2)?
            + argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 3)?
            + argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 4)?;
        Ok(Self {
            add_hl: instruction * operation_selector(view, 5)?,
            increment: instruction * operation_selector(view, 9)?,
            decrement: instruction * operation_selector(view, 10)?,
            rotate_accumulator: instruction * operation_selector(view, 12)?,
            decimal_adjust: instruction * operation_selector(view, 13)?,
            alu: instruction * operation_selector(view, 19)?,
            signed_sp: instruction
                * (operation_selector(view, 22)? + operation_selector(view, 23)?),
            conditional: instruction * conditional_operation * conditional_argument,
            cb_rotate: instruction * operation_selector(view, 37)?,
            test_bit: instruction * operation_selector(view, 38)?,
            reset_bit: instruction * operation_selector(view, 39)?,
            set_bit: instruction * operation_selector(view, 40)?,
        })
    }

    fn cb(self) -> NativeField {
        self.cb_rotate + self.test_bit + self.reset_bit + self.set_bit
    }
}

fn first_input_bit(
    view: &RowView<'_>,
    selectors: &LookupSelectors,
    bit: usize,
) -> Result<NativeField, UniformError> {
    if bit < BYTE_BITS {
        let mut expected = selectors.add_hl * before_cpu_bit(view, STATE_L, bit)?
            + selectors.signed_sp * before_sp_bit(view, bit)?
            + selectors.alu * before_cpu_bit(view, STATE_A, bit)?
            + (selectors.increment + selectors.decrement)
                * selected_primary_operand_bit(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 1, bit)?
            + selectors.rotate_accumulator * before_cpu_bit(view, STATE_A, bit)?
            + selectors.decimal_adjust * before_cpu_bit(view, STATE_A, bit)?
            + selectors.cb()
                * selected_primary_operand_bit(view, ISA_ARGUMENT_ONE_BITS_START, 4, 2, bit)?;
        if bit < 4 {
            expected += selectors.conditional * before_flag_bit(view, bit)?;
        } else if bit == 4 {
            expected += condition_code_bit(view, 0, selectors.conditional)?;
        } else if bit == 5 {
            expected += condition_code_bit(view, 1, selectors.conditional)?;
        }
        return Ok(expected);
    }
    if bit < 16 {
        return second_byte_input_bit(view, selectors, bit - BYTE_BITS);
    }
    let carry = before_flag_bit(view, 0)?;
    let add_carry = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 1)?;
    let subtract_carry = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 3)?;
    Ok(selectors.alu * (add_carry + subtract_carry) * carry)
}

fn second_byte_input_bit(
    view: &RowView<'_>,
    selectors: &LookupSelectors,
    bit: usize,
) -> Result<NativeField, UniformError> {
    let mut expected = selectors.add_hl * selected_word_bit(view, bit)?
        + selectors.signed_sp * view.value(TRACE_IMMEDIATE_LOW_BITS_START + bit)?
        + selectors.alu
            * selected_primary_operand_bit(view, ISA_ARGUMENT_ONE_BITS_START, 4, 1, bit)?;
    if bit == 0 {
        expected += (selectors.increment + selectors.decrement) * before_flag_bit(view, 0)?;
    }
    if bit < 3 {
        let operation_bit = view.isa(ISA_ARGUMENT_ZERO_BITS_START + bit)?;
        expected += (selectors.rotate_accumulator + selectors.cb_rotate) * operation_bit;
        expected += (selectors.test_bit + selectors.reset_bit + selectors.set_bit) * operation_bit;
    }
    if bit == 3 {
        expected +=
            (selectors.rotate_accumulator + selectors.cb_rotate) * before_flag_bit(view, 0)?;
        expected += selectors.test_bit * before_flag_bit(view, 0)?;
    }
    if bit == 4 {
        expected += selectors.cb_rotate;
    }
    if bit < 4 {
        expected += selectors.decimal_adjust * before_flag_bit(view, bit)?;
    }
    Ok(expected)
}

fn second_input_bit(
    row: &[NativeField],
    view: &RowView<'_>,
    selectors: &LookupSelectors,
    first: ExecutionLookupColumns,
    bit: usize,
) -> Result<NativeField, UniformError> {
    if bit < BYTE_BITS {
        return Ok(selectors.add_hl * before_cpu_bit(view, STATE_H, bit)?
            + selectors.signed_sp * before_sp_bit(view, bit + BYTE_BITS)?);
    }
    if bit < 16 {
        let high_bit = bit - BYTE_BITS;
        return Ok(
            selectors.add_hl * selected_word_bit(view, high_bit + BYTE_BITS)?
                + selectors.signed_sp
                    * view.value(TRACE_IMMEDIATE_LOW_BITS_START + BYTE_BITS - 1)?,
        );
    }
    Ok((selectors.add_hl + selectors.signed_sp) * lookup_output_bit(row, first, OUTPUT_CARRY_BIT)?)
}

fn constrain_result_bytes(
    row: &[NativeField],
    view: &RowView<'_>,
    selectors: &LookupSelectors,
    first: ExecutionLookupColumns,
    second: ExecutionLookupColumns,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let alu_write = selectors.alu
        * (NativeField::from_u64(1) - argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 7)?);
    let primary_write = selectors.increment + selectors.decrement;
    let cb_write = selectors.cb_rotate + selectors.reset_bit + selectors.set_bit;
    for bit in 0..BYTE_BITS {
        let first_output = lookup_output_bit(row, first, bit)?;
        let mut constraint = primary_write
            * (first_output
                - selected_primary_destination_bit(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 2, bit)?)
            + (selectors.rotate_accumulator + selectors.decimal_adjust + alu_write)
                * (first_output - after_cpu_bit(view, STATE_A, bit)?)
            + cb_write
                * (first_output
                    - selected_primary_destination_bit(
                        view,
                        ISA_ARGUMENT_ONE_BITS_START,
                        4,
                        3,
                        bit,
                    )?)
            + selectors.add_hl * (first_output - after_cpu_bit(view, STATE_L, bit)?)
            + selectors.signed_sp * (first_output - signed_destination_bit(view, bit)?);
        sink.push(constraint)?;
        constraint = selectors.add_hl
            * (lookup_output_bit(row, second, bit)? - after_cpu_bit(view, STATE_H, bit)?)
            + selectors.signed_sp
                * (lookup_output_bit(row, second, bit)?
                    - signed_destination_bit(view, bit + BYTE_BITS)?);
        sink.push(constraint)?;
    }
    Ok(())
}

fn constrain_result_flags(
    row: &[NativeField],
    view: &RowView<'_>,
    selectors: &LookupSelectors,
    first: ExecutionLookupColumns,
    second: ExecutionLookupColumns,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let single_flags = selectors.increment
        + selectors.decrement
        + selectors.rotate_accumulator
        + selectors.decimal_adjust
        + selectors.alu
        + selectors.cb_rotate
        + selectors.test_bit;
    for (output_bit, flag_bit) in [
        (OUTPUT_CARRY_BIT, 0),
        (OUTPUT_HALF_CARRY_BIT, 1),
        (OUTPUT_SUBTRACT_BIT, 2),
        (OUTPUT_ZERO_BIT, 3),
    ] {
        sink.push(
            single_flags
                * (lookup_output_bit(row, first, output_bit)? - after_flag_bit(view, flag_bit)?),
        )?;
    }
    sink.push(
        selectors.add_hl
            * (lookup_output_bit(row, second, OUTPUT_CARRY_BIT)? - after_flag_bit(view, 0)?),
    )?;
    sink.push(
        selectors.add_hl
            * (lookup_output_bit(row, second, OUTPUT_HALF_CARRY_BIT)? - after_flag_bit(view, 1)?),
    )?;
    sink.push(selectors.add_hl * after_flag_bit(view, 2)?)?;
    sink.push(selectors.add_hl * (after_flag_bit(view, 3)? - before_flag_bit(view, 3)?))?;
    sink.push(
        selectors.signed_sp
            * (lookup_output_bit(row, first, OUTPUT_CARRY_BIT)? - after_flag_bit(view, 0)?),
    )?;
    sink.push(
        selectors.signed_sp
            * (lookup_output_bit(row, first, OUTPUT_HALF_CARRY_BIT)? - after_flag_bit(view, 1)?),
    )?;
    sink.push(selectors.signed_sp * after_flag_bit(view, 2)?)?;
    sink.push(selectors.signed_sp * after_flag_bit(view, 3)?)
}

fn condition_code_bit(
    view: &RowView<'_>,
    bit: usize,
    selected: NativeField,
) -> Result<NativeField, UniformError> {
    let code_one = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 2)?;
    let code_two = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 3)?;
    let code_three = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 4)?;
    Ok(if bit == 0 {
        selected * (code_one + code_three)
    } else {
        selected * (code_two + code_three)
    })
}

fn selected_primary_operand_bit(
    view: &RowView<'_>,
    argument_start: usize,
    width: usize,
    bus_slot: usize,
    bit: usize,
) -> Result<NativeField, UniformError> {
    let mut selected = NativeField::from_u64(0);
    for (argument, state) in byte_register_routes() {
        selected += argument_selector(view, argument_start, width, argument)?
            * before_cpu_bit(view, state, bit)?;
    }
    let bus_bit = bus_value_bit(view, bus_slot, bit)?;
    selected += argument_selector(view, argument_start, width, 6)? * bus_bit;
    if width == 4 {
        selected += argument_selector(view, argument_start, width, 8)? * bus_bit;
    }
    Ok(selected)
}

fn selected_primary_destination_bit(
    view: &RowView<'_>,
    argument_start: usize,
    width: usize,
    bus_slot: usize,
    bit: usize,
) -> Result<NativeField, UniformError> {
    let mut selected = NativeField::from_u64(0);
    for (argument, state) in byte_register_routes() {
        selected += argument_selector(view, argument_start, width, argument)?
            * after_cpu_bit(view, state, bit)?;
    }
    selected +=
        argument_selector(view, argument_start, width, 6)? * bus_value_bit(view, bus_slot, bit)?;
    Ok(selected)
}

fn selected_word_bit(view: &RowView<'_>, bit: usize) -> Result<NativeField, UniformError> {
    let mut selected = NativeField::from_u64(0);
    let (byte_bit, register_bits) = if bit < BYTE_BITS {
        (bit, [(0, STATE_C), (1, STATE_E), (2, STATE_L)])
    } else {
        (bit - BYTE_BITS, [(0, STATE_B), (1, STATE_D), (2, STATE_H)])
    };
    for (argument, state) in register_bits {
        selected += argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, argument)?
            * before_cpu_bit(view, state, byte_bit)?;
    }
    selected +=
        argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 3)? * before_sp_bit(view, bit)?;
    Ok(selected)
}

fn signed_destination_bit(view: &RowView<'_>, bit: usize) -> Result<NativeField, UniformError> {
    let add_sp = operation_selector(view, 22)?;
    let load_hl = operation_selector(view, 23)?;
    let destination = if bit < BYTE_BITS {
        add_sp * after_sp_bit(view, bit)? + load_hl * after_cpu_bit(view, STATE_L, bit)?
    } else {
        add_sp * after_sp_bit(view, bit)? + load_hl * after_cpu_bit(view, STATE_H, bit - BYTE_BITS)?
    };
    Ok(destination)
}

fn lookup_address_bit(
    row: &[NativeField],
    layout: ExecutionLookupColumns,
    bit: usize,
) -> Result<NativeField, UniformError> {
    let column = layout
        .address_bits()
        .get(bit)
        .copied()
        .ok_or(UniformError::Shape)?;
    row.get(column).copied().ok_or(UniformError::Shape)
}

fn lookup_output_bit(
    row: &[NativeField],
    layout: ExecutionLookupColumns,
    bit: usize,
) -> Result<NativeField, UniformError> {
    let column = layout
        .output_bits()
        .get(bit)
        .copied()
        .ok_or(UniformError::Shape)?;
    row.get(column).copied().ok_or(UniformError::Shape)
}

fn before_cpu_bit(
    view: &RowView<'_>,
    state: usize,
    bit: usize,
) -> Result<NativeField, UniformError> {
    view.value(TRACE_BEFORE_CPU_BYTE_BITS_START + state * BYTE_BITS + bit)
}

fn after_cpu_bit(
    view: &RowView<'_>,
    state: usize,
    bit: usize,
) -> Result<NativeField, UniformError> {
    view.value(TRACE_AFTER_CPU_BYTE_BITS_START + state * BYTE_BITS + bit)
}

fn before_flag_bit(view: &RowView<'_>, bit: usize) -> Result<NativeField, UniformError> {
    before_cpu_bit(view, STATE_FLAGS, FLAG_CARRY_BIT + bit)
}

fn after_flag_bit(view: &RowView<'_>, bit: usize) -> Result<NativeField, UniformError> {
    after_cpu_bit(view, STATE_FLAGS, FLAG_CARRY_BIT + bit)
}

fn before_sp_bit(view: &RowView<'_>, bit: usize) -> Result<NativeField, UniformError> {
    view.value(TRACE_BEFORE_SP_BITS_START + bit)
}

fn after_sp_bit(view: &RowView<'_>, bit: usize) -> Result<NativeField, UniformError> {
    view.value(TRACE_AFTER_SP_BITS_START + bit)
}

fn bus_value_bit(view: &RowView<'_>, slot: usize, bit: usize) -> Result<NativeField, UniformError> {
    view.value(TRACE_BUS_VALUE_BITS_START + slot * BYTE_BITS + bit)
}

const fn byte_register_routes() -> [(u8, usize); 7] {
    [
        (0, STATE_B),
        (1, STATE_C),
        (2, STATE_D),
        (3, STATE_E),
        (4, STATE_H),
        (5, STATE_L),
        (7, STATE_A),
    ]
}

#[cfg(test)]
mod tests {
    use super::{
        ConstraintSink, EXECUTION_LOOKUP_GLUE_CONSTRAINT_COUNT, RowView,
        constrain_execution_lookup_glue,
    };
    use crate::{BlockCpuWitness, NativeField, block_test_support::lookup_blocks};
    use akita_pcs::Ring;

    #[test]
    fn representative_lookup_families_satisfy_cpu_glue() -> Result<(), Box<dyn std::error::Error>> {
        for program in [
            [0x80, 0x00, 0x00, 0x00],
            [0x04, 0x00, 0x00, 0x00],
            [0x09, 0x00, 0x00, 0x00],
            [0xe8, 0x00, 0x00, 0x00],
            [0x27, 0x00, 0x00, 0x00],
            [0xcb, 0x00, 0x00, 0x00],
            [0x20, 0x00, 0x00, 0x00],
        ] {
            let blocks = lookup_blocks(&program, 1)?;
            let witness = BlockCpuWitness::from_blocks(&blocks)?;
            let row = witness
                .columns()
                .iter()
                .map(|column| {
                    column
                        .first()
                        .copied()
                        .map(NativeField::from_u64)
                        .ok_or("missing packed lookup row")
                })
                .collect::<Result<Vec<_>, _>>()?;
            let view = RowView::packed(&row, 0)?;
            let mut constraints =
                vec![NativeField::from_u64(0); EXECUTION_LOOKUP_GLUE_CONSTRAINT_COUNT];
            let mut sink = ConstraintSink::new(&mut constraints);
            constrain_execution_lookup_glue(&row, 0, &view, &mut sink)?;
            assert_eq!(sink.finish()?, EXECUTION_LOOKUP_GLUE_CONSTRAINT_COUNT);
            assert!(
                constraints
                    .into_iter()
                    .all(|value| value == NativeField::from_u64(0))
            );
        }
        Ok(())
    }
}
