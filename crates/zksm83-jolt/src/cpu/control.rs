//! Instruction-fetch, conditional-branch, and program-counter identities.

use akita_pcs::Ring;

use super::{
    BUS_ADDRESS_OFFSET, BUS_VALUE_OFFSET, ConstraintSink, INSTRUCTION_MODE, RowView, STATE_FLAGS,
    argument_selector, boolean, bus_field, operation_selector, packed_bits,
};
use crate::{
    ISA_ARGUMENT_ZERO_BITS_START, ISA_IMMEDIATE_READS, ISA_OPCODE_FETCHES, NativeField,
    TRACE_BRANCH_TAKEN, TRACE_CONTROL_OVERFLOW, TRACE_CONTROL_UNDERFLOW, TRACE_FETCH_ONE_WRAP,
    TRACE_FETCH_TWO_WRAP, TRACE_HALT_BUG, TRACE_IMMEDIATE_HIGH, TRACE_IMMEDIATE_HIGH_BITS_START,
    TRACE_IMMEDIATE_LOW, TRACE_IMMEDIATE_LOW_BITS_START, TRACE_ISA_ADDRESS_START,
    TRACE_ISA_OUTPUT_START, TRACE_PC_WRAP, TRACE_SEQUENTIAL_PC, TRACE_SEQUENTIAL_PC_BITS_START,
    UniformError,
};

const STATE_PC: usize = 8;
const STATE_RUN_STATE: usize = 11;
const FLAGS_CARRY_BIT: usize = 4;
const FLAGS_ZERO_BIT: usize = 7;

pub(super) fn constrain_instruction_flow(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_instruction_witness(view, sink)?;
    constrain_fetch_alignment(view, sink)?;
    constrain_branch_decision(view, sink)?;
    constrain_program_counter(view, sink)
}

/// Packed-v2 flow constraints whose conditional predicate comes from the execution lookup.
pub(super) fn constrain_instruction_flow_with_lookup(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_instruction_witness(view, sink)?;
    constrain_fetch_alignment(view, sink)?;
    constrain_branch_routing_with_lookup(view, sink)?;
    constrain_program_counter(view, sink)
}

fn constrain_instruction_witness(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let instruction = view.mode(INSTRUCTION_MODE)?;
    for start in [
        TRACE_IMMEDIATE_LOW_BITS_START,
        TRACE_IMMEDIATE_HIGH_BITS_START,
    ] {
        for bit in 0..8 {
            sink.push(boolean(view.value(start + bit)?))?;
        }
    }
    for bit in 0..16 {
        sink.push(boolean(view.value(TRACE_SEQUENTIAL_PC_BITS_START + bit)?))?;
    }
    for column in [
        TRACE_PC_WRAP,
        TRACE_HALT_BUG,
        TRACE_CONTROL_UNDERFLOW,
        TRACE_CONTROL_OVERFLOW,
        TRACE_FETCH_ONE_WRAP,
        TRACE_FETCH_TWO_WRAP,
    ] {
        sink.push(boolean(view.value(column)?))?;
    }
    sink.push(
        view.value(TRACE_IMMEDIATE_LOW)? - packed_bits(view, TRACE_IMMEDIATE_LOW_BITS_START, 8)?,
    )?;
    sink.push(
        view.value(TRACE_IMMEDIATE_HIGH)? - packed_bits(view, TRACE_IMMEDIATE_HIGH_BITS_START, 8)?,
    )?;
    sink.push(
        view.value(TRACE_SEQUENTIAL_PC)? - packed_bits(view, TRACE_SEQUENTIAL_PC_BITS_START, 16)?,
    )?;
    let immediate_count = view.isa(ISA_IMMEDIATE_READS)?;
    sink.push(
        instruction
            * immediate_count
            * (view.value(TRACE_IMMEDIATE_LOW)? - bus_field(view, 1, BUS_VALUE_OFFSET)?),
    )?;
    sink.push(
        instruction
            * immediate_count
            * (immediate_count - one)
            * (view.value(TRACE_IMMEDIATE_HIGH)? - bus_field(view, 2, BUS_VALUE_OFFSET)?),
    )?;
    sink.push(
        instruction
            * view.value(TRACE_IMMEDIATE_LOW)?
            * (immediate_count - one)
            * (immediate_count - NativeField::from_u64(2)),
    )?;
    sink.push(
        instruction
            * view.value(TRACE_IMMEDIATE_HIGH)?
            * (immediate_count - NativeField::from_u64(2)),
    )?;
    let halt_bug = view.value(TRACE_HALT_BUG)?;
    let run_state = view.before(STATE_RUN_STATE)?;
    sink.push(instruction * run_state * (run_state - NativeField::from_u64(3)))?;
    sink.push(instruction * halt_bug * (run_state - NativeField::from_u64(3)))?;
    sink.push(
        instruction
            * (one - halt_bug)
            * run_state
            * (run_state - one)
            * (run_state - NativeField::from_u64(2)),
    )?;
    sink.push(
        instruction
            * (view.value(TRACE_SEQUENTIAL_PC)?
                - view.before(STATE_PC)?
                - view.isa(ISA_OPCODE_FETCHES)?
                - view.isa(ISA_IMMEDIATE_READS)?
                + halt_bug
                + NativeField::from_u64(65_536) * view.value(TRACE_PC_WRAP)?),
    )?;
    let not_instruction = one - instruction;
    for column in [
        TRACE_IMMEDIATE_LOW,
        TRACE_IMMEDIATE_HIGH,
        TRACE_SEQUENTIAL_PC,
        TRACE_PC_WRAP,
        TRACE_HALT_BUG,
        TRACE_CONTROL_UNDERFLOW,
        TRACE_CONTROL_OVERFLOW,
        TRACE_FETCH_ONE_WRAP,
        TRACE_FETCH_TWO_WRAP,
    ] {
        sink.push(not_instruction * view.value(column)?)?;
    }
    Ok(())
}

fn constrain_fetch_alignment(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let instruction = view.mode(INSTRUCTION_MODE)?;
    let prefix = view.value(TRACE_ISA_ADDRESS_START + 8)?;
    let opcode = packed_bits(view, TRACE_ISA_ADDRESS_START, 8)?;
    let halt_bug = view.value(TRACE_HALT_BUG)?;
    sink.push(instruction * (bus_field(view, 0, BUS_ADDRESS_OFFSET)? - view.before(STATE_PC)?))?;
    sink.push(
        instruction
            * (bus_field(view, 0, BUS_VALUE_OFFSET)?
                - (one - prefix) * opcode
                - prefix * NativeField::from_u64(0xcb)),
    )?;
    let fetch_one = view.before(STATE_PC)? + one
        - halt_bug
        - NativeField::from_u64(65_536) * view.value(TRACE_FETCH_ONE_WRAP)?;
    let fetch_two = view.before(STATE_PC)? + NativeField::from_u64(2)
        - halt_bug
        - NativeField::from_u64(65_536) * view.value(TRACE_FETCH_TWO_WRAP)?;
    sink.push(instruction * prefix * (bus_field(view, 1, BUS_ADDRESS_OFFSET)? - fetch_one))?;
    sink.push(instruction * prefix * (bus_field(view, 1, BUS_VALUE_OFFSET)? - opcode))?;
    let primary = one - prefix;
    let immediate_count = view.isa(ISA_IMMEDIATE_READS)?;
    sink.push(
        instruction
            * primary
            * immediate_count
            * (bus_field(view, 1, BUS_ADDRESS_OFFSET)? - fetch_one),
    )?;
    sink.push(
        instruction
            * primary
            * immediate_count
            * (immediate_count - one)
            * (bus_field(view, 2, BUS_ADDRESS_OFFSET)? - fetch_two),
    )
}

fn constrain_branch_decision(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let instruction = view.mode(INSTRUCTION_MODE)?;
    let branch = view.value(TRACE_BRANCH_TAKEN)?;
    let conditional = operation_selector(view, 3)?
        + operation_selector(view, 20)?
        + operation_selector(view, 28)?
        + operation_selector(view, 34)?;
    let fixed = operation_selector(view, 25)?
        + operation_selector(view, 26)?
        + operation_selector(view, 36)?;
    let zero = before_flag_bit(view, FLAGS_ZERO_BIT)?;
    let carry = before_flag_bit(view, FLAGS_CARRY_BIT)?;
    let expected = argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 0)?
        + argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 1)? * (one - zero)
        + argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 2)? * zero
        + argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 3)? * (one - carry)
        + argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 4)? * carry;
    sink.push(instruction * conditional * (branch - expected))?;
    sink.push(instruction * fixed * (branch - one))?;
    sink.push(instruction * (one - conditional - fixed) * branch)
}

fn constrain_branch_routing_with_lookup(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let instruction = view.mode(INSTRUCTION_MODE)?;
    let branch = view.value(TRACE_BRANCH_TAKEN)?;
    let conditional_operation = operation_selector(view, 3)?
        + operation_selector(view, 20)?
        + operation_selector(view, 28)?
        + operation_selector(view, 34)?;
    let unconditional =
        conditional_operation * argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 0)?;
    let conditional = conditional_operation
        * (argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 1)?
            + argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 2)?
            + argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 3)?
            + argument_selector(view, ISA_ARGUMENT_ZERO_BITS_START, 3, 4)?);
    let fixed = unconditional
        + operation_selector(view, 25)?
        + operation_selector(view, 26)?
        + operation_selector(view, 36)?;
    sink.push(instruction * fixed * (branch - one))?;
    sink.push(instruction * (one - conditional - fixed) * branch)
}

fn constrain_program_counter(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let instruction = view.mode(INSTRUCTION_MODE)?;
    let branch = view.value(TRACE_BRANCH_TAKEN)?;
    let sequential = view.value(TRACE_SEQUENTIAL_PC)?;
    let relative = operation_selector(view, 3)?;
    let return_operation = operation_selector(view, 20)?;
    let return_interrupt = operation_selector(view, 25)?;
    let jump_hl = operation_selector(view, 26)?;
    let absolute_jump = operation_selector(view, 28)?;
    let call = operation_selector(view, 34)?;
    let restart = operation_selector(view, 36)?;
    let control =
        relative + return_operation + return_interrupt + jump_hl + absolute_jump + call + restart;
    sink.push(instruction * (one - control) * (view.after(STATE_PC)? - sequential))?;
    let low = view.value(TRACE_IMMEDIATE_LOW)?;
    let high = view.value(TRACE_IMMEDIATE_HIGH)?;
    let immediate_word = low + NativeField::from_u64(256) * high;
    let sign = view.value(TRACE_IMMEDIATE_LOW_BITS_START + 7)?;
    let underflow = view.value(TRACE_CONTROL_UNDERFLOW)?;
    let overflow = view.value(TRACE_CONTROL_OVERFLOW)?;
    let relative_taken = instruction * relative * branch;
    sink.push(underflow * overflow)?;
    sink.push((one - relative_taken) * underflow)?;
    sink.push((one - relative_taken) * overflow)?;
    let relative_target = sequential + low - NativeField::from_u64(256) * sign
        + NativeField::from_u64(65_536) * underflow
        - NativeField::from_u64(65_536) * overflow;
    sink.push(
        instruction
            * relative
            * (view.after(STATE_PC)? - branch * relative_target - (one - branch) * sequential),
    )?;
    sink.push(
        instruction
            * (absolute_jump + call)
            * (view.after(STATE_PC)? - branch * immediate_word - (one - branch) * sequential),
    )?;
    let hl = view.before(5)? * NativeField::from_u64(256) + view.before(6)?;
    sink.push(instruction * jump_hl * (view.after(STATE_PC)? - hl))?;
    let popped = bus_field(view, 1, BUS_VALUE_OFFSET)?
        + NativeField::from_u64(256) * bus_field(view, 2, BUS_VALUE_OFFSET)?;
    sink.push(
        instruction
            * return_operation
            * (view.after(STATE_PC)? - branch * popped - (one - branch) * sequential),
    )?;
    sink.push(instruction * return_interrupt * (view.after(STATE_PC)? - popped))?;
    sink.push(
        instruction
            * restart
            * (view.after(STATE_PC)?
                - NativeField::from_u64(8)
                    * packed_bits(
                        view,
                        TRACE_ISA_OUTPUT_START + ISA_ARGUMENT_ZERO_BITS_START,
                        3,
                    )?),
    )
}

fn before_flag_bit(view: &RowView<'_>, bit: usize) -> Result<NativeField, UniformError> {
    view.value(crate::TRACE_BEFORE_CPU_BYTE_BITS_START + STATE_FLAGS * 8 + bit)
}
