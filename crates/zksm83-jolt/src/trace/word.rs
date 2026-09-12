//! Native 16-bit and signed-SP auxiliary witness encoding.

use zksm83_core::{StepKind, VmState};
use zksm83_isa::AlignedInstruction;
use zksm83_trace::TraceRow;

use super::{
    NativeTraceError, TRACE_ADDRESS_WRAP, TRACE_POP_FLAGS_LOW_NIBBLE,
    TRACE_POP_FLAGS_LOW_NIBBLE_BITS_START, TRACE_SIGNED_SP_OVERFLOW, TRACE_SIGNED_SP_UNDERFLOW,
    TRACE_STACK_FIRST_WRAP, TRACE_STACK_WRAP, TRACE_WORD_CARRY, TRACE_WORD_HALF_CARRY,
    TRACE_WORD_WRAP, append,
};

pub(super) fn append_word_witness(
    columns: &mut [Vec<u64>],
    row: &TraceRow,
) -> Result<(), NativeTraceError> {
    if matches!(row.effects().kind(), StepKind::InterruptDispatch(_)) {
        return append_interrupt_stack_witness(columns, row);
    }
    if row.effects().kind() != StepKind::Instruction {
        return append_empty_word_witness(columns);
    }
    let aligned = AlignedInstruction::from_decoded(row.effects().instruction());
    let before = row.before();
    let word_wrap = word_wrap(before, aligned)?;
    let (carry, half_carry) = add_hl_carries(before, aligned)?;
    let (underflow, overflow) = signed_sp_wraps(row, aligned);
    let (stack_wrap, stack_first_wrap) = stack_wraps(row, aligned);
    let pop_nibble = pop_flags_low_nibble(row, aligned);
    let address_wrap = aligned.operation == 1 && immediate_word(row) == u16::MAX;
    append(columns, TRACE_WORD_WRAP, u64::from(word_wrap))?;
    append(columns, TRACE_WORD_CARRY, u64::from(carry))?;
    append(columns, TRACE_WORD_HALF_CARRY, u64::from(half_carry))?;
    append(columns, TRACE_SIGNED_SP_UNDERFLOW, u64::from(underflow))?;
    append(columns, TRACE_SIGNED_SP_OVERFLOW, u64::from(overflow))?;
    append(columns, TRACE_STACK_WRAP, u64::from(stack_wrap))?;
    append(columns, TRACE_STACK_FIRST_WRAP, u64::from(stack_first_wrap))?;
    append(columns, TRACE_POP_FLAGS_LOW_NIBBLE, u64::from(pop_nibble))?;
    for bit in 0..4 {
        append(
            columns,
            TRACE_POP_FLAGS_LOW_NIBBLE_BITS_START + bit,
            u64::from((pop_nibble >> bit) & 1),
        )?;
    }
    append(columns, TRACE_ADDRESS_WRAP, u64::from(address_wrap))
}

fn append_interrupt_stack_witness(
    columns: &mut [Vec<u64>],
    row: &TraceRow,
) -> Result<(), NativeTraceError> {
    for column in [
        TRACE_WORD_WRAP,
        TRACE_WORD_CARRY,
        TRACE_WORD_HALF_CARRY,
        TRACE_SIGNED_SP_UNDERFLOW,
        TRACE_SIGNED_SP_OVERFLOW,
    ] {
        append(columns, column, 0)?;
    }
    let sp = row.before().cpu().sp();
    append(columns, TRACE_STACK_WRAP, u64::from(sp < 2))?;
    append(columns, TRACE_STACK_FIRST_WRAP, u64::from(sp < 1))?;
    append(columns, TRACE_POP_FLAGS_LOW_NIBBLE, 0)?;
    for bit in 0..4 {
        append(columns, TRACE_POP_FLAGS_LOW_NIBBLE_BITS_START + bit, 0)?;
    }
    append(columns, TRACE_ADDRESS_WRAP, 0)
}

pub(super) fn append_empty_word_witness(columns: &mut [Vec<u64>]) -> Result<(), NativeTraceError> {
    for column in [
        TRACE_WORD_WRAP,
        TRACE_WORD_CARRY,
        TRACE_WORD_HALF_CARRY,
        TRACE_SIGNED_SP_UNDERFLOW,
        TRACE_SIGNED_SP_OVERFLOW,
        TRACE_STACK_WRAP,
        TRACE_STACK_FIRST_WRAP,
        TRACE_POP_FLAGS_LOW_NIBBLE,
        TRACE_ADDRESS_WRAP,
    ] {
        append(columns, column, 0)?;
    }
    for bit in 0..4 {
        append(columns, TRACE_POP_FLAGS_LOW_NIBBLE_BITS_START + bit, 0)?;
    }
    Ok(())
}

fn word_wrap(before: VmState, aligned: AlignedInstruction) -> Result<bool, NativeTraceError> {
    let (word, increment) = match aligned.operation {
        6 => match aligned.argument_zero {
            2 => (register_word(before, 2)?, true),
            3 => (register_word(before, 2)?, false),
            0 | 1 => return Ok(false),
            _ => return Err(NativeTraceError::Layout),
        },
        7 => (register_word(before, aligned.argument_zero)?, true),
        8 => (register_word(before, aligned.argument_zero)?, false),
        _ => return Ok(false),
    };
    Ok(if increment {
        word == u16::MAX
    } else {
        word == 0
    })
}

fn add_hl_carries(
    before: VmState,
    aligned: AlignedInstruction,
) -> Result<(bool, bool), NativeTraceError> {
    if aligned.operation != 5 {
        return Ok((false, false));
    }
    let left = register_word(before, 2)?;
    let right = register_word(before, aligned.argument_zero)?;
    Ok((
        left.overflowing_add(right).1,
        (left & 0x0fff) + (right & 0x0fff) > 0x0fff,
    ))
}

fn signed_sp_wraps(row: &TraceRow, aligned: AlignedInstruction) -> (bool, bool) {
    if !matches!(aligned.operation, 22 | 23) {
        return (false, false);
    }
    let immediate = row
        .effects()
        .bus_events()
        .find(|event| matches!(event.kind().code(), 2 | 15))
        .map_or(0, |event| event.transcript_event().value);
    let target = i32::from(row.before().cpu().sp()) + i32::from(i8::from_ne_bytes([immediate]));
    (target < 0, target > i32::from(u16::MAX))
}

fn stack_wraps(row: &TraceRow, aligned: AlignedInstruction) -> (bool, bool) {
    let push = aligned.operation == 35
        || aligned.operation == 36
        || (aligned.operation == 34 && row.effects().branch_taken());
    let pop = aligned.operation == 24
        || aligned.operation == 25
        || (aligned.operation == 20 && row.effects().branch_taken());
    let sp = row.before().cpu().sp();
    if push {
        (sp < 2, sp < 1)
    } else if pop {
        (sp > u16::MAX - 2, sp == u16::MAX)
    } else {
        (false, false)
    }
}

fn pop_flags_low_nibble(row: &TraceRow, aligned: AlignedInstruction) -> u8 {
    if aligned.operation != 24 || aligned.argument_zero != 3 {
        return 0;
    }
    row.effects()
        .bus_events()
        .find(|event| matches!(event.kind().code(), 3 | 4 | 6 | 9 | 11 | 13))
        .map_or(0, |event| event.transcript_event().value & 0x0f)
}

fn immediate_word(row: &TraceRow) -> u16 {
    let mut values = row
        .effects()
        .bus_events()
        .filter(|event| matches!(event.kind().code(), 2 | 15))
        .map(|event| event.transcript_event().value);
    let low = values.next().unwrap_or(0);
    let high = values.next().unwrap_or(0);
    u16::from_le_bytes([low, high])
}

fn register_word(state: VmState, argument: u8) -> Result<u16, NativeTraceError> {
    let registers = state.cpu().registers();
    match argument {
        0 => Ok(u16::from_be_bytes([registers.b, registers.c])),
        1 => Ok(u16::from_be_bytes([registers.d, registers.e])),
        2 => Ok(u16::from_be_bytes([registers.h, registers.l])),
        3 => Ok(state.cpu().sp()),
        _ => Err(NativeTraceError::Layout),
    }
}
