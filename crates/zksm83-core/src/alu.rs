//! Pure SM83 arithmetic and flag relations.

use zksm83_isa::{AluOperation, CbOperation};

use crate::Flags;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ByteResult {
    pub(crate) value: u8,
    pub(crate) flags: Flags,
}

pub(crate) fn increment(value: u8, before: Flags) -> ByteResult {
    let result = value.wrapping_add(1);
    ByteResult {
        value: result,
        flags: Flags::from_bits(result == 0, false, value & 0x0f == 0x0f, before.carry()),
    }
}

pub(crate) fn decrement(value: u8, before: Flags) -> ByteResult {
    let result = value.wrapping_sub(1);
    ByteResult {
        value: result,
        flags: Flags::from_bits(result == 0, true, value & 0x0f == 0, before.carry()),
    }
}

pub(crate) fn add_hl(left: u16, right: u16, before: Flags) -> (u16, Flags) {
    let result = left.wrapping_add(right);
    let half_carry = (left & 0x0fff) + (right & 0x0fff) > 0x0fff;
    let carry = left.overflowing_add(right).1;
    (
        result,
        Flags::from_bits(before.zero(), false, half_carry, carry),
    )
}

pub(crate) fn add_signed_to_sp(sp: u16, encoded_offset: u8) -> (u16, Flags) {
    let signed = i8::from_ne_bytes([encoded_offset]);
    let result = sp.wrapping_add_signed(i16::from(signed));
    let half_carry = (sp & 0x000f) + (u16::from(encoded_offset) & 0x000f) > 0x000f;
    let carry = (sp & 0x00ff) + u16::from(encoded_offset) > 0x00ff;
    (result, Flags::from_bits(false, false, half_carry, carry))
}

pub(crate) fn apply_alu(
    operation: AluOperation,
    accumulator: u8,
    operand: u8,
    before: Flags,
) -> ByteResult {
    match operation {
        AluOperation::Add => add(accumulator, operand, false),
        AluOperation::AddCarry => add(accumulator, operand, before.carry()),
        AluOperation::Subtract => subtract(accumulator, operand, false),
        AluOperation::SubtractCarry => subtract(accumulator, operand, before.carry()),
        AluOperation::And => logical(accumulator & operand, true),
        AluOperation::Xor => logical(accumulator ^ operand, false),
        AluOperation::Or => logical(accumulator | operand, false),
        AluOperation::Compare => subtract(accumulator, operand, false),
    }
}

pub(crate) fn rotate_shift(
    operation: CbOperation,
    value: u8,
    carry_in: bool,
    zero_from_result: bool,
) -> Option<ByteResult> {
    let (result, carry) = match operation {
        CbOperation::RotateLeftCircular => (value.rotate_left(1), value & 0x80 != 0),
        CbOperation::RotateRightCircular => (value.rotate_right(1), value & 0x01 != 0),
        CbOperation::RotateLeft => ((value << 1) | u8::from(carry_in), value & 0x80 != 0),
        CbOperation::RotateRight => ((value >> 1) | (u8::from(carry_in) << 7), value & 0x01 != 0),
        CbOperation::ShiftLeftArithmetic => (value << 1, value & 0x80 != 0),
        CbOperation::ShiftRightArithmetic => ((value >> 1) | (value & 0x80), value & 1 != 0),
        CbOperation::SwapNibbles => (value.rotate_left(4), false),
        CbOperation::ShiftRightLogical => (value >> 1, value & 1 != 0),
        CbOperation::TestBit(_) | CbOperation::ResetBit(_) | CbOperation::SetBit(_) => return None,
    };
    Some(ByteResult {
        value: result,
        flags: Flags::from_bits(zero_from_result && result == 0, false, false, carry),
    })
}

pub(crate) fn decimal_adjust(accumulator: u8, before: Flags) -> ByteResult {
    let mut correction = 0_u8;
    let carry = if before.subtract() {
        if before.carry() {
            correction |= 0x60;
        }
        if before.half_carry() {
            correction |= 0x06;
        }
        before.carry()
    } else {
        let carry = before.carry() || accumulator > 0x99;
        if carry {
            correction |= 0x60;
        }
        if before.half_carry() || accumulator & 0x0f > 0x09 {
            correction |= 0x06;
        }
        carry
    };
    let value = if before.subtract() {
        accumulator.wrapping_sub(correction)
    } else {
        accumulator.wrapping_add(correction)
    };
    ByteResult {
        value,
        flags: Flags::from_bits(value == 0, before.subtract(), false, carry),
    }
}

fn add(left: u8, right: u8, carry_in: bool) -> ByteResult {
    let carry_byte = u8::from(carry_in);
    let (partial, first_carry) = left.overflowing_add(right);
    let (value, second_carry) = partial.overflowing_add(carry_byte);
    let half_carry =
        u16::from(left & 0x0f) + u16::from(right & 0x0f) + u16::from(carry_byte) > 0x0f;
    ByteResult {
        value,
        flags: Flags::from_bits(value == 0, false, half_carry, first_carry || second_carry),
    }
}

fn subtract(left: u8, right: u8, carry_in: bool) -> ByteResult {
    let carry_byte = u8::from(carry_in);
    let (partial, first_borrow) = left.overflowing_sub(right);
    let (value, second_borrow) = partial.overflowing_sub(carry_byte);
    let half_borrow = u16::from(left & 0x0f) < u16::from(right & 0x0f) + u16::from(carry_byte);
    ByteResult {
        value,
        flags: Flags::from_bits(value == 0, true, half_borrow, first_borrow || second_borrow),
    }
}

fn logical(value: u8, half_carry: bool) -> ByteResult {
    ByteResult {
        value,
        flags: Flags::from_bits(value == 0, false, half_carry, false),
    }
}
