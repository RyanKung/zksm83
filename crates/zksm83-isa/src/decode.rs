//! Total algorithmic SM83 opcode tables.

use crate::{
    AluOperation, CbOpcode, CbOperation, Condition, DecodedInstruction, IndirectAddress,
    InstructionEncoding, Opcode, OpcodeClassification, Operand8, Operation, Register8, Register16,
    StackRegister16, TransferDirection, UndefinedOpcode,
};

/// Complete primary and CB opcode table facade.
#[derive(Clone, Copy, Debug, Default)]
pub struct CompleteOpcodeTable;

/// The complete SM83 opcode table.
pub const OPCODE_TABLE: CompleteOpcodeTable = CompleteOpcodeTable;

impl CompleteOpcodeTable {
    /// Classifies one primary byte, including every undefined encoding.
    #[must_use]
    pub fn primary(self, byte: u8) -> OpcodeClassification {
        decode_primary(byte)
    }

    /// Decodes one of the 256 defined CB secondary bytes.
    #[must_use]
    pub fn cb(self, byte: u8) -> DecodedInstruction {
        decode_cb(byte)
    }

    /// Iterates over all 256 primary classifications in byte order.
    pub fn primary_entries(self) -> impl ExactSizeIterator<Item = OpcodeClassification> {
        (u8::MIN..=u8::MAX).map(decode_primary)
    }

    /// Iterates over all 256 CB instructions in secondary-byte order.
    pub fn cb_entries(self) -> impl ExactSizeIterator<Item = DecodedInstruction> {
        (u8::MIN..=u8::MAX).map(decode_cb)
    }
}

/// Classifies and decodes a primary opcode byte.
#[must_use]
pub fn decode_primary(byte: u8) -> OpcodeClassification {
    if is_undefined(byte) {
        return OpcodeClassification::Undefined(UndefinedOpcode { byte });
    }
    let opcode = Opcode(byte);
    OpcodeClassification::Defined(decode_defined_primary(opcode))
}

/// Decodes one of the 256 defined CB-prefixed secondary bytes.
#[must_use]
pub fn decode_cb(byte: u8) -> DecodedInstruction {
    let opcode = CbOpcode::new(byte);
    let x = byte >> 6;
    let y = (byte >> 3) & 0x07;
    let z = byte & 0x07;
    let target = operand8(z);
    let operation = match x {
        0 => cb_rotate(y),
        1 => CbOperation::TestBit(y),
        2 => CbOperation::ResetBit(y),
        _ => CbOperation::SetBit(y),
    };
    let m_cycles = match (x, target) {
        (1, Operand8::IndirectHl) => 3,
        (_, Operand8::IndirectHl) => 4,
        _ => 2,
    };
    crate::metadata::instruction(
        InstructionEncoding::Cb(opcode),
        Operation::Cb(operation, target),
        2,
        m_cycles,
        None,
    )
}

fn decode_defined_primary(opcode: Opcode) -> DecodedInstruction {
    let byte = opcode.byte();
    let x = byte >> 6;
    let y = (byte >> 3) & 0x07;
    let z = byte & 0x07;
    let p = y >> 1;
    let q = y & 0x01;
    let (operation, byte_len, base, taken) = match x {
        0 => decode_block_zero(y, z, p, q),
        1 => decode_block_one(y, z),
        2 => decode_block_two(y, z),
        _ => decode_block_three(y, z, p, q),
    };
    crate::metadata::instruction(
        InstructionEncoding::Primary(opcode),
        operation,
        byte_len,
        base,
        taken,
    )
}

fn decode_block_zero(y: u8, z: u8, p: u8, q: u8) -> (Operation, u8, u8, Option<u8>) {
    match z {
        0 => match y {
            0 => tuple(Operation::Nop, 1, 1),
            1 => tuple(Operation::StoreSpAbsolute, 3, 5),
            2 => tuple(Operation::Stop, 2, 1),
            3 => tuple(Operation::RelativeJump(None), 2, 3),
            _ => conditional(Operation::RelativeJump(Some(condition(y - 4))), 2, 2, 3),
        },
        1 => {
            if q == 0 {
                tuple(Operation::Load16Immediate(register16(p)), 3, 3)
            } else {
                tuple(Operation::AddHl(register16(p)), 1, 2)
            }
        }
        2 => tuple(indirect_accumulator(y), 1, 2),
        3 => {
            if q == 0 {
                tuple(Operation::Increment16(register16(p)), 1, 2)
            } else {
                tuple(Operation::Decrement16(register16(p)), 1, 2)
            }
        }
        4 => tuple(
            Operation::Increment8(operand8(y)),
            1,
            if y == 6 { 3 } else { 1 },
        ),
        5 => tuple(
            Operation::Decrement8(operand8(y)),
            1,
            if y == 6 { 3 } else { 1 },
        ),
        6 => tuple(
            Operation::Load8Immediate(operand8(y)),
            2,
            if y == 6 { 3 } else { 2 },
        ),
        _ => tuple(block_zero_misc(y), 1, 1),
    }
}

fn decode_block_one(y: u8, z: u8) -> (Operation, u8, u8, Option<u8>) {
    if y == 6 && z == 6 {
        tuple(Operation::Halt, 1, 1)
    } else {
        tuple(
            Operation::Load8(operand8(y), operand8(z)),
            1,
            if y == 6 || z == 6 { 2 } else { 1 },
        )
    }
}

fn decode_block_two(y: u8, z: u8) -> (Operation, u8, u8, Option<u8>) {
    tuple(
        Operation::Alu8(alu_operation(y), operand8(z)),
        1,
        if z == 6 { 2 } else { 1 },
    )
}

fn decode_block_three(y: u8, z: u8, p: u8, q: u8) -> (Operation, u8, u8, Option<u8>) {
    match z {
        0 => match y {
            0..=3 => conditional(Operation::Return(Some(condition(y))), 1, 2, 5),
            4 => tuple(
                Operation::HighImmediateLoad(TransferDirection::FromAccumulator),
                2,
                3,
            ),
            5 => tuple(Operation::AddSpOffset, 2, 4),
            6 => tuple(
                Operation::HighImmediateLoad(TransferDirection::IntoAccumulator),
                2,
                3,
            ),
            _ => tuple(Operation::LoadHlSpOffset, 2, 3),
        },
        1 => decode_block_three_z_one(p, q),
        2 => match y {
            0..=3 => conditional(Operation::Jump(Some(condition(y))), 3, 3, 4),
            4 => tuple(
                Operation::HighCLoad(TransferDirection::FromAccumulator),
                1,
                2,
            ),
            5 => tuple(
                Operation::AbsoluteAccumulatorLoad(TransferDirection::FromAccumulator),
                3,
                4,
            ),
            6 => tuple(
                Operation::HighCLoad(TransferDirection::IntoAccumulator),
                1,
                2,
            ),
            _ => tuple(
                Operation::AbsoluteAccumulatorLoad(TransferDirection::IntoAccumulator),
                3,
                4,
            ),
        },
        3 => match y {
            0 => tuple(Operation::Jump(None), 3, 4),
            1 => tuple(Operation::PrefixCb, 1, 1),
            6 => tuple(Operation::DisableInterrupts, 1, 1),
            _ => tuple(Operation::EnableInterrupts, 1, 1),
        },
        4 => conditional(Operation::Call(Some(condition(y))), 3, 3, 6),
        5 => {
            if q == 0 {
                tuple(Operation::Push(stack_register16(p)), 1, 4)
            } else {
                tuple(Operation::Call(None), 3, 6)
            }
        }
        6 => tuple(Operation::Alu8(alu_operation(y), Operand8::Immediate), 2, 2),
        _ => tuple(Operation::Restart(y << 3), 1, 4),
    }
}

fn decode_block_three_z_one(p: u8, q: u8) -> (Operation, u8, u8, Option<u8>) {
    if q == 0 {
        return tuple(Operation::Pop(stack_register16(p)), 1, 3);
    }
    match p {
        0 => tuple(Operation::Return(None), 1, 4),
        1 => tuple(Operation::ReturnFromInterrupt, 1, 4),
        2 => tuple(Operation::JumpHl, 1, 1),
        _ => tuple(Operation::LoadSpHl, 1, 2),
    }
}

fn indirect_accumulator(y: u8) -> Operation {
    let address = match y >> 1 {
        0 => IndirectAddress::Bc,
        1 => IndirectAddress::De,
        2 => IndirectAddress::HlIncrement,
        _ => IndirectAddress::HlDecrement,
    };
    let direction = if y & 1 == 0 {
        TransferDirection::FromAccumulator
    } else {
        TransferDirection::IntoAccumulator
    };
    Operation::LoadAccumulatorIndirect(address, direction)
}

fn block_zero_misc(y: u8) -> Operation {
    match y {
        0 => Operation::RotateAccumulator(CbOperation::RotateLeftCircular),
        1 => Operation::RotateAccumulator(CbOperation::RotateRightCircular),
        2 => Operation::RotateAccumulator(CbOperation::RotateLeft),
        3 => Operation::RotateAccumulator(CbOperation::RotateRight),
        4 => Operation::DecimalAdjust,
        5 => Operation::ComplementAccumulator,
        6 => Operation::SetCarry,
        _ => Operation::ComplementCarry,
    }
}

fn operand8(code: u8) -> Operand8 {
    let register = match code {
        0 => Some(Register8::B),
        1 => Some(Register8::C),
        2 => Some(Register8::D),
        3 => Some(Register8::E),
        4 => Some(Register8::H),
        5 => Some(Register8::L),
        6 => None,
        _ => Some(Register8::A),
    };
    register.map_or(Operand8::IndirectHl, Operand8::Register)
}

fn register16(code: u8) -> Register16 {
    match code {
        0 => Register16::Bc,
        1 => Register16::De,
        2 => Register16::Hl,
        _ => Register16::Sp,
    }
}

fn stack_register16(code: u8) -> StackRegister16 {
    match code {
        0 => StackRegister16::Bc,
        1 => StackRegister16::De,
        2 => StackRegister16::Hl,
        _ => StackRegister16::Af,
    }
}

fn condition(code: u8) -> Condition {
    match code {
        0 => Condition::NotZero,
        1 => Condition::Zero,
        2 => Condition::NotCarry,
        _ => Condition::Carry,
    }
}

fn alu_operation(code: u8) -> AluOperation {
    match code {
        0 => AluOperation::Add,
        1 => AluOperation::AddCarry,
        2 => AluOperation::Subtract,
        3 => AluOperation::SubtractCarry,
        4 => AluOperation::And,
        5 => AluOperation::Xor,
        6 => AluOperation::Or,
        _ => AluOperation::Compare,
    }
}

fn cb_rotate(code: u8) -> CbOperation {
    match code {
        0 => CbOperation::RotateLeftCircular,
        1 => CbOperation::RotateRightCircular,
        2 => CbOperation::RotateLeft,
        3 => CbOperation::RotateRight,
        4 => CbOperation::ShiftLeftArithmetic,
        5 => CbOperation::ShiftRightArithmetic,
        6 => CbOperation::SwapNibbles,
        _ => CbOperation::ShiftRightLogical,
    }
}

fn tuple(operation: Operation, byte_len: u8, m_cycles: u8) -> (Operation, u8, u8, Option<u8>) {
    (operation, byte_len, m_cycles, None)
}

fn conditional(
    operation: Operation,
    byte_len: u8,
    base_m_cycles: u8,
    taken_m_cycles: u8,
) -> (Operation, u8, u8, Option<u8>) {
    (operation, byte_len, base_m_cycles, Some(taken_m_cycles))
}

const fn is_undefined(byte: u8) -> bool {
    matches!(
        byte,
        0xd3 | 0xdb | 0xdd | 0xe3 | 0xe4 | 0xeb | 0xec | 0xed | 0xf4 | 0xfc | 0xfd
    )
}
