//! Metadata derived from the typed semantic operation.

use crate::{
    AluOperation, BusAccessPattern, CbOperation, DecodedInstruction, FlagAction, FlagEffect,
    InstructionClass, InstructionEncoding, Operand8, Operation, Register8, Register16,
    StackRegister16, StateAccess, StateComponent, Timing, TransferDirection,
};

pub(crate) fn instruction(
    encoding: InstructionEncoding,
    operation: Operation,
    byte_len: u8,
    base_m_cycles: u8,
    taken_m_cycles: Option<u8>,
) -> DecodedInstruction {
    DecodedInstruction {
        encoding,
        class: class(operation),
        operation,
        byte_len,
        timing: Timing::new(base_m_cycles, taken_m_cycles),
        flags: flag_effect(operation),
        state_access: state_access(operation),
        bus: bus_pattern(encoding, operation, byte_len),
    }
}

fn class(operation: Operation) -> InstructionClass {
    match operation {
        Operation::Nop
        | Operation::DecimalAdjust
        | Operation::ComplementAccumulator
        | Operation::SetCarry
        | Operation::ComplementCarry => InstructionClass::Control,
        Operation::StoreSpAbsolute
        | Operation::Load16Immediate(_)
        | Operation::LoadAccumulatorIndirect(_, _)
        | Operation::Load8Immediate(_)
        | Operation::Load8(_, _)
        | Operation::HighImmediateLoad(_)
        | Operation::LoadHlSpOffset
        | Operation::LoadSpHl
        | Operation::HighCLoad(_)
        | Operation::AbsoluteAccumulatorLoad(_) => InstructionClass::Load,
        Operation::Increment8(_) | Operation::Decrement8(_) | Operation::Alu8(_, _) => {
            InstructionClass::Alu8
        }
        Operation::AddHl(_)
        | Operation::Increment16(_)
        | Operation::Decrement16(_)
        | Operation::AddSpOffset => InstructionClass::Alu16,
        Operation::RotateAccumulator(_) => InstructionClass::RotateShift,
        Operation::Cb(cb, _) => match cb {
            CbOperation::TestBit(_) | CbOperation::ResetBit(_) | CbOperation::SetBit(_) => {
                InstructionClass::Bit
            }
            _ => InstructionClass::RotateShift,
        },
        Operation::RelativeJump(_) | Operation::JumpHl | Operation::Jump(_) => {
            InstructionClass::Jump
        }
        Operation::Return(_)
        | Operation::ReturnFromInterrupt
        | Operation::Call(_)
        | Operation::Restart(_) => InstructionClass::CallReturn,
        Operation::Pop(_) | Operation::Push(_) => InstructionClass::Stack,
        Operation::DisableInterrupts | Operation::EnableInterrupts => InstructionClass::Interrupt,
        Operation::Stop | Operation::Halt => InstructionClass::LowPower,
        Operation::PrefixCb => InstructionClass::Prefix,
    }
}

fn flag_effect(operation: Operation) -> FlagEffect {
    const PRESERVE: FlagEffect = FlagEffect {
        zero: FlagAction::Preserve,
        subtract: FlagAction::Preserve,
        half_carry: FlagAction::Preserve,
        carry: FlagAction::Preserve,
    };
    const INC: FlagEffect = FlagEffect {
        zero: FlagAction::Derived,
        subtract: FlagAction::Clear,
        half_carry: FlagAction::Derived,
        carry: FlagAction::Preserve,
    };
    const DEC: FlagEffect = FlagEffect {
        zero: FlagAction::Derived,
        subtract: FlagAction::Set,
        half_carry: FlagAction::Derived,
        carry: FlagAction::Preserve,
    };
    const ADD_HL: FlagEffect = FlagEffect {
        zero: FlagAction::Preserve,
        subtract: FlagAction::Clear,
        half_carry: FlagAction::Derived,
        carry: FlagAction::Derived,
    };
    const ADD_SP: FlagEffect = FlagEffect {
        zero: FlagAction::Clear,
        subtract: FlagAction::Clear,
        half_carry: FlagAction::Derived,
        carry: FlagAction::Derived,
    };
    const ROTATE_A: FlagEffect = FlagEffect {
        zero: FlagAction::Clear,
        subtract: FlagAction::Clear,
        half_carry: FlagAction::Clear,
        carry: FlagAction::Derived,
    };
    const ROTATE_CB: FlagEffect = FlagEffect {
        zero: FlagAction::Derived,
        subtract: FlagAction::Clear,
        half_carry: FlagAction::Clear,
        carry: FlagAction::Derived,
    };
    const BIT: FlagEffect = FlagEffect {
        zero: FlagAction::Derived,
        subtract: FlagAction::Clear,
        half_carry: FlagAction::Set,
        carry: FlagAction::Preserve,
    };
    match operation {
        Operation::Increment8(_) => INC,
        Operation::Decrement8(_) => DEC,
        Operation::AddHl(_) => ADD_HL,
        Operation::AddSpOffset | Operation::LoadHlSpOffset => ADD_SP,
        Operation::RotateAccumulator(_) => ROTATE_A,
        Operation::DecimalAdjust => FlagEffect {
            zero: FlagAction::Derived,
            subtract: FlagAction::Preserve,
            half_carry: FlagAction::Clear,
            carry: FlagAction::Derived,
        },
        Operation::ComplementAccumulator => FlagEffect {
            zero: FlagAction::Preserve,
            subtract: FlagAction::Set,
            half_carry: FlagAction::Set,
            carry: FlagAction::Preserve,
        },
        Operation::SetCarry => FlagEffect {
            zero: FlagAction::Preserve,
            subtract: FlagAction::Clear,
            half_carry: FlagAction::Clear,
            carry: FlagAction::Set,
        },
        Operation::ComplementCarry => FlagEffect {
            zero: FlagAction::Preserve,
            subtract: FlagAction::Clear,
            half_carry: FlagAction::Clear,
            carry: FlagAction::Derived,
        },
        Operation::Alu8(alu, _) => alu_flags(alu),
        Operation::Cb(cb, _) => match cb {
            CbOperation::TestBit(_) => BIT,
            CbOperation::ResetBit(_) | CbOperation::SetBit(_) => PRESERVE,
            _ => ROTATE_CB,
        },
        Operation::Pop(StackRegister16::Af) => FlagEffect {
            zero: FlagAction::Derived,
            subtract: FlagAction::Derived,
            half_carry: FlagAction::Derived,
            carry: FlagAction::Derived,
        },
        _ => PRESERVE,
    }
}

fn alu_flags(operation: AluOperation) -> FlagEffect {
    match operation {
        AluOperation::Add | AluOperation::AddCarry => FlagEffect {
            zero: FlagAction::Derived,
            subtract: FlagAction::Clear,
            half_carry: FlagAction::Derived,
            carry: FlagAction::Derived,
        },
        AluOperation::Subtract | AluOperation::SubtractCarry | AluOperation::Compare => {
            FlagEffect {
                zero: FlagAction::Derived,
                subtract: FlagAction::Set,
                half_carry: FlagAction::Derived,
                carry: FlagAction::Derived,
            }
        }
        AluOperation::And => FlagEffect {
            zero: FlagAction::Derived,
            subtract: FlagAction::Clear,
            half_carry: FlagAction::Set,
            carry: FlagAction::Clear,
        },
        AluOperation::Xor | AluOperation::Or => FlagEffect {
            zero: FlagAction::Derived,
            subtract: FlagAction::Clear,
            half_carry: FlagAction::Clear,
            carry: FlagAction::Clear,
        },
    }
}

fn bus_pattern(
    encoding: InstructionEncoding,
    operation: Operation,
    byte_len: u8,
) -> BusAccessPattern {
    let opcode_fetches = match encoding {
        InstructionEncoding::Primary(_) => 1,
        InstructionEncoding::Cb(_) => 2,
    };
    let immediate_reads = match encoding {
        InstructionEncoding::Primary(_) => byte_len.saturating_sub(1),
        InstructionEncoding::Cb(_) => 0,
    };
    let (data_reads, data_writes, taken_data_reads, taken_data_writes) = match operation {
        Operation::StoreSpAbsolute => (0, 2, 0, 0),
        Operation::LoadAccumulatorIndirect(_, direction)
        | Operation::HighImmediateLoad(direction)
        | Operation::HighCLoad(direction)
        | Operation::AbsoluteAccumulatorLoad(direction) => direction_bus(direction),
        Operation::Increment8(Operand8::IndirectHl)
        | Operation::Decrement8(Operand8::IndirectHl) => (1, 1, 0, 0),
        Operation::Load8Immediate(Operand8::IndirectHl) => (0, 1, 0, 0),
        Operation::Load8(destination, source) => operand_transfer_bus(destination, source),
        Operation::Alu8(_, Operand8::IndirectHl) => (1, 0, 0, 0),
        Operation::Return(Some(_)) => (0, 0, 2, 0),
        Operation::Return(None) | Operation::ReturnFromInterrupt | Operation::Pop(_) => {
            (2, 0, 0, 0)
        }
        Operation::Call(Some(_)) => (0, 0, 0, 2),
        Operation::Call(None) | Operation::Push(_) | Operation::Restart(_) => (0, 2, 0, 0),
        Operation::Cb(_, Operand8::IndirectHl) => match operation {
            Operation::Cb(CbOperation::TestBit(_), _) => (1, 0, 0, 0),
            _ => (1, 1, 0, 0),
        },
        _ => (0, 0, 0, 0),
    };
    BusAccessPattern::new(
        opcode_fetches,
        immediate_reads,
        data_reads,
        data_writes,
        taken_data_reads,
        taken_data_writes,
    )
}

fn direction_bus(direction: TransferDirection) -> (u8, u8, u8, u8) {
    match direction {
        TransferDirection::IntoAccumulator => (1, 0, 0, 0),
        TransferDirection::FromAccumulator => (0, 1, 0, 0),
    }
}

fn operand_transfer_bus(destination: Operand8, source: Operand8) -> (u8, u8, u8, u8) {
    match (destination, source) {
        (Operand8::IndirectHl, _) => (0, 1, 0, 0),
        (_, Operand8::IndirectHl) => (1, 0, 0, 0),
        _ => (0, 0, 0, 0),
    }
}

fn state_access(operation: Operation) -> StateAccess {
    let mut reads = components(&[
        StateComponent::Pc,
        StateComponent::Ime,
        StateComponent::RunState,
        StateComponent::MCycles,
        StateComponent::F,
    ]);
    let mut writes = components(&[
        StateComponent::Pc,
        StateComponent::Ime,
        StateComponent::MCycles,
    ]);
    add_operation_access(operation, &mut reads, &mut writes);
    let flags = flag_effect(operation);
    if flags != preserve_flags() {
        writes |= StateComponent::F.mask();
    }
    StateAccess::new(reads, writes)
}

fn add_operation_access(operation: Operation, reads: &mut u16, writes: &mut u16) {
    match operation {
        Operation::StoreSpAbsolute => add_read(reads, Register16::Sp),
        Operation::Stop | Operation::Halt => *writes |= StateComponent::RunState.mask(),
        Operation::RelativeJump(condition)
        | Operation::Return(condition)
        | Operation::Jump(condition)
        | Operation::Call(condition) => {
            if condition.is_some() {
                *reads |= StateComponent::F.mask();
            }
            stack_access(operation, reads, writes);
        }
        Operation::Load16Immediate(register)
        | Operation::Increment16(register)
        | Operation::Decrement16(register) => {
            if !matches!(operation, Operation::Load16Immediate(_)) {
                add_read(reads, register);
            }
            add_write(writes, register);
        }
        Operation::AddHl(register) => {
            add_read(reads, Register16::Hl);
            add_read(reads, register);
            add_write(writes, Register16::Hl);
        }
        Operation::LoadAccumulatorIndirect(address, direction) => {
            add_indirect_transfer_access(address, direction, reads, writes);
        }
        Operation::Increment8(operand) | Operation::Decrement8(operand) => {
            add_operand_read(reads, operand);
            add_operand_write(writes, operand);
        }
        Operation::Load8Immediate(operand) => add_destination_access(reads, writes, operand),
        Operation::RotateAccumulator(_)
        | Operation::DecimalAdjust
        | Operation::ComplementAccumulator => {
            *reads |= StateComponent::A.mask();
            *writes |= StateComponent::A.mask();
        }
        Operation::Load8(destination, source) => {
            add_operand_read(reads, source);
            add_destination_access(reads, writes, destination);
        }
        Operation::Alu8(_, operand) => {
            *reads |= StateComponent::A.mask();
            add_operand_read(reads, operand);
            if !matches!(operation, Operation::Alu8(AluOperation::Compare, _)) {
                *writes |= StateComponent::A.mask();
            }
        }
        Operation::HighImmediateLoad(direction)
        | Operation::HighCLoad(direction)
        | Operation::AbsoluteAccumulatorLoad(direction) => {
            if matches!(operation, Operation::HighCLoad(_)) {
                *reads |= StateComponent::C.mask();
            }
            add_transfer_access(direction, reads, writes);
        }
        Operation::AddSpOffset => {
            add_read(reads, Register16::Sp);
            add_write(writes, Register16::Sp);
        }
        Operation::LoadHlSpOffset => {
            add_read(reads, Register16::Sp);
            add_write(writes, Register16::Hl);
        }
        Operation::Pop(register) => {
            *reads |= StateComponent::Sp.mask();
            *writes |= StateComponent::Sp.mask();
            add_stack_write(writes, register);
        }
        Operation::ReturnFromInterrupt => stack_access(operation, reads, writes),
        Operation::JumpHl => add_read(reads, Register16::Hl),
        Operation::LoadSpHl => {
            add_read(reads, Register16::Hl);
            add_write(writes, Register16::Sp);
        }
        Operation::DisableInterrupts | Operation::EnableInterrupts => {
            *writes |= StateComponent::Ime.mask();
        }
        Operation::Push(register) => {
            add_stack_read(reads, register);
            stack_access(operation, reads, writes);
        }
        Operation::Restart(_) => stack_access(operation, reads, writes),
        Operation::Cb(_, operand) => {
            add_operand_read(reads, operand);
            if !matches!(operation, Operation::Cb(CbOperation::TestBit(_), _)) {
                add_operand_write(writes, operand);
            }
        }
        Operation::Nop | Operation::SetCarry | Operation::ComplementCarry | Operation::PrefixCb => {
        }
    }
}

fn add_indirect_transfer_access(
    address: crate::IndirectAddress,
    direction: TransferDirection,
    reads: &mut u16,
    writes: &mut u16,
) {
    add_indirect_read(reads, address);
    add_transfer_access(direction, reads, writes);
    if matches!(
        address,
        crate::IndirectAddress::HlIncrement | crate::IndirectAddress::HlDecrement
    ) {
        add_write(writes, Register16::Hl);
    }
}

fn stack_access(operation: Operation, reads: &mut u16, writes: &mut u16) {
    match operation {
        Operation::Return(_) | Operation::ReturnFromInterrupt => {
            *reads |= StateComponent::Sp.mask();
            *writes |= StateComponent::Sp.mask();
        }
        Operation::Call(_) | Operation::Push(_) | Operation::Restart(_) => {
            *reads |= StateComponent::Sp.mask();
            *writes |= StateComponent::Sp.mask();
        }
        _ => {}
    }
}

fn add_transfer_access(direction: TransferDirection, reads: &mut u16, writes: &mut u16) {
    match direction {
        TransferDirection::IntoAccumulator => *writes |= StateComponent::A.mask(),
        TransferDirection::FromAccumulator => *reads |= StateComponent::A.mask(),
    }
}

fn add_indirect_read(reads: &mut u16, address: crate::IndirectAddress) {
    match address {
        crate::IndirectAddress::Bc => add_read(reads, Register16::Bc),
        crate::IndirectAddress::De => add_read(reads, Register16::De),
        crate::IndirectAddress::HlIncrement | crate::IndirectAddress::HlDecrement => {
            add_read(reads, Register16::Hl);
        }
    }
}

fn add_operand_read(mask: &mut u16, operand: Operand8) {
    match operand {
        Operand8::Register(register) => *mask |= register_component(register).mask(),
        Operand8::Immediate => {}
        Operand8::IndirectHl => add_read(mask, Register16::Hl),
    }
}

fn add_operand_write(mask: &mut u16, operand: Operand8) {
    match operand {
        Operand8::Register(register) => *mask |= register_component(register).mask(),
        Operand8::Immediate => {}
        Operand8::IndirectHl => {}
    }
}

fn add_destination_access(reads: &mut u16, writes: &mut u16, operand: Operand8) {
    if operand == Operand8::IndirectHl {
        add_read(reads, Register16::Hl);
    }
    add_operand_write(writes, operand);
}

fn add_read(mask: &mut u16, register: Register16) {
    *mask |= register_mask(register);
}

fn add_write(mask: &mut u16, register: Register16) {
    *mask |= register_mask(register);
}

fn add_stack_read(mask: &mut u16, register: StackRegister16) {
    *mask |= stack_register_mask(register);
}

fn add_stack_write(mask: &mut u16, register: StackRegister16) {
    *mask |= stack_register_mask(register);
}

fn register_component(register: Register8) -> StateComponent {
    match register {
        Register8::A => StateComponent::A,
        Register8::B => StateComponent::B,
        Register8::C => StateComponent::C,
        Register8::D => StateComponent::D,
        Register8::E => StateComponent::E,
        Register8::H => StateComponent::H,
        Register8::L => StateComponent::L,
    }
}

fn register_mask(register: Register16) -> u16 {
    match register {
        Register16::Bc => StateComponent::B.mask() | StateComponent::C.mask(),
        Register16::De => StateComponent::D.mask() | StateComponent::E.mask(),
        Register16::Hl => StateComponent::H.mask() | StateComponent::L.mask(),
        Register16::Sp => StateComponent::Sp.mask(),
    }
}

fn stack_register_mask(register: StackRegister16) -> u16 {
    match register {
        StackRegister16::Bc => register_mask(Register16::Bc),
        StackRegister16::De => register_mask(Register16::De),
        StackRegister16::Hl => register_mask(Register16::Hl),
        StackRegister16::Af => StateComponent::A.mask() | StateComponent::F.mask(),
    }
}

fn components(values: &[StateComponent]) -> u16 {
    values
        .iter()
        .fold(0, |mask, component| mask | component.mask())
}

const fn preserve_flags() -> FlagEffect {
    FlagEffect {
        zero: FlagAction::Preserve,
        subtract: FlagAction::Preserve,
        half_carry: FlagAction::Preserve,
        carry: FlagAction::Preserve,
    }
}
