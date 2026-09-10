//! Instruction semantics over the exact bus executor.

use zksm83_isa::{
    AluOperation, CbOperation, Condition, DecodedInstruction, IndirectAddress, InstructionClass,
    Operand8, Operation, Register8, Register16, StackRegister16, TransferDirection,
};

use crate::{Flags, ImeState, RunState, StepError, alu, bus::Executor};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ImmediateBytes {
    first: Option<u8>,
    second: Option<u8>,
}

impl ImmediateBytes {
    pub(crate) fn push(&mut self, value: u8) -> Result<(), StepError> {
        if self.first.is_none() {
            self.first = Some(value);
            return Ok(());
        }
        if self.second.is_none() {
            self.second = Some(value);
            return Ok(());
        }
        Err(StepError::InstructionMetadataInvariant)
    }

    pub(crate) fn byte(self) -> Result<u8, StepError> {
        self.first.ok_or(StepError::MissingImmediateByte)
    }

    pub(crate) fn word(self) -> Result<u16, StepError> {
        let low = self.first.ok_or(StepError::MissingImmediateByte)?;
        let high = self.second.ok_or(StepError::MissingImmediateByte)?;
        Ok(u16::from_le_bytes([low, high]))
    }
}

pub(crate) fn execute(
    executor: &mut Executor,
    instruction: DecodedInstruction,
    immediate: ImmediateBytes,
) -> Result<bool, StepError> {
    let operation = instruction.operation();
    match instruction.class() {
        InstructionClass::Control => execute_control(executor, operation),
        InstructionClass::Load => execute_load(executor, operation, immediate),
        InstructionClass::Alu8 => execute_alu8(executor, operation, immediate),
        InstructionClass::Alu16 => execute_alu16(executor, operation, immediate),
        InstructionClass::RotateShift => execute_rotate(executor, operation, immediate),
        InstructionClass::Bit => execute_bit(executor, operation, immediate),
        InstructionClass::Jump => execute_jump(executor, operation, immediate),
        InstructionClass::CallReturn => execute_call_return(executor, operation, immediate),
        InstructionClass::Stack => execute_stack(executor, operation),
        InstructionClass::Interrupt => execute_interrupt(executor, operation),
        InstructionClass::LowPower => execute_low_power(executor, operation, immediate),
        InstructionClass::Prefix => Err(StepError::UndispatchedCbPrefix),
    }
}

fn execute_control(executor: &mut Executor, operation: Operation) -> Result<bool, StepError> {
    let cpu = executor.state_mut().cpu_mut();
    match operation {
        Operation::Nop => {}
        Operation::DecimalAdjust => {
            let result = alu::decimal_adjust(cpu.registers().a, cpu.flags());
            cpu.registers_mut().a = result.value;
            cpu.set_flags(result.flags);
        }
        Operation::ComplementAccumulator => {
            let accumulator = cpu.registers().a;
            cpu.registers_mut().a = !accumulator;
            let flags = cpu.flags();
            cpu.set_flags(Flags::from_bits(flags.zero(), true, true, flags.carry()));
        }
        Operation::SetCarry => {
            let flags = cpu.flags();
            cpu.set_flags(Flags::from_bits(flags.zero(), false, false, true));
        }
        Operation::ComplementCarry => {
            let flags = cpu.flags();
            cpu.set_flags(Flags::from_bits(flags.zero(), false, false, !flags.carry()));
        }
        _ => return Err(StepError::InstructionMetadataInvariant),
    }
    Ok(false)
}

fn execute_load(
    executor: &mut Executor,
    operation: Operation,
    immediate: ImmediateBytes,
) -> Result<bool, StepError> {
    match operation {
        Operation::StoreSpAbsolute => store_sp_absolute(executor, immediate.word()?)?,
        Operation::Load16Immediate(register) => {
            set_register16(executor, register, immediate.word()?);
        }
        Operation::LoadAccumulatorIndirect(address, direction) => {
            let target = indirect_address(executor, address);
            transfer_accumulator(executor, target, direction)?;
            update_hl_after_indirect(executor, address);
        }
        Operation::Load8Immediate(target) => {
            write_operand(executor, target, immediate, immediate.byte()?)?;
        }
        Operation::Load8(destination, source) => {
            let value = read_operand(executor, source, immediate)?;
            write_operand(executor, destination, immediate, value)?;
        }
        Operation::HighImmediateLoad(direction) => {
            let address = 0xff00 | u16::from(immediate.byte()?);
            transfer_accumulator(executor, address, direction)?;
        }
        Operation::LoadHlSpOffset => {
            let (value, flags) =
                alu::add_signed_to_sp(executor.state().cpu().sp(), immediate.byte()?);
            set_register16(executor, Register16::Hl, value);
            executor.state_mut().cpu_mut().set_flags(flags);
        }
        Operation::LoadSpHl => {
            let value = register16(executor, Register16::Hl);
            executor.state_mut().cpu_mut().set_sp(value);
        }
        Operation::HighCLoad(direction) => {
            let address = 0xff00 | u16::from(executor.state().cpu().registers().c);
            transfer_accumulator(executor, address, direction)?;
        }
        Operation::AbsoluteAccumulatorLoad(direction) => {
            transfer_accumulator(executor, immediate.word()?, direction)?;
        }
        _ => return Err(StepError::InstructionMetadataInvariant),
    }
    Ok(false)
}

fn execute_alu8(
    executor: &mut Executor,
    operation: Operation,
    immediate: ImmediateBytes,
) -> Result<bool, StepError> {
    match operation {
        Operation::Increment8(target) => {
            let before = read_operand(executor, target, immediate)?;
            let result = alu::increment(before, executor.state().cpu().flags());
            write_operand(executor, target, immediate, result.value)?;
            executor.state_mut().cpu_mut().set_flags(result.flags);
        }
        Operation::Decrement8(target) => {
            let before = read_operand(executor, target, immediate)?;
            let result = alu::decrement(before, executor.state().cpu().flags());
            write_operand(executor, target, immediate, result.value)?;
            executor.state_mut().cpu_mut().set_flags(result.flags);
        }
        Operation::Alu8(alu_operation, source) => {
            let operand = read_operand(executor, source, immediate)?;
            let accumulator = executor.state().cpu().registers().a;
            let result = alu::apply_alu(
                alu_operation,
                accumulator,
                operand,
                executor.state().cpu().flags(),
            );
            if alu_operation != AluOperation::Compare {
                executor.state_mut().cpu_mut().registers_mut().a = result.value;
            }
            executor.state_mut().cpu_mut().set_flags(result.flags);
        }
        _ => return Err(StepError::InstructionMetadataInvariant),
    }
    Ok(false)
}

fn execute_alu16(
    executor: &mut Executor,
    operation: Operation,
    immediate: ImmediateBytes,
) -> Result<bool, StepError> {
    match operation {
        Operation::AddHl(source) => {
            let left = register16(executor, Register16::Hl);
            let right = register16(executor, source);
            let (value, flags) = alu::add_hl(left, right, executor.state().cpu().flags());
            set_register16(executor, Register16::Hl, value);
            executor.state_mut().cpu_mut().set_flags(flags);
        }
        Operation::Increment16(target) => {
            let value = register16(executor, target).wrapping_add(1);
            set_register16(executor, target, value);
        }
        Operation::Decrement16(target) => {
            let value = register16(executor, target).wrapping_sub(1);
            set_register16(executor, target, value);
        }
        Operation::AddSpOffset => {
            let (value, flags) =
                alu::add_signed_to_sp(executor.state().cpu().sp(), immediate.byte()?);
            executor.state_mut().cpu_mut().set_sp(value);
            executor.state_mut().cpu_mut().set_flags(flags);
        }
        _ => return Err(StepError::InstructionMetadataInvariant),
    }
    Ok(false)
}

fn execute_rotate(
    executor: &mut Executor,
    operation: Operation,
    immediate: ImmediateBytes,
) -> Result<bool, StepError> {
    match operation {
        Operation::RotateAccumulator(rotate) => {
            let cpu = executor.state().cpu();
            let result = alu::rotate_shift(rotate, cpu.registers().a, cpu.flags().carry(), false)
                .ok_or(StepError::InstructionMetadataInvariant)?;
            executor.state_mut().cpu_mut().registers_mut().a = result.value;
            executor.state_mut().cpu_mut().set_flags(result.flags);
        }
        Operation::Cb(rotate, target) => {
            let before = read_operand(executor, target, immediate)?;
            let result =
                alu::rotate_shift(rotate, before, executor.state().cpu().flags().carry(), true)
                    .ok_or(StepError::InstructionMetadataInvariant)?;
            write_operand(executor, target, immediate, result.value)?;
            executor.state_mut().cpu_mut().set_flags(result.flags);
        }
        _ => return Err(StepError::InstructionMetadataInvariant),
    }
    Ok(false)
}

fn execute_bit(
    executor: &mut Executor,
    operation: Operation,
    immediate: ImmediateBytes,
) -> Result<bool, StepError> {
    let Operation::Cb(cb, target) = operation else {
        return Err(StepError::InstructionMetadataInvariant);
    };
    let value = read_operand(executor, target, immediate)?;
    match cb {
        CbOperation::TestBit(bit) => {
            let mask = bit_mask(bit)?;
            let carry = executor.state().cpu().flags().carry();
            executor.state_mut().cpu_mut().set_flags(Flags::from_bits(
                value & mask == 0,
                false,
                true,
                carry,
            ));
        }
        CbOperation::ResetBit(bit) => {
            write_operand(executor, target, immediate, value & !bit_mask(bit)?)?;
        }
        CbOperation::SetBit(bit) => {
            write_operand(executor, target, immediate, value | bit_mask(bit)?)?;
        }
        _ => return Err(StepError::InstructionMetadataInvariant),
    }
    Ok(false)
}

fn execute_jump(
    executor: &mut Executor,
    operation: Operation,
    immediate: ImmediateBytes,
) -> Result<bool, StepError> {
    match operation {
        Operation::RelativeJump(condition) => {
            let taken = condition.is_none_or(|predicate| condition_holds(executor, predicate));
            if taken {
                let offset = i8::from_ne_bytes([immediate.byte()?]);
                let pc = executor
                    .state()
                    .cpu()
                    .pc()
                    .wrapping_add_signed(i16::from(offset));
                executor.state_mut().cpu_mut().set_pc(pc);
            }
            Ok(taken)
        }
        Operation::JumpHl => {
            let target = register16(executor, Register16::Hl);
            executor.state_mut().cpu_mut().set_pc(target);
            Ok(true)
        }
        Operation::Jump(condition) => {
            let taken = condition.is_none_or(|predicate| condition_holds(executor, predicate));
            if taken {
                executor.state_mut().cpu_mut().set_pc(immediate.word()?);
            }
            Ok(taken)
        }
        _ => Err(StepError::InstructionMetadataInvariant),
    }
}

fn execute_call_return(
    executor: &mut Executor,
    operation: Operation,
    immediate: ImmediateBytes,
) -> Result<bool, StepError> {
    match operation {
        Operation::Return(condition) => {
            let taken = condition.is_none_or(|predicate| condition_holds(executor, predicate));
            if taken {
                let target = pop_word(executor)?;
                executor.state_mut().cpu_mut().set_pc(target);
            }
            Ok(taken)
        }
        Operation::ReturnFromInterrupt => {
            let target = pop_word(executor)?;
            executor.state_mut().cpu_mut().set_pc(target);
            executor.state_mut().cpu_mut().set_ime(ImeState::Enabled);
            Ok(true)
        }
        Operation::Call(condition) => {
            let taken = condition.is_none_or(|predicate| condition_holds(executor, predicate));
            if taken {
                let return_address = executor.state().cpu().pc();
                push_word(executor, return_address)?;
                executor.state_mut().cpu_mut().set_pc(immediate.word()?);
            }
            Ok(taken)
        }
        Operation::Restart(vector) => {
            let return_address = executor.state().cpu().pc();
            push_word(executor, return_address)?;
            executor.state_mut().cpu_mut().set_pc(u16::from(vector));
            Ok(true)
        }
        _ => Err(StepError::InstructionMetadataInvariant),
    }
}

fn execute_stack(executor: &mut Executor, operation: Operation) -> Result<bool, StepError> {
    match operation {
        Operation::Pop(register) => {
            let value = pop_word(executor)?;
            set_stack_register(executor, register, value)?;
        }
        Operation::Push(register) => {
            let value = stack_register(executor, register);
            push_word(executor, value)?;
        }
        _ => return Err(StepError::InstructionMetadataInvariant),
    }
    Ok(false)
}

fn execute_interrupt(executor: &mut Executor, operation: Operation) -> Result<bool, StepError> {
    let ime = match operation {
        Operation::DisableInterrupts => ImeState::Disabled,
        Operation::EnableInterrupts => ImeState::EnablePending,
        _ => return Err(StepError::InstructionMetadataInvariant),
    };
    executor.state_mut().cpu_mut().set_ime(ime);
    Ok(false)
}

fn execute_low_power(
    executor: &mut Executor,
    operation: Operation,
    immediate: ImmediateBytes,
) -> Result<bool, StepError> {
    let run_state = match operation {
        Operation::Halt => RunState::Halted,
        Operation::Stop => {
            let padding = immediate.byte()?;
            if padding != 0 {
                return Err(StepError::InvalidStopPadding { value: padding });
            }
            RunState::Stopped
        }
        _ => return Err(StepError::InstructionMetadataInvariant),
    };
    executor.state_mut().cpu_mut().set_run_state(run_state);
    Ok(false)
}

fn read_operand(
    executor: &mut Executor,
    operand: Operand8,
    immediate: ImmediateBytes,
) -> Result<u8, StepError> {
    match operand {
        Operand8::Register(register) => Ok(register8(executor, register)),
        Operand8::Immediate => immediate.byte(),
        Operand8::IndirectHl => {
            let address = register16(executor, Register16::Hl);
            executor.read_data(address)
        }
    }
}

fn write_operand(
    executor: &mut Executor,
    operand: Operand8,
    _immediate: ImmediateBytes,
    value: u8,
) -> Result<(), StepError> {
    match operand {
        Operand8::Register(register) => {
            set_register8(executor, register, value);
            Ok(())
        }
        Operand8::Immediate => Err(StepError::InstructionMetadataInvariant),
        Operand8::IndirectHl => {
            let address = register16(executor, Register16::Hl);
            executor.write_data(address, value)
        }
    }
}

fn transfer_accumulator(
    executor: &mut Executor,
    address: u16,
    direction: TransferDirection,
) -> Result<(), StepError> {
    match direction {
        TransferDirection::IntoAccumulator => {
            let value = executor.read_data(address)?;
            executor.state_mut().cpu_mut().registers_mut().a = value;
            Ok(())
        }
        TransferDirection::FromAccumulator => {
            executor.write_data(address, executor.state().cpu().registers().a)
        }
    }
}

fn store_sp_absolute(executor: &mut Executor, address: u16) -> Result<(), StepError> {
    let [low, high] = executor.state().cpu().sp().to_le_bytes();
    executor.write_data(address, low)?;
    executor.write_data(address.wrapping_add(1), high)
}

fn push_word(executor: &mut Executor, value: u16) -> Result<(), StepError> {
    let [high, low] = value.to_be_bytes();
    let high_address = executor.state().cpu().sp().wrapping_sub(1);
    executor.write_data(high_address, high)?;
    executor.state_mut().cpu_mut().set_sp(high_address);
    let low_address = high_address.wrapping_sub(1);
    executor.write_data(low_address, low)?;
    executor.state_mut().cpu_mut().set_sp(low_address);
    Ok(())
}

fn pop_word(executor: &mut Executor) -> Result<u16, StepError> {
    let low_address = executor.state().cpu().sp();
    let low = executor.read_data(low_address)?;
    let high_address = low_address.wrapping_add(1);
    let high = executor.read_data(high_address)?;
    executor
        .state_mut()
        .cpu_mut()
        .set_sp(high_address.wrapping_add(1));
    Ok(u16::from_le_bytes([low, high]))
}

fn indirect_address(executor: &Executor, address: IndirectAddress) -> u16 {
    match address {
        IndirectAddress::Bc => register16(executor, Register16::Bc),
        IndirectAddress::De => register16(executor, Register16::De),
        IndirectAddress::HlIncrement | IndirectAddress::HlDecrement => {
            register16(executor, Register16::Hl)
        }
    }
}

fn update_hl_after_indirect(executor: &mut Executor, address: IndirectAddress) {
    let current = register16(executor, Register16::Hl);
    match address {
        IndirectAddress::HlIncrement => {
            set_register16(executor, Register16::Hl, current.wrapping_add(1));
        }
        IndirectAddress::HlDecrement => {
            set_register16(executor, Register16::Hl, current.wrapping_sub(1));
        }
        IndirectAddress::Bc | IndirectAddress::De => {}
    }
}

fn condition_holds(executor: &Executor, condition: Condition) -> bool {
    let flags = executor.state().cpu().flags();
    match condition {
        Condition::NotZero => !flags.zero(),
        Condition::Zero => flags.zero(),
        Condition::NotCarry => !flags.carry(),
        Condition::Carry => flags.carry(),
    }
}

fn register8(executor: &Executor, register: Register8) -> u8 {
    let registers = executor.state().cpu().registers();
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

fn set_register8(executor: &mut Executor, register: Register8, value: u8) {
    let registers = executor.state_mut().cpu_mut().registers_mut();
    match register {
        Register8::A => registers.a = value,
        Register8::B => registers.b = value,
        Register8::C => registers.c = value,
        Register8::D => registers.d = value,
        Register8::E => registers.e = value,
        Register8::H => registers.h = value,
        Register8::L => registers.l = value,
    }
}

fn register16(executor: &Executor, register: Register16) -> u16 {
    let cpu = executor.state().cpu();
    let registers = cpu.registers();
    match register {
        Register16::Bc => u16::from_be_bytes([registers.b, registers.c]),
        Register16::De => u16::from_be_bytes([registers.d, registers.e]),
        Register16::Hl => u16::from_be_bytes([registers.h, registers.l]),
        Register16::Sp => cpu.sp(),
    }
}

fn set_register16(executor: &mut Executor, register: Register16, value: u16) {
    let [high, low] = value.to_be_bytes();
    let cpu = executor.state_mut().cpu_mut();
    match register {
        Register16::Bc => {
            cpu.registers_mut().b = high;
            cpu.registers_mut().c = low;
        }
        Register16::De => {
            cpu.registers_mut().d = high;
            cpu.registers_mut().e = low;
        }
        Register16::Hl => {
            cpu.registers_mut().h = high;
            cpu.registers_mut().l = low;
        }
        Register16::Sp => cpu.set_sp(value),
    }
}

fn stack_register(executor: &Executor, register: StackRegister16) -> u16 {
    match register {
        StackRegister16::Bc => register16(executor, Register16::Bc),
        StackRegister16::De => register16(executor, Register16::De),
        StackRegister16::Hl => register16(executor, Register16::Hl),
        StackRegister16::Af => u16::from_be_bytes([
            executor.state().cpu().registers().a,
            executor.state().cpu().flags().byte(),
        ]),
    }
}

fn set_stack_register(
    executor: &mut Executor,
    register: StackRegister16,
    value: u16,
) -> Result<(), StepError> {
    match register {
        StackRegister16::Bc => set_register16(executor, Register16::Bc, value),
        StackRegister16::De => set_register16(executor, Register16::De, value),
        StackRegister16::Hl => set_register16(executor, Register16::Hl, value),
        StackRegister16::Af => {
            let [accumulator, flags] = value.to_be_bytes();
            executor.state_mut().cpu_mut().registers_mut().a = accumulator;
            executor
                .state_mut()
                .cpu_mut()
                .set_flags(Flags::from_byte(flags & 0xf0)?);
        }
    }
    Ok(())
}

fn bit_mask(bit: u8) -> Result<u8, StepError> {
    1_u8.checked_shl(u32::from(bit))
        .ok_or(StepError::InstructionMetadataInvariant)
}
