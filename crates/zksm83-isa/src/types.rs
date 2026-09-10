//! Typed instruction and metadata values.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A validated defined primary opcode byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Opcode(pub(crate) u8);

impl Opcode {
    /// Returns the encoded primary byte.
    #[must_use]
    pub const fn byte(self) -> u8 {
        self.0
    }
}

/// A CB-prefixed secondary opcode byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CbOpcode(u8);

impl CbOpcode {
    /// Constructs the secondary opcode, all of which are defined.
    #[must_use]
    pub const fn new(byte: u8) -> Self {
        Self(byte)
    }

    /// Returns the encoded secondary byte.
    #[must_use]
    pub const fn byte(self) -> u8 {
        self.0
    }
}

/// A primary byte that the SM83 ISA leaves undefined.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq, Serialize, Deserialize)]
#[error("undefined SM83 primary opcode 0x{byte:02x}")]
pub struct UndefinedOpcode {
    /// Rejected opcode byte.
    pub byte: u8,
}

/// Classification of one of the 256 primary opcode bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum OpcodeClassification {
    /// The byte has a defined instruction relation.
    Defined(DecodedInstruction),
    /// The byte fails closed and has no transition.
    Undefined(UndefinedOpcode),
}

/// Encoding that uniquely identifies a decoded instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum InstructionEncoding {
    /// A one-byte primary opcode, possibly followed by immediate data.
    Primary(Opcode),
    /// A `0xcb` prefix followed by the contained secondary opcode.
    Cb(CbOpcode),
}

/// High-level instruction family used by the proof lookup table.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum InstructionClass {
    /// No state change beyond PC and timing.
    Control,
    /// Byte or word data movement.
    Load,
    /// Eight-bit arithmetic or logic.
    Alu8,
    /// Sixteen-bit arithmetic.
    Alu16,
    /// Rotate or shift operation.
    RotateShift,
    /// Single-bit test or mutation.
    Bit,
    /// Relative or absolute branch.
    Jump,
    /// Subroutine call, return, or restart.
    CallReturn,
    /// Stack push or pop.
    Stack,
    /// Interrupt-master-enable state change.
    Interrupt,
    /// Low-power terminal state change.
    LowPower,
    /// CB prefix dispatch marker in the primary table.
    Prefix,
}

impl InstructionClass {
    /// Returns the stable proof-table code for this instruction class.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Control => 0,
            Self::Load => 1,
            Self::Alu8 => 2,
            Self::Alu16 => 3,
            Self::RotateShift => 4,
            Self::Bit => 5,
            Self::Jump => 6,
            Self::CallReturn => 7,
            Self::Stack => 8,
            Self::Interrupt => 9,
            Self::LowPower => 10,
            Self::Prefix => 11,
        }
    }
}

/// One general-purpose eight-bit register.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Register8 {
    /// Accumulator.
    A,
    /// B register.
    B,
    /// C register.
    C,
    /// D register.
    D,
    /// E register.
    E,
    /// H register.
    H,
    /// L register.
    L,
}

/// One arithmetic or addressing 16-bit register pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Register16 {
    /// BC pair.
    Bc,
    /// DE pair.
    De,
    /// HL pair.
    Hl,
    /// Stack pointer.
    Sp,
}

/// One 16-bit register pair admitted by stack instructions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum StackRegister16 {
    /// BC pair.
    Bc,
    /// DE pair.
    De,
    /// HL pair.
    Hl,
    /// Accumulator and flags pair.
    Af,
}

/// An eight-bit register or the byte addressed by HL.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Operand8 {
    /// A general-purpose register.
    Register(Register8),
    /// Immediate byte following the primary opcode.
    Immediate,
    /// Mutable or profile-owned memory at address HL.
    IndirectHl,
}

/// Address source used by accumulator-indirect loads.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum IndirectAddress {
    /// Address held in BC.
    Bc,
    /// Address held in DE.
    De,
    /// Address held in HL, then increment HL.
    HlIncrement,
    /// Address held in HL, then decrement HL.
    HlDecrement,
}

/// Direction of a load involving memory and the accumulator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TransferDirection {
    /// Read memory into A.
    IntoAccumulator,
    /// Write A to memory.
    FromAccumulator,
}

/// Conditional branch predicate over the current flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Condition {
    /// Zero flag is clear.
    NotZero,
    /// Zero flag is set.
    Zero,
    /// Carry flag is clear.
    NotCarry,
    /// Carry flag is set.
    Carry,
}

/// Eight-bit arithmetic or logical operation selected by an opcode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AluOperation {
    /// Add without carry.
    Add,
    /// Add with carry.
    AddCarry,
    /// Subtract without carry.
    Subtract,
    /// Subtract with carry.
    SubtractCarry,
    /// Bitwise AND.
    And,
    /// Bitwise XOR.
    Xor,
    /// Bitwise OR.
    Or,
    /// Compare by subtraction without storing the result.
    Compare,
}

/// Operation selected by the upper five bits of a CB opcode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CbOperation {
    /// Rotate left circular.
    RotateLeftCircular,
    /// Rotate right circular.
    RotateRightCircular,
    /// Rotate left through carry.
    RotateLeft,
    /// Rotate right through carry.
    RotateRight,
    /// Shift left arithmetic.
    ShiftLeftArithmetic,
    /// Shift right arithmetic, retaining the sign bit.
    ShiftRightArithmetic,
    /// Swap the upper and lower nibbles.
    SwapNibbles,
    /// Shift right logical.
    ShiftRightLogical,
    /// Test a bit without changing the operand.
    TestBit(u8),
    /// Reset a bit.
    ResetBit(u8),
    /// Set a bit.
    SetBit(u8),
}

/// Fully typed semantic operation for a defined instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Operation {
    /// No operation.
    Nop,
    /// Store SP at the absolute immediate address, low byte first.
    StoreSpAbsolute,
    /// Enter the terminal stopped state after consuming the padding byte.
    Stop,
    /// Relative jump, unconditional when the condition is absent.
    RelativeJump(Option<Condition>),
    /// Load a 16-bit immediate into a register pair.
    Load16Immediate(Register16),
    /// Add a register pair into HL.
    AddHl(Register16),
    /// Transfer A through a register-indirect address.
    LoadAccumulatorIndirect(IndirectAddress, TransferDirection),
    /// Increment a 16-bit register pair.
    Increment16(Register16),
    /// Decrement a 16-bit register pair.
    Decrement16(Register16),
    /// Increment an eight-bit operand.
    Increment8(Operand8),
    /// Decrement an eight-bit operand.
    Decrement8(Operand8),
    /// Load an immediate byte into an operand.
    Load8Immediate(Operand8),
    /// Rotate A; the contained CB operation is one of the four rotate forms.
    RotateAccumulator(CbOperation),
    /// Decimal-adjust A after binary-coded-decimal arithmetic.
    DecimalAdjust,
    /// Complement every bit of A.
    ComplementAccumulator,
    /// Set the carry flag.
    SetCarry,
    /// Complement the carry flag.
    ComplementCarry,
    /// Copy one eight-bit operand to another.
    Load8(Operand8, Operand8),
    /// Enter the terminal halted state in the no-interrupt v1 profile.
    Halt,
    /// Apply an eight-bit ALU operation to A and a source operand.
    Alu8(AluOperation, Operand8),
    /// Return, unconditional when the condition is absent.
    Return(Option<Condition>),
    /// Transfer A through `0xff00 +` an immediate byte.
    HighImmediateLoad(TransferDirection),
    /// Add a signed immediate byte to SP.
    AddSpOffset,
    /// Set HL to SP plus a signed immediate byte.
    LoadHlSpOffset,
    /// Pop a register pair from the stack.
    Pop(StackRegister16),
    /// Return and enable interrupt dispatch.
    ReturnFromInterrupt,
    /// Jump to the address in HL.
    JumpHl,
    /// Copy HL into SP.
    LoadSpHl,
    /// Absolute jump, unconditional when the condition is absent.
    Jump(Option<Condition>),
    /// Transfer A through `0xff00 + C`.
    HighCLoad(TransferDirection),
    /// Transfer A through an absolute immediate address.
    AbsoluteAccumulatorLoad(TransferDirection),
    /// Dispatch the following byte through the CB opcode table.
    PrefixCb,
    /// Disable interrupt dispatch immediately.
    DisableInterrupts,
    /// Enable interrupt dispatch after the following instruction.
    EnableInterrupts,
    /// Call, unconditional when the condition is absent.
    Call(Option<Condition>),
    /// Push a register pair onto the stack.
    Push(StackRegister16),
    /// Call a fixed low-memory vector.
    Restart(u8),
    /// Apply a CB operation to an eight-bit operand.
    Cb(CbOperation, Operand8),
}

/// How one flag bit evolves through an instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FlagAction {
    /// Preserve the input flag.
    Preserve,
    /// Clear the flag.
    Clear,
    /// Set the flag.
    Set,
    /// Derive the flag from the instruction operands and result.
    Derived,
}

/// Explicit effects on the SM83 Z, N, H, and C flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlagEffect {
    /// Zero-flag action.
    pub zero: FlagAction,
    /// Subtract-flag action.
    pub subtract: FlagAction,
    /// Half-carry-flag action.
    pub half_carry: FlagAction,
    /// Carry-flag action.
    pub carry: FlagAction,
}

/// Base and condition-taken instruction timing in SM83 M-cycles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Timing {
    base_m_cycles: u8,
    taken_m_cycles: Option<u8>,
}

impl Timing {
    pub(crate) const fn new(base_m_cycles: u8, taken_m_cycles: Option<u8>) -> Self {
        Self {
            base_m_cycles,
            taken_m_cycles,
        }
    }

    /// Returns unconditional timing or untaken conditional timing.
    #[must_use]
    pub const fn base_m_cycles(self) -> u8 {
        self.base_m_cycles
    }

    /// Returns taken conditional timing, when the instruction is conditional.
    #[must_use]
    pub const fn taken_m_cycles(self) -> Option<u8> {
        self.taken_m_cycles
    }
}

/// Explicit instruction-level bus event counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BusAccessPattern {
    opcode_fetches: u8,
    immediate_reads: u8,
    data_reads: u8,
    data_writes: u8,
    taken_data_reads: u8,
    taken_data_writes: u8,
}

impl BusAccessPattern {
    pub(crate) const fn new(
        opcode_fetches: u8,
        immediate_reads: u8,
        data_reads: u8,
        data_writes: u8,
        taken_data_reads: u8,
        taken_data_writes: u8,
    ) -> Self {
        Self {
            opcode_fetches,
            immediate_reads,
            data_reads,
            data_writes,
            taken_data_reads,
            taken_data_writes,
        }
    }

    /// Returns authenticated opcode-fetch count.
    #[must_use]
    pub const fn opcode_fetches(self) -> u8 {
        self.opcode_fetches
    }

    /// Returns authenticated immediate-byte read count.
    #[must_use]
    pub const fn immediate_reads(self) -> u8 {
        self.immediate_reads
    }

    /// Returns unconditional data-read count.
    #[must_use]
    pub const fn data_reads(self) -> u8 {
        self.data_reads
    }

    /// Returns unconditional data-write count.
    #[must_use]
    pub const fn data_writes(self) -> u8 {
        self.data_writes
    }

    /// Returns additional data reads when a condition is taken.
    #[must_use]
    pub const fn taken_data_reads(self) -> u8 {
        self.taken_data_reads
    }

    /// Returns additional data writes when a condition is taken.
    #[must_use]
    pub const fn taken_data_writes(self) -> u8 {
        self.taken_data_writes
    }
}

/// CPU state component named by instruction read/write metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateComponent {
    /// A register.
    A,
    /// B register.
    B,
    /// C register.
    C,
    /// D register.
    D,
    /// E register.
    E,
    /// H register.
    H,
    /// L register.
    L,
    /// Flags register.
    F,
    /// Program counter.
    Pc,
    /// Stack pointer.
    Sp,
    /// Interrupt-master-enable state.
    Ime,
    /// Running, halted, or stopped state.
    RunState,
    /// Accumulated M-cycle counter.
    MCycles,
}

impl StateComponent {
    /// Returns every component in stable proof-table order.
    #[must_use]
    pub const fn all() -> [Self; 13] {
        [
            Self::A,
            Self::B,
            Self::C,
            Self::D,
            Self::E,
            Self::H,
            Self::L,
            Self::F,
            Self::Pc,
            Self::Sp,
            Self::Ime,
            Self::RunState,
            Self::MCycles,
        ]
    }

    pub(crate) const fn mask(self) -> u16 {
        match self {
            Self::A => 1 << 0,
            Self::B => 1 << 1,
            Self::C => 1 << 2,
            Self::D => 1 << 3,
            Self::E => 1 << 4,
            Self::H => 1 << 5,
            Self::L => 1 << 6,
            Self::F => 1 << 7,
            Self::Pc => 1 << 8,
            Self::Sp => 1 << 9,
            Self::Ime => 1 << 10,
            Self::RunState => 1 << 11,
            Self::MCycles => 1 << 12,
        }
    }
}

/// Explicit CPU state components read and written by an instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StateAccess {
    reads: u16,
    writes: u16,
}

impl StateAccess {
    pub(crate) const fn new(reads: u16, writes: u16) -> Self {
        Self { reads, writes }
    }

    /// Returns whether the instruction reads the component.
    #[must_use]
    pub const fn reads(self, component: StateComponent) -> bool {
        self.reads & component.mask() != 0
    }

    /// Returns whether the instruction writes the component.
    #[must_use]
    pub const fn writes(self, component: StateComponent) -> bool {
        self.writes & component.mask() != 0
    }
}

/// Complete metadata and semantic operation for one defined encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DecodedInstruction {
    pub(crate) encoding: InstructionEncoding,
    pub(crate) class: InstructionClass,
    pub(crate) operation: Operation,
    pub(crate) byte_len: u8,
    pub(crate) timing: Timing,
    pub(crate) flags: FlagEffect,
    pub(crate) state_access: StateAccess,
    pub(crate) bus: BusAccessPattern,
}

/// Stable operation and operand codes consumed by the proof lookup table.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct InstructionDescriptor {
    /// Semantic operation code.
    pub operation: u8,
    /// First operation-specific operand code.
    pub argument_zero: u8,
    /// Second operation-specific operand code.
    pub argument_one: u8,
}

impl DecodedInstruction {
    /// Returns the unique opcode encoding.
    #[must_use]
    pub const fn encoding(self) -> InstructionEncoding {
        self.encoding
    }

    /// Returns the high-level proof-table class.
    #[must_use]
    pub const fn class(self) -> InstructionClass {
        self.class
    }

    /// Returns the typed semantic operation.
    #[must_use]
    pub const fn operation(self) -> Operation {
        self.operation
    }

    /// Returns total encoded instruction bytes, including immediates.
    #[must_use]
    pub const fn byte_len(self) -> u8 {
        self.byte_len
    }

    /// Returns explicit base and condition-taken timing.
    #[must_use]
    pub const fn timing(self) -> Timing {
        self.timing
    }

    /// Returns explicit flag evolution.
    #[must_use]
    pub const fn flags(self) -> FlagEffect {
        self.flags
    }

    /// Returns explicit CPU component reads and writes.
    #[must_use]
    pub const fn state_access(self) -> StateAccess {
        self.state_access
    }

    /// Returns explicit bus event counts.
    #[must_use]
    pub const fn bus(self) -> BusAccessPattern {
        self.bus
    }

    /// Returns stable semantic codes for the proof-system opcode table.
    #[must_use]
    pub const fn descriptor(self) -> InstructionDescriptor {
        descriptor(self.operation)
    }

    /// Returns opcode bytes and their count, excluding immediate operands.
    #[must_use]
    pub const fn encoded_opcode(self) -> ([u8; 2], u8) {
        match self.encoding {
            InstructionEncoding::Primary(opcode) => ([opcode.byte(), 0], 1),
            InstructionEncoding::Cb(opcode) => ([0xcb, opcode.byte()], 2),
        }
    }
}

const fn descriptor(operation: Operation) -> InstructionDescriptor {
    let (code, argument_zero, argument_one) = match operation {
        Operation::Nop => (0, 0, 0),
        Operation::StoreSpAbsolute => (1, 0, 0),
        Operation::Stop => (2, 0, 0),
        Operation::RelativeJump(condition) => (3, condition_code(condition), 0),
        Operation::Load16Immediate(register) => (4, register16_code(register), 0),
        Operation::AddHl(register) => (5, register16_code(register), 0),
        Operation::LoadAccumulatorIndirect(address, direction) => {
            (6, indirect_code(address), direction_code(direction))
        }
        Operation::Increment16(register) => (7, register16_code(register), 0),
        Operation::Decrement16(register) => (8, register16_code(register), 0),
        Operation::Increment8(operand) => (9, operand8_code(operand), 0),
        Operation::Decrement8(operand) => (10, operand8_code(operand), 0),
        Operation::Load8Immediate(operand) => (11, operand8_code(operand), 0),
        Operation::RotateAccumulator(rotate) => (12, cb_operation_code(rotate), 0),
        Operation::DecimalAdjust => (13, 0, 0),
        Operation::ComplementAccumulator => (14, 0, 0),
        Operation::SetCarry => (15, 0, 0),
        Operation::ComplementCarry => (16, 0, 0),
        Operation::Load8(destination, source) => {
            (17, operand8_code(destination), operand8_code(source))
        }
        Operation::Halt => (18, 0, 0),
        Operation::Alu8(alu, source) => (19, alu_code(alu), operand8_code(source)),
        Operation::Return(condition) => (20, condition_code(condition), 0),
        Operation::HighImmediateLoad(direction) => (21, direction_code(direction), 0),
        Operation::AddSpOffset => (22, 0, 0),
        Operation::LoadHlSpOffset => (23, 0, 0),
        Operation::Pop(register) => (24, stack_register_code(register), 0),
        Operation::ReturnFromInterrupt => (25, 0, 0),
        Operation::JumpHl => (26, 0, 0),
        Operation::LoadSpHl => (27, 0, 0),
        Operation::Jump(condition) => (28, condition_code(condition), 0),
        Operation::HighCLoad(direction) => (29, direction_code(direction), 0),
        Operation::AbsoluteAccumulatorLoad(direction) => (30, direction_code(direction), 0),
        Operation::PrefixCb => (31, 0, 0),
        Operation::DisableInterrupts => (32, 0, 0),
        Operation::EnableInterrupts => (33, 0, 0),
        Operation::Call(condition) => (34, condition_code(condition), 0),
        Operation::Push(register) => (35, stack_register_code(register), 0),
        Operation::Restart(vector) => (36, vector >> 3, 0),
        Operation::Cb(cb, operand) => cb_descriptor(cb, operand),
    };
    InstructionDescriptor {
        operation: code,
        argument_zero,
        argument_one,
    }
}

const fn cb_descriptor(operation: CbOperation, operand: Operand8) -> (u8, u8, u8) {
    match operation {
        CbOperation::TestBit(bit) => (38, bit, operand8_code(operand)),
        CbOperation::ResetBit(bit) => (39, bit, operand8_code(operand)),
        CbOperation::SetBit(bit) => (40, bit, operand8_code(operand)),
        _ => (37, cb_operation_code(operation), operand8_code(operand)),
    }
}

const fn condition_code(condition: Option<Condition>) -> u8 {
    match condition {
        None => 0,
        Some(Condition::NotZero) => 1,
        Some(Condition::Zero) => 2,
        Some(Condition::NotCarry) => 3,
        Some(Condition::Carry) => 4,
    }
}

const fn operand8_code(operand: Operand8) -> u8 {
    match operand {
        Operand8::Register(Register8::B) => 0,
        Operand8::Register(Register8::C) => 1,
        Operand8::Register(Register8::D) => 2,
        Operand8::Register(Register8::E) => 3,
        Operand8::Register(Register8::H) => 4,
        Operand8::Register(Register8::L) => 5,
        Operand8::IndirectHl => 6,
        Operand8::Register(Register8::A) => 7,
        Operand8::Immediate => 8,
    }
}

const fn register16_code(register: Register16) -> u8 {
    match register {
        Register16::Bc => 0,
        Register16::De => 1,
        Register16::Hl => 2,
        Register16::Sp => 3,
    }
}

const fn stack_register_code(register: StackRegister16) -> u8 {
    match register {
        StackRegister16::Bc => 0,
        StackRegister16::De => 1,
        StackRegister16::Hl => 2,
        StackRegister16::Af => 3,
    }
}

const fn indirect_code(address: IndirectAddress) -> u8 {
    match address {
        IndirectAddress::Bc => 0,
        IndirectAddress::De => 1,
        IndirectAddress::HlIncrement => 2,
        IndirectAddress::HlDecrement => 3,
    }
}

const fn direction_code(direction: TransferDirection) -> u8 {
    match direction {
        TransferDirection::IntoAccumulator => 0,
        TransferDirection::FromAccumulator => 1,
    }
}

const fn alu_code(operation: AluOperation) -> u8 {
    match operation {
        AluOperation::Add => 0,
        AluOperation::AddCarry => 1,
        AluOperation::Subtract => 2,
        AluOperation::SubtractCarry => 3,
        AluOperation::And => 4,
        AluOperation::Xor => 5,
        AluOperation::Or => 6,
        AluOperation::Compare => 7,
    }
}

const fn cb_operation_code(operation: CbOperation) -> u8 {
    match operation {
        CbOperation::RotateLeftCircular => 0,
        CbOperation::RotateRightCircular => 1,
        CbOperation::RotateLeft => 2,
        CbOperation::RotateRight => 3,
        CbOperation::ShiftLeftArithmetic => 4,
        CbOperation::ShiftRightArithmetic => 5,
        CbOperation::SwapNibbles => 6,
        CbOperation::ShiftRightLogical => 7,
        CbOperation::TestBit(bit) | CbOperation::ResetBit(bit) | CbOperation::SetBit(bit) => bit,
    }
}
