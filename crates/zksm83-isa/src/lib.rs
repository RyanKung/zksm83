#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Complete, fail-closed SM83 instruction metadata and decoding.

mod alignment;
mod decode;
mod metadata;
mod types;

pub use alignment::{
    ALIGNMENT_ROW_COUNT, AlignedInstruction, AlignmentKey, AlignmentPackingError,
    ProgramCounterRule,
};
pub use decode::{CompleteOpcodeTable, OPCODE_TABLE, decode_cb, decode_primary};
pub use types::{
    AluOperation, BusAccessPattern, CbOpcode, CbOperation, Condition, DecodedInstruction,
    FlagAction, FlagEffect, IndirectAddress, InstructionClass, InstructionDescriptor,
    InstructionEncoding, Opcode, OpcodeClassification, Operand8, Operation, Register8, Register16,
    StackRegister16, StateAccess, StateComponent, Timing, TransferDirection, UndefinedOpcode,
};
