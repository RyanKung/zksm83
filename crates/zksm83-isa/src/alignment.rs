//! Stable rows for aligning raw SM83 encodings to the proof ISA.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    DecodedInstruction, FlagAction, InstructionEncoding, OPCODE_TABLE, OpcodeClassification,
    Operation, StateComponent,
};

/// Number of defined primary encodings plus all CB-prefixed encodings.
pub const ALIGNMENT_ROW_COUNT: usize = 501;

/// Raw opcode key consumed by the alignment lookup.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct AlignmentKey {
    /// Zero for a primary opcode and one for a CB-prefixed opcode.
    pub prefix: u8,
    /// Primary or CB secondary opcode byte.
    pub opcode: u8,
}

/// Program-counter behavior selected by an aligned instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProgramCounterRule {
    /// Advance by the encoded instruction length.
    Sequential,
    /// Add a signed immediate displacement when selected.
    Relative,
    /// Load an absolute immediate target when selected.
    Absolute,
    /// Load the HL register pair.
    IndirectHl,
    /// Push the return address and load a target.
    Call,
    /// Pop a target from the stack.
    Return,
    /// Push the return address and load a fixed low-memory vector.
    Restart,
}

impl ProgramCounterRule {
    /// Returns the stable field code used by the proof relation.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Sequential => 0,
            Self::Relative => 1,
            Self::Absolute => 2,
            Self::IndirectHl => 3,
            Self::Call => 4,
            Self::Return => 5,
            Self::Restart => 6,
        }
    }
}

/// Uniform proof-ISA record selected from a raw SM83 encoding.
///
/// The record deliberately includes semantic routing, flag, timing, and bus
/// fields. The execution relation consumes these columns after the lookup;
/// it does not decode the opcode a second time.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AlignedInstruction {
    /// Raw encoding lookup key.
    pub key: AlignmentKey,
    /// High-level instruction-family code.
    pub family_id: u8,
    /// Uniform semantic operation code.
    pub operation: u8,
    /// First operation-specific route or selector.
    pub argument_zero: u8,
    /// Second operation-specific route or selector.
    pub argument_one: u8,
    /// Encoded byte length, including immediates.
    pub byte_len: u8,
    /// Untaken or unconditional M-cycle count.
    pub base_m_cycles: u8,
    /// Taken M-cycle count, or zero for non-conditional instructions.
    pub taken_m_cycles: u8,
    /// Stable PC-update rule.
    pub pc_rule: u8,
    /// Packed two-bit actions for Z, N, H, and C, in that order.
    pub flag_rule: u8,
    /// CPU components read by the instruction.
    pub register_reads: u16,
    /// CPU components written by the instruction.
    pub register_writes: u16,
    /// Authenticated opcode fetch count.
    pub opcode_fetches: u8,
    /// Authenticated immediate read count.
    pub immediate_reads: u8,
    /// Unconditional data read count.
    pub data_reads: u8,
    /// Unconditional data write count.
    pub data_writes: u8,
    /// Additional data reads on a taken branch.
    pub taken_data_reads: u8,
    /// Additional data writes on a taken branch.
    pub taken_data_writes: u8,
}

impl AlignedInstruction {
    /// Aligns one already-decoded SM83 instruction into the proof ISA.
    #[must_use]
    pub fn from_decoded(instruction: DecodedInstruction) -> Self {
        let key = match instruction.encoding() {
            InstructionEncoding::Primary(opcode) => AlignmentKey {
                prefix: 0,
                opcode: opcode.byte(),
            },
            InstructionEncoding::Cb(opcode) => AlignmentKey {
                prefix: 1,
                opcode: opcode.byte(),
            },
        };
        let descriptor = instruction.descriptor();
        let timing = instruction.timing();
        let bus = instruction.bus();
        let access = instruction.state_access();
        let (register_reads, register_writes) = StateComponent::all().into_iter().enumerate().fold(
            (0_u16, 0_u16),
            |(reads, writes), (index, component)| {
                let bit = 1_u16 << index;
                (
                    if access.reads(component) {
                        reads | bit
                    } else {
                        reads
                    },
                    if access.writes(component) {
                        writes | bit
                    } else {
                        writes
                    },
                )
            },
        );
        let flags = instruction.flags();
        Self {
            key,
            family_id: instruction.class().code(),
            operation: descriptor.operation,
            argument_zero: descriptor.argument_zero,
            argument_one: descriptor.argument_one,
            byte_len: instruction.byte_len(),
            base_m_cycles: timing.base_m_cycles(),
            taken_m_cycles: timing.taken_m_cycles().unwrap_or(0),
            pc_rule: pc_rule(instruction.operation()).code(),
            flag_rule: flag_action_code(flags.zero)
                | (flag_action_code(flags.subtract) << 2)
                | (flag_action_code(flags.half_carry) << 4)
                | (flag_action_code(flags.carry) << 6),
            register_reads,
            register_writes,
            opcode_fetches: bus.opcode_fetches(),
            immediate_reads: bus.immediate_reads(),
            data_reads: bus.data_reads(),
            data_writes: bus.data_writes(),
            taken_data_reads: bus.taken_data_reads(),
            taken_data_writes: bus.taken_data_writes(),
        }
    }

    /// Returns all 501 defined alignment rows in stable key order.
    pub fn all() -> impl ExactSizeIterator<Item = Self> {
        let mut rows = Vec::with_capacity(ALIGNMENT_ROW_COUNT);
        rows.extend(
            OPCODE_TABLE
                .primary_entries()
                .filter_map(|entry| match entry {
                    OpcodeClassification::Defined(instruction) => {
                        Some(Self::from_decoded(instruction))
                    }
                    OpcodeClassification::Undefined(_) => None,
                }),
        );
        rows.extend(OPCODE_TABLE.cb_entries().map(Self::from_decoded));
        rows.into_iter()
    }

    /// Packs the complete lookup key and semantic row into 106 collision-free bits.
    pub fn packed(self) -> Result<u128, AlignmentPackingError> {
        let mut packed = 0_u128;
        let mut shift = 0_u8;
        for (name, value, bits) in [
            ("prefix", u64::from(self.key.prefix), 1_u8),
            ("opcode", u64::from(self.key.opcode), 8),
            ("family_id", u64::from(self.family_id), 8),
            ("operation", u64::from(self.operation), 8),
            ("argument_zero", u64::from(self.argument_zero), 8),
            ("argument_one", u64::from(self.argument_one), 8),
            ("byte_len", u64::from(self.byte_len), 2),
            ("base_m_cycles", u64::from(self.base_m_cycles), 4),
            ("taken_m_cycles", u64::from(self.taken_m_cycles), 4),
            ("pc_rule", u64::from(self.pc_rule), 3),
            ("flag_rule", u64::from(self.flag_rule), 8),
            ("register_reads", u64::from(self.register_reads), 16),
            ("register_writes", u64::from(self.register_writes), 16),
            ("opcode_fetches", u64::from(self.opcode_fetches), 2),
            ("immediate_reads", u64::from(self.immediate_reads), 2),
            ("data_reads", u64::from(self.data_reads), 2),
            ("data_writes", u64::from(self.data_writes), 2),
            ("taken_data_reads", u64::from(self.taken_data_reads), 2),
            ("taken_data_writes", u64::from(self.taken_data_writes), 2),
        ] {
            append_packed(&mut packed, &mut shift, name, value, bits)?;
        }
        Ok(packed)
    }
}

/// A semantic alignment row exceeds its fixed collision-free bit allocation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("alignment field {field} value {value} exceeds {bits} bits")]
pub struct AlignmentPackingError {
    /// Stable field name.
    pub field: &'static str,
    /// Rejected value.
    pub value: u64,
    /// Allocated width.
    pub bits: u8,
}

fn append_packed(
    packed: &mut u128,
    shift: &mut u8,
    field: &'static str,
    value: u64,
    bits: u8,
) -> Result<(), AlignmentPackingError> {
    let limit = 1_u64.checked_shl(u32::from(bits)).unwrap_or(0);
    if value >= limit || u16::from(*shift) + u16::from(bits) > 128 {
        return Err(AlignmentPackingError { field, value, bits });
    }
    *packed |= u128::from(value) << *shift;
    *shift = shift.saturating_add(bits);
    Ok(())
}

const fn flag_action_code(action: FlagAction) -> u8 {
    match action {
        FlagAction::Preserve => 0,
        FlagAction::Clear => 1,
        FlagAction::Set => 2,
        FlagAction::Derived => 3,
    }
}

const fn pc_rule(operation: Operation) -> ProgramCounterRule {
    match operation {
        Operation::RelativeJump(_) => ProgramCounterRule::Relative,
        Operation::Jump(_) => ProgramCounterRule::Absolute,
        Operation::JumpHl => ProgramCounterRule::IndirectHl,
        Operation::Call(_) => ProgramCounterRule::Call,
        Operation::Return(_) | Operation::ReturnFromInterrupt => ProgramCounterRule::Return,
        Operation::Restart(_) => ProgramCounterRule::Restart,
        _ => ProgramCounterRule::Sequential,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{ALIGNMENT_ROW_COUNT, AlignedInstruction};

    #[test]
    fn alignment_table_has_501_unique_rows() {
        let rows = AlignedInstruction::all().collect::<Vec<_>>();
        assert_eq!(rows.len(), ALIGNMENT_ROW_COUNT);
        let keys = rows.iter().map(|row| row.key).collect::<HashSet<_>>();
        assert_eq!(keys.len(), ALIGNMENT_ROW_COUNT);
    }

    #[test]
    fn cb_rows_are_aligned_after_primary_rows() {
        let rows = AlignedInstruction::all().collect::<Vec<_>>();
        let first_cb = rows.iter().position(|row| row.key.prefix == 1);
        assert_eq!(first_cb, Some(245));
        assert!(
            rows.get(245)
                .is_some_and(|row| row.key.opcode == 0 && row.opcode_fetches == 2)
        );
    }

    #[test]
    fn every_alignment_row_has_a_unique_canonical_packing() -> Result<(), Box<dyn std::error::Error>>
    {
        let packed = AlignedInstruction::all()
            .map(AlignedInstruction::packed)
            .collect::<Result<HashSet<_>, _>>()?;
        assert_eq!(packed.len(), ALIGNMENT_ROW_COUNT);
        Ok(())
    }
}
