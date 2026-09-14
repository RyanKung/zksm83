//! Total lookup routing for defined SM83 instruction semantics.

use crate::{AluOperation, CbOperation, DecodedInstruction, Operation};

/// One verifier-fixed execution table used by the SM83 instruction lookup.
///
/// The table identity is static instruction metadata. Dynamic operands and
/// outputs belong to the execution trace and are authenticated separately.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ExecutionLookupTable {
    /// Eight-bit addition, including optional carry input and output flags.
    Add8 = 1,
    /// Eight-bit subtraction, including optional borrow input and output flags.
    Subtract8 = 2,
    /// Eight-bit bitwise AND and output flags.
    And8 = 3,
    /// Eight-bit bitwise XOR and output flags.
    Xor8 = 4,
    /// Eight-bit bitwise OR and output flags.
    Or8 = 5,
    /// Eight-bit increment with preserved carry.
    Increment8 = 6,
    /// Eight-bit decrement with preserved carry.
    Decrement8 = 7,
    /// Eight-bit rotate or shift selected by its committed operation code.
    RotateShift8 = 8,
    /// Decimal adjustment over the accumulator and incoming flags.
    DecimalAdjust8 = 9,
    /// Test one selected bit and derive the output flags.
    TestBit8 = 10,
    /// Clear one selected bit.
    ResetBit8 = 11,
    /// Set one selected bit.
    SetBit8 = 12,
    /// Evaluate one committed branch condition against the incoming flags.
    Condition = 13,
}

impl ExecutionLookupTable {
    /// Every execution table in stable protocol order.
    pub const ALL: [Self; 13] = [
        Self::Add8,
        Self::Subtract8,
        Self::And8,
        Self::Xor8,
        Self::Or8,
        Self::Increment8,
        Self::Decrement8,
        Self::RotateShift8,
        Self::DecimalAdjust8,
        Self::TestBit8,
        Self::ResetBit8,
        Self::SetBit8,
        Self::Condition,
    ];

    /// Returns the stable non-zero table selector committed by the proof ISA.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns the Boolean address width of this verifier-fixed table.
    #[must_use]
    pub const fn input_bit_count(self) -> usize {
        match self {
            Self::Add8 | Self::Subtract8 => 17,
            Self::And8 | Self::Xor8 | Self::Or8 => 16,
            Self::Increment8 | Self::Decrement8 => 9,
            Self::RotateShift8 => 13,
            Self::DecimalAdjust8 => 12,
            Self::TestBit8 => 12,
            Self::ResetBit8 | Self::SetBit8 => 11,
            Self::Condition => 6,
        }
    }

    /// Returns this table's aligned base in the compact 19-bit execution domain.
    #[must_use]
    pub const fn packed_offset(self) -> u32 {
        match self {
            Self::Add8 => 0,
            Self::Subtract8 => 131_072,
            Self::And8 => 262_144,
            Self::Xor8 => 327_680,
            Self::Or8 => 393_216,
            Self::Increment8 => 479_232,
            Self::Decrement8 => 480_256,
            Self::RotateShift8 => 458_752,
            Self::DecimalAdjust8 => 466_944,
            Self::TestBit8 => 471_040,
            Self::ResetBit8 => 475_136,
            Self::SetBit8 => 477_184,
            Self::Condition => 481_280,
        }
    }

    /// Returns the exact power-of-two row count of this table.
    #[must_use]
    pub const fn row_count(self) -> u32 {
        1_u32 << self.input_bit_count()
    }
}

/// Complete proof routing for one defined SM83 instruction.
///
/// `GlueOnly` is an explicit proof strategy, not an unsupported fallback.
/// Such instructions only copy, route, or affinely update already checked
/// register, program-counter, stack, and memory values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionProofPlan {
    /// No nonlinear execution table is required; low-degree glue is sufficient.
    GlueOnly,
    /// Dynamic instruction operands and outputs must satisfy the selected table.
    Lookup(ExecutionLookupTable),
    /// Two byte-level queries to the same table prove one word-level operation.
    DoubleLookup(ExecutionLookupTable),
}

impl ExecutionProofPlan {
    /// Returns the selected table, or `None` for an explicit glue-only plan.
    #[must_use]
    pub const fn lookup_table(self) -> Option<ExecutionLookupTable> {
        match self {
            Self::GlueOnly => None,
            Self::Lookup(table) | Self::DoubleLookup(table) => Some(table),
        }
    }

    /// Returns the exact number of dynamic table queries required.
    #[must_use]
    pub const fn lookup_count(self) -> usize {
        match self {
            Self::GlueOnly => 0,
            Self::Lookup(_) => 1,
            Self::DoubleLookup(_) => 2,
        }
    }
}

impl DecodedInstruction {
    /// Returns the total execution-proof plan for this defined instruction.
    #[must_use]
    pub const fn execution_proof_plan(self) -> ExecutionProofPlan {
        execution_proof_plan(self.operation())
    }
}

const fn execution_proof_plan(operation: Operation) -> ExecutionProofPlan {
    use ExecutionLookupTable as Table;
    use ExecutionProofPlan::{DoubleLookup, GlueOnly, Lookup};

    match operation {
        Operation::AddHl(_) => DoubleLookup(Table::Add8),
        Operation::Increment8(_) => Lookup(Table::Increment8),
        Operation::Decrement8(_) => Lookup(Table::Decrement8),
        Operation::RotateAccumulator(_) => Lookup(Table::RotateShift8),
        Operation::DecimalAdjust => Lookup(Table::DecimalAdjust8),
        Operation::Alu8(alu, _) => Lookup(alu_lookup_table(alu)),
        Operation::AddSpOffset | Operation::LoadHlSpOffset => DoubleLookup(Table::Add8),
        Operation::RelativeJump(Some(_))
        | Operation::Return(Some(_))
        | Operation::Jump(Some(_))
        | Operation::Call(Some(_)) => Lookup(Table::Condition),
        Operation::Cb(cb, _) => Lookup(cb_lookup_table(cb)),
        Operation::Nop
        | Operation::StoreSpAbsolute
        | Operation::Stop
        | Operation::RelativeJump(None)
        | Operation::Load16Immediate(_)
        | Operation::LoadAccumulatorIndirect(_, _)
        | Operation::Increment16(_)
        | Operation::Decrement16(_)
        | Operation::Load8Immediate(_)
        | Operation::ComplementAccumulator
        | Operation::SetCarry
        | Operation::ComplementCarry
        | Operation::Load8(_, _)
        | Operation::Halt
        | Operation::Return(None)
        | Operation::HighImmediateLoad(_)
        | Operation::Pop(_)
        | Operation::ReturnFromInterrupt
        | Operation::JumpHl
        | Operation::LoadSpHl
        | Operation::Jump(None)
        | Operation::HighCLoad(_)
        | Operation::AbsoluteAccumulatorLoad(_)
        | Operation::PrefixCb
        | Operation::DisableInterrupts
        | Operation::EnableInterrupts
        | Operation::Call(None)
        | Operation::Push(_)
        | Operation::Restart(_) => GlueOnly,
    }
}

const fn alu_lookup_table(operation: AluOperation) -> ExecutionLookupTable {
    match operation {
        AluOperation::Add | AluOperation::AddCarry => ExecutionLookupTable::Add8,
        AluOperation::Subtract | AluOperation::SubtractCarry | AluOperation::Compare => {
            ExecutionLookupTable::Subtract8
        }
        AluOperation::And => ExecutionLookupTable::And8,
        AluOperation::Xor => ExecutionLookupTable::Xor8,
        AluOperation::Or => ExecutionLookupTable::Or8,
    }
}

const fn cb_lookup_table(operation: CbOperation) -> ExecutionLookupTable {
    match operation {
        CbOperation::RotateLeftCircular
        | CbOperation::RotateRightCircular
        | CbOperation::RotateLeft
        | CbOperation::RotateRight
        | CbOperation::ShiftLeftArithmetic
        | CbOperation::ShiftRightArithmetic
        | CbOperation::SwapNibbles
        | CbOperation::ShiftRightLogical => ExecutionLookupTable::RotateShift8,
        CbOperation::TestBit(_) => ExecutionLookupTable::TestBit8,
        CbOperation::ResetBit(_) => ExecutionLookupTable::ResetBit8,
        CbOperation::SetBit(_) => ExecutionLookupTable::SetBit8,
    }
}

#[cfg(test)]
mod tests {
    use super::{ExecutionLookupTable, ExecutionProofPlan};
    use crate::{ALIGNMENT_ROW_COUNT, OPCODE_TABLE, OpcodeClassification};

    #[test]
    fn every_defined_instruction_has_one_total_execution_plan() -> Result<(), &'static str> {
        let mut defined = 0_usize;
        let mut glue_only = 0_usize;
        let mut table_uses = [0_usize; ExecutionLookupTable::ALL.len()];
        let instructions = OPCODE_TABLE
            .primary_entries()
            .filter_map(|entry| match entry {
                OpcodeClassification::Defined(instruction) => Some(instruction),
                OpcodeClassification::Undefined(_) => None,
            })
            .chain(OPCODE_TABLE.cb_entries());

        for instruction in instructions {
            defined += 1;
            match instruction.execution_proof_plan() {
                ExecutionProofPlan::GlueOnly => glue_only += 1,
                ExecutionProofPlan::Lookup(table) | ExecutionProofPlan::DoubleLookup(table) => {
                    let index = usize::from(table.code() - 1);
                    let uses = table_uses
                        .get_mut(index)
                        .ok_or("execution table code exceeds stable table list")?;
                    *uses += 1;
                }
            }
        }

        assert_eq!(defined, ALIGNMENT_ROW_COUNT);
        assert!(glue_only > 0);
        assert!(table_uses.into_iter().all(|uses| uses > 0));
        Ok(())
    }

    #[test]
    fn execution_table_codes_are_dense_and_stable() {
        for (index, table) in ExecutionLookupTable::ALL.into_iter().enumerate() {
            assert_eq!(usize::from(table.code()), index + 1);
            assert!((6..=17).contains(&table.input_bit_count()));
        }
    }

    #[test]
    fn compact_table_ranges_are_aligned_disjoint_and_fit_nineteen_bits() {
        for table in ExecutionLookupTable::ALL {
            assert_eq!(table.packed_offset() % table.row_count(), 0);
            assert!(table.packed_offset() + table.row_count() <= 1 << 19);
            for other in ExecutionLookupTable::ALL {
                if table == other {
                    continue;
                }
                let table_end = table.packed_offset() + table.row_count();
                let other_end = other.packed_offset() + other.row_count();
                assert!(table_end <= other.packed_offset() || other_end <= table.packed_offset());
            }
        }
    }
}
