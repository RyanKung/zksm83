//! Execution-lookup records derived from accepted SM83 transitions.

use thiserror::Error;
use zksm83_core::{
    BusEventKind, ExecutionLookupError, ExecutionLookupOutput, ExecutionLookupQuery, Flags,
    StepKind, VmState,
};
use zksm83_isa::{
    AluOperation, CbOperation, ExecutionLookupTable, Operand8, Operation, Register8, Register16,
};

use crate::TraceRow;

/// One dynamic execution lookup and its canonical output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstructionLookupRecord {
    query: ExecutionLookupQuery,
    output: ExecutionLookupOutput,
}

/// At most two byte-level lookups proving one accepted SM83 transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstructionLookupRecords {
    records: [Option<InstructionLookupRecord>; 2],
    count: u8,
}

/// An accepted transition could not be represented by its static lookup plan.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InstructionLookupRecordError {
    /// Construction or evaluation violated an execution-table domain.
    #[error(transparent)]
    Lookup(#[from] ExecutionLookupError),
    /// An instruction needing a dynamic operand emitted no matching bus event.
    #[error("SM83 execution lookup is missing a dynamic operand")]
    MissingOperand,
    /// Static ISA routing selected a different table than the dynamic query.
    #[error(
        "SM83 execution lookup planned {planned:?} x{planned_count}, constructed {actual:?} x{actual_count}"
    )]
    TableMismatch {
        /// Table selected by static ISA metadata.
        planned: Option<ExecutionLookupTable>,
        /// Number of queries selected by static ISA metadata.
        planned_count: usize,
        /// Table selected by the dynamic query constructor.
        actual: Option<ExecutionLookupTable>,
        /// Number of queries constructed from the accepted transition.
        actual_count: usize,
    },
    /// The table output disagrees with the accepted post-state or bus effect.
    #[error("SM83 execution lookup output disagrees with table {table:?}")]
    OutputMismatch {
        /// Table whose output was rejected.
        table: ExecutionLookupTable,
    },
}

impl InstructionLookupRecords {
    /// Derives the execution lookup for one accepted instruction transition.
    ///
    /// Machine-event and explicit glue-only rows return an empty set. Word
    /// additions return two byte-level records; every other table-backed
    /// instruction returns exactly one.
    pub fn from_row(row: &TraceRow) -> Result<Self, InstructionLookupRecordError> {
        if row.effects().kind() != StepKind::Instruction {
            return Ok(Self::empty());
        }
        let instruction = row.effects().instruction();
        let plan = instruction.execution_proof_plan();
        let queries = build_queries(row, instruction.operation())?;
        let records = queries.evaluate()?;
        let actual = records.first().map(InstructionLookupRecord::query);
        let actual_table = actual.map(ExecutionLookupQuery::table);
        if plan.lookup_table() != actual_table || plan.lookup_count() != records.len() {
            return Err(InstructionLookupRecordError::TableMismatch {
                planned: plan.lookup_table(),
                planned_count: plan.lookup_count(),
                actual: actual_table,
                actual_count: records.len(),
            });
        }
        for index in 0..records.len() {
            let record = records
                .get(index)
                .ok_or(InstructionLookupRecordError::TableMismatch {
                    planned: plan.lookup_table(),
                    planned_count: plan.lookup_count(),
                    actual: actual_table,
                    actual_count: records.len(),
                })?;
            if record.query().table()
                != actual_table.ok_or(InstructionLookupRecordError::TableMismatch {
                    planned: plan.lookup_table(),
                    planned_count: plan.lookup_count(),
                    actual: actual_table,
                    actual_count: records.len(),
                })?
            {
                return Err(InstructionLookupRecordError::TableMismatch {
                    planned: plan.lookup_table(),
                    planned_count: plan.lookup_count(),
                    actual: Some(record.query().table()),
                    actual_count: records.len(),
                });
            }
        }
        if !outputs_match_transition(row, instruction.operation(), &records) {
            let table = actual_table.ok_or(InstructionLookupRecordError::TableMismatch {
                planned: plan.lookup_table(),
                planned_count: plan.lookup_count(),
                actual: actual_table,
                actual_count: records.len(),
            })?;
            return Err(InstructionLookupRecordError::OutputMismatch { table });
        }
        Ok(records)
    }

    /// Returns the number of active lookup records.
    #[must_use]
    pub const fn len(self) -> usize {
        self.count as usize
    }

    /// Returns whether no execution lookup is required.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.count == 0
    }

    /// Returns one record by stable query order.
    #[must_use]
    pub fn get(self, index: usize) -> Option<InstructionLookupRecord> {
        self.records.get(index).copied().flatten()
    }

    /// Returns the first record, if present.
    #[must_use]
    pub const fn first(self) -> Option<InstructionLookupRecord> {
        let [first, _] = self.records;
        first
    }

    const fn empty() -> Self {
        Self {
            records: [None, None],
            count: 0,
        }
    }

    const fn one(record: InstructionLookupRecord) -> Self {
        Self {
            records: [Some(record), None],
            count: 1,
        }
    }

    const fn two(first: InstructionLookupRecord, second: InstructionLookupRecord) -> Self {
        Self {
            records: [Some(first), Some(second)],
            count: 2,
        }
    }
}

impl InstructionLookupRecord {
    /// Returns the validated table query.
    #[must_use]
    pub const fn query(self) -> ExecutionLookupQuery {
        self.query
    }

    /// Returns the canonical table output.
    #[must_use]
    pub const fn output(self) -> ExecutionLookupOutput {
        self.output
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InstructionLookupQueries {
    queries: [Option<ExecutionLookupQuery>; 2],
    count: u8,
}

impl InstructionLookupQueries {
    const fn empty() -> Self {
        Self {
            queries: [None, None],
            count: 0,
        }
    }

    const fn one(query: ExecutionLookupQuery) -> Self {
        Self {
            queries: [Some(query), None],
            count: 1,
        }
    }

    const fn two(first: ExecutionLookupQuery, second: ExecutionLookupQuery) -> Self {
        Self {
            queries: [Some(first), Some(second)],
            count: 2,
        }
    }

    fn evaluate(self) -> Result<InstructionLookupRecords, InstructionLookupRecordError> {
        match self.queries {
            [None, None] if self.count == 0 => Ok(InstructionLookupRecords::empty()),
            [Some(query), None] if self.count == 1 => {
                Ok(InstructionLookupRecords::one(InstructionLookupRecord {
                    query,
                    output: query.evaluate()?,
                }))
            }
            [Some(first), Some(second)] if self.count == 2 => Ok(InstructionLookupRecords::two(
                InstructionLookupRecord {
                    query: first,
                    output: first.evaluate()?,
                },
                InstructionLookupRecord {
                    query: second,
                    output: second.evaluate()?,
                },
            )),
            _ => Err(InstructionLookupRecordError::TableMismatch {
                planned: None,
                planned_count: 0,
                actual: None,
                actual_count: usize::from(self.count),
            }),
        }
    }
}

fn build_queries(
    row: &TraceRow,
    operation: Operation,
) -> Result<InstructionLookupQueries, InstructionLookupRecordError> {
    let before = row.before();
    let flags = before.cpu().flags();
    let queries = match operation {
        Operation::AddHl(source) => {
            let left = register16(before, Register16::Hl);
            let right = register16(before, source);
            byte_add_queries(left, right)
        }
        Operation::Increment8(target) => InstructionLookupQueries::one(
            ExecutionLookupQuery::increment8(operand_value(row, target)?, flags.carry()),
        ),
        Operation::Decrement8(target) => InstructionLookupQueries::one(
            ExecutionLookupQuery::decrement8(operand_value(row, target)?, flags.carry()),
        ),
        Operation::RotateAccumulator(rotate) => {
            InstructionLookupQueries::one(ExecutionLookupQuery::rotate_shift8(
                before.cpu().registers().a,
                rotate,
                flags.carry(),
                false,
            )?)
        }
        Operation::DecimalAdjust => InstructionLookupQueries::one(
            ExecutionLookupQuery::decimal_adjust8(before.cpu().registers().a, flags),
        ),
        Operation::Alu8(alu, source) => {
            let left = before.cpu().registers().a;
            let right = operand_value(row, source)?;
            InstructionLookupQueries::one(match alu {
                AluOperation::Add => ExecutionLookupQuery::add8(left, right, false),
                AluOperation::AddCarry => ExecutionLookupQuery::add8(left, right, flags.carry()),
                AluOperation::Subtract | AluOperation::Compare => {
                    ExecutionLookupQuery::subtract8(left, right, false)
                }
                AluOperation::SubtractCarry => {
                    ExecutionLookupQuery::subtract8(left, right, flags.carry())
                }
                AluOperation::And => ExecutionLookupQuery::and8(left, right),
                AluOperation::Xor => ExecutionLookupQuery::xor8(left, right),
                AluOperation::Or => ExecutionLookupQuery::or8(left, right),
            })
        }
        Operation::AddSpOffset | Operation::LoadHlSpOffset => {
            signed_byte_add_queries(before.cpu().sp(), immediate_value(row)?)
        }
        Operation::RelativeJump(Some(condition))
        | Operation::Return(Some(condition))
        | Operation::Jump(Some(condition))
        | Operation::Call(Some(condition)) => {
            InstructionLookupQueries::one(ExecutionLookupQuery::condition(condition, flags))
        }
        Operation::Cb(cb, target) => {
            InstructionLookupQueries::one(cb_query(row, cb, target, flags)?)
        }
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
        | Operation::Restart(_) => InstructionLookupQueries::empty(),
    };
    Ok(queries)
}

fn byte_add_queries(left: u16, right: u16) -> InstructionLookupQueries {
    let [left_low, left_high] = left.to_le_bytes();
    let [right_low, right_high] = right.to_le_bytes();
    let (_, carry) = left_low.overflowing_add(right_low);
    InstructionLookupQueries::two(
        ExecutionLookupQuery::add8(left_low, right_low, false),
        ExecutionLookupQuery::add8(left_high, right_high, carry),
    )
}

fn signed_byte_add_queries(left: u16, offset: u8) -> InstructionLookupQueries {
    let [left_low, left_high] = left.to_le_bytes();
    let (_, carry) = left_low.overflowing_add(offset);
    let sign_extension = if offset & 0x80 == 0 { 0 } else { u8::MAX };
    InstructionLookupQueries::two(
        ExecutionLookupQuery::add8(left_low, offset, false),
        ExecutionLookupQuery::add8(left_high, sign_extension, carry),
    )
}

fn cb_query(
    row: &TraceRow,
    operation: CbOperation,
    target: Operand8,
    flags: Flags,
) -> Result<ExecutionLookupQuery, InstructionLookupRecordError> {
    let value = operand_value(row, target)?;
    match operation {
        CbOperation::TestBit(bit) => {
            ExecutionLookupQuery::test_bit8(value, bit, flags.carry()).map_err(Into::into)
        }
        CbOperation::ResetBit(bit) => {
            ExecutionLookupQuery::reset_bit8(value, bit).map_err(Into::into)
        }
        CbOperation::SetBit(bit) => ExecutionLookupQuery::set_bit8(value, bit).map_err(Into::into),
        rotate => ExecutionLookupQuery::rotate_shift8(value, rotate, flags.carry(), true)
            .map_err(Into::into),
    }
}

fn outputs_match_transition(
    row: &TraceRow,
    operation: Operation,
    records: &InstructionLookupRecords,
) -> bool {
    match operation {
        Operation::AddHl(_) => word_add_matches_transition(row, *records, true),
        Operation::AddSpOffset => word_add_matches_transition(row, *records, false),
        Operation::LoadHlSpOffset => word_add_matches_transition(row, *records, false),
        _ if records.is_empty() => true,
        _ => records
            .first()
            .is_some_and(|record| output_matches_transition(row, operation, record.output())),
    }
}

fn word_add_matches_transition(
    row: &TraceRow,
    records: InstructionLookupRecords,
    preserve_zero: bool,
) -> bool {
    let Some(first) = records.get(0) else {
        return false;
    };
    let Some(second) = records.get(1) else {
        return false;
    };
    let (
        ExecutionLookupOutput::ByteWithFlags {
            value: low,
            flags: low_flags,
        },
        ExecutionLookupOutput::ByteWithFlags {
            value: high,
            flags: high_flags,
        },
    ) = (first.output(), second.output())
    else {
        return false;
    };
    let value = u16::from_le_bytes([low, high]);
    let expected_flags = if preserve_zero {
        Flags::from_bits(
            row.before().cpu().flags().zero(),
            false,
            high_flags.half_carry(),
            high_flags.carry(),
        )
    } else {
        Flags::from_bits(false, false, low_flags.half_carry(), low_flags.carry())
    };
    let destination = match row.effects().instruction().operation() {
        Operation::AddHl(_) | Operation::LoadHlSpOffset => register16(row.after(), Register16::Hl),
        Operation::AddSpOffset => row.after().cpu().sp(),
        _ => return false,
    };
    destination == value && row.after().cpu().flags() == expected_flags
}

fn output_matches_transition(
    row: &TraceRow,
    operation: Operation,
    output: ExecutionLookupOutput,
) -> bool {
    let after = row.after();
    match (operation, output) {
        (
            Operation::Alu8(AluOperation::Compare, _) | Operation::Cb(CbOperation::TestBit(_), _),
            ExecutionLookupOutput::ByteWithFlags { flags, .. },
        ) => after.cpu().flags() == flags,
        (
            Operation::Increment8(target)
            | Operation::Decrement8(target)
            | Operation::Cb(_, target),
            ExecutionLookupOutput::ByteWithFlags { value, flags },
        ) => after.cpu().flags() == flags && output_operand_value(row, target) == Some(value),
        (
            Operation::RotateAccumulator(_) | Operation::DecimalAdjust | Operation::Alu8(_, _),
            ExecutionLookupOutput::ByteWithFlags { value, flags },
        ) => after.cpu().registers().a == value && after.cpu().flags() == flags,
        (
            Operation::Cb(CbOperation::ResetBit(_) | CbOperation::SetBit(_), target),
            ExecutionLookupOutput::Byte(value),
        ) => output_operand_value(row, target) == Some(value),
        (
            Operation::RelativeJump(Some(_))
            | Operation::Return(Some(_))
            | Operation::Jump(Some(_))
            | Operation::Call(Some(_)),
            ExecutionLookupOutput::Predicate(taken),
        ) => row.effects().branch_taken() == taken,
        _ => false,
    }
}

fn operand_value(row: &TraceRow, operand: Operand8) -> Result<u8, InstructionLookupRecordError> {
    match operand {
        Operand8::Register(register) => Ok(register8(row.before(), register)),
        Operand8::Immediate => immediate_value(row),
        Operand8::IndirectHl => row
            .effects()
            .ordered_bus_events()
            .iter()
            .find(|event| is_data_read(event.kind()))
            .map(|event| event.transcript_event().value)
            .ok_or(InstructionLookupRecordError::MissingOperand),
    }
}

fn immediate_value(row: &TraceRow) -> Result<u8, InstructionLookupRecordError> {
    row.effects()
        .ordered_bus_events()
        .iter()
        .find(|event| {
            matches!(
                event.kind(),
                BusEventKind::ImmediateRead | BusEventKind::MemoryImmediateRead
            )
        })
        .map(|event| event.transcript_event().value)
        .ok_or(InstructionLookupRecordError::MissingOperand)
}

const fn is_data_read(kind: BusEventKind) -> bool {
    matches!(
        kind,
        BusEventKind::RomRead
            | BusEventKind::MemoryRead
            | BusEventKind::InputRead
            | BusEventKind::Mbc3OpenBusRead
            | BusEventKind::DmgMmioRead
            | BusEventKind::DmgJoypadRead
    )
}

fn output_operand_value(row: &TraceRow, operand: Operand8) -> Option<u8> {
    match operand {
        Operand8::Register(register) => Some(register8(row.after(), register)),
        Operand8::Immediate => None,
        Operand8::IndirectHl => row
            .effects()
            .ordered_bus_events()
            .iter()
            .rev()
            .find(|event| is_data_write(event.kind()))
            .map(|event| event.transcript_event().value),
    }
}

const fn is_data_write(kind: BusEventKind) -> bool {
    matches!(
        kind,
        BusEventKind::MemoryWrite
            | BusEventKind::OutputWrite
            | BusEventKind::Mbc3ControlWrite
            | BusEventKind::Mbc3IgnoredWrite
            | BusEventKind::DmgMmioWrite
    )
}

fn register8(state: VmState, register: Register8) -> u8 {
    let registers = state.cpu().registers();
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

fn register16(state: VmState, register: Register16) -> u16 {
    let registers = state.cpu().registers();
    match register {
        Register16::Bc => u16::from_be_bytes([registers.b, registers.c]),
        Register16::De => u16::from_be_bytes([registers.d, registers.e]),
        Register16::Hl => u16::from_be_bytes([registers.h, registers.l]),
        Register16::Sp => state.cpu().sp(),
    }
}

#[cfg(test)]
mod tests {
    use zksm83_core::{BusWitness, ExecutionLookupOutput, StepInput, VmState};
    use zksm83_isa::ExecutionLookupTable;
    use zksm83_memory::{MemoryImage, RomImage};

    use super::InstructionLookupRecords;
    use crate::TraceRow;

    #[test]
    fn accepted_alu_transition_produces_matching_lookup_record()
    -> Result<(), Box<dyn std::error::Error>> {
        let rom = RomImage::new(vec![0x80])?;
        let memory = MemoryImage::zeroed()?;
        let before = VmState::profile_initial(rom.root(), memory.root());
        let row = TraceRow::execute(before, StepInput::new(vec![BusWitness::Rom(rom.read(0)?)]))?;
        let records = InstructionLookupRecords::from_row(&row)?;
        let record = records.first().ok_or("missing lookup record")?;

        assert_eq!(record.query().table(), ExecutionLookupTable::Add8);
        assert_eq!(
            record.output(),
            ExecutionLookupOutput::ByteWithFlags {
                value: 0,
                flags: row.after().cpu().flags(),
            }
        );
        Ok(())
    }

    #[test]
    fn accepted_glue_only_transition_has_no_lookup_record() -> Result<(), Box<dyn std::error::Error>>
    {
        let rom = RomImage::new(vec![0x00])?;
        let memory = MemoryImage::zeroed()?;
        let before = VmState::profile_initial(rom.root(), memory.root());
        let row = TraceRow::execute(before, StepInput::new(vec![BusWitness::Rom(rom.read(0)?)]))?;

        assert!(InstructionLookupRecords::from_row(&row)?.is_empty());
        Ok(())
    }

    #[test]
    fn word_addition_uses_two_byte_table_queries() -> Result<(), Box<dyn std::error::Error>> {
        let rom = RomImage::new(vec![0x09])?;
        let memory = MemoryImage::zeroed()?;
        let before = VmState::profile_initial(rom.root(), memory.root());
        let row = TraceRow::execute(before, StepInput::new(vec![BusWitness::Rom(rom.read(0)?)]))?;

        let records = InstructionLookupRecords::from_row(&row)?;
        assert_eq!(records.len(), 2);
        for index in 0..records.len() {
            let record = records.get(index).ok_or("missing word-add lookup")?;
            assert_eq!(record.query().table(), ExecutionLookupTable::Add8);
        }
        Ok(())
    }
}
