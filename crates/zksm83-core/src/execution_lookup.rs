//! Pure execution-table queries shared by tracing and proof construction.

use thiserror::Error;
use zksm83_isa::{AluOperation, CbOperation, Condition, ExecutionLookupTable};

use crate::{Flags, alu};

/// A validated query into one verifier-fixed SM83 execution table.
///
/// Constructors enforce the domain of each table. The query is a pure value;
/// evaluating it performs no memory, device, transcript, or filesystem effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionLookupQuery {
    kind: QueryKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QueryKind {
    Binary8 {
        table: ExecutionLookupTable,
        left: u8,
        right: u8,
        carry: bool,
    },
    Unary8 {
        table: ExecutionLookupTable,
        value: u8,
        carry: bool,
    },
    RotateShift8 {
        value: u8,
        operation: RotateShiftOperation,
        carry: bool,
        zero_from_result: bool,
    },
    DecimalAdjust8 {
        accumulator: u8,
        flags: Flags,
    },
    Bit8 {
        table: ExecutionLookupTable,
        value: u8,
        bit: u8,
        carry: bool,
    },
    Condition {
        condition: Condition,
        flags: Flags,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum RotateShiftOperation {
    RotateLeftCircular,
    RotateRightCircular,
    RotateLeft,
    RotateRight,
    ShiftLeftArithmetic,
    ShiftRightArithmetic,
    SwapNibbles,
    ShiftRightLogical,
}

impl RotateShiftOperation {
    const fn from_cb(operation: CbOperation) -> Option<Self> {
        match operation {
            CbOperation::RotateLeftCircular => Some(Self::RotateLeftCircular),
            CbOperation::RotateRightCircular => Some(Self::RotateRightCircular),
            CbOperation::RotateLeft => Some(Self::RotateLeft),
            CbOperation::RotateRight => Some(Self::RotateRight),
            CbOperation::ShiftLeftArithmetic => Some(Self::ShiftLeftArithmetic),
            CbOperation::ShiftRightArithmetic => Some(Self::ShiftRightArithmetic),
            CbOperation::SwapNibbles => Some(Self::SwapNibbles),
            CbOperation::ShiftRightLogical => Some(Self::ShiftRightLogical),
            CbOperation::TestBit(_) | CbOperation::ResetBit(_) | CbOperation::SetBit(_) => None,
        }
    }

    const fn as_cb(self) -> CbOperation {
        match self {
            Self::RotateLeftCircular => CbOperation::RotateLeftCircular,
            Self::RotateRightCircular => CbOperation::RotateRightCircular,
            Self::RotateLeft => CbOperation::RotateLeft,
            Self::RotateRight => CbOperation::RotateRight,
            Self::ShiftLeftArithmetic => CbOperation::ShiftLeftArithmetic,
            Self::ShiftRightArithmetic => CbOperation::ShiftRightArithmetic,
            Self::SwapNibbles => CbOperation::SwapNibbles,
            Self::ShiftRightLogical => CbOperation::ShiftRightLogical,
        }
    }

    const fn code(self) -> u8 {
        self as u8
    }
}

/// Canonical output of one SM83 execution-table query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionLookupOutput {
    /// One byte and the complete resulting F register.
    ByteWithFlags {
        /// Result byte.
        value: u8,
        /// Resulting flags.
        flags: Flags,
    },
    /// One byte with flags preserved outside the lookup.
    Byte(u8),
    /// Boolean branch predicate.
    Predicate(bool),
}

impl ExecutionLookupOutput {
    /// Packs the table-specific output into one proof field scalar.
    ///
    /// The selected table fixes the variant, so no dynamic tag is encoded.
    #[must_use]
    pub const fn packed(self) -> u32 {
        match self {
            Self::ByteWithFlags { value, flags } => value as u32 | ((flags.byte() as u32) << 8),
            Self::Byte(value) => value as u32,
            Self::Predicate(value) => value as u32,
        }
    }
}

/// A query violated a verifier-fixed execution-table domain.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ExecutionLookupError {
    /// A bit operation selected an index outside zero through seven.
    #[error("SM83 execution lookup bit index {bit} exceeds seven")]
    InvalidBit {
        /// Rejected bit index.
        bit: u8,
    },
    /// A rotate/shift table query selected a bit-test or bit-mutation operation.
    #[error("SM83 execution lookup operation is not a rotate or shift")]
    InvalidRotateShift,
    /// A private query variant selected a table of the wrong algebraic shape.
    #[error("SM83 execution lookup table {table:?} does not match its query shape")]
    TableQueryMismatch {
        /// Rejected table identity.
        table: ExecutionLookupTable,
    },
    /// A table address exceeds the selected table's Boolean hypercube.
    #[error("SM83 execution lookup address {index} exceeds table {table:?}")]
    AddressOutOfRange {
        /// Selected table identity.
        table: ExecutionLookupTable,
        /// Rejected table address.
        index: u64,
    },
}

impl ExecutionLookupQuery {
    /// Constructs an eight-bit addition query.
    #[must_use]
    pub const fn add8(left: u8, right: u8, carry: bool) -> Self {
        Self::binary8(ExecutionLookupTable::Add8, left, right, carry)
    }

    /// Constructs an eight-bit subtraction query.
    #[must_use]
    pub const fn subtract8(left: u8, right: u8, borrow: bool) -> Self {
        Self::binary8(ExecutionLookupTable::Subtract8, left, right, borrow)
    }

    /// Constructs an eight-bit AND query.
    #[must_use]
    pub const fn and8(left: u8, right: u8) -> Self {
        Self::binary8(ExecutionLookupTable::And8, left, right, false)
    }

    /// Constructs an eight-bit XOR query.
    #[must_use]
    pub const fn xor8(left: u8, right: u8) -> Self {
        Self::binary8(ExecutionLookupTable::Xor8, left, right, false)
    }

    /// Constructs an eight-bit OR query.
    #[must_use]
    pub const fn or8(left: u8, right: u8) -> Self {
        Self::binary8(ExecutionLookupTable::Or8, left, right, false)
    }

    /// Constructs an eight-bit increment query with preserved carry.
    #[must_use]
    pub const fn increment8(value: u8, carry: bool) -> Self {
        Self::unary8(ExecutionLookupTable::Increment8, value, carry)
    }

    /// Constructs an eight-bit decrement query with preserved carry.
    #[must_use]
    pub const fn decrement8(value: u8, carry: bool) -> Self {
        Self::unary8(ExecutionLookupTable::Decrement8, value, carry)
    }

    /// Constructs a rotate/shift query.
    pub const fn rotate_shift8(
        value: u8,
        operation: CbOperation,
        carry: bool,
        zero_from_result: bool,
    ) -> Result<Self, ExecutionLookupError> {
        let Some(operation) = RotateShiftOperation::from_cb(operation) else {
            return Err(ExecutionLookupError::InvalidRotateShift);
        };
        Ok(Self {
            kind: QueryKind::RotateShift8 {
                value,
                operation,
                carry,
                zero_from_result,
            },
        })
    }

    /// Constructs a decimal-adjust query.
    #[must_use]
    pub const fn decimal_adjust8(accumulator: u8, flags: Flags) -> Self {
        Self {
            kind: QueryKind::DecimalAdjust8 { accumulator, flags },
        }
    }

    /// Constructs a bit-test query with preserved carry.
    pub const fn test_bit8(value: u8, bit: u8, carry: bool) -> Result<Self, ExecutionLookupError> {
        Self::bit8(ExecutionLookupTable::TestBit8, value, bit, carry)
    }

    /// Constructs a bit-reset query.
    pub const fn reset_bit8(value: u8, bit: u8) -> Result<Self, ExecutionLookupError> {
        Self::bit8(ExecutionLookupTable::ResetBit8, value, bit, false)
    }

    /// Constructs a bit-set query.
    pub const fn set_bit8(value: u8, bit: u8) -> Result<Self, ExecutionLookupError> {
        Self::bit8(ExecutionLookupTable::SetBit8, value, bit, false)
    }

    /// Constructs a conditional-control query.
    #[must_use]
    pub const fn condition(condition: Condition, flags: Flags) -> Self {
        Self {
            kind: QueryKind::Condition { condition, flags },
        }
    }

    /// Returns the verifier-fixed table selected by this query.
    #[must_use]
    pub const fn table(self) -> ExecutionLookupTable {
        match self.kind {
            QueryKind::Binary8 { table, .. }
            | QueryKind::Unary8 { table, .. }
            | QueryKind::Bit8 { table, .. } => table,
            QueryKind::RotateShift8 { .. } => ExecutionLookupTable::RotateShift8,
            QueryKind::DecimalAdjust8 { .. } => ExecutionLookupTable::DecimalAdjust8,
            QueryKind::Condition { .. } => ExecutionLookupTable::Condition,
        }
    }

    /// Returns the number of Boolean address variables for the selected table.
    #[must_use]
    pub const fn lookup_num_variables(self) -> usize {
        self.table().input_bit_count()
    }

    /// Returns the canonical little-endian bit-concatenated table address.
    #[must_use]
    pub const fn lookup_index(self) -> u64 {
        match self.kind {
            QueryKind::Binary8 {
                left, right, carry, ..
            } => (left as u64) | ((right as u64) << 8) | ((carry as u64) << 16),
            QueryKind::Unary8 { value, carry, .. } => (value as u64) | ((carry as u64) << 8),
            QueryKind::RotateShift8 {
                value,
                operation,
                carry,
                zero_from_result,
            } => {
                (value as u64)
                    | ((operation.code() as u64) << 8)
                    | ((carry as u64) << 11)
                    | ((zero_from_result as u64) << 12)
            }
            QueryKind::DecimalAdjust8 { accumulator, flags } => {
                (accumulator as u64) | (((flags.byte() >> 4) as u64) << 8)
            }
            QueryKind::Bit8 {
                value, bit, carry, ..
            } => (value as u64) | ((bit as u64) << 8) | ((carry as u64) << 11),
            QueryKind::Condition { condition, flags } => {
                ((flags.byte() >> 4) as u64) | ((condition_code(condition) as u64) << 4)
            }
        }
    }

    /// Evaluates the canonical table function at this query.
    pub fn evaluate(self) -> Result<ExecutionLookupOutput, ExecutionLookupError> {
        match self.kind {
            QueryKind::Binary8 {
                table,
                left,
                right,
                carry,
            } => evaluate_binary8(table, left, right, carry),
            QueryKind::Unary8 {
                table,
                value,
                carry,
            } => evaluate_unary8(table, value, carry),
            QueryKind::RotateShift8 {
                value,
                operation,
                carry,
                zero_from_result,
            } => {
                let result = alu::rotate_shift(operation.as_cb(), value, carry, zero_from_result)
                    .ok_or(ExecutionLookupError::InvalidRotateShift)?;
                Ok(ExecutionLookupOutput::ByteWithFlags {
                    value: result.value,
                    flags: result.flags,
                })
            }
            QueryKind::DecimalAdjust8 { accumulator, flags } => {
                let result = alu::decimal_adjust(accumulator, flags);
                Ok(ExecutionLookupOutput::ByteWithFlags {
                    value: result.value,
                    flags: result.flags,
                })
            }
            QueryKind::Bit8 {
                table,
                value,
                bit,
                carry,
            } => evaluate_bit8(table, value, bit, carry),
            QueryKind::Condition { condition, flags } => Ok(ExecutionLookupOutput::Predicate(
                condition_holds(flags, condition),
            )),
        }
    }

    /// Reconstructs the unique validated query at one table address.
    pub fn from_index(
        table: ExecutionLookupTable,
        index: u64,
    ) -> Result<Self, ExecutionLookupError> {
        let bit_count = table.input_bit_count();
        let shift = u32::try_from(bit_count)
            .map_err(|_| ExecutionLookupError::AddressOutOfRange { table, index })?;
        let bound = 1_u64
            .checked_shl(shift)
            .ok_or(ExecutionLookupError::AddressOutOfRange { table, index })?;
        if index >= bound {
            return Err(ExecutionLookupError::AddressOutOfRange { table, index });
        }
        let byte = |shift: u32| {
            u8::try_from((index >> shift) & u64::from(u8::MAX))
                .map_err(|_| ExecutionLookupError::AddressOutOfRange { table, index })
        };
        let bit = |shift: u32| (index >> shift) & 1 != 0;
        match table {
            ExecutionLookupTable::Add8 => Ok(Self::add8(byte(0)?, byte(8)?, bit(16))),
            ExecutionLookupTable::Subtract8 => Ok(Self::subtract8(byte(0)?, byte(8)?, bit(16))),
            ExecutionLookupTable::And8 => Ok(Self::and8(byte(0)?, byte(8)?)),
            ExecutionLookupTable::Xor8 => Ok(Self::xor8(byte(0)?, byte(8)?)),
            ExecutionLookupTable::Or8 => Ok(Self::or8(byte(0)?, byte(8)?)),
            ExecutionLookupTable::Increment8 => Ok(Self::increment8(byte(0)?, bit(8))),
            ExecutionLookupTable::Decrement8 => Ok(Self::decrement8(byte(0)?, bit(8))),
            ExecutionLookupTable::RotateShift8 => Self::rotate_shift8(
                byte(0)?,
                rotate_shift_from_code(byte(8)? & 0x07),
                bit(11),
                bit(12),
            ),
            ExecutionLookupTable::DecimalAdjust8 => Ok(Self::decimal_adjust8(
                byte(0)?,
                flags_from_nibble(byte(8)? & 0x0f),
            )),
            ExecutionLookupTable::TestBit8 => Self::test_bit8(byte(0)?, byte(8)? & 0x07, bit(11)),
            ExecutionLookupTable::ResetBit8 => Self::reset_bit8(byte(0)?, byte(8)? & 0x07),
            ExecutionLookupTable::SetBit8 => Self::set_bit8(byte(0)?, byte(8)? & 0x07),
            ExecutionLookupTable::Condition => Ok(Self::condition(
                condition_from_code(byte(4)? & 0x03),
                flags_from_nibble(byte(0)? & 0x0f),
            )),
        }
    }

    const fn binary8(table: ExecutionLookupTable, left: u8, right: u8, carry: bool) -> Self {
        Self {
            kind: QueryKind::Binary8 {
                table,
                left,
                right,
                carry,
            },
        }
    }

    const fn unary8(table: ExecutionLookupTable, value: u8, carry: bool) -> Self {
        Self {
            kind: QueryKind::Unary8 {
                table,
                value,
                carry,
            },
        }
    }

    const fn bit8(
        table: ExecutionLookupTable,
        value: u8,
        bit: u8,
        carry: bool,
    ) -> Result<Self, ExecutionLookupError> {
        if bit >= 8 {
            return Err(ExecutionLookupError::InvalidBit { bit });
        }
        Ok(Self {
            kind: QueryKind::Bit8 {
                table,
                value,
                bit,
                carry,
            },
        })
    }
}

/// Evaluates one verifier-fixed execution-table entry by canonical address.
pub fn evaluate_execution_table_entry(
    table: ExecutionLookupTable,
    index: u64,
) -> Result<u32, ExecutionLookupError> {
    ExecutionLookupQuery::from_index(table, index)?
        .evaluate()
        .map(ExecutionLookupOutput::packed)
}

fn evaluate_binary8(
    table: ExecutionLookupTable,
    left: u8,
    right: u8,
    carry: bool,
) -> Result<ExecutionLookupOutput, ExecutionLookupError> {
    let operation = match table {
        ExecutionLookupTable::Add8 => {
            if carry {
                AluOperation::AddCarry
            } else {
                AluOperation::Add
            }
        }
        ExecutionLookupTable::Subtract8 => {
            if carry {
                AluOperation::SubtractCarry
            } else {
                AluOperation::Subtract
            }
        }
        ExecutionLookupTable::And8 => AluOperation::And,
        ExecutionLookupTable::Xor8 => AluOperation::Xor,
        ExecutionLookupTable::Or8 => AluOperation::Or,
        _ => return Err(ExecutionLookupError::TableQueryMismatch { table }),
    };
    let before = Flags::from_bits(false, false, false, carry);
    let result = alu::apply_alu(operation, left, right, before);
    Ok(ExecutionLookupOutput::ByteWithFlags {
        value: result.value,
        flags: result.flags,
    })
}

fn evaluate_unary8(
    table: ExecutionLookupTable,
    value: u8,
    carry: bool,
) -> Result<ExecutionLookupOutput, ExecutionLookupError> {
    let before = Flags::from_bits(false, false, false, carry);
    let result = match table {
        ExecutionLookupTable::Increment8 => alu::increment(value, before),
        ExecutionLookupTable::Decrement8 => alu::decrement(value, before),
        _ => return Err(ExecutionLookupError::TableQueryMismatch { table }),
    };
    Ok(ExecutionLookupOutput::ByteWithFlags {
        value: result.value,
        flags: result.flags,
    })
}

fn evaluate_bit8(
    table: ExecutionLookupTable,
    value: u8,
    bit: u8,
    carry: bool,
) -> Result<ExecutionLookupOutput, ExecutionLookupError> {
    let mask = 1_u8 << bit;
    match table {
        ExecutionLookupTable::TestBit8 => Ok(ExecutionLookupOutput::ByteWithFlags {
            value,
            flags: Flags::from_bits(value & mask == 0, false, true, carry),
        }),
        ExecutionLookupTable::ResetBit8 => Ok(ExecutionLookupOutput::Byte(value & !mask)),
        ExecutionLookupTable::SetBit8 => Ok(ExecutionLookupOutput::Byte(value | mask)),
        _ => Err(ExecutionLookupError::TableQueryMismatch { table }),
    }
}

const fn condition_holds(flags: Flags, condition: Condition) -> bool {
    match condition {
        Condition::NotZero => !flags.zero(),
        Condition::Zero => flags.zero(),
        Condition::NotCarry => !flags.carry(),
        Condition::Carry => flags.carry(),
    }
}

const fn condition_code(condition: Condition) -> u8 {
    match condition {
        Condition::NotZero => 0,
        Condition::Zero => 1,
        Condition::NotCarry => 2,
        Condition::Carry => 3,
    }
}

const fn flags_from_nibble(nibble: u8) -> Flags {
    Flags::from_bits(
        nibble & 0x08 != 0,
        nibble & 0x04 != 0,
        nibble & 0x02 != 0,
        nibble & 0x01 != 0,
    )
}

const fn rotate_shift_from_code(code: u8) -> CbOperation {
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

const fn condition_from_code(code: u8) -> Condition {
    match code {
        0 => Condition::NotZero,
        1 => Condition::Zero,
        2 => Condition::NotCarry,
        _ => Condition::Carry,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ExecutionLookupError, ExecutionLookupOutput, ExecutionLookupQuery,
        evaluate_execution_table_entry,
    };
    use crate::Flags;
    use zksm83_isa::{CbOperation, Condition};

    #[test]
    fn query_indices_fit_their_declared_hypercubes() -> Result<(), ExecutionLookupError> {
        let queries = [
            ExecutionLookupQuery::add8(u8::MAX, u8::MAX, true),
            ExecutionLookupQuery::subtract8(u8::MAX, u8::MAX, true),
            ExecutionLookupQuery::and8(u8::MAX, u8::MAX),
            ExecutionLookupQuery::xor8(u8::MAX, u8::MAX),
            ExecutionLookupQuery::or8(u8::MAX, u8::MAX),
            ExecutionLookupQuery::increment8(u8::MAX, true),
            ExecutionLookupQuery::decrement8(u8::MAX, true),
            ExecutionLookupQuery::rotate_shift8(
                u8::MAX,
                CbOperation::ShiftRightLogical,
                true,
                true,
            )?,
            ExecutionLookupQuery::decimal_adjust8(
                u8::MAX,
                Flags::from_bits(true, true, true, true),
            ),
            ExecutionLookupQuery::test_bit8(u8::MAX, 7, true)?,
            ExecutionLookupQuery::reset_bit8(u8::MAX, 7)?,
            ExecutionLookupQuery::set_bit8(u8::MAX, 7)?,
            ExecutionLookupQuery::condition(
                Condition::Carry,
                Flags::from_bits(true, true, true, true),
            ),
        ];
        for query in queries {
            assert!(query.lookup_index() < (1_u64 << query.lookup_num_variables()));
            assert_eq!(
                ExecutionLookupQuery::from_index(query.table(), query.lookup_index())?,
                query
            );
            assert_eq!(
                evaluate_execution_table_entry(query.table(), query.lookup_index())?,
                query.evaluate()?.packed()
            );
        }
        Ok(())
    }

    #[test]
    fn arithmetic_queries_return_result_and_flags() -> Result<(), ExecutionLookupError> {
        let add = ExecutionLookupQuery::add8(0xff, 0x01, false).evaluate()?;
        assert_eq!(
            add,
            ExecutionLookupOutput::ByteWithFlags {
                value: 0,
                flags: Flags::from_bits(true, false, true, true),
            }
        );
        let subtract = ExecutionLookupQuery::subtract8(0, 1, false).evaluate()?;
        assert_eq!(
            subtract,
            ExecutionLookupOutput::ByteWithFlags {
                value: 0xff,
                flags: Flags::from_bits(false, true, true, true),
            }
        );
        Ok(())
    }

    #[test]
    fn rotate_and_bit_queries_reject_cross_family_operations() {
        assert_eq!(
            ExecutionLookupQuery::rotate_shift8(0, CbOperation::TestBit(0), false, true,),
            Err(ExecutionLookupError::InvalidRotateShift)
        );
        assert_eq!(
            ExecutionLookupQuery::test_bit8(0, 8, false),
            Err(ExecutionLookupError::InvalidBit { bit: 8 })
        );
    }
}
