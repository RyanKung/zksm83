//! Fixed-shape execution-lookup projection for packed SM83 blocks.

pub(crate) mod proof;

use akita_pcs::Ring;
use thiserror::Error;
use zksm83_core::evaluate_execution_table_entry;
use zksm83_isa::ExecutionLookupTable;
use zksm83_trace::{
    BASIC_BLOCK_INSTRUCTION_BOUND, BasicBlock, InstructionLookupRecordError,
    InstructionLookupRecords,
};

use crate::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_ISA_CONTROL_COLUMN_COUNT, BLOCK_MEMORY_COLUMN_COUNT,
    ConstraintOutput, ISA_ARGUMENT_ZERO_BITS_START, ISA_OPERATION_BITS_START, NativeField,
    UNIFORM_ROW_COUNT, UniformError, UniformRelation, block_isa::lane_output_values,
    block_metadata, trace::PACKED_CPU_AUX_COLUMN_COUNT,
};

pub use proof::{ExecutionLookupProof, ExecutionLookupProofError};

/// Maximum address width of any byte-level SM83 execution table.
pub const EXECUTION_LOOKUP_INPUT_BIT_COUNT: usize = 17;
/// Address bits in the aligned compact union of every execution table.
pub const EXECUTION_LOOKUP_ADDRESS_BIT_COUNT: usize = 19;
/// Committed bits for the byte result followed by C, H, N, and Z.
pub const EXECUTION_LOOKUP_OUTPUT_BIT_COUNT: usize = 12;
/// Maximum table queries emitted by one SM83 instruction.
pub const EXECUTION_LOOKUPS_PER_INSTRUCTION: usize = 2;
/// Lookup slots carried by one packed block row.
pub const EXECUTION_LOOKUPS_PER_BLOCK: usize =
    BASIC_BLOCK_INSTRUCTION_BOUND * EXECUTION_LOOKUPS_PER_INSTRUCTION;

const LOOKUP_SELECTOR_OFFSET: usize = 0;
const LOOKUP_ADDRESS_BITS_OFFSET: usize = LOOKUP_SELECTOR_OFFSET + 1;
const LOOKUP_OUTPUT_BITS_OFFSET: usize =
    LOOKUP_ADDRESS_BITS_OFFSET + EXECUTION_LOOKUP_ADDRESS_BIT_COUNT;
const EXECUTION_LOOKUP_SLOT_WIDTH: usize =
    LOOKUP_OUTPUT_BITS_OFFSET + EXECUTION_LOOKUP_OUTPUT_BIT_COUNT;
/// Number of columns in the packed execution-lookup projection.
pub const EXECUTION_LOOKUP_COLUMN_COUNT: usize =
    EXECUTION_LOOKUPS_PER_BLOCK * EXECUTION_LOOKUP_SLOT_WIDTH;
/// Identities enforcing selectors, Boolean addresses, routing, and canonical padding.
pub const EXECUTION_LOOKUP_WELL_FORMED_CONSTRAINT_COUNT: usize = EXECUTION_LOOKUPS_PER_BLOCK * 64;
const EXECUTION_LOOKUP_TABLE_ROW_COUNT: u32 = 1 << EXECUTION_LOOKUP_ADDRESS_BIT_COUNT;
pub(crate) const EXECUTION_LOOKUP_OUTPUT_BIT_SHIFTS: [u32; EXECUTION_LOOKUP_OUTPUT_BIT_COUNT] =
    [0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15];

const _: () = assert!(EXECUTION_LOOKUPS_PER_BLOCK == 8);
const _: () = assert!(EXECUTION_LOOKUP_SLOT_WIDTH == 32);
const _: () = assert!(EXECUTION_LOOKUP_COLUMN_COUNT == 256);

/// Canonical columns for one conditional lookup in the packed projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionLookupColumns {
    selector: usize,
    address_bits: [usize; EXECUTION_LOOKUP_ADDRESS_BIT_COUNT],
    output_bits: [usize; EXECUTION_LOOKUP_OUTPUT_BIT_COUNT],
}

/// Fixed-row execution-lookup witness derived from accepted trace rows.
#[derive(Debug)]
pub struct ExecutionLookupWitness {
    columns: Vec<Vec<u64>>,
    active_block_count: usize,
    lookup_count: usize,
}

/// Low-degree shape and static-routing checks for packed execution lookups.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExecutionLookupWellFormedRelation;

/// Failure to construct the packed execution-lookup projection.
#[derive(Debug, Error)]
pub enum ExecutionLookupWitnessError {
    /// No packed blocks were supplied.
    #[error("packed execution lookup witness is empty")]
    Empty,
    /// An accepted transition could not be represented by its static lookup plan.
    #[error(transparent)]
    Record(#[from] InstructionLookupRecordError),
    /// A table query exceeded the compact address space.
    #[error("SM83 execution lookup address exceeds the 19-bit compact table")]
    AddressOutOfRange,
    /// Packed rows or columns violated their fixed layout.
    #[error("packed execution lookup witness violated its typed layout")]
    Layout,
}

impl ExecutionLookupColumns {
    /// Returns the Boolean selector for an active lookup.
    #[must_use]
    pub const fn selector(self) -> usize {
        self.selector
    }

    /// Returns the compact table address bits in least-significant-bit-first order.
    #[must_use]
    pub const fn address_bits(self) -> [usize; EXECUTION_LOOKUP_ADDRESS_BIT_COUNT] {
        self.address_bits
    }

    /// Returns byte-result bits followed by C, H, N, and Z.
    #[must_use]
    pub const fn output_bits(self) -> [usize; EXECUTION_LOOKUP_OUTPUT_BIT_COUNT] {
        self.output_bits
    }
}

impl ExecutionLookupWitness {
    /// Encodes every block into eight fixed lookup slots and canonical padding.
    pub fn from_blocks(blocks: &[BasicBlock]) -> Result<Self, ExecutionLookupWitnessError> {
        if blocks.is_empty() {
            return Err(ExecutionLookupWitnessError::Empty);
        }
        if blocks.len() > UNIFORM_ROW_COUNT {
            return Err(ExecutionLookupWitnessError::Layout);
        }
        let mut columns = (0..EXECUTION_LOOKUP_COLUMN_COUNT)
            .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
            .collect::<Vec<_>>();
        let mut lookup_count = 0_usize;
        for block in blocks {
            let mut packed = [0_u64; EXECUTION_LOOKUP_COLUMN_COUNT];
            let block_lookups = append_block(&mut packed, block)?;
            lookup_count = lookup_count
                .checked_add(block_lookups)
                .ok_or(ExecutionLookupWitnessError::Layout)?;
            for (column, value) in columns.iter_mut().zip(packed) {
                column.push(value);
            }
        }
        for column in &mut columns {
            column.resize(UNIFORM_ROW_COUNT, 0);
        }
        Ok(Self {
            columns,
            active_block_count: blocks.len(),
            lookup_count,
        })
    }

    /// Returns all fixed lookup columns in slot-major order.
    #[must_use]
    pub fn columns(&self) -> &[Vec<u64>] {
        &self.columns
    }

    /// Returns the number of non-padding block rows.
    #[must_use]
    pub const fn active_block_count(&self) -> usize {
        self.active_block_count
    }

    /// Returns the number of active execution-table queries.
    #[must_use]
    pub const fn lookup_count(&self) -> usize {
        self.lookup_count
    }

    /// Returns the relative layout for one lane and byte-query index.
    pub fn lookup_columns(
        lane: usize,
        query: usize,
    ) -> Result<ExecutionLookupColumns, ExecutionLookupWitnessError> {
        let slot = lane
            .checked_mul(EXECUTION_LOOKUPS_PER_INSTRUCTION)
            .and_then(|value| value.checked_add(query))
            .filter(|value| *value < EXECUTION_LOOKUPS_PER_BLOCK)
            .ok_or(ExecutionLookupWitnessError::Layout)?;
        let start = slot
            .checked_mul(EXECUTION_LOOKUP_SLOT_WIDTH)
            .ok_or(ExecutionLookupWitnessError::Layout)?;
        let selector = start
            .checked_add(LOOKUP_SELECTOR_OFFSET)
            .ok_or(ExecutionLookupWitnessError::Layout)?;
        let mut address_bits = [0_usize; EXECUTION_LOOKUP_ADDRESS_BIT_COUNT];
        for (bit, column) in address_bits.iter_mut().enumerate() {
            *column = start
                .checked_add(LOOKUP_ADDRESS_BITS_OFFSET)
                .and_then(|value| value.checked_add(bit))
                .ok_or(ExecutionLookupWitnessError::Layout)?;
        }
        let mut output_bits = [0_usize; EXECUTION_LOOKUP_OUTPUT_BIT_COUNT];
        for (bit, column) in output_bits.iter_mut().enumerate() {
            *column = start
                .checked_add(LOOKUP_OUTPUT_BITS_OFFSET)
                .and_then(|value| value.checked_add(bit))
                .ok_or(ExecutionLookupWitnessError::Layout)?;
        }
        Ok(ExecutionLookupColumns {
            selector,
            address_bits,
            output_bits,
        })
    }

    pub(crate) fn lookup_columns_at(
        start: usize,
        lane: usize,
        query: usize,
    ) -> Result<ExecutionLookupColumns, ExecutionLookupWitnessError> {
        let relative = Self::lookup_columns(lane, query)?;
        let mut address_bits = relative.address_bits();
        for column in &mut address_bits {
            *column = start
                .checked_add(*column)
                .ok_or(ExecutionLookupWitnessError::Layout)?;
        }
        let mut output_bits = relative.output_bits();
        for column in &mut output_bits {
            *column = start
                .checked_add(*column)
                .ok_or(ExecutionLookupWitnessError::Layout)?;
        }
        Ok(ExecutionLookupColumns {
            selector: start
                .checked_add(relative.selector())
                .ok_or(ExecutionLookupWitnessError::Layout)?,
            address_bits,
            output_bits,
        })
    }

    pub(crate) fn into_columns(self) -> Vec<Vec<u64>> {
        self.columns
    }
}

impl UniformRelation for ExecutionLookupWellFormedRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-execution-lookup-well-formed/v1"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        [
            EXECUTION_LOOKUP_COLUMN_COUNT as u64,
            EXECUTION_LOOKUP_WELL_FORMED_CONSTRAINT_COUNT as u64,
            EXECUTION_LOOKUP_ADDRESS_BIT_COUNT as u64,
            EXECUTION_LOOKUPS_PER_BLOCK as u64,
        ]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect()
    }

    fn column_count(&self) -> usize {
        crate::BLOCK_CPU_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        EXECUTION_LOOKUP_WELL_FORMED_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        12
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        constrain_execution_lookup_well_formed(row, constraints)
    }
}

/// Evaluates the total compact union of verifier-fixed execution tables.
///
/// Aligned gaps map to zero. Active queries are separately constrained to the
/// table range selected by ISA metadata; the zero fill makes the hypercube total.
#[must_use]
pub fn evaluate_packed_execution_table_entry(address: u32) -> u32 {
    if address >= EXECUTION_LOOKUP_TABLE_ROW_COUNT {
        return 0;
    }
    for table in ExecutionLookupTable::ALL {
        let Some(end) = table.packed_offset().checked_add(table.row_count()) else {
            return 0;
        };
        if (table.packed_offset()..end).contains(&address) {
            return evaluate_execution_table_entry(
                table,
                u64::from(address - table.packed_offset()),
            )
            .map_or(0, |output| output);
        }
    }
    0
}

fn append_block(
    packed: &mut [u64; EXECUTION_LOOKUP_COLUMN_COUNT],
    block: &BasicBlock,
) -> Result<usize, ExecutionLookupWitnessError> {
    if block.instruction_count() > BASIC_BLOCK_INSTRUCTION_BOUND {
        return Err(ExecutionLookupWitnessError::Layout);
    }
    let mut lookup_count = 0_usize;
    for (lane, row) in block.rows().enumerate() {
        if lane >= BASIC_BLOCK_INSTRUCTION_BOUND {
            if block.instruction_count() == 0 {
                continue;
            }
            return Err(ExecutionLookupWitnessError::Layout);
        }
        let records = InstructionLookupRecords::from_row(row)?;
        for query in 0..records.len() {
            let record = records
                .get(query)
                .ok_or(ExecutionLookupWitnessError::Layout)?;
            append_record(
                packed,
                lane,
                query,
                record.query().table(),
                record.query().lookup_index(),
                u64::from(record.output().packed()),
            )?;
            lookup_count = lookup_count
                .checked_add(1)
                .ok_or(ExecutionLookupWitnessError::Layout)?;
        }
    }
    Ok(lookup_count)
}

fn append_record(
    packed: &mut [u64; EXECUTION_LOOKUP_COLUMN_COUNT],
    lane: usize,
    query: usize,
    table: ExecutionLookupTable,
    query_index: u64,
    output: u64,
) -> Result<(), ExecutionLookupWitnessError> {
    let layout = ExecutionLookupWitness::lookup_columns(lane, query)?;
    set(packed, layout.selector(), 1)?;
    let address = u64::from(table.packed_offset())
        .checked_add(query_index)
        .ok_or(ExecutionLookupWitnessError::AddressOutOfRange)?;
    if address >= u64::from(EXECUTION_LOOKUP_TABLE_ROW_COUNT) {
        return Err(ExecutionLookupWitnessError::AddressOutOfRange);
    }
    for (bit, column) in layout.address_bits().into_iter().enumerate() {
        let shift =
            u32::try_from(bit).map_err(|_| ExecutionLookupWitnessError::AddressOutOfRange)?;
        set(packed, column, address >> shift & 1)?;
    }
    for (column, shift) in layout
        .output_bits()
        .into_iter()
        .zip(EXECUTION_LOOKUP_OUTPUT_BIT_SHIFTS)
    {
        set(packed, column, output >> shift & 1)?;
    }
    Ok(())
}

fn set(row: &mut [u64], column: usize, value: u64) -> Result<(), ExecutionLookupWitnessError> {
    *row.get_mut(column)
        .ok_or(ExecutionLookupWitnessError::Layout)? = value;
    Ok(())
}

pub(crate) fn constrain_execution_lookup_well_formed(
    row: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if row.len() != crate::BLOCK_CPU_COLUMN_COUNT
        || constraints.len() != EXECUTION_LOOKUP_WELL_FORMED_CONSTRAINT_COUNT
    {
        return Err(UniformError::Shape);
    }
    let isa = row
        .get(BLOCK_CONTROL_COLUMN_COUNT..BLOCK_ISA_CONTROL_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let mut sink = ConstraintSink::new(constraints);
    for lane in 0..BASIC_BLOCK_INSTRUCTION_BOUND {
        let active = block_metadata::lane_value(row, lane)?;
        let tables = table_selectors(isa, lane, active)?;
        constrain_lookup_slot(row, lane, 0, &tables, &mut sink)?;
        let mut second = [NativeField::from_u64(0); 13];
        let double = active
            * (operation_selector(isa, lane, 5)?
                + operation_selector(isa, lane, 22)?
                + operation_selector(isa, lane, 23)?);
        *second.first_mut().ok_or(UniformError::Shape)? = double;
        constrain_lookup_slot(row, lane, 1, &second, &mut sink)?;
    }
    sink.finish()
}

fn constrain_lookup_slot(
    row: &[NativeField],
    lane: usize,
    query: usize,
    tables: &[NativeField; 13],
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let layout = absolute_lookup_columns(lane, query)?;
    let selector = value(row, layout.selector())?;
    let expected_selector = tables
        .iter()
        .copied()
        .fold(NativeField::from_u64(0), |sum, table| sum + table);
    sink.push(selector * (selector - one))?;
    sink.push(selector - expected_selector)?;
    let address_bits = layout.address_bits();
    for column in address_bits {
        let bit = value(row, column)?;
        sink.push(bit * (bit - one))?;
    }
    for address_bit in 0..EXECUTION_LOOKUP_ADDRESS_BIT_COUNT {
        let allowed = ExecutionLookupTable::ALL.iter().zip(tables).fold(
            NativeField::from_u64(0),
            |sum, (table, selected)| {
                if address_bit < table.input_bit_count() {
                    sum + *selected
                } else {
                    sum
                }
            },
        );
        let fixed = ExecutionLookupTable::ALL.iter().zip(tables).fold(
            NativeField::from_u64(0),
            |sum, (table, selected)| {
                if address_bit < table.input_bit_count() {
                    sum
                } else {
                    let bit = table.packed_offset() >> address_bit & 1;
                    sum + *selected * NativeField::from_u64(u64::from(bit))
                }
            },
        );
        let column = address_bits
            .get(address_bit)
            .copied()
            .ok_or(UniformError::Shape)?;
        sink.push((one - allowed) * value(row, column)? - fixed)?;
    }
    for column in layout.output_bits() {
        let bit = value(row, column)?;
        sink.push(bit * (bit - one))?;
        sink.push((one - selector) * bit)?;
    }
    Ok(())
}

pub(crate) fn absolute_lookup_columns(
    lane: usize,
    query: usize,
) -> Result<ExecutionLookupColumns, UniformError> {
    let start = BLOCK_MEMORY_COLUMN_COUNT
        .checked_add(PACKED_CPU_AUX_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    ExecutionLookupWitness::lookup_columns_at(start, lane, query).map_err(|_| UniformError::Shape)
}

fn table_selectors(
    isa: &[NativeField],
    lane: usize,
    active: NativeField,
) -> Result<[NativeField; 13], UniformError> {
    let mut tables = [NativeField::from_u64(0); 13];
    let alu = operation_selector(isa, lane, 19)?;
    let argument = |code| argument_zero_selector(isa, lane, code);
    let add = operation_selector(isa, lane, 5)?
        + operation_selector(isa, lane, 22)?
        + operation_selector(isa, lane, 23)?
        + alu * (argument(0)? + argument(1)?);
    let subtract = alu * (argument(2)? + argument(3)? + argument(7)?);
    let condition_argument = argument(1)? + argument(2)? + argument(3)? + argument(4)?;
    let condition = (operation_selector(isa, lane, 3)?
        + operation_selector(isa, lane, 20)?
        + operation_selector(isa, lane, 28)?
        + operation_selector(isa, lane, 34)?)
        * condition_argument;
    let values = [
        add,
        subtract,
        alu * argument(4)?,
        alu * argument(5)?,
        alu * argument(6)?,
        operation_selector(isa, lane, 9)?,
        operation_selector(isa, lane, 10)?,
        operation_selector(isa, lane, 12)? + operation_selector(isa, lane, 37)?,
        operation_selector(isa, lane, 13)?,
        operation_selector(isa, lane, 38)?,
        operation_selector(isa, lane, 39)?,
        operation_selector(isa, lane, 40)?,
        condition,
    ];
    for (target, selected) in tables.iter_mut().zip(values) {
        *target = active * selected;
    }
    Ok(tables)
}

fn operation_selector(
    isa: &[NativeField],
    lane: usize,
    code: u8,
) -> Result<NativeField, UniformError> {
    bit_selector(
        lane_output_values(isa, lane, ISA_OPERATION_BITS_START, 6)?,
        code,
    )
}

fn argument_zero_selector(
    isa: &[NativeField],
    lane: usize,
    code: u8,
) -> Result<NativeField, UniformError> {
    bit_selector(
        lane_output_values(isa, lane, ISA_ARGUMENT_ZERO_BITS_START, 3)?,
        code,
    )
}

fn bit_selector(bits: &[NativeField], code: u8) -> Result<NativeField, UniformError> {
    let mut selected = NativeField::from_u64(1);
    let one = NativeField::from_u64(1);
    for (bit, actual) in bits.iter().copied().enumerate() {
        let shift = u32::try_from(bit).map_err(|_| UniformError::Shape)?;
        selected *= if code >> shift & 1 == 1 {
            actual
        } else {
            one - actual
        };
    }
    Ok(selected)
}

fn value(row: &[NativeField], column: usize) -> Result<NativeField, UniformError> {
    row.get(column).copied().ok_or(UniformError::Shape)
}

struct ConstraintSink<'a> {
    constraints: &'a mut [NativeField],
    next: usize,
}

impl<'a> ConstraintSink<'a> {
    const fn new(constraints: &'a mut [NativeField]) -> Self {
        Self {
            constraints,
            next: 0,
        }
    }

    fn push(&mut self, constraint: NativeField) -> Result<(), UniformError> {
        *self
            .constraints
            .get_mut(self.next)
            .ok_or(UniformError::Shape)? = constraint;
        self.next = self.next.checked_add(1).ok_or(UniformError::Shape)?;
        Ok(())
    }

    fn finish(self) -> Result<(), UniformError> {
        if self.next == self.constraints.len() {
            Ok(())
        } else {
            Err(UniformError::Shape)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EXECUTION_LOOKUP_ADDRESS_BIT_COUNT, EXECUTION_LOOKUP_OUTPUT_BIT_SHIFTS,
        ExecutionLookupWellFormedRelation, ExecutionLookupWitness,
        evaluate_packed_execution_table_entry,
    };
    use crate::{BlockCpuWitness, block_test_support::lookup_blocks, validate_uniform_witness};

    #[test]
    fn packed_lookup_projection_encodes_byte_and_word_operations()
    -> Result<(), Box<dyn std::error::Error>> {
        let add_a_b = lookup_blocks(&[0x80, 0x00, 0x00, 0x00], 1)?;
        let byte_witness = ExecutionLookupWitness::from_blocks(&add_a_b)?;
        assert_eq!(byte_witness.lookup_count(), 1);

        let add_hl_bc = lookup_blocks(&[0x09, 0x00, 0x00, 0x00], 1)?;
        let word_witness = ExecutionLookupWitness::from_blocks(&add_hl_bc)?;
        assert_eq!(word_witness.lookup_count(), 2);
        for query in 0..2 {
            let layout = ExecutionLookupWitness::lookup_columns(0, query)?;
            assert_eq!(first_row_value(&word_witness, layout.selector())?, 1);
            let address = layout.address_bits().into_iter().enumerate().try_fold(
                0_u32,
                |value, (bit, column)| {
                    let shift = u32::try_from(bit)?;
                    Ok::<_, Box<dyn std::error::Error>>(
                        value | u32::try_from(first_row_value(&word_witness, column)?)? << shift,
                    )
                },
            )?;
            let output = layout
                .output_bits()
                .into_iter()
                .zip(EXECUTION_LOOKUP_OUTPUT_BIT_SHIFTS)
                .try_fold(0_u64, |value, (column, shift)| {
                    Ok::<_, Box<dyn std::error::Error>>(
                        value | first_row_value(&word_witness, column)? << shift,
                    )
                })?;
            assert_eq!(
                u64::from(evaluate_packed_execution_table_entry(address)),
                output
            );
        }
        assert_eq!(EXECUTION_LOOKUP_ADDRESS_BIT_COUNT, 19);
        Ok(())
    }

    #[test]
    fn packed_lookup_projection_satisfies_static_routing_relation()
    -> Result<(), Box<dyn std::error::Error>> {
        let blocks = lookup_blocks(&[0x80, 0x09, 0x00, 0x00], 2)?;
        let witness = BlockCpuWitness::from_blocks(&blocks)?;
        validate_uniform_witness(&ExecutionLookupWellFormedRelation, witness.columns())?;
        Ok(())
    }

    fn first_row_value(
        witness: &ExecutionLookupWitness,
        column: usize,
    ) -> Result<u64, &'static str> {
        witness
            .columns()
            .get(column)
            .and_then(|values| values.first())
            .copied()
            .ok_or("missing execution lookup witness cell")
    }
}
