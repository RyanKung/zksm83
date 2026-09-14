//! Canonical fixed-row native witness columns derived from validated SM83 rows.

mod bus;
mod cpu_semantic;
mod daa;
pub(crate) mod device;
mod memory;
pub(crate) mod mode;
mod padding;
#[cfg(test)]
mod tests;
mod word;

use thiserror::Error;
use zksm83_core::{DmgInterrupt, StepKind, VmState};
use zksm83_trace::{TraceRow, Witness};

use crate::{
    ISA_ADDRESS_BIT_COUNT, ISA_OUTPUT_COUNT, ISA_PADDING_ADDRESS, ISA_TABLE_ROW_COUNT,
    ROM_ADDRESS_BIT_COUNT, STATE_SCALAR_COUNT, UNIFORM_ROW_COUNT, encode_state_scalars,
    fixed_isa_table,
};
pub(crate) use cpu_semantic::{
    CPU_BOUNDARY_AUX_COLUMN_COUNT, CPU_LANE_AUX_COLUMN_COUNT, CPU_SEMANTIC_AUX_COLUMN_COUNT,
    CpuSemanticAuxEncoder, PACKED_CPU_AUX_COLUMN_COUNT, PACKED_CPU_DERIVED_SCALAR_COUNT,
    cpu_semantic_legacy_column, packed_cpu_aux_offset, packed_cpu_derived_scalar,
    packed_cpu_derived_scalar_at,
};
pub use device::{
    TRACE_AFTER_DMA_BITS_START, TRACE_AFTER_INTERRUPT_ENABLE_BITS_START,
    TRACE_AFTER_INTERRUPT_REQUEST_BITS_START, TRACE_BEFORE_DMA_BITS_START,
    TRACE_BEFORE_INTERRUPT_ENABLE_BITS_START, TRACE_BEFORE_INTERRUPT_REQUEST_BITS_START,
    TRACE_BEFORE_JOYPAD_BITS_START, TRACE_JOYPAD_FALL_NONE_START, TRACE_JOYPAD_IF_BIT_START,
    TRACE_JOYPAD_STAGE_BITS_START, TRACE_JOYPAD_STAGE_WIDTH, TRACE_JOYPAD_WRITE_START,
    TRACE_PENDING_INTERRUPT,
};
use mode::TraceMode;

/// First column of the row's pre-state boundary.
pub const TRACE_BEFORE_STATE_START: usize = 0;
/// First column of the row's post-state boundary.
pub const TRACE_AFTER_STATE_START: usize = TRACE_BEFORE_STATE_START + STATE_SCALAR_COUNT;
/// Boolean selector for a real transition rather than canonical padding.
pub const TRACE_ACTIVE: usize = TRACE_AFTER_STATE_START + STATE_SCALAR_COUNT;
/// First column of seven one-hot transition modes, including padding mode six.
pub const TRACE_MODE_START: usize = TRACE_ACTIVE + 1;
/// Number of one-hot transition modes, including one canonical padding mode.
pub const TRACE_MODE_COUNT: usize = TraceMode::COUNT;
/// First column of five one-hot interrupt sources.
pub const TRACE_INTERRUPT_START: usize = TRACE_MODE_START + TRACE_MODE_COUNT;
/// Number of priority-ordered DMG interrupt-source selectors.
pub const TRACE_INTERRUPT_COUNT: usize = 5;
/// Exact `m_cycles` increment for this row.
pub const TRACE_CYCLE_INCREMENT: usize = TRACE_INTERRUPT_START + TRACE_INTERRUPT_COUNT;
/// Boolean conditional-control decision for instruction rows.
pub const TRACE_BRANCH_TAKEN: usize = TRACE_CYCLE_INCREMENT + 1;
/// First least-significant-bit-first ISA lookup address column.
pub const TRACE_ISA_ADDRESS_START: usize = TRACE_BRANCH_TAKEN + 1;
/// First fixed-ISA lookup output column.
pub const TRACE_ISA_OUTPUT_START: usize = TRACE_ISA_ADDRESS_START + ISA_ADDRESS_BIT_COUNT;
/// First column of the five canonical bus-event slots.
pub const TRACE_BUS_START: usize = TRACE_ISA_OUTPUT_START + ISA_OUTPUT_COUNT;
/// Maximum bus events admitted by one native transition row.
pub const TRACE_BUS_SLOTS: usize = 5;
/// Number of Boolean kind bits in each bus slot.
pub const TRACE_BUS_KIND_BITS: usize = 5;
/// Number of scalar fields in the canonical bus tuple.
pub const TRACE_BUS_TUPLE_FIELDS: usize = 6;
/// Width of one bus slot: active, kind bits, then canonical tuple.
pub const TRACE_BUS_SLOT_WIDTH: usize = 1 + TRACE_BUS_KIND_BITS + TRACE_BUS_TUPLE_FIELDS;
/// First bit column decomposing the eight before-state CPU byte limbs.
pub const TRACE_BEFORE_CPU_BYTE_BITS_START: usize =
    TRACE_BUS_START + TRACE_BUS_SLOTS * TRACE_BUS_SLOT_WIDTH;
/// First bit column decomposing the eight after-state CPU byte limbs.
pub const TRACE_AFTER_CPU_BYTE_BITS_START: usize = TRACE_BEFORE_CPU_BYTE_BITS_START + 8 * 8;
/// First bit column decomposing the before-state PC.
pub const TRACE_BEFORE_PC_BITS_START: usize = TRACE_AFTER_CPU_BYTE_BITS_START + 8 * 8;
/// First bit column decomposing the after-state PC.
pub const TRACE_AFTER_PC_BITS_START: usize = TRACE_BEFORE_PC_BITS_START + 16;
/// First bit column decomposing the before-state SP.
pub const TRACE_BEFORE_SP_BITS_START: usize = TRACE_AFTER_PC_BITS_START + 16;
/// First bit column decomposing the after-state SP.
pub const TRACE_AFTER_SP_BITS_START: usize = TRACE_BEFORE_SP_BITS_START + 16;
/// Committed byte selected as the arithmetic or load source operand.
pub const TRACE_OPERAND_VALUE: usize = TRACE_AFTER_SP_BITS_START + 16;
/// Committed byte produced by the selected arithmetic operation.
pub const TRACE_RESULT_VALUE: usize = TRACE_OPERAND_VALUE + 1;
/// First bit column decomposing the selected operand byte.
pub const TRACE_OPERAND_BITS_START: usize = TRACE_RESULT_VALUE + 1;
/// First bit column decomposing the arithmetic result byte.
pub const TRACE_RESULT_BITS_START: usize = TRACE_OPERAND_BITS_START + 8;
/// Boolean carry or borrow witness for byte arithmetic.
pub const TRACE_ARITHMETIC_CARRY: usize = TRACE_RESULT_BITS_START + 8;
/// Boolean half-carry or half-borrow witness for byte arithmetic.
pub const TRACE_ARITHMETIC_HALF_CARRY: usize = TRACE_ARITHMETIC_CARRY + 1;
/// Boolean witness that the arithmetic result byte is zero.
pub const TRACE_RESULT_ZERO: usize = TRACE_ARITHMETIC_HALF_CARRY + 1;
/// First of six quadratic products used to prove the zero predicate at low degree.
pub const TRACE_RESULT_ZERO_PRODUCTS_START: usize = TRACE_RESULT_ZERO + 1;
/// Number of pair and quartet products in the result-zero product tree.
pub const TRACE_RESULT_ZERO_PRODUCT_COUNT: usize = 6;
/// First immediate byte, or zero when the instruction has none.
pub const TRACE_IMMEDIATE_LOW: usize =
    TRACE_RESULT_ZERO_PRODUCTS_START + TRACE_RESULT_ZERO_PRODUCT_COUNT;
/// Second immediate byte, or zero when the instruction has fewer than two.
pub const TRACE_IMMEDIATE_HIGH: usize = TRACE_IMMEDIATE_LOW + 1;
/// First bit column decomposing the first immediate byte.
pub const TRACE_IMMEDIATE_LOW_BITS_START: usize = TRACE_IMMEDIATE_HIGH + 1;
/// First bit column decomposing the second immediate byte.
pub const TRACE_IMMEDIATE_HIGH_BITS_START: usize = TRACE_IMMEDIATE_LOW_BITS_START + 8;
/// Canonical sequential PC after fetches, before any control transfer.
pub const TRACE_SEQUENTIAL_PC: usize = TRACE_IMMEDIATE_HIGH_BITS_START + 8;
/// First bit column decomposing the canonical sequential PC.
pub const TRACE_SEQUENTIAL_PC_BITS_START: usize = TRACE_SEQUENTIAL_PC + 1;
/// Boolean carry witnessing wrap of the sequential PC calculation.
pub const TRACE_PC_WRAP: usize = TRACE_SEQUENTIAL_PC_BITS_START + 16;
/// Boolean selector that the pre-state is the one-fetch HALT-bug state.
pub const TRACE_HALT_BUG: usize = TRACE_PC_WRAP + 1;
/// Boolean wrap witness for a taken relative target below zero.
pub const TRACE_CONTROL_UNDERFLOW: usize = TRACE_HALT_BUG + 1;
/// Boolean wrap witness for a taken relative target above `u16::MAX`.
pub const TRACE_CONTROL_OVERFLOW: usize = TRACE_CONTROL_UNDERFLOW + 1;
/// Boolean modular wrap witness for 16-bit increment/decrement operations.
pub const TRACE_WORD_WRAP: usize = TRACE_CONTROL_OVERFLOW + 1;
/// Boolean full carry witness for `ADD HL,rr`.
pub const TRACE_WORD_CARRY: usize = TRACE_WORD_WRAP + 1;
/// Boolean bit-11 half-carry witness for `ADD HL,rr`.
pub const TRACE_WORD_HALF_CARRY: usize = TRACE_WORD_CARRY + 1;
/// Boolean wrap witness for a signed-SP result below zero.
pub const TRACE_SIGNED_SP_UNDERFLOW: usize = TRACE_WORD_HALF_CARRY + 1;
/// Boolean wrap witness for a signed-SP result above `u16::MAX`.
pub const TRACE_SIGNED_SP_OVERFLOW: usize = TRACE_SIGNED_SP_UNDERFLOW + 1;
/// Boolean modular wrap witness for the final stack-pointer update.
pub const TRACE_STACK_WRAP: usize = TRACE_SIGNED_SP_OVERFLOW + 1;
/// Boolean modular wrap witness for the first stack byte address.
pub const TRACE_STACK_FIRST_WRAP: usize = TRACE_STACK_WRAP + 1;
/// Discarded low nibble of the flags byte consumed by `POP AF`.
pub const TRACE_POP_FLAGS_LOW_NIBBLE: usize = TRACE_STACK_FIRST_WRAP + 1;
/// First bit column decomposing the discarded `POP AF` low nibble.
pub const TRACE_POP_FLAGS_LOW_NIBBLE_BITS_START: usize = TRACE_POP_FLAGS_LOW_NIBBLE + 1;
/// Boolean predicate that the pre-DAA accumulator low nibble exceeds nine.
pub const TRACE_DAA_LOW_GT_NINE: usize = TRACE_POP_FLAGS_LOW_NIBBLE_BITS_START + 4;
/// Boolean predicate that the pre-DAA accumulator high nibble exceeds nine.
pub const TRACE_DAA_HIGH_GT_NINE: usize = TRACE_DAA_LOW_GT_NINE + 1;
/// Boolean predicate that the pre-DAA accumulator high nibble equals nine.
pub const TRACE_DAA_HIGH_EQUALS_NINE: usize = TRACE_DAA_HIGH_GT_NINE + 1;
/// Boolean predicate that the full pre-DAA accumulator exceeds `0x99`.
pub const TRACE_DAA_ACC_GT_99: usize = TRACE_DAA_HIGH_EQUALS_NINE + 1;
/// Boolean selector for applying the DAA `0x06` correction.
pub const TRACE_DAA_LOW_ADJUST: usize = TRACE_DAA_ACC_GT_99 + 1;
/// Boolean selector for applying the DAA `0x60` correction.
pub const TRACE_DAA_HIGH_ADJUST: usize = TRACE_DAA_LOW_ADJUST + 1;
/// Boolean modular wrap or borrow witness for the DAA correction.
pub const TRACE_DAA_WRAP: usize = TRACE_DAA_HIGH_ADJUST + 1;
/// Boolean modular wrap witness for the second byte of `LD (a16),SP`.
pub const TRACE_ADDRESS_WRAP: usize = TRACE_DAA_WRAP + 1;
/// Boolean wrap witness for the first byte following the primary fetch.
pub const TRACE_FETCH_ONE_WRAP: usize = TRACE_ADDRESS_WRAP + 1;
/// Boolean wrap witness for the second byte following the primary fetch.
pub const TRACE_FETCH_TWO_WRAP: usize = TRACE_FETCH_ONE_WRAP + 1;
/// First bit column decomposing each bus slot's 16-bit CPU-visible address.
pub const TRACE_BUS_ADDRESS_BITS_START: usize = TRACE_FETCH_TWO_WRAP + 1;
/// First bit column decomposing each bus slot's 20-bit physical address.
pub const TRACE_BUS_PHYSICAL_BITS_START: usize =
    TRACE_BUS_ADDRESS_BITS_START + TRACE_BUS_SLOTS * 16;
/// First bit column decomposing each bus slot's byte value.
pub const TRACE_BUS_VALUE_BITS_START: usize =
    TRACE_BUS_PHYSICAL_BITS_START + TRACE_BUS_SLOTS * ROM_ADDRESS_BIT_COUNT;
/// First bit column decomposing each bus slot's prior byte.
pub const TRACE_BUS_BEFORE_BITS_START: usize = TRACE_BUS_VALUE_BITS_START + TRACE_BUS_SLOTS * 8;
/// First bit column decomposing the before-state MBC3 ROM bank.
pub const TRACE_BEFORE_ROM_BANK_BITS_START: usize =
    TRACE_BUS_BEFORE_BITS_START + TRACE_BUS_SLOTS * 8;
/// First bit column decomposing the after-state MBC3 ROM bank.
pub const TRACE_AFTER_ROM_BANK_BITS_START: usize = TRACE_BEFORE_ROM_BANK_BITS_START + 6;
/// First bit column decomposing the before-state MBC3 RAM/RTC selector.
pub const TRACE_BEFORE_RAM_RTC_BITS_START: usize = TRACE_AFTER_ROM_BANK_BITS_START + 6;
/// First bit column decomposing the after-state MBC3 RAM/RTC selector.
pub const TRACE_AFTER_RAM_RTC_BITS_START: usize = TRACE_BEFORE_RAM_RTC_BITS_START + 4;
/// First Boolean column selecting immutable-ROM events in each bus slot.
pub const TRACE_ROM_SELECTOR_START: usize = TRACE_AFTER_RAM_RTC_BITS_START + 4;
/// First column containing the selected ROM byte, or zero for a non-ROM slot.
pub const TRACE_ROM_VALUE_START: usize = TRACE_ROM_SELECTOR_START + TRACE_BUS_SLOTS;
/// First fixed row-index bit, least-significant bit first.
pub const TRACE_ROW_BITS_START: usize = TRACE_ROM_VALUE_START + TRACE_BUS_SLOTS;
/// Number of row-index bits in a 16,384-row segment.
pub const TRACE_ROW_BIT_COUNT: usize = 14;
/// First ordered-memory witness column for the five bus slots.
pub const TRACE_MEMORY_START: usize = TRACE_ROW_BITS_START + TRACE_ROW_BIT_COUNT;
/// Width of one ordered-memory slot witness.
pub const TRACE_MEMORY_SLOT_WIDTH: usize = 38;
/// Memory-event selector offset within one ordered-memory slot.
pub const TRACE_MEMORY_SELECTOR_OFFSET: usize = 0;
/// Mutable-write selector offset within one ordered-memory slot.
pub const TRACE_MEMORY_WRITE_SELECTOR_OFFSET: usize = 1;
/// Selected prior byte offset within one ordered-memory slot.
pub const TRACE_MEMORY_BEFORE_OFFSET: usize = 2;
/// Selected resulting byte offset within one ordered-memory slot.
pub const TRACE_MEMORY_AFTER_OFFSET: usize = 3;
/// First predecessor-timestamp bit offset within one ordered-memory slot.
pub const TRACE_MEMORY_PREDECESSOR_BITS_OFFSET: usize = 4;
/// First strict-order delta bit offset within one ordered-memory slot.
pub const TRACE_MEMORY_DELTA_BITS_OFFSET: usize = 21;
/// Number of bits in ordered-memory timestamps and deltas.
pub const TRACE_MEMORY_TIMESTAMP_BITS: usize = 17;
/// Total logical columns in the one-transition reference schema.
pub const NATIVE_TRACE_COLUMN_COUNT: usize = device::TRACE_DEVICE_COLUMN_END;

const PADDING_MODE: usize = TraceMode::Padding.index();

/// Fixed-shape reference projection built from `StepRelation`-validated rows.
///
/// This type feeds packed-lane semantic construction and focused relation
/// checks. It has no receipt or wire representation.
#[derive(Debug)]
pub struct NativeTraceWitness {
    columns: Vec<Vec<u64>>,
    active_row_count: usize,
    initial_state: VmState,
    final_state: VmState,
    final_memory_timestamps: Vec<u64>,
}

/// Failure to encode validated rows into canonical reference columns.
#[derive(Debug, Error)]
pub enum NativeTraceError {
    /// At least one validated transition row is required.
    #[error("native trace witness is empty")]
    Empty,
    /// More rows were supplied than the frozen segment capacity.
    #[error("native trace has {actual} rows, maximum is {maximum}")]
    TooManyRows {
        /// Supplied validated row count.
        actual: usize,
        /// Fixed native segment capacity.
        maximum: usize,
    },
    /// Adjacent rows do not share an exact VM boundary.
    #[error("native trace is discontinuous after row {index}")]
    Discontinuous {
        /// Index of the first mismatched row.
        index: usize,
    },
    /// The post-state cycle count is smaller than its pre-state count.
    #[error("native trace cycle counter regressed at row {index}")]
    CycleRegression {
        /// Rejected row index.
        index: usize,
    },
    /// One transition emitted more than five canonical bus events.
    #[error("native trace row {index} exceeds five bus events")]
    TooManyBusEvents {
        /// Rejected row index.
        index: usize,
    },
    /// Canonical column indexing or table dimensions were inconsistent.
    #[error("native trace column layout is inconsistent")]
    Layout,
    /// Construction of the fixed ISA lookup table failed.
    #[error(transparent)]
    Isa(#[from] crate::IsaTableError),
    /// A mutable-memory event selected an address outside the 17-bit checkpoint table.
    #[error("mutable-memory physical address 0x{physical_address:05x} exceeds 17 bits")]
    MemoryPhysicalAddressOutOfRange {
        /// Rejected physical byte address.
        physical_address: u32,
    },
    /// Fixed row/slot chronology exceeded the frozen 17-bit timestamp range.
    #[error("native mutable-memory timestamp exceeds 17 bits")]
    MemoryTimestampOverflow,
}

impl NativeTraceWitness {
    /// Encodes every row of an already validated execution witness.
    pub fn from_witness(witness: &Witness) -> Result<Self, NativeTraceError> {
        let rows = witness.rows().collect::<Vec<_>>();
        Self::from_rows(&rows)
    }

    /// Encodes a non-empty contiguous list of validated rows and pads to 16,384.
    pub fn from_rows(rows: &[&TraceRow]) -> Result<Self, NativeTraceError> {
        let first = rows.first().copied().ok_or(NativeTraceError::Empty)?;
        let last = rows.last().copied().ok_or(NativeTraceError::Empty)?;
        if rows.len() > UNIFORM_ROW_COUNT {
            return Err(NativeTraceError::TooManyRows {
                actual: rows.len(),
                maximum: UNIFORM_ROW_COUNT,
            });
        }
        validate_continuity(rows)?;
        let table = fixed_isa_table()?;
        let mut columns = (0..NATIVE_TRACE_COLUMN_COUNT)
            .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
            .collect::<Vec<_>>();
        let mut memory_order = memory::MemoryOrderTracker::new();
        for (index, row) in rows.iter().copied().enumerate() {
            encode_active_row(&mut columns, row, index, &table, &mut memory_order)?;
        }
        let final_state = last.after();
        padding::append_rows(&mut columns, final_state, rows.len(), &table)?;
        if columns
            .iter()
            .any(|column| column.len() != UNIFORM_ROW_COUNT)
        {
            return Err(NativeTraceError::Layout);
        }
        Ok(Self {
            columns,
            active_row_count: rows.len(),
            initial_state: first.before(),
            final_state,
            final_memory_timestamps: memory_order.into_timestamps(),
        })
    }

    /// Returns all reference columns in canonical order.
    #[must_use]
    pub fn columns(&self) -> &[Vec<u64>] {
        &self.columns
    }

    /// Returns the number of non-padding transition rows.
    #[must_use]
    pub const fn active_row_count(&self) -> usize {
        self.active_row_count
    }

    /// Returns the exact first pre-state boundary.
    #[must_use]
    pub const fn initial_state(&self) -> VmState {
        self.initial_state
    }

    /// Returns the exact last post-state boundary.
    #[must_use]
    pub const fn final_state(&self) -> VmState {
        self.final_state
    }

    /// Returns the last ordered event timestamp for every 17-bit memory address.
    #[must_use]
    pub fn final_memory_timestamps(&self) -> &[u64] {
        &self.final_memory_timestamps
    }
}

fn validate_continuity(rows: &[&TraceRow]) -> Result<(), NativeTraceError> {
    for (index, pair) in rows.windows(2).enumerate() {
        let left = pair.first().copied().ok_or(NativeTraceError::Layout)?;
        let right = pair.get(1).copied().ok_or(NativeTraceError::Layout)?;
        if left.after() != right.before() {
            return Err(NativeTraceError::Discontinuous { index });
        }
    }
    Ok(())
}

fn encode_active_row(
    columns: &mut [Vec<u64>],
    row: &TraceRow,
    row_index: usize,
    table: &[crate::IsaTableRow],
    memory_order: &mut memory::MemoryOrderTracker,
) -> Result<(), NativeTraceError> {
    memory::append_row_bits(columns, row_index)?;
    append_state(columns, TRACE_BEFORE_STATE_START, row.before())?;
    append_state(columns, TRACE_AFTER_STATE_START, row.after())?;
    device::append_state_bits(columns, row.before(), row.after())?;
    device::append_apu_witness(columns, row.after(), Some(row))?;
    device::append_serial_witness(columns, row.before(), row.after(), Some(row))?;
    device::append_timer_witness(columns, row.before(), row.after(), Some(row))?;
    device::append_ppu_transition_witness(columns, row.before(), row.after(), Some(row))?;
    device::append_bus_access_witness(columns, Some(row))?;
    device::append_joypad_witness(columns, row.before(), Some(row))?;
    append_cpu_range_bits(columns, row.before(), row.after())?;
    append_mapper_bits(columns, row.before(), row.after())?;
    append_operation_witness(columns, row)?;
    append_instruction_witness(columns, row)?;
    word::append_word_witness(columns, row)?;
    daa::append_daa_witness(columns, row)?;
    append(columns, TRACE_ACTIVE, 1)?;
    append_modes(columns, row.effects().kind())?;
    let increment = row
        .after()
        .cpu()
        .m_cycles()
        .checked_sub(row.before().cpu().m_cycles())
        .ok_or(NativeTraceError::CycleRegression { index: row_index })?;
    append(columns, TRACE_CYCLE_INCREMENT, increment)?;
    append(
        columns,
        TRACE_BRANCH_TAKEN,
        u64::from(row.effects().branch_taken()),
    )?;
    let aligned = zksm83_isa::AlignedInstruction::from_decoded(row.effects().instruction());
    let address = usize::from(aligned.key.prefix)
        .checked_mul(256)
        .and_then(|prefix| prefix.checked_add(usize::from(aligned.key.opcode)))
        .ok_or(NativeTraceError::Layout)?;
    append_isa(columns, address, table)?;
    bus::append_bus(columns, row, row_index, memory_order)
}

fn encode_padding_row(
    columns: &mut [Vec<u64>],
    state: VmState,
    row_index: usize,
    table: &[crate::IsaTableRow],
) -> Result<(), NativeTraceError> {
    memory::append_row_bits(columns, row_index)?;
    append_state(columns, TRACE_BEFORE_STATE_START, state)?;
    append_state(columns, TRACE_AFTER_STATE_START, state)?;
    device::append_state_bits(columns, state, state)?;
    device::append_apu_witness(columns, state, None)?;
    device::append_serial_witness(columns, state, state, None)?;
    device::append_timer_witness(columns, state, state, None)?;
    device::append_ppu_transition_witness(columns, state, state, None)?;
    device::append_bus_access_witness(columns, None)?;
    device::append_joypad_witness(columns, state, None)?;
    append_cpu_range_bits(columns, state, state)?;
    append_mapper_bits(columns, state, state)?;
    append_arithmetic_witness(columns, ArithmeticWitness::default())?;
    append_empty_instruction_witness(columns)?;
    word::append_empty_word_witness(columns)?;
    daa::append_empty_daa_witness(columns)?;
    append(columns, TRACE_ACTIVE, 0)?;
    for mode in 0..TRACE_MODE_COUNT {
        append(
            columns,
            TRACE_MODE_START + mode,
            u64::from(mode == PADDING_MODE),
        )?;
    }
    for source in 0..TRACE_INTERRUPT_COUNT {
        append(columns, TRACE_INTERRUPT_START + source, 0)?;
    }
    append(columns, TRACE_CYCLE_INCREMENT, 0)?;
    append(columns, TRACE_BRANCH_TAKEN, 0)?;
    append_isa(columns, usize::from(ISA_PADDING_ADDRESS), table)?;
    bus::append_empty_bus(columns)
}

fn append_state(
    columns: &mut [Vec<u64>],
    start: usize,
    state: VmState,
) -> Result<(), NativeTraceError> {
    for (offset, value) in encode_state_scalars(state).into_iter().enumerate() {
        append(
            columns,
            start.checked_add(offset).ok_or(NativeTraceError::Layout)?,
            value,
        )?;
    }
    Ok(())
}

fn append_cpu_range_bits(
    columns: &mut [Vec<u64>],
    before: VmState,
    after: VmState,
) -> Result<(), NativeTraceError> {
    let before = encode_state_scalars(before);
    let after = encode_state_scalars(after);
    for byte_index in 0..8 {
        append_bits(
            columns,
            TRACE_BEFORE_CPU_BYTE_BITS_START + byte_index * 8,
            *before.get(byte_index).ok_or(NativeTraceError::Layout)?,
            8,
        )?;
        append_bits(
            columns,
            TRACE_AFTER_CPU_BYTE_BITS_START + byte_index * 8,
            *after.get(byte_index).ok_or(NativeTraceError::Layout)?,
            8,
        )?;
    }
    append_bits(
        columns,
        TRACE_BEFORE_PC_BITS_START,
        *before.get(8).ok_or(NativeTraceError::Layout)?,
        16,
    )?;
    append_bits(
        columns,
        TRACE_AFTER_PC_BITS_START,
        *after.get(8).ok_or(NativeTraceError::Layout)?,
        16,
    )?;
    append_bits(
        columns,
        TRACE_BEFORE_SP_BITS_START,
        *before.get(9).ok_or(NativeTraceError::Layout)?,
        16,
    )?;
    append_bits(
        columns,
        TRACE_AFTER_SP_BITS_START,
        *after.get(9).ok_or(NativeTraceError::Layout)?,
        16,
    )
}

fn append_mapper_bits(
    columns: &mut [Vec<u64>],
    before: VmState,
    after: VmState,
) -> Result<(), NativeTraceError> {
    append_bits(
        columns,
        TRACE_BEFORE_ROM_BANK_BITS_START,
        u64::from(before.mbc3().rom_bank()),
        6,
    )?;
    append_bits(
        columns,
        TRACE_AFTER_ROM_BANK_BITS_START,
        u64::from(after.mbc3().rom_bank()),
        6,
    )?;
    append_bits(
        columns,
        TRACE_BEFORE_RAM_RTC_BITS_START,
        u64::from(before.mbc3().ram_rtc_select()),
        4,
    )?;
    append_bits(
        columns,
        TRACE_AFTER_RAM_RTC_BITS_START,
        u64::from(after.mbc3().ram_rtc_select()),
        4,
    )
}

#[derive(Clone, Copy, Debug, Default)]
struct ArithmeticWitness {
    operand: u8,
    result: u8,
    carry: bool,
    half_carry: bool,
}

fn append_operation_witness(
    columns: &mut [Vec<u64>],
    row: &TraceRow,
) -> Result<(), NativeTraceError> {
    let aligned = zksm83_isa::AlignedInstruction::from_decoded(row.effects().instruction());
    if row.effects().kind() != StepKind::Instruction {
        return append_arithmetic_witness(columns, ArithmeticWitness::default());
    }
    let operand = arithmetic_operand(row, aligned)?;
    let witness = match aligned.operation {
        9 => ArithmeticWitness {
            operand,
            result: operand.wrapping_add(1),
            carry: operand == u8::MAX,
            half_carry: operand & 0x0f == 0x0f,
        },
        10 => ArithmeticWitness {
            operand,
            result: operand.wrapping_sub(1),
            carry: operand == 0,
            half_carry: operand & 0x0f == 0,
        },
        17 => ArithmeticWitness {
            operand,
            ..ArithmeticWitness::default()
        },
        19 => alu_witness(row, aligned.argument_zero, operand),
        22 | 23 => signed_sp_witness(row, operand),
        12 | 37 => rotate_witness(
            aligned.argument_zero,
            operand,
            row.before().cpu().flags().carry(),
        )?,
        13 => ArithmeticWitness {
            operand,
            result: row.after().cpu().registers().a,
            carry: row.after().cpu().flags().carry(),
            half_carry: false,
        },
        38 => ArithmeticWitness {
            operand,
            result: operand,
            ..ArithmeticWitness::default()
        },
        39 | 40 => bit_write_witness(aligned.operation, aligned.argument_zero, operand)?,
        _ => ArithmeticWitness::default(),
    };
    append_arithmetic_witness(columns, witness)
}

fn arithmetic_operand(
    row: &TraceRow,
    aligned: zksm83_isa::AlignedInstruction,
) -> Result<u8, NativeTraceError> {
    let argument = match aligned.operation {
        9 | 10 => aligned.argument_zero,
        12 | 13 => return Ok(row.before().cpu().registers().a),
        17 | 19 | 37..=40 => aligned.argument_one,
        22 | 23 => return first_immediate_value(row).ok_or(NativeTraceError::Layout),
        _ => return Ok(0),
    };
    let registers = row.before().cpu().registers();
    match argument {
        0 => Ok(registers.b),
        1 => Ok(registers.c),
        2 => Ok(registers.d),
        3 => Ok(registers.e),
        4 => Ok(registers.h),
        5 => Ok(registers.l),
        6 => first_data_value(row).ok_or(NativeTraceError::Layout),
        7 => Ok(registers.a),
        8 => first_immediate_value(row).ok_or(NativeTraceError::Layout),
        _ => Err(NativeTraceError::Layout),
    }
}

fn first_data_value(row: &TraceRow) -> Option<u8> {
    row.effects()
        .bus_events()
        .find(|event| matches!(event.kind().code(), 3 | 4 | 6 | 9 | 11 | 13))
        .map(|event| event.transcript_event().value)
}

fn first_immediate_value(row: &TraceRow) -> Option<u8> {
    row.effects()
        .bus_events()
        .find(|event| matches!(event.kind().code(), 2 | 15))
        .map(|event| event.transcript_event().value)
}

fn alu_witness(row: &TraceRow, operation: u8, operand: u8) -> ArithmeticWitness {
    let accumulator = row.before().cpu().registers().a;
    let carry_in = u8::from(row.before().cpu().flags().carry());
    match operation {
        0 | 1 => add_witness(accumulator, operand, operation * carry_in),
        2 | 3 | 7 => subtract_witness(accumulator, operand, u8::from(operation == 3) * carry_in),
        4 => ArithmeticWitness {
            operand,
            result: accumulator & operand,
            carry: false,
            half_carry: true,
        },
        5 => ArithmeticWitness {
            operand,
            result: accumulator ^ operand,
            carry: false,
            half_carry: false,
        },
        6 => ArithmeticWitness {
            operand,
            result: accumulator | operand,
            carry: false,
            half_carry: false,
        },
        _ => ArithmeticWitness::default(),
    }
}

fn add_witness(left: u8, right: u8, carry_in: u8) -> ArithmeticWitness {
    let sum = u16::from(left) + u16::from(right) + u16::from(carry_in);
    ArithmeticWitness {
        operand: right,
        result: sum as u8,
        carry: sum > u16::from(u8::MAX),
        half_carry: u16::from(left & 0x0f) + u16::from(right & 0x0f) + u16::from(carry_in) > 0x0f,
    }
}

fn subtract_witness(left: u8, right: u8, carry_in: u8) -> ArithmeticWitness {
    let subtrahend = u16::from(right) + u16::from(carry_in);
    ArithmeticWitness {
        operand: right,
        result: left.wrapping_sub(right).wrapping_sub(carry_in),
        carry: u16::from(left) < subtrahend,
        half_carry: u16::from(left & 0x0f) < u16::from(right & 0x0f) + u16::from(carry_in),
    }
}

fn signed_sp_witness(row: &TraceRow, operand: u8) -> ArithmeticWitness {
    let [sp_low, _] = row.before().cpu().sp().to_le_bytes();
    let result = match row.effects().instruction().descriptor().operation {
        22 => {
            let [low, _] = row.after().cpu().sp().to_le_bytes();
            low
        }
        23 => row.after().cpu().registers().l,
        _ => 0,
    };
    let low_sum = u16::from(sp_low) + u16::from(operand);
    ArithmeticWitness {
        operand,
        result,
        carry: low_sum > u16::from(u8::MAX),
        half_carry: u16::from(sp_low & 0x0f) + u16::from(operand & 0x0f) > 0x0f,
    }
}

fn rotate_witness(
    operation: u8,
    operand: u8,
    carry_in: bool,
) -> Result<ArithmeticWitness, NativeTraceError> {
    let (result, carry) = match operation {
        0 => (operand.rotate_left(1), operand & 0x80 != 0),
        1 => (operand.rotate_right(1), operand & 0x01 != 0),
        2 => ((operand << 1) | u8::from(carry_in), operand & 0x80 != 0),
        3 => (
            (operand >> 1) | (u8::from(carry_in) << 7),
            operand & 0x01 != 0,
        ),
        4 => (operand << 1, operand & 0x80 != 0),
        5 => ((operand >> 1) | (operand & 0x80), operand & 1 != 0),
        6 => (operand.rotate_left(4), false),
        7 => (operand >> 1, operand & 1 != 0),
        _ => return Err(NativeTraceError::Layout),
    };
    Ok(ArithmeticWitness {
        operand,
        result,
        carry,
        half_carry: false,
    })
}

fn bit_write_witness(
    operation: u8,
    bit: u8,
    operand: u8,
) -> Result<ArithmeticWitness, NativeTraceError> {
    let mask = 1_u8
        .checked_shl(u32::from(bit))
        .ok_or(NativeTraceError::Layout)?;
    let result = match operation {
        39 => operand & !mask,
        40 => operand | mask,
        _ => return Err(NativeTraceError::Layout),
    };
    Ok(ArithmeticWitness {
        operand,
        result,
        ..ArithmeticWitness::default()
    })
}

fn append_arithmetic_witness(
    columns: &mut [Vec<u64>],
    witness: ArithmeticWitness,
) -> Result<(), NativeTraceError> {
    append(columns, TRACE_OPERAND_VALUE, u64::from(witness.operand))?;
    append(columns, TRACE_RESULT_VALUE, u64::from(witness.result))?;
    append_bits(
        columns,
        TRACE_OPERAND_BITS_START,
        u64::from(witness.operand),
        8,
    )?;
    append_bits(
        columns,
        TRACE_RESULT_BITS_START,
        u64::from(witness.result),
        8,
    )?;
    append(columns, TRACE_ARITHMETIC_CARRY, u64::from(witness.carry))?;
    append(
        columns,
        TRACE_ARITHMETIC_HALF_CARRY,
        u64::from(witness.half_carry),
    )?;
    let result_bits = std::array::from_fn::<_, 8, _>(|bit| (witness.result >> bit) & 1);
    let [
        bit_zero,
        bit_one,
        bit_two,
        bit_three,
        bit_four,
        bit_five,
        bit_six,
        bit_seven,
    ] = result_bits;
    let pairs = [
        (1 - bit_zero) * (1 - bit_one),
        (1 - bit_two) * (1 - bit_three),
        (1 - bit_four) * (1 - bit_five),
        (1 - bit_six) * (1 - bit_seven),
    ];
    let [pair_zero, pair_one, pair_two, pair_three] = pairs;
    let quartets = [pair_zero * pair_one, pair_two * pair_three];
    let [quartet_zero, quartet_one] = quartets;
    append(
        columns,
        TRACE_RESULT_ZERO,
        u64::from(quartet_zero * quartet_one),
    )?;
    for (offset, value) in pairs.into_iter().chain(quartets).enumerate() {
        append(
            columns,
            TRACE_RESULT_ZERO_PRODUCTS_START + offset,
            u64::from(value),
        )?;
    }
    Ok(())
}

fn append_instruction_witness(
    columns: &mut [Vec<u64>],
    row: &TraceRow,
) -> Result<(), NativeTraceError> {
    if row.effects().kind() != StepKind::Instruction {
        return append_empty_instruction_witness(columns);
    }
    let aligned = zksm83_isa::AlignedInstruction::from_decoded(row.effects().instruction());
    let mut immediates = row
        .effects()
        .bus_events()
        .filter(|event| matches!(event.kind().code(), 2 | 15))
        .map(|event| event.transcript_event().value);
    let low = immediates.next().unwrap_or(0);
    let high = immediates.next().unwrap_or(0);
    let halt_bug = row.before().cpu().run_state() == zksm83_core::RunState::HaltBug;
    let unwrapped = u32::from(row.before().cpu().pc())
        .checked_add(u32::from(aligned.byte_len))
        .and_then(|value| value.checked_sub(u32::from(halt_bug)))
        .ok_or(NativeTraceError::Layout)?;
    let sequential =
        u16::try_from(unwrapped & u32::from(u16::MAX)).map_err(|_| NativeTraceError::Layout)?;
    let signed_target = i32::from(sequential)
        .checked_add(i32::from(i8::from_ne_bytes([low])))
        .ok_or(NativeTraceError::Layout)?;
    let relative_taken = aligned.operation == 3 && row.effects().branch_taken();
    append(columns, TRACE_IMMEDIATE_LOW, u64::from(low))?;
    append(columns, TRACE_IMMEDIATE_HIGH, u64::from(high))?;
    append_bits(columns, TRACE_IMMEDIATE_LOW_BITS_START, u64::from(low), 8)?;
    append_bits(columns, TRACE_IMMEDIATE_HIGH_BITS_START, u64::from(high), 8)?;
    append(columns, TRACE_SEQUENTIAL_PC, u64::from(sequential))?;
    append_bits(
        columns,
        TRACE_SEQUENTIAL_PC_BITS_START,
        u64::from(sequential),
        16,
    )?;
    append(
        columns,
        TRACE_PC_WRAP,
        u64::from(unwrapped > u32::from(u16::MAX)),
    )?;
    append(columns, TRACE_HALT_BUG, u64::from(halt_bug))?;
    let fetch_one = u32::from(row.before().cpu().pc())
        .checked_add(1)
        .and_then(|value| value.checked_sub(u32::from(halt_bug)))
        .ok_or(NativeTraceError::Layout)?;
    let fetch_two = u32::from(row.before().cpu().pc())
        .checked_add(2)
        .and_then(|value| value.checked_sub(u32::from(halt_bug)))
        .ok_or(NativeTraceError::Layout)?;
    append(
        columns,
        TRACE_FETCH_ONE_WRAP,
        u64::from(fetch_one > u32::from(u16::MAX)),
    )?;
    append(
        columns,
        TRACE_FETCH_TWO_WRAP,
        u64::from(fetch_two > u32::from(u16::MAX)),
    )?;
    append(
        columns,
        TRACE_CONTROL_UNDERFLOW,
        u64::from(relative_taken && signed_target < 0),
    )?;
    append(
        columns,
        TRACE_CONTROL_OVERFLOW,
        u64::from(relative_taken && signed_target > i32::from(u16::MAX)),
    )
}

fn append_empty_instruction_witness(columns: &mut [Vec<u64>]) -> Result<(), NativeTraceError> {
    append(columns, TRACE_IMMEDIATE_LOW, 0)?;
    append(columns, TRACE_IMMEDIATE_HIGH, 0)?;
    for bit in 0..8 {
        append(columns, TRACE_IMMEDIATE_LOW_BITS_START + bit, 0)?;
        append(columns, TRACE_IMMEDIATE_HIGH_BITS_START + bit, 0)?;
    }
    append(columns, TRACE_SEQUENTIAL_PC, 0)?;
    for bit in 0..16 {
        append(columns, TRACE_SEQUENTIAL_PC_BITS_START + bit, 0)?;
    }
    append(columns, TRACE_PC_WRAP, 0)?;
    append(columns, TRACE_HALT_BUG, 0)?;
    append(columns, TRACE_FETCH_ONE_WRAP, 0)?;
    append(columns, TRACE_FETCH_TWO_WRAP, 0)?;
    append(columns, TRACE_CONTROL_UNDERFLOW, 0)?;
    append(columns, TRACE_CONTROL_OVERFLOW, 0)
}

fn append_bits(
    columns: &mut [Vec<u64>],
    start: usize,
    value: u64,
    width: usize,
) -> Result<(), NativeTraceError> {
    for bit in 0..width {
        append(
            columns,
            start.checked_add(bit).ok_or(NativeTraceError::Layout)?,
            (value >> bit) & 1,
        )?;
    }
    Ok(())
}

fn append_modes(columns: &mut [Vec<u64>], kind: StepKind) -> Result<(), NativeTraceError> {
    let mode = TraceMode::for_step(kind).index();
    for index in 0..TRACE_MODE_COUNT {
        append(columns, TRACE_MODE_START + index, u64::from(index == mode))?;
    }
    for source in 0..TRACE_INTERRUPT_COUNT {
        let selected = matches!(kind, StepKind::InterruptDispatch(interrupt) if interrupt_index(interrupt) == source);
        append(columns, TRACE_INTERRUPT_START + source, u64::from(selected))?;
    }
    Ok(())
}

fn append_isa(
    columns: &mut [Vec<u64>],
    address: usize,
    table: &[crate::IsaTableRow],
) -> Result<(), NativeTraceError> {
    if address >= ISA_TABLE_ROW_COUNT {
        return Err(NativeTraceError::Layout);
    }
    for bit in 0..ISA_ADDRESS_BIT_COUNT {
        append(
            columns,
            TRACE_ISA_ADDRESS_START + bit,
            u64::from(((address >> bit) & 1) != 0),
        )?;
    }
    let outputs = table
        .get(address)
        .copied()
        .ok_or(NativeTraceError::Layout)?
        .outputs();
    for (offset, value) in outputs.into_iter().enumerate() {
        append(columns, TRACE_ISA_OUTPUT_START + offset, value)?;
    }
    Ok(())
}

pub(super) fn append(
    columns: &mut [Vec<u64>],
    index: usize,
    value: u64,
) -> Result<(), NativeTraceError> {
    columns
        .get_mut(index)
        .ok_or(NativeTraceError::Layout)?
        .push(value);
    Ok(())
}

const fn interrupt_index(interrupt: DmgInterrupt) -> usize {
    match interrupt {
        DmgInterrupt::VBlank => 0,
        DmgInterrupt::LcdStat => 1,
        DmgInterrupt::Timer => 2,
        DmgInterrupt::Serial => 3,
        DmgInterrupt::Joypad => 4,
    }
}
