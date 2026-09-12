//! Native low-degree structural constraints for CPU, ISA, and bus trace rows.

mod apu;
#[cfg(test)]
mod apu_tests;
mod bit;
mod control;
mod daa;
mod data;
mod devices;
#[cfg(test)]
mod dma_tests;
mod joypad;
#[cfg(test)]
mod joypad_tests;
#[cfg(test)]
mod log_tests;
mod logs;
mod machine;
mod mbc3;
mod memory;
mod mmio;
#[cfg(test)]
mod mmio_tests;
mod ppu;
#[cfg(test)]
mod ppu_tests;
#[cfg(test)]
mod register_tests;
mod registers;
mod semantics;
mod serial;
#[cfg(test)]
mod serial_tests;
mod stack;
#[cfg(test)]
mod summary_tests;
#[cfg(test)]
mod test_fixtures;
#[cfg(test)]
mod tests_more;
mod timer;
#[cfg(test)]
mod timer_tests;
mod word;

use akita_pcs::Ring;
use thiserror::Error;

use crate::{
    CommittedMemory, CommittedProtocolLogs, CommittedRom, CommittedWitness, ContinuityError,
    ContinuityProof, ISA_ARGUMENT_ONE_BITS_START, ISA_ARGUMENT_ZERO_BITS_START,
    ISA_OPERATION_BITS_START, ISA_OUTPUT_COUNT, ISA_TAKEN_TIMING, ISA_VALID, ISA_WRITE_BITS_START,
    IsaLookupError, IsaLookupProof, MemoryCommitment, MutableMemoryError, MutableMemoryProof,
    NATIVE_TRACE_COLUMN_COUNT, NativeExecutionClaim, NativeField, NativeTraceError,
    NativeTraceWitness, ProtocolLogCommitments, ProtocolLogError, ProtocolLogProof,
    ROM_ADDRESS_BIT_COUNT, RomCommitment, RomLookupError, RomLookupProof, STATE_SCALAR_COUNT,
    TRACE_ACTIVE, TRACE_AFTER_CPU_BYTE_BITS_START, TRACE_AFTER_PC_BITS_START,
    TRACE_AFTER_RAM_RTC_BITS_START, TRACE_AFTER_ROM_BANK_BITS_START, TRACE_AFTER_SP_BITS_START,
    TRACE_AFTER_STATE_START, TRACE_BEFORE_CPU_BYTE_BITS_START, TRACE_BEFORE_PC_BITS_START,
    TRACE_BEFORE_RAM_RTC_BITS_START, TRACE_BEFORE_ROM_BANK_BITS_START, TRACE_BEFORE_SP_BITS_START,
    TRACE_BEFORE_STATE_START, TRACE_BRANCH_TAKEN, TRACE_BUS_ADDRESS_BITS_START,
    TRACE_BUS_BEFORE_BITS_START, TRACE_BUS_KIND_BITS, TRACE_BUS_PHYSICAL_BITS_START,
    TRACE_BUS_SLOT_WIDTH, TRACE_BUS_SLOTS, TRACE_BUS_START, TRACE_BUS_VALUE_BITS_START,
    TRACE_CYCLE_INCREMENT, TRACE_HALT_BUG, TRACE_INTERRUPT_COUNT, TRACE_INTERRUPT_START,
    TRACE_ISA_ADDRESS_START, TRACE_ISA_OUTPUT_START, TRACE_MODE_COUNT, TRACE_MODE_START,
    TRACE_ROM_SELECTOR_START, TRACE_ROM_VALUE_START, UniformError, UniformRelation,
    UniformRelationProof, WitnessCommitments, commit_witness, prove_continuity, prove_isa_lookup,
    prove_mutable_memory, prove_protocol_logs, prove_rom_lookup, prove_uniform_committed,
    verify_continuity, verify_isa_lookup, verify_mutable_memory, verify_protocol_logs,
    verify_rom_lookup, verify_uniform_committed,
};

/// Number of relation slots; unused tail slots are canonical zero identities.
pub const CPU_STRUCTURAL_CONSTRAINT_COUNT: usize = 6144;
/// Maximum algebraic degree of one CPU/device constraint before equality weighting.
pub const CPU_STRUCTURAL_MAX_DEGREE: usize = 18;

const CPU_STRUCTURAL_DOMAIN: &[u8] = b"zksm83/native-cpu-structural/v17";
const PADDING_MODE: usize = 6;
const INTERRUPT_MODE: usize = 8;
pub(super) const INSTRUCTION_MODE: usize = 0;
const HALT_IDLE_MODE: usize = 1;
const HALT_WAKE_MODE: usize = 7;
const DMA_BYTE_MODE: usize = 9;
const PADDING_ISA_ADDRESS: usize = 0xd3;
pub(super) const STATE_FLAGS: usize = 7;
const STATE_PC: usize = 8;
const STATE_SP: usize = 9;
const STATE_IME: usize = 10;
const STATE_RUN_STATE: usize = 11;
const STATE_CYCLES: usize = 12;
pub(super) const STATE_MBC3_RAM_ENABLED: usize = 13;
pub(super) const STATE_MBC3_ROM_BANK: usize = 14;
pub(super) const STATE_MBC3_RAM_RTC_SELECT: usize = 15;
const STATE_PROFILE: usize = 20;
const ISA_PREFIX: usize = 3;
const ISA_OPCODE: usize = 4;
const ISA_OPERATION: usize = 6;
const ISA_ARGUMENT_ZERO: usize = 7;
const ISA_ARGUMENT_ONE: usize = 8;
const ISA_BASE_CYCLES: usize = 10;
const ISA_TAKEN_CYCLES: usize = 11;
const ISA_OPCODE_FETCHES: usize = 16;
const ISA_IMMEDIATE_READS: usize = 17;
const ISA_DATA_READS: usize = 18;
const ISA_DATA_WRITES: usize = 19;
const ISA_TAKEN_DATA_READS: usize = 20;
const ISA_TAKEN_DATA_WRITES: usize = 21;
pub(super) const BUS_ADDRESS_OFFSET: usize = 1 + TRACE_BUS_KIND_BITS;
pub(super) const BUS_PHYSICAL_ADDRESS_OFFSET: usize = BUS_ADDRESS_OFFSET + 1;
pub(super) const BUS_BEFORE_OFFSET: usize = BUS_ADDRESS_OFFSET + 2;
pub(super) const BUS_AUXILIARY_OFFSET: usize = BUS_ADDRESS_OFFSET + 3;
pub(super) const BUS_VALUE_OFFSET: usize = BUS_ADDRESS_OFFSET + 4;
pub(super) const BUS_INDEX_OFFSET: usize = BUS_ADDRESS_OFFSET + 5;
const BUS_TUPLE_FIELDS: usize = 6;

/// Row-local native CPU, fixed-ISA, bus, memory-routing, and partial-device relation.
///
/// Ordinary SM83 instruction and current machine-step CPU semantics are complete.
/// The receipt remains incomplete until every DMG device transition, ordered log
/// commitment, segment-continuity rule, and public-statement check is composed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CpuStructuralRelation;

/// Transparent CPU/ISA structural proof sharing one trace commitment plane.
///
/// This is an integration proof, not a complete SM83 receipt. Row-to-row
/// continuity, committed logs, and the remaining DMG device relations are
/// separate unfinished obligations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeCpuStructuralProof {
    commitments: WitnessCommitments,
    relation: UniformRelationProof,
    isa_lookup: IsaLookupProof,
}

/// CPU, fixed-ISA, and dynamic-ROM proof sharing one trace commitment plane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRomCpuProof {
    commitments: WitnessCommitments,
    relation: UniformRelationProof,
    isa_lookup: IsaLookupProof,
    rom_lookup: RomLookupProof,
}

/// CPU, ISA, ROM, mutable-memory, and ordered-continuity proof sharing one trace plane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeMemoryCpuProof {
    pub(crate) commitments: WitnessCommitments,
    pub(crate) relation: UniformRelationProof,
    pub(crate) isa_lookup: IsaLookupProof,
    pub(crate) rom_lookup: RomLookupProof,
    pub(crate) memory: MutableMemoryProof,
    pub(crate) continuity: ContinuityProof,
    pub(crate) logs: ProtocolLogProof,
}

/// Failure to build or verify the incomplete CPU/ISA structural proof.
#[derive(Debug, Error)]
pub enum NativeCpuStructuralError {
    /// Canonical native trace construction failed.
    #[error(transparent)]
    Trace(#[from] NativeTraceError),
    /// Shared witness commitment or structural-relation proof failed.
    #[error(transparent)]
    Uniform(#[from] UniformError),
    /// Fixed ISA Shout lookup construction or verification failed.
    #[error(transparent)]
    IsaLookup(#[from] IsaLookupError),
    /// Dynamic cartridge-ROM Shout lookup construction or verification failed.
    #[error(transparent)]
    RomLookup(#[from] RomLookupError),
    /// Ordered mutable-memory proof construction or verification failed.
    #[error(transparent)]
    MutableMemory(#[from] MutableMemoryError),
    /// Ordered row-continuity or public semantic-boundary proof failed.
    #[error(transparent)]
    Continuity(#[from] ContinuityError),
    /// Ordered input, output, bus, or ISA log proof failed.
    #[error(transparent)]
    ProtocolLog(#[from] ProtocolLogError),
}

impl NativeCpuStructuralProof {
    /// Returns the shared commitments consumed by both relation claims.
    #[must_use]
    pub const fn commitments(&self) -> &WitnessCommitments {
        &self.commitments
    }
}

impl NativeRomCpuProof {
    /// Returns the shared commitments consumed by all three claims.
    #[must_use]
    pub const fn commitments(&self) -> &WitnessCommitments {
        &self.commitments
    }
}

impl NativeMemoryCpuProof {
    /// Returns the trace commitments consumed by all four native claims.
    #[must_use]
    pub const fn commitments(&self) -> &WitnessCommitments {
        &self.commitments
    }
}

/// Proves the current CPU/ISA structural subset from canonical trace columns.
pub fn prove_native_cpu_structural(
    trace: &NativeTraceWitness,
) -> Result<NativeCpuStructuralProof, NativeCpuStructuralError> {
    let witness = commit_witness(trace.columns())?;
    prove_cpu_claims(trace, witness)
}

/// Verifies the current CPU/ISA structural subset without replaying execution.
pub fn verify_native_cpu_structural(
    proof: &NativeCpuStructuralProof,
) -> Result<(), NativeCpuStructuralError> {
    let relation = CpuStructuralRelation;
    verify_uniform_committed(&relation, &proof.commitments, &proof.relation)?;
    let layout = crate::trace::canonical_isa_lookup_columns()?;
    verify_isa_lookup(layout, &proof.commitments, &proof.isa_lookup)?;
    Ok(())
}

/// Proves the current CPU relation, fixed ISA, and all immutable-ROM reads.
pub fn prove_native_rom_cpu(
    trace: &NativeTraceWitness,
    rom: &CommittedRom,
) -> Result<NativeRomCpuProof, NativeCpuStructuralError> {
    let witness = commit_witness(trace.columns())?;
    let relation = CpuStructuralRelation;
    let relation = prove_uniform_committed(&relation, &witness)?;
    let isa_lookup = prove_isa_lookup(trace.isa_lookup_columns()?, &witness)?;
    let rom_lookup = prove_rom_lookup(trace.rom_lookup_columns()?, rom, &witness)?;
    Ok(NativeRomCpuProof {
        commitments: witness.into_commitments(),
        relation,
        isa_lookup,
        rom_lookup,
    })
}

/// Verifies the combined CPU/ISA/ROM proof without replaying SM83 execution.
pub fn verify_native_rom_cpu(
    proof: &NativeRomCpuProof,
    rom: &RomCommitment,
) -> Result<(), NativeCpuStructuralError> {
    let relation = CpuStructuralRelation;
    verify_uniform_committed(&relation, &proof.commitments, &proof.relation)?;
    let isa_layout = crate::trace::canonical_isa_lookup_columns()?;
    verify_isa_lookup(isa_layout, &proof.commitments, &proof.isa_lookup)?;
    let rom_layout = crate::trace::canonical_rom_lookup_columns()?;
    verify_rom_lookup(rom_layout, rom, &proof.commitments, &proof.rom_lookup)?;
    Ok(())
}

/// Proves CPU/ISA semantics, immutable ROM, and ordered mutable memory together.
pub fn prove_native_memory_cpu(
    trace: &NativeTraceWitness,
    claim: &NativeExecutionClaim,
    logs: &CommittedProtocolLogs,
    rom: &CommittedRom,
    initial_memory: &CommittedMemory,
    final_memory: &CommittedMemory,
) -> Result<NativeMemoryCpuProof, NativeCpuStructuralError> {
    let witness = commit_witness(trace.columns())?;
    let relation = CpuStructuralRelation;
    let relation = prove_uniform_committed(&relation, &witness)?;
    let isa_lookup = prove_isa_lookup(trace.isa_lookup_columns()?, &witness)?;
    let rom_lookup = prove_rom_lookup(trace.rom_lookup_columns()?, rom, &witness)?;
    let memory = prove_mutable_memory(trace, &witness, initial_memory, final_memory)?;
    let continuity = prove_continuity(trace, &witness, claim)?;
    let logs = prove_protocol_logs(trace, &witness, logs, claim)?;
    Ok(NativeMemoryCpuProof {
        commitments: witness.into_commitments(),
        relation,
        isa_lookup,
        rom_lookup,
        memory,
        continuity,
        logs,
    })
}

/// Verifies the combined CPU/ISA/ROM/memory proof without replaying execution.
pub fn verify_native_memory_cpu(
    proof: &NativeMemoryCpuProof,
    claim: &NativeExecutionClaim,
    logs: &ProtocolLogCommitments,
    rom: &RomCommitment,
    initial_memory: &MemoryCommitment,
    final_memory: &MemoryCommitment,
) -> Result<(), NativeCpuStructuralError> {
    let relation = CpuStructuralRelation;
    verify_uniform_committed(&relation, &proof.commitments, &proof.relation)?;
    let isa_layout = crate::trace::canonical_isa_lookup_columns()?;
    verify_isa_lookup(isa_layout, &proof.commitments, &proof.isa_lookup)?;
    let rom_layout = crate::trace::canonical_rom_lookup_columns()?;
    verify_rom_lookup(rom_layout, rom, &proof.commitments, &proof.rom_lookup)?;
    verify_mutable_memory(
        &proof.memory,
        &proof.commitments,
        initial_memory,
        final_memory,
    )?;
    verify_continuity(&proof.continuity, &proof.commitments, claim)?;
    verify_protocol_logs(&proof.logs, &proof.commitments, logs, claim)?;
    Ok(())
}

fn prove_cpu_claims(
    trace: &NativeTraceWitness,
    witness: CommittedWitness,
) -> Result<NativeCpuStructuralProof, NativeCpuStructuralError> {
    let relation = CpuStructuralRelation;
    let relation_proof = prove_uniform_committed(&relation, &witness)?;
    let isa_lookup = prove_isa_lookup(trace.isa_lookup_columns()?, &witness)?;
    Ok(NativeCpuStructuralProof {
        commitments: witness.into_commitments(),
        relation: relation_proof,
        isa_lookup,
    })
}

impl UniformRelation for CpuStructuralRelation {
    fn domain(&self) -> &'static [u8] {
        CPU_STRUCTURAL_DOMAIN
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut statement = Vec::new();
        statement.extend_from_slice(&(NATIVE_TRACE_COLUMN_COUNT as u64).to_le_bytes());
        statement.extend_from_slice(&(CPU_STRUCTURAL_CONSTRAINT_COUNT as u64).to_le_bytes());
        statement.extend_from_slice(&(PADDING_ISA_ADDRESS as u64).to_le_bytes());
        statement
    }

    fn column_count(&self) -> usize {
        NATIVE_TRACE_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        CPU_STRUCTURAL_CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        CPU_STRUCTURAL_MAX_DEGREE
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != NATIVE_TRACE_COLUMN_COUNT
            || constraints.len() != CPU_STRUCTURAL_CONSTRAINT_COUNT
        {
            return Err(UniformError::Shape);
        }
        constraints.fill(NativeField::from_u64(0));
        let view = RowView { row };
        let mut sink = ConstraintSink::new(constraints);
        constrain_selectors(&view, &mut sink)?;
        constrain_cpu_ranges(&view, &mut sink)?;
        constrain_mapper_ranges(&view, &mut sink)?;
        devices::constrain_interrupt_control(&view, &mut sink)?;
        apu::constrain_apu(&view, &mut sink)?;
        constrain_isa(&view, &mut sink)?;
        constrain_cycles_and_frames(&view, &mut sink)?;
        constrain_bus(&view, &mut sink)?;
        logs::constrain_cursors_and_log_events(&view, &mut sink)?;
        mmio::constrain_mmio_events(&view, &mut sink)?;
        registers::constrain_visible_registers(&view, &mut sink)?;
        serial::constrain_serial(&view, &mut sink)?;
        timer::constrain_timer(&view, &mut sink)?;
        ppu::constrain_ppu(&view, &mut sink)?;
        joypad::constrain_joypad(&view, &mut sink)?;
        memory::constrain_memory_events(&view, &mut sink)?;
        mbc3::constrain_mapper_and_rom(&view, &mut sink)?;
        semantics::constrain_byte_arithmetic(&view, &mut sink)?;
        control::constrain_instruction_flow(&view, &mut sink)?;
        data::constrain_data_and_simple_operations(&view, &mut sink)?;
        word::constrain_word_operations(&view, &mut sink)?;
        stack::constrain_stack_operations(&view, &mut sink)?;
        bit::constrain_rotate_and_bit_operations(&view, &mut sink)?;
        daa::constrain_decimal_adjust(&view, &mut sink)?;
        machine::constrain_machine_cpu(&view, &mut sink)?;
        Ok(())
    }
}

pub(super) struct RowView<'a> {
    row: &'a [NativeField],
}

impl RowView<'_> {
    pub(super) fn value(&self, index: usize) -> Result<NativeField, UniformError> {
        self.row.get(index).copied().ok_or(UniformError::Shape)
    }

    pub(super) fn before(&self, index: usize) -> Result<NativeField, UniformError> {
        self.value(TRACE_BEFORE_STATE_START + index)
    }

    pub(super) fn after(&self, index: usize) -> Result<NativeField, UniformError> {
        self.value(TRACE_AFTER_STATE_START + index)
    }

    pub(super) fn mode(&self, index: usize) -> Result<NativeField, UniformError> {
        self.value(TRACE_MODE_START + index)
    }

    pub(super) fn isa(&self, index: usize) -> Result<NativeField, UniformError> {
        self.value(TRACE_ISA_OUTPUT_START + index)
    }
}

pub(super) struct ConstraintSink<'a> {
    constraints: &'a mut [NativeField],
    cursor: usize,
}

impl<'a> ConstraintSink<'a> {
    const fn new(constraints: &'a mut [NativeField]) -> Self {
        Self {
            constraints,
            cursor: 0,
        }
    }

    pub(super) fn push(&mut self, value: NativeField) -> Result<(), UniformError> {
        let target = self
            .constraints
            .get_mut(self.cursor)
            .ok_or(UniformError::Shape)?;
        *target = value;
        self.cursor = self.cursor.checked_add(1).ok_or(UniformError::Shape)?;
        Ok(())
    }
}

fn constrain_selectors(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let active = view.value(TRACE_ACTIVE)?;
    sink.push(boolean(active))?;
    let mut mode_sum = NativeField::from_u64(0);
    for mode in 0..TRACE_MODE_COUNT {
        let selector = view.mode(mode)?;
        sink.push(boolean(selector))?;
        mode_sum += selector;
    }
    sink.push(mode_sum - one)?;
    sink.push(view.mode(PADDING_MODE)? - (one - active))?;
    let mut interrupt_sum = NativeField::from_u64(0);
    for source in 0..TRACE_INTERRUPT_COUNT {
        let selector = view.value(TRACE_INTERRUPT_START + source)?;
        sink.push(boolean(selector))?;
        interrupt_sum += selector;
    }
    sink.push(interrupt_sum - view.mode(INTERRUPT_MODE)?)?;
    let branch = view.value(TRACE_BRANCH_TAKEN)?;
    sink.push(boolean(branch))?;
    sink.push((one - view.mode(INSTRUCTION_MODE)?) * branch)
}

fn constrain_cpu_ranges(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    constrain_bit_range(view, sink, TRACE_BEFORE_CPU_BYTE_BITS_START, 8 * 8)?;
    constrain_bit_range(view, sink, TRACE_AFTER_CPU_BYTE_BITS_START, 8 * 8)?;
    constrain_bit_range(view, sink, TRACE_BEFORE_PC_BITS_START, 16)?;
    constrain_bit_range(view, sink, TRACE_AFTER_PC_BITS_START, 16)?;
    constrain_bit_range(view, sink, TRACE_BEFORE_SP_BITS_START, 16)?;
    constrain_bit_range(view, sink, TRACE_AFTER_SP_BITS_START, 16)?;
    for byte in 0..8 {
        sink.push(
            view.before(byte)? - packed_bits(view, TRACE_BEFORE_CPU_BYTE_BITS_START + byte * 8, 8)?,
        )?;
        sink.push(
            view.after(byte)? - packed_bits(view, TRACE_AFTER_CPU_BYTE_BITS_START + byte * 8, 8)?,
        )?;
    }
    for bit in 0..4 {
        sink.push(view.value(TRACE_BEFORE_CPU_BYTE_BITS_START + STATE_FLAGS * 8 + bit)?)?;
        sink.push(view.value(TRACE_AFTER_CPU_BYTE_BITS_START + STATE_FLAGS * 8 + bit)?)?;
    }
    for (state, before_bits, after_bits) in [
        (
            STATE_PC,
            TRACE_BEFORE_PC_BITS_START,
            TRACE_AFTER_PC_BITS_START,
        ),
        (
            STATE_SP,
            TRACE_BEFORE_SP_BITS_START,
            TRACE_AFTER_SP_BITS_START,
        ),
    ] {
        sink.push(view.before(state)? - packed_bits(view, before_bits, 16)?)?;
        sink.push(view.after(state)? - packed_bits(view, after_bits, 16)?)?;
    }
    sink.push(enum_range(view.before(STATE_IME)?, 3))?;
    sink.push(enum_range(view.after(STATE_IME)?, 3))?;
    sink.push(enum_range(view.before(STATE_RUN_STATE)?, 4))?;
    sink.push(enum_range(view.after(STATE_RUN_STATE)?, 4))?;
    sink.push(boolean(view.before(STATE_PROFILE)?))?;
    sink.push(boolean(view.after(STATE_PROFILE)?))
}

fn constrain_mapper_ranges(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    sink.push(boolean(view.before(STATE_MBC3_RAM_ENABLED)?))?;
    sink.push(boolean(view.after(STATE_MBC3_RAM_ENABLED)?))?;
    for (state, bits) in [
        (STATE_MBC3_ROM_BANK, TRACE_BEFORE_ROM_BANK_BITS_START),
        (STATE_MBC3_ROM_BANK, TRACE_AFTER_ROM_BANK_BITS_START),
    ] {
        constrain_bit_range(view, sink, bits, 6)?;
        let value = if bits == TRACE_BEFORE_ROM_BANK_BITS_START {
            view.before(state)?
        } else {
            view.after(state)?
        };
        sink.push(value - packed_bits(view, bits, 6)?)?;
        sink.push(zero_from_bits(view, bits, 6)?)?;
    }
    for (state, bits) in [
        (STATE_MBC3_RAM_RTC_SELECT, TRACE_BEFORE_RAM_RTC_BITS_START),
        (STATE_MBC3_RAM_RTC_SELECT, TRACE_AFTER_RAM_RTC_BITS_START),
    ] {
        constrain_bit_range(view, sink, bits, 4)?;
        let value = if bits == TRACE_BEFORE_RAM_RTC_BITS_START {
            view.before(state)?
        } else {
            view.after(state)?
        };
        sink.push(value - packed_bits(view, bits, 4)?)?;
    }
    Ok(())
}

pub(super) fn zero_from_bits(
    view: &RowView<'_>,
    start: usize,
    width: usize,
) -> Result<NativeField, UniformError> {
    let one = NativeField::from_u64(1);
    (0..width).try_fold(one, |product, bit| {
        Ok(product * (one - view.value(start + bit)?))
    })
}

fn constrain_isa(view: &RowView<'_>, sink: &mut ConstraintSink<'_>) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let active = view.value(TRACE_ACTIVE)?;
    let padding = view.mode(PADDING_MODE)?;
    constrain_bit_range(view, sink, TRACE_ISA_ADDRESS_START, 9)?;
    for index in ISA_WRITE_BITS_START..ISA_TAKEN_TIMING {
        sink.push(boolean(view.isa(index)?))?;
    }
    sink.push(boolean(view.isa(ISA_TAKEN_TIMING)?))?;
    for index in ISA_OPERATION_BITS_START..ISA_OUTPUT_COUNT {
        sink.push(boolean(view.isa(index)?))?;
    }
    sink.push(active * (view.isa(ISA_VALID)? - one))?;
    for output in 0..ISA_OUTPUT_COUNT {
        sink.push(padding * view.isa(output)?)?;
    }
    for bit in 0..9 {
        let expected = NativeField::from_u64(((PADDING_ISA_ADDRESS >> bit) & 1) as u64);
        sink.push(padding * (view.value(TRACE_ISA_ADDRESS_START + bit)? - expected))?;
    }
    sink.push(active * (view.isa(ISA_PREFIX)? - view.value(TRACE_ISA_ADDRESS_START + 8)?))?;
    sink.push(active * (view.isa(ISA_OPCODE)? - packed_bits(view, TRACE_ISA_ADDRESS_START, 8)?))?;
    for (field, start, width) in [
        (ISA_OPERATION, ISA_OPERATION_BITS_START, 6),
        (ISA_ARGUMENT_ZERO, ISA_ARGUMENT_ZERO_BITS_START, 3),
        (ISA_ARGUMENT_ONE, ISA_ARGUMENT_ONE_BITS_START, 4),
    ] {
        sink.push(
            active * (view.isa(field)? - packed_bits(view, TRACE_ISA_OUTPUT_START + start, width)?),
        )?;
    }
    Ok(())
}

fn constrain_cycles_and_frames(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let increment = view.value(TRACE_CYCLE_INCREMENT)?;
    sink.push(view.after(STATE_CYCLES)? - view.before(STATE_CYCLES)? - increment)?;
    sink.push(view.after(STATE_PROFILE)? - view.before(STATE_PROFILE)?)?;
    sink.push(view.mode(PADDING_MODE)? * increment)?;
    sink.push((view.mode(HALT_WAKE_MODE)? + view.mode(DMA_BYTE_MODE)?) * increment)?;
    sink.push(view.mode(INTERRUPT_MODE)? * (increment - NativeField::from_u64(5)))?;
    let mut halt_idle_range = view.mode(HALT_IDLE_MODE)?;
    for admitted in 1..=6 {
        halt_idle_range *= increment - NativeField::from_u64(admitted);
    }
    sink.push(halt_idle_range)?;
    let branch = view.value(TRACE_BRANCH_TAKEN)?;
    let halt_bug = view.value(TRACE_HALT_BUG)?;
    let base = view.isa(ISA_BASE_CYCLES)?;
    let taken = view.isa(ISA_TAKEN_CYCLES)?;
    let selected = base + branch * view.isa(ISA_TAKEN_TIMING)? * (taken - base);
    sink.push(view.mode(INSTRUCTION_MODE)? * (increment - selected))?;
    for state in 0..STATE_CYCLES {
        let write = view.isa(ISA_WRITE_BITS_START + state)?;
        let halt_bug_reset = if state == STATE_RUN_STATE {
            NativeField::from_u64(3) * halt_bug
        } else {
            NativeField::from_u64(0)
        };
        sink.push(
            view.mode(INSTRUCTION_MODE)?
                * (one - write)
                * (view.after(state)? - view.before(state)? + halt_bug_reset),
        )?;
    }
    for state in 0..STATE_SCALAR_COUNT {
        sink.push(view.mode(PADDING_MODE)? * (view.after(state)? - view.before(state)?))?;
    }
    Ok(())
}

fn constrain_bus(view: &RowView<'_>, sink: &mut ConstraintSink<'_>) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let mut slot_active = Vec::with_capacity(TRACE_BUS_SLOTS);
    for slot in 0..TRACE_BUS_SLOTS {
        let active = bus_field(view, slot, 0)?;
        let kind_bits = bus_kind_bits(view, slot)?;
        sink.push(boolean(active))?;
        for bit in kind_bits {
            sink.push(boolean(*bit))?;
        }
        let mut valid = NativeField::from_u64(0);
        for code in 0..=18 {
            valid += bit_selector(kind_bits, code)?;
        }
        sink.push(valid - one)?;
        sink.push(active - (one - bit_selector(kind_bits, 0)?))?;
        for offset in BUS_ADDRESS_OFFSET..BUS_ADDRESS_OFFSET + BUS_TUPLE_FIELDS {
            sink.push((one - active) * bus_field(view, slot, offset)?)?;
        }
        let address_bits = TRACE_BUS_ADDRESS_BITS_START + slot * 16;
        constrain_bit_range(view, sink, address_bits, 16)?;
        sink.push(
            bus_field(view, slot, BUS_ADDRESS_OFFSET)? - packed_bits(view, address_bits, 16)?,
        )?;
        let physical_bits = TRACE_BUS_PHYSICAL_BITS_START + slot * ROM_ADDRESS_BIT_COUNT;
        constrain_bit_range(view, sink, physical_bits, ROM_ADDRESS_BIT_COUNT)?;
        sink.push(
            bus_field(view, slot, BUS_PHYSICAL_ADDRESS_OFFSET)?
                - packed_bits(view, physical_bits, ROM_ADDRESS_BIT_COUNT)?,
        )?;
        let value_bits = TRACE_BUS_VALUE_BITS_START + slot * 8;
        constrain_bit_range(view, sink, value_bits, 8)?;
        sink.push(bus_field(view, slot, BUS_VALUE_OFFSET)? - packed_bits(view, value_bits, 8)?)?;
        let before_bits = TRACE_BUS_BEFORE_BITS_START + slot * 8;
        constrain_bit_range(view, sink, before_bits, 8)?;
        sink.push(bus_field(view, slot, BUS_BEFORE_OFFSET)? - packed_bits(view, before_bits, 8)?)?;
        let rom_selector = view.value(TRACE_ROM_SELECTOR_START + slot)?;
        let expected_rom_selector = [1_u8, 2, 3, 16]
            .into_iter()
            .try_fold(NativeField::from_u64(0), |sum, code| {
                Ok::<_, UniformError>(sum + bit_selector(kind_bits, code)?)
            })?;
        sink.push(boolean(rom_selector))?;
        sink.push(rom_selector - expected_rom_selector)?;
        sink.push(
            view.value(TRACE_ROM_VALUE_START + slot)?
                - rom_selector * bus_field(view, slot, BUS_VALUE_OFFSET)?,
        )?;
        sink.push(view.mode(PADDING_MODE)? * active)?;
        slot_active.push(active);
    }
    for pair in slot_active.windows(2) {
        let prior = pair.first().copied().ok_or(UniformError::Shape)?;
        let next = pair.get(1).copied().ok_or(UniformError::Shape)?;
        sink.push(next * (one - prior))?;
    }
    constrain_instruction_bus_counts(view, sink, &slot_active)
}

fn constrain_instruction_bus_counts(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    slot_active: &[NativeField],
) -> Result<(), UniformError> {
    let instruction = view.mode(INSTRUCTION_MODE)?;
    let branch = view.value(TRACE_BRANCH_TAKEN)?;
    let event_count = slot_active.iter().copied().sum::<NativeField>();
    let opcode = bus_category(view, &[1, 14])?;
    let immediate = bus_category(view, &[2, 15])?;
    let data_read = bus_category(view, &[3, 4, 6, 9, 11, 13])?;
    let data_write = bus_category(view, &[5, 7, 8, 10, 12])?;
    let base_count = view.isa(ISA_OPCODE_FETCHES)?
        + view.isa(ISA_IMMEDIATE_READS)?
        + view.isa(ISA_DATA_READS)?
        + view.isa(ISA_DATA_WRITES)?;
    let taken_count = view.isa(ISA_TAKEN_DATA_READS)? + view.isa(ISA_TAKEN_DATA_WRITES)?;
    sink.push(instruction * (event_count - base_count - branch * taken_count))?;
    sink.push(instruction * (opcode - view.isa(ISA_OPCODE_FETCHES)?))?;
    sink.push(instruction * (immediate - view.isa(ISA_IMMEDIATE_READS)?))?;
    sink.push(
        instruction
            * (data_read - view.isa(ISA_DATA_READS)? - branch * view.isa(ISA_TAKEN_DATA_READS)?),
    )?;
    sink.push(
        instruction
            * (data_write
                - view.isa(ISA_DATA_WRITES)?
                - branch * view.isa(ISA_TAKEN_DATA_WRITES)?),
    )
}

fn constrain_bit_range(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    start: usize,
    count: usize,
) -> Result<(), UniformError> {
    for index in start..start.checked_add(count).ok_or(UniformError::Shape)? {
        sink.push(boolean(view.value(index)?))?;
    }
    Ok(())
}

pub(super) fn packed_bits(
    view: &RowView<'_>,
    start: usize,
    width: usize,
) -> Result<NativeField, UniformError> {
    let mut power = NativeField::from_u64(1);
    let mut packed = NativeField::from_u64(0);
    for bit in 0..width {
        packed += power * view.value(start + bit)?;
        power += power;
    }
    Ok(packed)
}

pub(super) fn boolean(value: NativeField) -> NativeField {
    value * (value - NativeField::from_u64(1))
}

fn enum_range(value: NativeField, count: u64) -> NativeField {
    (0..count).fold(NativeField::from_u64(1), |product, admitted| {
        product * (value - NativeField::from_u64(admitted))
    })
}

fn bus_slot_start(slot: usize) -> Result<usize, UniformError> {
    TRACE_BUS_START
        .checked_add(
            slot.checked_mul(TRACE_BUS_SLOT_WIDTH)
                .ok_or(UniformError::Shape)?,
        )
        .ok_or(UniformError::Shape)
}

pub(super) fn bus_field(
    view: &RowView<'_>,
    slot: usize,
    offset: usize,
) -> Result<NativeField, UniformError> {
    view.value(
        bus_slot_start(slot)?
            .checked_add(offset)
            .ok_or(UniformError::Shape)?,
    )
}

pub(super) fn bus_kind_bits<'a>(
    view: &'a RowView<'a>,
    slot: usize,
) -> Result<&'a [NativeField], UniformError> {
    let start = bus_slot_start(slot)?
        .checked_add(1)
        .ok_or(UniformError::Shape)?;
    let end = start
        .checked_add(TRACE_BUS_KIND_BITS)
        .ok_or(UniformError::Shape)?;
    view.row.get(start..end).ok_or(UniformError::Shape)
}

fn bus_category(view: &RowView<'_>, codes: &[u8]) -> Result<NativeField, UniformError> {
    let mut count = NativeField::from_u64(0);
    for slot in 0..TRACE_BUS_SLOTS {
        let bits = bus_kind_bits(view, slot)?;
        for code in codes {
            count += bit_selector(bits, *code)?;
        }
    }
    Ok(count)
}

pub(super) fn bit_selector(bits: &[NativeField], code: u8) -> Result<NativeField, UniformError> {
    if bits.is_empty() || bits.len() > 8 {
        return Err(UniformError::Shape);
    }
    let one = NativeField::from_u64(1);
    Ok(bits
        .iter()
        .copied()
        .enumerate()
        .fold(one, |selector, (bit, value)| {
            if (code >> bit) & 1 == 1 {
                selector * value
            } else {
                selector * (one - value)
            }
        }))
}

pub(super) fn operation_selector(
    view: &RowView<'_>,
    code: u8,
) -> Result<NativeField, UniformError> {
    isa_selector(view, ISA_OPERATION_BITS_START, 6, code)
}

pub(super) fn argument_selector(
    view: &RowView<'_>,
    start: usize,
    width: usize,
    code: u8,
) -> Result<NativeField, UniformError> {
    isa_selector(view, start, width, code)
}

fn isa_selector(
    view: &RowView<'_>,
    start: usize,
    width: usize,
    code: u8,
) -> Result<NativeField, UniformError> {
    let bits = (0..width)
        .map(|bit| view.isa(start + bit))
        .collect::<Result<Vec<_>, _>>()?;
    bit_selector(&bits, code)
}

#[cfg(test)]
mod tests;
