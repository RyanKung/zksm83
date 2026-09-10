//! Committed structural glue for complete VM-state trace segments.

use ff::{Field, PrimeField};
use pasta_curves::Fp;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zksm83_core::{DmgInterrupt, RunState, StepKind, VmState};
use zksm83_isa::{AlignedInstruction, AlignmentPackingError};
use zksm83_memory::{BusTranscriptError, BusTranscriptEvent, IsaTranscriptError};
use zksm83_trace::TraceRow;

use crate::{
    CommittedMultiQueryShoutError, CommittedMultiQueryShoutProof,
    CommittedShiftedUniformTraceProof, IpaCommitment, IpaParameters, ShiftedUniformRelation,
    UniformTraceError, VM_STATE_FIELD_COUNT, encode_vm_state, encode_vm_state_columns,
};

const MODE_COUNT: usize = 10;
const INTERRUPT_SOURCE_COUNT: usize = 5;
const LOCAL_CYCLE_INCREMENT: usize = MODE_COUNT + INTERRUPT_SOURCE_COUNT;
const LOCAL_BRANCH_TAKEN: usize = LOCAL_CYCLE_INCREMENT + 1;
const LOCAL_ISA_ADDRESS_START: usize = LOCAL_BRANCH_TAKEN + 1;
const ISA_ADDRESS_BITS: usize = 9;
const LOCAL_ISA_OUTPUT_START: usize = LOCAL_ISA_ADDRESS_START + ISA_ADDRESS_BITS;
const ISA_OUTPUT_COUNT: usize = 56;
const ISA_OPERATION_BITS_START: usize = 35;
const ISA_OPERATION_BITS: usize = 6;
const ISA_ARGUMENT_ZERO_BITS_START: usize = ISA_OPERATION_BITS_START + ISA_OPERATION_BITS;
const ISA_ARGUMENT_ZERO_BITS: usize = 3;
const ISA_ARGUMENT_ONE_BITS_START: usize = ISA_ARGUMENT_ZERO_BITS_START + ISA_ARGUMENT_ZERO_BITS;
const ISA_ARGUMENT_ONE_BITS: usize = 4;
const LOCAL_CPU_FLAG_BITS_START: usize = LOCAL_ISA_OUTPUT_START + ISA_OUTPUT_COUNT;
const CPU_FLAG_BITS: usize = 8;
const LOCAL_NEXT_CPU_FLAG_BITS_START: usize = LOCAL_CPU_FLAG_BITS_START + CPU_FLAG_BITS;
const LOCAL_PC_WRAP: usize = LOCAL_NEXT_CPU_FLAG_BITS_START + CPU_FLAG_BITS;
const LOCAL_OPERAND_VALUE: usize = LOCAL_PC_WRAP + 1;
const LOCAL_RESULT_VALUE: usize = LOCAL_OPERAND_VALUE + 1;
const LOCAL_WORD_WRAP: usize = LOCAL_RESULT_VALUE + 1;
const LOCAL_IMMEDIATE_BITS_START: usize = LOCAL_WORD_WRAP + 1;
const IMMEDIATE_BITS: usize = 8;
const LOCAL_CONTROL_WRAP: usize = LOCAL_IMMEDIATE_BITS_START + IMMEDIATE_BITS;
const LOCAL_STACK_WRAP: usize = LOCAL_CONTROL_WRAP + 1;
const LOCAL_STACK_FIRST_WRAP: usize = LOCAL_STACK_WRAP + 1;
const LOCAL_ADDRESS_WRAP: usize = LOCAL_STACK_FIRST_WRAP + 1;
const LOCAL_OPERAND_BITS_START: usize = LOCAL_ADDRESS_WRAP + 1;
const OPERAND_BITS: usize = 8;
const LOCAL_RESULT_BITS_START: usize = LOCAL_OPERAND_BITS_START + OPERAND_BITS;
const RESULT_BITS: usize = 8;
const LOCAL_ARITHMETIC_CARRY: usize = LOCAL_RESULT_BITS_START + RESULT_BITS;
const LOCAL_HALF_CARRY: usize = LOCAL_ARITHMETIC_CARRY + 1;
const LOCAL_RESULT_ZERO: usize = LOCAL_HALF_CARRY + 1;
const LOCAL_RESULT_INVERSE: usize = LOCAL_RESULT_ZERO + 1;
const LOCAL_CPU_BYTE_BITS_START: usize = LOCAL_RESULT_INVERSE + 1;
const CPU_BYTE_COUNT: usize = 7;
const BYTE_BITS: usize = 8;
const LOCAL_PC_BITS_START: usize = LOCAL_CPU_BYTE_BITS_START + CPU_BYTE_COUNT * BYTE_BITS;
const WORD_BITS: usize = 16;
const LOCAL_SP_BITS_START: usize = LOCAL_PC_BITS_START + WORD_BITS;
const LOCAL_BUS_START: usize = LOCAL_SP_BITS_START + WORD_BITS;
const BUS_EVENT_SLOTS: usize = 5;
const BUS_KIND_BITS: usize = 5;
const BUS_TUPLE_FIELDS: usize = 6;
const BUS_SLOT_WIDTH: usize = 1 + BUS_KIND_BITS + BUS_TUPLE_FIELDS;
const BUS_ADDRESS: usize = 1 + BUS_KIND_BITS;
const BUS_PHYSICAL_ADDRESS: usize = BUS_ADDRESS + 1;
const BUS_BEFORE: usize = BUS_PHYSICAL_ADDRESS + 1;
const BUS_AUXILIARY: usize = BUS_BEFORE + 1;
const BUS_VALUE: usize = BUS_AUXILIARY + 1;
const BUS_INDEX: usize = BUS_VALUE + 1;
const LOCAL_COLUMN_COUNT: usize = LOCAL_BUS_START + BUS_EVENT_SLOTS * BUS_SLOT_WIDTH;
const CONSTRAINT_COUNT: usize = 466 + BUS_EVENT_SLOTS * BUS_TUPLE_FIELDS;
const ISA_VALID: usize = 0;
const ISA_PREFIX: usize = 2;
const ISA_OPCODE: usize = 3;
const ISA_BASE_CYCLES: usize = 9;
const ISA_TAKEN_CYCLES: usize = 10;
const ISA_WRITE_BITS_START: usize = 21;
const ISA_TAKEN_TIMING: usize = 34;
const STATE_PC: usize = 8;
const STATE_IME: usize = 10;
const STATE_RUN_STATE: usize = 11;
const STATE_CYCLES: usize = 12;
const STATE_ROM_ROOT: usize = 16;
const STATE_BUS_TRANSCRIPT_INDEX: usize = 22;
const STATE_ISA_TRANSCRIPT_INDEX: usize = 24;
const STATE_PROFILE: usize = 26;

/// Structural transition relation for one complete VM-state segment.
///
/// This relation binds both public boundaries, ordered state columns, one-hot
/// machine-step modes, interrupt-source selection, cycle deltas, immutable ROM
/// identity, and machine-profile continuity. It deliberately does **not** yet
/// prove opcode semantics, bus authentication, transcript hashing, or device
/// transitions; those are separate native Shout/Twist and low-degree glue
/// obligations under active implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmStateStructuralRelation {
    initial: [Fp; VM_STATE_FIELD_COUNT],
}

impl VmStateStructuralRelation {
    /// Constructs the public relation statement from the exact initial state.
    #[must_use]
    pub fn new(initial: VmState) -> Self {
        Self {
            initial: encode_vm_state(initial),
        }
    }
}

impl ShiftedUniformRelation for VmStateStructuralRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83-vm-state-structural-glue/v1"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        self.initial
            .iter()
            .flat_map(|value| value.to_repr())
            .collect()
    }

    fn state_column_count(&self) -> usize {
        VM_STATE_FIELD_COUNT
    }

    fn local_column_count(&self) -> usize {
        LOCAL_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        CONSTRAINT_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        14
    }

    fn evaluate(
        &self,
        current: &[Fp],
        next: &[Fp],
        local: &[Fp],
        first_selector: Fp,
        constraints: &mut [Fp],
    ) -> Result<(), UniformTraceError> {
        if current.len() != VM_STATE_FIELD_COUNT
            || next.len() != VM_STATE_FIELD_COUNT
            || local.len() != LOCAL_COLUMN_COUNT
            || constraints.len() != CONSTRAINT_COUNT
        {
            return Err(UniformTraceError::Relation);
        }
        let mut cursor = 0;
        for ((current, initial), constraint) in
            current.iter().zip(self.initial).zip(constraints.iter_mut())
        {
            *constraint = first_selector * (*current - initial);
            cursor += 1;
        }
        for selector in local.iter().take(MODE_COUNT + INTERRUPT_SOURCE_COUNT) {
            set_constraint(constraints, &mut cursor, *selector * (*selector - Fp::ONE))?;
        }
        let branch = *local
            .get(LOCAL_BRANCH_TAKEN)
            .ok_or(UniformTraceError::Relation)?;
        set_constraint(constraints, &mut cursor, branch * (branch - Fp::ONE))?;
        let address_bits = local
            .get(LOCAL_ISA_ADDRESS_START..LOCAL_ISA_OUTPUT_START)
            .ok_or(UniformTraceError::Relation)?;
        let isa = local
            .get(LOCAL_ISA_OUTPUT_START..LOCAL_BUS_START)
            .ok_or(UniformTraceError::Relation)?;
        let write_bits = isa
            .get(ISA_WRITE_BITS_START..ISA_TAKEN_TIMING)
            .ok_or(UniformTraceError::Relation)?;
        let operation_bits = isa
            .get(ISA_OPERATION_BITS_START..ISA_ARGUMENT_ZERO_BITS_START)
            .ok_or(UniformTraceError::Relation)?;
        let argument_zero_bits = isa
            .get(ISA_ARGUMENT_ZERO_BITS_START..ISA_ARGUMENT_ONE_BITS_START)
            .ok_or(UniformTraceError::Relation)?;
        let argument_one_bits = isa
            .get(ISA_ARGUMENT_ONE_BITS_START..ISA_OUTPUT_COUNT)
            .ok_or(UniformTraceError::Relation)?;
        let flag_bits = local
            .get(LOCAL_CPU_FLAG_BITS_START..LOCAL_PC_WRAP)
            .ok_or(UniformTraceError::Relation)?;
        let immediate_bits = local
            .get(LOCAL_IMMEDIATE_BITS_START..LOCAL_CONTROL_WRAP)
            .ok_or(UniformTraceError::Relation)?;
        let cpu_byte_bits = local
            .get(LOCAL_CPU_BYTE_BITS_START..LOCAL_PC_BITS_START)
            .ok_or(UniformTraceError::Relation)?;
        let pc_bits = local
            .get(LOCAL_PC_BITS_START..LOCAL_SP_BITS_START)
            .ok_or(UniformTraceError::Relation)?;
        let sp_bits = local
            .get(LOCAL_SP_BITS_START..LOCAL_BUS_START)
            .ok_or(UniformTraceError::Relation)?;
        let operand_bits = local
            .get(LOCAL_OPERAND_BITS_START..LOCAL_RESULT_BITS_START)
            .ok_or(UniformTraceError::Relation)?;
        let result_bits = local
            .get(LOCAL_RESULT_BITS_START..LOCAL_ARITHMETIC_CARRY)
            .ok_or(UniformTraceError::Relation)?;
        let taken_timing = *isa
            .get(ISA_TAKEN_TIMING)
            .ok_or(UniformTraceError::Relation)?;
        for bit in address_bits
            .iter()
            .chain(write_bits)
            .chain(operation_bits)
            .chain(argument_zero_bits)
            .chain(argument_one_bits)
            .chain(flag_bits)
            .chain(immediate_bits)
            .chain(operand_bits)
            .chain(result_bits)
            .chain(cpu_byte_bits)
            .chain(pc_bits)
            .chain(sp_bits)
        {
            set_constraint(constraints, &mut cursor, *bit * (*bit - Fp::ONE))?;
        }
        set_constraint(
            constraints,
            &mut cursor,
            taken_timing * (taken_timing - Fp::ONE),
        )?;
        let pc_wrap = indexed(local, LOCAL_PC_WRAP)?;
        set_constraint(constraints, &mut cursor, pc_wrap * (pc_wrap - Fp::ONE))?;
        let word_wrap = indexed(local, LOCAL_WORD_WRAP)?;
        set_constraint(constraints, &mut cursor, word_wrap * (word_wrap - Fp::ONE))?;
        let control_wrap = indexed(local, LOCAL_CONTROL_WRAP)?;
        set_constraint(
            constraints,
            &mut cursor,
            control_wrap * (control_wrap - Fp::ONE) * (control_wrap + Fp::ONE),
        )?;
        let stack_wrap = indexed(local, LOCAL_STACK_WRAP)?;
        set_constraint(
            constraints,
            &mut cursor,
            stack_wrap * (stack_wrap - Fp::ONE),
        )?;
        let stack_first_wrap = indexed(local, LOCAL_STACK_FIRST_WRAP)?;
        set_constraint(
            constraints,
            &mut cursor,
            stack_first_wrap * (stack_first_wrap - Fp::ONE),
        )?;
        let address_wrap = indexed(local, LOCAL_ADDRESS_WRAP)?;
        set_constraint(
            constraints,
            &mut cursor,
            address_wrap * (address_wrap - Fp::ONE),
        )?;
        let arithmetic_carry = indexed(local, LOCAL_ARITHMETIC_CARRY)?;
        set_constraint(
            constraints,
            &mut cursor,
            arithmetic_carry * (arithmetic_carry - Fp::ONE),
        )?;
        let half_carry = indexed(local, LOCAL_HALF_CARRY)?;
        set_constraint(
            constraints,
            &mut cursor,
            half_carry * (half_carry - Fp::ONE),
        )?;
        let result_zero = indexed(local, LOCAL_RESULT_ZERO)?;
        set_constraint(
            constraints,
            &mut cursor,
            result_zero * (result_zero - Fp::ONE),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            indexed(current, 7)? - packed_bits_value(flag_bits, 0, CPU_FLAG_BITS)?,
        )?;
        for bit in flag_bits.iter().take(4) {
            set_constraint(constraints, &mut cursor, *bit)?;
        }
        for state_index in 0..CPU_BYTE_COUNT {
            let bit_start = state_index
                .checked_mul(BYTE_BITS)
                .ok_or(UniformTraceError::Relation)?;
            set_constraint(
                constraints,
                &mut cursor,
                indexed(current, state_index)?
                    - packed_bits_value(cpu_byte_bits, bit_start, BYTE_BITS)?,
            )?;
        }
        set_constraint(
            constraints,
            &mut cursor,
            indexed(current, STATE_PC)? - packed_bits_value(pc_bits, 0, WORD_BITS)?,
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            indexed(current, 9)? - packed_bits_value(sp_bits, 0, WORD_BITS)?,
        )?;
        let operand_value = indexed(local, LOCAL_OPERAND_VALUE)?;
        set_constraint(
            constraints,
            &mut cursor,
            operand_value - packed_bits_value(operand_bits, 0, OPERAND_BITS)?,
        )?;
        let result_value = packed_bits_value(result_bits, 0, RESULT_BITS)?;
        set_constraint(
            constraints,
            &mut cursor,
            result_value - indexed(local, LOCAL_RESULT_VALUE)?,
        )?;
        set_constraint(constraints, &mut cursor, result_value * result_zero)?;
        set_constraint(
            constraints,
            &mut cursor,
            result_value * indexed(local, LOCAL_RESULT_INVERSE)? - (Fp::ONE - result_zero),
        )?;
        let mut bus_active = Vec::with_capacity(BUS_EVENT_SLOTS);
        for slot in 0..BUS_EVENT_SLOTS {
            let (active, kind_bits) = bus_slot(local, slot)?;
            set_constraint(constraints, &mut cursor, active * (active - Fp::ONE))?;
            for bit in kind_bits {
                set_constraint(constraints, &mut cursor, *bit * (*bit - Fp::ONE))?;
            }
            let valid = (0_u8..=18).try_fold(Fp::ZERO, |sum, code| {
                Ok::<_, UniformTraceError>(sum + kind_selector(kind_bits, code)?)
            })?;
            set_constraint(constraints, &mut cursor, valid - Fp::ONE)?;
            set_constraint(
                constraints,
                &mut cursor,
                active - (Fp::ONE - kind_selector(kind_bits, 0)?),
            )?;
            for value in bus_tuple(local, slot)? {
                set_constraint(constraints, &mut cursor, (Fp::ONE - active) * *value)?;
            }
            bus_active.push(active);
        }
        for pair in bus_active.windows(2) {
            let prior = *pair.first().ok_or(UniformTraceError::Relation)?;
            let next = *pair.get(1).ok_or(UniformTraceError::Relation)?;
            set_constraint(constraints, &mut cursor, next * (Fp::ONE - prior))?;
        }
        let modes = local.get(..MODE_COUNT).ok_or(UniformTraceError::Relation)?;
        let instruction = *modes.first().ok_or(UniformTraceError::Relation)?;
        let interrupt_sources = local
            .get(MODE_COUNT..LOCAL_CYCLE_INCREMENT)
            .ok_or(UniformTraceError::Relation)?;
        let interrupt = *modes.get(8).ok_or(UniformTraceError::Relation)?;
        let halt_wake = *modes.get(7).ok_or(UniformTraceError::Relation)?;
        let dma = *modes.get(9).ok_or(UniformTraceError::Relation)?;
        let cycle_increment = *local
            .get(LOCAL_CYCLE_INCREMENT)
            .ok_or(UniformTraceError::Relation)?;
        let base_cycles = *isa
            .get(ISA_BASE_CYCLES)
            .ok_or(UniformTraceError::Relation)?;
        let taken_cycles = *isa
            .get(ISA_TAKEN_CYCLES)
            .ok_or(UniformTraceError::Relation)?;

        set_constraint(
            constraints,
            &mut cursor,
            modes.iter().copied().sum::<Fp>() - Fp::ONE,
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            interrupt_sources.iter().copied().sum::<Fp>() - interrupt,
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            indexed(next, STATE_ROM_ROOT)? - indexed(current, STATE_ROM_ROOT)?,
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            indexed(next, STATE_PROFILE)? - indexed(current, STATE_PROFILE)?,
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            indexed(next, STATE_CYCLES)? - indexed(current, STATE_CYCLES)? - cycle_increment,
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            (halt_wake + dma) * cycle_increment,
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            interrupt * (cycle_increment - Fp::from(5)),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            *modes.get(6).ok_or(UniformTraceError::Relation)?,
        )?;
        let event_count = bus_active.iter().copied().sum::<Fp>();
        set_constraint(
            constraints,
            &mut cursor,
            indexed(next, STATE_BUS_TRANSCRIPT_INDEX)?
                - indexed(current, STATE_BUS_TRANSCRIPT_INDEX)?
                - event_count,
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            indexed(next, STATE_ISA_TRANSCRIPT_INDEX)?
                - indexed(current, STATE_ISA_TRANSCRIPT_INDEX)?
                - Fp::ONE,
        )?;
        let base_event_count = *isa.get(15).ok_or(UniformTraceError::Relation)?
            + *isa.get(16).ok_or(UniformTraceError::Relation)?
            + *isa.get(17).ok_or(UniformTraceError::Relation)?
            + *isa.get(18).ok_or(UniformTraceError::Relation)?;
        let taken_event_count = *isa.get(19).ok_or(UniformTraceError::Relation)?
            + *isa.get(20).ok_or(UniformTraceError::Relation)?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction * (event_count - base_event_count - branch * taken_event_count),
        )?;
        let categories = bus_category_counts(local)?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction * (categories.opcode - *isa.get(15).ok_or(UniformTraceError::Relation)?),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * (categories.immediate - *isa.get(16).ok_or(UniformTraceError::Relation)?),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * (categories.data_read
                    - *isa.get(17).ok_or(UniformTraceError::Relation)?
                    - branch * *isa.get(19).ok_or(UniformTraceError::Relation)?),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * (categories.data_write
                    - *isa.get(18).ok_or(UniformTraceError::Relation)?
                    - branch * *isa.get(20).ok_or(UniformTraceError::Relation)?),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            *isa.get(ISA_VALID).ok_or(UniformTraceError::Relation)? - Fp::ONE,
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            *isa.get(ISA_PREFIX).ok_or(UniformTraceError::Relation)? - indexed(address_bits, 8)?,
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            *isa.get(ISA_OPCODE).ok_or(UniformTraceError::Relation)?
                - packed_bits_value(address_bits, 0, 8)?,
        )?;
        set_constraint(constraints, &mut cursor, (Fp::ONE - instruction) * branch)?;
        let zero_flag = indexed(flag_bits, 7)?;
        let carry_flag = indexed(flag_bits, 4)?;
        let conditional = isa_operation_selector(isa, 3)?
            + isa_operation_selector(isa, 20)?
            + isa_operation_selector(isa, 28)?
            + isa_operation_selector(isa, 34)?;
        let condition = isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 0)?
            + isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 1)? * (Fp::ONE - zero_flag)
            + isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 2)? * zero_flag
            + isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 3)? * (Fp::ONE - carry_flag)
            + isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 4)? * carry_flag;
        let fixed_taken = isa_operation_selector(isa, 25)?
            + isa_operation_selector(isa, 26)?
            + isa_operation_selector(isa, 36)?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction * (branch - conditional * condition - fixed_taken),
        )?;
        let ime = indexed(current, STATE_IME)?;
        set_constraint(
            constraints,
            &mut cursor,
            ime * (ime - Fp::ONE) * (ime - Fp::from(2)),
        )?;
        let ime_pending = ime * (Fp::from(2) - ime);
        let delayed_ime = ime + ime_pending * (Fp::from(2) - ime);
        let disable_interrupts = isa_operation_selector(isa, 32)?;
        let enable_interrupts = isa_operation_selector(isa, 33)?;
        let return_from_interrupt = isa_operation_selector(isa, 25)?;
        let expected_ime = delayed_ime - disable_interrupts * delayed_ime
            + enable_interrupts * (Fp::ONE + ime_pending - delayed_ime)
            + return_from_interrupt * (Fp::from(2) - delayed_ime);
        set_constraint(
            constraints,
            &mut cursor,
            instruction * (indexed(next, STATE_IME)? - expected_ime),
        )?;
        let run_state = indexed(current, STATE_RUN_STATE)?;
        set_constraint(
            constraints,
            &mut cursor,
            run_state
                * (run_state - Fp::ONE)
                * (run_state - Fp::from(2))
                * (run_state - Fp::from(3)),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction * run_state * (run_state - Fp::from(3)),
        )?;
        let stop = isa_operation_selector(isa, 2)?;
        let halt = isa_operation_selector(isa, 18)?;
        let next_run_state = indexed(next, STATE_RUN_STATE)?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction * (Fp::ONE - stop - halt) * next_run_state,
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction * stop * (next_run_state - Fp::from(2)),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction * halt * (next_run_state - Fp::ONE) * (next_run_state - Fp::from(3)),
        )?;
        let prefix = *isa.get(ISA_PREFIX).ok_or(UniformTraceError::Relation)?;
        let opcode = *isa.get(ISA_OPCODE).ok_or(UniformTraceError::Relation)?;
        let first_opcode = bus_kind_sum(local, 0, &[1, 14])?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction * (first_opcode - Fp::ONE),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction * (bus_field(local, 0, BUS_ADDRESS)? - indexed(current, STATE_PC)?),
        )?;
        let expected_first = prefix * Fp::from(0xcb) + (Fp::ONE - prefix) * opcode;
        set_constraint(
            constraints,
            &mut cursor,
            instruction * (bus_field(local, 0, BUS_VALUE)? - expected_first),
        )?;
        let second_opcode = bus_kind_sum(local, 1, &[1, 14])?;
        let halt_bug = run_state
            * Option::<Fp>::from(Fp::from(3).invert()).ok_or(UniformTraceError::Relation)?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction * prefix * (second_opcode - Fp::ONE),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * prefix
                * (bus_field(local, 1, BUS_ADDRESS)? - indexed(current, STATE_PC)? - Fp::ONE
                    + halt_bug),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction * prefix * (bus_field(local, 1, BUS_VALUE)? - opcode),
        )?;
        let immediate_count = *isa.get(16).ok_or(UniformTraceError::Relation)?;
        let inverse_two =
            Option::<Fp>::from(Fp::from(2).invert()).ok_or(UniformTraceError::Relation)?;
        let first_immediate = immediate_count * (Fp::from(3) - immediate_count) * inverse_two;
        let second_immediate = immediate_count * (immediate_count - Fp::ONE) * inverse_two;
        let primary = instruction * (Fp::ONE - prefix);
        set_constraint(
            constraints,
            &mut cursor,
            packed_bits_value(immediate_bits, 0, IMMEDIATE_BITS)?
                - primary * first_immediate * bus_field(local, 1, BUS_VALUE)?,
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            primary * first_immediate * (bus_kind_sum(local, 1, &[2, 15])? - Fp::ONE),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            primary
                * first_immediate
                * (bus_field(local, 1, BUS_ADDRESS)? - indexed(current, STATE_PC)? - Fp::ONE
                    + halt_bug),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            primary * second_immediate * (bus_kind_sum(local, 2, &[2, 15])? - Fp::ONE),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            primary
                * second_immediate
                * (bus_field(local, 2, BUS_ADDRESS)? - indexed(current, STATE_PC)? - Fp::from(2)
                    + halt_bug),
        )?;
        let load16 = isa_operation_selector(isa, 4)?;
        let immediate_low = bus_field(local, 1, BUS_VALUE)?;
        let immediate_high = bus_field(local, 2, BUS_VALUE)?;
        let immediate_word = immediate_low + immediate_high * Fp::from(256);
        set_constraint(constraints, &mut cursor, instruction * stop * immediate_low)?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * load16
                * isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 0)?
                * (indexed(next, 1)? - immediate_high),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * load16
                * isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 0)?
                * (indexed(next, 2)? - immediate_low),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * load16
                * isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 1)?
                * (indexed(next, 3)? - immediate_high),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * load16
                * isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 1)?
                * (indexed(next, 4)? - immediate_low),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * load16
                * isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 2)?
                * (indexed(next, 5)? - immediate_high),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * load16
                * isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 2)?
                * (indexed(next, 6)? - immediate_low),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * load16
                * isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 3)?
                * (indexed(next, 9)? - immediate_word),
        )?;
        let load8_immediate = isa_operation_selector(isa, 11)?;
        for (argument, state_index) in [
            (0_u8, 1_usize),
            (1, 2),
            (2, 3),
            (3, 4),
            (4, 5),
            (5, 6),
            (7, 0),
        ] {
            set_constraint(
                constraints,
                &mut cursor,
                instruction
                    * load8_immediate
                    * isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, argument)?
                    * (indexed(next, state_index)? - immediate_low),
            )?;
        }
        let load8_immediate_memory = instruction
            * load8_immediate
            * isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 6)?;
        set_constraint(
            constraints,
            &mut cursor,
            load8_immediate_memory
                * (bus_field(local, 2, BUS_ADDRESS)?
                    - indexed(current, 5)? * Fp::from(256)
                    - indexed(current, 6)?),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            load8_immediate_memory * (bus_field(local, 2, BUS_VALUE)? - immediate_low),
        )?;
        let load8 = isa_operation_selector(isa, 17)?;
        let fetch_count = *isa.get(15).ok_or(UniformTraceError::Relation)? + immediate_count;
        let position_one = (fetch_count - Fp::from(2)) * (fetch_count - Fp::from(3)) * inverse_two;
        let position_two = -(fetch_count - Fp::ONE) * (fetch_count - Fp::from(3));
        let position_three = (fetch_count - Fp::ONE) * (fetch_count - Fp::from(2)) * inverse_two;
        let data_value = position_one * bus_field(local, 1, BUS_VALUE)?
            + position_two * bus_field(local, 2, BUS_VALUE)?
            + position_three * bus_field(local, 3, BUS_VALUE)?;
        let operand_value = indexed(local, LOCAL_OPERAND_VALUE)?;
        let selected_operand = isa_argument_selector(isa, ISA_ARGUMENT_ONE_BITS_START, 0)?
            * indexed(current, 1)?
            + isa_argument_selector(isa, ISA_ARGUMENT_ONE_BITS_START, 1)? * indexed(current, 2)?
            + isa_argument_selector(isa, ISA_ARGUMENT_ONE_BITS_START, 2)? * indexed(current, 3)?
            + isa_argument_selector(isa, ISA_ARGUMENT_ONE_BITS_START, 3)? * indexed(current, 4)?
            + isa_argument_selector(isa, ISA_ARGUMENT_ONE_BITS_START, 4)? * indexed(current, 5)?
            + isa_argument_selector(isa, ISA_ARGUMENT_ONE_BITS_START, 5)? * indexed(current, 6)?
            + isa_argument_selector(isa, ISA_ARGUMENT_ONE_BITS_START, 6)? * data_value
            + isa_argument_selector(isa, ISA_ARGUMENT_ONE_BITS_START, 7)? * indexed(current, 0)?
            + isa_argument_selector(isa, ISA_ARGUMENT_ONE_BITS_START, 8)? * immediate_low;
        set_constraint(
            constraints,
            &mut cursor,
            instruction * load8 * (operand_value - selected_operand),
        )?;
        for (argument, state_index) in [
            (0_u8, 1_usize),
            (1, 2),
            (2, 3),
            (3, 4),
            (4, 5),
            (5, 6),
            (7, 0),
        ] {
            set_constraint(
                constraints,
                &mut cursor,
                instruction
                    * load8
                    * isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, argument)?
                    * (indexed(next, state_index)? - operand_value),
            )?;
        }
        let load8_memory =
            instruction * load8 * isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 6)?;
        set_constraint(
            constraints,
            &mut cursor,
            load8_memory
                * (bus_field(local, 1, BUS_ADDRESS)?
                    - indexed(current, 5)? * Fp::from(256)
                    - indexed(current, 6)?),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            load8_memory * (bus_field(local, 1, BUS_VALUE)? - operand_value),
        )?;
        let increment8 = isa_operation_selector(isa, 9)?;
        let decrement8 = isa_operation_selector(isa, 10)?;
        let alu8 = isa_operation_selector(isa, 19)?;
        let increment_decrement = increment8 + decrement8;
        let selected_target_operand = isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 0)?
            * indexed(current, 1)?
            + isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 1)? * indexed(current, 2)?
            + isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 2)? * indexed(current, 3)?
            + isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 3)? * indexed(current, 4)?
            + isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 4)? * indexed(current, 5)?
            + isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 5)? * indexed(current, 6)?
            + isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 6)? * data_value
            + isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 7)? * indexed(current, 0)?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction * increment_decrement * (operand_value - selected_target_operand),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction * alu8 * (operand_value - selected_operand),
        )?;
        let arithmetic_use = increment_decrement + alu8;
        set_constraint(
            constraints,
            &mut cursor,
            result_value * (Fp::ONE - arithmetic_use),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            arithmetic_carry * (Fp::ONE - arithmetic_use),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            half_carry * (Fp::ONE - arithmetic_use),
        )?;
        let operand_low = packed_bits_value(operand_bits, 0, 4)?;
        let result_low = packed_bits_value(result_bits, 0, 4)?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * increment8
                * (operand_value + Fp::ONE - result_value - Fp::from(256) * arithmetic_carry),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * increment8
                * (operand_low + Fp::ONE - result_low - Fp::from(16) * half_carry),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * decrement8
                * (operand_value + Fp::from(256) * arithmetic_carry - result_value - Fp::ONE),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * decrement8
                * (operand_low + Fp::from(16) * half_carry - result_low - Fp::ONE),
        )?;
        for (argument, state_index) in [
            (0_u8, 1_usize),
            (1, 2),
            (2, 3),
            (3, 4),
            (4, 5),
            (5, 6),
            (7, 0),
        ] {
            set_constraint(
                constraints,
                &mut cursor,
                instruction
                    * increment_decrement
                    * isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, argument)?
                    * (indexed(next, state_index)? - result_value),
            )?;
        }
        let increment_decrement_memory =
            increment_decrement * isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 6)?;
        let arithmetic_hl = indexed(current, 5)? * Fp::from(256) + indexed(current, 6)?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * increment_decrement_memory
                * (bus_field(local, 1, BUS_ADDRESS)? - arithmetic_hl),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * increment_decrement_memory
                * (bus_field(local, 1, BUS_VALUE)? - operand_value),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * increment_decrement_memory
                * (bus_field(local, 2, BUS_ADDRESS)? - arithmetic_hl),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * increment_decrement_memory
                * (bus_field(local, 2, BUS_VALUE)? - result_value),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * increment8
                * (indexed(next, 7)?
                    - result_zero * Fp::from(128)
                    - half_carry * Fp::from(32)
                    - carry_flag * Fp::from(16)),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * decrement8
                * (indexed(next, 7)?
                    - result_zero * Fp::from(128)
                    - Fp::from(64)
                    - half_carry * Fp::from(32)
                    - carry_flag * Fp::from(16)),
        )?;

        let alu_add = isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 0)?;
        let alu_add_carry = isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 1)?;
        let alu_subtract = isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 2)?;
        let alu_subtract_carry = isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 3)?;
        let alu_and = isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 4)?;
        let alu_xor = isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 5)?;
        let alu_or = isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 6)?;
        let alu_compare = isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 7)?;
        let add_group = alu_add + alu_add_carry;
        let subtract_group = alu_subtract + alu_subtract_carry + alu_compare;
        let logical_group = alu_and + alu_xor + alu_or;
        let accumulator_low = packed_bits_value(cpu_byte_bits, 0, 4)?;
        let add_carry_in = alu_add_carry * carry_flag;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * alu8
                * add_group
                * (indexed(current, 0)? + operand_value + add_carry_in
                    - result_value
                    - Fp::from(256) * arithmetic_carry),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * alu8
                * add_group
                * (accumulator_low + operand_low + add_carry_in
                    - result_low
                    - Fp::from(16) * half_carry),
        )?;
        let subtract_carry_in = alu_subtract_carry * carry_flag;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * alu8
                * subtract_group
                * (indexed(current, 0)? + Fp::from(256) * arithmetic_carry
                    - operand_value
                    - subtract_carry_in
                    - result_value),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * alu8
                * subtract_group
                * (accumulator_low + Fp::from(16) * half_carry
                    - operand_low
                    - subtract_carry_in
                    - result_low),
        )?;
        let accumulator_bits = cpu_byte_bits
            .get(..BYTE_BITS)
            .ok_or(UniformTraceError::Relation)?;
        for bit in 0..RESULT_BITS {
            let left = indexed(accumulator_bits, bit)?;
            let right = indexed(operand_bits, bit)?;
            let product = left * right;
            let expected = alu_and * product
                + alu_xor * (left + right - Fp::from(2) * product)
                + alu_or * (left + right - product);
            set_constraint(
                constraints,
                &mut cursor,
                instruction * alu8 * (logical_group * indexed(result_bits, bit)? - expected),
            )?;
        }
        set_constraint(
            constraints,
            &mut cursor,
            instruction * alu8 * (Fp::ONE - alu_compare) * (indexed(next, 0)? - result_value),
        )?;
        let expected_alu_flags = result_zero * Fp::from(128)
            + subtract_group * Fp::from(64)
            + (add_group + subtract_group) * half_carry * Fp::from(32)
            + alu_and * Fp::from(32)
            + (add_group + subtract_group) * arithmetic_carry * Fp::from(16);
        set_constraint(
            constraints,
            &mut cursor,
            instruction * alu8 * (indexed(next, 7)? - expected_alu_flags),
        )?;
        let current_word = selected_register_word(current, isa)?;
        let next_word = selected_register_word(next, isa)?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * isa_operation_selector(isa, 7)?
                * (next_word - current_word - Fp::ONE + word_wrap * Fp::from(65_536_u64)),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * isa_operation_selector(isa, 8)?
                * (next_word - current_word + Fp::ONE - word_wrap * Fp::from(65_536_u64)),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * isa_operation_selector(isa, 27)?
                * (indexed(next, 9)? - indexed(current, 5)? * Fp::from(256) - indexed(current, 6)?),
        )?;
        let store_sp = isa_operation_selector(isa, 1)?;
        set_constraint(
            constraints,
            &mut cursor,
            address_wrap * (Fp::ONE - store_sp),
        )?;
        let sp_low = packed_bits_value(sp_bits, 0, BYTE_BITS)?;
        let sp_high = packed_bits_value(sp_bits, BYTE_BITS, BYTE_BITS)?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction * store_sp * (bus_field(local, 3, BUS_ADDRESS)? - immediate_word),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction * store_sp * (bus_field(local, 3, BUS_VALUE)? - sp_low),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * store_sp
                * (bus_field(local, 4, BUS_ADDRESS)? - immediate_word - Fp::ONE
                    + Fp::from(65_536_u64) * address_wrap),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction * store_sp * (bus_field(local, 4, BUS_VALUE)? - sp_high),
        )?;

        let load_accumulator_indirect = isa_operation_selector(isa, 6)?;
        let indirect_address = isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 0)?
            * (indexed(current, 1)? * Fp::from(256) + indexed(current, 2)?)
            + isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 1)?
                * (indexed(current, 3)? * Fp::from(256) + indexed(current, 4)?)
            + (isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 2)?
                + isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 3)?)
                * (indexed(current, 5)? * Fp::from(256) + indexed(current, 6)?);
        let direction_in = isa_argument_selector(isa, ISA_ARGUMENT_ONE_BITS_START, 0)?;
        let direction_out = isa_argument_selector(isa, ISA_ARGUMENT_ONE_BITS_START, 1)?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * load_accumulator_indirect
                * (bus_field(local, 1, BUS_ADDRESS)? - indirect_address),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * load_accumulator_indirect
                * direction_in
                * (indexed(next, 0)? - bus_field(local, 1, BUS_VALUE)?),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * load_accumulator_indirect
                * direction_out
                * (bus_field(local, 1, BUS_VALUE)? - indexed(current, 0)?),
        )?;
        let current_hl = indexed(current, 5)? * Fp::from(256) + indexed(current, 6)?;
        let next_hl = indexed(next, 5)? * Fp::from(256) + indexed(next, 6)?;
        let hl_increment = isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 2)?;
        let hl_decrement = isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 3)?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * load_accumulator_indirect
                * hl_increment
                * (next_hl - current_hl - Fp::ONE + Fp::from(65_536_u64) * word_wrap),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * load_accumulator_indirect
                * hl_decrement
                * (next_hl - current_hl + Fp::ONE - Fp::from(65_536_u64) * word_wrap),
        )?;
        let word_wrap_use = isa_operation_selector(isa, 7)?
            + isa_operation_selector(isa, 8)?
            + load_accumulator_indirect * (hl_increment + hl_decrement);
        set_constraint(
            constraints,
            &mut cursor,
            word_wrap * (Fp::ONE - word_wrap_use),
        )?;

        for (operation, slot, address) in [
            (21_u8, 2_usize, Fp::from(0xff00_u64) + immediate_low),
            (29, 1, Fp::from(0xff00_u64) + indexed(current, 2)?),
            (30, 3, immediate_word),
        ] {
            let selector = isa_operation_selector(isa, operation)?;
            let load_in = isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 0)?;
            let load_out = isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 1)?;
            set_constraint(
                constraints,
                &mut cursor,
                instruction * selector * (bus_field(local, slot, BUS_ADDRESS)? - address),
            )?;
            set_constraint(
                constraints,
                &mut cursor,
                instruction
                    * selector
                    * load_in
                    * (indexed(next, 0)? - bus_field(local, slot, BUS_VALUE)?),
            )?;
            set_constraint(
                constraints,
                &mut cursor,
                instruction
                    * selector
                    * load_out
                    * (bus_field(local, slot, BUS_VALUE)? - indexed(current, 0)?),
            )?;
        }
        let relative = isa_operation_selector(isa, 3)?;
        let return_operation = isa_operation_selector(isa, 20)?;
        let jump_hl = isa_operation_selector(isa, 26)?;
        let absolute_jump = isa_operation_selector(isa, 28)?;
        let call = isa_operation_selector(isa, 34)?;
        let restart = isa_operation_selector(isa, 36)?;
        let control = relative
            + return_operation
            + return_from_interrupt
            + jump_hl
            + absolute_jump
            + call
            + restart;
        let sequential = indexed(current, STATE_PC)?
            + *isa.get(8).ok_or(UniformTraceError::Relation)?
            - halt_bug
            - pc_wrap * Fp::from(65_536_u64);
        set_constraint(
            constraints,
            &mut cursor,
            instruction * (Fp::ONE - control) * (indexed(next, STATE_PC)? - sequential),
        )?;
        let relative_taken = relative * branch;
        set_constraint(
            constraints,
            &mut cursor,
            control_wrap * (Fp::ONE - relative_taken),
        )?;
        let relative_target = sequential + immediate_low
            - indexed(immediate_bits, 7)? * Fp::from(256)
            - control_wrap * Fp::from(65_536_u64);
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * relative
                * (indexed(next, STATE_PC)?
                    - branch * relative_target
                    - (Fp::ONE - branch) * sequential),
        )?;
        let absolute_control = absolute_jump + call;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * absolute_control
                * (indexed(next, STATE_PC)?
                    - branch * immediate_word
                    - (Fp::ONE - branch) * sequential),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * jump_hl
                * (indexed(next, STATE_PC)?
                    - indexed(current, 5)? * Fp::from(256)
                    - indexed(current, 6)?),
        )?;
        let return_pop_control = return_operation * branch + return_from_interrupt;
        let return_group = return_operation + return_from_interrupt;
        let popped_target =
            bus_field(local, 1, BUS_VALUE)? + bus_field(local, 2, BUS_VALUE)? * Fp::from(256);
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * return_group
                * (indexed(next, STATE_PC)?
                    - return_pop_control * popped_target
                    - (return_group - return_pop_control) * sequential),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * restart
                * (indexed(next, STATE_PC)?
                    - packed_bits_value(argument_zero_bits, 0, ISA_ARGUMENT_ZERO_BITS)?
                        * Fp::from(8)),
        )?;

        let call_taken = call * branch;
        let push_instruction = isa_operation_selector(isa, 35)?;
        let pop_instruction = isa_operation_selector(isa, 24)?;
        let control_push = call_taken + restart;
        let push_control = control_push + push_instruction;
        let pop_control = return_pop_control + pop_instruction;
        set_constraint(
            constraints,
            &mut cursor,
            stack_wrap * (Fp::ONE - push_control - pop_control),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            stack_first_wrap * (Fp::ONE - push_control - pop_control),
        )?;
        let push_group = call + restart + push_instruction;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * push_group
                * (indexed(next, 9)? - indexed(current, 9)? + Fp::from(2) * push_control
                    - Fp::from(65_536_u64) * stack_wrap),
        )?;
        let push_high_address = call_taken * bus_field(local, 3, BUS_ADDRESS)?
            + (restart + push_instruction) * bus_field(local, 1, BUS_ADDRESS)?;
        let push_low_address = call_taken * bus_field(local, 4, BUS_ADDRESS)?
            + (restart + push_instruction) * bus_field(local, 2, BUS_ADDRESS)?;
        set_constraint(
            constraints,
            &mut cursor,
            push_high_address
                - push_control
                    * (indexed(current, 9)? - Fp::ONE + Fp::from(65_536_u64) * stack_first_wrap),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            push_low_address
                - push_control
                    * (indexed(current, 9)? - Fp::from(2) + Fp::from(65_536_u64) * stack_wrap),
        )?;
        let pushed_high = call_taken * bus_field(local, 3, BUS_VALUE)?
            + (restart + push_instruction) * bus_field(local, 1, BUS_VALUE)?;
        let pushed_low = call_taken * bus_field(local, 4, BUS_VALUE)?
            + (restart + push_instruction) * bus_field(local, 2, BUS_VALUE)?;
        let pushed_word =
            control_push * sequential + push_instruction * selected_stack_word(current, isa)?;
        set_constraint(
            constraints,
            &mut cursor,
            pushed_low + pushed_high * Fp::from(256) - pushed_word,
        )?;
        let pop_group = return_group + pop_instruction;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * pop_group
                * (indexed(next, 9)? - indexed(current, 9)? - Fp::from(2) * pop_control
                    + Fp::from(65_536_u64) * stack_wrap),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * pop_group
                * (bus_field(local, 1, BUS_ADDRESS)? - pop_control * indexed(current, 9)?),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * pop_group
                * (bus_field(local, 2, BUS_ADDRESS)?
                    - pop_control
                        * (indexed(current, 9)? + Fp::ONE
                            - Fp::from(65_536_u64) * stack_first_wrap)),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction * pop_instruction * (operand_value - bus_field(local, 1, BUS_VALUE)?),
        )?;
        let pop_low = bus_field(local, 1, BUS_VALUE)?;
        let pop_high = bus_field(local, 2, BUS_VALUE)?;
        for (argument, high_index, low_index) in [(0_u8, 1_usize, 2_usize), (1, 3, 4), (2, 5, 6)] {
            let selected = isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, argument)?;
            set_constraint(
                constraints,
                &mut cursor,
                instruction * pop_instruction * selected * (indexed(next, high_index)? - pop_high),
            )?;
            set_constraint(
                constraints,
                &mut cursor,
                instruction * pop_instruction * selected * (indexed(next, low_index)? - pop_low),
            )?;
        }
        let pop_af = isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 3)?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction * pop_instruction * pop_af * (indexed(next, 0)? - pop_high),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            instruction
                * pop_instruction
                * pop_af
                * (indexed(next, 7)? - packed_bits_value(operand_bits, 4, 4)? * Fp::from(16)),
        )?;
        set_constraint(
            constraints,
            &mut cursor,
            operand_value * (Fp::ONE - load8 - increment_decrement - alu8 - pop_instruction),
        )?;
        let selected_cycles = base_cycles + branch * taken_timing * (taken_cycles - base_cycles);
        set_constraint(
            constraints,
            &mut cursor,
            instruction * (cycle_increment - selected_cycles),
        )?;
        // The ISA write mask is ordered A..RunState,MCycles. Cycles have their
        // own exact delta identity above, while every other CPU component must
        // be preserved whenever the fixed ISA row says it is not written.
        for state_index in 0..STATE_CYCLES {
            let write_bit = *write_bits
                .get(state_index)
                .ok_or(UniformTraceError::Relation)?;
            set_constraint(
                constraints,
                &mut cursor,
                instruction
                    * (Fp::ONE - write_bit)
                    * (indexed(next, state_index)? - indexed(current, state_index)?),
            )?;
        }
        if cursor != CONSTRAINT_COUNT {
            return Err(UniformTraceError::Relation);
        }
        Ok(())
    }
}

/// Succinct structural proof over complete native trace-row boundaries.
///
/// Verification of this value establishes only the obligations documented on
/// [`VmStateStructuralRelation`], not complete SM83 execution validity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommittedVmStateStructuralProof {
    proof: CommittedShiftedUniformTraceProof,
}

impl CommittedVmStateStructuralProof {
    /// Constructs the committed structural proof for a non-empty power-of-two
    /// sequence of already validated native trace rows.
    pub fn prove(
        parameters: &IpaParameters,
        rows: &[TraceRow],
    ) -> Result<Self, VmStateStructuralError> {
        let first = rows.first().ok_or(VmStateStructuralError::EmptyTrace)?;
        if rows.len() != parameters.vector_len() {
            return Err(VmStateStructuralError::LengthMismatch {
                rows: rows.len(),
                parameters: parameters.vector_len(),
            });
        }
        validate_continuity(rows)?;
        let relation = VmStateStructuralRelation::new(first.before());
        let states = rows.iter().map(TraceRow::before).collect::<Vec<_>>();
        let state_columns = encode_vm_state_columns(&states);
        let local_rows = rows
            .iter()
            .enumerate()
            .map(|(index, row)| encode_structural_local(row, index))
            .collect::<Result<Vec<_>, _>>()?;
        let local_columns = transpose_local(&local_rows);
        let final_values = encode_vm_state(
            rows.last()
                .ok_or(VmStateStructuralError::EmptyTrace)?
                .after(),
        );
        let proof = CommittedShiftedUniformTraceProof::prove(
            parameters,
            &relation,
            &state_columns,
            &local_columns,
            &final_values,
        )?;
        Ok(Self { proof })
    }

    /// Verifies the structural trace statement against both complete public
    /// VM boundaries.
    pub fn verify(
        &self,
        parameters: &IpaParameters,
        initial: VmState,
        final_state: VmState,
    ) -> Result<(), VmStateStructuralError> {
        let relation = VmStateStructuralRelation::new(initial);
        self.proof
            .verify(parameters, &relation, &encode_vm_state(final_state))?;
        Ok(())
    }

    /// Returns the number of committed state and local columns.
    #[must_use]
    pub fn column_count(&self) -> usize {
        self.proof.column_count()
    }

    /// Returns the proof size in curve points and scalar field elements.
    #[must_use]
    pub fn element_count(&self) -> (usize, usize) {
        self.proof.element_count()
    }

    fn isa_query_commitments(
        &self,
    ) -> Result<(Vec<IpaCommitment>, Vec<IpaCommitment>), VmStateStructuralError> {
        let address_start = VM_STATE_FIELD_COUNT
            .checked_add(LOCAL_ISA_ADDRESS_START)
            .ok_or(VmStateStructuralError::CommitmentLayout)?;
        let address_end = address_start
            .checked_add(ISA_ADDRESS_BITS)
            .ok_or(VmStateStructuralError::CommitmentLayout)?;
        let output_start = VM_STATE_FIELD_COUNT
            .checked_add(LOCAL_ISA_OUTPUT_START)
            .ok_or(VmStateStructuralError::CommitmentLayout)?;
        let output_end = output_start
            .checked_add(ISA_OUTPUT_COUNT)
            .ok_or(VmStateStructuralError::CommitmentLayout)?;
        let addresses = self
            .proof
            .commitments()
            .get(address_start..address_end)
            .ok_or(VmStateStructuralError::CommitmentLayout)?
            .to_vec();
        let outputs = self
            .proof
            .commitments()
            .get(output_start..output_end)
            .ok_or(VmStateStructuralError::CommitmentLayout)?
            .to_vec();
        Ok((addresses, outputs))
    }

    fn bus_commitments(&self) -> Result<Vec<IpaCommitment>, VmStateStructuralError> {
        let start = VM_STATE_FIELD_COUNT
            .checked_add(LOCAL_BUS_START)
            .ok_or(VmStateStructuralError::CommitmentLayout)?;
        let end = start
            .checked_add(BUS_EVENT_SLOTS * BUS_SLOT_WIDTH)
            .ok_or(VmStateStructuralError::CommitmentLayout)?;
        Ok(self
            .proof
            .commitments()
            .get(start..end)
            .ok_or(VmStateStructuralError::CommitmentLayout)?
            .to_vec())
    }

    fn isa_packed_commitment(&self) -> Result<IpaCommitment, VmStateStructuralError> {
        let index = VM_STATE_FIELD_COUNT
            .checked_add(LOCAL_ISA_OUTPUT_START)
            .and_then(|start| start.checked_add(1))
            .ok_or(VmStateStructuralError::CommitmentLayout)?;
        self.proof
            .commitments()
            .get(index)
            .copied()
            .ok_or(VmStateStructuralError::CommitmentLayout)
    }
}

/// Complete-state structural glue combined with a PCS-bound ISA Shout lookup.
///
/// This removes the explicit ISA query vector from verification and proves
/// that every committed local opcode address selects its unique fixed 106-bit
/// semantic row. CPU, bus, and device transition identities remain outside
/// this structural-plus-lookup milestone.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommittedVmIsaStructuralProof {
    structural: CommittedVmStateStructuralProof,
    isa: CommittedMultiQueryShoutProof,
}

impl CommittedVmIsaStructuralProof {
    /// Proves structural VM continuity and fixed-table ISA alignment for one
    /// power-of-two trace segment.
    pub fn prove(
        table_parameters: &IpaParameters,
        trace_parameters: &IpaParameters,
        rows: &[TraceRow],
    ) -> Result<Self, VmIsaStructuralError> {
        let structural = CommittedVmStateStructuralProof::prove(trace_parameters, rows)?;
        let queries = rows
            .iter()
            .map(|row| {
                aligned_outputs(AlignedInstruction::from_decoded(
                    row.effects().instruction(),
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let addresses = queries
            .iter()
            .map(|(address, _)| *address)
            .collect::<Vec<_>>();
        let output_rows = queries
            .iter()
            .map(|(_, outputs)| *outputs)
            .collect::<Vec<_>>();
        let values = transpose_isa_outputs(&output_rows);
        let tables = fixed_isa_tables()?;
        let isa = CommittedMultiQueryShoutProof::prove(
            table_parameters,
            trace_parameters,
            &tables,
            &addresses,
            &values,
        )?;
        let table_commitments = table_parameters.commit_batch(&tables)?;
        let (address_commitments, value_commitments) = structural.isa_query_commitments()?;
        isa.verify(
            table_parameters,
            trace_parameters,
            &table_commitments,
            &address_commitments,
            &value_commitments,
        )?;
        Ok(Self { structural, isa })
    }

    /// Verifies both complete structural boundaries and the fixed ISA lookup
    /// without receiving any query address or semantic-row vector.
    pub fn verify(
        &self,
        table_parameters: &IpaParameters,
        trace_parameters: &IpaParameters,
        initial: VmState,
        final_state: VmState,
    ) -> Result<(), VmIsaStructuralError> {
        self.structural
            .verify(trace_parameters, initial, final_state)?;
        let tables = fixed_isa_tables()?;
        let table_commitments = table_parameters.commit_batch(&tables)?;
        let (address_commitments, value_commitments) = self.structural.isa_query_commitments()?;
        self.isa.verify(
            table_parameters,
            trace_parameters,
            &table_commitments,
            &address_commitments,
            &value_commitments,
        )?;
        Ok(())
    }

    /// Returns total standalone proof size in curve points and scalar field elements.
    #[must_use]
    pub fn element_count(&self) -> (usize, usize) {
        let structural = self.structural.element_count();
        let isa = self.isa.element_count();
        (
            structural.0.saturating_add(isa.0),
            structural.1.saturating_add(isa.1),
        )
    }

    fn bus_commitments(&self) -> Result<Vec<IpaCommitment>, VmIsaStructuralError> {
        Ok(self.structural.bus_commitments()?)
    }

    fn isa_packed_commitment(&self) -> Result<IpaCommitment, VmIsaStructuralError> {
        Ok(self.structural.isa_packed_commitment()?)
    }
}

/// Serializable proof receipt for one power-of-two native VM/ISA segment.
///
/// The receipt carries exact complete VM boundaries and can be chained without
/// hidden host state. Callers must still verify every segment proof until
/// recursive aggregation is connected.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VmIsaSegmentReceipt {
    step_count: u64,
    initial: VmState,
    final_state: VmState,
    bus_rows: Vec<[BusTranscriptEvent; BUS_EVENT_SLOTS]>,
    isa_rows: Vec<u128>,
    proof: CommittedVmIsaStructuralProof,
}

impl VmIsaSegmentReceipt {
    /// Constructs a receipt from one exact power-of-two trace segment.
    pub fn prove(
        table_parameters: &IpaParameters,
        trace_parameters: &IpaParameters,
        rows: &[TraceRow],
    ) -> Result<Self, VmIsaSegmentError> {
        let first = rows.first().ok_or(VmIsaSegmentError::EmptySegment)?;
        let last = rows.last().ok_or(VmIsaSegmentError::EmptySegment)?;
        let step_count = u64::try_from(rows.len()).map_err(|_| VmIsaSegmentError::StepOverflow)?;
        let bus_rows = rows
            .iter()
            .map(receipt_bus_row)
            .collect::<Result<Vec<_>, _>>()?;
        let isa_rows = rows
            .iter()
            .map(|row| {
                AlignedInstruction::from_decoded(row.effects().instruction())
                    .packed()
                    .map_err(|_| VmIsaSegmentError::IsaRow)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let proof = CommittedVmIsaStructuralProof::prove(table_parameters, trace_parameters, rows)?;
        Ok(Self {
            step_count,
            initial: first.before(),
            final_state: last.after(),
            bus_rows,
            isa_rows,
            proof,
        })
    }

    /// Verifies the proof and requires caller-selected complete boundaries.
    pub fn verify(
        &self,
        table_parameters: &IpaParameters,
        trace_parameters: &IpaParameters,
        expected_initial: VmState,
        expected_final: VmState,
    ) -> Result<(), VmIsaSegmentError> {
        if self.initial != expected_initial || self.final_state != expected_final {
            return Err(VmIsaSegmentError::BoundaryMismatch);
        }
        let parameter_steps = u64::try_from(trace_parameters.vector_len())
            .map_err(|_| VmIsaSegmentError::StepOverflow)?;
        if self.step_count != parameter_steps {
            return Err(VmIsaSegmentError::ParameterLengthMismatch);
        }
        if self.bus_rows.len() != trace_parameters.vector_len()
            || self.isa_rows.len() != trace_parameters.vector_len()
        {
            return Err(VmIsaSegmentError::PublicRowsLengthMismatch);
        }
        self.proof.verify(
            table_parameters,
            trace_parameters,
            self.initial,
            self.final_state,
        )?;
        self.verify_public_commitments(trace_parameters)?;
        self.verify_transcript_boundaries()?;
        Ok(())
    }

    /// Returns the complete initial VM boundary.
    #[must_use]
    pub const fn initial_state(&self) -> VmState {
        self.initial
    }

    /// Returns the complete final VM boundary.
    #[must_use]
    pub const fn final_state(&self) -> VmState {
        self.final_state
    }

    /// Returns native rows represented by this segment.
    #[must_use]
    pub const fn step_count(&self) -> u64 {
        self.step_count
    }

    /// Iterates the exact canonical bus events committed by this segment.
    pub fn bus_events(&self) -> impl Iterator<Item = BusTranscriptEvent> + '_ {
        self.bus_rows
            .iter()
            .flatten()
            .copied()
            .filter(|event| event.kind != 0)
    }

    /// Returns the exact packed ISA rows committed by this segment.
    #[must_use]
    pub fn isa_rows(&self) -> &[u128] {
        &self.isa_rows
    }

    /// Returns proof size in curve points and scalar field elements.
    #[must_use]
    pub fn element_count(&self) -> (usize, usize) {
        self.proof.element_count()
    }

    fn verify_public_commitments(
        &self,
        trace_parameters: &IpaParameters,
    ) -> Result<(), VmIsaSegmentError> {
        let bus_columns = receipt_bus_columns(&self.bus_rows)?;
        let expected_bus = trace_parameters.commit_batch(&bus_columns)?;
        if expected_bus != self.proof.bus_commitments()? {
            return Err(VmIsaSegmentError::BusCommitmentMismatch);
        }
        let isa_column = self
            .isa_rows
            .iter()
            .copied()
            .map(Fp::from_u128)
            .collect::<Vec<_>>();
        if trace_parameters.commit(&isa_column)? != self.proof.isa_packed_commitment()? {
            return Err(VmIsaSegmentError::IsaCommitmentMismatch);
        }
        Ok(())
    }

    fn verify_transcript_boundaries(&self) -> Result<(), VmIsaSegmentError> {
        let bus = self
            .bus_events()
            .try_fold(self.initial.bus_transcript(), |transcript, event| {
                transcript.append(event)
            })?;
        if bus != self.final_state.bus_transcript() {
            return Err(VmIsaSegmentError::BusTranscriptBoundary);
        }
        let isa = self
            .isa_rows
            .iter()
            .try_fold(self.initial.isa_transcript(), |transcript, row| {
                transcript.append(*row)
            })?;
        if isa != self.final_state.isa_transcript() {
            return Err(VmIsaSegmentError::IsaTranscriptBoundary);
        }
        Ok(())
    }
}

/// Verifies an ordered receipt chain and returns its exact complete boundary.
pub fn verify_vm_isa_segment_chain(
    table_parameters: &IpaParameters,
    trace_parameters: &[IpaParameters],
    receipts: &[VmIsaSegmentReceipt],
) -> Result<(VmState, VmState, u64), VmIsaSegmentError> {
    if receipts.is_empty() {
        return Err(VmIsaSegmentError::EmptyChain);
    }
    if trace_parameters.len() != receipts.len() {
        return Err(VmIsaSegmentError::ChainShape);
    }
    for (index, pair) in receipts.windows(2).enumerate() {
        let left = pair.first().ok_or(VmIsaSegmentError::EmptyChain)?;
        let right = pair.get(1).ok_or(VmIsaSegmentError::EmptyChain)?;
        if left.final_state != right.initial {
            return Err(VmIsaSegmentError::DiscontinuousChain { index });
        }
    }
    let mut steps = 0_u64;
    for (receipt, parameters) in receipts.iter().zip(trace_parameters) {
        receipt.verify(
            table_parameters,
            parameters,
            receipt.initial,
            receipt.final_state,
        )?;
        steps = steps
            .checked_add(receipt.step_count)
            .ok_or(VmIsaSegmentError::StepOverflow)?;
    }
    let initial = receipts
        .first()
        .ok_or(VmIsaSegmentError::EmptyChain)?
        .initial;
    let final_state = receipts
        .last()
        .ok_or(VmIsaSegmentError::EmptyChain)?
        .final_state;
    Ok((initial, final_state, steps))
}

/// Invalid VM/ISA segment receipt or ordered receipt chain.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VmIsaSegmentError {
    /// A segment must contain at least one row.
    #[error("VM/ISA receipt segment is empty")]
    EmptySegment,
    /// At least one receipt is required.
    #[error("VM/ISA receipt chain is empty")]
    EmptyChain,
    /// Receipt and parameter lists differ in length.
    #[error("VM/ISA receipt and parameter chain lengths differ")]
    ChainShape,
    /// Receipt row count does not match its trace PCS parameter length.
    #[error("VM/ISA receipt length does not match trace parameters")]
    ParameterLengthMismatch,
    /// Public bus/ISA row vectors do not match the segment length.
    #[error("VM/ISA receipt public row lengths do not match trace parameters")]
    PublicRowsLengthMismatch,
    /// Caller-selected and receipt-carried boundaries differ.
    #[error("VM/ISA receipt boundary mismatch")]
    BoundaryMismatch,
    /// Adjacent receipt boundaries differ.
    #[error("VM/ISA receipt chain is discontinuous after segment {index}")]
    DiscontinuousChain {
        /// First receipt in the mismatched pair.
        index: usize,
    },
    /// Step count conversion or accumulation overflowed.
    #[error("VM/ISA receipt step count overflow")]
    StepOverflow,
    /// A row exceeded the five-event fixed shape.
    #[error("VM/ISA receipt row exceeds the fixed bus-event shape")]
    TooManyBusEvents,
    /// An active event appeared after an unused slot or padding carried data.
    #[error("VM/ISA receipt bus-event padding is not canonical")]
    NonCanonicalBusPadding,
    /// A public bus event exceeds the protocol kind or address range.
    #[error("VM/ISA receipt bus event is not canonically encodable")]
    NonCanonicalBusEvent,
    /// A packed ISA row could not be constructed.
    #[error("VM/ISA receipt ISA row is not canonically encodable")]
    IsaRow,
    /// Explicit canonical bus rows do not match the structural PCS columns.
    #[error("VM/ISA receipt bus-event commitments do not match the structural proof")]
    BusCommitmentMismatch,
    /// Explicit packed ISA rows do not match the structural PCS column.
    #[error("VM/ISA receipt ISA-row commitment does not match the structural proof")]
    IsaCommitmentMismatch,
    /// Replaying committed public bus events does not reach the public boundary.
    #[error("VM/ISA receipt bus transcript boundary mismatch")]
    BusTranscriptBoundary,
    /// Replaying committed public ISA rows does not reach the public boundary.
    #[error("VM/ISA receipt ISA transcript boundary mismatch")]
    IsaTranscriptBoundary,
    /// A public bus transcript event is non-canonical.
    #[error(transparent)]
    BusTranscript(#[from] BusTranscriptError),
    /// A public ISA transcript row is non-canonical.
    #[error(transparent)]
    IsaTranscript(#[from] IsaTranscriptError),
    /// A public event/ISA column commitment could not be constructed.
    #[error(transparent)]
    Ipa(#[from] crate::IpaError),
    /// The structural and ISA proof failed.
    #[error(transparent)]
    Proof(#[from] VmIsaStructuralError),
}

/// Invalid combined structural VM and committed ISA lookup proof.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VmIsaStructuralError {
    /// Complete-state structural glue failed.
    #[error(transparent)]
    Structural(#[from] VmStateStructuralError),
    /// The PCS-bound ISA Shout proof failed.
    #[error(transparent)]
    Shout(#[from] CommittedMultiQueryShoutError),
    /// The fixed 512-entry ISA table could not be constructed.
    #[error("fixed ISA alignment table construction failed")]
    FixedIsaTable,
    /// The fixed ISA table commitment could not be computed.
    #[error("fixed ISA table polynomial commitment failed")]
    Ipa,
}

impl From<crate::IpaError> for VmIsaStructuralError {
    fn from(_: crate::IpaError) -> Self {
        Self::Ipa
    }
}

/// Invalid construction or verification of structural VM-state glue.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VmStateStructuralError {
    /// At least one native transition is required.
    #[error("structural VM trace is empty")]
    EmptyTrace,
    /// Trace rows must exactly fill the PCS vector.
    #[error("structural VM trace has {rows} rows but PCS parameters require {parameters}")]
    LengthMismatch {
        /// Native rows supplied by the prover.
        rows: usize,
        /// Vector length fixed by the PCS parameters.
        parameters: usize,
    },
    /// Adjacent native rows do not carry the same complete boundary.
    #[error("structural VM trace is discontinuous after row {index}")]
    Discontinuous {
        /// First row in the mismatched pair.
        index: usize,
    },
    /// A native cycle counter decreased.
    #[error("VM cycle counter regressed in row {index}")]
    CycleRegression {
        /// Rejected row index.
        index: usize,
    },
    /// The decoded instruction did not fit the fixed 106-bit ISA row.
    #[error("VM ISA alignment row packing failed")]
    Alignment,
    /// The committed column list does not match the stable VM/ISA layout.
    #[error("VM structural commitment layout is invalid")]
    CommitmentLayout,
    /// The underlying committed uniform-trace proof failed.
    #[error(transparent)]
    Uniform(#[from] UniformTraceError),
}

fn validate_continuity(rows: &[TraceRow]) -> Result<(), VmStateStructuralError> {
    for (index, pair) in rows.windows(2).enumerate() {
        let left = pair.first().ok_or(VmStateStructuralError::EmptyTrace)?;
        let right = pair.get(1).ok_or(VmStateStructuralError::EmptyTrace)?;
        if left.after() != right.before() {
            return Err(VmStateStructuralError::Discontinuous { index });
        }
    }
    Ok(())
}

fn encode_structural_local(
    row: &TraceRow,
    index: usize,
) -> Result<[Fp; LOCAL_COLUMN_COUNT], VmStateStructuralError> {
    let mut local = [Fp::ZERO; LOCAL_COLUMN_COUNT];
    let mode = match row.effects().kind() {
        StepKind::Instruction => 0,
        StepKind::HaltIdle => 1,
        StepKind::HaltUntilVBlank => 2,
        StepKind::BlueSoundWait => 3,
        StepKind::BlueDelayLoop => 4,
        StepKind::BlueDmaWait => 5,
        StepKind::HaltWake => 7,
        StepKind::InterruptDispatch(_) => 8,
        StepKind::DmaByte => 9,
    };
    *local
        .get_mut(mode)
        .ok_or(VmStateStructuralError::EmptyTrace)? = Fp::ONE;
    if let StepKind::InterruptDispatch(interrupt) = row.effects().kind() {
        let source = interrupt_source_index(interrupt);
        *local
            .get_mut(MODE_COUNT + source)
            .ok_or(VmStateStructuralError::EmptyTrace)? = Fp::ONE;
    }
    let increment = row
        .after()
        .cpu()
        .m_cycles()
        .checked_sub(row.before().cpu().m_cycles())
        .ok_or(VmStateStructuralError::CycleRegression { index })?;
    *local
        .get_mut(LOCAL_CYCLE_INCREMENT)
        .ok_or(VmStateStructuralError::EmptyTrace)? = Fp::from(increment);
    *local
        .get_mut(LOCAL_BRANCH_TAKEN)
        .ok_or(VmStateStructuralError::EmptyTrace)? =
        Fp::from(u64::from(row.effects().branch_taken()));
    let aligned = AlignedInstruction::from_decoded(row.effects().instruction());
    let (address, outputs) = aligned_outputs(aligned)?;
    for bit in 0..ISA_ADDRESS_BITS {
        *local
            .get_mut(LOCAL_ISA_ADDRESS_START + bit)
            .ok_or(VmStateStructuralError::EmptyTrace)? = Fp::from(((address >> bit) & 1) as u64);
    }
    for (target, output) in local
        .get_mut(LOCAL_ISA_OUTPUT_START..LOCAL_CPU_FLAG_BITS_START)
        .ok_or(VmStateStructuralError::EmptyTrace)?
        .iter_mut()
        .zip(outputs)
    {
        *target = output;
    }
    let flags = row.before().cpu().flags().byte();
    for bit in 0..CPU_FLAG_BITS {
        *local
            .get_mut(LOCAL_CPU_FLAG_BITS_START + bit)
            .ok_or(VmStateStructuralError::CommitmentLayout)? =
            Fp::from(u64::from((flags >> bit) & 1));
    }
    if row.effects().kind() == StepKind::Instruction {
        let halt_bug = row.before().cpu().run_state() == RunState::HaltBug;
        let unwrapped = u32::from(row.before().cpu().pc())
            .checked_add(u32::from(row.effects().instruction().byte_len()))
            .and_then(|value| value.checked_sub(u32::from(halt_bug)))
            .ok_or(VmStateStructuralError::CommitmentLayout)?;
        *local
            .get_mut(LOCAL_PC_WRAP)
            .ok_or(VmStateStructuralError::CommitmentLayout)? =
            Fp::from(u64::from(unwrapped > u32::from(u16::MAX)));
    }
    let operand_value = native_operand_value(row, aligned)?;
    *local
        .get_mut(LOCAL_OPERAND_VALUE)
        .ok_or(VmStateStructuralError::CommitmentLayout)? = Fp::from(u64::from(operand_value));
    let arithmetic = native_arithmetic_witness(row, aligned, operand_value);
    *local
        .get_mut(LOCAL_RESULT_VALUE)
        .ok_or(VmStateStructuralError::CommitmentLayout)? = Fp::from(u64::from(arithmetic.result));
    *local
        .get_mut(LOCAL_WORD_WRAP)
        .ok_or(VmStateStructuralError::CommitmentLayout)? =
        Fp::from(u64::from(native_word_wrap(row, aligned)?));
    let immediate = native_first_immediate(row, aligned);
    for bit in 0..IMMEDIATE_BITS {
        *local
            .get_mut(LOCAL_IMMEDIATE_BITS_START + bit)
            .ok_or(VmStateStructuralError::CommitmentLayout)? =
            Fp::from(u64::from((immediate >> bit) & 1));
    }
    *local
        .get_mut(LOCAL_CONTROL_WRAP)
        .ok_or(VmStateStructuralError::CommitmentLayout)? = native_control_wrap(row, aligned);
    let (stack_wrap, stack_first_wrap) = native_stack_wraps(row, aligned);
    *local
        .get_mut(LOCAL_STACK_WRAP)
        .ok_or(VmStateStructuralError::CommitmentLayout)? = Fp::from(u64::from(stack_wrap));
    *local
        .get_mut(LOCAL_STACK_FIRST_WRAP)
        .ok_or(VmStateStructuralError::CommitmentLayout)? = Fp::from(u64::from(stack_first_wrap));
    *local
        .get_mut(LOCAL_ADDRESS_WRAP)
        .ok_or(VmStateStructuralError::CommitmentLayout)? =
        Fp::from(u64::from(native_address_wrap(row, aligned)));
    encode_local_bits(
        &mut local,
        LOCAL_OPERAND_BITS_START,
        OPERAND_BITS,
        u64::from(operand_value),
    )?;
    encode_local_bits(
        &mut local,
        LOCAL_RESULT_BITS_START,
        RESULT_BITS,
        u64::from(arithmetic.result),
    )?;
    *local
        .get_mut(LOCAL_ARITHMETIC_CARRY)
        .ok_or(VmStateStructuralError::CommitmentLayout)? = Fp::from(u64::from(arithmetic.carry));
    *local
        .get_mut(LOCAL_HALF_CARRY)
        .ok_or(VmStateStructuralError::CommitmentLayout)? =
        Fp::from(u64::from(arithmetic.half_carry));
    *local
        .get_mut(LOCAL_RESULT_ZERO)
        .ok_or(VmStateStructuralError::CommitmentLayout)? =
        Fp::from(u64::from(arithmetic.result == 0));
    let result = Fp::from(u64::from(arithmetic.result));
    *local
        .get_mut(LOCAL_RESULT_INVERSE)
        .ok_or(VmStateStructuralError::CommitmentLayout)? =
        Option::<Fp>::from(result.invert()).unwrap_or(Fp::ZERO);
    let registers = row.before().cpu().registers();
    for (byte_index, value) in [
        registers.a,
        registers.b,
        registers.c,
        registers.d,
        registers.e,
        registers.h,
        registers.l,
    ]
    .into_iter()
    .enumerate()
    {
        let start = LOCAL_CPU_BYTE_BITS_START
            .checked_add(byte_index.saturating_mul(BYTE_BITS))
            .ok_or(VmStateStructuralError::CommitmentLayout)?;
        encode_local_bits(&mut local, start, BYTE_BITS, u64::from(value))?;
    }
    encode_local_bits(
        &mut local,
        LOCAL_PC_BITS_START,
        WORD_BITS,
        u64::from(row.before().cpu().pc()),
    )?;
    encode_local_bits(
        &mut local,
        LOCAL_SP_BITS_START,
        WORD_BITS,
        u64::from(row.before().cpu().sp()),
    )?;
    for (slot, event) in row.effects().bus_events().enumerate() {
        let start = LOCAL_BUS_START
            .checked_add(slot.saturating_mul(BUS_SLOT_WIDTH))
            .ok_or(VmStateStructuralError::CommitmentLayout)?;
        *local
            .get_mut(start)
            .ok_or(VmStateStructuralError::CommitmentLayout)? = Fp::ONE;
        let code = event.kind().code();
        for bit in 0..BUS_KIND_BITS {
            *local
                .get_mut(start + 1 + bit)
                .ok_or(VmStateStructuralError::CommitmentLayout)? =
                Fp::from(u64::from((code >> bit) & 1));
        }
        encode_bus_tuple(&mut local, start, event.transcript_event())?;
    }
    Ok(local)
}

fn encode_local_bits(
    local: &mut [Fp],
    start: usize,
    width: usize,
    value: u64,
) -> Result<(), VmStateStructuralError> {
    for bit in 0..width {
        *local
            .get_mut(
                start
                    .checked_add(bit)
                    .ok_or(VmStateStructuralError::CommitmentLayout)?,
            )
            .ok_or(VmStateStructuralError::CommitmentLayout)? = Fp::from((value >> bit) & 1);
    }
    Ok(())
}

fn native_operand_value(
    row: &TraceRow,
    aligned: AlignedInstruction,
) -> Result<u8, VmStateStructuralError> {
    if row.effects().kind() != StepKind::Instruction {
        return Ok(0);
    }
    if aligned.operation == 24 {
        return row
            .effects()
            .bus_events()
            .find(|event| matches!(event.kind().code(), 3 | 4 | 6 | 9 | 11 | 13))
            .map(|event| event.transcript_event().value)
            .ok_or(VmStateStructuralError::CommitmentLayout);
    }
    let argument = match aligned.operation {
        9 | 10 => aligned.argument_zero,
        17 | 19 => aligned.argument_one,
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
        6 => row
            .effects()
            .bus_events()
            .find(|event| matches!(event.kind().code(), 3 | 4 | 6 | 9 | 11 | 13))
            .map(|event| event.transcript_event().value)
            .ok_or(VmStateStructuralError::CommitmentLayout),
        7 => Ok(registers.a),
        8 => Ok(native_first_immediate(row, aligned)),
        _ => Err(VmStateStructuralError::Alignment),
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct NativeArithmeticWitness {
    result: u8,
    carry: bool,
    half_carry: bool,
}

fn native_arithmetic_witness(
    row: &TraceRow,
    aligned: AlignedInstruction,
    operand: u8,
) -> NativeArithmeticWitness {
    if row.effects().kind() != StepKind::Instruction {
        return NativeArithmeticWitness::default();
    }
    match aligned.operation {
        9 => NativeArithmeticWitness {
            result: operand.wrapping_add(1),
            carry: operand == u8::MAX,
            half_carry: operand & 0x0f == 0x0f,
        },
        10 => NativeArithmeticWitness {
            result: operand.wrapping_sub(1),
            carry: operand == 0,
            half_carry: operand & 0x0f == 0,
        },
        19 => native_alu8_witness(row, aligned.argument_zero, operand),
        _ => NativeArithmeticWitness::default(),
    }
}

fn native_alu8_witness(row: &TraceRow, operation: u8, operand: u8) -> NativeArithmeticWitness {
    let accumulator = row.before().cpu().registers().a;
    let carry_in = u8::from(row.before().cpu().flags().carry());
    match operation {
        0 | 1 => {
            let selected_carry = if operation == 1 { carry_in } else { 0 };
            let sum = u16::from(accumulator) + u16::from(operand) + u16::from(selected_carry);
            NativeArithmeticWitness {
                result: sum as u8,
                carry: sum > u16::from(u8::MAX),
                half_carry: u16::from(accumulator & 0x0f)
                    + u16::from(operand & 0x0f)
                    + u16::from(selected_carry)
                    > 0x0f,
            }
        }
        2 | 3 | 7 => {
            let selected_carry = if operation == 3 { carry_in } else { 0 };
            let subtrahend = u16::from(operand) + u16::from(selected_carry);
            NativeArithmeticWitness {
                result: accumulator
                    .wrapping_sub(operand)
                    .wrapping_sub(selected_carry),
                carry: u16::from(accumulator) < subtrahend,
                half_carry: u16::from(accumulator & 0x0f)
                    < u16::from(operand & 0x0f) + u16::from(selected_carry),
            }
        }
        4 => NativeArithmeticWitness {
            result: accumulator & operand,
            carry: false,
            half_carry: true,
        },
        5 => NativeArithmeticWitness {
            result: accumulator ^ operand,
            carry: false,
            half_carry: false,
        },
        6 => NativeArithmeticWitness {
            result: accumulator | operand,
            carry: false,
            half_carry: false,
        },
        _ => NativeArithmeticWitness::default(),
    }
}

fn native_word_wrap(
    row: &TraceRow,
    aligned: AlignedInstruction,
) -> Result<bool, VmStateStructuralError> {
    if row.effects().kind() != StepKind::Instruction || !matches!(aligned.operation, 6..=8) {
        return Ok(false);
    }
    let registers = row.before().cpu().registers();
    let (word, increment) = if aligned.operation == 6 {
        match aligned.argument_zero {
            2 => (u16::from_be_bytes([registers.h, registers.l]), true),
            3 => (u16::from_be_bytes([registers.h, registers.l]), false),
            0 | 1 => return Ok(false),
            _ => return Err(VmStateStructuralError::Alignment),
        }
    } else {
        let word = match aligned.argument_zero {
            0 => u16::from_be_bytes([registers.b, registers.c]),
            1 => u16::from_be_bytes([registers.d, registers.e]),
            2 => u16::from_be_bytes([registers.h, registers.l]),
            3 => row.before().cpu().sp(),
            _ => return Err(VmStateStructuralError::Alignment),
        };
        (word, aligned.operation == 7)
    };
    Ok(if increment {
        word == u16::MAX
    } else {
        word == 0
    })
}

fn native_address_wrap(row: &TraceRow, aligned: AlignedInstruction) -> bool {
    row.effects().kind() == StepKind::Instruction
        && aligned.operation == 1
        && native_immediate_word(row, aligned) == u16::MAX
}

fn native_immediate_word(row: &TraceRow, aligned: AlignedInstruction) -> u16 {
    if row.effects().kind() != StepKind::Instruction || aligned.immediate_reads != 2 {
        return 0;
    }
    let mut immediates = row
        .effects()
        .bus_events()
        .filter(|event| matches!(event.kind().code(), 2 | 15))
        .map(|event| event.transcript_event().value);
    let low = immediates.next().unwrap_or(0);
    let high = immediates.next().unwrap_or(0);
    u16::from_le_bytes([low, high])
}

fn native_first_immediate(row: &TraceRow, aligned: AlignedInstruction) -> u8 {
    if row.effects().kind() != StepKind::Instruction || aligned.immediate_reads == 0 {
        return 0;
    }
    row.effects()
        .bus_events()
        .find(|event| matches!(event.kind().code(), 2 | 15))
        .map_or(0, |event| event.transcript_event().value)
}

fn native_control_wrap(row: &TraceRow, aligned: AlignedInstruction) -> Fp {
    if row.effects().kind() != StepKind::Instruction
        || aligned.operation != 3
        || !row.effects().branch_taken()
    {
        return Fp::ZERO;
    }
    let halt_bug = row.before().cpu().run_state() == RunState::HaltBug;
    let sequential = row
        .before()
        .cpu()
        .pc()
        .wrapping_add(u16::from(aligned.byte_len).saturating_sub(u16::from(halt_bug)));
    let offset = i32::from(i8::from_ne_bytes([native_first_immediate(row, aligned)]));
    let unwrapped = i32::from(sequential) + offset;
    if unwrapped < 0 {
        -Fp::ONE
    } else if unwrapped > i32::from(u16::MAX) {
        Fp::ONE
    } else {
        Fp::ZERO
    }
}

fn native_stack_wraps(row: &TraceRow, aligned: AlignedInstruction) -> (bool, bool) {
    if row.effects().kind() != StepKind::Instruction {
        return (false, false);
    }
    let push = (aligned.operation == 34 && row.effects().branch_taken())
        || matches!(aligned.operation, 35 | 36);
    let pop = (aligned.operation == 20 && row.effects().branch_taken())
        || matches!(aligned.operation, 24 | 25);
    let sp = row.before().cpu().sp();
    if push {
        (sp < 2, sp == 0)
    } else if pop {
        (sp > u16::MAX - 2, sp == u16::MAX)
    } else {
        (false, false)
    }
}

fn encode_bus_tuple(
    local: &mut [Fp],
    start: usize,
    event: BusTranscriptEvent,
) -> Result<(), VmStateStructuralError> {
    let values = [
        Fp::from(u64::from(event.address)),
        Fp::from(u64::from(event.physical_address)),
        Fp::from(u64::from(event.before)),
        Fp::from(u64::from(event.auxiliary)),
        Fp::from(u64::from(event.value)),
        Fp::from(event.index),
    ];
    for (offset, value) in (BUS_ADDRESS..=BUS_INDEX).zip(values) {
        *local
            .get_mut(start + offset)
            .ok_or(VmStateStructuralError::CommitmentLayout)? = value;
    }
    Ok(())
}

const fn empty_bus_event() -> BusTranscriptEvent {
    BusTranscriptEvent {
        kind: 0,
        address: 0,
        physical_address: 0,
        before: 0,
        auxiliary: 0,
        value: 0,
        index: 0,
    }
}

fn receipt_bus_row(
    row: &TraceRow,
) -> Result<[BusTranscriptEvent; BUS_EVENT_SLOTS], VmIsaSegmentError> {
    let mut result = [empty_bus_event(); BUS_EVENT_SLOTS];
    for (slot, event) in row.effects().bus_events().enumerate() {
        *result
            .get_mut(slot)
            .ok_or(VmIsaSegmentError::TooManyBusEvents)? = event.transcript_event();
    }
    Ok(result)
}

fn receipt_bus_columns(
    rows: &[[BusTranscriptEvent; BUS_EVENT_SLOTS]],
) -> Result<Vec<Vec<Fp>>, VmIsaSegmentError> {
    let mut columns = (0..BUS_EVENT_SLOTS * BUS_SLOT_WIDTH)
        .map(|_| Vec::with_capacity(rows.len()))
        .collect::<Vec<_>>();
    for row in rows {
        let mut saw_padding = false;
        for (slot, event) in row.iter().copied().enumerate() {
            let active = event.kind != 0;
            if active && saw_padding {
                return Err(VmIsaSegmentError::NonCanonicalBusPadding);
            }
            if !active {
                saw_padding = true;
                if event != empty_bus_event() {
                    return Err(VmIsaSegmentError::NonCanonicalBusPadding);
                }
            }
            if event.kind > 18 || event.physical_address >= 1_u32 << 20 {
                return Err(VmIsaSegmentError::NonCanonicalBusEvent);
            }
            let start = slot * BUS_SLOT_WIDTH;
            columns
                .get_mut(start)
                .ok_or(VmIsaSegmentError::PublicRowsLengthMismatch)?
                .push(Fp::from(u64::from(active)));
            for bit in 0..BUS_KIND_BITS {
                columns
                    .get_mut(start + 1 + bit)
                    .ok_or(VmIsaSegmentError::PublicRowsLengthMismatch)?
                    .push(Fp::from(u64::from((event.kind >> bit) & 1)));
            }
            let tuple = [
                Fp::from(u64::from(event.address)),
                Fp::from(u64::from(event.physical_address)),
                Fp::from(u64::from(event.before)),
                Fp::from(u64::from(event.auxiliary)),
                Fp::from(u64::from(event.value)),
                Fp::from(event.index),
            ];
            for (offset, value) in (BUS_ADDRESS..=BUS_INDEX).zip(tuple) {
                columns
                    .get_mut(start + offset)
                    .ok_or(VmIsaSegmentError::PublicRowsLengthMismatch)?
                    .push(value);
            }
        }
    }
    Ok(columns)
}

fn aligned_outputs(
    aligned: AlignedInstruction,
) -> Result<(usize, [Fp; ISA_OUTPUT_COUNT]), VmStateStructuralError> {
    let address = usize::from(aligned.key.prefix)
        .checked_mul(256)
        .and_then(|prefix| prefix.checked_add(usize::from(aligned.key.opcode)))
        .ok_or(VmStateStructuralError::Alignment)?;
    let packed = aligned.packed().map_err(VmStateStructuralError::from)?;
    let mut outputs = [Fp::ZERO; ISA_OUTPUT_COUNT];
    let fields = [
        Fp::ONE,
        Fp::from_u128(packed),
        Fp::from(u64::from(aligned.key.prefix)),
        Fp::from(u64::from(aligned.key.opcode)),
        Fp::from(u64::from(aligned.family_id)),
        Fp::from(u64::from(aligned.operation)),
        Fp::from(u64::from(aligned.argument_zero)),
        Fp::from(u64::from(aligned.argument_one)),
        Fp::from(u64::from(aligned.byte_len)),
        Fp::from(u64::from(aligned.base_m_cycles)),
        Fp::from(u64::from(aligned.taken_m_cycles)),
        Fp::from(u64::from(aligned.pc_rule)),
        Fp::from(u64::from(aligned.flag_rule)),
        Fp::from(u64::from(aligned.register_reads)),
        Fp::from(u64::from(aligned.register_writes)),
        Fp::from(u64::from(aligned.opcode_fetches)),
        Fp::from(u64::from(aligned.immediate_reads)),
        Fp::from(u64::from(aligned.data_reads)),
        Fp::from(u64::from(aligned.data_writes)),
        Fp::from(u64::from(aligned.taken_data_reads)),
        Fp::from(u64::from(aligned.taken_data_writes)),
    ];
    outputs
        .get_mut(..fields.len())
        .ok_or(VmStateStructuralError::Alignment)?
        .copy_from_slice(&fields);
    for bit in 0..13 {
        *outputs
            .get_mut(ISA_WRITE_BITS_START + bit)
            .ok_or(VmStateStructuralError::Alignment)? =
            Fp::from(u64::from((aligned.register_writes >> bit) & 1));
    }
    *outputs
        .get_mut(ISA_TAKEN_TIMING)
        .ok_or(VmStateStructuralError::Alignment)? =
        Fp::from(u64::from(aligned.taken_m_cycles != 0));
    for bit in 0..ISA_OPERATION_BITS {
        *outputs
            .get_mut(ISA_OPERATION_BITS_START + bit)
            .ok_or(VmStateStructuralError::Alignment)? =
            Fp::from(u64::from((aligned.operation >> bit) & 1));
    }
    for bit in 0..ISA_ARGUMENT_ZERO_BITS {
        *outputs
            .get_mut(ISA_ARGUMENT_ZERO_BITS_START + bit)
            .ok_or(VmStateStructuralError::Alignment)? =
            Fp::from(u64::from((aligned.argument_zero >> bit) & 1));
    }
    for bit in 0..ISA_ARGUMENT_ONE_BITS {
        *outputs
            .get_mut(ISA_ARGUMENT_ONE_BITS_START + bit)
            .ok_or(VmStateStructuralError::Alignment)? =
            Fp::from(u64::from((aligned.argument_one >> bit) & 1));
    }
    Ok((address, outputs))
}

fn fixed_isa_tables() -> Result<Vec<Vec<Fp>>, VmIsaStructuralError> {
    let mut columns = (0..ISA_OUTPUT_COUNT)
        .map(|_| vec![Fp::ZERO; 512])
        .collect::<Vec<_>>();
    for aligned in AlignedInstruction::all() {
        let (address, outputs) = aligned_outputs(aligned).map_err(VmIsaStructuralError::from)?;
        for (column, output) in columns.iter_mut().zip(outputs) {
            let target = column
                .get_mut(address)
                .ok_or(VmIsaStructuralError::FixedIsaTable)?;
            *target = output;
        }
    }
    Ok(columns)
}

fn transpose_isa_outputs(rows: &[[Fp; ISA_OUTPUT_COUNT]]) -> Vec<Vec<Fp>> {
    let mut columns = (0..ISA_OUTPUT_COUNT)
        .map(|_| Vec::with_capacity(rows.len()))
        .collect::<Vec<_>>();
    for row in rows {
        for (column, value) in columns.iter_mut().zip(row) {
            column.push(*value);
        }
    }
    columns
}

impl From<AlignmentPackingError> for VmStateStructuralError {
    fn from(_: AlignmentPackingError) -> Self {
        Self::Alignment
    }
}

const fn interrupt_source_index(interrupt: DmgInterrupt) -> usize {
    match interrupt {
        DmgInterrupt::VBlank => 0,
        DmgInterrupt::LcdStat => 1,
        DmgInterrupt::Timer => 2,
        DmgInterrupt::Serial => 3,
        DmgInterrupt::Joypad => 4,
    }
}

fn transpose_local(rows: &[[Fp; LOCAL_COLUMN_COUNT]]) -> Vec<Vec<Fp>> {
    let mut columns = (0..LOCAL_COLUMN_COUNT)
        .map(|_| Vec::with_capacity(rows.len()))
        .collect::<Vec<_>>();
    for row in rows {
        for (column, value) in columns.iter_mut().zip(row) {
            column.push(*value);
        }
    }
    columns
}

fn set_constraint(
    constraints: &mut [Fp],
    cursor: &mut usize,
    value: Fp,
) -> Result<(), UniformTraceError> {
    let constraint = constraints
        .get_mut(*cursor)
        .ok_or(UniformTraceError::Relation)?;
    *constraint = value;
    *cursor = cursor.checked_add(1).ok_or(UniformTraceError::Relation)?;
    Ok(())
}

fn indexed(values: &[Fp], index: usize) -> Result<Fp, UniformTraceError> {
    values
        .get(index)
        .copied()
        .ok_or(UniformTraceError::Relation)
}

fn bus_slot(local: &[Fp], slot: usize) -> Result<(Fp, &[Fp]), UniformTraceError> {
    let start = LOCAL_BUS_START
        .checked_add(
            slot.checked_mul(BUS_SLOT_WIDTH)
                .ok_or(UniformTraceError::Relation)?,
        )
        .ok_or(UniformTraceError::Relation)?;
    let active = indexed(local, start)?;
    let bits_start = start.checked_add(1).ok_or(UniformTraceError::Relation)?;
    let bits_end = bits_start
        .checked_add(BUS_KIND_BITS)
        .ok_or(UniformTraceError::Relation)?;
    let bits = local
        .get(bits_start..bits_end)
        .ok_or(UniformTraceError::Relation)?;
    Ok((active, bits))
}

fn bus_tuple(local: &[Fp], slot: usize) -> Result<&[Fp], UniformTraceError> {
    let start = LOCAL_BUS_START
        .checked_add(
            slot.checked_mul(BUS_SLOT_WIDTH)
                .ok_or(UniformTraceError::Relation)?,
        )
        .and_then(|slot_start| slot_start.checked_add(BUS_ADDRESS))
        .ok_or(UniformTraceError::Relation)?;
    let end = start
        .checked_add(BUS_TUPLE_FIELDS)
        .ok_or(UniformTraceError::Relation)?;
    local.get(start..end).ok_or(UniformTraceError::Relation)
}

fn bus_field(local: &[Fp], slot: usize, offset: usize) -> Result<Fp, UniformTraceError> {
    let start = LOCAL_BUS_START
        .checked_add(
            slot.checked_mul(BUS_SLOT_WIDTH)
                .ok_or(UniformTraceError::Relation)?,
        )
        .and_then(|slot_start| slot_start.checked_add(offset))
        .ok_or(UniformTraceError::Relation)?;
    indexed(local, start)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct BusCategoryCounts {
    opcode: Fp,
    immediate: Fp,
    data_read: Fp,
    data_write: Fp,
}

fn bus_category_counts(local: &[Fp]) -> Result<BusCategoryCounts, UniformTraceError> {
    let mut counts = BusCategoryCounts::default();
    for slot in 0..BUS_EVENT_SLOTS {
        counts.opcode += bus_kind_sum(local, slot, &[1, 14])?;
        counts.immediate += bus_kind_sum(local, slot, &[2, 15])?;
        counts.data_read += bus_kind_sum(local, slot, &[3, 4, 6, 9, 11, 13])?;
        counts.data_write += bus_kind_sum(local, slot, &[5, 7, 8, 10, 12])?;
    }
    Ok(counts)
}

fn bus_kind_sum(local: &[Fp], slot: usize, codes: &[u8]) -> Result<Fp, UniformTraceError> {
    let (_, bits) = bus_slot(local, slot)?;
    codes
        .iter()
        .try_fold(Fp::ZERO, |sum, code| Ok(sum + kind_selector(bits, *code)?))
}

fn kind_selector(bits: &[Fp], code: u8) -> Result<Fp, UniformTraceError> {
    if bits.len() != BUS_KIND_BITS {
        return Err(UniformTraceError::Relation);
    }
    bit_selector(bits, code)
}

fn isa_operation_selector(isa: &[Fp], code: u8) -> Result<Fp, UniformTraceError> {
    let end = ISA_OPERATION_BITS_START
        .checked_add(ISA_OPERATION_BITS)
        .ok_or(UniformTraceError::Relation)?;
    bit_selector(
        isa.get(ISA_OPERATION_BITS_START..end)
            .ok_or(UniformTraceError::Relation)?,
        code,
    )
}

fn isa_argument_selector(isa: &[Fp], start: usize, code: u8) -> Result<Fp, UniformTraceError> {
    let width = match start {
        ISA_ARGUMENT_ZERO_BITS_START => ISA_ARGUMENT_ZERO_BITS,
        ISA_ARGUMENT_ONE_BITS_START => ISA_ARGUMENT_ONE_BITS,
        _ => return Err(UniformTraceError::Relation),
    };
    let end = start
        .checked_add(width)
        .ok_or(UniformTraceError::Relation)?;
    bit_selector(
        isa.get(start..end).ok_or(UniformTraceError::Relation)?,
        code,
    )
}

fn selected_register_word(state: &[Fp], isa: &[Fp]) -> Result<Fp, UniformTraceError> {
    Ok(isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 0)?
        * (indexed(state, 1)? * Fp::from(256) + indexed(state, 2)?)
        + isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 1)?
            * (indexed(state, 3)? * Fp::from(256) + indexed(state, 4)?)
        + isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 2)?
            * (indexed(state, 5)? * Fp::from(256) + indexed(state, 6)?)
        + isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 3)? * indexed(state, 9)?)
}

fn selected_stack_word(state: &[Fp], isa: &[Fp]) -> Result<Fp, UniformTraceError> {
    Ok(isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 0)?
        * (indexed(state, 1)? * Fp::from(256) + indexed(state, 2)?)
        + isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 1)?
            * (indexed(state, 3)? * Fp::from(256) + indexed(state, 4)?)
        + isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 2)?
            * (indexed(state, 5)? * Fp::from(256) + indexed(state, 6)?)
        + isa_argument_selector(isa, ISA_ARGUMENT_ZERO_BITS_START, 3)?
            * (indexed(state, 0)? * Fp::from(256) + indexed(state, 7)?))
}

fn bit_selector(bits: &[Fp], code: u8) -> Result<Fp, UniformTraceError> {
    if bits.len() > u8::BITS as usize {
        return Err(UniformTraceError::Relation);
    }
    Ok(bits
        .iter()
        .enumerate()
        .fold(Fp::ONE, |selected, (bit, value)| {
            if (code >> bit) & 1 == 1 {
                selected * *value
            } else {
                selected * (Fp::ONE - *value)
            }
        }))
}

fn packed_bits_value(bits: &[Fp], start: usize, width: usize) -> Result<Fp, UniformTraceError> {
    let end = start
        .checked_add(width)
        .ok_or(UniformTraceError::Relation)?;
    let selected = bits.get(start..end).ok_or(UniformTraceError::Relation)?;
    let mut coefficient = Fp::ONE;
    Ok(selected.iter().fold(Fp::ZERO, |value, bit| {
        let next = value + coefficient * *bit;
        coefficient = coefficient.double();
        next
    }))
}

#[cfg(test)]
mod tests {
    use zksm83_memory::{MemoryImage, RomImage};
    use zksm83_trace::TraceBuilder;

    use super::{
        BUS_SLOT_WIDTH, BUS_VALUE, CommittedVmStateStructuralProof, LOCAL_BUS_START,
        LOCAL_COLUMN_COUNT, VmIsaSegmentReceipt, VmStateStructuralRelation,
        encode_structural_local, transpose_local, verify_vm_isa_segment_chain,
    };
    use crate::{
        CommittedShiftedUniformTraceProof, IpaParameters, ShiftedUniformRelation,
        VM_STATE_FIELD_COUNT, encode_vm_state, encode_vm_state_columns,
    };

    #[test]
    fn real_native_rows_bind_complete_boundaries_and_structural_invariants()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut builder = TraceBuilder::new(
            RomImage::new(vec![0; 8])?,
            MemoryImage::zeroed()?,
            Vec::new(),
        );
        let mut rows = Vec::new();
        for _ in 0..8 {
            rows.push(builder.step()?);
        }
        let parameters = IpaParameters::new(8)?;
        let initial = rows
            .first()
            .ok_or_else(|| std::io::Error::other("missing first row"))?
            .before();
        let final_state = rows
            .last()
            .ok_or_else(|| std::io::Error::other("missing final row"))?
            .after();
        let proof = CommittedVmStateStructuralProof::prove(&parameters, &rows)?;
        proof.verify(&parameters, initial, final_state)?;
        assert_eq!(
            proof.column_count(),
            VM_STATE_FIELD_COUNT + LOCAL_COLUMN_COUNT
        );
        assert!(proof.verify(&parameters, final_state, final_state).is_err());

        let table_parameters = IpaParameters::new(512)?;
        let receipt = VmIsaSegmentReceipt::prove(&table_parameters, &parameters, &rows)?;
        receipt.verify(&table_parameters, &parameters, initial, final_state)?;
        assert_eq!(receipt.step_count(), 8);
        assert_eq!(
            verify_vm_isa_segment_chain(
                &table_parameters,
                std::slice::from_ref(&parameters),
                std::slice::from_ref(&receipt),
            )?,
            (initial, final_state, 8),
        );
        assert!(
            receipt
                .verify(&table_parameters, &parameters, final_state, final_state,)
                .is_err()
        );
        let mut changed_bus = receipt.clone();
        changed_bus
            .bus_rows
            .first_mut()
            .and_then(|row| row.first_mut())
            .ok_or_else(|| std::io::Error::other("missing bus event"))?
            .value ^= 1;
        assert!(
            changed_bus
                .verify(&table_parameters, &parameters, initial, final_state)
                .is_err()
        );
        let mut changed_isa = receipt.clone();
        *changed_isa
            .isa_rows
            .first_mut()
            .ok_or_else(|| std::io::Error::other("missing ISA row"))? ^= 1;
        assert!(
            changed_isa
                .verify(&table_parameters, &parameters, initial, final_state)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn committed_fetch_and_immediate_tampering_cannot_satisfy_relation()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut builder = TraceBuilder::new(
            RomImage::new(vec![0x01, 0x34, 0x12, 0x18, 0xfe])?,
            MemoryImage::zeroed()?,
            Vec::new(),
        );
        let rows = (0..2)
            .map(|_| builder.step())
            .collect::<Result<Vec<_>, _>>()?;
        let parameters = IpaParameters::new(2)?;
        let initial = rows
            .first()
            .ok_or_else(|| std::io::Error::other("missing first row"))?
            .before();
        let relation = VmStateStructuralRelation::new(initial);
        let states = rows
            .iter()
            .map(zksm83_trace::TraceRow::before)
            .collect::<Vec<_>>();
        let state_columns = encode_vm_state_columns(&states);
        let local_rows = rows
            .iter()
            .enumerate()
            .map(|(index, row)| encode_structural_local(row, index))
            .collect::<Result<Vec<_>, _>>()?;
        let final_values = encode_vm_state(
            rows.last()
                .ok_or_else(|| std::io::Error::other("missing final row"))?
                .after(),
        );

        let mut changed_opcode = local_rows.clone();
        *changed_opcode
            .first_mut()
            .and_then(|row| row.get_mut(LOCAL_BUS_START + BUS_VALUE))
            .ok_or_else(|| std::io::Error::other("missing opcode value"))? +=
            pasta_curves::Fp::from(1);
        let changed_opcode_proof = CommittedShiftedUniformTraceProof::prove(
            &parameters,
            &relation,
            &state_columns,
            &transpose_local(&changed_opcode),
            &final_values,
        )?;
        assert!(
            changed_opcode_proof
                .verify(&parameters, &relation, &final_values)
                .is_err()
        );

        let mut changed_immediate = local_rows;
        *changed_immediate
            .first_mut()
            .and_then(|row| row.get_mut(LOCAL_BUS_START + BUS_SLOT_WIDTH + BUS_VALUE))
            .ok_or_else(|| std::io::Error::other("missing immediate value"))? +=
            pasta_curves::Fp::from(1);
        let changed_immediate_proof = CommittedShiftedUniformTraceProof::prove(
            &parameters,
            &relation,
            &state_columns,
            &transpose_local(&changed_immediate),
            &final_values,
        )?;
        assert!(
            changed_immediate_proof
                .verify(&parameters, &relation, &final_values)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn instruction_cannot_change_unwritten_run_state() -> Result<(), Box<dyn std::error::Error>> {
        let mut builder = TraceBuilder::new(
            RomImage::new(vec![0; 8])?,
            MemoryImage::zeroed()?,
            Vec::new(),
        );
        let row = builder.step()?;
        let parameters = IpaParameters::new(1)?;
        let relation = VmStateStructuralRelation::new(row.before());
        let state_columns = encode_vm_state_columns(&[row.before()]);
        let local = encode_structural_local(&row, 0)?;
        let mut false_final = encode_vm_state(row.after());
        false_final[super::STATE_RUN_STATE] = pasta_curves::Fp::from(1);
        let proof = CommittedShiftedUniformTraceProof::prove(
            &parameters,
            &relation,
            &state_columns,
            &transpose_local(&[local]),
            &false_final,
        )?;

        assert!(proof.verify(&parameters, &relation, &false_final).is_err());
        Ok(())
    }

    #[test]
    fn committed_control_flow_and_delayed_ime_programs_verify()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut call_program = vec![0_u8; 0x8000];
        place(&mut call_program, 0, &[0x31, 0x00, 0xc1])?; // LD SP,$c100
        place(&mut call_program, 3, &[0xcd, 0x08, 0x00])?; // CALL $0008
        place(&mut call_program, 6, &[0x18, 0x04])?; // JR $000c
        place(&mut call_program, 8, &[0xc9])?; // RET
        place(&mut call_program, 12, &[0x21, 0x18, 0x00])?; // LD HL,$0018
        place(&mut call_program, 15, &[0xe9])?; // JP (HL)
        place(&mut call_program, 24, &[0xfb])?; // EI
        place(&mut call_program, 25, &[0x00])?; // NOP: pending -> enabled
        prove_program_segment(call_program, 8)?;

        let mut interrupt_program = vec![0_u8; 0x8000];
        place(&mut interrupt_program, 0, &[0x31, 0x00, 0xc1])?; // LD SP,$c100
        place(&mut interrupt_program, 3, &[0xaf])?; // XOR A: Z=1
        place(&mut interrupt_program, 4, &[0xc2, 0x10, 0x00])?; // JP NZ,$0010
        place(&mut interrupt_program, 7, &[0xdf])?; // RST $18
        place(&mut interrupt_program, 8, &[0xf3])?; // DI
        place(&mut interrupt_program, 9, &[0xfb])?; // EI
        place(&mut interrupt_program, 10, &[0x00])?; // NOP: pending -> enabled
        place(&mut interrupt_program, 0x18, &[0xd9])?; // RETI
        prove_program_segment(interrupt_program, 8)?;

        let mut stack_program = vec![0_u8; 0x8000];
        place(&mut stack_program, 0, &[0x31, 0x00, 0xc1])?; // LD SP,$c100
        place(&mut stack_program, 3, &[0x01, 0x34, 0x12])?; // LD BC,$1234
        place(&mut stack_program, 6, &[0xc5])?; // PUSH BC
        place(&mut stack_program, 7, &[0x01, 0x00, 0x00])?; // LD BC,$0000
        place(&mut stack_program, 10, &[0xd1])?; // POP DE
        place(&mut stack_program, 11, &[0x3e, 0xf3])?; // LD A,$f3
        place(&mut stack_program, 13, &[0xf5])?; // PUSH AF
        place(&mut stack_program, 14, &[0xf1])?; // POP AF
        prove_program_segment(stack_program, 8)?;
        Ok(())
    }

    #[test]
    fn committed_byte_alu_and_indirect_read_modify_write_verify()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut program = vec![0_u8; 0x8000];
        place(&mut program, 0, &[0x21, 0x00, 0xc0])?; // LD HL,$c000
        place(&mut program, 3, &[0x36, 0x0f])?; // LD (HL),$0f
        place(&mut program, 5, &[0x34])?; // INC (HL)
        place(&mut program, 6, &[0x35])?; // DEC (HL)
        place(&mut program, 7, &[0x3e, 0xf0])?; // LD A,$f0
        place(&mut program, 9, &[0x86])?; // ADD A,(HL)
        place(&mut program, 10, &[0xce, 0x01])?; // ADC A,$01
        place(&mut program, 12, &[0xd6, 0x10])?; // SUB $10
        place(&mut program, 14, &[0xde, 0xf1])?; // SBC A,$f1
        place(&mut program, 16, &[0xe6, 0x0f])?; // AND $0f
        place(&mut program, 18, &[0xee, 0xff])?; // XOR $ff
        place(&mut program, 20, &[0xf6, 0x0f])?; // OR $0f
        place(&mut program, 22, &[0xfe, 0xff])?; // CP $ff
        place(&mut program, 24, &[0x3c])?; // INC A
        place(&mut program, 25, &[0x3d])?; // DEC A
        place(&mut program, 26, &[0x00])?; // NOP
        prove_program_segment(program, 16)
    }

    fn prove_program_segment(
        rom: Vec<u8>,
        step_count: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut builder =
            TraceBuilder::new(RomImage::new(rom)?, MemoryImage::zeroed()?, Vec::new());
        let rows = (0..step_count)
            .map(|_| builder.step())
            .collect::<Result<Vec<_>, _>>()?;
        let trace_parameters = IpaParameters::new(step_count)?;
        let table_parameters = IpaParameters::new(512)?;
        let initial = rows
            .first()
            .ok_or_else(|| std::io::Error::other("missing first row"))?
            .before();
        let final_state = rows
            .last()
            .ok_or_else(|| std::io::Error::other("missing final row"))?
            .after();
        let relation = VmStateStructuralRelation::new(initial);
        for (index, row) in rows.iter().enumerate() {
            let local = encode_structural_local(row, index)?;
            let mut constraints = vec![pasta_curves::Fp::from(0); super::CONSTRAINT_COUNT];
            relation.evaluate(
                &encode_vm_state(row.before()),
                &encode_vm_state(row.after()),
                &local,
                pasta_curves::Fp::from(u64::from(index == 0)),
                &mut constraints,
            )?;
            let failed = constraints
                .iter()
                .enumerate()
                .filter_map(|(constraint, value)| {
                    (*value != pasta_curves::Fp::from(0)).then_some(constraint)
                })
                .collect::<Vec<_>>();
            if !failed.is_empty() {
                return Err(std::io::Error::other(format!(
                    "relation row {index} pc {:04x} failed constraints {failed:?}",
                    row.before().cpu().pc()
                ))
                .into());
            }
        }
        let receipt = VmIsaSegmentReceipt::prove(&table_parameters, &trace_parameters, &rows)?;
        receipt.verify(&table_parameters, &trace_parameters, initial, final_state)?;
        Ok(())
    }

    fn place(
        rom: &mut [u8],
        address: usize,
        bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let end = address
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("ROM placement overflow"))?;
        rom.get_mut(address..end)
            .ok_or_else(|| std::io::Error::other("ROM placement out of bounds"))?
            .copy_from_slice(bytes);
        Ok(())
    }
}
