//! Packed-lane projection onto the existing SM83 instruction semantic view.

use akita_pcs::Ring;
use zksm83_trace::{BASIC_BLOCK_BUS_EVENT_BOUND, BASIC_BLOCK_INSTRUCTION_BOUND};

use super::{
    ConstraintSink, RowView, STATE_FLAGS, STATE_IME, STATE_MBC3_RAM_ENABLED,
    STATE_MBC3_RAM_RTC_SELECT, STATE_MBC3_ROM_BANK, STATE_PC, STATE_PROFILE, STATE_RUN_STATE,
    STATE_SP, boolean, constrain_bit_range, enum_range, packed_bits, profile_256kib_selector,
    zero_from_bits,
};
use crate::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_FRONTEND_COLUMN_COUNT, BLOCK_ISA_CONTROL_COLUMN_COUNT,
    BLOCK_MEMORY_COLUMN_COUNT, BLOCK_ROUTING_COLUMN_COUNT, ISA_ADDRESS_BIT_COUNT, ISA_OUTPUT_COUNT,
    NativeField, ROM_ADDRESS_BIT_COUNT, STATE_SCALAR_COUNT, TRACE_ACTIVE,
    TRACE_AFTER_CPU_BYTE_BITS_START, TRACE_AFTER_PC_BITS_START, TRACE_AFTER_RAM_RTC_BITS_START,
    TRACE_AFTER_ROM_BANK_BITS_START, TRACE_AFTER_SP_BITS_START, TRACE_AFTER_STATE_START,
    TRACE_BEFORE_CPU_BYTE_BITS_START, TRACE_BEFORE_PC_BITS_START, TRACE_BEFORE_RAM_RTC_BITS_START,
    TRACE_BEFORE_ROM_BANK_BITS_START, TRACE_BEFORE_SP_BITS_START, TRACE_BEFORE_STATE_START,
    TRACE_BRANCH_TAKEN, TRACE_BUS_ADDRESS_BITS_START, TRACE_BUS_BEFORE_BITS_START,
    TRACE_BUS_KIND_BITS, TRACE_BUS_PHYSICAL_BITS_START, TRACE_BUS_SLOT_WIDTH, TRACE_BUS_START,
    TRACE_BUS_VALUE_BITS_START, TRACE_CYCLE_INCREMENT, TRACE_INTERRUPT_COUNT,
    TRACE_INTERRUPT_START, TRACE_ISA_ADDRESS_START, TRACE_ISA_OUTPUT_START, TRACE_MODE_COUNT,
    TRACE_MODE_START, TRACE_ROM_SELECTOR_START, TRACE_ROM_VALUE_START, UniformError,
    block_boundary::local_state_value,
    block_bus::{
        slot_address_bit, slot_before_bit, slot_field_value, slot_kind_selector,
        slot_physical_address_bit, slot_rom_selector_value, slot_rom_value_value, slot_value_bit,
    },
    block_isa::{lane_address_bit_value, lane_branch_value, lane_output_value, lane_output_values},
    block_metadata,
    block_routing::bus_owner_value,
    trace::{
        PACKED_CPU_AUX_COLUMN_COUNT, PACKED_CPU_BUS_MATCH_COLUMN_COUNT,
        PACKED_CPU_DERIVED_SCALAR_COUNT, packed_cpu_aux_offset, packed_cpu_bus_match_offset,
        packed_cpu_derived_scalar, packed_cpu_derived_scalar_at,
    },
};

const CPU_BOUNDARY_RANGE_CONSTRAINT_COUNT: usize = 113;
const MAPPER_BOUNDARY_RANGE_CONSTRAINT_COUNT: usize = 15;
pub(crate) const PACKED_CPU_BOUNDARY_CONSTRAINT_COUNT: usize =
    CPU_BOUNDARY_RANGE_CONSTRAINT_COUNT + MAPPER_BOUNDARY_RANGE_CONSTRAINT_COUNT;
pub(crate) const PACKED_CPU_LANE_RANGE_CONSTRAINT_COUNT: usize =
    PACKED_CPU_BOUNDARY_CONSTRAINT_COUNT * 2;
pub(crate) const PACKED_CPU_SHARED_BOUNDARY_CONSTRAINT_COUNT: usize =
    (BASIC_BLOCK_INSTRUCTION_BOUND + 1) * PACKED_CPU_BOUNDARY_CONSTRAINT_COUNT;
pub(crate) const PACKED_CPU_BUS_MATCH_CONSTRAINT_COUNT: usize = PACKED_CPU_BUS_MATCH_COLUMN_COUNT;

const _: () = assert!(PACKED_CPU_LANE_RANGE_CONSTRAINT_COUNT == 256);
const _: () = assert!(PACKED_CPU_SHARED_BOUNDARY_CONSTRAINT_COUNT == 640);
const _: () = assert!(PACKED_CPU_BUS_MATCH_CONSTRAINT_COUNT == 60);

pub(super) struct PackedProjection<'a> {
    row: &'a [NativeField],
    lane: usize,
    bus_kind_bits: [[NativeField; TRACE_BUS_KIND_BITS]; BASIC_BLOCK_BUS_EVENT_BOUND],
    derived_scalars: [NativeField; PACKED_CPU_DERIVED_SCALAR_COUNT],
}

impl<'a> PackedProjection<'a> {
    pub(super) fn new(row: &'a [NativeField], lane: usize) -> Result<Self, UniformError> {
        let expected = BLOCK_MEMORY_COLUMN_COUNT
            .checked_add(PACKED_CPU_AUX_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        if row.len() < expected || lane >= BASIC_BLOCK_INSTRUCTION_BOUND {
            return Err(UniformError::Shape);
        }
        let mut bus_kind_bits =
            [[NativeField::from_u64(0); TRACE_BUS_KIND_BITS]; BASIC_BLOCK_BUS_EVENT_BOUND];
        for slot in 0..BASIC_BLOCK_BUS_EVENT_BOUND {
            for bit in 0..TRACE_BUS_KIND_BITS {
                let target = bus_kind_bits
                    .get_mut(slot)
                    .and_then(|bits| bits.get_mut(bit))
                    .ok_or(UniformError::Shape)?;
                *target = local_bus_field(row, lane, slot, 1 + bit)?;
            }
        }
        let derived_scalars = project_derived_scalars(row, lane)?;
        Ok(Self {
            row,
            lane,
            bus_kind_bits,
            derived_scalars,
        })
    }

    pub(super) fn value(&self, legacy_column: usize) -> Result<NativeField, UniformError> {
        if legacy_column < TRACE_AFTER_STATE_START {
            return self.state_value(false, legacy_column - TRACE_BEFORE_STATE_START);
        }
        if legacy_column < TRACE_ACTIVE {
            return self.state_value(true, legacy_column - TRACE_AFTER_STATE_START);
        }
        if legacy_column == TRACE_ACTIVE {
            return block_metadata::lane_value(self.row, self.lane);
        }
        if (TRACE_MODE_START..TRACE_INTERRUPT_START).contains(&legacy_column) {
            return self.mode_value(legacy_column - TRACE_MODE_START);
        }
        if (TRACE_INTERRUPT_START..TRACE_CYCLE_INCREMENT).contains(&legacy_column) {
            return Ok(NativeField::from_u64(0));
        }
        if legacy_column == TRACE_CYCLE_INCREMENT {
            return self.state_delta(super::STATE_CYCLES);
        }
        if legacy_column == TRACE_BRANCH_TAKEN {
            return lane_branch_value(self.isa_row()?, self.lane);
        }
        if (TRACE_ISA_ADDRESS_START..TRACE_ISA_OUTPUT_START).contains(&legacy_column) {
            return lane_address_bit_value(
                self.isa_row()?,
                self.lane,
                legacy_column - TRACE_ISA_ADDRESS_START,
            );
        }
        if (TRACE_ISA_OUTPUT_START..TRACE_BUS_START).contains(&legacy_column) {
            return lane_output_value(
                self.isa_row()?,
                self.lane,
                legacy_column - TRACE_ISA_OUTPUT_START,
            );
        }
        if (TRACE_BUS_START..crate::TRACE_BEFORE_CPU_BYTE_BITS_START).contains(&legacy_column) {
            return self.bus_tuple_value(legacy_column);
        }
        if let Some((index, _, _)) = packed_cpu_derived_scalar(legacy_column) {
            return self
                .derived_scalars
                .get(index)
                .copied()
                .ok_or(UniformError::Shape);
        }
        if let Some(offset) = packed_cpu_aux_offset(legacy_column, self.lane) {
            return self.aux_value(offset);
        }
        if (TRACE_BUS_ADDRESS_BITS_START..TRACE_BUS_PHYSICAL_BITS_START).contains(&legacy_column) {
            return self.bus_bit_value(
                legacy_column,
                TRACE_BUS_ADDRESS_BITS_START,
                16,
                BusBits::Address,
            );
        }
        if (TRACE_BUS_PHYSICAL_BITS_START..TRACE_BUS_VALUE_BITS_START).contains(&legacy_column) {
            return self.bus_bit_value(
                legacy_column,
                TRACE_BUS_PHYSICAL_BITS_START,
                ROM_ADDRESS_BIT_COUNT,
                BusBits::Physical,
            );
        }
        if (TRACE_BUS_VALUE_BITS_START..TRACE_BUS_BEFORE_BITS_START).contains(&legacy_column) {
            return self.bus_bit_value(
                legacy_column,
                TRACE_BUS_VALUE_BITS_START,
                8,
                BusBits::Value,
            );
        }
        if (TRACE_BUS_BEFORE_BITS_START..TRACE_BEFORE_RAM_RTC_BITS_START).contains(&legacy_column) {
            return self.bus_bit_value(
                legacy_column,
                TRACE_BUS_BEFORE_BITS_START,
                8,
                BusBits::Before,
            );
        }
        if (TRACE_ROM_SELECTOR_START..TRACE_ROM_VALUE_START).contains(&legacy_column) {
            return local_bus_rom_value(
                self.row,
                self.lane,
                legacy_column - TRACE_ROM_SELECTOR_START,
                false,
            );
        }
        if (TRACE_ROM_VALUE_START..TRACE_ROM_VALUE_START + BASIC_BLOCK_BUS_EVENT_BOUND)
            .contains(&legacy_column)
        {
            return local_bus_rom_value(
                self.row,
                self.lane,
                legacy_column - TRACE_ROM_VALUE_START,
                true,
            );
        }
        Err(UniformError::Shape)
    }

    pub(super) fn values(
        &self,
        legacy_start: usize,
        count: usize,
    ) -> Result<&[NativeField], UniformError> {
        if (TRACE_ISA_OUTPUT_START..TRACE_BUS_START).contains(&legacy_start) {
            return lane_output_values(
                self.isa_row()?,
                self.lane,
                legacy_start - TRACE_ISA_OUTPUT_START,
                count,
            );
        }
        for slot in 0..BASIC_BLOCK_BUS_EVENT_BOUND {
            let start = TRACE_BUS_START
                .checked_add(
                    slot.checked_mul(TRACE_BUS_SLOT_WIDTH)
                        .ok_or(UniformError::Shape)?,
                )
                .and_then(|value| value.checked_add(1))
                .ok_or(UniformError::Shape)?;
            if legacy_start == start && count == TRACE_BUS_KIND_BITS {
                return self
                    .bus_kind_bits
                    .get(slot)
                    .map(AsRef::as_ref)
                    .ok_or(UniformError::Shape);
            }
        }
        Err(UniformError::Shape)
    }

    pub(super) fn bus_kind_selector(
        &self,
        local_slot: usize,
        code: u8,
    ) -> Result<NativeField, UniformError> {
        project_local_bus(self.row, self.lane, local_slot, |bus, shared_slot| {
            slot_kind_selector(bus, shared_slot, code)
        })
    }

    fn state_value(&self, after: bool, scalar: usize) -> Result<NativeField, UniformError> {
        if scalar >= STATE_SCALAR_COUNT {
            return Err(UniformError::Shape);
        }
        let boundary = self.boundary_row()?;
        let position = self
            .lane
            .checked_add(usize::from(after))
            .ok_or(UniformError::Shape)?;
        local_state_value(boundary, position, scalar)
    }

    fn state_delta(&self, scalar: usize) -> Result<NativeField, UniformError> {
        Ok(self.state_value(true, scalar)? - self.state_value(false, scalar)?)
    }

    fn mode_value(&self, mode: usize) -> Result<NativeField, UniformError> {
        if mode >= TRACE_MODE_COUNT {
            return Err(UniformError::Shape);
        }
        let active = block_metadata::lane_value(self.row, self.lane)?;
        if mode == super::INSTRUCTION_MODE {
            Ok(active)
        } else if mode == super::PADDING_MODE {
            Ok(NativeField::from_u64(1) - active)
        } else {
            Ok(NativeField::from_u64(0))
        }
    }

    fn bus_tuple_value(&self, legacy_column: usize) -> Result<NativeField, UniformError> {
        let relative = legacy_column
            .checked_sub(TRACE_BUS_START)
            .ok_or(UniformError::Shape)?;
        let slot = relative / TRACE_BUS_SLOT_WIDTH;
        let offset = relative % TRACE_BUS_SLOT_WIDTH;
        if offset > 0 && offset <= TRACE_BUS_KIND_BITS {
            return self
                .bus_kind_bits
                .get(slot)
                .and_then(|bits| bits.get(offset - 1))
                .copied()
                .ok_or(UniformError::Shape);
        }
        local_bus_field(self.row, self.lane, slot, offset)
    }

    fn bus_bit_value(
        &self,
        legacy_column: usize,
        start: usize,
        width: usize,
        kind: BusBits,
    ) -> Result<NativeField, UniformError> {
        let relative = legacy_column
            .checked_sub(start)
            .ok_or(UniformError::Shape)?;
        let slot = relative / width;
        let bit = relative % width;
        local_bus_bit(self.row, self.lane, slot, bit, kind)
    }

    fn aux_value(&self, offset: usize) -> Result<NativeField, UniformError> {
        let index = BLOCK_MEMORY_COLUMN_COUNT
            .checked_add(offset)
            .ok_or(UniformError::Shape)?;
        self.row.get(index).copied().ok_or(UniformError::Shape)
    }

    fn boundary_row(&self) -> Result<&[NativeField], UniformError> {
        self.row
            .get(BLOCK_ROUTING_COLUMN_COUNT..BLOCK_CONTROL_COLUMN_COUNT)
            .ok_or(UniformError::Shape)
    }

    fn isa_row(&self) -> Result<&[NativeField], UniformError> {
        self.row
            .get(BLOCK_CONTROL_COLUMN_COUNT..BLOCK_ISA_CONTROL_COLUMN_COUNT)
            .ok_or(UniformError::Shape)
    }
}

fn project_derived_scalars(
    row: &[NativeField],
    lane: usize,
) -> Result<[NativeField; PACKED_CPU_DERIVED_SCALAR_COUNT], UniformError> {
    let mut derived = [NativeField::from_u64(0); PACKED_CPU_DERIVED_SCALAR_COUNT];
    for index in 0..PACKED_CPU_DERIVED_SCALAR_COUNT {
        let (_, bits_start, width) =
            packed_cpu_derived_scalar_at(index).ok_or(UniformError::Shape)?;
        let target = derived.get_mut(index).ok_or(UniformError::Shape)?;
        let mut coefficient = NativeField::from_u64(1);
        // Post: target = sum(bits[bit] * 2^bit) in the native relation field.
        for bit in 0..width {
            let legacy_bit = bits_start.checked_add(bit).ok_or(UniformError::Shape)?;
            let offset = packed_cpu_aux_offset(legacy_bit, lane).ok_or(UniformError::Shape)?;
            let value = row
                .get(
                    BLOCK_MEMORY_COLUMN_COUNT
                        .checked_add(offset)
                        .ok_or(UniformError::Shape)?,
                )
                .copied()
                .ok_or(UniformError::Shape)?;
            *target += coefficient * value;
            coefficient *= NativeField::from_u64(2);
        }
    }
    Ok(derived)
}

#[derive(Clone, Copy)]
enum BusBits {
    Address,
    Physical,
    Value,
    Before,
}

fn constrain_cpu_boundary(
    view: &RowView<'_>,
    after: bool,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let (byte_bits, pc_bits, sp_bits) = if after {
        (
            TRACE_AFTER_CPU_BYTE_BITS_START,
            TRACE_AFTER_PC_BITS_START,
            TRACE_AFTER_SP_BITS_START,
        )
    } else {
        (
            TRACE_BEFORE_CPU_BYTE_BITS_START,
            TRACE_BEFORE_PC_BITS_START,
            TRACE_BEFORE_SP_BITS_START,
        )
    };
    constrain_bit_range(view, sink, byte_bits, 8 * 8)?;
    constrain_bit_range(view, sink, pc_bits, 16)?;
    constrain_bit_range(view, sink, sp_bits, 16)?;
    for byte in 0..8 {
        sink.push(state_value(view, after, byte)? - packed_bits(view, byte_bits + byte * 8, 8)?)?;
    }
    for bit in 0..4 {
        sink.push(view.value(byte_bits + STATE_FLAGS * 8 + bit)?)?;
    }
    for (state, bits) in [(STATE_PC, pc_bits), (STATE_SP, sp_bits)] {
        sink.push(state_value(view, after, state)? - packed_bits(view, bits, 16)?)?;
    }
    sink.push(enum_range(state_value(view, after, STATE_IME)?, 3))?;
    sink.push(enum_range(state_value(view, after, STATE_RUN_STATE)?, 4))?;
    sink.push(enum_range(state_value(view, after, STATE_PROFILE)?, 5))
}

fn constrain_mapper_boundary(
    view: &RowView<'_>,
    after: bool,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let (rom_bits, select_bits) = if after {
        (
            TRACE_AFTER_ROM_BANK_BITS_START,
            TRACE_AFTER_RAM_RTC_BITS_START,
        )
    } else {
        (
            TRACE_BEFORE_ROM_BANK_BITS_START,
            TRACE_BEFORE_RAM_RTC_BITS_START,
        )
    };
    sink.push(boolean(state_value(view, after, STATE_MBC3_RAM_ENABLED)?))?;
    constrain_bit_range(view, sink, rom_bits, 6)?;
    sink.push(state_value(view, after, STATE_MBC3_ROM_BANK)? - packed_bits(view, rom_bits, 6)?)?;
    sink.push(zero_from_bits(view, rom_bits, 6)?)?;
    sink.push(
        profile_256kib_selector(state_value(view, after, STATE_PROFILE)?)?
            * (state_value(view, after, STATE_MBC3_ROM_BANK)? - packed_bits(view, rom_bits, 4)?),
    )?;
    constrain_bit_range(view, sink, select_bits, 4)?;
    sink.push(
        state_value(view, after, STATE_MBC3_RAM_RTC_SELECT)? - packed_bits(view, select_bits, 4)?,
    )
}

fn state_value(view: &RowView<'_>, after: bool, state: usize) -> Result<NativeField, UniformError> {
    if after {
        view.after(state)
    } else {
        view.before(state)
    }
}

pub(crate) fn constrain_instruction_lane(
    row: &[NativeField],
    lane: usize,
    boundary_constraints: &mut [NativeField],
    constraints: &mut [NativeField],
) -> Result<usize, UniformError> {
    let expected_boundary_constraints = if lane == 0 {
        PACKED_CPU_LANE_RANGE_CONSTRAINT_COUNT
    } else {
        PACKED_CPU_BOUNDARY_CONSTRAINT_COUNT
    };
    if boundary_constraints.len() != expected_boundary_constraints {
        return Err(UniformError::Shape);
    }
    let view = RowView::packed(row, lane)?;
    let mut boundary_sink = ConstraintSink::new(boundary_constraints);
    if lane == 0 {
        constrain_cpu_boundary(&view, false, &mut boundary_sink)?;
        constrain_mapper_boundary(&view, false, &mut boundary_sink)?;
    }
    constrain_cpu_boundary(&view, true, &mut boundary_sink)?;
    constrain_mapper_boundary(&view, true, &mut boundary_sink)?;
    if boundary_sink.finish()? != expected_boundary_constraints {
        return Err(UniformError::Shape);
    }
    let mut sink = ConstraintSink::new(constraints);
    constrain_state_write_mask(&view, &mut sink)?;
    super::execution::constrain_execution_lookup_glue(row, lane, &view, &mut sink)?;
    super::mbc3::constrain_mapper_and_rom(&view, &mut sink)?;
    super::control::constrain_instruction_flow_with_lookup(&view, &mut sink)?;
    super::data::constrain_data_and_simple_operations(&view, &mut sink)?;
    super::word::constrain_word_operations_with_lookup(&view, &mut sink)?;
    super::stack::constrain_stack_operations(&view, &mut sink)?;
    super::bit::constrain_cb_bus_with_lookup(&view, &mut sink)?;
    sink.finish()
}

fn constrain_state_write_mask(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let one = NativeField::from_u64(1);
    let instruction = view.mode(super::INSTRUCTION_MODE)?;
    let halt_bug = view.value(crate::TRACE_HALT_BUG)?;
    for state in 0..super::STATE_CYCLES {
        let write = view.isa(crate::ISA_WRITE_BITS_START + state)?;
        let halt_bug_reset = if state == super::STATE_RUN_STATE {
            NativeField::from_u64(3) * halt_bug
        } else {
            NativeField::from_u64(0)
        };
        sink.push(
            instruction
                * (one - write)
                * (view.after(state)? - view.before(state)? + halt_bug_reset),
        )?;
    }
    Ok(())
}

fn local_bus_field(
    row: &[NativeField],
    lane: usize,
    local_slot: usize,
    offset: usize,
) -> Result<NativeField, UniformError> {
    project_local_bus(row, lane, local_slot, |bus, shared_slot| {
        slot_field_value(bus, shared_slot, offset)
    })
}

fn local_bus_bit(
    row: &[NativeField],
    lane: usize,
    local_slot: usize,
    bit: usize,
    kind: BusBits,
) -> Result<NativeField, UniformError> {
    project_local_bus(row, lane, local_slot, |bus, shared_slot| match kind {
        BusBits::Address => slot_address_bit(bus, shared_slot, bit),
        BusBits::Physical => slot_physical_address_bit(bus, shared_slot, bit),
        BusBits::Value => slot_value_bit(bus, shared_slot, bit),
        BusBits::Before => slot_before_bit(bus, shared_slot, bit),
    })
}

fn local_bus_rom_value(
    row: &[NativeField],
    lane: usize,
    local_slot: usize,
    value: bool,
) -> Result<NativeField, UniformError> {
    project_local_bus(row, lane, local_slot, |bus, shared_slot| {
        if value {
            slot_rom_value_value(bus, shared_slot)
        } else {
            slot_rom_selector_value(bus, shared_slot)
        }
    })
}

fn project_local_bus(
    row: &[NativeField],
    lane: usize,
    local_slot: usize,
    mut shared_value: impl FnMut(&[NativeField], usize) -> Result<NativeField, UniformError>,
) -> Result<NativeField, UniformError> {
    if lane >= BASIC_BLOCK_INSTRUCTION_BOUND || local_slot >= BASIC_BLOCK_BUS_EVENT_BOUND {
        return Err(UniformError::Shape);
    }
    let bus = row
        .get(BLOCK_ISA_CONTROL_COLUMN_COUNT..BLOCK_FRONTEND_COLUMN_COUNT)
        .ok_or(UniformError::Shape)?;
    let mut projected = NativeField::from_u64(0);
    for shared_slot in local_slot..BASIC_BLOCK_BUS_EVENT_BOUND {
        projected += committed_local_bus_match(row, lane, local_slot, shared_slot)?
            * shared_value(bus, shared_slot)?;
    }
    Ok(projected)
}

fn committed_local_bus_match(
    row: &[NativeField],
    lane: usize,
    local_slot: usize,
    shared_slot: usize,
) -> Result<NativeField, UniformError> {
    let offset =
        packed_cpu_bus_match_offset(lane, local_slot, shared_slot).ok_or(UniformError::Shape)?;
    let index = BLOCK_MEMORY_COLUMN_COUNT
        .checked_add(offset)
        .ok_or(UniformError::Shape)?;
    row.get(index).copied().ok_or(UniformError::Shape)
}

fn expected_local_bus_match(
    routing: &[NativeField],
    lane: usize,
    local_slot: usize,
    shared_slot: usize,
) -> Result<NativeField, UniformError> {
    let first_slot = shared_slot
        .checked_sub(local_slot)
        .ok_or(UniformError::Shape)?;
    let owner = bus_owner_value(routing, first_slot, lane)?;
    let first = if first_slot == 0 {
        owner
    } else {
        owner * (NativeField::from_u64(1) - bus_owner_value(routing, first_slot - 1, lane)?)
    };
    if local_slot == 0 {
        Ok(first)
    } else {
        Ok(first * bus_owner_value(routing, shared_slot, lane)?)
    }
}

pub(crate) fn constrain_bus_matches(
    row: &[NativeField],
    constraints: &mut [NativeField],
) -> Result<(), UniformError> {
    if constraints.len() != PACKED_CPU_BUS_MATCH_CONSTRAINT_COUNT {
        return Err(UniformError::Shape);
    }
    let mut cursor = 0_usize;
    for lane in 0..BASIC_BLOCK_INSTRUCTION_BOUND {
        for local_slot in 0..BASIC_BLOCK_BUS_EVENT_BOUND {
            for shared_slot in local_slot..BASIC_BLOCK_BUS_EVENT_BOUND {
                let output = constraints.get_mut(cursor).ok_or(UniformError::Shape)?;
                *output = committed_local_bus_match(row, lane, local_slot, shared_slot)?
                    - expected_local_bus_match(row, lane, local_slot, shared_slot)?;
                cursor = cursor.checked_add(1).ok_or(UniformError::Shape)?;
            }
        }
    }
    if cursor != PACKED_CPU_BUS_MATCH_CONSTRAINT_COUNT {
        return Err(UniformError::Shape);
    }
    Ok(())
}

const _: () = assert!(ISA_ADDRESS_BIT_COUNT == 9);
const _: () = assert!(ISA_OUTPUT_COUNT == 38);
const _: () = assert!(TRACE_INTERRUPT_COUNT == 5);
const _: () = assert!(TRACE_BUS_KIND_BITS == 5);
const _: () = assert!(BASIC_BLOCK_BUS_EVENT_BOUND == 5);
const _: () = assert!(BASIC_BLOCK_INSTRUCTION_BOUND == 4);
