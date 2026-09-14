use akita_pcs::Ring;
use jolt_field::CanonicalBytes;

use crate::{
    BLOCK_CONTROL_COLUMN_COUNT, BLOCK_CPU_COLUMN_COUNT, BLOCK_FRONTEND_COLUMN_COUNT,
    BLOCK_ISA_CONTROL_COLUMN_COUNT, BlockCpuWitness, ConstraintOutput, ISA_PACKED_HIGH,
    ISA_PACKED_LOW, NativeField, NativeProtocolVersion, TRACE_BUS_KIND_BITS, TRACE_BUS_SLOTS,
    UNIFORM_ROW_COUNT, UniformError, UniformRelation, WitnessCommitments,
    block_bus::{
        slot_active_column, slot_active_value, slot_address_column, slot_address_value,
        slot_auxiliary_column, slot_auxiliary_value, slot_before_column, slot_before_value,
        slot_index_column, slot_index_value, slot_kind_bit_column, slot_physical_address_column,
        slot_physical_address_value, slot_value_column, slot_value_value,
    },
    block_isa::lane_output_value,
    block_memory::{BLOCK_MEMORY_ROW_BITS_START, memory_row_index_value},
    block_metadata::{lane_column, lane_value},
    uniform::{
        CommittedWitness, CompositeUniformRelationProof, prove_uniform_composite,
        verify_uniform_composite_for_protocol,
    },
};

use super::{
    BUS_START, BUS_WIDTH, INPUT_START, ISA_START, ISA_WIDTH, LOG_COLUMN_COUNT, LogChallenges,
    LogEntries, LogKind, OUTPUT_START, PACKED_TRACE_INVERSE_COLUMN_COUNT,
    PACKED_TRACE_INVERSE_ENTRY_COUNT, PROTOCOL_LOG_ROW_COUNT, ProtocolLogError, append_table,
    compress, packed_trace, push_inverse, selected_inverse, trace_value,
};

const PACKED_ISA_LANES: usize = 4;
const BUS_TOKEN_FIELD_COUNT: usize = 8;
const PACKED_LANES: [zksm83_trace::BasicBlockLaneIndex; PACKED_ISA_LANES] = [
    zksm83_trace::BasicBlockLaneIndex::Lane0,
    zksm83_trace::BasicBlockLaneIndex::Lane1,
    zksm83_trace::BasicBlockLaneIndex::Lane2,
    zksm83_trace::BasicBlockLaneIndex::Lane3,
];

pub(super) fn log_columns(trace: &BlockCpuWitness) -> Result<Vec<Vec<u64>>, ProtocolLogError> {
    let entries = extract_entries(trace)?;
    let mut columns = (0..LOG_COLUMN_COUNT)
        .map(|_| Vec::with_capacity(PROTOCOL_LOG_ROW_COUNT))
        .collect::<Vec<_>>();
    append_table(&mut columns, BUS_START, &entries.bus)?;
    append_table(&mut columns, INPUT_START, &entries.input)?;
    append_table(&mut columns, OUTPUT_START, &entries.output)?;
    append_table(&mut columns, ISA_START, &entries.isa)?;
    if columns
        .iter()
        .any(|column| column.len() != PROTOCOL_LOG_ROW_COUNT)
    {
        return Err(ProtocolLogError::Shape);
    }
    Ok(columns)
}

fn extract_entries(trace: &BlockCpuWitness) -> Result<LogEntries, ProtocolLogError> {
    if trace.columns().len() != BLOCK_CPU_COLUMN_COUNT {
        return Err(ProtocolLogError::Shape);
    }
    let mut entries = LogEntries {
        bus: Vec::with_capacity(trace.bus_event_count()),
        input: Vec::new(),
        output: Vec::new(),
        isa: Vec::with_capacity(trace.instruction_count()),
    };
    for row in 0..trace.active_block_count() {
        append_log_row(trace, row, &mut entries)?;
    }
    if entries.bus.len() != trace.bus_event_count()
        || entries.isa.len() != trace.instruction_count()
    {
        return Err(ProtocolLogError::Shape);
    }
    Ok(entries)
}

fn append_log_row(
    trace: &BlockCpuWitness,
    row: usize,
    entries: &mut LogEntries,
) -> Result<(), ProtocolLogError> {
    let row_index = u64::try_from(row).map_err(|_| ProtocolLogError::Shape)?;
    for slot in 0..TRACE_BUS_SLOTS {
        if packed_bus_value(trace, slot_active_column(slot)?, row)? == 0 {
            continue;
        }
        let kind = packed_bus_kind(trace, slot, row)?;
        let position = row_index
            .checked_mul(TRACE_BUS_SLOTS as u64)
            .and_then(|value| value.checked_add(u64::try_from(slot).ok()?))
            .ok_or(ProtocolLogError::Shape)?;
        entries
            .bus
            .push(packed_bus_entry(trace, row, slot, position, kind)?);
        append_byte_entry(trace, row, slot, kind, entries)?;
    }
    for lane in 0..PACKED_ISA_LANES {
        if trace_value(
            trace.columns(),
            lane_column(lane).ok_or(ProtocolLogError::Shape)?,
            row,
        )? == 0
        {
            continue;
        }
        let position = row_index
            .checked_mul(PACKED_ISA_LANES as u64)
            .and_then(|value| value.checked_add(u64::try_from(lane).ok()?))
            .ok_or(ProtocolLogError::Shape)?;
        entries
            .isa
            .push(packed_isa_entry(trace, row, lane, position)?);
    }
    Ok(())
}

fn packed_bus_entry(
    trace: &BlockCpuWitness,
    row: usize,
    slot: usize,
    position: u64,
    kind: u64,
) -> Result<[u64; BUS_WIDTH - 1], ProtocolLogError> {
    Ok([
        position,
        kind,
        packed_bus_value(trace, slot_address_column(slot)?, row)?,
        packed_bus_value(trace, slot_physical_address_column(slot)?, row)?,
        packed_bus_value(trace, slot_before_column(slot)?, row)?,
        packed_bus_value(trace, slot_auxiliary_column(slot)?, row)?,
        packed_bus_value(trace, slot_value_column(slot)?, row)?,
        packed_bus_value(trace, slot_index_column(slot)?, row)?,
    ])
}

fn append_byte_entry(
    trace: &BlockCpuWitness,
    row: usize,
    slot: usize,
    kind: u64,
    entries: &mut LogEntries,
) -> Result<(), ProtocolLogError> {
    let index = packed_bus_value(trace, slot_index_column(slot)?, row)?;
    if kind == 6 || kind == 13 {
        let value_column = if kind == 13 {
            slot_auxiliary_column(slot)?
        } else {
            slot_value_column(slot)?
        };
        entries
            .input
            .push([index, packed_bus_value(trace, value_column, row)?]);
    }
    if kind == 7 {
        entries.output.push([
            index,
            packed_bus_value(trace, slot_value_column(slot)?, row)?,
        ]);
    }
    Ok(())
}

fn packed_isa_entry(
    trace: &BlockCpuWitness,
    row: usize,
    lane: usize,
    position: u64,
) -> Result<[u64; ISA_WIDTH - 1], ProtocolLogError> {
    let typed_lane = *PACKED_LANES.get(lane).ok_or(ProtocolLogError::Shape)?;
    let outputs = BlockCpuWitness::lane_isa_lookup_columns(typed_lane)
        .map_err(|_| ProtocolLogError::Shape)?
        .outputs();
    Ok([
        position,
        trace_value(
            trace.columns(),
            *outputs.get(ISA_PACKED_LOW).ok_or(ProtocolLogError::Shape)?,
            row,
        )?,
        trace_value(
            trace.columns(),
            *outputs
                .get(ISA_PACKED_HIGH)
                .ok_or(ProtocolLogError::Shape)?,
            row,
        )?,
    ])
}

pub(super) fn prove(
    trace: &CommittedWitness,
    inverses: &CommittedWitness,
    challenges: LogChallenges,
) -> Result<CompositeUniformRelationProof, ProtocolLogError> {
    prove_uniform_composite(&PackedTraceLogRelation { challenges }, trace, inverses)
        .map_err(Into::into)
}

pub(super) fn verify(
    protocol: NativeProtocolVersion,
    trace: &WitnessCommitments,
    inverses: &WitnessCommitments,
    challenges: LogChallenges,
    proof: &CompositeUniformRelationProof,
) -> Result<(), ProtocolLogError> {
    verify_uniform_composite_for_protocol(
        protocol,
        &PackedTraceLogRelation { challenges },
        trace,
        inverses,
        proof,
    )
    .map_err(Into::into)
}

struct PackedTraceLogRelation {
    challenges: LogChallenges,
}

impl UniformRelation for PackedTraceLogRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-block-protocol-log-trace-inverses/v2"
    }

    fn statement_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for challenge in self
            .challenges
            .tuple_mix
            .into_iter()
            .chain(self.challenges.inverse_point)
        {
            bytes.extend_from_slice(&challenge.to_bytes_le_vec());
        }
        for value in [
            BLOCK_CPU_COLUMN_COUNT as u64,
            TRACE_BUS_SLOTS as u64,
            PACKED_ISA_LANES as u64,
            PACKED_TRACE_INVERSE_ENTRY_COUNT as u64,
            5,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    fn column_count(&self) -> usize {
        BLOCK_CPU_COLUMN_COUNT + PACKED_TRACE_INVERSE_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        PACKED_TRACE_INVERSE_ENTRY_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        7
    }

    fn constraint_output(&self) -> ConstraintOutput {
        ConstraintOutput::Overwritten
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != self.column_count() || constraints.len() != self.constraint_count() {
            return Err(UniformError::Shape);
        }
        let bus = row
            .get(BLOCK_ISA_CONTROL_COLUMN_COUNT..BLOCK_FRONTEND_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let isa = row
            .get(BLOCK_CONTROL_COLUMN_COUNT..BLOCK_ISA_CONTROL_COLUMN_COUNT)
            .ok_or(UniformError::Shape)?;
        let row_index = memory_row_index_value(row)?;
        for slot in 0..TRACE_BUS_SLOTS {
            self.evaluate_bus_slot(row, bus, constraints, row_index, slot)?;
        }
        for lane in 0..PACKED_ISA_LANES {
            self.evaluate_isa_lane(row, isa, constraints, row_index, lane)?;
        }
        Ok(())
    }
}

impl PackedTraceLogRelation {
    fn evaluate_bus_slot(
        &self,
        row: &[NativeField],
        bus: &[NativeField],
        constraints: &mut [NativeField],
        row_index: NativeField,
        slot: usize,
    ) -> Result<(), UniformError> {
        let active = slot_active_value(bus, slot)?;
        let kind_bits = bus_kind_bits(bus, slot)?;
        let private = bit_selector(&kind_bits, 6);
        let joypad = bit_selector(&kind_bits, 13);
        let input = private + joypad;
        let output = bit_selector(&kind_bits, 7);
        let position = row_index * NativeField::from_u64(TRACE_BUS_SLOTS as u64)
            + NativeField::from_u64(u64::try_from(slot).map_err(|_| UniformError::Shape)?);
        let bus_token = compress(&bus_values(bus, slot, position)?, self.mix(LogKind::Bus));
        let input_value =
            private * slot_value_value(bus, slot)? + joypad * slot_auxiliary_value(bus, slot)?;
        let input_token = compress(
            &[slot_index_value(bus, slot)?, input_value],
            self.mix(LogKind::Input),
        );
        let output_token = compress(
            &[slot_index_value(bus, slot)?, slot_value_value(bus, slot)?],
            self.mix(LogKind::Output),
        );
        for (kind, selector, token, entry) in [
            (LogKind::Bus, active, bus_token, slot),
            (LogKind::Input, input, input_token, TRACE_BUS_SLOTS + slot),
            (
                LogKind::Output,
                output,
                output_token,
                TRACE_BUS_SLOTS * 2 + slot,
            ),
        ] {
            let inverse = inverse_at(row, entry)?;
            *constraints.get_mut(entry).ok_or(UniformError::Shape)? =
                (self.point(kind) - token) * inverse - selector;
        }
        Ok(())
    }

    fn evaluate_isa_lane(
        &self,
        row: &[NativeField],
        isa: &[NativeField],
        constraints: &mut [NativeField],
        row_index: NativeField,
        lane: usize,
    ) -> Result<(), UniformError> {
        let position = row_index * NativeField::from_u64(PACKED_ISA_LANES as u64)
            + NativeField::from_u64(u64::try_from(lane).map_err(|_| UniformError::Shape)?);
        let token = compress(
            &[
                position,
                lane_output_value(isa, lane, ISA_PACKED_LOW)?,
                lane_output_value(isa, lane, ISA_PACKED_HIGH)?,
            ],
            self.mix(LogKind::Isa),
        );
        let entry = TRACE_BUS_SLOTS * 3 + lane;
        let inverse = inverse_at(row, entry)?;
        *constraints.get_mut(entry).ok_or(UniformError::Shape)? =
            (self.point(LogKind::Isa) - token) * inverse - lane_value(row, lane)?;
        Ok(())
    }

    fn mix(&self, kind: LogKind) -> NativeField {
        self.challenges.mix(kind)
    }

    fn point(&self, kind: LogKind) -> NativeField {
        self.challenges.point(kind)
    }
}

pub(super) fn inverse_columns(
    trace: &BlockCpuWitness,
    challenges: LogChallenges,
) -> Result<Vec<Vec<u64>>, ProtocolLogError> {
    if trace.columns().len() != BLOCK_CPU_COLUMN_COUNT {
        return Err(ProtocolLogError::Shape);
    }
    let mut columns = (0..PACKED_TRACE_INVERSE_COLUMN_COUNT)
        .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
        .collect::<Vec<_>>();
    for row in 0..UNIFORM_ROW_COUNT {
        append_row_inverses(trace, row, challenges, &mut columns)?;
    }
    Ok(columns)
}

fn append_row_inverses(
    trace: &BlockCpuWitness,
    row: usize,
    challenges: LogChallenges,
    columns: &mut [Vec<u64>],
) -> Result<(), ProtocolLogError> {
    let row_index = packed_trace(
        trace.columns(),
        BLOCK_MEMORY_ROW_BITS_START,
        crate::UNIFORM_NUM_VARIABLES,
        row,
    )?;
    for slot in 0..TRACE_BUS_SLOTS {
        append_bus_inverses(trace, row, row_index, slot, challenges, columns)?;
    }
    for lane in 0..PACKED_ISA_LANES {
        append_isa_inverse(trace, row, row_index, lane, challenges, columns)?;
    }
    Ok(())
}

fn append_bus_inverses(
    trace: &BlockCpuWitness,
    row: usize,
    row_index: u64,
    slot: usize,
    challenges: LogChallenges,
    columns: &mut [Vec<u64>],
) -> Result<(), ProtocolLogError> {
    let active = packed_bus_value(trace, slot_active_column(slot)?, row)?;
    let kind = packed_bus_kind(trace, slot, row)?;
    let position = row_index
        .checked_mul(TRACE_BUS_SLOTS as u64)
        .and_then(|value| value.checked_add(u64::try_from(slot).ok()?))
        .ok_or(ProtocolLogError::Shape)?;
    let bus_token = compress_trace_bus(trace, slot, row, position, kind, challenges)?;
    push_selected(columns, slot, active, bus_token, LogKind::Bus, challenges)?;
    let input = u64::from(kind == 6 || kind == 13);
    let input_offset = if kind == 13 {
        slot_auxiliary_column(slot)?
    } else {
        slot_value_column(slot)?
    };
    let input_token =
        compress_trace_byte(trace, slot, row, input_offset, LogKind::Input, challenges)?;
    push_selected(
        columns,
        TRACE_BUS_SLOTS + slot,
        input,
        input_token,
        LogKind::Input,
        challenges,
    )?;
    let output_token = compress_trace_byte(
        trace,
        slot,
        row,
        slot_value_column(slot)?,
        LogKind::Output,
        challenges,
    )?;
    push_selected(
        columns,
        TRACE_BUS_SLOTS * 2 + slot,
        u64::from(kind == 7),
        output_token,
        LogKind::Output,
        challenges,
    )
}

fn append_isa_inverse(
    trace: &BlockCpuWitness,
    row: usize,
    row_index: u64,
    lane: usize,
    challenges: LogChallenges,
    columns: &mut [Vec<u64>],
) -> Result<(), ProtocolLogError> {
    let position = row_index
        .checked_mul(PACKED_ISA_LANES as u64)
        .and_then(|value| value.checked_add(u64::try_from(lane).ok()?))
        .ok_or(ProtocolLogError::Shape)?;
    let typed_lane = *PACKED_LANES.get(lane).ok_or(ProtocolLogError::Shape)?;
    let layout = BlockCpuWitness::lane_isa_lookup_columns(typed_lane)
        .map_err(|_| ProtocolLogError::Shape)?;
    let outputs = layout.outputs();
    let token = compress(
        &[
            NativeField::from_u64(position),
            NativeField::from_u64(trace_value(
                trace.columns(),
                *outputs.get(ISA_PACKED_LOW).ok_or(ProtocolLogError::Shape)?,
                row,
            )?),
            NativeField::from_u64(trace_value(
                trace.columns(),
                *outputs
                    .get(ISA_PACKED_HIGH)
                    .ok_or(ProtocolLogError::Shape)?,
                row,
            )?),
        ],
        challenges.mix(LogKind::Isa),
    );
    let active_column = lane_column(lane).ok_or(ProtocolLogError::Shape)?;
    push_selected(
        columns,
        TRACE_BUS_SLOTS * 3 + lane,
        trace_value(trace.columns(), active_column, row)?,
        token,
        LogKind::Isa,
        challenges,
    )
}

fn compress_trace_bus(
    trace: &BlockCpuWitness,
    slot: usize,
    row: usize,
    position: u64,
    kind: u64,
    challenges: LogChallenges,
) -> Result<NativeField, ProtocolLogError> {
    let values = [
        position,
        kind,
        packed_bus_value(trace, slot_address_column(slot)?, row)?,
        packed_bus_value(trace, slot_physical_address_column(slot)?, row)?,
        packed_bus_value(trace, slot_before_column(slot)?, row)?,
        packed_bus_value(trace, slot_auxiliary_column(slot)?, row)?,
        packed_bus_value(trace, slot_value_column(slot)?, row)?,
        packed_bus_value(trace, slot_index_column(slot)?, row)?,
    ]
    .map(NativeField::from_u64);
    Ok(compress(&values, challenges.mix(LogKind::Bus)))
}

fn compress_trace_byte(
    trace: &BlockCpuWitness,
    slot: usize,
    row: usize,
    value_column: usize,
    kind: LogKind,
    challenges: LogChallenges,
) -> Result<NativeField, ProtocolLogError> {
    Ok(compress(
        &[
            NativeField::from_u64(packed_bus_value(trace, slot_index_column(slot)?, row)?),
            NativeField::from_u64(packed_bus_value(trace, value_column, row)?),
        ],
        challenges.mix(kind),
    ))
}

fn packed_bus_kind(
    trace: &BlockCpuWitness,
    slot: usize,
    row: usize,
) -> Result<u64, ProtocolLogError> {
    let mut kind = 0_u64;
    for bit in 0..TRACE_BUS_KIND_BITS {
        kind |= packed_bus_value(trace, slot_kind_bit_column(slot, bit)?, row)? << bit;
    }
    Ok(kind)
}

fn packed_bus_value(
    trace: &BlockCpuWitness,
    relative: usize,
    row: usize,
) -> Result<u64, ProtocolLogError> {
    let column = BLOCK_ISA_CONTROL_COLUMN_COUNT
        .checked_add(relative)
        .ok_or(ProtocolLogError::Shape)?;
    trace_value(trace.columns(), column, row)
}

fn push_selected(
    columns: &mut [Vec<u64>],
    entry: usize,
    selector: u64,
    token: NativeField,
    kind: LogKind,
    challenges: LogChallenges,
) -> Result<(), ProtocolLogError> {
    let inverse = selected_inverse(selector, token, challenges.point(kind))?;
    push_inverse(columns, entry * 2, inverse)
}

fn bus_values(
    bus: &[NativeField],
    slot: usize,
    position: NativeField,
) -> Result<[NativeField; BUS_TOKEN_FIELD_COUNT], UniformError> {
    Ok([
        position,
        packed_kind(bus, slot)?,
        slot_address_value(bus, slot)?,
        slot_physical_address_value(bus, slot)?,
        slot_before_value(bus, slot)?,
        slot_auxiliary_value(bus, slot)?,
        slot_value_value(bus, slot)?,
        slot_index_value(bus, slot)?,
    ])
}

fn bus_kind_bits(
    bus: &[NativeField],
    slot: usize,
) -> Result<[NativeField; TRACE_BUS_KIND_BITS], UniformError> {
    let mut bits = [NativeField::from_u64(0); TRACE_BUS_KIND_BITS];
    for (bit, value) in bits.iter_mut().enumerate() {
        *value = *bus
            .get(slot_kind_bit_column(slot, bit)?)
            .ok_or(UniformError::Shape)?;
    }
    Ok(bits)
}

fn packed_kind(bus: &[NativeField], slot: usize) -> Result<NativeField, UniformError> {
    let mut packed = NativeField::from_u64(0);
    let mut power = NativeField::from_u64(1);
    for bit in bus_kind_bits(bus, slot)? {
        packed += power * bit;
        power += power;
    }
    Ok(packed)
}

fn bit_selector(bits: &[NativeField], code: u8) -> NativeField {
    let one = NativeField::from_u64(1);
    bits.iter()
        .copied()
        .enumerate()
        .fold(one, |selector, (bit, value)| {
            if (code >> bit) & 1 == 1 {
                selector * value
            } else {
                selector * (one - value)
            }
        })
}

fn inverse_at(row: &[NativeField], entry: usize) -> Result<NativeField, UniformError> {
    let start = BLOCK_CPU_COLUMN_COUNT
        .checked_add(entry.checked_mul(2).ok_or(UniformError::Shape)?)
        .ok_or(UniformError::Shape)?;
    Ok(super::join_limbs(
        *row.get(start).ok_or(UniformError::Shape)?,
        *row.get(start + 1).ok_or(UniformError::Shape)?,
    ))
}
