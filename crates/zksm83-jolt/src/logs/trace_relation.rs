use akita_pcs::Ring;
use jolt_field::CanonicalBytes;

use crate::{
    ISA_PACKED_HIGH, ISA_PACKED_LOW, NATIVE_TRACE_COLUMN_COUNT, NativeField, TRACE_ACTIVE,
    TRACE_BEFORE_STATE_START, TRACE_BUS_KIND_BITS, TRACE_BUS_SLOT_WIDTH, TRACE_BUS_SLOTS,
    TRACE_BUS_START, TRACE_ISA_OUTPUT_START, UNIFORM_ROW_COUNT, UniformError, UniformRelation,
    WitnessCommitments,
    uniform::{
        CommittedWitness, CompositeUniformRelationProof, prove_uniform_composite,
        verify_uniform_composite,
    },
};

use super::{
    BUS_ADDRESS_OFFSET, BUS_AUXILIARY_OFFSET, BUS_EVENT_INDEX_OFFSET, BUS_VALUE_OFFSET,
    LogChallenges, LogKind, ProtocolLogError, STATE_BUS_INDEX, STATE_ISA_INDEX,
    TRACE_INVERSE_COLUMN_COUNT, bus_start, compress, push_inverse, selected_inverse, trace_value,
};

pub(super) fn prove(
    trace: &CommittedWitness,
    inverses: &CommittedWitness,
    challenges: LogChallenges,
) -> Result<CompositeUniformRelationProof, ProtocolLogError> {
    let relation = TraceLogRelation { challenges };
    prove_uniform_composite(&relation, trace, inverses).map_err(Into::into)
}

pub(super) fn verify(
    trace: &WitnessCommitments,
    inverses: &WitnessCommitments,
    challenges: LogChallenges,
    proof: &CompositeUniformRelationProof,
) -> Result<(), ProtocolLogError> {
    let relation = TraceLogRelation { challenges };
    verify_uniform_composite(&relation, trace, inverses, proof).map_err(Into::into)
}

struct TraceLogRelation {
    challenges: LogChallenges,
}

impl UniformRelation for TraceLogRelation {
    fn domain(&self) -> &'static [u8] {
        b"zksm83/native-protocol-log-trace-inverses/v1"
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
        bytes
    }

    fn column_count(&self) -> usize {
        NATIVE_TRACE_COLUMN_COUNT + TRACE_INVERSE_COLUMN_COUNT
    }

    fn constraint_count(&self) -> usize {
        super::TRACE_INVERSE_ENTRY_COUNT
    }

    fn max_constraint_degree(&self) -> usize {
        7
    }

    fn evaluate(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        if row.len() != self.column_count() || constraints.len() != self.constraint_count() {
            return Err(UniformError::Shape);
        }
        let mut bus_ordinal = NativeField::from_u64(0);
        for slot in 0..TRACE_BUS_SLOTS {
            self.evaluate_bus_slot(row, constraints, slot, bus_ordinal)?;
            bus_ordinal += bus_field(row, slot, 0)?;
        }
        self.evaluate_isa(row, constraints)
    }
}

impl TraceLogRelation {
    fn evaluate_bus_slot(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
        slot: usize,
        ordinal: NativeField,
    ) -> Result<(), UniformError> {
        let active = bus_field(row, slot, 0)?;
        let kind_bits = bus_kind_bits(row, slot)?;
        let private = bit_selector(&kind_bits, 6);
        let joypad = bit_selector(&kind_bits, 13);
        let input = private + joypad;
        let output = bit_selector(&kind_bits, 7);
        let bus_token = compress(&bus_values(row, slot, ordinal)?, self.mix(LogKind::Bus));
        let input_value = private * bus_field(row, slot, BUS_VALUE_OFFSET)?
            + joypad * bus_field(row, slot, BUS_AUXILIARY_OFFSET)?;
        let input_token = compress(
            &[bus_field(row, slot, BUS_EVENT_INDEX_OFFSET)?, input_value],
            self.mix(LogKind::Input),
        );
        let output_token = compress(
            &[
                bus_field(row, slot, BUS_EVENT_INDEX_OFFSET)?,
                bus_field(row, slot, BUS_VALUE_OFFSET)?,
            ],
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

    fn evaluate_isa(
        &self,
        row: &[NativeField],
        constraints: &mut [NativeField],
    ) -> Result<(), UniformError> {
        let entry = TRACE_BUS_SLOTS * 3;
        let token = compress(
            &[
                state_field(row, STATE_ISA_INDEX)?,
                value(row, TRACE_ISA_OUTPUT_START + ISA_PACKED_LOW)?,
                value(row, TRACE_ISA_OUTPUT_START + ISA_PACKED_HIGH)?,
            ],
            self.mix(LogKind::Isa),
        );
        let inverse = inverse_at(row, entry)?;
        *constraints.get_mut(entry).ok_or(UniformError::Shape)? =
            (self.point(LogKind::Isa) - token) * inverse - value(row, TRACE_ACTIVE)?;
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
    trace: &[Vec<u64>],
    challenges: LogChallenges,
) -> Result<Vec<Vec<u64>>, ProtocolLogError> {
    if trace.len() != NATIVE_TRACE_COLUMN_COUNT {
        return Err(ProtocolLogError::Shape);
    }
    let mut columns = (0..TRACE_INVERSE_COLUMN_COUNT)
        .map(|_| Vec::with_capacity(UNIFORM_ROW_COUNT))
        .collect::<Vec<_>>();
    for row in 0..UNIFORM_ROW_COUNT {
        append_row_inverses(trace, row, challenges, &mut columns)?;
    }
    Ok(columns)
}

fn append_row_inverses(
    trace: &[Vec<u64>],
    row: usize,
    challenges: LogChallenges,
    columns: &mut [Vec<u64>],
) -> Result<(), ProtocolLogError> {
    let mut ordinal = 0_u64;
    for slot in 0..TRACE_BUS_SLOTS {
        let start = bus_start(slot)?;
        let active = trace_value(trace, start, row)?;
        let kind = trace_kind(trace, start, row)?;
        let bus_token = compress_trace_bus(trace, start, row, ordinal, challenges)?;
        push_selected(columns, slot, active, bus_token, LogKind::Bus, challenges)?;
        let (input, input_token) = trace_input(trace, start, row, kind, challenges)?;
        push_selected(
            columns,
            TRACE_BUS_SLOTS + slot,
            input,
            input_token,
            LogKind::Input,
            challenges,
        )?;
        let output = u64::from(kind == 7);
        let output_token = compress_trace_byte(
            trace,
            start,
            row,
            BUS_VALUE_OFFSET,
            LogKind::Output,
            challenges,
        )?;
        push_selected(
            columns,
            TRACE_BUS_SLOTS * 2 + slot,
            output,
            output_token,
            LogKind::Output,
            challenges,
        )?;
        ordinal = ordinal.checked_add(active).ok_or(ProtocolLogError::Shape)?;
    }
    append_isa_inverse(trace, row, challenges, columns)
}

fn append_isa_inverse(
    trace: &[Vec<u64>],
    row: usize,
    challenges: LogChallenges,
    columns: &mut [Vec<u64>],
) -> Result<(), ProtocolLogError> {
    let token = compress(
        &[
            NativeField::from_u64(trace_value(
                trace,
                TRACE_BEFORE_STATE_START + STATE_ISA_INDEX,
                row,
            )?),
            NativeField::from_u64(trace_value(
                trace,
                TRACE_ISA_OUTPUT_START + ISA_PACKED_LOW,
                row,
            )?),
            NativeField::from_u64(trace_value(
                trace,
                TRACE_ISA_OUTPUT_START + ISA_PACKED_HIGH,
                row,
            )?),
        ],
        challenges.mix(LogKind::Isa),
    );
    push_selected(
        columns,
        TRACE_BUS_SLOTS * 3,
        trace_value(trace, TRACE_ACTIVE, row)?,
        token,
        LogKind::Isa,
        challenges,
    )
}

fn compress_trace_bus(
    trace: &[Vec<u64>],
    start: usize,
    row: usize,
    ordinal: u64,
    challenges: LogChallenges,
) -> Result<NativeField, ProtocolLogError> {
    let global = trace_value(trace, TRACE_BEFORE_STATE_START + STATE_BUS_INDEX, row)?
        .checked_add(ordinal)
        .ok_or(ProtocolLogError::Shape)?;
    let kind = trace_kind(trace, start, row)?;
    let mut values = vec![NativeField::from_u64(global), NativeField::from_u64(kind)];
    for offset in BUS_ADDRESS_OFFSET..=BUS_EVENT_INDEX_OFFSET {
        values.push(NativeField::from_u64(trace_value(
            trace,
            start + offset,
            row,
        )?));
    }
    Ok(compress(&values, challenges.mix(LogKind::Bus)))
}

fn trace_input(
    trace: &[Vec<u64>],
    start: usize,
    row: usize,
    kind: u64,
    challenges: LogChallenges,
) -> Result<(u64, NativeField), ProtocolLogError> {
    let selected = u64::from(kind == 6 || kind == 13);
    let value_offset = if kind == 13 {
        BUS_AUXILIARY_OFFSET
    } else {
        BUS_VALUE_OFFSET
    };
    Ok((
        selected,
        compress_trace_byte(trace, start, row, value_offset, LogKind::Input, challenges)?,
    ))
}

fn compress_trace_byte(
    trace: &[Vec<u64>],
    start: usize,
    row: usize,
    value_offset: usize,
    kind: LogKind,
    challenges: LogChallenges,
) -> Result<NativeField, ProtocolLogError> {
    Ok(compress(
        &[
            NativeField::from_u64(trace_value(trace, start + BUS_EVENT_INDEX_OFFSET, row)?),
            NativeField::from_u64(trace_value(trace, start + value_offset, row)?),
        ],
        challenges.mix(kind),
    ))
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
    row: &[NativeField],
    slot: usize,
    ordinal: NativeField,
) -> Result<Vec<NativeField>, UniformError> {
    let mut values = vec![state_field(row, STATE_BUS_INDEX)? + ordinal];
    values.push(packed_kind(row, slot)?);
    for offset in BUS_ADDRESS_OFFSET..=BUS_EVENT_INDEX_OFFSET {
        values.push(bus_field(row, slot, offset)?);
    }
    Ok(values)
}

fn bus_kind_bits(
    row: &[NativeField],
    slot: usize,
) -> Result<[NativeField; TRACE_BUS_KIND_BITS], UniformError> {
    let start = bus_start_uniform(slot)? + 1;
    let mut bits = [NativeField::from_u64(0); TRACE_BUS_KIND_BITS];
    for (offset, bit) in bits.iter_mut().enumerate() {
        *bit = value(row, start + offset)?;
    }
    Ok(bits)
}

fn packed_kind(row: &[NativeField], slot: usize) -> Result<NativeField, UniformError> {
    let mut packed = NativeField::from_u64(0);
    let mut power = NativeField::from_u64(1);
    for bit in bus_kind_bits(row, slot)? {
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
    let start = NATIVE_TRACE_COLUMN_COUNT + entry * 2;
    Ok(super::join_limbs(
        value(row, start)?,
        value(row, start + 1)?,
    ))
}

fn bus_field(row: &[NativeField], slot: usize, offset: usize) -> Result<NativeField, UniformError> {
    value(row, bus_start_uniform(slot)? + offset)
}

fn state_field(row: &[NativeField], scalar: usize) -> Result<NativeField, UniformError> {
    value(row, TRACE_BEFORE_STATE_START + scalar)
}

fn value(row: &[NativeField], index: usize) -> Result<NativeField, UniformError> {
    row.get(index).copied().ok_or(UniformError::Shape)
}

fn bus_start_uniform(slot: usize) -> Result<usize, UniformError> {
    TRACE_BUS_START
        .checked_add(
            slot.checked_mul(TRACE_BUS_SLOT_WIDTH)
                .ok_or(UniformError::Shape)?,
        )
        .ok_or(UniformError::Shape)
}

fn trace_kind(trace: &[Vec<u64>], start: usize, row: usize) -> Result<u64, ProtocolLogError> {
    let mut kind = 0_u64;
    for bit in 0..TRACE_BUS_KIND_BITS {
        kind |= trace_value(trace, start + 1 + bit, row)? << bit;
    }
    Ok(kind)
}
