//! Private bus-event columns linked to public event kinds and VM root endpoints.

use halo2_proofs::{
    circuit::{AssignedCell, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::Fp;
use zksm83_core::BusEvent;
use zksm83_trace::TraceRow;

use crate::{
    shape::{BusEventKind, EVENT_SLOTS, ShapeConfig},
    state::StateTraceConfig,
};

#[derive(Clone, Copy, Debug)]
pub(crate) struct EventColumns {
    pub(crate) address: Column<Advice>,
    pub(crate) value: Column<Advice>,
    pub(crate) before: Column<Advice>,
    pub(crate) index: Column<Advice>,
}

impl EventColumns {
    fn create(meta: &mut ConstraintSystem<Fp>) -> Self {
        let columns = Self {
            address: meta.advice_column(),
            value: meta.advice_column(),
            before: meta.advice_column(),
            index: meta.advice_column(),
        };
        for column in [
            columns.address,
            columns.value,
            columns.before,
            columns.index,
        ] {
            meta.enable_equality(column);
        }
        columns
    }
}

#[derive(Clone, Debug)]
pub(crate) struct BusConfig {
    pub(crate) events: [EventColumns; EVENT_SLOTS],
    memory_before: Column<Advice>,
    memory_after: Column<Advice>,
    input_before: Column<Advice>,
    input_after: Column<Advice>,
    output_before: Column<Advice>,
    output_after: Column<Advice>,
    q_row: Selector,
}

pub(crate) struct AssignedEvent {
    pub(crate) address: AssignedCell<Fp, Fp>,
    pub(crate) value: AssignedCell<Fp, Fp>,
    pub(crate) before: AssignedCell<Fp, Fp>,
    pub(crate) index: AssignedCell<Fp, Fp>,
}

pub(crate) struct AssignedBusRow {
    pub(crate) events: Vec<AssignedEvent>,
    pub(crate) memory_before: AssignedCell<Fp, Fp>,
    pub(crate) memory_after: AssignedCell<Fp, Fp>,
    pub(crate) input_before: AssignedCell<Fp, Fp>,
    pub(crate) input_after: AssignedCell<Fp, Fp>,
    pub(crate) output_before: AssignedCell<Fp, Fp>,
    pub(crate) output_after: AssignedCell<Fp, Fp>,
}

impl BusConfig {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<Fp>,
        shape: &ShapeConfig,
        state: &StateTraceConfig,
    ) -> Self {
        let events = std::array::from_fn(|_| EventColumns::create(meta));
        let memory_before = meta.advice_column();
        let memory_after = meta.advice_column();
        let input_before = meta.advice_column();
        let input_after = meta.advice_column();
        let output_before = meta.advice_column();
        let output_after = meta.advice_column();
        for column in [
            memory_before,
            memory_after,
            input_before,
            input_after,
            output_before,
            output_after,
        ] {
            meta.enable_equality(column);
        }
        let q_row = meta.selector();
        configure_bus_gate(
            meta,
            q_row,
            shape,
            state,
            events,
            [
                memory_before,
                memory_after,
                input_before,
                input_after,
                output_before,
                output_after,
            ],
        );
        for event in events {
            for column in [event.value, event.before] {
                meta.lookup(|meta| {
                    let value = meta.query_advice(column, Rotation::cur());
                    vec![(value, state.byte_table)]
                });
            }
        }
        Self {
            events,
            memory_before,
            memory_after,
            input_before,
            input_after,
            output_before,
            output_after,
            q_row,
        }
    }

    pub(crate) fn assign_row(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        row: Option<&TraceRow>,
    ) -> Result<AssignedBusRow, Error> {
        self.q_row.enable(region, offset)?;
        let event_values = row.map(|trace| trace.effects().bus_events().collect::<Vec<_>>());
        let mut assigned = Vec::with_capacity(EVENT_SLOTS);
        for (slot, columns) in self.events.iter().enumerate() {
            let event = event_values
                .as_ref()
                .and_then(|values| values.get(slot).copied());
            assigned.push(assign_event(
                region,
                offset,
                *columns,
                event,
                row.is_some(),
            )?);
        }
        let before = row.map(TraceRow::before);
        let after = row.map(TraceRow::after);
        let memory_before = assign_root(
            region,
            self.memory_before,
            offset,
            before.map(|state| state.memory_root().field()),
        )?;
        let memory_after = assign_root(
            region,
            self.memory_after,
            offset,
            after.map(|state| state.memory_root().field()),
        )?;
        let input_before = assign_root(
            region,
            self.input_before,
            offset,
            before.map(|state| state.input_log().root().field()),
        )?;
        let input_after = assign_root(
            region,
            self.input_after,
            offset,
            after.map(|state| state.input_log().root().field()),
        )?;
        let output_before = assign_root(
            region,
            self.output_before,
            offset,
            before.map(|state| state.output_log().root().field()),
        )?;
        let output_after = assign_root(
            region,
            self.output_after,
            offset,
            after.map(|state| state.output_log().root().field()),
        )?;
        Ok(AssignedBusRow {
            events: assigned,
            memory_before,
            memory_after,
            input_before,
            input_after,
            output_before,
            output_after,
        })
    }
}

fn assign_root(
    region: &mut Region<'_, Fp>,
    column: Column<Advice>,
    offset: usize,
    value: Option<Fp>,
) -> Result<AssignedCell<Fp, Fp>, Error> {
    region.assign_advice(
        || "bus root endpoint",
        column,
        offset,
        || value.map_or(Value::unknown(), Value::known),
    )
}

fn assign_event(
    region: &mut Region<'_, Fp>,
    offset: usize,
    columns: EventColumns,
    event: Option<&BusEvent>,
    witness_present: bool,
) -> Result<AssignedEvent, Error> {
    let values = event.map(EventValues::from_event).or_else(|| {
        witness_present.then_some(EventValues {
            address: 0,
            value: 0,
            before: 0,
            index: 0,
        })
    });
    let address = region.assign_advice(
        || "bus address",
        columns.address,
        offset,
        || optional_value(values, |event| Fp::from(u64::from(event.address))),
    )?;
    let value = region.assign_advice(
        || "bus value",
        columns.value,
        offset,
        || optional_value(values, |event| Fp::from(u64::from(event.value))),
    )?;
    let before = region.assign_advice(
        || "bus before value",
        columns.before,
        offset,
        || optional_value(values, |event| Fp::from(u64::from(event.before))),
    )?;
    let index = region.assign_advice(
        || "bus log index",
        columns.index,
        offset,
        || optional_value(values, |event| Fp::from(event.index)),
    )?;
    Ok(AssignedEvent {
        address,
        value,
        before,
        index,
    })
}

fn optional_value(
    values: Option<EventValues>,
    convert: impl FnOnce(EventValues) -> Fp,
) -> Value<Fp> {
    values.map_or(Value::unknown(), |event| Value::known(convert(event)))
}

#[derive(Clone, Copy)]
struct EventValues {
    address: u16,
    value: u8,
    before: u8,
    index: u64,
}

impl EventValues {
    const fn from_event(event: &BusEvent) -> Self {
        match event {
            BusEvent::OpcodeFetch(read)
            | BusEvent::ImmediateRead(read)
            | BusEvent::RomRead(read) => Self::read(read.address, read.value),
            BusEvent::MemoryOpcodeFetch(read)
            | BusEvent::MemoryImmediateRead(read)
            | BusEvent::MemoryRead(read)
            | BusEvent::DmgDmaMemoryRead(read) => Self::read(read.address, read.value),
            BusEvent::DmgDmaRomRead(read) => Self::read(read.address, read.value),
            BusEvent::MemoryWrite(write) | BusEvent::DmgDmaWrite(write) => Self {
                address: write.address,
                value: write.after,
                before: write.before,
                index: 0,
            },
            BusEvent::InputRead { index, value } => Self {
                address: 0xfff0,
                value: *value,
                before: *value,
                index: *index,
            },
            BusEvent::OutputWrite { index, value } => Self {
                address: 0xfff1,
                value: *value,
                before: *value,
                index: *index,
            },
            BusEvent::Mbc3ControlWrite { address, value }
            | BusEvent::Mbc3OpenBusRead { address, value }
            | BusEvent::Mbc3IgnoredWrite { address, value } => Self {
                address: *address,
                value: *value,
                before: 0,
                index: 0,
            },
            BusEvent::DmgMmioRead { address, value } => Self::read(*address, *value),
            BusEvent::DmgMmioWrite {
                address,
                before,
                value,
            } => Self {
                address: *address,
                value: *value,
                before: *before,
                index: 0,
            },
            BusEvent::DmgJoypadRead { index, value, .. } => Self {
                address: 0xff00,
                value: *value,
                before: *value,
                index: *index,
            },
        }
    }

    const fn read(address: u16, value: u8) -> Self {
        Self {
            address,
            value,
            before: value,
            index: 0,
        }
    }
}

fn configure_bus_gate(
    meta: &mut ConstraintSystem<Fp>,
    selector: Selector,
    shape: &ShapeConfig,
    state: &StateTraceConfig,
    events: [EventColumns; EVENT_SLOTS],
    roots: [Column<Advice>; 6],
) {
    meta.create_gate("typed bus values and state root endpoints", |meta| {
        let enabled = meta.query_selector(selector);
        let mut constraints = root_constraints(meta, enabled.clone(), state, roots);
        let before_input_index = meta.query_advice(state.before.input_index, Rotation::cur());
        let after_input_index = meta.query_advice(state.after.input_index, Rotation::cur());
        let before_output_index = meta.query_advice(state.before.output_index, Rotation::cur());
        let after_output_index = meta.query_advice(state.after.output_index, Rotation::cur());
        let mut input_seen = Expression::Constant(Fp::zero());
        let mut output_seen = Expression::Constant(Fp::zero());
        for (slot, columns) in events.iter().enumerate() {
            let Some(kind_columns) = shape.event_kinds.get(slot) else {
                continue;
            };
            let address = meta.query_advice(columns.address, Rotation::cur());
            let value = meta.query_advice(columns.value, Rotation::cur());
            let before = meta.query_advice(columns.before, Rotation::cur());
            let index = meta.query_advice(columns.index, Rotation::cur());
            let unused = query_kind(meta, kind_columns, BusEventKind::Unused);
            let input = query_kind(meta, kind_columns, BusEventKind::InputRead);
            let output = query_kind(meta, kind_columns, BusEventKind::OutputWrite);
            let read = query_kind(meta, kind_columns, BusEventKind::OpcodeFetch)
                + query_kind(meta, kind_columns, BusEventKind::ImmediateRead)
                + query_kind(meta, kind_columns, BusEventKind::RomRead)
                + query_kind(meta, kind_columns, BusEventKind::MemoryRead)
                + input.clone()
                + output.clone();
            constraints.extend([
                enabled.clone() * unused.clone() * address.clone(),
                enabled.clone() * unused.clone() * value.clone(),
                enabled.clone() * unused.clone() * before.clone(),
                enabled.clone() * unused * index.clone(),
                enabled.clone() * read * (before - value),
                enabled.clone()
                    * input.clone()
                    * (address.clone() - Expression::Constant(Fp::from(0xfff0))),
                enabled.clone()
                    * output.clone()
                    * (address - Expression::Constant(Fp::from(0xfff1))),
                enabled.clone()
                    * input.clone()
                    * (index.clone() - before_input_index.clone() - input_seen.clone()),
                enabled.clone()
                    * output.clone()
                    * (index - before_output_index.clone() - output_seen.clone()),
            ]);
            input_seen = input_seen + input;
            output_seen = output_seen + output;
        }
        constraints.push(enabled.clone() * (after_input_index - before_input_index - input_seen));
        constraints.push(enabled * (after_output_index - before_output_index - output_seen));
        constraints
    });
}

fn root_constraints(
    meta: &mut halo2_proofs::plonk::VirtualCells<'_, Fp>,
    enabled: Expression<Fp>,
    state: &StateTraceConfig,
    roots: [Column<Advice>; 6],
) -> Vec<Expression<Fp>> {
    let [
        memory_before,
        memory_after,
        input_before,
        input_after,
        output_before,
        output_after,
    ] = roots;
    [
        (memory_before, state.before.memory_root),
        (memory_after, state.after.memory_root),
        (input_before, state.before.input_root),
        (input_after, state.after.input_root),
        (output_before, state.before.output_root),
        (output_after, state.after.output_root),
    ]
    .into_iter()
    .map(|(bus, state)| {
        enabled.clone()
            * (meta.query_advice(bus, Rotation::cur()) - meta.query_advice(state, Rotation::cur()))
    })
    .collect()
}

fn query_kind(
    meta: &mut halo2_proofs::plonk::VirtualCells<'_, Fp>,
    columns: &[Column<halo2_proofs::plonk::Fixed>; 8],
    kind: BusEventKind,
) -> Expression<Fp> {
    columns
        .get(kind.index())
        .map_or(Expression::Constant(Fp::zero()), |column| {
            meta.query_fixed(*column)
        })
}
