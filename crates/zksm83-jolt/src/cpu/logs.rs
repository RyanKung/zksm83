//! Ordered cursor identities for bus, ISA, private input, and public output events.

use akita_pcs::Ring;

use super::{
    BUS_ADDRESS_OFFSET, BUS_AUXILIARY_OFFSET, BUS_BEFORE_OFFSET, BUS_INDEX_OFFSET,
    BUS_PHYSICAL_ADDRESS_OFFSET, ConstraintSink, RowView, bit_selector, bus_field, bus_kind_bits,
};
use crate::{NativeField, TRACE_ACTIVE, TRACE_BUS_SLOTS, UniformError};

const STATE_INPUT_INDEX: usize = 16;
const STATE_OUTPUT_INDEX: usize = 17;
const STATE_BUS_INDEX: usize = 18;
const STATE_ISA_INDEX: usize = 19;
const INPUT_PORT: u64 = 0xfff0;
const OUTPUT_PORT: u64 = 0xfff1;

pub(super) fn constrain_cursors_and_log_events(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
) -> Result<(), UniformError> {
    let mut bus_count = NativeField::from_u64(0);
    let mut input_count = NativeField::from_u64(0);
    let mut output_count = NativeField::from_u64(0);
    for slot in 0..TRACE_BUS_SLOTS {
        let active = bus_field(view, slot, 0)?;
        let kinds = bus_kind_bits(view, slot)?;
        let private_input = bit_selector(kinds, 6)?;
        let joypad_input = bit_selector(kinds, 13)?;
        let public_output = bit_selector(kinds, 7)?;
        let input = private_input + joypad_input;
        let index = bus_field(view, slot, BUS_INDEX_OFFSET)?;
        sink.push(input * (index - view.before(STATE_INPUT_INDEX)? - input_count))?;
        sink.push(public_output * (index - view.before(STATE_OUTPUT_INDEX)? - output_count))?;
        constrain_plain_log_tuple(view, sink, slot, private_input, INPUT_PORT)?;
        constrain_plain_log_tuple(view, sink, slot, public_output, OUTPUT_PORT)?;
        bus_count += active;
        input_count += input;
        output_count += public_output;
    }
    sink.push(view.after(STATE_BUS_INDEX)? - view.before(STATE_BUS_INDEX)? - bus_count)?;
    sink.push(
        view.after(STATE_ISA_INDEX)? - view.before(STATE_ISA_INDEX)? - view.value(TRACE_ACTIVE)?,
    )?;
    sink.push(view.after(STATE_INPUT_INDEX)? - view.before(STATE_INPUT_INDEX)? - input_count)?;
    sink.push(view.after(STATE_OUTPUT_INDEX)? - view.before(STATE_OUTPUT_INDEX)? - output_count)
}

fn constrain_plain_log_tuple(
    view: &RowView<'_>,
    sink: &mut ConstraintSink<'_>,
    slot: usize,
    selected: NativeField,
    address: u64,
) -> Result<(), UniformError> {
    sink.push(
        selected * (bus_field(view, slot, BUS_ADDRESS_OFFSET)? - NativeField::from_u64(address)),
    )?;
    for offset in [
        BUS_PHYSICAL_ADDRESS_OFFSET,
        BUS_BEFORE_OFFSET,
        BUS_AUXILIARY_OFFSET,
    ] {
        sink.push(selected * bus_field(view, slot, offset)?)?;
    }
    Ok(())
}
