//! Per-row caches for repeated ISA, bus-kind, and low-address selectors.

use std::cell::{Cell, OnceCell};

use akita_pcs::Ring;

use super::{RowView, bit_selector, bus_kind_bits};
use crate::{
    ISA_ARGUMENT_ONE_BITS_START, ISA_ARGUMENT_ZERO_BITS_START, ISA_OPERATION_BITS_START,
    NativeField, TRACE_BUS_ADDRESS_BITS_START, TRACE_BUS_KIND_BITS, TRACE_BUS_SLOTS, UniformError,
};

const OPERATION_WIDTH: usize = 6;
const ARGUMENT_ZERO_WIDTH: usize = 3;
const ARGUMENT_ONE_WIDTH: usize = 4;
const OPERATION_SELECTOR_COUNT: usize = 1 << OPERATION_WIDTH;
const ARGUMENT_ZERO_SELECTOR_COUNT: usize = 1 << ARGUMENT_ZERO_WIDTH;
const ARGUMENT_ONE_SELECTOR_COUNT: usize = 1 << ARGUMENT_ONE_WIDTH;
const BUS_CACHED_KIND_START: u8 = 8;
const BUS_CACHED_KIND_COUNT: usize = 11;
const BUS_SELECTOR_COUNT: usize = TRACE_BUS_SLOTS * BUS_CACHED_KIND_COUNT;
const LOW_ADDRESS_BIT_COUNT: usize = 8;
const LOW_ADDRESS_SELECTOR_COUNT: usize = 1 << LOW_ADDRESS_BIT_COUNT;

pub(super) struct IsaSelectorCache {
    operation: [Cell<Option<NativeField>>; OPERATION_SELECTOR_COUNT],
    argument_zero: [Cell<Option<NativeField>>; ARGUMENT_ZERO_SELECTOR_COUNT],
    argument_one: [Cell<Option<NativeField>>; ARGUMENT_ONE_SELECTOR_COUNT],
}

pub(super) struct BusSelectorCache {
    entries: [Cell<Option<NativeField>>; BUS_SELECTOR_COUNT],
}

pub(super) struct LowAddressSelectorCache {
    slots: [OnceCell<[NativeField; LOW_ADDRESS_SELECTOR_COUNT]>; TRACE_BUS_SLOTS],
}

impl LowAddressSelectorCache {
    pub(super) fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| OnceCell::new()),
        }
    }

    pub(super) fn select(
        &self,
        view: &RowView<'_>,
        slot: usize,
        expected: u8,
    ) -> Result<NativeField, UniformError> {
        let cache = self.slots.get(slot).ok_or(UniformError::Shape)?;
        if cache.get().is_none() {
            let values = low_address_selectors(view, slot)?;
            cache.set(values).map_err(|_| UniformError::Shape)?;
        }
        cache
            .get()
            .and_then(|values| values.get(usize::from(expected)))
            .copied()
            .ok_or(UniformError::Shape)
    }
}

impl BusSelectorCache {
    pub(super) fn new() -> Self {
        Self {
            entries: std::array::from_fn(|_| Cell::new(None)),
        }
    }

    pub(super) fn select(
        &self,
        view: &RowView<'_>,
        slot: usize,
        code: u8,
    ) -> Result<NativeField, UniformError> {
        if usize::from(code) >= 1 << TRACE_BUS_KIND_BITS {
            return Err(UniformError::Shape);
        }
        let Some(relative_code) = code.checked_sub(BUS_CACHED_KIND_START).map(usize::from) else {
            return direct_bus_selector(view, slot, code);
        };
        if relative_code >= BUS_CACHED_KIND_COUNT {
            return direct_bus_selector(view, slot, code);
        }
        let index = slot
            .checked_mul(BUS_CACHED_KIND_COUNT)
            .and_then(|start| start.checked_add(relative_code))
            .ok_or(UniformError::Shape)?;
        let entry = self.entries.get(index).ok_or(UniformError::Shape)?;
        if let Some(selector) = entry.get() {
            return Ok(selector);
        }
        let selector = direct_bus_selector(view, slot, code)?;
        entry.set(Some(selector));
        Ok(selector)
    }
}

fn direct_bus_selector(
    view: &RowView<'_>,
    slot: usize,
    code: u8,
) -> Result<NativeField, UniformError> {
    match (view.native, view.packed.as_ref()) {
        (Some(_), None) => bit_selector(bus_kind_bits(view, slot)?, code),
        (None, Some(projection)) => projection.bus_kind_selector(slot, code),
        _ => Err(UniformError::Shape),
    }
}

fn low_address_selectors(
    view: &RowView<'_>,
    slot: usize,
) -> Result<[NativeField; LOW_ADDRESS_SELECTOR_COUNT], UniformError> {
    let zero = NativeField::from_u64(0);
    let one = NativeField::from_u64(1);
    let mut selectors = [zero; LOW_ADDRESS_SELECTOR_COUNT];
    *selectors.first_mut().ok_or(UniformError::Shape)? = one;
    let start = TRACE_BUS_ADDRESS_BITS_START
        .checked_add(slot.checked_mul(16).ok_or(UniformError::Shape)?)
        .ok_or(UniformError::Shape)?;
    let mut populated = 1_usize;
    for bit in 0..LOW_ADDRESS_BIT_COUNT {
        let actual = view.value(start.checked_add(bit).ok_or(UniformError::Shape)?)?;
        for index in 0..populated {
            let base = selectors.get(index).copied().ok_or(UniformError::Shape)?;
            *selectors
                .get_mut(index.checked_add(populated).ok_or(UniformError::Shape)?)
                .ok_or(UniformError::Shape)? = base * actual;
            *selectors.get_mut(index).ok_or(UniformError::Shape)? = base * (one - actual);
        }
        populated = populated.checked_mul(2).ok_or(UniformError::Shape)?;
    }
    if populated != LOW_ADDRESS_SELECTOR_COUNT {
        return Err(UniformError::Shape);
    }
    Ok(selectors)
}

impl IsaSelectorCache {
    pub(super) fn new() -> Self {
        Self {
            operation: std::array::from_fn(|_| Cell::new(None)),
            argument_zero: std::array::from_fn(|_| Cell::new(None)),
            argument_one: std::array::from_fn(|_| Cell::new(None)),
        }
    }

    fn entries(&self, start: usize, width: usize) -> Option<&[Cell<Option<NativeField>>]> {
        match (start, width) {
            (ISA_OPERATION_BITS_START, OPERATION_WIDTH) => Some(&self.operation),
            (ISA_ARGUMENT_ZERO_BITS_START, ARGUMENT_ZERO_WIDTH) => Some(&self.argument_zero),
            (ISA_ARGUMENT_ONE_BITS_START, ARGUMENT_ONE_WIDTH) => Some(&self.argument_one),
            _ => None,
        }
    }

    fn select(
        &self,
        view: &RowView<'_>,
        start: usize,
        width: usize,
        code: u8,
    ) -> Result<NativeField, UniformError> {
        let Some(entry) = self
            .entries(start, width)
            .and_then(|entries| entries.get(usize::from(code)))
        else {
            return bit_selector(view.isa_values(start, width)?, code);
        };
        if let Some(selector) = entry.get() {
            return Ok(selector);
        }
        let selector = bit_selector(view.isa_values(start, width)?, code)?;
        entry.set(Some(selector));
        Ok(selector)
    }
}

pub(super) fn operation_selector(
    view: &RowView<'_>,
    code: u8,
) -> Result<NativeField, UniformError> {
    view.selectors
        .select(view, ISA_OPERATION_BITS_START, OPERATION_WIDTH, code)
}

pub(super) fn argument_selector(
    view: &RowView<'_>,
    start: usize,
    width: usize,
    code: u8,
) -> Result<NativeField, UniformError> {
    view.selectors.select(view, start, width, code)
}

#[cfg(test)]
mod tests {
    use akita_pcs::Ring;

    use super::*;
    use crate::NATIVE_TRACE_COLUMN_COUNT;

    #[test]
    fn cached_families_match_direct_selectors() -> Result<(), UniformError> {
        let row = (0..NATIVE_TRACE_COLUMN_COUNT)
            .map(|index| NativeField::from_u64((index & 1) as u64))
            .collect::<Vec<_>>();
        let view = RowView::new(&row);

        assert_family(
            &view,
            ISA_OPERATION_BITS_START,
            OPERATION_WIDTH,
            OPERATION_SELECTOR_COUNT,
        )?;
        assert_family(
            &view,
            ISA_ARGUMENT_ZERO_BITS_START,
            ARGUMENT_ZERO_WIDTH,
            ARGUMENT_ZERO_SELECTOR_COUNT,
        )?;
        assert_family(
            &view,
            ISA_ARGUMENT_ONE_BITS_START,
            ARGUMENT_ONE_WIDTH,
            ARGUMENT_ONE_SELECTOR_COUNT,
        )
    }

    fn assert_family(
        view: &RowView<'_>,
        start: usize,
        width: usize,
        count: usize,
    ) -> Result<(), UniformError> {
        for code in 0..count {
            let code = u8::try_from(code).map_err(|_| UniformError::Shape)?;
            let cached = view.selectors.select(view, start, width, code)?;
            let direct = bit_selector(view.isa_values(start, width)?, code)?;
            assert_eq!(cached, direct);
        }
        Ok(())
    }
}
