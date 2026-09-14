//! Per-row caches for repeated ISA operation and argument selectors.

use std::cell::Cell;

use super::{RowView, bit_selector};
use crate::{
    ISA_ARGUMENT_ONE_BITS_START, ISA_ARGUMENT_ZERO_BITS_START, ISA_OPERATION_BITS_START,
    NativeField, UniformError,
};

const OPERATION_WIDTH: usize = 6;
const ARGUMENT_ZERO_WIDTH: usize = 3;
const ARGUMENT_ONE_WIDTH: usize = 4;
const OPERATION_SELECTOR_COUNT: usize = 1 << OPERATION_WIDTH;
const ARGUMENT_ZERO_SELECTOR_COUNT: usize = 1 << ARGUMENT_ZERO_WIDTH;
const ARGUMENT_ONE_SELECTOR_COUNT: usize = 1 << ARGUMENT_ONE_WIDTH;

pub(super) struct IsaSelectorCache {
    operation: [Cell<Option<NativeField>>; OPERATION_SELECTOR_COUNT],
    argument_zero: [Cell<Option<NativeField>>; ARGUMENT_ZERO_SELECTOR_COUNT],
    argument_one: [Cell<Option<NativeField>>; ARGUMENT_ONE_SELECTOR_COUNT],
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
