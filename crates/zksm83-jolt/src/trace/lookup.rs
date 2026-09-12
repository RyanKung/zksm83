use crate::{
    IsaLookupColumns, IsaLookupError, ROM_ADDRESS_BIT_COUNT, RomLookupColumns, RomLookupError,
    TRACE_BUS_PHYSICAL_BITS_START, TRACE_ISA_ADDRESS_START, TRACE_ISA_OUTPUT_START,
    TRACE_ROM_SELECTOR_START, TRACE_ROM_VALUE_START,
};

pub(crate) fn canonical_isa_lookup_columns() -> Result<IsaLookupColumns, IsaLookupError> {
    let address_bits = std::array::from_fn(|index| TRACE_ISA_ADDRESS_START + index);
    let outputs = std::array::from_fn(|index| TRACE_ISA_OUTPUT_START + index);
    IsaLookupColumns::new(address_bits, outputs)
}

pub(crate) fn canonical_rom_lookup_columns() -> Result<RomLookupColumns, RomLookupError> {
    let selectors = std::array::from_fn(|slot| TRACE_ROM_SELECTOR_START + slot);
    let values = std::array::from_fn(|slot| TRACE_ROM_VALUE_START + slot);
    let address_bits = std::array::from_fn(|slot| {
        std::array::from_fn(|bit| {
            TRACE_BUS_PHYSICAL_BITS_START + slot * ROM_ADDRESS_BIT_COUNT + bit
        })
    });
    RomLookupColumns::new(selectors, address_bits, values)
}
