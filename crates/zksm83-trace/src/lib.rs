#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Validated, contiguous SM83 execution witnesses.

mod builder;
mod lookup_builder;
mod model;

pub use builder::{TraceBuilder, TraceBuilderError};
pub use lookup_builder::{LookupTraceBuilder, LookupTraceBuilderError};
pub use model::{
    BLUE_ROM_BLOCK_MAX_EVENTS, BLUE_ROM_BLOCK_MAX_INSTRUCTIONS, BLUE_ROM_BLOCK_MAX_M_CYCLES,
    BlueRomBlockCost, ExecutionBoundary, ExecutionMetrics, ProgramCounterCount,
    ProgramCounterProfile, TraceChunk, TraceError, TraceRow, Witness, blue_rom_block_candidate,
    blue_rom_block_cost,
};
