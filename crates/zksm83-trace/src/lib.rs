#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Validated, contiguous SM83 execution witnesses.

mod block;
mod builder;
mod execution_lookup;
mod lookup_builder;
mod model;

pub use block::{
    BASIC_BLOCK_BUS_EVENT_BOUND, BASIC_BLOCK_INSTRUCTION_BOUND, BASIC_BLOCK_M_CYCLE_BOUND,
    BasicBlock, BasicBlockCut, BasicBlockLane, BasicBlockLaneDescriptor, BasicBlockLaneIndex,
    BasicBlockPlanError, BasicBlockResourceOwner, BasicBlockSpan, pack_witness_basic_blocks,
    pack_witness_basic_blocks_at, plan_basic_blocks, plan_witness_basic_blocks,
};
pub use builder::{TraceBuilder, TraceBuilderError};
pub use execution_lookup::{
    InstructionLookupRecord, InstructionLookupRecordError, InstructionLookupRecords,
};
pub use lookup_builder::{LookupTraceBuilder, LookupTraceBuilderError};
pub use model::{
    ExecutionBoundary, ExecutionMetrics, ProgramCounterCount, ProgramCounterProfile, TraceChunk,
    TraceError, TraceRow, Witness,
};
