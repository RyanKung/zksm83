#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Pure SM83 CPU and VM state transitions for the clean machine profile.

mod alu;
mod bus;
mod dmg;
mod execute;
mod execution_lookup;
mod mbc3;
mod state;
mod transition;

pub use bus::{
    BusEvent, BusEventKind, BusEventKindError, BusRole, BusWitness, StepEffects, StepInput,
    StepKind, WitnessKind, WitnessRequest,
};
pub use dmg::{DmgApuState, DmgDeviceState, DmgInterrupt, DmgTimerState, apu_read_mask};
pub use execution_lookup::{
    ExecutionLookupError, ExecutionLookupOutput, ExecutionLookupQuery,
    evaluate_execution_table_entry,
};
pub use mbc3::{
    Mbc3CartridgeProfile, Mbc3ExternalWindow, Mbc3RomSize, Mbc3RtcMode, Mbc3State, Mbc3StateError,
};
pub use state::{
    CpuState, Flags, ImeState, MachineContext, MachineProfile, Registers, RunState, VmState,
    VmStateError,
};
pub use transition::{LookupStepRelation, StepError, StepRelation};
