//! Pure one-instruction transition orchestration.

use thiserror::Error;
use zksm83_isa::{
    AlignmentPackingError, OpcodeClassification, Operation, decode_cb, decode_primary,
};
use zksm83_memory::{
    BusTranscriptError, IsaTranscriptError, LogError, MemoryTranscriptError, RomReadError,
};

use crate::{
    BusRole, DmgInterrupt, ImeState, MachineProfile, RunState, StepEffects, StepInput, StepKind,
    VmState, VmStateError, WitnessKind, WitnessRequest,
    bus::{BusAuthentication, Executor},
    execute::{ImmediateBytes, execute},
};

/// Pure SM83 step relation shared by every supported machine profile.
#[derive(Clone, Copy, Debug, Default)]
pub struct StepRelation;

impl StepRelation {
    /// Applies one instruction transition to a value state and exact witness input.
    pub fn apply(state: VmState, input: StepInput) -> Result<(VmState, StepEffects), StepError> {
        apply(state, input, BusAuthentication::Merkle)
    }
}

/// Lookup-backed SM83 transition used only inside a proof system that
/// independently authenticates the supplied ROM and mutable-memory accesses.
#[derive(Clone, Copy, Debug, Default)]
pub struct LookupStepRelation;

impl LookupStepRelation {
    /// Applies one transition while preserving the external memory-root anchor.
    /// Address mapping, values, CPU/device semantics, and ordered effects remain
    /// checked; the enclosing lookup-memory proof must authenticate the bytes.
    pub fn apply(state: VmState, input: StepInput) -> Result<(VmState, StepEffects), StepError> {
        apply(state, input, BusAuthentication::Lookup)
    }
}

fn apply(
    state: VmState,
    input: StepInput,
    authentication: BusAuthentication,
) -> Result<(VmState, StepEffects), StepError> {
    if state.profile() == MachineProfile::DmgPostBootMbc3V1 {
        if state.dmg_devices().dma_owed() != 0 {
            return dma_byte(state, input, authentication);
        }
        match classify_dmg_machine_event(state)? {
            Some(DmgMachineEvent::Interrupt(interrupt)) => {
                return dispatch_interrupt(state, input, interrupt, authentication);
            }
            Some(DmgMachineEvent::HaltWake) => {
                return halt_wake(state, input, authentication);
            }
            Some(DmgMachineEvent::HaltUntilVBlank(increment)) => {
                return halt_until_vblank(state, input, increment, authentication);
            }
            Some(DmgMachineEvent::HaltUntilSerial(increment)) => {
                return halt_until_serial(state, input, increment, authentication);
            }
            Some(DmgMachineEvent::HaltUntilTimer(increment)) => {
                return halt_until_timer(state, input, increment, authentication);
            }
            Some(DmgMachineEvent::HaltIdle) => {
                return halt_idle(state, input, authentication);
            }
            None => {}
        }
    }
    if !state.cpu().run_state().can_execute_instruction() {
        return Err(StepError::CpuNotRunning {
            state: state.cpu().run_state(),
        });
    }
    let enable_after_step = state.cpu().ime() == ImeState::EnablePending;
    let dma_active_at_start = state.dmg_devices().dma_active();
    let halt_bug_fetch = state.cpu().run_state() == RunState::HaltBug;
    let mut executor = Executor::new(state, input, authentication);
    let opcode = fetch_first_opcode(&mut executor, halt_bug_fetch)?;
    let (instruction, immediate) = if opcode == 0xcb {
        let secondary = fetch_and_advance(&mut executor, BusRole::OpcodeFetch)?;
        (decode_cb(secondary), ImmediateBytes::default())
    } else {
        let instruction = match decode_primary(opcode) {
            OpcodeClassification::Defined(instruction) => instruction,
            OpcodeClassification::Undefined(undefined) => {
                return Err(StepError::UndefinedOpcode {
                    opcode: undefined.byte,
                });
            }
        };
        let immediate = fetch_immediates(&mut executor, instruction.byte_len())?;
        (instruction, immediate)
    };
    let branch_taken = execute(&mut executor, instruction, immediate)?;
    apply_delayed_ime(&mut executor, instruction.operation(), enable_after_step);
    add_timing(
        &mut executor,
        instruction,
        branch_taken,
        dma_active_at_start,
    )?;
    if instruction.operation() == Operation::Halt
        && state.cpu().ime() != ImeState::Enabled
        && state.dmg_devices().pending_interrupt().is_some()
    {
        executor
            .state_mut()
            .cpu_mut()
            .set_run_state(RunState::HaltBug);
    }
    executor.finish(instruction, branch_taken)
}

/// Algebraic failure of the pure transition relation.
#[derive(Debug, Error)]
pub enum StepError {
    /// HALT or STOP has no wake transition in the v1 machine profile.
    #[error("CPU is not running: {state:?}")]
    CpuNotRunning {
        /// Terminal CPU state.
        state: RunState,
    },
    /// The next required witness is absent.
    #[error("missing witness for {request:?}")]
    MissingWitness {
        /// Exact relation request.
        request: WitnessRequest,
    },
    /// A witness appears at the wrong semantic position.
    #[error("expected witness for {request:?}, got {actual:?}")]
    UnexpectedWitness {
        /// Exact relation request.
        request: WitnessRequest,
        /// Supplied witness kind.
        actual: WitnessKind,
    },
    /// The witness enum disagreed with its already-checked kind.
    #[error("witness kind check violated its internal invariant")]
    WitnessKindInvariant,
    /// A bus witness authenticates a different address.
    #[error("{role:?} address mismatch: expected 0x{expected:04x}, got 0x{actual:04x}")]
    AddressMismatch {
        /// Semantic bus role.
        role: BusRole,
        /// CPU-derived address.
        expected: u16,
        /// Witness address.
        actual: u16,
    },
    /// A bus witness authenticates a different physical cartridge or memory byte.
    #[error("{role:?} physical address mismatch: expected 0x{expected:05x}, got 0x{actual:05x}")]
    PhysicalAddressMismatch {
        /// Semantic bus role.
        role: BusRole,
        /// Mapper-derived physical byte index.
        expected: u32,
        /// Witness physical byte index.
        actual: u32,
    },
    /// A write witness contains a different new byte.
    #[error("memory write value mismatch: expected 0x{expected:02x}, got 0x{actual:02x}")]
    WriteValueMismatch {
        /// CPU-derived byte.
        expected: u8,
        /// Witness byte.
        actual: u8,
    },
    /// One or more witnesses were not caused by the instruction.
    #[error("step supplied {remaining} surplus witnesses")]
    SurplusWitnesses {
        /// Unconsumed witness count.
        remaining: usize,
    },
    /// Immutable ROM authentication failed.
    #[error(transparent)]
    RomAuthentication(#[from] RomReadError),
    /// Mutable-memory authentication failed.
    #[error(transparent)]
    MemoryAuthentication(#[from] MemoryTranscriptError),
    /// Ordered input or output commitment could not advance.
    #[error(transparent)]
    LogCommitment(#[from] LogError),
    /// Ordered proof-relation bus transcript could not advance.
    #[error(transparent)]
    BusTranscriptCommitment(#[from] BusTranscriptError),
    /// Ordered proof-relation ISA transcript could not advance.
    #[error(transparent)]
    IsaTranscriptCommitment(#[from] IsaTranscriptError),
    /// A decoded instruction exceeded the fixed ISA-row bit allocation.
    #[error(transparent)]
    AlignmentPacking(#[from] AlignmentPackingError),
    /// A validated VM state invariant failed.
    #[error(transparent)]
    InvalidState(#[from] VmStateError),
    /// Undefined primary opcode has no transition.
    #[error("undefined SM83 primary opcode 0x{opcode:02x}")]
    UndefinedOpcode {
        /// Rejected opcode byte.
        opcode: u8,
    },
    /// ROM fetch metadata requested more than two immediate bytes.
    #[error("decoded instruction metadata exceeds the two-byte immediate bound")]
    InstructionMetadataInvariant,
    /// An operation requested an immediate byte absent from its metadata.
    #[error("instruction semantic relation requires a missing immediate byte")]
    MissingImmediateByte,
    /// The STOP padding byte is not the declared zero value.
    #[error("STOP padding byte must be zero, got 0x{value:02x}")]
    InvalidStopPadding {
        /// Rejected padding byte.
        value: u8,
    },
    /// The primary CB marker reached semantic execution without secondary dispatch.
    #[error("CB prefix reached execution without secondary-opcode dispatch")]
    UndispatchedCbPrefix,
    /// Mutable writes to ROM are outside the profile.
    #[error("write to immutable ROM address 0x{address:04x}")]
    WriteToRom {
        /// Rejected address.
        address: u16,
    },
    /// The input port is read-only.
    #[error("write to read-only input port")]
    WriteToInputPort,
    /// The output port is write-only.
    #[error("read from write-only output port")]
    ReadFromOutputPort,
    /// A read targeted an address with no declared owner.
    #[error("read from unowned address 0x{address:04x}")]
    UnownedRead {
        /// Rejected address.
        address: u16,
    },
    /// Instruction fetch targeted a non-executable device or unowned address.
    #[error("instruction fetch from non-executable address 0x{address:04x}")]
    UnownedInstructionFetch {
        /// Rejected program-counter address.
        address: u16,
    },
    /// A write targeted an address with no declared owner.
    #[error("write to unowned address 0x{address:04x}")]
    UnownedWrite {
        /// Rejected address.
        address: u16,
    },
    /// A DMG MMIO register was reached before its typed device relation exists.
    #[error("DMG MMIO register 0x{address:04x} is not implemented yet")]
    DmgMmioUnavailable {
        /// Rejected device-register address.
        address: u16,
    },
    /// DMG CPU attempted to use a non-HRAM bus while OAM DMA owned it.
    #[error("CPU address 0x{address:04x} is unavailable during DMG OAM DMA")]
    DmgDmaCpuBusUnavailable {
        /// Rejected CPU bus address.
        address: u16,
    },
    /// OAM DMA selected a source not modeled by the MBC3 DMG profile.
    #[error("OAM DMA source address 0x{address:04x} is unavailable")]
    DmgDmaSourceUnavailable {
        /// Rejected DMA source address.
        address: u16,
    },
    /// DMG CPU attempted a VRAM/OAM access while the LCD controller owned that region.
    #[error("CPU video-memory address 0x{address:04x} is unavailable in the current PPU mode")]
    DmgPpuCpuBusUnavailable {
        /// Rejected CPU address.
        address: u16,
    },
    /// DMG echo RAM was reached before its alias relation exists.
    #[error("DMG echo-RAM address 0x{address:04x} is not implemented yet")]
    DmgEchoUnavailable {
        /// Rejected aliased address.
        address: u16,
    },
    /// The checked total M-cycle counter overflowed.
    #[error("M-cycle counter overflow")]
    CycleCountOverflow,
    /// A fixed synthetic instruction used to label a machine event was absent.
    #[error("internal DMG machine-event instruction marker is unavailable")]
    MachineEventMarkerInvariant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DmgMachineEvent {
    Interrupt(DmgInterrupt),
    HaltWake,
    HaltUntilVBlank(u16),
    HaltUntilSerial(u16),
    HaltUntilTimer(u32),
    HaltIdle,
}

fn classify_dmg_machine_event(state: VmState) -> Result<Option<DmgMachineEvent>, StepError> {
    let pending = state.dmg_devices().pending_interrupt();
    match state.cpu().run_state() {
        RunState::Stopped => Err(StepError::CpuNotRunning {
            state: RunState::Stopped,
        }),
        RunState::Running | RunState::HaltBug if state.cpu().ime() == ImeState::Enabled => {
            Ok(pending.map(DmgMachineEvent::Interrupt))
        }
        RunState::Running | RunState::HaltBug => Ok(None),
        RunState::Halted => match pending {
            Some(interrupt) if state.cpu().ime() == ImeState::Enabled => {
                Ok(Some(DmgMachineEvent::Interrupt(interrupt)))
            }
            Some(_) => Ok(Some(DmgMachineEvent::HaltWake)),
            None => {
                let devices = state.dmg_devices();
                let event = if let Some(increment) = devices.halt_until_vblank_m_cycles() {
                    DmgMachineEvent::HaltUntilVBlank(increment)
                } else if let Some(increment) = devices.halt_until_serial_m_cycles() {
                    DmgMachineEvent::HaltUntilSerial(increment)
                } else if let Some(increment) = devices.halt_until_timer_m_cycles() {
                    DmgMachineEvent::HaltUntilTimer(increment)
                } else {
                    DmgMachineEvent::HaltIdle
                };
                Ok(Some(event))
            }
        },
    }
}

fn dispatch_interrupt(
    state: VmState,
    input: StepInput,
    interrupt: DmgInterrupt,
    authentication: BusAuthentication,
) -> Result<(VmState, StepEffects), StepError> {
    let mut executor = Executor::new(state, input, authentication);
    executor
        .state_mut()
        .cpu_mut()
        .set_run_state(RunState::Running);
    executor.state_mut().cpu_mut().set_ime(ImeState::Disabled);
    executor
        .state_mut()
        .dmg_devices_mut()
        .acknowledge_interrupt(interrupt);
    let return_address = executor.state().cpu().pc();
    push_interrupt_return(&mut executor, return_address)?;
    executor.state_mut().cpu_mut().set_pc(interrupt.vector());
    add_machine_timing(&mut executor, 5)?;
    executor.finish_machine(
        StepKind::InterruptDispatch(interrupt),
        machine_event_marker(0xff)?,
    )
}

fn halt_wake(
    state: VmState,
    input: StepInput,
    authentication: BusAuthentication,
) -> Result<(VmState, StepEffects), StepError> {
    let mut executor = Executor::new(state, input, authentication);
    executor
        .state_mut()
        .cpu_mut()
        .set_run_state(RunState::Running);
    executor.finish_machine(StepKind::HaltWake, machine_event_marker(0x76)?)
}

fn halt_until_vblank(
    state: VmState,
    input: StepInput,
    increment: u16,
    authentication: BusAuthentication,
) -> Result<(VmState, StepEffects), StepError> {
    let mut executor = Executor::new(state, input, authentication);
    let next = executor
        .state()
        .cpu()
        .m_cycles()
        .checked_add(u64::from(increment))
        .ok_or(StepError::CycleCountOverflow)?;
    executor.state_mut().cpu_mut().set_m_cycles(next);
    executor
        .state_mut()
        .dmg_devices_mut()
        .advance_halt_until_vblank(increment);
    executor.finish_machine(StepKind::HaltUntilVBlank, machine_event_marker(0x76)?)
}

fn halt_until_serial(
    state: VmState,
    input: StepInput,
    increment: u16,
    authentication: BusAuthentication,
) -> Result<(VmState, StepEffects), StepError> {
    let mut executor = Executor::new(state, input, authentication);
    let next = executor
        .state()
        .cpu()
        .m_cycles()
        .checked_add(u64::from(increment))
        .ok_or(StepError::CycleCountOverflow)?;
    executor.state_mut().cpu_mut().set_m_cycles(next);
    executor
        .state_mut()
        .dmg_devices_mut()
        .advance_halt_until_serial(increment);
    executor.finish_machine(StepKind::HaltUntilSerial, machine_event_marker(0x76)?)
}

fn halt_until_timer(
    state: VmState,
    input: StepInput,
    increment: u32,
    authentication: BusAuthentication,
) -> Result<(VmState, StepEffects), StepError> {
    let mut executor = Executor::new(state, input, authentication);
    let next = executor
        .state()
        .cpu()
        .m_cycles()
        .checked_add(u64::from(increment))
        .ok_or(StepError::CycleCountOverflow)?;
    executor.state_mut().cpu_mut().set_m_cycles(next);
    executor
        .state_mut()
        .dmg_devices_mut()
        .advance_halt_until_timer(increment);
    executor.finish_machine(StepKind::HaltUntilTimer, machine_event_marker(0x76)?)
}

fn halt_idle(
    state: VmState,
    input: StepInput,
    authentication: BusAuthentication,
) -> Result<(VmState, StepEffects), StepError> {
    let increment = state.dmg_devices().halt_idle_m_cycles();
    let mut executor = Executor::new(state, input, authentication);
    add_machine_timing(&mut executor, increment)?;
    executor.finish_machine(StepKind::HaltIdle, machine_event_marker(0x76)?)
}

fn dma_byte(
    state: VmState,
    input: StepInput,
    authentication: BusAuthentication,
) -> Result<(VmState, StepEffects), StepError> {
    let mut executor = Executor::new(state, input, authentication);
    executor.copy_dma_byte()?;
    executor.finish_machine(StepKind::DmaByte, machine_event_marker(0x00)?)
}

fn push_interrupt_return(executor: &mut Executor, value: u16) -> Result<(), StepError> {
    let [high, low] = value.to_be_bytes();
    let high_address = executor.state().cpu().sp().wrapping_sub(1);
    executor.write_data(high_address, high)?;
    executor.state_mut().cpu_mut().set_sp(high_address);
    let low_address = high_address.wrapping_sub(1);
    executor.write_data(low_address, low)?;
    executor.state_mut().cpu_mut().set_sp(low_address);
    Ok(())
}

fn add_machine_timing(executor: &mut Executor, increment: u8) -> Result<(), StepError> {
    let dma_active_at_start = executor.state().dmg_devices().dma_active();
    let next = executor
        .state()
        .cpu()
        .m_cycles()
        .checked_add(u64::from(increment))
        .ok_or(StepError::CycleCountOverflow)?;
    executor.state_mut().cpu_mut().set_m_cycles(next);
    executor
        .state_mut()
        .dmg_devices_mut()
        .advance_m_cycles(increment);
    executor
        .state_mut()
        .dmg_devices_mut()
        .schedule_dma_bytes(increment, dma_active_at_start);
    Ok(())
}

fn machine_event_marker(opcode: u8) -> Result<zksm83_isa::DecodedInstruction, StepError> {
    match decode_primary(opcode) {
        OpcodeClassification::Defined(instruction) => Ok(instruction),
        OpcodeClassification::Undefined(_) => Err(StepError::MachineEventMarkerInvariant),
    }
}

fn fetch_and_advance(executor: &mut Executor, role: BusRole) -> Result<u8, StepError> {
    let address = executor.state().cpu().pc();
    let value = executor.fetch_instruction(address, role)?;
    executor
        .state_mut()
        .cpu_mut()
        .set_pc(address.wrapping_add(1));
    Ok(value)
}

fn fetch_first_opcode(executor: &mut Executor, halt_bug: bool) -> Result<u8, StepError> {
    let address = executor.state().cpu().pc();
    let value = executor.fetch_instruction(address, BusRole::OpcodeFetch)?;
    if halt_bug {
        executor
            .state_mut()
            .cpu_mut()
            .set_run_state(RunState::Running);
    } else {
        executor
            .state_mut()
            .cpu_mut()
            .set_pc(address.wrapping_add(1));
    }
    Ok(value)
}

fn fetch_immediates(
    executor: &mut Executor,
    instruction_len: u8,
) -> Result<ImmediateBytes, StepError> {
    let mut immediate = ImmediateBytes::default();
    for _ in 0..instruction_len.saturating_sub(1) {
        immediate.push(fetch_and_advance(executor, BusRole::ImmediateRead)?)?;
    }
    Ok(immediate)
}

fn apply_delayed_ime(executor: &mut Executor, operation: Operation, enable_after_step: bool) {
    if enable_after_step && operation != Operation::DisableInterrupts {
        executor.state_mut().cpu_mut().set_ime(ImeState::Enabled);
    }
}

fn add_timing(
    executor: &mut Executor,
    instruction: zksm83_isa::DecodedInstruction,
    branch_taken: bool,
    dma_active_at_start: bool,
) -> Result<(), StepError> {
    let timing = instruction.timing();
    let increment = if branch_taken {
        timing
            .taken_m_cycles()
            .map_or(timing.base_m_cycles(), |cycles| cycles)
    } else {
        timing.base_m_cycles()
    };
    let next = executor
        .state()
        .cpu()
        .m_cycles()
        .checked_add(u64::from(increment))
        .ok_or(StepError::CycleCountOverflow)?;
    executor.state_mut().cpu_mut().set_m_cycles(next);
    executor
        .state_mut()
        .dmg_devices_mut()
        .advance_m_cycles(increment);
    executor
        .state_mut()
        .dmg_devices_mut()
        .schedule_dma_bytes(increment, dma_active_at_start);
    Ok(())
}
