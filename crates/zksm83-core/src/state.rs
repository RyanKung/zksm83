//! Validated CPU and VM state values.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zksm83_memory::{
    BusTranscriptAccumulator, CommitmentRoot, IsaTranscriptAccumulator, LogAccumulator, LogKind,
};

use crate::{DmgDeviceState, Mbc3State, Mbc3StateError};

/// Stable machine semantics selected for a VM state.
///
/// The profile is part of every recursive boundary. Two otherwise identical
/// snapshots under different address/device rules are therefore distinct.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MachineProfile {
    /// Synthetic clean-core profile with declared byte input/output ports.
    CleanCoreV1,
    /// Original monochrome Game Boy state immediately after the boot ROM.
    DmgPostBootMbc3V1,
}

impl MachineProfile {
    /// Returns the stable public field encoding.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::CleanCoreV1 => 0,
            Self::DmgPostBootMbc3V1 => 1,
        }
    }
}

/// Machine semantics and typed device snapshot selected at a trace boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MachineContext {
    profile: MachineProfile,
    dmg_devices: DmgDeviceState,
}

impl MachineContext {
    /// Constructs an explicit profile/device boundary for validated resumption.
    #[must_use]
    pub const fn new(profile: MachineProfile, dmg_devices: DmgDeviceState) -> Self {
        Self {
            profile,
            dmg_devices,
        }
    }

    /// Returns the selected machine profile.
    #[must_use]
    pub const fn profile(self) -> MachineProfile {
        self.profile
    }

    /// Returns the complete typed device snapshot.
    #[must_use]
    pub const fn dmg_devices(self) -> DmgDeviceState {
        self.dmg_devices
    }
}

/// General-purpose eight-bit register file.
///
/// This is an identity-free mathematical snapshot; copying it preserves value.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Registers {
    /// Accumulator.
    pub a: u8,
    /// B register.
    pub b: u8,
    /// C register.
    pub c: u8,
    /// D register.
    pub d: u8,
    /// E register.
    pub e: u8,
    /// H register.
    pub h: u8,
    /// L register.
    pub l: u8,
}

/// Validated SM83 flags with a zero low nibble.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Flags(u8);

impl Flags {
    /// Zero flag bit.
    pub const ZERO_MASK: u8 = 0x80;
    /// Subtract flag bit.
    pub const SUBTRACT_MASK: u8 = 0x40;
    /// Half-carry flag bit.
    pub const HALF_CARRY_MASK: u8 = 0x20;
    /// Carry flag bit.
    pub const CARRY_MASK: u8 = 0x10;

    /// Validates an encoded F register.
    pub const fn from_byte(value: u8) -> Result<Self, VmStateError> {
        if value & 0x0f != 0 {
            return Err(VmStateError::InvalidFlags { value });
        }
        Ok(Self(value))
    }

    /// Constructs flags from their four propositions.
    #[must_use]
    pub const fn from_bits(zero: bool, subtract: bool, half_carry: bool, carry: bool) -> Self {
        Self(
            bool_mask(zero, Self::ZERO_MASK)
                | bool_mask(subtract, Self::SUBTRACT_MASK)
                | bool_mask(half_carry, Self::HALF_CARRY_MASK)
                | bool_mask(carry, Self::CARRY_MASK),
        )
    }

    /// Returns the encoded F register.
    #[must_use]
    pub const fn byte(self) -> u8 {
        self.0
    }

    /// Returns whether Z is set.
    #[must_use]
    pub const fn zero(self) -> bool {
        self.0 & Self::ZERO_MASK != 0
    }

    /// Returns whether N is set.
    #[must_use]
    pub const fn subtract(self) -> bool {
        self.0 & Self::SUBTRACT_MASK != 0
    }

    /// Returns whether H is set.
    #[must_use]
    pub const fn half_carry(self) -> bool {
        self.0 & Self::HALF_CARRY_MASK != 0
    }

    /// Returns whether C is set.
    #[must_use]
    pub const fn carry(self) -> bool {
        self.0 & Self::CARRY_MASK != 0
    }
}

/// Interrupt-master-enable state, including the one-instruction EI delay.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ImeState {
    /// Interrupt dispatch is disabled.
    Disabled,
    /// EI was executed and enablement is delayed through the next instruction.
    EnablePending,
    /// Interrupt dispatch is enabled.
    Enabled,
}

impl ImeState {
    /// Returns the stable public field encoding, including the EI delay state.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Disabled => 0,
            Self::EnablePending => 1,
            Self::Enabled => 2,
        }
    }
}

/// CPU execution state in the no-wake-event v1 profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RunState {
    /// An instruction may execute.
    Running,
    /// HALT was executed; no v1 transition can wake the CPU.
    Halted,
    /// STOP was executed; no v1 transition can wake the CPU.
    Stopped,
    /// The next opcode fetch suppresses its PC increment because HALT met a pending interrupt.
    HaltBug,
}

impl RunState {
    /// Returns the stable public field encoding.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Running => 0,
            Self::Halted => 1,
            Self::Stopped => 2,
            Self::HaltBug => 3,
        }
    }

    /// Returns whether the state can begin an opcode transition.
    #[must_use]
    pub const fn can_execute_instruction(self) -> bool {
        matches!(self, Self::Running | Self::HaltBug)
    }
}

/// Complete SM83 CPU snapshot.
///
/// The snapshot has no resource identity. Copying it denotes the same state and
/// does not itself perform a transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CpuState {
    registers: Registers,
    flags: Flags,
    pc: u16,
    sp: u16,
    ime: ImeState,
    run_state: RunState,
    m_cycles: u64,
}

impl CpuState {
    /// Constructs a validated CPU snapshot.
    #[must_use]
    pub const fn new(
        registers: Registers,
        flags: Flags,
        pc: u16,
        sp: u16,
        ime: ImeState,
        run_state: RunState,
        m_cycles: u64,
    ) -> Self {
        Self {
            registers,
            flags,
            pc,
            sp,
            ime,
            run_state,
            m_cycles,
        }
    }

    /// Returns the fixed initial CPU state for `sm83-core-v1`.
    #[must_use]
    pub const fn profile_initial() -> Self {
        Self::new(
            Registers {
                a: 0,
                b: 0,
                c: 0,
                d: 0,
                e: 0,
                h: 0,
                l: 0,
            },
            Flags(0),
            0,
            0xff00,
            ImeState::Disabled,
            RunState::Running,
            0,
        )
    }

    /// Returns the canonical DMG CPU state after the original boot ROM exits.
    #[must_use]
    pub const fn dmg_post_boot_initial() -> Self {
        Self::new(
            Registers {
                a: 0x01,
                b: 0x00,
                c: 0x13,
                d: 0x00,
                e: 0xd8,
                h: 0x01,
                l: 0x4d,
            },
            Flags(0xb0),
            0x0100,
            0xfffe,
            ImeState::Disabled,
            RunState::Running,
            0,
        )
    }

    /// Returns the general-purpose register file.
    #[must_use]
    pub const fn registers(self) -> Registers {
        self.registers
    }

    /// Returns the flags.
    #[must_use]
    pub const fn flags(self) -> Flags {
        self.flags
    }

    /// Returns PC.
    #[must_use]
    pub const fn pc(self) -> u16 {
        self.pc
    }

    /// Returns SP.
    #[must_use]
    pub const fn sp(self) -> u16 {
        self.sp
    }

    /// Returns IME state.
    #[must_use]
    pub const fn ime(self) -> ImeState {
        self.ime
    }

    /// Returns the current execution or one-fetch HALT-bug state.
    #[must_use]
    pub const fn run_state(self) -> RunState {
        self.run_state
    }

    /// Returns accumulated M-cycles.
    #[must_use]
    pub const fn m_cycles(self) -> u64 {
        self.m_cycles
    }

    pub(crate) const fn registers_mut(&mut self) -> &mut Registers {
        &mut self.registers
    }

    pub(crate) const fn set_flags(&mut self, flags: Flags) {
        self.flags = flags;
    }

    pub(crate) const fn set_pc(&mut self, pc: u16) {
        self.pc = pc;
    }

    pub(crate) const fn set_sp(&mut self, sp: u16) {
        self.sp = sp;
    }

    pub(crate) const fn set_ime(&mut self, ime: ImeState) {
        self.ime = ime;
    }

    pub(crate) const fn set_run_state(&mut self, run_state: RunState) {
        self.run_state = run_state;
    }

    pub(crate) const fn set_m_cycles(&mut self, m_cycles: u64) {
        self.m_cycles = m_cycles;
    }
}

/// Complete clean-profile VM snapshot.
///
/// Copying is value duplication of an immutable mathematical snapshot. The
/// transition API still consumes the value to make state flow explicit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmState {
    profile: MachineProfile,
    cpu: CpuState,
    mbc3: Mbc3State,
    dmg_devices: DmgDeviceState,
    rom_root: CommitmentRoot,
    memory_root: CommitmentRoot,
    input_log: LogAccumulator,
    output_log: LogAccumulator,
    bus_transcript: BusTranscriptAccumulator,
    isa_transcript: IsaTranscriptAccumulator,
}

impl VmState {
    /// Constructs the fixed initial VM state for committed ROM and memory.
    #[must_use]
    pub fn profile_initial(rom_root: CommitmentRoot, memory_root: CommitmentRoot) -> Self {
        Self {
            profile: MachineProfile::CleanCoreV1,
            cpu: CpuState::profile_initial(),
            mbc3: Mbc3State::profile_initial(),
            dmg_devices: DmgDeviceState::empty(),
            rom_root,
            memory_root,
            input_log: LogAccumulator::empty(LogKind::Input),
            output_log: LogAccumulator::empty(LogKind::Output),
            bus_transcript: BusTranscriptAccumulator::empty(),
            isa_transcript: IsaTranscriptAccumulator::empty(),
        }
    }

    /// Constructs the canonical post-boot DMG + no-RTC MBC3 boundary state.
    #[must_use]
    pub fn dmg_post_boot_mbc3_initial(
        rom_root: CommitmentRoot,
        memory_root: CommitmentRoot,
    ) -> Self {
        Self {
            profile: MachineProfile::DmgPostBootMbc3V1,
            cpu: CpuState::dmg_post_boot_initial(),
            mbc3: Mbc3State::profile_initial(),
            dmg_devices: DmgDeviceState::dmg_post_boot(),
            rom_root,
            memory_root,
            input_log: LogAccumulator::empty(LogKind::Input),
            output_log: LogAccumulator::empty(LogKind::Output),
            bus_transcript: BusTranscriptAccumulator::empty(),
            isa_transcript: IsaTranscriptAccumulator::empty(),
        }
    }

    /// Constructs a validated arbitrary snapshot for fixtures and trace boundaries.
    pub fn from_parts(
        cpu: CpuState,
        rom_root: CommitmentRoot,
        memory_root: CommitmentRoot,
        input_log: LogAccumulator,
        output_log: LogAccumulator,
    ) -> Result<Self, VmStateError> {
        if input_log.kind() != LogKind::Input {
            return Err(VmStateError::WrongInputLogDomain);
        }
        if output_log.kind() != LogKind::Output {
            return Err(VmStateError::WrongOutputLogDomain);
        }
        Ok(Self {
            profile: MachineProfile::CleanCoreV1,
            cpu,
            mbc3: Mbc3State::profile_initial(),
            dmg_devices: DmgDeviceState::empty(),
            rom_root,
            memory_root,
            input_log,
            output_log,
            bus_transcript: BusTranscriptAccumulator::empty(),
            isa_transcript: IsaTranscriptAccumulator::empty(),
        })
    }

    /// Constructs an arbitrary snapshot with an explicit MBC3 mapper state.
    pub fn from_parts_with_mbc3(
        cpu: CpuState,
        mbc3: Mbc3State,
        rom_root: CommitmentRoot,
        memory_root: CommitmentRoot,
        input_log: LogAccumulator,
        output_log: LogAccumulator,
    ) -> Result<Self, VmStateError> {
        let mut state = Self::from_parts(cpu, rom_root, memory_root, input_log, output_log)?;
        state.mbc3 = mbc3;
        Ok(state)
    }

    /// Constructs an arbitrary snapshot with explicit profile and mapper state.
    pub fn from_profile_parts(
        machine: MachineContext,
        cpu: CpuState,
        mbc3: Mbc3State,
        rom_root: CommitmentRoot,
        memory_root: CommitmentRoot,
        input_log: LogAccumulator,
        output_log: LogAccumulator,
    ) -> Result<Self, VmStateError> {
        let mut state =
            Self::from_parts_with_mbc3(cpu, mbc3, rom_root, memory_root, input_log, output_log)?;
        state.profile = machine.profile();
        state.dmg_devices = machine.dmg_devices();
        Ok(state)
    }

    /// Returns the machine semantics carried by this state.
    #[must_use]
    pub const fn profile(self) -> MachineProfile {
        self.profile
    }

    /// Returns CPU state.
    #[must_use]
    pub const fn cpu(self) -> CpuState {
        self.cpu
    }

    /// Returns the complete MBC3 mapper state.
    #[must_use]
    pub const fn mbc3(self) -> Mbc3State {
        self.mbc3
    }

    /// Returns the complete typed DMG device snapshot.
    #[must_use]
    pub const fn dmg_devices(self) -> DmgDeviceState {
        self.dmg_devices
    }

    /// Returns immutable ROM root.
    #[must_use]
    pub const fn rom_root(self) -> CommitmentRoot {
        self.rom_root
    }

    /// Returns current mutable-memory root.
    #[must_use]
    pub const fn memory_root(self) -> CommitmentRoot {
        self.memory_root
    }

    /// Returns consumed input prefix commitment.
    #[must_use]
    pub const fn input_log(self) -> LogAccumulator {
        self.input_log
    }

    /// Returns produced output commitment.
    #[must_use]
    pub const fn output_log(self) -> LogAccumulator {
        self.output_log
    }

    /// Returns the committed prefix of all bus events consumed by the relation.
    #[must_use]
    pub const fn bus_transcript(self) -> BusTranscriptAccumulator {
        self.bus_transcript
    }

    /// Replaces the typed bus-transcript boundary when reconstructing a checkpoint.
    #[must_use]
    pub const fn with_bus_transcript(mut self, transcript: BusTranscriptAccumulator) -> Self {
        self.bus_transcript = transcript;
        self
    }

    /// Returns the committed prefix of all aligned ISA rows consumed by the relation.
    #[must_use]
    pub const fn isa_transcript(self) -> IsaTranscriptAccumulator {
        self.isa_transcript
    }

    /// Replaces the typed ISA-transcript boundary when reconstructing a checkpoint.
    #[must_use]
    pub const fn with_isa_transcript(mut self, transcript: IsaTranscriptAccumulator) -> Self {
        self.isa_transcript = transcript;
        self
    }

    pub(crate) const fn cpu_mut(&mut self) -> &mut CpuState {
        &mut self.cpu
    }

    pub(crate) const fn mbc3_mut(&mut self) -> &mut Mbc3State {
        &mut self.mbc3
    }

    pub(crate) const fn dmg_devices_mut(&mut self) -> &mut DmgDeviceState {
        &mut self.dmg_devices
    }

    pub(crate) const fn set_memory_root(&mut self, root: CommitmentRoot) {
        self.memory_root = root;
    }

    pub(crate) const fn set_input_log(&mut self, log: LogAccumulator) {
        self.input_log = log;
    }

    pub(crate) const fn set_output_log(&mut self, log: LogAccumulator) {
        self.output_log = log;
    }

    pub(crate) const fn set_bus_transcript(&mut self, transcript: BusTranscriptAccumulator) {
        self.bus_transcript = transcript;
    }

    pub(crate) const fn set_isa_transcript(&mut self, transcript: IsaTranscriptAccumulator) {
        self.isa_transcript = transcript;
    }
}

/// Invalid state construction.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VmStateError {
    /// The low flag nibble must remain zero.
    #[error("invalid F register 0x{value:02x}: low nibble must be zero")]
    InvalidFlags {
        /// Rejected encoded flags.
        value: u8,
    },
    /// The supplied input accumulator uses the output domain.
    #[error("VM input accumulator has the wrong domain")]
    WrongInputLogDomain,
    /// The supplied output accumulator uses the input domain.
    #[error("VM output accumulator has the wrong domain")]
    WrongOutputLogDomain,
    /// An explicit MBC3 mapper snapshot violated the cartridge profile.
    #[error(transparent)]
    InvalidMbc3(#[from] Mbc3StateError),
}

const fn bool_mask(value: bool, mask: u8) -> u8 {
    if value { mask } else { 0 }
}
