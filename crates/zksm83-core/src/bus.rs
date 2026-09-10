//! Exact typed bus-witness consumption and ordered step effects.

use serde::{Deserialize, Serialize};
use zksm83_isa::{AlignedInstruction, DecodedInstruction};
use zksm83_memory::{
    AddressOwner, BusTranscriptEvent, INPUT_PORT, MemoryRead, MemoryWrite, OUTPUT_PORT, RomRead,
    dmg_owner, owner,
};

use crate::{DmgInterrupt, MachineProfile, StepError, VmState};

/// Semantic role of an authenticated ROM read.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum BusRole {
    /// Primary or CB opcode fetch.
    OpcodeFetch,
    /// Immediate operand-byte read.
    ImmediateRead,
    /// Instruction-requested data read from ROM.
    DataRead,
    /// Instruction-requested mutable-memory write.
    DataWrite,
}

/// One prover-supplied authentication or private-input witness.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum BusWitness {
    /// Authenticated immutable ROM byte.
    Rom(RomRead),
    /// Authenticated mutable-memory byte.
    MemoryRead(MemoryRead),
    /// Authenticated mutable-memory update.
    MemoryWrite(MemoryWrite),
    /// Next private input byte consumed at the declared input port.
    InputByte(u8),
}

impl BusWitness {
    /// Returns the witness's algebraic kind.
    #[must_use]
    pub const fn kind(&self) -> WitnessKind {
        match self {
            Self::Rom(_) => WitnessKind::Rom,
            Self::MemoryRead(_) => WitnessKind::MemoryRead,
            Self::MemoryWrite(_) => WitnessKind::MemoryWrite,
            Self::InputByte(_) => WitnessKind::InputByte,
        }
    }
}

/// Kind of witness required or encountered by the transition relation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum WitnessKind {
    /// ROM authentication path.
    Rom,
    /// Mutable-memory read path.
    MemoryRead,
    /// Mutable-memory write path.
    MemoryWrite,
    /// Private input byte.
    InputByte,
}

/// Exact witness requested by the relation at the next bus boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum WitnessRequest {
    /// Authenticated ROM byte at an instruction-derived address.
    Rom {
        /// Requested address.
        address: u16,
        /// Mapper-derived physical ROM byte index.
        physical_address: u32,
        /// Semantic fetch/read role.
        role: BusRole,
    },
    /// Authenticated mutable-memory read at an instruction-derived address.
    MemoryRead {
        /// Requested address.
        address: u16,
        /// Mapper-derived physical mutable byte index.
        physical_address: u32,
    },
    /// Authenticated mutable-memory update with an instruction-derived new byte.
    MemoryWrite {
        /// Requested address.
        address: u16,
        /// Mapper-derived physical mutable byte index.
        physical_address: u32,
        /// Required after-value.
        value: u8,
    },
    /// Next committed private input byte.
    InputByte,
}

impl WitnessRequest {
    /// Returns the algebraic witness kind.
    #[must_use]
    pub const fn kind(self) -> WitnessKind {
        match self {
            Self::Rom { .. } => WitnessKind::Rom,
            Self::MemoryRead { .. } => WitnessKind::MemoryRead,
            Self::MemoryWrite { .. } => WitnessKind::MemoryWrite,
            Self::InputByte => WitnessKind::InputByte,
        }
    }
}

/// Exact ordered witnesses supplied to one pure instruction transition.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StepInput {
    witnesses: Vec<BusWitness>,
}

impl StepInput {
    /// Constructs a step input. The relation rejects missing or surplus witnesses.
    #[must_use]
    pub fn new(witnesses: Vec<BusWitness>) -> Self {
        Self { witnesses }
    }

    /// Returns the supplied witness count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.witnesses.len()
    }

    /// Returns whether no witnesses were supplied.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.witnesses.is_empty()
    }

    pub(crate) fn into_witnesses(self) -> std::vec::IntoIter<BusWitness> {
        self.witnesses.into_iter()
    }
}

/// One ordered bus event caused by a valid CPU transition.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum BusEvent {
    /// Authenticated primary or CB opcode fetch.
    OpcodeFetch(RomRead),
    /// Authenticated immediate operand read.
    ImmediateRead(RomRead),
    /// Authenticated opcode byte fetched from mutable executable memory.
    MemoryOpcodeFetch(MemoryRead),
    /// Authenticated immediate byte fetched from mutable executable memory.
    MemoryImmediateRead(MemoryRead),
    /// Authenticated instruction data read from ROM.
    RomRead(RomRead),
    /// Authenticated latest-value mutable-memory read.
    MemoryRead(MemoryRead),
    /// OAM DMA source byte authenticated against immutable ROM.
    DmgDmaRomRead(RomRead),
    /// OAM DMA source byte authenticated against mutable memory.
    DmgDmaMemoryRead(MemoryRead),
    /// OAM DMA destination update authenticated against mutable OAM.
    DmgDmaWrite(MemoryWrite),
    /// Authenticated root-changing mutable-memory write.
    MemoryWrite(MemoryWrite),
    /// MBC3 control-register write in the CPU ROM address window.
    Mbc3ControlWrite {
        /// CPU-visible control address.
        address: u16,
        /// Written control byte.
        value: u8,
    },
    /// Deterministic `0xff` read from disabled or unselected external RAM.
    Mbc3OpenBusRead {
        /// CPU-visible external-RAM address.
        address: u16,
        /// Returned byte, fixed to `0xff` by the relation.
        value: u8,
    },
    /// Write ignored because external RAM is disabled or an RTC register is selected.
    Mbc3IgnoredWrite {
        /// CPU-visible external-RAM address.
        address: u16,
        /// Ignored byte.
        value: u8,
    },
    /// Ordered private-input consumption.
    InputRead {
        /// Zero-based input index.
        index: u64,
        /// Consumed byte.
        value: u8,
    },
    /// Ordered public-output production.
    OutputWrite {
        /// Zero-based output index.
        index: u64,
        /// Produced byte.
        value: u8,
    },
    /// Deterministic read from a typed DMG MMIO register.
    DmgMmioRead {
        /// CPU-visible device-register address.
        address: u16,
        /// Returned register byte.
        value: u8,
    },
    /// Deterministic write to a typed DMG MMIO register.
    DmgMmioWrite {
        /// CPU-visible device-register address.
        address: u16,
        /// Prior CPU-visible register byte.
        before: u8,
        /// Raw byte written by the CPU.
        value: u8,
    },
    /// One committed joypad sample and its resulting P1 read value.
    DmgJoypadRead {
        /// Zero-based committed input index.
        index: u64,
        /// Previously held pressed-button mask.
        before_buttons: u8,
        /// Newly committed pressed-button mask.
        buttons: u8,
        /// CPU-visible active-low P1 value.
        value: u8,
    },
}

/// Stable kind committed for every bus event consumed by the proof relation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum BusEventKind {
    /// Padding used only by fixed-shape proof witnesses.
    Unused,
    /// Immutable-ROM opcode fetch.
    OpcodeFetch,
    /// Immutable-ROM immediate-byte read.
    ImmediateRead,
    /// Immutable-ROM data read.
    RomRead,
    /// Mutable-memory data read.
    MemoryRead,
    /// Mutable-memory write.
    MemoryWrite,
    /// Ordered private-input read.
    InputRead,
    /// Ordered public-output write.
    OutputWrite,
    /// MBC3 control-register write.
    Mbc3ControlWrite,
    /// MBC3 disabled-RAM open-bus read.
    Mbc3OpenBusRead,
    /// MBC3 disabled-RAM ignored write.
    Mbc3IgnoredWrite,
    /// Typed DMG MMIO read.
    DmgMmioRead,
    /// Typed DMG MMIO write.
    DmgMmioWrite,
    /// Committed joypad sample and P1 read.
    DmgJoypadRead,
    /// Opcode fetched from mutable executable memory.
    MemoryOpcodeFetch,
    /// Immediate byte fetched from mutable executable memory.
    MemoryImmediateRead,
    /// DMA source read from immutable ROM.
    DmgDmaRomRead,
    /// DMA source read from mutable memory.
    DmgDmaMemoryRead,
    /// DMA destination write to mutable OAM.
    DmgDmaWrite,
}

impl BusEventKind {
    /// Returns the stable five-bit transcript and circuit code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Unused => 0,
            Self::OpcodeFetch => 1,
            Self::ImmediateRead => 2,
            Self::RomRead => 3,
            Self::MemoryRead => 4,
            Self::MemoryWrite => 5,
            Self::InputRead => 6,
            Self::OutputWrite => 7,
            Self::Mbc3ControlWrite => 8,
            Self::Mbc3OpenBusRead => 9,
            Self::Mbc3IgnoredWrite => 10,
            Self::DmgMmioRead => 11,
            Self::DmgMmioWrite => 12,
            Self::DmgJoypadRead => 13,
            Self::MemoryOpcodeFetch => 14,
            Self::MemoryImmediateRead => 15,
            Self::DmgDmaRomRead => 16,
            Self::DmgDmaMemoryRead => 17,
            Self::DmgDmaWrite => 18,
        }
    }
}

/// A byte does not encode one of the stable proof-relation bus event kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BusEventKindError {
    /// Rejected code.
    pub code: u8,
}

impl TryFrom<u8> for BusEventKind {
    type Error = BusEventKindError;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        match code {
            0 => Ok(Self::Unused),
            1 => Ok(Self::OpcodeFetch),
            2 => Ok(Self::ImmediateRead),
            3 => Ok(Self::RomRead),
            4 => Ok(Self::MemoryRead),
            5 => Ok(Self::MemoryWrite),
            6 => Ok(Self::InputRead),
            7 => Ok(Self::OutputWrite),
            8 => Ok(Self::Mbc3ControlWrite),
            9 => Ok(Self::Mbc3OpenBusRead),
            10 => Ok(Self::Mbc3IgnoredWrite),
            11 => Ok(Self::DmgMmioRead),
            12 => Ok(Self::DmgMmioWrite),
            13 => Ok(Self::DmgJoypadRead),
            14 => Ok(Self::MemoryOpcodeFetch),
            15 => Ok(Self::MemoryImmediateRead),
            16 => Ok(Self::DmgDmaRomRead),
            17 => Ok(Self::DmgDmaMemoryRead),
            18 => Ok(Self::DmgDmaWrite),
            _ => Err(BusEventKindError { code }),
        }
    }
}

impl BusEvent {
    /// Returns the stable proof-relation event kind.
    #[must_use]
    pub const fn kind(&self) -> BusEventKind {
        match self {
            Self::OpcodeFetch(_) => BusEventKind::OpcodeFetch,
            Self::ImmediateRead(_) => BusEventKind::ImmediateRead,
            Self::MemoryOpcodeFetch(_) => BusEventKind::MemoryOpcodeFetch,
            Self::MemoryImmediateRead(_) => BusEventKind::MemoryImmediateRead,
            Self::RomRead(_) => BusEventKind::RomRead,
            Self::MemoryRead(_) => BusEventKind::MemoryRead,
            Self::DmgDmaRomRead(_) => BusEventKind::DmgDmaRomRead,
            Self::DmgDmaMemoryRead(_) => BusEventKind::DmgDmaMemoryRead,
            Self::DmgDmaWrite(_) => BusEventKind::DmgDmaWrite,
            Self::MemoryWrite(_) => BusEventKind::MemoryWrite,
            Self::Mbc3ControlWrite { .. } => BusEventKind::Mbc3ControlWrite,
            Self::Mbc3OpenBusRead { .. } => BusEventKind::Mbc3OpenBusRead,
            Self::Mbc3IgnoredWrite { .. } => BusEventKind::Mbc3IgnoredWrite,
            Self::InputRead { .. } => BusEventKind::InputRead,
            Self::OutputWrite { .. } => BusEventKind::OutputWrite,
            Self::DmgMmioRead { .. } => BusEventKind::DmgMmioRead,
            Self::DmgMmioWrite { .. } => BusEventKind::DmgMmioWrite,
            Self::DmgJoypadRead { .. } => BusEventKind::DmgJoypadRead,
        }
    }

    /// Returns the canonical tuple consumed by the lookup-memory audit interface.
    #[must_use]
    pub fn transcript_event(&self) -> BusTranscriptEvent {
        let mut event = BusTranscriptEvent {
            kind: self.kind().code(),
            address: 0,
            physical_address: 0,
            before: 0,
            auxiliary: 0,
            value: 0,
            index: 0,
        };
        match self {
            Self::OpcodeFetch(read)
            | Self::ImmediateRead(read)
            | Self::RomRead(read)
            | Self::DmgDmaRomRead(read) => {
                event.address = read.address;
                event.physical_address = read.physical_address;
                event.value = read.value;
            }
            Self::MemoryOpcodeFetch(read)
            | Self::MemoryImmediateRead(read)
            | Self::MemoryRead(read)
            | Self::DmgDmaMemoryRead(read) => {
                event.address = read.address;
                event.physical_address = read.physical_address;
                event.value = read.value;
            }
            Self::MemoryWrite(write) | Self::DmgDmaWrite(write) => {
                event.address = write.address;
                event.physical_address = write.physical_address;
                event.before = write.before;
                event.value = write.after;
            }
            Self::Mbc3ControlWrite { address, value }
            | Self::Mbc3OpenBusRead { address, value }
            | Self::Mbc3IgnoredWrite { address, value }
            | Self::DmgMmioRead { address, value } => {
                event.address = *address;
                event.value = *value;
            }
            Self::InputRead { index, value } => {
                event.address = INPUT_PORT;
                event.value = *value;
                event.index = *index;
            }
            Self::OutputWrite { index, value } => {
                event.address = OUTPUT_PORT;
                event.value = *value;
                event.index = *index;
            }
            Self::DmgMmioWrite {
                address,
                before,
                value,
            } => {
                event.address = *address;
                event.before = *before;
                event.value = *value;
            }
            Self::DmgJoypadRead {
                index,
                before_buttons,
                buttons,
                value,
            } => {
                event.address = 0xff00;
                event.before = *before_buttons;
                event.auxiliary = *buttons;
                event.value = *value;
                event.index = *index;
            }
        }
        event
    }
}

/// Effects and decoded metadata of one accepted instruction transition.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StepEffects {
    kind: StepKind,
    instruction: DecodedInstruction,
    branch_taken: bool,
    bus_events: Vec<BusEvent>,
}

impl StepEffects {
    pub(crate) const fn new(
        instruction: DecodedInstruction,
        branch_taken: bool,
        bus_events: Vec<BusEvent>,
    ) -> Self {
        Self {
            kind: StepKind::Instruction,
            instruction,
            branch_taken,
            bus_events,
        }
    }

    pub(crate) const fn machine(
        kind: StepKind,
        instruction: DecodedInstruction,
        bus_events: Vec<BusEvent>,
    ) -> Self {
        Self {
            kind,
            instruction,
            branch_taken: false,
            bus_events,
        }
    }

    /// Returns whether this row executes an opcode or a DMG machine event.
    #[must_use]
    pub const fn kind(&self) -> StepKind {
        self.kind
    }

    /// Returns the decoded instruction constrained by this step.
    #[must_use]
    pub const fn instruction(&self) -> DecodedInstruction {
        self.instruction
    }

    /// Returns whether a conditional control transfer was taken.
    #[must_use]
    pub const fn branch_taken(&self) -> bool {
        self.branch_taken
    }

    /// Returns ordered bus effects.
    pub fn bus_events(&self) -> impl ExactSizeIterator<Item = &BusEvent> {
        self.bus_events.iter()
    }
}

/// Public discriminator for an opcode step or a DMG machine transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum StepKind {
    /// A decoded SM83 instruction executes.
    Instruction,
    /// HALT consumes a canonical 1-6 M-cycle idle batch because no interrupt is pending.
    HaltIdle,
    /// HALT advances exactly to the next VBlank under the constrained quiet-device preconditions.
    HaltUntilVBlank,
    /// Pokémon Blue's authenticated sound wait loop advances without crossing VBlank.
    BlueSoundWait,
    /// Pokémon Blue's ROM-bound pure DE delay loop executes to completion with IME disabled.
    BlueDelayLoop,
    /// The authenticated HRAM OAM-DMA wait loop schedules every remaining copy at once.
    BlueDmaWait,
    /// HALT exits without dispatch because IME is disabled.
    HaltWake,
    /// The CPU acknowledges and dispatches the selected interrupt.
    InterruptDispatch(DmgInterrupt),
    /// One authenticated OAM DMA byte copy serialized at zero additional hardware time.
    DmaByte,
}

pub(crate) struct Executor {
    state: VmState,
    witnesses: std::vec::IntoIter<BusWitness>,
    events: Vec<BusEvent>,
    authentication: BusAuthentication,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BusAuthentication {
    Merkle,
    Lookup,
}

impl Executor {
    pub(crate) fn new(state: VmState, input: StepInput, authentication: BusAuthentication) -> Self {
        Self {
            state,
            witnesses: input.into_witnesses(),
            events: Vec::new(),
            authentication,
        }
    }

    pub(crate) const fn state(&self) -> VmState {
        self.state
    }

    pub(crate) const fn state_mut(&mut self) -> &mut VmState {
        &mut self.state
    }

    pub(crate) fn fetch(&mut self, address: u16, role: BusRole) -> Result<u8, StepError> {
        let physical_address = self.state.mbc3().map_rom(address);
        let read = self.take_rom_read(address, physical_address, role)?;
        let value = read.value;
        self.events.push(match role {
            BusRole::OpcodeFetch => BusEvent::OpcodeFetch(read),
            BusRole::ImmediateRead => BusEvent::ImmediateRead(read),
            BusRole::DataRead => BusEvent::RomRead(read),
            BusRole::DataWrite => return Err(StepError::InstructionMetadataInvariant),
        });
        Ok(value)
    }

    fn take_rom_read(
        &mut self,
        address: u16,
        physical_address: u32,
        role: BusRole,
    ) -> Result<RomRead, StepError> {
        let witness = self.next(WitnessRequest::Rom {
            address,
            physical_address,
            role,
        })?;
        let BusWitness::Rom(read) = witness else {
            return Err(StepError::WitnessKindInvariant);
        };
        require_address(address, read.address, role)?;
        require_physical_address(physical_address, read.physical_address, role)?;
        if self.authentication == BusAuthentication::Merkle {
            read.verify(self.state.rom_root())?;
        }
        Ok(read)
    }

    pub(crate) fn fetch_instruction(
        &mut self,
        address: u16,
        role: BusRole,
    ) -> Result<u8, StepError> {
        self.require_cpu_dma_access(address)?;
        self.require_cpu_ppu_access(address)?;
        match state_owner(self.state, address) {
            AddressOwner::Rom => self.fetch(address, role),
            AddressOwner::Memory => self.read_instruction_memory(address, role),
            AddressOwner::Input
            | AddressOwner::Output
            | AddressOwner::DmgMmio
            | AddressOwner::DmgEcho
            | AddressOwner::Unowned => Err(StepError::UnownedInstructionFetch { address }),
        }
    }

    pub(crate) fn read_data(&mut self, address: u16) -> Result<u8, StepError> {
        self.require_cpu_dma_access(address)?;
        self.require_cpu_ppu_access(address)?;
        if self.state.profile() == MachineProfile::DmgPostBootMbc3V1 && address == 0xff00 {
            return self.read_dmg_joypad();
        }
        if (0xa000..=0xbfff).contains(&address) {
            return match self.state.mbc3().map_ram(address) {
                Some(physical_address) => self.read_memory(address, physical_address),
                None => {
                    let value = 0xff;
                    self.events
                        .push(BusEvent::Mbc3OpenBusRead { address, value });
                    Ok(value)
                }
            };
        }
        match state_owner(self.state, address) {
            AddressOwner::Rom => self.fetch(address, BusRole::DataRead),
            AddressOwner::Memory => self.read_memory(address, u32::from(address)),
            AddressOwner::Input => self.read_input(),
            AddressOwner::Output => Err(StepError::ReadFromOutputPort),
            AddressOwner::DmgMmio => self.read_dmg_mmio(address),
            AddressOwner::DmgEcho => Err(StepError::DmgEchoUnavailable { address }),
            AddressOwner::Unowned => Err(StepError::UnownedRead { address }),
        }
    }

    pub(crate) fn write_data(&mut self, address: u16, value: u8) -> Result<(), StepError> {
        self.require_cpu_dma_access(address)?;
        self.require_cpu_ppu_access(address)?;
        if address <= 0x7fff {
            self.state.mbc3_mut().apply_control_write(address, value);
            self.events
                .push(BusEvent::Mbc3ControlWrite { address, value });
            return Ok(());
        }
        if (0xa000..=0xbfff).contains(&address) {
            return match self.state.mbc3().map_ram(address) {
                Some(physical_address) => self.write_memory(address, physical_address, value),
                None => {
                    self.events
                        .push(BusEvent::Mbc3IgnoredWrite { address, value });
                    Ok(())
                }
            };
        }
        match state_owner(self.state, address) {
            AddressOwner::Memory => self.write_memory(address, u32::from(address), value),
            AddressOwner::Output => self.write_output(value),
            AddressOwner::Rom => Err(StepError::WriteToRom { address }),
            AddressOwner::Input => Err(StepError::WriteToInputPort),
            AddressOwner::DmgMmio => self.write_dmg_mmio(address, value),
            AddressOwner::DmgEcho => Err(StepError::DmgEchoUnavailable { address }),
            AddressOwner::Unowned => Err(StepError::UnownedWrite { address }),
        }
    }

    pub(crate) fn finish(
        self,
        instruction: DecodedInstruction,
        branch_taken: bool,
    ) -> Result<(VmState, StepEffects), StepError> {
        let (state, events) = self.finalize(instruction)?;
        Ok((state, StepEffects::new(instruction, branch_taken, events)))
    }

    pub(crate) fn finish_machine(
        self,
        kind: StepKind,
        instruction: DecodedInstruction,
    ) -> Result<(VmState, StepEffects), StepError> {
        let (state, events) = self.finalize(instruction)?;
        Ok((state, StepEffects::machine(kind, instruction, events)))
    }

    fn finalize(
        mut self,
        instruction: DecodedInstruction,
    ) -> Result<(VmState, Vec<BusEvent>), StepError> {
        let remaining = self.witnesses.len();
        if remaining != 0 {
            return Err(StepError::SurplusWitnesses { remaining });
        }
        if self.authentication == BusAuthentication::Merkle {
            let transcript = self
                .events
                .iter()
                .try_fold(self.state.bus_transcript(), |transcript, event| {
                    transcript.append(event.transcript_event())
                })?;
            self.state.set_bus_transcript(transcript);
            let aligned_row = AlignedInstruction::from_decoded(instruction).packed()?;
            self.state
                .set_isa_transcript(self.state.isa_transcript().append(aligned_row)?);
        }
        Ok((self.state, self.events))
    }

    pub(crate) fn copy_dma_byte(&mut self) -> Result<(), StepError> {
        let devices = self.state.dmg_devices();
        let source = devices.dma_source_address();
        let destination = devices.dma_destination_address();
        if source > 0xdf9f {
            return Err(StepError::DmgDmaSourceUnavailable { address: source });
        }
        let value = match state_owner(self.state, source) {
            AddressOwner::Rom => {
                let physical = self.state.mbc3().map_rom(source);
                let read = self.take_rom_read(source, physical, BusRole::DataRead)?;
                let value = read.value;
                self.events.push(BusEvent::DmgDmaRomRead(read));
                value
            }
            AddressOwner::Memory => {
                let physical = if (0xa000..=0xbfff).contains(&source) {
                    self.state
                        .mbc3()
                        .map_ram(source)
                        .ok_or(StepError::DmgDmaSourceUnavailable { address: source })?
                } else {
                    u32::from(source)
                };
                let read = self.take_memory_read(source, physical, BusRole::DataRead)?;
                let value = read.value;
                self.events.push(BusEvent::DmgDmaMemoryRead(read));
                value
            }
            AddressOwner::Input
            | AddressOwner::Output
            | AddressOwner::DmgMmio
            | AddressOwner::DmgEcho
            | AddressOwner::Unowned => {
                return Err(StepError::DmgDmaSourceUnavailable { address: source });
            }
        };
        let write = self.take_memory_write(destination, u32::from(destination), value)?;
        if self.authentication == BusAuthentication::Merkle {
            self.state
                .set_memory_root(write.verify(self.state.memory_root())?);
        }
        self.events.push(BusEvent::DmgDmaWrite(write));
        self.state.dmg_devices_mut().complete_dma_byte();
        Ok(())
    }

    fn read_memory(&mut self, address: u16, physical_address: u32) -> Result<u8, StepError> {
        let read = self.take_memory_read(address, physical_address, BusRole::DataRead)?;
        let value = read.value;
        self.events.push(BusEvent::MemoryRead(read));
        Ok(value)
    }

    fn read_instruction_memory(&mut self, address: u16, role: BusRole) -> Result<u8, StepError> {
        let read = self.take_memory_read(address, u32::from(address), role)?;
        let value = read.value;
        self.events.push(match role {
            BusRole::OpcodeFetch => BusEvent::MemoryOpcodeFetch(read),
            BusRole::ImmediateRead => BusEvent::MemoryImmediateRead(read),
            BusRole::DataRead | BusRole::DataWrite => {
                return Err(StepError::InstructionMetadataInvariant);
            }
        });
        Ok(value)
    }

    fn take_memory_read(
        &mut self,
        address: u16,
        physical_address: u32,
        role: BusRole,
    ) -> Result<MemoryRead, StepError> {
        let witness = self.next(WitnessRequest::MemoryRead {
            address,
            physical_address,
        })?;
        let BusWitness::MemoryRead(read) = witness else {
            return Err(StepError::WitnessKindInvariant);
        };
        require_address(address, read.address, role)?;
        require_physical_address(physical_address, read.physical_address, role)?;
        if self.authentication == BusAuthentication::Merkle {
            read.verify(self.state.memory_root())?;
        }
        Ok(read)
    }

    fn read_input(&mut self) -> Result<u8, StepError> {
        let witness = self.next(WitnessRequest::InputByte)?;
        let BusWitness::InputByte(value) = witness else {
            return Err(StepError::WitnessKindInvariant);
        };
        let index = self.state.input_log().next_index();
        let next = self.state.input_log().append(value)?;
        self.state.set_input_log(next);
        self.events.push(BusEvent::InputRead { index, value });
        Ok(value)
    }

    fn read_dmg_mmio(&mut self, address: u16) -> Result<u8, StepError> {
        let value = self
            .state
            .dmg_devices()
            .read_mmio(address)
            .ok_or(StepError::DmgMmioUnavailable { address })?;
        self.events.push(BusEvent::DmgMmioRead { address, value });
        Ok(value)
    }

    fn read_dmg_joypad(&mut self) -> Result<u8, StepError> {
        let witness = self.next(WitnessRequest::InputByte)?;
        let BusWitness::InputByte(buttons) = witness else {
            return Err(StepError::WitnessKindInvariant);
        };
        let index = self.state.input_log().next_index();
        let next = self.state.input_log().append(buttons)?;
        let before_buttons = self.state.dmg_devices().joypad_buttons();
        let value = self.state.dmg_devices_mut().sample_joypad(buttons);
        self.state.set_input_log(next);
        self.events.push(BusEvent::DmgJoypadRead {
            index,
            before_buttons,
            buttons,
            value,
        });
        Ok(value)
    }

    fn write_dmg_mmio(&mut self, address: u16, value: u8) -> Result<(), StepError> {
        let before = self
            .state
            .dmg_devices_mut()
            .write_mmio(address, value)
            .ok_or(StepError::DmgMmioUnavailable { address })?;
        self.events.push(BusEvent::DmgMmioWrite {
            address,
            before,
            value,
        });
        Ok(())
    }

    fn write_memory(
        &mut self,
        address: u16,
        physical_address: u32,
        value: u8,
    ) -> Result<(), StepError> {
        let write = self.take_memory_write(address, physical_address, value)?;
        if self.authentication == BusAuthentication::Merkle {
            let next_root = write.verify(self.state.memory_root())?;
            self.state.set_memory_root(next_root);
        }
        self.events.push(BusEvent::MemoryWrite(write));
        Ok(())
    }

    fn take_memory_write(
        &mut self,
        address: u16,
        physical_address: u32,
        value: u8,
    ) -> Result<MemoryWrite, StepError> {
        let witness = self.next(WitnessRequest::MemoryWrite {
            address,
            physical_address,
            value,
        })?;
        let BusWitness::MemoryWrite(write) = witness else {
            return Err(StepError::WitnessKindInvariant);
        };
        require_address(address, write.address, BusRole::DataWrite)?;
        require_physical_address(physical_address, write.physical_address, BusRole::DataWrite)?;
        if write.after != value {
            return Err(StepError::WriteValueMismatch {
                expected: value,
                actual: write.after,
            });
        }
        Ok(write)
    }

    fn write_output(&mut self, value: u8) -> Result<(), StepError> {
        let index = self.state.output_log().next_index();
        let next = self.state.output_log().append(value)?;
        self.state.set_output_log(next);
        self.events.push(BusEvent::OutputWrite { index, value });
        Ok(())
    }

    fn next(&mut self, request: WitnessRequest) -> Result<BusWitness, StepError> {
        let witness = self
            .witnesses
            .next()
            .ok_or(StepError::MissingWitness { request })?;
        let actual = witness.kind();
        if actual != request.kind() {
            return Err(StepError::UnexpectedWitness { request, actual });
        }
        Ok(witness)
    }

    fn require_cpu_dma_access(&self, address: u16) -> Result<(), StepError> {
        if self.state.profile() == MachineProfile::DmgPostBootMbc3V1
            && self.state.dmg_devices().dma_active()
            && !(0xff80..=0xfffe).contains(&address)
        {
            return Err(StepError::DmgDmaCpuBusUnavailable { address });
        }
        Ok(())
    }

    fn require_cpu_ppu_access(&self, address: u16) -> Result<(), StepError> {
        if self.state.profile() != MachineProfile::DmgPostBootMbc3V1 {
            return Ok(());
        }
        let devices = self.state.dmg_devices();
        let blocked = ((0x8000..=0x9fff).contains(&address) && devices.cpu_vram_blocked())
            || ((0xfe00..=0xfe9f).contains(&address) && devices.cpu_oam_blocked());
        if blocked {
            return Err(StepError::DmgPpuCpuBusUnavailable { address });
        }
        Ok(())
    }
}

const fn state_owner(state: VmState, address: u16) -> AddressOwner {
    match state.profile() {
        MachineProfile::CleanCoreV1 => owner(address),
        MachineProfile::DmgPostBootMbc3V1 => dmg_owner(address),
    }
}

fn require_address(expected: u16, actual: u16, role: BusRole) -> Result<(), StepError> {
    if actual != expected {
        return Err(StepError::AddressMismatch {
            role,
            expected,
            actual,
        });
    }
    Ok(())
}

fn require_physical_address(expected: u32, actual: u32, role: BusRole) -> Result<(), StepError> {
    if actual != expected {
        return Err(StepError::PhysicalAddressMismatch {
            role,
            expected,
            actual,
        });
    }
    Ok(())
}
