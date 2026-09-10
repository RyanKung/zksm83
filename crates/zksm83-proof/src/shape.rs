//! Public circuit shape derived from instruction and event kinds only.

use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Column, ConstraintSystem, Error, Fixed},
};
use pasta_curves::Fp;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zksm83_core::BusEvent;
use zksm83_isa::{
    DecodedInstruction, InstructionEncoding, OpcodeClassification, Operation, decode_cb,
    decode_primary,
};
use zksm83_trace::Witness;

pub(crate) const OPERATION_COUNT: usize = 41;
pub(crate) const ARGUMENT_COUNT: usize = 9;
pub(crate) const EVENT_SLOTS: usize = 5;
const EVENT_KIND_COUNT: usize = 8;
pub(crate) const EVENT_ROLE_COUNT: usize = 7;

/// Public kind of one bus event; values and paths remain private witness data.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BusEventKind {
    /// No event occupies this fixed slot.
    Unused,
    /// Authenticated opcode byte.
    OpcodeFetch,
    /// Authenticated immediate byte.
    ImmediateRead,
    /// Authenticated ROM data byte.
    RomRead,
    /// Authenticated mutable-memory read.
    MemoryRead,
    /// Authenticated mutable-memory update.
    MemoryWrite,
    /// Ordered private-input byte.
    InputRead,
    /// Ordered public-output byte.
    OutputWrite,
}

impl BusEventKind {
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Unused => 0,
            Self::OpcodeFetch => 1,
            Self::ImmediateRead => 2,
            Self::RomRead => 3,
            Self::MemoryRead => 4,
            Self::MemoryWrite => 5,
            Self::InputRead => 6,
            Self::OutputWrite => 7,
        }
    }

    const fn from_event(event: &BusEvent) -> Result<Self, ShapeError> {
        match event {
            BusEvent::OpcodeFetch(_) => Ok(Self::OpcodeFetch),
            BusEvent::ImmediateRead(_) => Ok(Self::ImmediateRead),
            BusEvent::MemoryOpcodeFetch(_)
            | BusEvent::MemoryImmediateRead(_)
            | BusEvent::DmgDmaRomRead(_)
            | BusEvent::DmgDmaMemoryRead(_)
            | BusEvent::DmgDmaWrite(_) => Err(ShapeError::UnsupportedDmgDeviceEvent),
            BusEvent::RomRead(_) => Ok(Self::RomRead),
            BusEvent::MemoryRead(_) => Ok(Self::MemoryRead),
            BusEvent::MemoryWrite(_) => Ok(Self::MemoryWrite),
            BusEvent::InputRead { .. } => Ok(Self::InputRead),
            BusEvent::OutputWrite { .. } => Ok(Self::OutputWrite),
            BusEvent::Mbc3ControlWrite { .. }
            | BusEvent::Mbc3OpenBusRead { .. }
            | BusEvent::Mbc3IgnoredWrite { .. } => Err(ShapeError::UnsupportedMbc3Event),
            BusEvent::DmgMmioRead { .. }
            | BusEvent::DmgMmioWrite { .. }
            | BusEvent::DmgJoypadRead { .. } => Err(ShapeError::UnsupportedDmgDeviceEvent),
        }
    }
}

/// Public circuit specialization for one instruction row.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StepShape {
    instruction: DecodedInstruction,
    branch_taken: bool,
    events: [BusEventKind; EVENT_SLOTS],
}

impl StepShape {
    /// Returns the decoded instruction whose encoding is authenticated in-circuit.
    #[must_use]
    pub const fn instruction(&self) -> DecodedInstruction {
        self.instruction
    }

    /// Returns the public conditional-path choice, constrained against flags.
    #[must_use]
    pub const fn branch_taken(&self) -> bool {
        self.branch_taken
    }

    /// Returns the fixed event-kind slots; event contents remain private.
    #[must_use]
    pub const fn events(&self) -> [BusEventKind; EVENT_SLOTS] {
        self.events
    }
}

/// Public verifier-derived circuit shape, excluding all state and bus values.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionShape {
    steps: Vec<StepShape>,
}

impl ExecutionShape {
    /// Extracts the public instruction/event shape from a validated witness.
    pub fn from_witness(witness: &Witness) -> Result<Self, ShapeError> {
        let mut steps = Vec::new();
        for row in witness.rows() {
            let effects = row.effects();
            let mut events = [BusEventKind::Unused; EVENT_SLOTS];
            for (target, event) in events.iter_mut().zip(effects.bus_events()) {
                *target = BusEventKind::from_event(event)?;
            }
            if effects.bus_events().len() > EVENT_SLOTS {
                return Err(ShapeError::TooManyEvents {
                    actual: effects.bus_events().len(),
                    maximum: EVENT_SLOTS,
                });
            }
            steps.push(StepShape {
                instruction: effects.instruction(),
                branch_taken: effects.branch_taken(),
                events,
            });
        }
        if steps.is_empty() {
            return Err(ShapeError::EmptyExecution);
        }
        Ok(Self { steps })
    }

    /// Validates canonical decoded metadata, event padding, and branch-shape
    /// conventions after deserialization.
    pub fn validate(&self) -> Result<(), ShapeError> {
        if self.steps.is_empty() {
            return Err(ShapeError::EmptyExecution);
        }
        for step in &self.steps {
            validate_instruction(step.instruction)?;
            validate_events(step.events)?;
            if !is_control_branch(step.instruction.operation()) && step.branch_taken {
                return Err(ShapeError::UnexpectedBranchFlag);
            }
        }
        Ok(())
    }

    /// Returns instruction rows in execution order.
    pub fn steps(&self) -> impl ExactSizeIterator<Item = &StepShape> {
        self.steps.iter()
    }

    /// Returns the exact public instruction count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Returns whether the shape contains no instruction, which validated shapes forbid.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

/// Invalid public execution shape.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ShapeError {
    /// A receipt cannot describe an empty execution.
    #[error("execution shape is empty")]
    EmptyExecution,
    /// A transition exceeded the profile's fixed bus-event slots.
    #[error("instruction has {actual} bus events, maximum is {maximum}")]
    TooManyEvents {
        /// Observed event count.
        actual: usize,
        /// Circuit slot count.
        maximum: usize,
    },
    /// A semantic or argument code is outside the fixed circuit selector set.
    #[error("instruction descriptor is outside the circuit selector set")]
    DescriptorOutOfRange,
    /// Serialized instruction metadata differs from the canonical decoder.
    #[error("execution shape contains non-canonical decoded instruction metadata")]
    NonCanonicalInstruction,
    /// An occupied event appears after the first unused padding slot.
    #[error("execution shape contains non-canonical event-slot padding")]
    NonCanonicalEventPadding,
    /// A non-control instruction declares a branch choice.
    #[error("non-control instruction declares a taken branch")]
    UnexpectedBranchFlag,
    /// The reference Halo2 V1 relation does not carry MBC3 mapper state.
    #[error("the reference Halo2 relation does not support MBC3 cartridge events")]
    UnsupportedMbc3Event,
    /// The reference Halo2 V1 relation does not carry typed DMG device state.
    #[error("the reference Halo2 relation does not support typed DMG device events")]
    UnsupportedDmgDeviceEvent,
}

fn validate_instruction(instruction: DecodedInstruction) -> Result<(), ShapeError> {
    let canonical = match instruction.encoding() {
        InstructionEncoding::Primary(opcode) => match decode_primary(opcode.byte()) {
            OpcodeClassification::Defined(decoded) => decoded,
            OpcodeClassification::Undefined(_) => return Err(ShapeError::NonCanonicalInstruction),
        },
        InstructionEncoding::Cb(opcode) => decode_cb(opcode.byte()),
    };
    if instruction == canonical {
        Ok(())
    } else {
        Err(ShapeError::NonCanonicalInstruction)
    }
}

fn validate_events(events: [BusEventKind; EVENT_SLOTS]) -> Result<(), ShapeError> {
    let mut padding = false;
    for event in events {
        if event == BusEventKind::Unused {
            padding = true;
        } else if padding {
            return Err(ShapeError::NonCanonicalEventPadding);
        }
    }
    Ok(())
}

const fn is_control_branch(operation: Operation) -> bool {
    matches!(
        operation,
        Operation::RelativeJump(_) | Operation::Return(_) | Operation::Jump(_) | Operation::Call(_)
    )
}

#[derive(Clone, Debug)]
pub(crate) struct ShapeConfig {
    pub(crate) operation: [Column<Fixed>; OPERATION_COUNT],
    pub(crate) argument_zero: [Column<Fixed>; ARGUMENT_COUNT],
    pub(crate) argument_one: [Column<Fixed>; ARGUMENT_COUNT],
    pub(crate) branch_taken: Column<Fixed>,
    pub(crate) event_kinds: [[Column<Fixed>; EVENT_KIND_COUNT]; EVENT_SLOTS],
    pub(crate) event_roles: [[Column<Fixed>; EVENT_ROLE_COUNT]; EVENT_SLOTS],
}

impl ShapeConfig {
    pub(crate) fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        Self {
            operation: std::array::from_fn(|_| meta.fixed_column()),
            argument_zero: std::array::from_fn(|_| meta.fixed_column()),
            argument_one: std::array::from_fn(|_| meta.fixed_column()),
            branch_taken: meta.fixed_column(),
            event_kinds: std::array::from_fn(|_| std::array::from_fn(|_| meta.fixed_column())),
            event_roles: std::array::from_fn(|_| std::array::from_fn(|_| meta.fixed_column())),
        }
    }

    pub(crate) fn assign_row(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        shape: &StepShape,
    ) -> Result<(), Error> {
        let descriptor = shape.instruction.descriptor();
        assign_one_hot(
            region,
            offset,
            self.operation,
            usize::from(descriptor.operation),
        )?;
        assign_one_hot(
            region,
            offset,
            self.argument_zero,
            usize::from(descriptor.argument_zero),
        )?;
        assign_one_hot(
            region,
            offset,
            self.argument_one,
            usize::from(descriptor.argument_one),
        )?;
        region.assign_fixed(
            || "branch taken",
            self.branch_taken,
            offset,
            || Value::known(Fp::from(u64::from(shape.branch_taken))),
        )?;
        let mut opcode_index = 0_usize;
        let mut immediate_index = 0_usize;
        let mut data_index = 0_usize;
        for ((columns, roles), kind) in self
            .event_kinds
            .iter()
            .zip(&self.event_roles)
            .zip(shape.events)
        {
            assign_one_hot(region, offset, *columns, kind.index())?;
            let role = match kind {
                BusEventKind::Unused => 0,
                BusEventKind::OpcodeFetch => {
                    let selected = 1 + opcode_index;
                    opcode_index += 1;
                    selected
                }
                BusEventKind::ImmediateRead => {
                    let selected = 3 + immediate_index;
                    immediate_index += 1;
                    selected
                }
                BusEventKind::RomRead
                | BusEventKind::MemoryRead
                | BusEventKind::MemoryWrite
                | BusEventKind::InputRead
                | BusEventKind::OutputWrite => {
                    let selected = 5 + data_index;
                    data_index += 1;
                    selected
                }
            };
            assign_one_hot(region, offset, *roles, role)?;
        }
        Ok(())
    }
}

fn assign_one_hot<const N: usize>(
    region: &mut Region<'_, Fp>,
    offset: usize,
    columns: [Column<Fixed>; N],
    selected: usize,
) -> Result<(), Error> {
    if selected >= N {
        return Err(Error::Synthesis);
    }
    for (index, column) in columns.into_iter().enumerate() {
        region.assign_fixed(
            || "shape selector",
            column,
            offset,
            || Value::known(Fp::from(u64::from(index == selected))),
        )?;
    }
    Ok(())
}
