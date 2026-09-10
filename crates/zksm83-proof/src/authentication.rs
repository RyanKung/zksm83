//! ROM, memory, input, and output authentication for typed bus slots.

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::Error,
};
use pasta_curves::Fp;
use zksm83_core::BusEvent;
use zksm83_memory::{HashDomain, MerklePath};
use zksm83_trace::TraceRow;

use crate::{
    address::AddressConfig,
    bus::{AssignedBusRow, AssignedEvent},
    log::LogConfig,
    merkle::{AuthenticatedPath, MerkleConfig},
    shape::{BusEventKind, StepShape},
};

pub(crate) const ROM_ROOT_INSTANCE: usize = 2;

#[derive(Clone, Debug)]
pub(crate) struct AuthenticationConfig {
    merkle: MerkleConfig,
    address: AddressConfig,
    log: LogConfig,
}

impl AuthenticationConfig {
    pub(crate) fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<Fp>) -> Self {
        Self {
            merkle: MerkleConfig::configure(meta),
            address: AddressConfig::configure(meta),
            log: LogConfig::configure(meta),
        }
    }

    pub(crate) fn load(&self, layouter: impl Layouter<Fp>) -> Result<(), Error> {
        self.address.load(layouter)
    }

    pub(crate) fn constrain_row(
        &self,
        mut layouter: impl Layouter<Fp>,
        shape: &StepShape,
        row: Option<&TraceRow>,
        assigned: &AssignedBusRow,
    ) -> Result<(), Error> {
        let mut memory_root = assigned.memory_before.clone();
        let mut input_root = assigned.input_before.clone();
        let mut output_root = assigned.output_before.clone();
        for (slot, (kind, bus)) in shape.events().iter().zip(&assigned.events).enumerate() {
            let event = row.and_then(|trace| trace.effects().bus_events().nth(slot));
            let witness = EventWitness::from_optional(event, *kind)?;
            match kind {
                BusEventKind::OpcodeFetch | BusEventKind::ImmediateRead | BusEventKind::RomRead => {
                    self.authenticate_rom(
                        layouter.namespace(|| format!("ROM event {slot}")),
                        bus,
                        witness,
                    )?;
                }
                BusEventKind::MemoryRead => {
                    let authentication = self.authenticate_memory(
                        layouter.namespace(|| format!("memory read {slot}")),
                        bus,
                        &bus.value,
                        witness.address,
                        witness.value,
                        witness.path,
                    )?;
                    constrain_equal(
                        layouter.namespace(|| "memory read root"),
                        &authentication.root,
                        &memory_root,
                    )?;
                }
                BusEventKind::MemoryWrite => {
                    let before = self.authenticate_memory(
                        layouter.namespace(|| format!("memory write before {slot}")),
                        bus,
                        &bus.before,
                        witness.address,
                        witness.before,
                        witness.path,
                    )?;
                    let after = self.authenticate_memory(
                        layouter.namespace(|| format!("memory write after {slot}")),
                        bus,
                        &bus.value,
                        witness.address,
                        witness.value,
                        witness.path,
                    )?;
                    constrain_equal(
                        layouter.namespace(|| "memory write before root"),
                        &before.root,
                        &memory_root,
                    )?;
                    memory_root = after.root;
                }
                BusEventKind::InputRead => {
                    input_root = self.log.append(
                        layouter.namespace(|| format!("input event {slot}")),
                        &self.merkle,
                        HashDomain::InputElement,
                        &input_root,
                        &bus.index,
                        &bus.value,
                    )?;
                }
                BusEventKind::OutputWrite => {
                    output_root = self.log.append(
                        layouter.namespace(|| format!("output event {slot}")),
                        &self.merkle,
                        HashDomain::OutputElement,
                        &output_root,
                        &bus.index,
                        &bus.value,
                    )?;
                }
                BusEventKind::Unused => {}
            }
        }
        constrain_equal(
            layouter.namespace(|| "memory row endpoint"),
            &memory_root,
            &assigned.memory_after,
        )?;
        constrain_equal(
            layouter.namespace(|| "input row endpoint"),
            &input_root,
            &assigned.input_after,
        )?;
        constrain_equal(
            layouter.namespace(|| "output row endpoint"),
            &output_root,
            &assigned.output_after,
        )
    }

    pub(crate) const fn instance(
        &self,
    ) -> halo2_proofs::plonk::Column<halo2_proofs::plonk::Instance> {
        self.merkle.instance()
    }

    fn authenticate_rom(
        &self,
        mut layouter: impl Layouter<Fp>,
        bus: &AssignedEvent,
        witness: EventWitness,
    ) -> Result<(), Error> {
        let authentication = self.merkle.authenticate(
            layouter.namespace(|| "ROM Merkle path"),
            HashDomain::RomLeaf,
            HashDomain::RomNode,
            witness.address,
            witness.value,
            witness.path,
        )?;
        constrain_bus_cells(
            layouter.namespace(|| "ROM bus linkage"),
            bus,
            &authentication,
        )?;
        self.address.constrain_rom(
            layouter.namespace(|| "ROM address owner"),
            &authentication.address_bits,
        )?;
        layouter.constrain_instance(
            authentication.root.cell(),
            self.merkle.instance(),
            ROM_ROOT_INSTANCE,
        )
    }

    fn authenticate_memory(
        &self,
        mut layouter: impl Layouter<Fp>,
        bus: &AssignedEvent,
        expected_value: &AssignedCell<Fp, Fp>,
        address: Value<u16>,
        value: Value<u8>,
        path: Option<MerklePath>,
    ) -> Result<AuthenticatedPath, Error> {
        let authentication = self.merkle.authenticate(
            layouter.namespace(|| "memory Merkle path"),
            HashDomain::MemoryLeaf,
            HashDomain::MemoryNode,
            address,
            value,
            path,
        )?;
        constrain_equal(
            layouter.namespace(|| "memory address linkage"),
            &authentication.address,
            &bus.address,
        )?;
        constrain_equal(
            layouter.namespace(|| "memory value linkage"),
            &authentication.value,
            expected_value,
        )?;
        self.address.constrain_memory(
            layouter.namespace(|| "memory address owner"),
            &authentication.address_bits,
        )?;
        Ok(authentication)
    }
}

fn constrain_bus_cells(
    mut layouter: impl Layouter<Fp>,
    bus: &AssignedEvent,
    authentication: &AuthenticatedPath,
) -> Result<(), Error> {
    layouter.assign_region(
        || "authenticated bus cells",
        |mut region| {
            region.constrain_equal(bus.address.cell(), authentication.address.cell())?;
            region.constrain_equal(bus.value.cell(), authentication.value.cell())
        },
    )
}

fn constrain_equal(
    mut layouter: impl Layouter<Fp>,
    left: &AssignedCell<Fp, Fp>,
    right: &AssignedCell<Fp, Fp>,
) -> Result<(), Error> {
    layouter.assign_region(
        || "equality",
        |mut region| region.constrain_equal(left.cell(), right.cell()),
    )
}

#[derive(Clone, Copy)]
struct EventWitness {
    address: Value<u16>,
    value: Value<u8>,
    before: Value<u8>,
    path: Option<MerklePath>,
}

impl EventWitness {
    fn from_optional(event: Option<&BusEvent>, expected: BusEventKind) -> Result<Self, Error> {
        let Some(event) = event else {
            return Ok(Self::unknown());
        };
        match (expected, event) {
            (BusEventKind::OpcodeFetch, BusEvent::OpcodeFetch(read))
            | (BusEventKind::ImmediateRead, BusEvent::ImmediateRead(read))
            | (BusEventKind::RomRead, BusEvent::RomRead(read)) => Ok(Self {
                address: Value::known(read.address),
                value: Value::known(read.value),
                before: Value::known(read.value),
                path: Some(read.path),
            }),
            (BusEventKind::MemoryRead, BusEvent::MemoryRead(read)) => Ok(Self {
                address: Value::known(read.address),
                value: Value::known(read.value),
                before: Value::known(read.value),
                path: Some(read.path),
            }),
            (BusEventKind::MemoryWrite, BusEvent::MemoryWrite(write)) => Ok(Self {
                address: Value::known(write.address),
                value: Value::known(write.after),
                before: Value::known(write.before),
                path: Some(write.path),
            }),
            (BusEventKind::InputRead, BusEvent::InputRead { value, .. })
            | (BusEventKind::OutputWrite, BusEvent::OutputWrite { value, .. }) => Ok(Self {
                address: Value::known(0),
                value: Value::known(*value),
                before: Value::known(*value),
                path: None,
            }),
            (BusEventKind::Unused, _) => Err(Error::Synthesis),
            _ => Err(Error::Synthesis),
        }
    }

    const fn unknown() -> Self {
        Self {
            address: Value::unknown(),
            value: Value::unknown(),
            before: Value::unknown(),
            path: None,
        }
    }
}
