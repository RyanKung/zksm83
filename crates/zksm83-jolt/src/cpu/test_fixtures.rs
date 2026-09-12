//! Shared native CPU relation fixtures.

use akita_pcs::Ring;
use zksm83_core::{BusWitness, CpuState, Flags, ImeState, Registers, RunState, StepInput, VmState};
use zksm83_memory::{MemoryImage, RomImage};
use zksm83_trace::TraceRow;

use super::{CPU_STRUCTURAL_CONSTRAINT_COUNT, CpuStructuralRelation};
use crate::{NativeField, NativeTraceWitness, UniformError, UniformRelation};

pub(super) fn assert_row_satisfied(
    relation: &CpuStructuralRelation,
    columns: &[Vec<u64>],
    row_index: usize,
) -> Result<(), UniformError> {
    let row = columns
        .iter()
        .map(|column| {
            column
                .get(row_index)
                .copied()
                .map(NativeField::from_u64)
                .ok_or(UniformError::Shape)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut constraints = vec![NativeField::from_u64(0); CPU_STRUCTURAL_CONSTRAINT_COUNT];
    relation.evaluate(&row, &mut constraints)?;
    if constraints
        .iter()
        .any(|constraint| *constraint != NativeField::from_u64(0))
    {
        return Err(UniformError::Unsatisfied);
    }
    Ok(())
}

pub(super) fn assert_native_row_rejected(
    relation: &CpuStructuralRelation,
    row: &[u64],
) -> Result<(), UniformError> {
    let mut constraints = vec![NativeField::from_u64(0); CPU_STRUCTURAL_CONSTRAINT_COUNT];
    relation.evaluate(
        &row.iter()
            .copied()
            .map(NativeField::from_u64)
            .collect::<Vec<_>>(),
        &mut constraints,
    )?;
    if constraints
        .iter()
        .all(|constraint| *constraint == NativeField::from_u64(0))
    {
        return Err(UniformError::Unsatisfied);
    }
    Ok(())
}

pub(super) fn native_row(
    trace: &NativeTraceWitness,
    row_index: usize,
) -> Result<Vec<u64>, UniformError> {
    trace
        .columns()
        .iter()
        .map(|column| column.get(row_index).copied().ok_or(UniformError::Shape))
        .collect()
}

pub(super) fn single_opcode_trace(
    opcode: u8,
) -> Result<NativeTraceWitness, Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![opcode])?;
    let memory = MemoryImage::zeroed()?;
    let before = VmState::profile_initial(rom.root(), memory.root());
    let row = TraceRow::execute(before, StepInput::new(vec![BusWitness::Rom(rom.read(0)?)]))?;
    NativeTraceWitness::from_rows(&[&row]).map_err(Into::into)
}

pub(super) fn arithmetic_opcode_trace(
    opcode: u8,
    accumulator: u8,
    operand: u8,
    flags: u8,
) -> Result<NativeTraceWitness, Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![opcode])?;
    let memory = MemoryImage::zeroed()?;
    let cpu = CpuState::new(
        Registers {
            a: accumulator,
            b: operand,
            ..Registers::default()
        },
        Flags::from_byte(flags)?,
        0,
        0xff00,
        ImeState::Disabled,
        RunState::Running,
        0,
    );
    let baseline = VmState::profile_initial(rom.root(), memory.root());
    let before = VmState::from_parts(
        cpu,
        rom.root(),
        memory.root(),
        baseline.input_log(),
        baseline.output_log(),
    )?;
    let row = TraceRow::execute(before, StepInput::new(vec![BusWitness::Rom(rom.read(0)?)]))?;
    NativeTraceWitness::from_rows(&[&row]).map_err(Into::into)
}

pub(super) fn control_opcode_trace(
    bytes: Vec<u8>,
    flags: u8,
    hl: u16,
) -> Result<NativeTraceWitness, Box<dyn std::error::Error>> {
    let [h, l] = hl.to_be_bytes();
    register_opcode_trace(
        bytes,
        Registers {
            h,
            l,
            ..Registers::default()
        },
        flags,
        ImeState::Disabled,
    )
}

pub(super) fn register_opcode_trace(
    bytes: Vec<u8>,
    registers: Registers,
    flags: u8,
    ime: ImeState,
) -> Result<NativeTraceWitness, Box<dyn std::error::Error>> {
    let rom = RomImage::new(bytes)?;
    let memory = MemoryImage::zeroed()?;
    let cpu = CpuState::new(
        registers,
        Flags::from_byte(flags)?,
        0,
        0xff00,
        ime,
        RunState::Running,
        0,
    );
    let baseline = VmState::profile_initial(rom.root(), memory.root());
    let before = VmState::from_parts(
        cpu,
        rom.root(),
        memory.root(),
        baseline.input_log(),
        baseline.output_log(),
    )?;
    let first = rom.read(0)?;
    let instruction = match zksm83_isa::decode_primary(first.value) {
        zksm83_isa::OpcodeClassification::Defined(instruction) => instruction,
        zksm83_isa::OpcodeClassification::Undefined(_) => {
            return Err(std::io::Error::other("undefined fixture opcode").into());
        }
    };
    let mut witnesses = Vec::with_capacity(usize::from(instruction.byte_len()));
    witnesses.push(BusWitness::Rom(first));
    for address in 1..usize::from(instruction.byte_len()) {
        let address = u16::try_from(address)
            .map_err(|_| std::io::Error::other("fixture address overflow"))?;
        witnesses.push(BusWitness::Rom(rom.read(address)?));
    }
    let row = TraceRow::execute(before, StepInput::new(witnesses))?;
    NativeTraceWitness::from_rows(&[&row]).map_err(Into::into)
}

pub(super) fn push_bc_trace() -> Result<NativeTraceWitness, Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0xc5])?;
    let mut memory = MemoryImage::zeroed()?;
    let cpu = CpuState::new(
        Registers {
            b: 0x12,
            c: 0x34,
            ..Registers::default()
        },
        Flags::default(),
        0,
        0xff00,
        ImeState::Disabled,
        RunState::Running,
        0,
    );
    let baseline = VmState::profile_initial(rom.root(), memory.root());
    let before = VmState::from_parts(
        cpu,
        rom.root(),
        memory.root(),
        baseline.input_log(),
        baseline.output_log(),
    )?;
    let high = memory.write(0xfeff, 0x12)?;
    let low = memory.write(0xfefe, 0x34)?;
    let row = TraceRow::execute(
        before,
        StepInput::new(vec![
            BusWitness::Rom(rom.read(0)?),
            BusWitness::MemoryWrite(high),
            BusWitness::MemoryWrite(low),
        ]),
    )?;
    NativeTraceWitness::from_rows(&[&row]).map_err(Into::into)
}

pub(super) fn pop_bc_trace() -> Result<NativeTraceWitness, Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0xc1])?;
    let mut memory = MemoryImage::zeroed()?;
    let _low = memory.write(0xff00, 0x34)?;
    let _high = memory.write(0xff01, 0x12)?;
    let cpu = CpuState::new(
        Registers::default(),
        Flags::default(),
        0,
        0xff00,
        ImeState::Disabled,
        RunState::Running,
        0,
    );
    let baseline = VmState::profile_initial(rom.root(), memory.root());
    let before = VmState::from_parts(
        cpu,
        rom.root(),
        memory.root(),
        baseline.input_log(),
        baseline.output_log(),
    )?;
    let row = TraceRow::execute(
        before,
        StepInput::new(vec![
            BusWitness::Rom(rom.read(0)?),
            BusWitness::MemoryRead(memory.read(0xff00)?),
            BusWitness::MemoryRead(memory.read(0xff01)?),
        ]),
    )?;
    NativeTraceWitness::from_rows(&[&row]).map_err(Into::into)
}

pub(super) fn call_trace() -> Result<NativeTraceWitness, Box<dyn std::error::Error>> {
    let mut bytes = vec![0xcd, 0x34, 0x12];
    bytes.resize(0x1235, 0);
    let rom = RomImage::new(bytes)?;
    let mut memory = MemoryImage::zeroed()?;
    let before = VmState::profile_initial(rom.root(), memory.root());
    let high = memory.write(0xfeff, 0x00)?;
    let low = memory.write(0xfefe, 0x03)?;
    let row = TraceRow::execute(
        before,
        StepInput::new(vec![
            BusWitness::Rom(rom.read(0)?),
            BusWitness::Rom(rom.read(1)?),
            BusWitness::Rom(rom.read(2)?),
            BusWitness::MemoryWrite(high),
            BusWitness::MemoryWrite(low),
        ]),
    )?;
    NativeTraceWitness::from_rows(&[&row]).map_err(Into::into)
}

pub(super) fn cb_opcode_trace(
    opcode: u8,
    registers: Registers,
    flags: u8,
) -> Result<NativeTraceWitness, Box<dyn std::error::Error>> {
    let rom = RomImage::new(vec![0xcb, opcode])?;
    let memory = MemoryImage::zeroed()?;
    let cpu = CpuState::new(
        registers,
        Flags::from_byte(flags)?,
        0,
        0xff00,
        ImeState::Disabled,
        RunState::Running,
        0,
    );
    let baseline = VmState::profile_initial(rom.root(), memory.root());
    let before = VmState::from_parts(
        cpu,
        rom.root(),
        memory.root(),
        baseline.input_log(),
        baseline.output_log(),
    )?;
    let row = TraceRow::execute(
        before,
        StepInput::new(vec![
            BusWitness::Rom(rom.read(0)?),
            BusWitness::Rom(rom.read(1)?),
        ]),
    )?;
    NativeTraceWitness::from_rows(&[&row]).map_err(Into::into)
}
