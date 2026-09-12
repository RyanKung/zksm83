//! Canonical bounded encoding for statements and receipts.

use crate::{NativeMemoryCpuProof, NativeStateBoundary};

use super::{
    CommitmentIdentity, CommitmentKind, MAX_NATIVE_RECEIPT_BYTES, MAX_NATIVE_ROM_COMMITMENT_BYTES,
    MAX_NATIVE_SEGMENT_BYTES, MAX_NATIVE_SEGMENT_COUNT, MAX_NATIVE_STATEMENT_BYTES,
    NATIVE_RECEIPT_VERSION, NativeBoundary, NativeReceipt, NativeReceiptError,
    NativeSegmentReceipt, NativeStatement, ProtocolLogCounts, ProtocolLogIdentities,
};
use crate::wire::{Wire, WireError, WireReader, WireWriter};

pub(super) const RECEIPT_MAGIC: &[u8; 8] = b"ZKSM83R1";
const STATEMENT_MAGIC: &[u8; 8] = b"ZKSM83S1";

pub(super) fn encode_statement(statement: &NativeStatement) -> Result<Vec<u8>, NativeReceiptError> {
    let mut writer = WireWriter::new();
    writer.raw(STATEMENT_MAGIC);
    statement.encode(&mut writer).map_err(map_wire)?;
    let bytes = writer.finish();
    ensure_size(bytes, MAX_NATIVE_STATEMENT_BYTES)
}

pub(super) fn decode_statement(bytes: &[u8]) -> Result<NativeStatement, NativeReceiptError> {
    if bytes.len() > MAX_NATIVE_STATEMENT_BYTES {
        return Err(NativeReceiptError::Wire(
            "statement length limit".to_owned(),
        ));
    }
    let mut reader = WireReader::new(bytes);
    if reader.fixed::<8>().map_err(map_wire)? != *STATEMENT_MAGIC {
        return Err(NativeReceiptError::Wire("statement magic".to_owned()));
    }
    let statement = NativeStatement::decode(&mut reader).map_err(map_wire)?;
    reader.finish().map_err(map_wire)?;
    Ok(statement)
}

pub(super) fn encode_receipt(receipt: &NativeReceipt) -> Result<Vec<u8>, NativeReceiptError> {
    let mut writer = WireWriter::new();
    writer.raw(RECEIPT_MAGIC);
    writer.u64(receipt.version);
    writer
        .blob(&encode_statement(&receipt.statement)?)
        .map_err(map_wire)?;
    writer.blob(&encode_rom(&receipt.rom)?).map_err(map_wire)?;
    writer.usize(receipt.segments.len()).map_err(map_wire)?;
    for segment in &receipt.segments {
        writer.blob(&encode_segment(segment)?).map_err(map_wire)?;
    }
    let bytes = writer.finish();
    ensure_size(bytes, MAX_NATIVE_RECEIPT_BYTES)
}

pub(super) fn decode_receipt(bytes: &[u8]) -> Result<NativeReceipt, NativeReceiptError> {
    if bytes.len() > MAX_NATIVE_RECEIPT_BYTES {
        return Err(NativeReceiptError::Wire("receipt length limit".to_owned()));
    }
    let mut reader = WireReader::new(bytes);
    if reader.fixed::<8>().map_err(map_wire)? != *RECEIPT_MAGIC {
        return Err(NativeReceiptError::Wire("receipt magic".to_owned()));
    }
    let version = reader.u64().map_err(map_wire)?;
    if version != NATIVE_RECEIPT_VERSION {
        return Err(NativeReceiptError::UnsupportedBackend);
    }
    let statement = decode_statement(reader.blob(MAX_NATIVE_STATEMENT_BYTES).map_err(map_wire)?)?;
    let rom = decode_rom(
        reader
            .blob(MAX_NATIVE_ROM_COMMITMENT_BYTES)
            .map_err(map_wire)?,
    )?;
    let length = reader.usize(MAX_NATIVE_SEGMENT_COUNT).map_err(map_wire)?;
    let mut segments = Vec::with_capacity(length);
    for _ in 0..length {
        segments.push(decode_segment(
            reader.blob(MAX_NATIVE_SEGMENT_BYTES).map_err(map_wire)?,
        )?);
    }
    reader.finish().map_err(map_wire)?;
    Ok(NativeReceipt {
        version,
        statement,
        rom,
        segments,
    })
}

pub(super) fn encode_rom(commitment: &crate::RomCommitment) -> Result<Vec<u8>, NativeReceiptError> {
    encode_wire(commitment, MAX_NATIVE_ROM_COMMITMENT_BYTES)
}

pub(super) fn decode_rom(bytes: &[u8]) -> Result<crate::RomCommitment, NativeReceiptError> {
    decode_wire(bytes, MAX_NATIVE_ROM_COMMITMENT_BYTES)
}

pub(super) fn encode_segment(
    segment: &NativeSegmentReceipt,
) -> Result<Vec<u8>, NativeReceiptError> {
    encode_wire(segment, MAX_NATIVE_SEGMENT_BYTES)
}

pub(super) fn decode_segment(bytes: &[u8]) -> Result<NativeSegmentReceipt, NativeReceiptError> {
    decode_wire(bytes, MAX_NATIVE_SEGMENT_BYTES)
}

fn encode_wire<T: Wire>(value: &T, maximum: usize) -> Result<Vec<u8>, NativeReceiptError> {
    let mut writer = WireWriter::new();
    value.encode(&mut writer).map_err(map_wire)?;
    ensure_size(writer.finish(), maximum)
}

fn decode_wire<T: Wire>(bytes: &[u8], maximum: usize) -> Result<T, NativeReceiptError> {
    if bytes.len() > maximum {
        return Err(NativeReceiptError::Wire(
            "component length limit".to_owned(),
        ));
    }
    let mut reader = WireReader::new(bytes);
    let value = T::decode(&mut reader).map_err(map_wire)?;
    reader.finish().map_err(map_wire)?;
    Ok(value)
}

fn ensure_size(bytes: Vec<u8>, maximum: usize) -> Result<Vec<u8>, NativeReceiptError> {
    if bytes.len() > maximum {
        Err(NativeReceiptError::Wire("encoded length limit".to_owned()))
    } else {
        Ok(bytes)
    }
}

fn map_wire(error: WireError) -> NativeReceiptError {
    NativeReceiptError::Wire(error.to_string())
}

impl Wire for CommitmentKind {
    fn encode(&self, writer: &mut WireWriter) -> Result<(), WireError> {
        writer.u64(self.code());
        Ok(())
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self, WireError> {
        Self::from_code(reader.u64()?).ok_or(WireError::Shape)
    }
}

impl Wire for CommitmentIdentity {
    fn encode(&self, writer: &mut WireWriter) -> Result<(), WireError> {
        self.kind.encode(writer)?;
        writer.raw(&self.layout_digest);
        writer.u64(self.committed_length);
        writer.raw(&self.digest);
        Ok(())
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self, WireError> {
        Ok(Self {
            kind: CommitmentKind::decode(reader)?,
            layout_digest: reader.fixed()?,
            committed_length: reader.u64()?,
            digest: reader.fixed()?,
        })
    }
}

impl Wire for ProtocolLogIdentities {
    fn encode(&self, writer: &mut WireWriter) -> Result<(), WireError> {
        self.bus.encode(writer)?;
        self.input.encode(writer)?;
        self.output.encode(writer)?;
        self.isa.encode(writer)
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self, WireError> {
        Ok(Self {
            bus: CommitmentIdentity::decode(reader)?,
            input: CommitmentIdentity::decode(reader)?,
            output: CommitmentIdentity::decode(reader)?,
            isa: CommitmentIdentity::decode(reader)?,
        })
    }
}

impl Wire for ProtocolLogCounts {
    fn encode(&self, writer: &mut WireWriter) -> Result<(), WireError> {
        writer.u64(self.bus);
        writer.u64(self.input);
        writer.u64(self.output);
        writer.u64(self.isa);
        Ok(())
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self, WireError> {
        Ok(Self {
            bus: reader.u64()?,
            input: reader.u64()?,
            output: reader.u64()?,
            isa: reader.u64()?,
        })
    }
}

impl Wire for NativeStateBoundary {
    fn encode(&self, writer: &mut WireWriter) -> Result<(), WireError> {
        for scalar in self.scalars() {
            writer.u64(*scalar);
        }
        Ok(())
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self, WireError> {
        let mut scalars = [0_u64; crate::STATE_SCALAR_COUNT];
        for scalar in &mut scalars {
            *scalar = reader.u64()?;
        }
        Ok(Self::from_scalars(scalars))
    }
}

impl Wire for NativeBoundary {
    fn encode(&self, writer: &mut WireWriter) -> Result<(), WireError> {
        self.state.encode(writer)?;
        self.memory.encode(writer)?;
        self.logs.encode(writer)
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self, WireError> {
        Ok(Self {
            state: NativeStateBoundary::decode(reader)?,
            memory: CommitmentIdentity::decode(reader)?,
            logs: ProtocolLogIdentities::decode(reader)?,
        })
    }
}

impl Wire for NativeStatement {
    fn encode(&self, writer: &mut WireWriter) -> Result<(), WireError> {
        writer.raw(&self.backend_digest);
        writer.u64(self.machine_profile);
        writer.u64(self.rom_byte_length);
        self.rom.encode(writer)?;
        self.initial.encode(writer)?;
        self.final_boundary.encode(writer)?;
        writer.u64(self.segment_count);
        writer.u64(self.relation_step_count);
        writer.u64(self.m_cycle_count);
        self.logs.encode(writer)?;
        writer.raw(&self.statement_id);
        Ok(())
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self, WireError> {
        Ok(Self {
            backend_digest: reader.fixed()?,
            machine_profile: reader.u64()?,
            rom_byte_length: reader.u64()?,
            rom: CommitmentIdentity::decode(reader)?,
            initial: NativeBoundary::decode(reader)?,
            final_boundary: NativeBoundary::decode(reader)?,
            segment_count: reader.u64()?,
            relation_step_count: reader.u64()?,
            m_cycle_count: reader.u64()?,
            logs: ProtocolLogCounts::decode(reader)?,
            statement_id: reader.fixed()?,
        })
    }
}

impl Wire for NativeSegmentReceipt {
    fn encode(&self, writer: &mut WireWriter) -> Result<(), WireError> {
        writer.u64(self.segment_index);
        writer.u64(self.active_row_count);
        writer.u64(self.padded_row_count);
        self.initial.encode(writer)?;
        self.final_boundary.encode(writer)?;
        self.initial_memory.encode(writer)?;
        self.final_memory.encode(writer)?;
        self.logs.encode(writer)?;
        writer.u64(self.m_cycle_count);
        self.log_counts.encode(writer)?;
        self.proof.encode(writer)
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self, WireError> {
        Ok(Self {
            segment_index: reader.u64()?,
            active_row_count: reader.u64()?,
            padded_row_count: reader.u64()?,
            initial: NativeBoundary::decode(reader)?,
            final_boundary: NativeBoundary::decode(reader)?,
            initial_memory: crate::MemoryCommitment::decode(reader)?,
            final_memory: crate::MemoryCommitment::decode(reader)?,
            logs: crate::ProtocolLogCommitments::decode(reader)?,
            m_cycle_count: reader.u64()?,
            log_counts: ProtocolLogCounts::decode(reader)?,
            proof: NativeMemoryCpuProof::decode(reader)?,
        })
    }
}
