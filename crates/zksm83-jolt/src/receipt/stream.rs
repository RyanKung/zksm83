//! Bounded incremental prover and verifier for the canonical receipt format.

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
};

use crate::{CommittedRom, MemoryCommitment, NativeStateBoundary};

use super::{
    MAX_NATIVE_ROM_COMMITMENT_BYTES, MAX_NATIVE_SEGMENT_BYTES, MAX_NATIVE_SEGMENT_COUNT,
    MAX_NATIVE_STATEMENT_BYTES, MAX_NATIVE_STREAM_RECEIPT_BYTES, NATIVE_RECEIPT_VERSION,
    NativeBoundary, NativeReceiptError, NativeSegmentWitness, NativeStatement,
    VerifiedNativeReceipt, direct_memory_identity, direct_rom_identity, prove_segment,
    verify_segment,
    wire::{
        RECEIPT_MAGIC, decode_rom, decode_segment, encode_rom, encode_segment, encode_statement,
    },
};

/// Incrementally proves segments into a seekable spool without retaining prior proofs.
pub struct NativeReceiptStreamProver<'a, S> {
    rom: &'a CommittedRom,
    spool: S,
    initial: Option<NativeBoundary>,
    boundary: Option<NativeBoundary>,
    previous_memory: Option<MemoryCommitment>,
    segment_count: u64,
    relation_step_count: u64,
    spool_bytes: u64,
}

impl<'a, S> NativeReceiptStreamProver<'a, S>
where
    S: Read + Write + Seek,
{
    /// Starts a receipt whose segment frames will be written to an empty `spool`.
    pub fn new(rom: &'a CommittedRom, mut spool: S) -> Result<Self, NativeReceiptError> {
        if spool.seek(SeekFrom::End(0))? != 0 {
            return Err(NativeReceiptError::Wire(
                "segment spool is not empty".to_owned(),
            ));
        }
        spool.seek(SeekFrom::Start(0))?;
        Ok(Self {
            rom,
            spool,
            initial: None,
            boundary: None,
            previous_memory: None,
            segment_count: 0,
            relation_step_count: 0,
            spool_bytes: 0,
        })
    }

    /// Restores progress by decoding and verifying every complete frame in a spool.
    pub fn resume(rom: &'a CommittedRom, mut spool: S) -> Result<Self, NativeReceiptError> {
        let spool_bytes = spool.seek(SeekFrom::End(0))?;
        if spool_bytes == 0 || spool_bytes > MAX_NATIVE_STREAM_RECEIPT_BYTES {
            return Err(NativeReceiptError::Wire(
                "segment spool length is invalid".to_owned(),
            ));
        }
        spool.seek(SeekFrom::Start(0))?;
        let progress = verify_spool(&mut spool, spool_bytes, rom.commitment())?;
        spool.seek(SeekFrom::Start(spool_bytes))?;
        Ok(Self {
            rom,
            spool,
            initial: Some(progress.initial),
            boundary: Some(progress.boundary),
            previous_memory: Some(progress.previous_memory),
            segment_count: progress.segment_count,
            relation_step_count: progress.relation_step_count,
            spool_bytes,
        })
    }

    /// Returns the number of segment proofs already written to the spool.
    #[must_use]
    pub const fn segment_count(&self) -> u64 {
        self.segment_count
    }

    /// Returns the number of authenticated relation rows already spooled.
    #[must_use]
    pub const fn relation_step_count(&self) -> u64 {
        self.relation_step_count
    }

    /// Returns the exact encoded byte length of all spooled segment frames.
    #[must_use]
    pub const fn spooled_bytes(&self) -> u64 {
        self.spool_bytes
    }

    /// Returns the last verifier-checked public boundary, if any frame exists.
    #[must_use]
    pub const fn current_boundary(&self) -> Option<&NativeBoundary> {
        self.boundary.as_ref()
    }

    /// Returns the last verifier-checked mutable-memory commitment, if present.
    #[must_use]
    pub const fn current_memory_commitment(&self) -> Option<&MemoryCommitment> {
        self.previous_memory.as_ref()
    }

    /// Consumes this handle and returns its seekable segment spool.
    #[must_use]
    pub fn into_spool(self) -> S {
        self.spool
    }

    /// Proves and appends exactly one contiguous segment frame.
    pub fn append(&mut self, witness: NativeSegmentWitness<'_>) -> Result<(), NativeReceiptError> {
        let index = usize::try_from(self.segment_count).map_err(|_| NativeReceiptError::Counter)?;
        if index >= MAX_NATIVE_SEGMENT_COUNT {
            return Err(NativeReceiptError::InvalidStatement);
        }
        if let Some(memory) = self.previous_memory.as_ref() {
            ensure_same_memory(memory, witness.initial_memory.commitment())?;
        }
        let boundary = match &self.boundary {
            Some(boundary) => boundary.clone(),
            None => NativeBoundary::initial(
                NativeStateBoundary::from_vm_state(witness.trace.initial_state()),
                witness.initial_memory.commitment(),
            )?,
        };
        let proved = prove_frame(index, boundary, witness, self.rom)?;
        let frame_bytes = 8_u64
            .checked_add(
                u64::try_from(proved.encoded.len()).map_err(|_| NativeReceiptError::Counter)?,
            )
            .ok_or(NativeReceiptError::Counter)?;
        let next_spool_bytes = self
            .spool_bytes
            .checked_add(frame_bytes)
            .ok_or(NativeReceiptError::Counter)?;
        if next_spool_bytes > MAX_NATIVE_STREAM_RECEIPT_BYTES {
            return Err(NativeReceiptError::Wire(
                "stream receipt length limit".to_owned(),
            ));
        }
        self.spool.seek(SeekFrom::Start(self.spool_bytes))?;
        write_blob(&mut self.spool, &proved.encoded)?;
        self.relation_step_count = self
            .relation_step_count
            .checked_add(proved.active_row_count)
            .ok_or(NativeReceiptError::Counter)?;
        self.segment_count = self
            .segment_count
            .checked_add(1)
            .ok_or(NativeReceiptError::Counter)?;
        self.spool_bytes = next_spool_bytes;
        self.previous_memory = Some(proved.final_memory);
        self.initial.get_or_insert(proved.initial);
        self.boundary = Some(proved.final_boundary);
        Ok(())
    }

    /// Finalizes the public statement and copies canonical frames into `output`.
    pub fn finish<W: Write>(
        mut self,
        mut output: W,
    ) -> Result<NativeStatement, NativeReceiptError> {
        let initial = self.initial.ok_or(NativeReceiptError::InvalidStatement)?;
        let final_boundary = self.boundary.ok_or(NativeReceiptError::InvalidStatement)?;
        let statement = NativeStatement::new(
            direct_rom_identity(self.rom.commitment())?,
            initial,
            final_boundary,
            self.segment_count,
            self.relation_step_count,
        )?;
        let statement_bytes = encode_statement(&statement)?;
        let rom_bytes = encode_rom(self.rom.commitment())?;
        let header_bytes = header_length(statement_bytes.len(), rom_bytes.len())?;
        let total_bytes = header_bytes
            .checked_add(self.spool_bytes)
            .ok_or(NativeReceiptError::Counter)?;
        if total_bytes > MAX_NATIVE_STREAM_RECEIPT_BYTES {
            return Err(NativeReceiptError::Wire(
                "stream receipt length limit".to_owned(),
            ));
        }
        output.write_all(RECEIPT_MAGIC)?;
        output.write_all(&NATIVE_RECEIPT_VERSION.to_le_bytes())?;
        write_blob(&mut output, &statement_bytes)?;
        write_blob(&mut output, &rom_bytes)?;
        output.write_all(&self.segment_count.to_le_bytes())?;
        self.spool.seek(SeekFrom::Start(0))?;
        let copied = io::copy(
            &mut Read::by_ref(&mut self.spool).take(self.spool_bytes),
            &mut output,
        )?;
        if copied != self.spool_bytes {
            return Err(NativeReceiptError::Wire(
                "segment spool ended unexpectedly".to_owned(),
            ));
        }
        output.flush()?;
        Ok(statement)
    }
}

struct ProvedFrame {
    encoded: Vec<u8>,
    initial: NativeBoundary,
    final_boundary: NativeBoundary,
    final_memory: MemoryCommitment,
    active_row_count: u64,
}

fn prove_frame(
    index: usize,
    initial: NativeBoundary,
    witness: NativeSegmentWitness<'_>,
    rom: &CommittedRom,
) -> Result<ProvedFrame, NativeReceiptError> {
    crate::on_akita_worker(|| {
        let (receipt, final_boundary) = prove_segment(index, initial, witness, rom)?;
        let encoded = encode_segment(&receipt)?;
        Ok(ProvedFrame {
            encoded,
            initial: receipt.initial,
            final_boundary,
            final_memory: receipt.final_memory,
            active_row_count: receipt.active_row_count,
        })
    })
    .map_err(|error| match error {
        crate::AkitaWorkerError::Spawn(source) => NativeReceiptError::WorkerSpawn(source),
        crate::AkitaWorkerError::Panicked => NativeReceiptError::WorkerPanicked,
    })?
}

impl NativeReceiptStreamProver<'_, File> {
    /// Flushes completed segment frames to stable storage before checkpointing.
    pub fn sync_spool(&self) -> Result<(), NativeReceiptError> {
        self.spool.sync_data()?;
        Ok(())
    }
}

/// Incrementally verifies a canonical receipt while retaining at most one proof frame.
pub fn verify_native_receipt_reader<R: Read>(
    reader: R,
    expected: &NativeStatement,
) -> Result<VerifiedNativeReceipt, NativeReceiptError> {
    expected.validate()?;
    let mut reader = BoundedReader::new(reader);
    if reader.fixed::<8>()? != *RECEIPT_MAGIC {
        return Err(NativeReceiptError::Wire("receipt magic".to_owned()));
    }
    if reader.u64()? != NATIVE_RECEIPT_VERSION {
        return Err(NativeReceiptError::UnsupportedBackend);
    }
    let statement = NativeStatement::from_bytes(&reader.blob(MAX_NATIVE_STATEMENT_BYTES)?)?;
    if statement != *expected {
        return Err(NativeReceiptError::StatementMismatch);
    }
    let rom = decode_rom(&reader.blob(MAX_NATIVE_ROM_COMMITMENT_BYTES)?)?;
    if direct_rom_identity(&rom)? != statement.rom {
        return Err(NativeReceiptError::StatementMismatch);
    }
    let count = reader.usize(MAX_NATIVE_SEGMENT_COUNT)?;
    if u64::try_from(count).map_err(|_| NativeReceiptError::Counter)? != statement.segment_count {
        return Err(NativeReceiptError::StatementMismatch);
    }
    verify_frames(&mut reader, count, &statement, &rom)?;
    reader.finish()?;
    Ok(VerifiedNativeReceipt {
        statement_id: expected.statement_id,
        segment_count: expected.segment_count,
    })
}

fn verify_frames<R: Read>(
    reader: &mut BoundedReader<R>,
    count: usize,
    statement: &NativeStatement,
    rom: &crate::RomCommitment,
) -> Result<(), NativeReceiptError> {
    let mut boundary = statement.initial.clone();
    let mut previous_memory: Option<MemoryCommitment> = None;
    let mut steps = 0_u64;
    for index in 0..count {
        let segment = decode_segment(&reader.blob(MAX_NATIVE_SEGMENT_BYTES)?)?;
        if let Some(memory) = previous_memory.as_ref() {
            ensure_same_memory(memory, &segment.initial_memory)?;
        }
        verify_segment(index, &segment, &boundary, rom)?;
        steps = steps
            .checked_add(segment.active_row_count)
            .ok_or(NativeReceiptError::Counter)?;
        boundary = segment.final_boundary;
        previous_memory = Some(segment.final_memory);
    }
    if boundary != statement.final_boundary || steps != statement.relation_step_count {
        return Err(NativeReceiptError::SegmentChain(
            "final boundary or relation-step count differs from the statement",
        ));
    }
    Ok(())
}

struct SpoolProgress {
    initial: NativeBoundary,
    boundary: NativeBoundary,
    previous_memory: MemoryCommitment,
    segment_count: u64,
    relation_step_count: u64,
}

fn verify_spool<S: Read + Seek>(
    spool: &mut S,
    spool_bytes: u64,
    rom: &crate::RomCommitment,
) -> Result<SpoolProgress, NativeReceiptError> {
    let mut initial: Option<NativeBoundary> = None;
    let mut boundary: Option<NativeBoundary> = None;
    let mut previous_memory: Option<MemoryCommitment> = None;
    let mut segment_count = 0_u64;
    let mut relation_step_count = 0_u64;
    while spool.stream_position()? < spool_bytes {
        let index = usize::try_from(segment_count).map_err(|_| NativeReceiptError::Counter)?;
        if index >= MAX_NATIVE_SEGMENT_COUNT {
            return Err(NativeReceiptError::InvalidStatement);
        }
        let segment = decode_segment(&read_spool_frame(spool, spool_bytes)?)?;
        let expected_initial = match &boundary {
            Some(current) => current.clone(),
            None => NativeBoundary::initial(segment.initial.state, &segment.initial_memory)?,
        };
        if let Some(memory) = previous_memory.as_ref() {
            ensure_same_memory(memory, &segment.initial_memory)?;
        }
        verify_segment(index, &segment, &expected_initial, rom)?;
        relation_step_count = relation_step_count
            .checked_add(segment.active_row_count)
            .ok_or(NativeReceiptError::Counter)?;
        segment_count = segment_count
            .checked_add(1)
            .ok_or(NativeReceiptError::Counter)?;
        initial.get_or_insert(segment.initial);
        boundary = Some(segment.final_boundary);
        previous_memory = Some(segment.final_memory);
    }
    Ok(SpoolProgress {
        initial: initial.ok_or(NativeReceiptError::InvalidStatement)?,
        boundary: boundary.ok_or(NativeReceiptError::InvalidStatement)?,
        previous_memory: previous_memory.ok_or(NativeReceiptError::InvalidStatement)?,
        segment_count,
        relation_step_count,
    })
}

fn ensure_same_memory(
    left: &MemoryCommitment,
    right: &MemoryCommitment,
) -> Result<(), NativeReceiptError> {
    if direct_memory_identity(left)? != direct_memory_identity(right)? {
        return Err(NativeReceiptError::SegmentChain(
            "adjacent mutable-memory commitment identities differ",
        ));
    }
    Ok(())
}

fn read_spool_frame<S: Read + Seek>(
    spool: &mut S,
    spool_bytes: u64,
) -> Result<Vec<u8>, NativeReceiptError> {
    let mut length_bytes = [0_u8; 8];
    read_exact_wire(spool, &mut length_bytes)?;
    let length = usize::try_from(u64::from_le_bytes(length_bytes))
        .map_err(|_| NativeReceiptError::Counter)?;
    if length > MAX_NATIVE_SEGMENT_BYTES {
        return Err(NativeReceiptError::Wire(
            "component length limit".to_owned(),
        ));
    }
    let end = spool
        .stream_position()?
        .checked_add(u64::try_from(length).map_err(|_| NativeReceiptError::Counter)?)
        .ok_or(NativeReceiptError::Counter)?;
    if end > spool_bytes {
        return Err(NativeReceiptError::Wire(
            "segment spool ended unexpectedly".to_owned(),
        ));
    }
    let mut bytes = vec![0_u8; length];
    read_exact_wire(spool, &mut bytes)?;
    Ok(bytes)
}

fn read_exact_wire<R: Read>(reader: &mut R, bytes: &mut [u8]) -> Result<(), NativeReceiptError> {
    match reader.read_exact(bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Err(
            NativeReceiptError::Wire("receipt ended unexpectedly".to_owned()),
        ),
        Err(error) => Err(error.into()),
    }
}

fn header_length(statement_length: usize, rom_length: usize) -> Result<u64, NativeReceiptError> {
    let variable = statement_length
        .checked_add(rom_length)
        .ok_or(NativeReceiptError::Counter)?;
    40_u64
        .checked_add(u64::try_from(variable).map_err(|_| NativeReceiptError::Counter)?)
        .ok_or(NativeReceiptError::Counter)
}

fn write_blob<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<(), NativeReceiptError> {
    let length = u64::try_from(bytes.len()).map_err(|_| NativeReceiptError::Counter)?;
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(bytes)?;
    Ok(())
}

struct BoundedReader<R> {
    inner: R,
    consumed: u64,
}

impl<R: Read> BoundedReader<R> {
    const fn new(inner: R) -> Self {
        Self { inner, consumed: 0 }
    }

    fn fixed<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], NativeReceiptError> {
        let mut bytes = [0_u8; LENGTH];
        self.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn u64(&mut self) -> Result<u64, NativeReceiptError> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }

    fn usize(&mut self, maximum: usize) -> Result<usize, NativeReceiptError> {
        let length = usize::try_from(self.u64()?).map_err(|_| NativeReceiptError::Counter)?;
        if length > maximum {
            return Err(NativeReceiptError::Wire(
                "component length limit".to_owned(),
            ));
        }
        Ok(length)
    }

    fn blob(&mut self, maximum: usize) -> Result<Vec<u8>, NativeReceiptError> {
        let length = self.usize(maximum)?;
        let mut bytes = vec![0_u8; length];
        self.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn read_exact(&mut self, bytes: &mut [u8]) -> Result<(), NativeReceiptError> {
        let length = u64::try_from(bytes.len()).map_err(|_| NativeReceiptError::Counter)?;
        let next = self
            .consumed
            .checked_add(length)
            .ok_or(NativeReceiptError::Counter)?;
        if next > MAX_NATIVE_STREAM_RECEIPT_BYTES {
            return Err(NativeReceiptError::Wire(
                "stream receipt length limit".to_owned(),
            ));
        }
        match self.inner.read_exact(bytes) {
            Ok(()) => {
                self.consumed = next;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Err(
                NativeReceiptError::Wire("receipt ended unexpectedly".to_owned()),
            ),
            Err(error) => Err(error.into()),
        }
    }

    fn finish(mut self) -> Result<(), NativeReceiptError> {
        let mut trailing = [0_u8; 1];
        match self.inner.read(&mut trailing) {
            Ok(0) => Ok(()),
            Ok(_) => Err(NativeReceiptError::Wire(
                "receipt has trailing bytes".to_owned(),
            )),
            Err(error) => Err(error.into()),
        }
    }
}
