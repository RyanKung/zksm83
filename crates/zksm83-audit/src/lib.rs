#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Canonical Shout/Twist audit instances derived from the native bus transcript.
//!
//! This crate currently builds and checks the exact read-only and read-write
//! instance that the polynomial argument consumes. It is not itself a succinct
//! proof and deliberately uses the term `report`, not `receipt`.

mod fast_twist;
mod ipa;
mod isa_shout;
mod shout;
mod sumcheck;
mod twist;
mod uniform;
mod vm_glue;
mod vm_state;

pub use fast_twist::{CommittedInitialTwistProof, FastExplicitTwistProof, FastTwistError};
pub use ipa::{
    BatchedIpaLinearOpeningProof, BatchedIpaOpeningProof, IpaCommitment, IpaError, IpaOpeningProof,
    IpaParameters,
};
pub use isa_shout::{IsaAlignmentShoutError, IsaAlignmentShoutProof};
pub use shout::{
    CommittedMultiQueryShoutError, CommittedMultiQueryShoutProof, CommittedQueryShoutError,
    CommittedQueryShoutProof, CommittedShoutProof, ExplicitShoutError, ExplicitShoutProof,
    ReadOnlyQuery,
};
pub use twist::{ExplicitTwistError, ExplicitTwistProof, MemoryCycle};
pub use uniform::{
    CommittedShiftedUniformTraceProof, CommittedUniformTraceProof, ShiftedUniformRelation,
    UniformRelation, UniformTraceError,
};
pub use vm_glue::{
    CommittedVmIsaStructuralProof, CommittedVmStateStructuralProof, VmIsaSegmentError,
    VmIsaSegmentReceipt, VmIsaStructuralError, VmStateStructuralError, VmStateStructuralRelation,
    verify_vm_isa_segment_chain,
};
pub use vm_state::{
    VM_STATE_FIELD_COUNT, VM_STATE_FIELD_NAMES, encode_vm_state, encode_vm_state_columns,
};

use ff::Field;
use pasta_curves::Fp;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zksm83_core::BusEventKind;
use zksm83_memory::{
    BusTranscriptAccumulator, BusTranscriptError, BusTranscriptEvent, CommitmentRoot, MemoryImage,
    MemoryImageError, RomImage, RomImageError,
};

const ROM_ADDRESS_SPACE: usize = 1 << 20;
const MEMORY_ADDRESS_SPACE: usize = 1 << 17;

/// Exact counts and public boundary commitments of one checked audit segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LookupAuditReport {
    /// Immutable ROM commitment checked by every read-only ROM lookup.
    pub rom_root: CommitmentRoot,
    /// Mutable memory root before the segment.
    pub initial_memory_root: CommitmentRoot,
    /// Mutable memory root after applying every ordered write.
    pub final_memory_root: CommitmentRoot,
    /// Transcript prefix before the segment.
    pub initial_transcript: BusTranscriptAccumulator,
    /// Transcript prefix after the segment.
    pub final_transcript: BusTranscriptAccumulator,
    /// Read-only ROM lookups in the segment.
    pub rom_reads: u64,
    /// Mutable-memory reads in the segment.
    pub memory_reads: u64,
    /// Mutable-memory writes in the segment.
    pub memory_writes: u64,
    /// Non-ROM/RAM device and log events carried only by the common transcript.
    pub relation_only_events: u64,
}

/// Streaming constructor for the exact Shout/Twist audit witness.
#[derive(Debug)]
pub struct LookupAuditBuilder {
    rom: Vec<u8>,
    initial_memory: Vec<u8>,
    memory: Vec<u8>,
    rom_root: CommitmentRoot,
    initial_memory_root: CommitmentRoot,
    initial_transcript: BusTranscriptAccumulator,
    transcript: BusTranscriptAccumulator,
    rom_reads: u64,
    memory_reads: u64,
    memory_writes: u64,
    relation_only_events: u64,
    rom_queries: Vec<ReadOnlyQuery>,
    memory_cycles: Vec<MemoryCycle>,
}

/// Explicit-oracle Shout/Twist proofs for one ordered bus-transcript segment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExplicitLookupProof {
    rom: Option<ExplicitShoutProof>,
    memory: Option<FastExplicitTwistProof>,
}

/// Combined proof with a PCS-bound ROM Shout terminal and the current
/// explicit-oracle fast Twist memory terminal.
///
/// Verification does not receive ROM bytes. The caller must configure the
/// expected ROM IPA commitment and Poseidon ROM root as one trusted pair. The
/// ordered event vector remains explicit until the native relation binds it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommittedRomLookupProof {
    rom: Option<CommittedShoutProof>,
    memory: Option<FastExplicitTwistProof>,
}

/// PCS commitments for the immutable ROM and both mutable-memory boundaries.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LookupPcsBoundaries {
    /// Fixed 1 MiB ROM table commitment.
    pub rom: IpaCommitment,
    /// Mutable-memory commitment before the segment.
    pub initial_memory: IpaCommitment,
    /// Mutable-memory commitment after every ordered write in the segment.
    pub final_memory: IpaCommitment,
}

/// Combined Shout/Twist proof with PCS-bound ROM and mutable-memory terminals.
///
/// The event vector is still explicit. The native relation must bind that vector
/// and cross-bind these IPA commitments with the public Poseidon roots before
/// the main per-access Merkle path can be removed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommittedLookupProof {
    rom: Option<CommittedShoutProof>,
    memory: Option<CommittedInitialTwistProof>,
}

impl LookupAuditBuilder {
    /// Constructs an audit segment from exact ROM bytes, a complete mutable
    /// memory checkpoint, and the bus transcript prefix at the same boundary.
    pub fn new(
        rom: Vec<u8>,
        memory: Vec<u8>,
        initial_transcript: BusTranscriptAccumulator,
    ) -> Result<Self, LookupAuditError> {
        let rom_root = RomImage::new(rom.clone())?.root();
        let initial_memory_root = MemoryImage::from_checkpoint_bytes(memory.clone())?.root();
        Ok(Self {
            rom,
            initial_memory: memory.clone(),
            memory,
            rom_root,
            initial_memory_root,
            initial_transcript,
            transcript: initial_transcript,
            rom_reads: 0,
            memory_reads: 0,
            memory_writes: 0,
            relation_only_events: 0,
            rom_queries: Vec::new(),
            memory_cycles: Vec::new(),
        })
    }

    /// Checks and appends one relation event in its global execution order.
    pub fn accept(&mut self, event: BusTranscriptEvent) -> Result<(), LookupAuditError> {
        let kind = BusEventKind::try_from(event.kind)
            .map_err(|_| LookupAuditError::UnknownEventKind { kind: event.kind })?;
        match kind {
            BusEventKind::OpcodeFetch
            | BusEventKind::ImmediateRead
            | BusEventKind::RomRead
            | BusEventKind::DmgDmaRomRead => self.accept_rom_read(event)?,
            BusEventKind::MemoryRead
            | BusEventKind::MemoryOpcodeFetch
            | BusEventKind::MemoryImmediateRead
            | BusEventKind::DmgDmaMemoryRead => self.accept_memory_read(event)?,
            BusEventKind::MemoryWrite | BusEventKind::DmgDmaWrite => {
                self.accept_memory_write(event)?;
            }
            BusEventKind::Unused => return Err(LookupAuditError::UnusedEvent),
            BusEventKind::InputRead
            | BusEventKind::OutputWrite
            | BusEventKind::Mbc3ControlWrite
            | BusEventKind::Mbc3OpenBusRead
            | BusEventKind::Mbc3IgnoredWrite
            | BusEventKind::DmgMmioRead
            | BusEventKind::DmgMmioWrite
            | BusEventKind::DmgJoypadRead => increment(&mut self.relation_only_events)?,
        }
        self.transcript = self.transcript.append(event)?;
        Ok(())
    }

    /// Completes the segment, recomputes the final mutable-memory root, and
    /// returns both the checked report and final checkpoint bytes.
    pub fn finish(self) -> Result<(LookupAuditReport, Vec<u8>), LookupAuditError> {
        let final_memory_root = MemoryImage::from_checkpoint_bytes(self.memory.clone())?.root();
        Ok((
            LookupAuditReport {
                rom_root: self.rom_root,
                initial_memory_root: self.initial_memory_root,
                final_memory_root,
                initial_transcript: self.initial_transcript,
                final_transcript: self.transcript,
                rom_reads: self.rom_reads,
                memory_reads: self.memory_reads,
                memory_writes: self.memory_writes,
                relation_only_events: self.relation_only_events,
            },
            self.memory,
        ))
    }

    /// Completes the audit and also constructs the current explicit-oracle
    /// Shout ROM and Twist mutable-memory proofs.
    pub fn finish_with_explicit_proof(
        self,
    ) -> Result<(ExplicitLookupProof, LookupAuditReport, Vec<u8>), LookupAuditError> {
        let proof = ExplicitLookupProof::from_builder(&self)?;
        let (report, memory) = self.finish()?;
        Ok((proof, report, memory))
    }

    /// Completes the audit with a ROM PCS terminal and the current fast Twist
    /// memory proof.
    pub fn finish_with_committed_rom_proof(
        self,
        rom_parameters: &IpaParameters,
    ) -> Result<(CommittedRomLookupProof, LookupAuditReport, Vec<u8>), LookupAuditError> {
        let proof = CommittedRomLookupProof::from_builder(&self, rom_parameters)?;
        let (report, memory) = self.finish()?;
        Ok((proof, report, memory))
    }

    /// Completes the segment with PCS-bound ROM, initial-memory, and
    /// final-memory boundaries.
    pub fn finish_with_committed_proof(
        self,
        rom_parameters: &IpaParameters,
        memory_parameters: &IpaParameters,
    ) -> Result<
        (
            CommittedLookupProof,
            LookupPcsBoundaries,
            LookupAuditReport,
            Vec<u8>,
        ),
        LookupAuditError,
    > {
        let proof = CommittedLookupProof::from_builder(&self, rom_parameters, memory_parameters)?;
        let boundaries = proof.boundaries_from_builder(&self, rom_parameters, memory_parameters)?;
        let (report, memory) = self.finish()?;
        Ok((proof, boundaries, report, memory))
    }

    fn accept_rom_read(&mut self, event: BusTranscriptEvent) -> Result<(), LookupAuditError> {
        require_read_shape(event)?;
        let physical = physical_index(event, ROM_ADDRESS_SPACE)?;
        let expected = self.rom.get(physical).copied().unwrap_or(0);
        if event.value != expected {
            return Err(LookupAuditError::RomValueMismatch {
                physical_address: event.physical_address,
                expected,
                actual: event.value,
            });
        }
        self.rom_queries.push(ReadOnlyQuery {
            address: physical,
            value: Fp::from(u64::from(event.value)),
        });
        increment(&mut self.rom_reads)
    }

    fn accept_memory_read(&mut self, event: BusTranscriptEvent) -> Result<(), LookupAuditError> {
        require_read_shape(event)?;
        let physical = physical_index(event, MEMORY_ADDRESS_SPACE)?;
        let expected = self.memory.get(physical).copied().ok_or(
            LookupAuditError::PhysicalAddressOutOfRange {
                physical_address: event.physical_address,
            },
        )?;
        if event.value != expected {
            return Err(LookupAuditError::MemoryReadMismatch {
                physical_address: event.physical_address,
                expected,
                actual: event.value,
            });
        }
        self.memory_cycles.push(MemoryCycle::Read {
            address: event.physical_address,
            value: event.value,
        });
        increment(&mut self.memory_reads)
    }

    fn accept_memory_write(&mut self, event: BusTranscriptEvent) -> Result<(), LookupAuditError> {
        if event.auxiliary != 0 || event.index != 0 {
            return Err(LookupAuditError::NonCanonicalMemoryEvent);
        }
        let physical = physical_index(event, MEMORY_ADDRESS_SPACE)?;
        let target =
            self.memory
                .get_mut(physical)
                .ok_or(LookupAuditError::PhysicalAddressOutOfRange {
                    physical_address: event.physical_address,
                })?;
        if event.before != *target {
            return Err(LookupAuditError::MemoryWriteBeforeMismatch {
                physical_address: event.physical_address,
                expected: *target,
                actual: event.before,
            });
        }
        self.memory_cycles.push(MemoryCycle::Write {
            address: event.physical_address,
            before: event.before,
            after: event.value,
        });
        *target = event.value;
        increment(&mut self.memory_writes)
    }
}

impl ExplicitLookupProof {
    fn from_builder(builder: &LookupAuditBuilder) -> Result<Self, LookupAuditError> {
        let rom = if builder.rom_queries.is_empty() {
            None
        } else {
            Some(ExplicitShoutProof::prove(
                &fixed_rom_table(&builder.rom),
                &builder.rom_queries,
            )?)
        };
        let memory = if builder.memory_cycles.is_empty() {
            None
        } else {
            Some(FastExplicitTwistProof::prove(
                &builder.initial_memory,
                &builder.memory_cycles,
            )?)
        };
        Ok(Self { rom, memory })
    }

    /// Independently verifies the explicit proofs, the bus transcript, and
    /// both public memory boundaries against a claimed audit report.
    pub fn verify(
        &self,
        rom: &[u8],
        initial_memory: &[u8],
        initial_transcript: BusTranscriptAccumulator,
        events: &[BusTranscriptEvent],
        expected_report: &LookupAuditReport,
    ) -> Result<(), LookupAuditError> {
        let mut builder =
            LookupAuditBuilder::new(rom.to_vec(), initial_memory.to_vec(), initial_transcript)?;
        for event in events {
            builder.accept(*event)?;
        }
        match (&self.rom, builder.rom_queries.is_empty()) {
            (Some(proof), false) => {
                proof.verify(&fixed_rom_table(&builder.rom), &builder.rom_queries)?;
            }
            (None, true) => {}
            _ => return Err(LookupAuditError::ProofPresenceMismatch),
        }
        match (&self.memory, builder.memory_cycles.is_empty()) {
            (Some(proof), false) => {
                proof.verify(&builder.initial_memory, &builder.memory_cycles)?;
            }
            (None, true) => {}
            _ => return Err(LookupAuditError::ProofPresenceMismatch),
        }
        let (actual_report, _) = builder.finish()?;
        if &actual_report != expected_report {
            return Err(LookupAuditError::ReportMismatch);
        }
        Ok(())
    }

    /// Returns the sumcheck field-element count for the present subproofs.
    #[must_use]
    pub fn proof_field_elements(&self) -> usize {
        self.rom
            .as_ref()
            .map_or(0, ExplicitShoutProof::sumcheck_field_elements)
            .saturating_add(
                self.memory
                    .as_ref()
                    .map_or(0, FastExplicitTwistProof::proof_field_elements),
            )
    }
}

impl CommittedRomLookupProof {
    fn from_builder(
        builder: &LookupAuditBuilder,
        rom_parameters: &IpaParameters,
    ) -> Result<Self, LookupAuditError> {
        let rom = if builder.rom_queries.is_empty() {
            None
        } else {
            Some(CommittedShoutProof::prove(
                rom_parameters,
                &fixed_rom_table(&builder.rom),
                &builder.rom_queries,
            )?)
        };
        let memory = if builder.memory_cycles.is_empty() {
            None
        } else {
            Some(FastExplicitTwistProof::prove(
                &builder.initial_memory,
                &builder.memory_cycles,
            )?)
        };
        Ok(Self { rom, memory })
    }

    /// Verifies ROM lookups without ROM bytes, and independently replays the
    /// ordered mutable-memory and transcript boundaries.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        rom_parameters: &IpaParameters,
        expected_rom_commitment: IpaCommitment,
        expected_rom_root: CommitmentRoot,
        initial_memory: &[u8],
        initial_transcript: BusTranscriptAccumulator,
        events: &[BusTranscriptEvent],
        expected_report: &LookupAuditReport,
    ) -> Result<(), LookupAuditError> {
        let replay = CommittedReplay::new(initial_memory, initial_transcript)?;
        let replay = events.iter().try_fold(replay, |mut replay, event| {
            replay.accept(*event)?;
            Ok::<_, LookupAuditError>(replay)
        })?;
        match (&self.rom, replay.rom_queries.is_empty()) {
            (Some(proof), false) => {
                proof.verify(rom_parameters, expected_rom_commitment, &replay.rom_queries)?
            }
            (None, true) => {}
            _ => return Err(LookupAuditError::ProofPresenceMismatch),
        }
        match (&self.memory, replay.memory_cycles.is_empty()) {
            (Some(proof), false) => {
                proof.verify(&replay.initial_memory, &replay.memory_cycles)?;
            }
            (None, true) => {}
            _ => return Err(LookupAuditError::ProofPresenceMismatch),
        }
        let actual_report = replay.finish(expected_rom_root)?;
        if &actual_report != expected_report {
            return Err(LookupAuditError::ReportMismatch);
        }
        Ok(())
    }

    /// Returns the curve-point and scalar counts, excluding the explicit event
    /// and initial-memory vectors.
    #[must_use]
    pub fn proof_element_count(&self) -> (usize, usize) {
        let (rom_points, rom_scalars) = self
            .rom
            .as_ref()
            .map_or((0, 0), CommittedShoutProof::element_count);
        (
            rom_points,
            rom_scalars.saturating_add(
                self.memory
                    .as_ref()
                    .map_or(0, FastExplicitTwistProof::proof_field_elements),
            ),
        )
    }

    /// Returns the ROM table commitment when this segment contains ROM reads.
    #[must_use]
    pub fn rom_commitment(&self) -> Option<IpaCommitment> {
        self.rom.as_ref().map(CommittedShoutProof::table_commitment)
    }
}

impl CommittedLookupProof {
    fn from_builder(
        builder: &LookupAuditBuilder,
        rom_parameters: &IpaParameters,
        memory_parameters: &IpaParameters,
    ) -> Result<Self, LookupAuditError> {
        let rom = if builder.rom_queries.is_empty() {
            None
        } else {
            Some(CommittedShoutProof::prove(
                rom_parameters,
                &fixed_rom_table(&builder.rom),
                &builder.rom_queries,
            )?)
        };
        let memory = if builder.memory_cycles.is_empty() {
            None
        } else {
            Some(CommittedInitialTwistProof::prove(
                memory_parameters,
                &builder.initial_memory,
                &builder.memory_cycles,
            )?)
        };
        Ok(Self { rom, memory })
    }

    fn boundaries_from_builder(
        &self,
        builder: &LookupAuditBuilder,
        rom_parameters: &IpaParameters,
        memory_parameters: &IpaParameters,
    ) -> Result<LookupPcsBoundaries, LookupAuditError> {
        let rom = match &self.rom {
            Some(proof) => proof.table_commitment(),
            None => rom_parameters.commit(&fixed_rom_table(&builder.rom))?,
        };
        let initial_memory = match &self.memory {
            Some(proof) => proof.initial_commitment(),
            None => memory_parameters.commit(&memory_table(&builder.initial_memory))?,
        };
        let final_memory =
            apply_memory_cycles(memory_parameters, initial_memory, &builder.memory_cycles)?;
        Ok(LookupPcsBoundaries {
            rom,
            initial_memory,
            final_memory,
        })
    }

    /// Verifies all lookup terminals and both PCS memory boundaries without
    /// receiving ROM or initial-memory bytes.
    pub fn verify(
        &self,
        rom_parameters: &IpaParameters,
        memory_parameters: &IpaParameters,
        expected_boundaries: LookupPcsBoundaries,
        initial_transcript: BusTranscriptAccumulator,
        events: &[BusTranscriptEvent],
        expected_report: &LookupAuditReport,
    ) -> Result<(), LookupAuditError> {
        let replay =
            events
                .iter()
                .try_fold(PcsReplay::new(initial_transcript), |mut replay, event| {
                    replay.accept(*event)?;
                    Ok::<_, LookupAuditError>(replay)
                })?;
        match (&self.rom, replay.rom_queries.is_empty()) {
            (Some(proof), false) => {
                proof.verify(rom_parameters, expected_boundaries.rom, &replay.rom_queries)?
            }
            (None, true) => {}
            _ => return Err(LookupAuditError::ProofPresenceMismatch),
        }
        match (&self.memory, replay.memory_cycles.is_empty()) {
            (Some(proof), false) => proof.verify(
                memory_parameters,
                expected_boundaries.initial_memory,
                &replay.memory_cycles,
            )?,
            (None, true) => {}
            _ => return Err(LookupAuditError::ProofPresenceMismatch),
        }
        let final_memory = apply_memory_cycles(
            memory_parameters,
            expected_boundaries.initial_memory,
            &replay.memory_cycles,
        )?;
        if final_memory != expected_boundaries.final_memory {
            return Err(LookupAuditError::CommitmentBoundaryMismatch);
        }
        replay.verify_report(expected_report)?;
        Ok(())
    }

    /// Returns curve-point and scalar counts, excluding the explicit events.
    #[must_use]
    pub fn proof_element_count(&self) -> (usize, usize) {
        let (rom_points, rom_scalars) = self
            .rom
            .as_ref()
            .map_or((0, 0), CommittedShoutProof::element_count);
        let (memory_points, memory_scalars) = self
            .memory
            .as_ref()
            .map_or((0, 0), CommittedInitialTwistProof::proof_element_count);
        (
            rom_points.saturating_add(memory_points),
            rom_scalars.saturating_add(memory_scalars),
        )
    }
}

struct CommittedReplay {
    initial_memory: Vec<u8>,
    memory: Vec<u8>,
    initial_memory_root: CommitmentRoot,
    initial_transcript: BusTranscriptAccumulator,
    transcript: BusTranscriptAccumulator,
    rom_reads: u64,
    memory_reads: u64,
    memory_writes: u64,
    relation_only_events: u64,
    rom_queries: Vec<ReadOnlyQuery>,
    memory_cycles: Vec<MemoryCycle>,
}

impl CommittedReplay {
    fn new(
        initial_memory: &[u8],
        initial_transcript: BusTranscriptAccumulator,
    ) -> Result<Self, LookupAuditError> {
        let initial_memory_root =
            MemoryImage::from_checkpoint_bytes(initial_memory.to_vec())?.root();
        Ok(Self {
            initial_memory: initial_memory.to_vec(),
            memory: initial_memory.to_vec(),
            initial_memory_root,
            initial_transcript,
            transcript: initial_transcript,
            rom_reads: 0,
            memory_reads: 0,
            memory_writes: 0,
            relation_only_events: 0,
            rom_queries: Vec::new(),
            memory_cycles: Vec::new(),
        })
    }

    fn accept(&mut self, event: BusTranscriptEvent) -> Result<(), LookupAuditError> {
        let kind = BusEventKind::try_from(event.kind)
            .map_err(|_| LookupAuditError::UnknownEventKind { kind: event.kind })?;
        match kind {
            BusEventKind::OpcodeFetch
            | BusEventKind::ImmediateRead
            | BusEventKind::RomRead
            | BusEventKind::DmgDmaRomRead => self.accept_rom_read(event)?,
            BusEventKind::MemoryRead
            | BusEventKind::MemoryOpcodeFetch
            | BusEventKind::MemoryImmediateRead
            | BusEventKind::DmgDmaMemoryRead => self.accept_memory_read(event)?,
            BusEventKind::MemoryWrite | BusEventKind::DmgDmaWrite => {
                self.accept_memory_write(event)?;
            }
            BusEventKind::Unused => return Err(LookupAuditError::UnusedEvent),
            BusEventKind::InputRead
            | BusEventKind::OutputWrite
            | BusEventKind::Mbc3ControlWrite
            | BusEventKind::Mbc3OpenBusRead
            | BusEventKind::Mbc3IgnoredWrite
            | BusEventKind::DmgMmioRead
            | BusEventKind::DmgMmioWrite
            | BusEventKind::DmgJoypadRead => increment(&mut self.relation_only_events)?,
        }
        self.transcript = self.transcript.append(event)?;
        Ok(())
    }

    fn accept_rom_read(&mut self, event: BusTranscriptEvent) -> Result<(), LookupAuditError> {
        require_read_shape(event)?;
        let physical = physical_index(event, ROM_ADDRESS_SPACE)?;
        self.rom_queries.push(ReadOnlyQuery {
            address: physical,
            value: Fp::from(u64::from(event.value)),
        });
        increment(&mut self.rom_reads)
    }

    fn accept_memory_read(&mut self, event: BusTranscriptEvent) -> Result<(), LookupAuditError> {
        require_read_shape(event)?;
        let physical = physical_index(event, MEMORY_ADDRESS_SPACE)?;
        let expected = self.memory.get(physical).copied().ok_or(
            LookupAuditError::PhysicalAddressOutOfRange {
                physical_address: event.physical_address,
            },
        )?;
        if event.value != expected {
            return Err(LookupAuditError::MemoryReadMismatch {
                physical_address: event.physical_address,
                expected,
                actual: event.value,
            });
        }
        self.memory_cycles.push(MemoryCycle::Read {
            address: event.physical_address,
            value: event.value,
        });
        increment(&mut self.memory_reads)
    }

    fn accept_memory_write(&mut self, event: BusTranscriptEvent) -> Result<(), LookupAuditError> {
        if event.auxiliary != 0 || event.index != 0 {
            return Err(LookupAuditError::NonCanonicalMemoryEvent);
        }
        let physical = physical_index(event, MEMORY_ADDRESS_SPACE)?;
        let target =
            self.memory
                .get_mut(physical)
                .ok_or(LookupAuditError::PhysicalAddressOutOfRange {
                    physical_address: event.physical_address,
                })?;
        if event.before != *target {
            return Err(LookupAuditError::MemoryWriteBeforeMismatch {
                physical_address: event.physical_address,
                expected: *target,
                actual: event.before,
            });
        }
        self.memory_cycles.push(MemoryCycle::Write {
            address: event.physical_address,
            before: event.before,
            after: event.value,
        });
        *target = event.value;
        increment(&mut self.memory_writes)
    }

    fn finish(self, rom_root: CommitmentRoot) -> Result<LookupAuditReport, LookupAuditError> {
        let final_memory_root = MemoryImage::from_checkpoint_bytes(self.memory)?.root();
        Ok(LookupAuditReport {
            rom_root,
            initial_memory_root: self.initial_memory_root,
            final_memory_root,
            initial_transcript: self.initial_transcript,
            final_transcript: self.transcript,
            rom_reads: self.rom_reads,
            memory_reads: self.memory_reads,
            memory_writes: self.memory_writes,
            relation_only_events: self.relation_only_events,
        })
    }
}

struct PcsReplay {
    initial_transcript: BusTranscriptAccumulator,
    transcript: BusTranscriptAccumulator,
    rom_reads: u64,
    memory_reads: u64,
    memory_writes: u64,
    relation_only_events: u64,
    rom_queries: Vec<ReadOnlyQuery>,
    memory_cycles: Vec<MemoryCycle>,
}

impl PcsReplay {
    fn new(initial_transcript: BusTranscriptAccumulator) -> Self {
        Self {
            initial_transcript,
            transcript: initial_transcript,
            rom_reads: 0,
            memory_reads: 0,
            memory_writes: 0,
            relation_only_events: 0,
            rom_queries: Vec::new(),
            memory_cycles: Vec::new(),
        }
    }

    fn accept(&mut self, event: BusTranscriptEvent) -> Result<(), LookupAuditError> {
        let kind = BusEventKind::try_from(event.kind)
            .map_err(|_| LookupAuditError::UnknownEventKind { kind: event.kind })?;
        match kind {
            BusEventKind::OpcodeFetch
            | BusEventKind::ImmediateRead
            | BusEventKind::RomRead
            | BusEventKind::DmgDmaRomRead => {
                require_read_shape(event)?;
                let address = physical_index(event, ROM_ADDRESS_SPACE)?;
                self.rom_queries.push(ReadOnlyQuery {
                    address,
                    value: Fp::from(u64::from(event.value)),
                });
                increment(&mut self.rom_reads)?;
            }
            BusEventKind::MemoryRead
            | BusEventKind::MemoryOpcodeFetch
            | BusEventKind::MemoryImmediateRead
            | BusEventKind::DmgDmaMemoryRead => {
                require_read_shape(event)?;
                physical_index(event, MEMORY_ADDRESS_SPACE)?;
                self.memory_cycles.push(MemoryCycle::Read {
                    address: event.physical_address,
                    value: event.value,
                });
                increment(&mut self.memory_reads)?;
            }
            BusEventKind::MemoryWrite | BusEventKind::DmgDmaWrite => {
                if event.auxiliary != 0 || event.index != 0 {
                    return Err(LookupAuditError::NonCanonicalMemoryEvent);
                }
                physical_index(event, MEMORY_ADDRESS_SPACE)?;
                self.memory_cycles.push(MemoryCycle::Write {
                    address: event.physical_address,
                    before: event.before,
                    after: event.value,
                });
                increment(&mut self.memory_writes)?;
            }
            BusEventKind::Unused => return Err(LookupAuditError::UnusedEvent),
            BusEventKind::InputRead
            | BusEventKind::OutputWrite
            | BusEventKind::Mbc3ControlWrite
            | BusEventKind::Mbc3OpenBusRead
            | BusEventKind::Mbc3IgnoredWrite
            | BusEventKind::DmgMmioRead
            | BusEventKind::DmgMmioWrite
            | BusEventKind::DmgJoypadRead => increment(&mut self.relation_only_events)?,
        }
        self.transcript = self.transcript.append(event)?;
        Ok(())
    }

    fn verify_report(&self, report: &LookupAuditReport) -> Result<(), LookupAuditError> {
        if report.initial_transcript != self.initial_transcript
            || report.final_transcript != self.transcript
            || report.rom_reads != self.rom_reads
            || report.memory_reads != self.memory_reads
            || report.memory_writes != self.memory_writes
            || report.relation_only_events != self.relation_only_events
        {
            return Err(LookupAuditError::ReportMismatch);
        }
        Ok(())
    }
}

/// A bus transcript failed the exact lookup-memory instance relation.
#[derive(Debug, Error)]
pub enum LookupAuditError {
    /// The ROM image could not be committed.
    #[error(transparent)]
    Rom(#[from] RomImageError),
    /// The mutable checkpoint could not be committed.
    #[error(transparent)]
    Memory(#[from] MemoryImageError),
    /// The common ordered transcript could not advance.
    #[error(transparent)]
    Transcript(#[from] BusTranscriptError),
    /// The explicit Shout ROM proof failed.
    #[error(transparent)]
    Shout(#[from] ExplicitShoutError),
    /// The explicit Twist mutable-memory proof failed.
    #[error(transparent)]
    Twist(#[from] ExplicitTwistError),
    /// The fast explicit Twist mutable-memory proof failed.
    #[error(transparent)]
    FastTwist(#[from] FastTwistError),
    /// A polynomial commitment operation failed.
    #[error(transparent)]
    Commitment(#[from] IpaError),
    /// Proof presence disagrees with whether the segment contains lookups.
    #[error("lookup proof presence does not match the audit segment")]
    ProofPresenceMismatch,
    /// Recomputed public boundaries or counts differ from the claimed report.
    #[error("lookup audit report mismatch")]
    ReportMismatch,
    /// Sparse writes did not produce the claimed final PCS memory boundary.
    #[error("lookup final-memory PCS commitment mismatch")]
    CommitmentBoundaryMismatch,
    /// Padding is not a relation event and cannot enter the audit trace.
    #[error("unused padding event cannot enter lookup audit")]
    UnusedEvent,
    /// The five-bit event code is outside the stable relation enum.
    #[error("unknown bus event kind {kind}")]
    UnknownEventKind {
        /// Rejected code.
        kind: u8,
    },
    /// A physical ROM or RAM index exceeds its declared table.
    #[error("physical address 0x{physical_address:05x} is outside the audit table")]
    PhysicalAddressOutOfRange {
        /// Rejected index.
        physical_address: u32,
    },
    /// A read carried fields reserved for writes, input, or devices.
    #[error("read-only lookup event has non-canonical auxiliary fields")]
    NonCanonicalRead,
    /// A memory event carried device/log-only auxiliary fields.
    #[error("mutable-memory event has non-canonical auxiliary fields")]
    NonCanonicalMemoryEvent,
    /// A ROM lookup returned a byte different from the committed table.
    #[error("ROM lookup at 0x{physical_address:05x} expected 0x{expected:02x}, got 0x{actual:02x}")]
    RomValueMismatch {
        /// Physical ROM byte index.
        physical_address: u32,
        /// Committed table value.
        expected: u8,
        /// Claimed read value.
        actual: u8,
    },
    /// A RAM read did not return the latest value.
    #[error(
        "memory read at 0x{physical_address:05x} expected 0x{expected:02x}, got 0x{actual:02x}"
    )]
    MemoryReadMismatch {
        /// Physical mutable-memory byte index.
        physical_address: u32,
        /// Latest value.
        expected: u8,
        /// Claimed read value.
        actual: u8,
    },
    /// A RAM write's before-value did not match the latest value.
    #[error(
        "memory write at 0x{physical_address:05x} expected before 0x{expected:02x}, got 0x{actual:02x}"
    )]
    MemoryWriteBeforeMismatch {
        /// Physical mutable-memory byte index.
        physical_address: u32,
        /// Latest value before the write.
        expected: u8,
        /// Claimed before-value.
        actual: u8,
    },
    /// A 64-bit audit counter overflowed.
    #[error("lookup audit counter overflow")]
    CounterOverflow,
}

fn fixed_rom_table(rom: &[u8]) -> Vec<Fp> {
    let mut table = vec![Fp::ZERO; ROM_ADDRESS_SPACE];
    for (target, value) in table.iter_mut().zip(rom) {
        *target = Fp::from(u64::from(*value));
    }
    table
}

fn memory_table(memory: &[u8]) -> Vec<Fp> {
    memory
        .iter()
        .map(|value| Fp::from(u64::from(*value)))
        .collect()
}

fn apply_memory_cycles(
    parameters: &IpaParameters,
    initial: IpaCommitment,
    cycles: &[MemoryCycle],
) -> Result<IpaCommitment, LookupAuditError> {
    let updates = cycles
        .iter()
        .filter_map(|cycle| match cycle {
            MemoryCycle::Read { .. } => None,
            MemoryCycle::Write {
                address,
                before,
                after,
            } => Some((*address, *before, *after)),
        })
        .map(|(address, before, after)| {
            let address = usize::try_from(address).map_err(|_| {
                LookupAuditError::PhysicalAddressOutOfRange {
                    physical_address: address,
                }
            })?;
            Ok((
                address,
                Fp::from(u64::from(after)) - Fp::from(u64::from(before)),
            ))
        })
        .collect::<Result<Vec<_>, LookupAuditError>>()?;
    Ok(parameters.apply_updates(initial, &updates)?)
}

fn require_read_shape(event: BusTranscriptEvent) -> Result<(), LookupAuditError> {
    if event.before != 0 || event.auxiliary != 0 || event.index != 0 {
        return Err(LookupAuditError::NonCanonicalRead);
    }
    Ok(())
}

fn physical_index(event: BusTranscriptEvent, table_size: usize) -> Result<usize, LookupAuditError> {
    let physical = usize::try_from(event.physical_address).map_err(|_| {
        LookupAuditError::PhysicalAddressOutOfRange {
            physical_address: event.physical_address,
        }
    })?;
    if physical >= table_size {
        return Err(LookupAuditError::PhysicalAddressOutOfRange {
            physical_address: event.physical_address,
        });
    }
    Ok(physical)
}

fn increment(value: &mut u64) -> Result<(), LookupAuditError> {
    *value = value
        .checked_add(1)
        .ok_or(LookupAuditError::CounterOverflow)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{env, fs, io, time::Instant};

    use zksm83_core::BusEventKind;
    use zksm83_isa::AlignedInstruction;
    use zksm83_memory::{BusTranscriptAccumulator, BusTranscriptEvent, MemoryImage, RomImage};
    use zksm83_trace::TraceBuilder;

    use super::{IpaParameters, IsaAlignmentShoutProof, LookupAuditBuilder, ROM_ADDRESS_SPACE};

    const BLUE_ROM_ENV: &str = "ZKSM83_BLUE_ROM";

    fn read_blue_rom() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let path = env::var_os(BLUE_ROM_ENV)
            .ok_or_else(|| io::Error::other(format!("{BLUE_ROM_ENV} is not set")))?;
        Ok(fs::read(path)?)
    }

    fn event(
        kind: BusEventKind,
        physical_address: u32,
        before: u8,
        value: u8,
    ) -> BusTranscriptEvent {
        BusTranscriptEvent {
            kind: kind.code(),
            address: u16::try_from(physical_address).unwrap_or(0),
            physical_address,
            before,
            auxiliary: 0,
            value,
            index: 0,
        }
    }

    #[test]
    fn checks_rom_and_latest_ram_values_in_order() -> Result<(), Box<dyn std::error::Error>> {
        let rom = vec![0x00, 0x42];
        let memory = MemoryImage::zeroed()?.checkpoint_bytes();
        let mut audit = LookupAuditBuilder::new(rom, memory, BusTranscriptAccumulator::empty())?;
        audit.accept(event(BusEventKind::OpcodeFetch, 0, 0, 0x00))?;
        audit.accept(event(BusEventKind::MemoryWrite, 0xc000, 0, 0x5a))?;
        audit.accept(event(BusEventKind::MemoryRead, 0xc000, 0, 0x5a))?;
        let (report, _) = audit.finish()?;
        assert_eq!(report.rom_reads, 1);
        assert_eq!(report.memory_reads, 1);
        assert_eq!(report.memory_writes, 1);
        assert_eq!(report.final_transcript.next_index(), 3);
        assert_ne!(report.initial_memory_root, report.final_memory_root);
        Ok(())
    }

    #[test]
    fn rejects_wrong_rom_read_and_stale_ram_before_value() -> Result<(), Box<dyn std::error::Error>>
    {
        let memory = MemoryImage::zeroed()?.checkpoint_bytes();
        let mut wrong_rom = LookupAuditBuilder::new(
            vec![0x00],
            memory.clone(),
            BusTranscriptAccumulator::empty(),
        )?;
        assert!(
            wrong_rom
                .accept(event(BusEventKind::OpcodeFetch, 0, 0, 1))
                .is_err()
        );

        let mut stale =
            LookupAuditBuilder::new(vec![0x00], memory, BusTranscriptAccumulator::empty())?;
        stale.accept(event(BusEventKind::MemoryWrite, 0xc000, 0, 0x5a))?;
        assert!(
            stale
                .accept(event(BusEventKind::MemoryWrite, 0xc000, 0, 0x33))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn trace_events_reproduce_native_transcript_and_memory_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let rom_bytes = vec![
            0x21, 0x00, 0xc0, // LD HL,c000
            0x36, 0x5a, // LD (HL),5a
            0x7e, // LD A,(HL)
        ];
        let memory = MemoryImage::zeroed()?;
        let initial_memory = memory.checkpoint_bytes();
        let witness = TraceBuilder::new(RomImage::new(rom_bytes.clone())?, memory, Vec::new())
            .run_exact_steps(3)?;
        let initial = witness.initial_state();
        let mut audit = LookupAuditBuilder::new(
            rom_bytes.clone(),
            initial_memory.clone(),
            initial.bus_transcript(),
        )?;
        let events = witness
            .rows()
            .flat_map(|row| row.effects().bus_events())
            .map(|event| event.transcript_event())
            .collect::<Vec<_>>();
        for event in &events {
            audit.accept(*event)?;
        }
        let (proof, report, _) = audit.finish_with_explicit_proof()?;
        let final_state = witness.final_state();
        assert_eq!(report.final_transcript, final_state.bus_transcript());
        assert_eq!(report.final_memory_root, final_state.memory_root());
        assert_eq!(report.rom_reads, 6);
        assert_eq!(report.memory_reads, 1);
        assert_eq!(report.memory_writes, 1);
        proof.verify(
            &rom_bytes,
            &initial_memory,
            initial.bus_transcript(),
            &events,
            &report,
        )?;
        assert!(proof.proof_field_elements() > 0);
        Ok(())
    }

    #[test]
    #[ignore = "requires the user's locally supplied Pokémon Blue ROM"]
    fn blue_isa_shout_matches_the_native_transcript_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let rom = RomImage::new(read_blue_rom()?)?;
        let trace = TraceBuilder::new_dmg_post_boot_mbc3(rom, MemoryImage::zeroed()?, Vec::new())
            .run_exact_steps(60)?;
        let rows = trace
            .rows()
            .map(|row| AlignedInstruction::from_decoded(row.effects().instruction()))
            .collect::<Vec<_>>();
        let initial = trace.initial_state().isa_transcript();
        let final_transcript = trace.final_state().isa_transcript();
        let proof = IsaAlignmentShoutProof::prove_segment(initial, &rows)?;
        proof.verify_segment(initial, final_transcript, &rows)?;
        assert_eq!(proof.initial_transcript(), initial);
        assert_eq!(proof.final_transcript(), final_transcript);
        assert_eq!(final_transcript.next_index(), rows.len() as u64);
        Ok(())
    }

    #[test]
    #[ignore = "costly 1 MiB PCS gate over the user's locally supplied Pokémon Blue ROM"]
    fn blue_full_rom_committed_shout_round_trip_without_rom_at_verification()
    -> Result<(), Box<dyn std::error::Error>> {
        let rom_bytes = read_blue_rom()?;
        let memory = MemoryImage::zeroed()?;
        let initial_memory = memory.checkpoint_bytes();
        let trace = TraceBuilder::new_dmg_post_boot_mbc3(
            RomImage::new(rom_bytes.clone())?,
            memory,
            Vec::new(),
        )
        .run_exact_steps(60)?;
        let events = trace
            .rows()
            .flat_map(|row| row.effects().bus_events())
            .map(|event| event.transcript_event())
            .collect::<Vec<_>>();
        let initial_transcript = trace.initial_state().bus_transcript();
        let mut audit =
            LookupAuditBuilder::new(rom_bytes, initial_memory.clone(), initial_transcript)?;
        for event in &events {
            audit.accept(*event)?;
        }

        let setup_started = Instant::now();
        let parameters = IpaParameters::new(ROM_ADDRESS_SPACE)?;
        let setup_elapsed = setup_started.elapsed();
        let prove_started = Instant::now();
        let (proof, report, _) = audit.finish_with_committed_rom_proof(&parameters)?;
        let prove_elapsed = prove_started.elapsed();
        let commitment = proof
            .rom_commitment()
            .ok_or_else(|| std::io::Error::other("Blue trace contains no ROM reads"))?;
        let verify_started = Instant::now();
        proof.verify(
            &parameters,
            commitment,
            report.rom_root,
            &initial_memory,
            initial_transcript,
            &events,
            &report,
        )?;
        let verify_elapsed = verify_started.elapsed();
        let (points, scalars) = proof.proof_element_count();
        eprintln!(
            "blue-rom-pcs table_bytes={} events={} rom_reads={} setup_ms={} prove_ms={} verify_ms={} proof_points={} proof_scalars={}",
            ROM_ADDRESS_SPACE,
            events.len(),
            report.rom_reads,
            setup_elapsed.as_millis(),
            prove_elapsed.as_millis(),
            verify_elapsed.as_millis(),
            points,
            scalars,
        );

        let mut tampered_events = events.clone();
        let rom_event = tampered_events
            .iter_mut()
            .find(|event| {
                matches!(
                    BusEventKind::try_from(event.kind),
                    Ok(BusEventKind::OpcodeFetch
                        | BusEventKind::ImmediateRead
                        | BusEventKind::RomRead
                        | BusEventKind::DmgDmaRomRead)
                )
            })
            .ok_or_else(|| std::io::Error::other("Blue trace contains no mutable ROM event"))?;
        rom_event.value ^= 1;
        assert!(
            proof
                .verify(
                    &parameters,
                    commitment,
                    report.rom_root,
                    &initial_memory,
                    initial_transcript,
                    &tampered_events,
                    &report,
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    #[ignore = "costly full PCS gate over the user's locally supplied Pokémon Blue ROM"]
    fn blue_full_committed_lookup_round_trip_without_rom_or_initial_memory_at_verification()
    -> Result<(), Box<dyn std::error::Error>> {
        let rom_bytes = read_blue_rom()?;
        let memory = MemoryImage::zeroed()?;
        let initial_memory = memory.checkpoint_bytes();
        let trace = TraceBuilder::new_dmg_post_boot_mbc3(
            RomImage::new(rom_bytes.clone())?,
            memory,
            Vec::new(),
        )
        .run_exact_steps(60)?;
        let events = trace
            .rows()
            .flat_map(|row| row.effects().bus_events())
            .map(|event| event.transcript_event())
            .collect::<Vec<_>>();
        let initial_transcript = trace.initial_state().bus_transcript();
        let mut audit = LookupAuditBuilder::new(rom_bytes, initial_memory, initial_transcript)?;
        for event in &events {
            audit.accept(*event)?;
        }

        let setup_started = Instant::now();
        let rom_parameters = IpaParameters::new(ROM_ADDRESS_SPACE)?;
        let memory_parameters = IpaParameters::new(super::MEMORY_ADDRESS_SPACE)?;
        let setup_elapsed = setup_started.elapsed();
        let prove_started = Instant::now();
        let (proof, boundaries, report, final_memory) =
            audit.finish_with_committed_proof(&rom_parameters, &memory_parameters)?;
        let prove_elapsed = prove_started.elapsed();
        let verify_started = Instant::now();
        proof.verify(
            &rom_parameters,
            &memory_parameters,
            boundaries,
            initial_transcript,
            &events,
            &report,
        )?;
        let verify_elapsed = verify_started.elapsed();
        assert_eq!(
            boundaries.final_memory,
            memory_parameters.commit(&super::memory_table(&final_memory))?
        );
        let (points, scalars) = proof.proof_element_count();
        eprintln!(
            "blue-full-pcs rom_bytes={} memory_bytes={} events={} rom_reads={} memory_reads={} memory_writes={} setup_ms={} prove_ms={} verify_ms={} proof_points={} proof_scalars={}",
            ROM_ADDRESS_SPACE,
            super::MEMORY_ADDRESS_SPACE,
            events.len(),
            report.rom_reads,
            report.memory_reads,
            report.memory_writes,
            setup_elapsed.as_millis(),
            prove_elapsed.as_millis(),
            verify_elapsed.as_millis(),
            points,
            scalars,
        );

        let mut tampered_events = events.clone();
        let memory_event = tampered_events
            .iter_mut()
            .find(|event| {
                matches!(
                    BusEventKind::try_from(event.kind),
                    Ok(BusEventKind::MemoryRead
                        | BusEventKind::MemoryOpcodeFetch
                        | BusEventKind::MemoryImmediateRead
                        | BusEventKind::DmgDmaMemoryRead
                        | BusEventKind::MemoryWrite
                        | BusEventKind::DmgDmaWrite)
                )
            })
            .ok_or_else(|| std::io::Error::other("Blue trace contains no mutable-memory event"))?;
        memory_event.value ^= 1;
        assert!(
            proof
                .verify(
                    &rom_parameters,
                    &memory_parameters,
                    boundaries,
                    initial_transcript,
                    &tampered_events,
                    &report,
                )
                .is_err()
        );
        Ok(())
    }
}
