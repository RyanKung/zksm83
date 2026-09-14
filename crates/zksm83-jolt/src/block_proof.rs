//! Shared-commitment proof composition for the packed-block v2 witness.

use thiserror::Error;
use zksm83_trace::{BASIC_BLOCK_INSTRUCTION_BOUND, BasicBlockLaneIndex};

use crate::{
    BlockCpuRelation, BlockCpuWitness, BlockFrontendError, CommittedMemory, CommittedProtocolLogs,
    CommittedRom, CommittedWitness, ContinuityError, IsaLookupError, IsaLookupProof,
    MemoryCommitment, MutableMemoryError, NativeExecutionClaim, NativeProtocolVersion,
    PackedContinuityProof, PackedMutableMemoryProof, PackedProtocolLogClaim,
    PackedProtocolLogProof, ProtocolLogCommitments, ProtocolLogError, RomCommitment,
    RomLookupError, RomLookupProof, UniformError, UniformRelationProof, WitnessCommitments,
    commit_witness, prove_isa_lookup, prove_packed_continuity, prove_packed_mutable_memory,
    prove_packed_protocol_logs, prove_rom_lookup, prove_uniform_committed,
};
use crate::{
    continuity::verify_packed_continuity_for_protocol, isa_lookup::verify_isa_lookup_for_protocol,
    logs::verify_packed_protocol_logs_for_protocol,
    memory::verify_packed_mutable_memory_for_protocol, rom_lookup::verify_rom_lookup_for_protocol,
    uniform::verify_uniform_committed_for_protocol,
};

/// Number of independent fixed-ISA queries carried by one packed block row.
pub const PACKED_BLOCK_ISA_LOOKUP_COUNT: usize = BASIC_BLOCK_INSTRUCTION_BOUND;

const PACKED_LANES: [BasicBlockLaneIndex; PACKED_BLOCK_ISA_LOOKUP_COUNT] = [
    BasicBlockLaneIndex::Lane0,
    BasicBlockLaneIndex::Lane1,
    BasicBlockLaneIndex::Lane2,
    BasicBlockLaneIndex::Lane3,
];

const _: () = assert!(PACKED_BLOCK_ISA_LOOKUP_COUNT == 4);

pub(crate) struct PackedBlockVerificationInputs<'a> {
    pub(crate) claim: &'a NativeExecutionClaim,
    pub(crate) log_claim: PackedProtocolLogClaim,
    pub(crate) logs: &'a ProtocolLogCommitments,
    pub(crate) rom: &'a RomCommitment,
    pub(crate) initial_memory: &'a MemoryCommitment,
    pub(crate) final_memory: &'a MemoryCommitment,
}

/// Proof components that all open one packed-block witness commitment plane.
///
/// This object authenticates the current deepest row-local relation, four fixed
/// ISA lookups, immutable-ROM reads, mutable-memory chronology, cross-row state
/// continuity, and canonical-position ordered logs. A v2 segment receipt
/// serializes this object together with its public boundaries and commitments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackedBlockProof {
    pub(crate) commitments: WitnessCommitments,
    pub(crate) relation: UniformRelationProof,
    pub(crate) isa_lookups: [IsaLookupProof; PACKED_BLOCK_ISA_LOOKUP_COUNT],
    pub(crate) rom_lookup: RomLookupProof,
    pub(crate) memory: PackedMutableMemoryProof,
    pub(crate) continuity: PackedContinuityProof,
    pub(crate) logs: PackedProtocolLogProof,
}

/// Failure to build or verify the packed-block component proof.
#[derive(Debug, Error)]
pub enum PackedBlockProofError {
    /// A stable lookup layout could not be derived from the packed prefix.
    #[error(transparent)]
    Frontend(#[from] BlockFrontendError),
    /// The shared commitment or deepest uniform relation failed.
    #[error(transparent)]
    Uniform(#[from] UniformError),
    /// One fixed-ISA lookup failed.
    #[error(transparent)]
    IsaLookup(#[from] IsaLookupError),
    /// The immutable-ROM lookup failed.
    #[error(transparent)]
    RomLookup(#[from] RomLookupError),
    /// The packed mutable-memory proof failed.
    #[error(transparent)]
    MutableMemory(#[from] MutableMemoryError),
    /// The packed state chain or its public endpoints failed.
    #[error(transparent)]
    Continuity(#[from] ContinuityError),
    /// The packed ordered-log argument failed.
    #[error(transparent)]
    ProtocolLog(#[from] ProtocolLogError),
}

impl PackedBlockProof {
    /// Returns the commitments shared by every packed-block proof component.
    #[must_use]
    pub const fn commitments(&self) -> &WitnessCommitments {
        &self.commitments
    }
}

/// Proves all currently authenticated packed-block components on one commitment plane.
///
/// The operation performs PCS work and is therefore not part of proof-free
/// validation. Callers that only need bounded relation checking should use
/// [`crate::validate_uniform_witness`] with [`BlockCpuRelation`].
pub fn prove_packed_block_components(
    trace: &BlockCpuWitness,
    claim: &NativeExecutionClaim,
    log_claim: PackedProtocolLogClaim,
    logs: &CommittedProtocolLogs,
    rom: &CommittedRom,
    initial_memory: &CommittedMemory,
    final_memory: &CommittedMemory,
) -> Result<PackedBlockProof, PackedBlockProofError> {
    let witness = commit_witness(trace.columns())?;
    let relation = prove_uniform_committed(&BlockCpuRelation, &witness)?;
    let isa_lookups = [
        prove_lane_lookup(BasicBlockLaneIndex::Lane0, &witness)?,
        prove_lane_lookup(BasicBlockLaneIndex::Lane1, &witness)?,
        prove_lane_lookup(BasicBlockLaneIndex::Lane2, &witness)?,
        prove_lane_lookup(BasicBlockLaneIndex::Lane3, &witness)?,
    ];
    let rom_lookup = prove_rom_lookup(BlockCpuWitness::rom_lookup_columns()?, rom, &witness)?;
    let memory = prove_packed_mutable_memory(trace, &witness, initial_memory, final_memory)?;
    let continuity = prove_packed_continuity(trace, &witness, claim)?;
    let logs = prove_packed_protocol_logs(trace, &witness, logs, claim, log_claim)?;
    Ok(PackedBlockProof {
        commitments: witness.into_commitments(),
        relation,
        isa_lookups,
        rom_lookup,
        memory,
        continuity,
        logs,
    })
}

/// Verifies all currently authenticated packed-block components without replaying execution.
pub fn verify_packed_block_components(
    proof: &PackedBlockProof,
    claim: &NativeExecutionClaim,
    log_claim: PackedProtocolLogClaim,
    logs: &ProtocolLogCommitments,
    rom: &RomCommitment,
    initial_memory: &MemoryCommitment,
    final_memory: &MemoryCommitment,
) -> Result<(), PackedBlockProofError> {
    verify_packed_block_components_for_protocol(
        NativeProtocolVersion::current(),
        proof,
        PackedBlockVerificationInputs {
            claim,
            log_claim,
            logs,
            rom,
            initial_memory,
            final_memory,
        },
    )
}

pub(crate) fn verify_packed_block_components_for_protocol(
    protocol: NativeProtocolVersion,
    proof: &PackedBlockProof,
    inputs: PackedBlockVerificationInputs<'_>,
) -> Result<(), PackedBlockProofError> {
    verify_uniform_committed_for_protocol(
        protocol,
        &BlockCpuRelation,
        &proof.commitments,
        &proof.relation,
    )?;
    for (lane, lookup) in PACKED_LANES.into_iter().zip(proof.isa_lookups.iter()) {
        verify_isa_lookup_for_protocol(
            protocol,
            BlockCpuWitness::lane_isa_lookup_columns(lane)?,
            &proof.commitments,
            lookup,
        )?;
    }
    verify_rom_lookup_for_protocol(
        protocol,
        BlockCpuWitness::rom_lookup_columns()?,
        inputs.rom,
        &proof.commitments,
        &proof.rom_lookup,
    )?;
    verify_packed_mutable_memory_for_protocol(
        protocol,
        &proof.memory,
        &proof.commitments,
        inputs.initial_memory,
        inputs.final_memory,
    )?;
    verify_packed_continuity_for_protocol(
        protocol,
        &proof.continuity,
        &proof.commitments,
        inputs.claim,
    )?;
    verify_packed_protocol_logs_for_protocol(
        protocol,
        &proof.logs,
        &proof.commitments,
        inputs.logs,
        inputs.claim,
        inputs.log_claim,
    )?;
    Ok(())
}

fn prove_lane_lookup(
    lane: BasicBlockLaneIndex,
    witness: &CommittedWitness,
) -> Result<IsaLookupProof, PackedBlockProofError> {
    let layout = BlockCpuWitness::lane_isa_lookup_columns(lane)?;
    prove_isa_lookup(layout, witness).map_err(Into::into)
}
