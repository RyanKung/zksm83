#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Authenticated immutable ROM and mutable byte-memory commitments.

mod address;
mod bus_transcript;
mod commitment;
mod image;
mod isa_transcript;
mod log;
mod transcript;

pub use address::{AddressOwner, INPUT_PORT, OUTPUT_PORT, dmg_owner, owner};
pub use bus_transcript::{BusTranscriptAccumulator, BusTranscriptError, BusTranscriptEvent};
pub use commitment::{CommitmentRoot, HashDomain, hash_parts};
pub use image::{MemoryImage, MemoryImageError, RomImage, RomImageError};
pub use isa_transcript::{IsaTranscriptAccumulator, IsaTranscriptError};
pub use log::{LogAccumulator, LogError, LogKind};
pub use transcript::{
    MemoryAccess, MemoryRead, MemoryTranscript, MemoryTranscriptError, MemoryWrite, MerklePath,
    RomRead, RomReadError,
};
