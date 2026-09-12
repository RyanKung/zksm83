//! Ordered commitment to the bus events consumed by the proof relation.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{CommitmentRoot, HashDomain, hash_parts};

/// Canonical event tuple committed by the native and recursive relations.
///
/// Fields use an unambiguous fixed-width byte encoding. Authentication paths
/// are deliberately excluded: the event
/// describes the logical read or write that a later lookup-memory audit must
/// check, rather than committing to the temporary Merkle proof mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BusTranscriptEvent {
    /// Stable event-kind code in the low five bits.
    pub kind: u8,
    /// CPU-visible logical address.
    pub address: u16,
    /// Mapper-derived ROM or RAM byte address, or zero for device events.
    pub physical_address: u32,
    /// Prior byte for writes and selected device events.
    pub before: u8,
    /// Event-specific auxiliary byte, currently used by joypad samples.
    pub auxiliary: u8,
    /// Read, written, or returned byte.
    pub value: u8,
    /// Event-local ordered-log index, or zero when unused.
    pub index: u64,
}

impl BusTranscriptEvent {
    fn canonical_bytes(self, transcript_index: u64) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(26);
        bytes.push(self.kind);
        bytes.extend_from_slice(&self.address.to_le_bytes());
        bytes.extend_from_slice(&self.physical_address.to_le_bytes());
        bytes.push(self.before);
        bytes.push(self.auxiliary);
        bytes.push(self.value);
        bytes.extend_from_slice(&self.index.to_le_bytes());
        bytes.extend_from_slice(&transcript_index.to_le_bytes());
        bytes
    }
}

/// Prefix commitment and next ordinal of the proof-relation bus transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BusTranscriptAccumulator {
    next_index: u64,
    root: CommitmentRoot,
}

impl BusTranscriptAccumulator {
    /// Returns the domain-separated empty transcript.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            next_index: 0,
            root: hash_parts(HashDomain::BusTranscriptEmpty, &[], &[]),
        }
    }

    /// Appends one canonical event in relation order.
    pub fn append(self, event: BusTranscriptEvent) -> Result<Self, BusTranscriptError> {
        if event.kind >= 19 || event.physical_address >= 1_u32 << 20 {
            return Err(BusTranscriptError::NonCanonicalEvent);
        }
        let next_index = self
            .next_index
            .checked_add(1)
            .ok_or(BusTranscriptError::IndexOverflow)?;
        let encoded = event.canonical_bytes(self.next_index);
        let root = hash_parts(
            HashDomain::BusTranscriptElement,
            &self.root.to_bytes(),
            &encoded,
        );
        Ok(Self { next_index, root })
    }

    /// Returns the ordinal assigned to the next event.
    #[must_use]
    pub const fn next_index(self) -> u64 {
        self.next_index
    }

    /// Returns the current ordered prefix root.
    #[must_use]
    pub const fn root(self) -> CommitmentRoot {
        self.root
    }
}

/// Failure to extend the canonical bus transcript.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BusTranscriptError {
    /// The 64-bit global event ordinal cannot advance.
    #[error("bus transcript index overflow")]
    IndexOverflow,
    /// A tuple field exceeds the fixed protocol bit allocation.
    #[error("bus transcript event is not canonically encodable")]
    NonCanonicalEvent,
}

#[cfg(test)]
mod tests {
    use super::{BusTranscriptAccumulator, BusTranscriptEvent};

    fn event(value: u8) -> BusTranscriptEvent {
        BusTranscriptEvent {
            kind: 4,
            address: 0xc123,
            physical_address: 0xc123,
            before: 0,
            auxiliary: 0,
            value,
            index: 0,
        }
    }

    #[test]
    fn commits_event_values_and_order() -> Result<(), Box<dyn std::error::Error>> {
        let empty = BusTranscriptAccumulator::empty();
        let first = empty.append(event(7))?;
        let second = first.append(event(9))?;
        let reversed = empty.append(event(9))?.append(event(7))?;
        assert_eq!(second.next_index(), 2);
        assert_ne!(first.root(), second.root());
        assert_ne!(second.root(), reversed.root());
        Ok(())
    }

    #[test]
    fn rejects_out_of_range_kind_and_physical_address() {
        let mut invalid_kind = event(7);
        invalid_kind.kind = 19;
        assert!(
            BusTranscriptAccumulator::empty()
                .append(invalid_kind)
                .is_err()
        );

        let mut invalid_address = event(7);
        invalid_address.physical_address = 1 << 20;
        assert!(
            BusTranscriptAccumulator::empty()
                .append(invalid_address)
                .is_err()
        );
    }
}
