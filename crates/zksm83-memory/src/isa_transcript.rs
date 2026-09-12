//! Ordered commitment to ISA-alignment rows consumed by the proof relation.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{CommitmentRoot, HashDomain, hash_parts};

const PACKED_ROW_BITS: u64 = 106;
const PACKED_ROW_LIMIT: u128 = 1_u128 << PACKED_ROW_BITS;

/// Prefix commitment and next ordinal of the proof-relation ISA transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IsaTranscriptAccumulator {
    next_index: u64,
    root: CommitmentRoot,
}

impl IsaTranscriptAccumulator {
    /// Returns the domain-separated empty transcript.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            next_index: 0,
            root: hash_parts(HashDomain::IsaTranscriptEmpty, &[], &[]),
        }
    }

    /// Appends one collision-free packed ISA row in relation order.
    pub fn append(self, packed_row: u128) -> Result<Self, IsaTranscriptError> {
        if packed_row >= PACKED_ROW_LIMIT {
            return Err(IsaTranscriptError::NonCanonicalRow);
        }
        let next_index = self
            .next_index
            .checked_add(1)
            .ok_or(IsaTranscriptError::IndexOverflow)?;
        let mut row = Vec::with_capacity(24);
        row.extend_from_slice(&self.next_index.to_le_bytes());
        row.extend_from_slice(&packed_row.to_le_bytes());
        let root = hash_parts(
            HashDomain::IsaTranscriptElement,
            &self.root.to_bytes(),
            &row,
        );
        Ok(Self { next_index, root })
    }

    /// Returns the ordinal assigned to the next row.
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

/// Failure to extend the canonical ISA transcript.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum IsaTranscriptError {
    /// The 64-bit global row ordinal cannot advance.
    #[error("ISA transcript index overflow")]
    IndexOverflow,
    /// The row exceeds the fixed 106-bit ISA encoding.
    #[error("ISA transcript row is not canonically encodable")]
    NonCanonicalRow,
}

#[cfg(test)]
mod tests {
    use super::{IsaTranscriptAccumulator, IsaTranscriptError};

    #[test]
    fn commits_rows_and_order() -> Result<(), IsaTranscriptError> {
        let empty = IsaTranscriptAccumulator::empty();
        let first = empty.append(7)?;
        let second = first.append(9)?;
        let reversed = empty.append(9)?.append(7)?;

        assert_eq!(second.next_index(), 2);
        assert_ne!(first.root(), second.root());
        assert_ne!(second.root(), reversed.root());
        Ok(())
    }

    #[test]
    fn rejects_rows_outside_encoding() {
        assert_eq!(
            IsaTranscriptAccumulator::empty().append(1_u128 << 106),
            Err(IsaTranscriptError::NonCanonicalRow)
        );
    }
}
