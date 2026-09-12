//! Ordered input and output commitments.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{CommitmentRoot, HashDomain, hash_parts};

/// Domain of an ordered byte-log commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LogKind {
    /// Private input bytes consumed by the VM.
    Input,
    /// Public output bytes produced by the VM.
    Output,
}

/// Prefix commitment and next index of an ordered byte log.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LogAccumulator {
    kind: LogKind,
    next_index: u64,
    root: CommitmentRoot,
}

impl LogAccumulator {
    /// Returns the domain-separated empty accumulator.
    #[must_use]
    pub fn empty(kind: LogKind) -> Self {
        let domain = match kind {
            LogKind::Input => HashDomain::InputEmpty,
            LogKind::Output => HashDomain::OutputEmpty,
        };
        Self {
            kind,
            next_index: 0,
            root: hash_parts(domain, &[], &[]),
        }
    }

    /// Appends one byte and returns the extended accumulator.
    pub fn append(self, value: u8) -> Result<Self, LogError> {
        let next_index = self
            .next_index
            .checked_add(1)
            .ok_or(LogError::IndexOverflow)?;
        let domain = match self.kind {
            LogKind::Input => HashDomain::InputElement,
            LogKind::Output => HashDomain::OutputElement,
        };
        let mut element = Vec::with_capacity(9);
        element.extend_from_slice(&self.next_index.to_le_bytes());
        element.push(value);
        let root = hash_parts(domain, &self.root.to_bytes(), &element);
        Ok(Self {
            kind: self.kind,
            next_index,
            root,
        })
    }

    /// Commits a complete byte slice in order.
    pub fn commit(kind: LogKind, values: &[u8]) -> Result<Self, LogError> {
        values
            .iter()
            .try_fold(Self::empty(kind), |accumulator, value| {
                accumulator.append(*value)
            })
    }

    /// Returns the log domain.
    #[must_use]
    pub const fn kind(self) -> LogKind {
        self.kind
    }

    /// Returns the index assigned to the next appended byte.
    #[must_use]
    pub const fn next_index(self) -> u64 {
        self.next_index
    }

    /// Returns the current prefix root.
    #[must_use]
    pub const fn root(self) -> CommitmentRoot {
        self.root
    }
}

/// Failure to extend an ordered byte log.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LogError {
    /// The 64-bit element index cannot be advanced.
    #[error("ordered log index overflow")]
    IndexOverflow,
}
