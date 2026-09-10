//! Shout instance for the fixed 512-address SM83 alignment table.

use ff::{Field, PrimeField};
use pasta_curves::Fp;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zksm83_isa::{AlignedInstruction, AlignmentPackingError};
use zksm83_memory::{IsaTranscriptAccumulator, IsaTranscriptError};

use crate::{ExplicitShoutError, ExplicitShoutProof, ReadOnlyQuery};

const ISA_TABLE_SIZE: usize = 512;

/// Explicit-oracle Shout proof for raw opcode to semantic-row alignment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IsaAlignmentShoutProof {
    proof: ExplicitShoutProof,
    initial_transcript: IsaTranscriptAccumulator,
    final_transcript: IsaTranscriptAccumulator,
}

impl IsaAlignmentShoutProof {
    /// Proves that every supplied full semantic row is the unique table value
    /// at its primary or CB-prefixed opcode address.
    pub fn prove(rows: &[AlignedInstruction]) -> Result<Self, IsaAlignmentShoutError> {
        Self::prove_segment(IsaTranscriptAccumulator::empty(), rows)
    }

    /// Proves a segment and binds its rows to exact ISA transcript boundaries.
    pub fn prove_segment(
        initial_transcript: IsaTranscriptAccumulator,
        rows: &[AlignedInstruction],
    ) -> Result<Self, IsaAlignmentShoutError> {
        let table = alignment_table()?;
        let queries = alignment_queries(rows)?;
        let final_transcript = append_transcript(initial_transcript, rows)?;
        Ok(Self {
            proof: ExplicitShoutProof::prove(&table, &queries)?,
            initial_transcript,
            final_transcript,
        })
    }

    /// Verifies the alignment batch against the fixed 501-row proof ISA.
    pub fn verify(&self, rows: &[AlignedInstruction]) -> Result<(), IsaAlignmentShoutError> {
        self.verify_segment(self.initial_transcript, self.final_transcript, rows)
    }

    /// Verifies alignment and exact initial/final ISA transcript boundaries.
    pub fn verify_segment(
        &self,
        initial_transcript: IsaTranscriptAccumulator,
        final_transcript: IsaTranscriptAccumulator,
        rows: &[AlignedInstruction],
    ) -> Result<(), IsaAlignmentShoutError> {
        if self.initial_transcript != initial_transcript
            || self.final_transcript != final_transcript
            || append_transcript(initial_transcript, rows)? != final_transcript
        {
            return Err(IsaAlignmentShoutError::TranscriptMismatch);
        }
        let table = alignment_table()?;
        let queries = alignment_queries(rows)?;
        self.proof.verify(&table, &queries)?;
        Ok(())
    }

    /// Returns the number of quadratic-sumcheck field elements.
    #[must_use]
    pub fn sumcheck_field_elements(&self) -> usize {
        self.proof.sumcheck_field_elements()
    }

    /// Returns the ISA transcript boundary before this proof segment.
    #[must_use]
    pub const fn initial_transcript(&self) -> IsaTranscriptAccumulator {
        self.initial_transcript
    }

    /// Returns the ISA transcript boundary after this proof segment.
    #[must_use]
    pub const fn final_transcript(&self) -> IsaTranscriptAccumulator {
        self.final_transcript
    }
}

/// The SM83 alignment Shout instance or proof is invalid.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum IsaAlignmentShoutError {
    /// At least one aligned instruction is required.
    #[error("ISA alignment Shout batch is empty")]
    EmptyBatch,
    /// A row did not fit its canonical 106-bit semantic encoding.
    #[error("ISA alignment row packing failed")]
    Packing,
    /// The underlying explicit-oracle Shout proof failed.
    #[error("ISA alignment Shout proof failed")]
    Shout,
    /// A table address calculation exceeded the fixed 512-row space.
    #[error("ISA alignment address is outside the fixed table")]
    AddressInvariant,
    /// Packed rows do not reproduce the claimed ISA transcript boundary.
    #[error("ISA alignment transcript boundary mismatch")]
    TranscriptMismatch,
    /// The ordered ISA transcript could not advance.
    #[error("ISA alignment transcript append failed")]
    Transcript,
}

impl From<AlignmentPackingError> for IsaAlignmentShoutError {
    fn from(_: AlignmentPackingError) -> Self {
        Self::Packing
    }
}

impl From<ExplicitShoutError> for IsaAlignmentShoutError {
    fn from(_: ExplicitShoutError) -> Self {
        Self::Shout
    }
}

impl From<IsaTranscriptError> for IsaAlignmentShoutError {
    fn from(_: IsaTranscriptError) -> Self {
        Self::Transcript
    }
}

fn append_transcript(
    initial: IsaTranscriptAccumulator,
    rows: &[AlignedInstruction],
) -> Result<IsaTranscriptAccumulator, IsaAlignmentShoutError> {
    rows.iter().try_fold(initial, |transcript, row| {
        Ok(transcript.append(row.packed()?)?)
    })
}

pub(crate) fn alignment_table() -> Result<Vec<Fp>, IsaAlignmentShoutError> {
    let mut table = vec![Fp::ZERO; ISA_TABLE_SIZE];
    for row in AlignedInstruction::all() {
        let address = alignment_address(row)?;
        let target = table
            .get_mut(address)
            .ok_or(IsaAlignmentShoutError::AddressInvariant)?;
        *target = packed_field(row.packed()?);
    }
    Ok(table)
}

fn alignment_queries(
    rows: &[AlignedInstruction],
) -> Result<Vec<ReadOnlyQuery>, IsaAlignmentShoutError> {
    if rows.is_empty() {
        return Err(IsaAlignmentShoutError::EmptyBatch);
    }
    rows.iter()
        .copied()
        .map(|row| {
            Ok(ReadOnlyQuery {
                address: alignment_address(row)?,
                value: packed_field(row.packed()?),
            })
        })
        .collect()
}

fn alignment_address(row: AlignedInstruction) -> Result<usize, IsaAlignmentShoutError> {
    let prefix = usize::from(row.key.prefix);
    let address = prefix
        .checked_mul(256)
        .and_then(|prefix| prefix.checked_add(usize::from(row.key.opcode)))
        .ok_or(IsaAlignmentShoutError::AddressInvariant)?;
    if address >= ISA_TABLE_SIZE {
        return Err(IsaAlignmentShoutError::AddressInvariant);
    }
    Ok(address)
}

fn packed_field(packed: u128) -> Fp {
    Fp::from_u128(packed)
}

#[cfg(test)]
mod tests {
    use zksm83_isa::AlignedInstruction;
    use zksm83_memory::IsaTranscriptAccumulator;

    use super::IsaAlignmentShoutProof;

    #[test]
    fn isa_shout_aligns_complete_rows_and_rejects_metadata_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let rows = AlignedInstruction::all().take(7).collect::<Vec<_>>();
        let proof = IsaAlignmentShoutProof::prove(&rows)?;
        proof.verify(&rows)?;
        assert_eq!(proof.sumcheck_field_elements(), 27);

        let mut wrong = rows.clone();
        let row = wrong
            .get_mut(3)
            .ok_or_else(|| std::io::Error::other("missing fourth ISA row"))?;
        row.base_m_cycles = row.base_m_cycles.saturating_add(1);
        assert!(proof.verify(&wrong).is_err());
        let wrong_proof = IsaAlignmentShoutProof::prove(&wrong)?;
        assert!(wrong_proof.verify(&wrong).is_err());

        let segment =
            IsaAlignmentShoutProof::prove_segment(IsaTranscriptAccumulator::empty(), &rows)?;
        let incomplete = rows.iter().take(6).try_fold(
            IsaTranscriptAccumulator::empty(),
            |transcript, row| {
                Ok::<_, Box<dyn std::error::Error>>(transcript.append(row.packed()?)?)
            },
        )?;
        assert!(
            segment
                .verify_segment(IsaTranscriptAccumulator::empty(), incomplete, &rows)
                .is_err()
        );
        Ok(())
    }
}
