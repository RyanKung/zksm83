//! Bounded canonical wire primitives for native receipt objects.

use akita_serialization::{AkitaDeserialize, AkitaSerialize, SerializationError};
use akita_types::{
    AkitaBatchedProof, AkitaBatchedProofShape, CommittedGroup, OpeningScheduleSelection,
    ScheduleRowDigest,
};
use thiserror::Error;

use crate::{
    NativeField,
    block_proof::PackedBlockProof,
    continuity::{ContinuitySumProof, PackedContinuityProof},
    isa_lookup::{FixedIsaCommitments, IsaLookupProof},
    logs::{PackedProtocolLogProof, ProtocolLogCommitments, sum::ProtocolLogSumProof},
    memory::{
        MemoryCommitment, PackedMutableMemoryProof, clock::ClockProof, sum::MultisetSumProof,
    },
    pcs::{ColumnCommitments, GroupOpeningProof, OpeningProof},
    rom_lookup::{RomCommitment, RomLookupProof},
    sumcheck::{ProductSumcheckProof, SumOfProductsSumcheckProof},
    uniform::{CompositeUniformRelationProof, UniformRelationProof, WitnessCommitments},
};

const MAX_SEQUENCE_LENGTH: usize = 1 << 20;
const MAX_BLOB_LENGTH: usize = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub(crate) enum WireError {
    #[error("native receipt wire input ended unexpectedly")]
    UnexpectedEnd,
    #[error("native receipt wire length exceeds its protocol bound")]
    LengthLimit,
    #[error("native receipt wire value has an invalid shape")]
    Shape,
    #[error("native receipt wire input has trailing bytes")]
    TrailingBytes,
    #[error("Akita receipt component decoding failed: {0}")]
    Akita(#[from] SerializationError),
}

pub(crate) trait Wire: Sized {
    fn encode(&self, writer: &mut WireWriter) -> Result<(), WireError>;
    fn decode(reader: &mut WireReader<'_>) -> Result<Self, WireError>;
}

pub(crate) struct WireWriter {
    bytes: Vec<u8>,
}

pub(crate) struct WireReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl WireWriter {
    pub(crate) const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }

    pub(crate) fn raw(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    pub(crate) fn blob(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        self.usize(bytes.len())?;
        self.raw(bytes);
        Ok(())
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.raw(&value.to_le_bytes());
    }

    pub(crate) fn usize(&mut self, value: usize) -> Result<(), WireError> {
        self.u64(u64::try_from(value).map_err(|_| WireError::LengthLimit)?);
        Ok(())
    }
}

impl<'a> WireReader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) fn finish(self) -> Result<(), WireError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes)
        }
    }

    pub(crate) fn raw(&mut self, length: usize) -> Result<&'a [u8], WireError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(WireError::LengthLimit)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(WireError::UnexpectedEnd)?;
        self.offset = end;
        Ok(bytes)
    }

    pub(crate) fn fixed<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], WireError> {
        self.raw(LENGTH)?.try_into().map_err(|_| WireError::Shape)
    }

    pub(crate) fn blob(&mut self, maximum: usize) -> Result<&'a [u8], WireError> {
        let length = self.usize(maximum)?;
        self.raw(length)
    }

    pub(crate) fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }

    pub(crate) fn usize(&mut self, maximum: usize) -> Result<usize, WireError> {
        let encoded = self.u64()?;
        let value = usize::try_from(encoded).map_err(|_| WireError::LengthLimit)?;
        if value > maximum {
            return Err(WireError::LengthLimit);
        }
        Ok(value)
    }
}

impl Wire for usize {
    fn encode(&self, writer: &mut WireWriter) -> Result<(), WireError> {
        writer.usize(*self)
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self, WireError> {
        reader.usize(MAX_SEQUENCE_LENGTH)
    }
}

impl Wire for NativeField {
    fn encode(&self, writer: &mut WireWriter) -> Result<(), WireError> {
        let mut bytes = Vec::new();
        self.serialize_compressed(&mut bytes)?;
        writer.blob(&bytes)
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self, WireError> {
        let bytes = reader.blob(32)?;
        Self::deserialize_compressed_exact(bytes, &()).map_err(Into::into)
    }
}

impl<T: Wire> Wire for Vec<T> {
    fn encode(&self, writer: &mut WireWriter) -> Result<(), WireError> {
        writer.usize(self.len())?;
        for value in self {
            value.encode(writer)?;
        }
        Ok(())
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self, WireError> {
        let length = reader.usize(MAX_SEQUENCE_LENGTH)?;
        let mut values = Vec::with_capacity(length);
        for _ in 0..length {
            values.push(T::decode(reader)?);
        }
        Ok(values)
    }
}

impl Wire for [NativeField; 3] {
    fn encode(&self, writer: &mut WireWriter) -> Result<(), WireError> {
        for value in self {
            value.encode(writer)?;
        }
        Ok(())
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self, WireError> {
        let values = (0..3)
            .map(|_| NativeField::decode(reader))
            .collect::<Result<Vec<_>, _>>()?;
        values.try_into().map_err(|_| WireError::Shape)
    }
}

impl Wire for CommittedGroup<NativeField> {
    fn encode(&self, writer: &mut WireWriter) -> Result<(), WireError> {
        encode_akita(self, writer)
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self, WireError> {
        decode_akita(reader, &())
    }
}

impl Wire for OpeningScheduleSelection {
    fn encode(&self, writer: &mut WireWriter) -> Result<(), WireError> {
        writer.raw(self.row_digest.as_bytes());
        Ok(())
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self, WireError> {
        Ok(Self {
            row_digest: ScheduleRowDigest::from_bytes(reader.fixed()?),
        })
    }
}

impl Wire for AkitaBatchedProof<NativeField, NativeField> {
    fn encode(&self, writer: &mut WireWriter) -> Result<(), WireError> {
        let shape = self.shape();
        encode_akita(&shape, writer)?;
        encode_akita(self, writer)
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self, WireError> {
        let shape: AkitaBatchedProofShape = decode_akita(reader, &())?;
        decode_akita(reader, &shape)
    }
}

fn encode_akita<T: AkitaSerialize>(value: &T, writer: &mut WireWriter) -> Result<(), WireError> {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes)?;
    if bytes.len() > MAX_BLOB_LENGTH {
        return Err(WireError::LengthLimit);
    }
    writer.blob(&bytes)
}

fn decode_akita<T: AkitaDeserialize>(
    reader: &mut WireReader<'_>,
    context: &T::Context,
) -> Result<T, WireError> {
    let bytes = reader.blob(MAX_BLOB_LENGTH)?;
    T::deserialize_compressed_exact(bytes, context).map_err(Into::into)
}

macro_rules! wire_struct {
    ($type:path { $($field:ident),+ $(,)? }) => {
        impl Wire for $type {
            fn encode(&self, writer: &mut WireWriter) -> Result<(), WireError> {
                $(self.$field.encode(writer)?;)+
                Ok(())
            }

            fn decode(reader: &mut WireReader<'_>) -> Result<Self, WireError> {
                Ok(Self {
                    $($field: Wire::decode(reader)?,)+
                })
            }
        }
    };
}

wire_struct!(ColumnCommitments {
    num_variables,
    logical_column_count,
    group_columns,
    groups,
});
wire_struct!(WitnessCommitments { inner });
wire_struct!(OpeningProof { groups });
wire_struct!(GroupOpeningProof {
    selection,
    opened_values,
    proof,
});
wire_struct!(ProductSumcheckProof {
    rounds,
    final_left,
    final_right,
});
wire_struct!(SumOfProductsSumcheckProof {
    rounds,
    final_terms,
});
wire_struct!(UniformRelationProof {
    logical_column_count,
    sumcheck_rounds,
    opened_values,
    opening,
});
wire_struct!(CompositeUniformRelationProof {
    rounds,
    left_values,
    right_values,
    left_opening,
    right_opening,
});
wire_struct!(FixedIsaCommitments { inner });
wire_struct!(IsaLookupProof {
    table_commitments,
    claimed_output,
    table_sumcheck,
    address_sumcheck,
    table_values,
    trace_cycle_values,
    trace_address_values,
    table_opening,
    trace_cycle_opening,
    trace_address_opening,
});
wire_struct!(RomCommitment { inner });
wire_struct!(RomLookupProof {
    claimed_output,
    table_sumcheck,
    address_sumcheck,
    table_values,
    trace_cycle_values,
    trace_address_values,
    table_opening,
    trace_cycle_opening,
    trace_address_opening,
});
wire_struct!(MemoryCommitment { inner });
wire_struct!(ClockProof { values, opening });
wire_struct!(crate::memory::boundary::ColumnOpening { values, proof });
wire_struct!(crate::memory::boundary::BoundaryProof {
    sumcheck,
    initial_value,
    final_value,
    final_timestamp,
    initial_inverse,
    final_inverse,
});
wire_struct!(MultisetSumProof {
    trace_values,
    initial_values,
    final_values,
    trace_opening,
    initial_opening,
    final_opening,
});
wire_struct!(PackedMutableMemoryProof {
    final_timestamps,
    trace_inverses,
    initial_inverses,
    final_inverses,
    event_relation,
    clock,
    boundary,
    multiset_sum,
});
wire_struct!(ContinuitySumProof { values, opening });
wire_struct!(PackedContinuityProof {
    inverse_commitments,
    relation,
    sum,
});
wire_struct!(ProtocolLogCommitments { inner });
wire_struct!(crate::logs::table_relation::ColumnOpening { values, proof });
wire_struct!(crate::logs::table_relation::TableRelationProof {
    sumcheck,
    logs,
    inverses,
});
wire_struct!(ProtocolLogSumProof {
    trace_values,
    log_values,
    table_inverse_values,
    trace_opening,
    log_opening,
    table_inverse_opening,
});
wire_struct!(PackedProtocolLogProof {
    trace_inverses,
    table_inverses,
    trace_relation,
    table_relation,
    sum,
});
wire_struct!(PackedBlockProof {
    commitments,
    relation,
    isa_lookup,
    rom_lookup,
    memory,
    continuity,
    logs,
});
