//! Canonical SHA-256 commitment values and domain-separated hashing.

use std::fmt::{Display, Formatter};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};
use sha2::{Digest, Sha256};

const HASH_PROTOCOL: &[u8] = b"zksm83/witness-auth-sha256/v1";

/// Canonically encoded 32-byte Merkle or ordered-log root.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CommitmentRoot([u8; 32]);

impl CommitmentRoot {
    /// Constructs a root from its exact 32-byte digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the all-zero value used only for empty authentication paths.
    #[must_use]
    pub const fn zero() -> Self {
        Self([0; 32])
    }

    /// Returns the exact 32-byte digest.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns the lowercase canonical hexadecimal encoding.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.to_bytes())
    }
}

impl Display for CommitmentRoot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl Serialize for CommitmentRoot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for CommitmentRoot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(&encoded, &mut bytes).map_err(D::Error::custom)?;
        Ok(Self::from_bytes(bytes))
    }
}

/// Domain tag for one witness-side authentication hash invocation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HashDomain {
    /// ROM byte leaf.
    RomLeaf,
    /// Mutable-memory byte leaf.
    MemoryLeaf,
    /// ROM internal node at the contained zero-based level.
    RomNode(u8),
    /// Mutable-memory internal node at the contained zero-based level.
    MemoryNode(u8),
    /// Empty ordered input log.
    InputEmpty,
    /// Empty ordered output log.
    OutputEmpty,
    /// Ordered input-log element.
    InputElement,
    /// Ordered output-log element.
    OutputElement,
    /// Empty ordered proof-relation bus transcript.
    BusTranscriptEmpty,
    /// Ordered proof-relation bus event.
    BusTranscriptElement,
    /// Empty ordered ISA-alignment transcript.
    IsaTranscriptEmpty,
    /// Ordered packed ISA-alignment row.
    IsaTranscriptElement,
}

impl HashDomain {
    fn code(self) -> u16 {
        match self {
            Self::RomLeaf => 0x1000,
            Self::MemoryLeaf => 0x2000,
            Self::RomNode(level) => 0x3000 + u16::from(level),
            Self::MemoryNode(level) => 0x4000 + u16::from(level),
            Self::InputEmpty => 0x5000,
            Self::OutputEmpty => 0x6000,
            Self::InputElement => 0x7000,
            Self::OutputElement => 0x8000,
            Self::BusTranscriptEmpty => 0x9000,
            Self::BusTranscriptElement => 0xa000,
            Self::IsaTranscriptEmpty => 0xb000,
            Self::IsaTranscriptElement => 0xc000,
        }
    }
}

/// Hashes two exact byte strings with explicit protocol-domain separation.
#[must_use]
pub fn hash_parts(domain: HashDomain, left: &[u8], right: &[u8]) -> CommitmentRoot {
    let mut hash = Sha256::new();
    hash.update(HASH_PROTOCOL);
    hash.update(domain.code().to_le_bytes());
    hash.update((left.len() as u128).to_le_bytes());
    hash.update(left);
    hash.update((right.len() as u128).to_le_bytes());
    hash.update(right);
    CommitmentRoot::from_bytes(hash.finalize().into())
}
