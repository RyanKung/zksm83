//! Canonical Pasta-field commitment values and domain-separated hashing.

use std::{
    cell::RefCell,
    collections::HashMap,
    fmt::{Display, Formatter},
};

use ff::PrimeField;
use halo2_gadgets::poseidon::primitives::{P128Pow5T3, Spec};
use pasta_curves::Fp;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};
use thiserror::Error;

const HASH_CACHE_CAPACITY: usize = 262_144;
const WIDTH: usize = 3;
const RATE: usize = 2;
const DOMAIN_CAPACITY_BASE: u128 = 2_u128 << 64;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct HashCacheKey {
    domain: HashDomain,
    left: [u8; 32],
    right: [u8; 32],
}

thread_local! {
    /// Performance-only memoization of the deterministic protocol hash.
    /// Exact domain and field inputs are part of the key, so a cache hit is
    /// identical to evaluating the same Poseidon permutation again.
    static HASH_CACHE: RefCell<HashMap<HashCacheKey, Fp>> = RefCell::new(HashMap::new());
}

/// Canonically encoded field element used as a Merkle or log root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitmentRoot(Fp);

impl CommitmentRoot {
    /// Constructs a root from its underlying field element.
    #[must_use]
    pub const fn from_field(value: Fp) -> Self {
        Self(value)
    }

    /// Returns the underlying field element for proof construction.
    #[must_use]
    pub const fn field(self) -> Fp {
        self.0
    }

    /// Returns the canonical little-endian 32-byte field encoding.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_repr()
    }

    /// Validates and decodes a canonical little-endian field encoding.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, RootEncodingError> {
        Option::<Fp>::from(Fp::from_repr(bytes))
            .map(Self)
            .ok_or(RootEncodingError::NonCanonicalFieldElement)
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
        Self::from_bytes(bytes).map_err(D::Error::custom)
    }
}

/// Failure to decode a canonical commitment root.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RootEncodingError {
    /// The 32 bytes do not encode a canonical Pasta field element.
    #[error("commitment root is not a canonical Pasta field element")]
    NonCanonicalFieldElement,
}

/// Domain tag for one field-native hash invocation.
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
    /// Returns the protocol field element for this domain.
    #[must_use]
    pub fn field(self) -> Fp {
        let value = match self {
            Self::RomLeaf => 0x1000,
            Self::MemoryLeaf => 0x2000,
            Self::RomNode(level) => 0x3000 + u64::from(level),
            Self::MemoryNode(level) => 0x4000 + u64::from(level),
            Self::InputEmpty => 0x5000,
            Self::OutputEmpty => 0x6000,
            Self::InputElement => 0x7000,
            Self::OutputElement => 0x8000,
            Self::BusTranscriptEmpty => 0x9000,
            Self::BusTranscriptElement => 0xa000,
            Self::IsaTranscriptEmpty => 0xb000,
            Self::IsaTranscriptElement => 0xc000,
        };
        Fp::from(value)
    }
}

/// Hashes two field elements with explicit protocol-domain separation.
#[must_use]
pub fn hash_elements(domain: HashDomain, left: Fp, right: Fp) -> Fp {
    let key = HashCacheKey {
        domain,
        left: left.to_repr(),
        right: right.to_repr(),
    };
    if let Some(value) = HASH_CACHE.with(|cache| cache.borrow().get(&key).copied()) {
        return value;
    }
    let value = compress(domain, left, right);
    HASH_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.len() >= HASH_CACHE_CAPACITY {
            cache.clear();
        }
        cache.insert(key, value);
    });
    value
}

fn compress(domain: HashDomain, left: Fp, right: Fp) -> Fp {
    let mut state = [
        left,
        right,
        Fp::from_u128(DOMAIN_CAPACITY_BASE) + domain.field(),
    ];
    let (round_constants, mds, _) = <P128Pow5T3 as Spec<Fp, WIDTH, RATE>>::constants();
    let half_full = <P128Pow5T3 as Spec<Fp, WIDTH, RATE>>::full_rounds() / 2;
    let partial = <P128Pow5T3 as Spec<Fp, WIDTH, RATE>>::partial_rounds();
    for (round, constants) in round_constants.iter().enumerate() {
        for (word, constant) in state.iter_mut().zip(constants) {
            *word += constant;
        }
        if round < half_full || round >= half_full + partial {
            for word in &mut state {
                *word = <P128Pow5T3 as Spec<Fp, WIDTH, RATE>>::sbox(*word);
            }
        } else {
            state[0] = <P128Pow5T3 as Spec<Fp, WIDTH, RATE>>::sbox(state[0]);
        }
        let [zero, one, two] = state;
        state = mds.map(|row| row[0] * zero + row[1] * one + row[2] * two);
    }
    state[0]
}
