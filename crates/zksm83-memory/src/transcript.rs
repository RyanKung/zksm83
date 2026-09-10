//! Authenticated read/write witnesses and root-threaded transcripts.

use std::{array::TryFromSliceError, cell::RefCell, collections::HashMap};

use pasta_curves::Fp;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{AddressOwner, CommitmentRoot, HashDomain, dmg_owner, owner};

const ROM_VERIFICATION_CACHE_CAPACITY: usize = 32_768;
const MEMORY_VERIFICATION_CACHE_CAPACITY: usize = 8_192;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct RomVerificationKey {
    expected_root: [u8; 32],
    physical_address: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VerifiedRomWitness {
    value: u8,
    path: MerklePath,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct MemoryVerificationKey {
    expected_root: [u8; 32],
    physical_address: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct MemoryWriteVerificationKey {
    expected_root: [u8; 32],
    physical_address: u32,
    after: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VerifiedMemoryReadWitness {
    value: u8,
    path: MerklePath,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VerifiedMemoryWriteWitness {
    before: u8,
    path: MerklePath,
    after_root: CommitmentRoot,
}

thread_local! {
    /// Performance-only memoization of fully authenticated immutable witnesses.
    ///
    /// A hit is accepted only when the complete value and twenty-sibling path
    /// equal a witness that was already checked with the normal Poseidon
    /// derivation. The cache therefore cannot expand the accepted relation.
    static ROM_VERIFICATION_CACHE: RefCell<HashMap<RomVerificationKey, VerifiedRomWitness>> =
        RefCell::new(HashMap::new());
    static MEMORY_READ_VERIFICATION_CACHE:
        RefCell<HashMap<MemoryVerificationKey, VerifiedMemoryReadWitness>> =
        RefCell::new(HashMap::new());
    static MEMORY_WRITE_VERIFICATION_CACHE:
        RefCell<HashMap<MemoryWriteVerificationKey, VerifiedMemoryWriteWitness>> =
        RefCell::new(HashMap::new());
}

/// Binary Merkle authentication path into the one-MiB profile commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MerklePath {
    siblings: [CommitmentRoot; 20],
}

impl MerklePath {
    /// Constructs a path from exactly twenty sibling nodes.
    #[must_use]
    pub const fn new(siblings: [CommitmentRoot; 20]) -> Self {
        Self { siblings }
    }

    /// Returns a canonical placeholder path for lookup-backed execution.
    ///
    /// This path never authenticates a Merkle access; it is accepted only by
    /// the separately typed lookup relation whose enclosing proof supplies the
    /// ROM and memory argument.
    #[must_use]
    pub fn lookup_placeholder() -> Self {
        Self::new([CommitmentRoot::from_field(Fp::zero()); 20])
    }

    /// Iterates over sibling nodes from leaf level to root level.
    pub fn siblings(&self) -> impl ExactSizeIterator<Item = CommitmentRoot> + '_ {
        self.siblings.iter().copied()
    }

    pub(crate) fn from_slice(values: &[CommitmentRoot]) -> Result<Self, TryFromSliceError> {
        <[CommitmentRoot; 20]>::try_from(values).map(Self::new)
    }
}

/// Authenticated immutable ROM read.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RomRead {
    /// CPU-visible read address.
    pub address: u16,
    /// Physical byte index in the committed cartridge image.
    pub physical_address: u32,
    /// Read byte.
    pub value: u8,
    /// Authentication path to the ROM root.
    pub path: MerklePath,
}

impl RomRead {
    /// Verifies address ownership, byte value, path, and expected ROM root.
    pub fn verify(self, expected_root: CommitmentRoot) -> Result<(), RomReadError> {
        if owner(self.address) != AddressOwner::Rom {
            return Err(RomReadError::AddressNotRom {
                address: self.address,
            });
        }
        validate_physical_address(self.physical_address)?;
        let key = RomVerificationKey {
            expected_root: expected_root.to_bytes(),
            physical_address: self.physical_address,
        };
        let witness = VerifiedRomWitness {
            value: self.value,
            path: self.path,
        };
        if cached_rom_witness(key) == Some(witness) {
            return Ok(());
        }
        let actual = derive_root(
            HashDomain::RomLeaf,
            HashDomain::RomNode,
            self.physical_address,
            self.value,
            self.path,
        );
        if actual != expected_root {
            return Err(RomReadError::RootMismatch {
                expected: expected_root,
                actual,
            });
        }
        cache_verified_rom_witness(key, witness);
        Ok(())
    }
}

fn cached_rom_witness(key: RomVerificationKey) -> Option<VerifiedRomWitness> {
    ROM_VERIFICATION_CACHE.with(|cache| cache.borrow().get(&key).copied())
}

fn cache_verified_rom_witness(key: RomVerificationKey, witness: VerifiedRomWitness) {
    ROM_VERIFICATION_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.len() < ROM_VERIFICATION_CACHE_CAPACITY {
            cache.insert(key, witness);
        }
    });
}

/// Failure to authenticate an immutable ROM read.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RomReadError {
    /// The address belongs to a different profile owner.
    #[error("address 0x{address:04x} is not owned by ROM")]
    AddressNotRom {
        /// Rejected address.
        address: u16,
    },
    /// The physical byte index is outside the one-MiB commitment.
    #[error("physical ROM address 0x{address:05x} is outside the commitment")]
    PhysicalAddressOutOfRange {
        /// Rejected physical byte index.
        address: u32,
    },
    /// The supplied byte and path do not derive the expected root.
    #[error("ROM authentication root mismatch: expected {expected}, derived {actual}")]
    RootMismatch {
        /// Public or threaded expected root.
        expected: CommitmentRoot,
        /// Root derived from the witness.
        actual: CommitmentRoot,
    },
}

/// Authenticated mutable-memory read.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryRead {
    /// CPU-visible read address.
    pub address: u16,
    /// Physical byte index in the mutable commitment.
    pub physical_address: u32,
    /// Read byte.
    pub value: u8,
    /// Authentication path to the current mutable root.
    pub path: MerklePath,
}

impl MemoryRead {
    /// Verifies this read against the current mutable-memory root.
    pub fn verify(self, expected_root: CommitmentRoot) -> Result<(), MemoryTranscriptError> {
        validate_memory_address(self.address)?;
        validate_physical_memory_address(self.physical_address)?;
        let key = MemoryVerificationKey {
            expected_root: expected_root.to_bytes(),
            physical_address: self.physical_address,
        };
        let witness = VerifiedMemoryReadWitness {
            value: self.value,
            path: self.path,
        };
        if cached_memory_read(key) == Some(witness) {
            return Ok(());
        }
        let actual = mutable_root(self.physical_address, self.value, self.path);
        require_root(expected_root, actual)?;
        cache_verified_memory_read(key, witness);
        Ok(())
    }
}

/// Authenticated mutable-memory write.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryWrite {
    /// CPU-visible written address.
    pub address: u16,
    /// Physical byte index in the mutable commitment.
    pub physical_address: u32,
    /// Value authenticated under the before-root.
    pub before: u8,
    /// Value authenticated under the after-root.
    pub after: u8,
    /// Shared path whose leaf changes from `before` to `after`.
    pub path: MerklePath,
}

impl MemoryWrite {
    /// Verifies the before-root and returns the root produced by the new byte.
    pub fn verify(
        self,
        expected_root: CommitmentRoot,
    ) -> Result<CommitmentRoot, MemoryTranscriptError> {
        validate_memory_address(self.address)?;
        validate_physical_memory_address(self.physical_address)?;
        let key = MemoryWriteVerificationKey {
            expected_root: expected_root.to_bytes(),
            physical_address: self.physical_address,
            after: self.after,
        };
        if let Some(witness) = cached_memory_write(key)
            && witness.before == self.before
            && witness.path == self.path
        {
            return Ok(witness.after_root);
        }
        let before_root = mutable_root(self.physical_address, self.before, self.path);
        require_root(expected_root, before_root)?;
        let after_root = mutable_root(self.physical_address, self.after, self.path);
        cache_verified_memory_write(
            key,
            VerifiedMemoryWriteWitness {
                before: self.before,
                path: self.path,
                after_root,
            },
        );
        Ok(after_root)
    }
}

fn cached_memory_read(key: MemoryVerificationKey) -> Option<VerifiedMemoryReadWitness> {
    MEMORY_READ_VERIFICATION_CACHE.with(|cache| cache.borrow().get(&key).copied())
}

fn cache_verified_memory_read(key: MemoryVerificationKey, witness: VerifiedMemoryReadWitness) {
    MEMORY_READ_VERIFICATION_CACHE.with(|cache| {
        insert_bounded(&mut cache.borrow_mut(), key, witness);
    });
}

fn cached_memory_write(key: MemoryWriteVerificationKey) -> Option<VerifiedMemoryWriteWitness> {
    MEMORY_WRITE_VERIFICATION_CACHE.with(|cache| cache.borrow().get(&key).copied())
}

fn cache_verified_memory_write(
    key: MemoryWriteVerificationKey,
    witness: VerifiedMemoryWriteWitness,
) {
    MEMORY_WRITE_VERIFICATION_CACHE.with(|cache| {
        insert_bounded(&mut cache.borrow_mut(), key, witness);
    });
}

fn insert_bounded<Key, Value>(cache: &mut HashMap<Key, Value>, key: Key, value: Value)
where
    Key: Eq + std::hash::Hash,
{
    if cache.len() >= MEMORY_VERIFICATION_CACHE_CAPACITY {
        cache.clear();
    }
    cache.insert(key, value);
}

/// One ordered mutable-memory transcript event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MemoryAccess {
    /// Root-preserving read.
    Read(MemoryRead),
    /// Root-changing write.
    Write(MemoryWrite),
}

/// A transcript whose current root is preserved by every accepted event.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryTranscript {
    initial_root: CommitmentRoot,
    current_root: CommitmentRoot,
    accesses: Vec<MemoryAccess>,
}

impl MemoryTranscript {
    /// Starts an empty transcript at the committed initial root.
    #[must_use]
    pub const fn new(initial_root: CommitmentRoot) -> Self {
        Self {
            initial_root,
            current_root: initial_root,
            accesses: Vec::new(),
        }
    }

    /// Verifies and appends one root-preserving read.
    pub fn read(&mut self, read: MemoryRead) -> Result<(), MemoryTranscriptError> {
        read.verify(self.current_root)?;
        self.accesses.push(MemoryAccess::Read(read));
        Ok(())
    }

    /// Verifies and appends one root-changing write.
    pub fn write(&mut self, write: MemoryWrite) -> Result<(), MemoryTranscriptError> {
        self.current_root = write.verify(self.current_root)?;
        self.accesses.push(MemoryAccess::Write(write));
        Ok(())
    }

    /// Returns the transcript's initial committed root.
    #[must_use]
    pub const fn initial_root(&self) -> CommitmentRoot {
        self.initial_root
    }

    /// Returns the root after all accepted events.
    #[must_use]
    pub const fn current_root(&self) -> CommitmentRoot {
        self.current_root
    }

    /// Returns the ordered authenticated events.
    pub fn accesses(&self) -> impl ExactSizeIterator<Item = MemoryAccess> + '_ {
        self.accesses.iter().copied()
    }
}

/// Failure to extend a mutable-memory transcript.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MemoryTranscriptError {
    /// The address is not mutable memory in the active machine profile.
    #[error("address 0x{address:04x} is not owned by mutable memory")]
    AddressNotMutable {
        /// Rejected address.
        address: u16,
    },
    /// The physical byte index is outside the one-MiB commitment.
    #[error("physical memory address 0x{address:05x} is outside the commitment")]
    PhysicalAddressOutOfRange {
        /// Rejected physical byte index.
        address: u32,
    },
    /// The event does not authenticate against the threaded current root.
    #[error("memory authentication root mismatch: expected {expected}, derived {actual}")]
    RootMismatch {
        /// Current transcript root.
        expected: CommitmentRoot,
        /// Root derived from the event witness.
        actual: CommitmentRoot,
    },
}

pub(crate) fn derive_root(
    leaf_domain: HashDomain,
    node_domain: fn(u8) -> HashDomain,
    address: u32,
    value: u8,
    path: MerklePath,
) -> CommitmentRoot {
    let value_field = Fp::from(u64::from(value));
    let mut current = crate::hash_elements(leaf_domain, value_field, Fp::zero());
    let mut address_bits = address;
    for (level, sibling) in (0_u8..20).zip(path.siblings()) {
        let (left, right) = if address_bits & 1 == 0 {
            (current, sibling.field())
        } else {
            (sibling.field(), current)
        };
        current = crate::hash_elements(node_domain(level), left, right);
        address_bits >>= 1;
    }
    CommitmentRoot::from_field(current)
}

fn mutable_root(address: u32, value: u8, path: MerklePath) -> CommitmentRoot {
    derive_root(
        HashDomain::MemoryLeaf,
        HashDomain::MemoryNode,
        address,
        value,
        path,
    )
}

fn validate_physical_address(address: u32) -> Result<(), RomReadError> {
    if address >= (1_u32 << 20) {
        return Err(RomReadError::PhysicalAddressOutOfRange { address });
    }
    Ok(())
}

fn validate_physical_memory_address(address: u32) -> Result<(), MemoryTranscriptError> {
    if address >= (1_u32 << 20) {
        return Err(MemoryTranscriptError::PhysicalAddressOutOfRange { address });
    }
    Ok(())
}

fn validate_memory_address(address: u16) -> Result<(), MemoryTranscriptError> {
    if owner(address) != AddressOwner::Memory && dmg_owner(address) != AddressOwner::Memory {
        return Err(MemoryTranscriptError::AddressNotMutable { address });
    }
    Ok(())
}

fn require_root(
    expected: CommitmentRoot,
    actual: CommitmentRoot,
) -> Result<(), MemoryTranscriptError> {
    if actual != expected {
        return Err(MemoryTranscriptError::RootMismatch { expected, actual });
    }
    Ok(())
}
