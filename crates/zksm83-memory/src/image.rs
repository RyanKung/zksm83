//! Prover-side ROM and mutable-memory images that produce authentication paths.

use pasta_curves::Fp;
use thiserror::Error;

use crate::{
    AddressOwner, CommitmentRoot, HashDomain, MemoryRead, MemoryWrite, MerklePath, RomRead,
    dmg_owner, owner,
};

const CPU_ADDRESS_SPACE_BYTES: usize = 65_536;
const ROM_BYTES: usize = 1_048_576;
const MUTABLE_BYTES: usize = 32_752;
const MUTABLE_COMMITMENT_BYTES: usize = 131_072;
const BATTERY_SRAM_START: usize = 0x1_0000;
const BATTERY_SRAM_BYTES: usize = 32_768;
const MIN_TREE_DEPTH: usize = 16;
const TREE_DEPTH: usize = 20;

/// Immutable committed ROM image for witness construction.
#[derive(Debug)]
pub struct RomImage {
    tree: MerkleTree,
}

impl RomImage {
    /// Builds a ROM tree, padding the declared program range and full address tree with zeros.
    pub fn new(program: Vec<u8>) -> Result<Self, RomImageError> {
        if program.is_empty() {
            return Err(RomImageError::EmptyProgram);
        }
        if program.len() > ROM_BYTES {
            return Err(RomImageError::ProgramTooLarge {
                actual: program.len(),
                maximum: ROM_BYTES,
            });
        }
        let stored_bytes = program
            .len()
            .checked_next_power_of_two()
            .ok_or(RomImageError::CommitmentInvariant)?
            .max(CPU_ADDRESS_SPACE_BYTES);
        let mut bytes = program;
        bytes.resize(stored_bytes, 0);
        let tree = MerkleTree::build(TreeKind::Rom, bytes)
            .map_err(|_| RomImageError::CommitmentInvariant)?;
        Ok(Self { tree })
    }

    /// Returns the immutable ROM root.
    #[must_use]
    pub const fn root(&self) -> CommitmentRoot {
        self.tree.root
    }

    /// Returns an authenticated ROM read witness.
    pub fn read(&self, address: u16) -> Result<RomRead, RomImageError> {
        self.read_mapped(address, u32::from(address))
    }

    /// Returns an authenticated ROM read at an MBC-mapped physical byte index.
    pub fn read_mapped(
        &self,
        address: u16,
        physical_address: u32,
    ) -> Result<RomRead, RomImageError> {
        if owner(address) != AddressOwner::Rom {
            return Err(RomImageError::AddressNotRom { address });
        }
        let (value, path) = self
            .tree
            .read(physical_address)
            .map_err(|_| RomImageError::PhysicalAddressOutOfRange { physical_address })?;
        Ok(RomRead {
            address,
            physical_address,
            value,
            path,
        })
    }
}

/// Failure to construct or access a ROM image.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RomImageError {
    /// A proof ROM must contain at least one byte.
    #[error("ROM program is empty")]
    EmptyProgram,
    /// The program exceeds the profile-owned ROM range.
    #[error("ROM program has {actual} bytes; maximum is {maximum}")]
    ProgramTooLarge {
        /// Supplied byte count.
        actual: usize,
        /// Profile maximum.
        maximum: usize,
    },
    /// The address belongs to a different profile owner.
    #[error("address 0x{address:04x} is not owned by ROM")]
    AddressNotRom {
        /// Rejected address.
        address: u16,
    },
    /// The mapper selected a byte outside the committed cartridge image.
    #[error("physical ROM address 0x{physical_address:05x} is outside the committed image")]
    PhysicalAddressOutOfRange {
        /// Rejected physical byte index.
        physical_address: u32,
    },
    /// A validated fixed-size tree failed its internal shape invariant.
    #[error("ROM commitment tree violated its fixed shape invariant")]
    CommitmentInvariant,
}

/// Mutable committed byte-memory image for witness construction.
#[derive(Debug)]
pub struct MemoryImage {
    tree: MerkleTree,
}

impl MemoryImage {
    /// Builds a zero-initialized mutable-memory tree.
    pub fn zeroed() -> Result<Self, MemoryImageError> {
        Self::new(Vec::new())
    }

    /// Builds mutable memory from bytes mapped consecutively from address `0x8000`.
    pub fn new(initial_bytes: Vec<u8>) -> Result<Self, MemoryImageError> {
        if initial_bytes.len() > MUTABLE_BYTES {
            return Err(MemoryImageError::InitialMemoryTooLarge {
                actual: initial_bytes.len(),
                maximum: MUTABLE_BYTES,
            });
        }
        let mut bytes = vec![0_u8; MUTABLE_COMMITMENT_BYTES];
        for (address, value) in (0x8000_u16..=0xffef).zip(initial_bytes) {
            let slot = bytes
                .get_mut(usize::from(address))
                .ok_or(MemoryImageError::CommitmentInvariant)?;
            *slot = value;
        }
        let tree = MerkleTree::build(TreeKind::Memory, bytes)
            .map_err(|_| MemoryImageError::CommitmentInvariant)?;
        Ok(Self { tree })
    }

    /// Restores the complete committed mutable-memory image from a checkpoint.
    pub fn from_checkpoint_bytes(bytes: Vec<u8>) -> Result<Self, MemoryImageError> {
        if bytes.len() != MUTABLE_COMMITMENT_BYTES {
            return Err(MemoryImageError::InvalidCheckpointLength {
                actual: bytes.len(),
                expected: MUTABLE_COMMITMENT_BYTES,
            });
        }
        let tree = MerkleTree::build(TreeKind::Memory, bytes)
            .map_err(|_| MemoryImageError::CommitmentInvariant)?;
        Ok(Self { tree })
    }

    /// Builds zeroed working memory with an exact four-bank MBC3 battery SRAM image.
    pub fn with_battery_sram(sram: Vec<u8>) -> Result<Self, MemoryImageError> {
        if sram.len() != BATTERY_SRAM_BYTES {
            return Err(MemoryImageError::InvalidBatterySramLength {
                actual: sram.len(),
                expected: BATTERY_SRAM_BYTES,
            });
        }
        let mut bytes = vec![0_u8; MUTABLE_COMMITMENT_BYTES];
        let end = BATTERY_SRAM_START
            .checked_add(BATTERY_SRAM_BYTES)
            .ok_or(MemoryImageError::CommitmentInvariant)?;
        let target = bytes
            .get_mut(BATTERY_SRAM_START..end)
            .ok_or(MemoryImageError::CommitmentInvariant)?;
        target.copy_from_slice(&sram);
        let tree = MerkleTree::build(TreeKind::Memory, bytes)
            .map_err(|_| MemoryImageError::CommitmentInvariant)?;
        Ok(Self { tree })
    }

    /// Copies all committed bytes for deterministic trace resumption.
    #[must_use]
    pub fn checkpoint_bytes(&self) -> Vec<u8> {
        self.tree.bytes.clone()
    }

    /// Copies the four physical MBC3 battery SRAM banks in `.sav` byte order.
    pub fn battery_sram_bytes(&self) -> Result<Vec<u8>, MemoryImageError> {
        let end = BATTERY_SRAM_START
            .checked_add(BATTERY_SRAM_BYTES)
            .ok_or(MemoryImageError::CommitmentInvariant)?;
        self.tree
            .bytes
            .get(BATTERY_SRAM_START..end)
            .map(<[u8]>::to_vec)
            .ok_or(MemoryImageError::CommitmentInvariant)
    }

    /// Copies the mathematical memory snapshot for speculative witness planning.
    ///
    /// The copy has no independent authority or identity; subsequent writes to
    /// either image evolve only that value snapshot.
    #[must_use]
    pub fn fork(&self) -> Self {
        Self {
            tree: self.tree.clone(),
        }
    }

    /// Returns the current mutable-memory root.
    #[must_use]
    pub const fn root(&self) -> CommitmentRoot {
        self.tree.root
    }

    /// Returns an authenticated mutable-memory read witness.
    pub fn read(&self, address: u16) -> Result<MemoryRead, MemoryImageError> {
        self.read_mapped(address, u32::from(address))
    }

    /// Returns an authenticated read at an MBC-mapped physical byte index.
    pub fn read_mapped(
        &self,
        address: u16,
        physical_address: u32,
    ) -> Result<MemoryRead, MemoryImageError> {
        validate_mutable_address(address)?;
        let (value, path) = self
            .tree
            .read(physical_address)
            .map_err(|_| MemoryImageError::PhysicalAddressOutOfRange { physical_address })?;
        Ok(MemoryRead {
            address,
            physical_address,
            value,
            path,
        })
    }

    /// Applies a byte write and returns the authenticated before/after witness.
    pub fn write(&mut self, address: u16, after: u8) -> Result<MemoryWrite, MemoryImageError> {
        self.write_mapped(address, u32::from(address), after)
    }

    /// Applies an MBC-mapped byte write and returns its authentication witness.
    pub fn write_mapped(
        &mut self,
        address: u16,
        physical_address: u32,
        after: u8,
    ) -> Result<MemoryWrite, MemoryImageError> {
        let witness = self.preview_write_mapped(address, physical_address, after)?;
        self.tree
            .write(physical_address, after)
            .map_err(|_| MemoryImageError::PhysicalAddressOutOfRange { physical_address })?;
        Ok(witness)
    }

    /// Returns a write witness without mutating the image.
    pub fn preview_write(&self, address: u16, after: u8) -> Result<MemoryWrite, MemoryImageError> {
        self.preview_write_mapped(address, u32::from(address), after)
    }

    /// Returns an MBC-mapped write witness without mutating the image.
    pub fn preview_write_mapped(
        &self,
        address: u16,
        physical_address: u32,
        after: u8,
    ) -> Result<MemoryWrite, MemoryImageError> {
        validate_mutable_address(address)?;
        let (before, path) = self
            .tree
            .read(physical_address)
            .map_err(|_| MemoryImageError::PhysicalAddressOutOfRange { physical_address })?;
        Ok(MemoryWrite {
            address,
            physical_address,
            before,
            after,
            path,
        })
    }
}

/// Failure to construct or access mutable committed memory.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MemoryImageError {
    /// Initial bytes exceed the mutable address range.
    #[error("initial mutable memory has {actual} bytes; maximum is {maximum}")]
    InitialMemoryTooLarge {
        /// Supplied byte count.
        actual: usize,
        /// Profile maximum.
        maximum: usize,
    },
    /// A checkpoint must carry the complete fixed-size memory commitment image.
    #[error("checkpoint memory has {actual} bytes; expected exactly {expected}")]
    InvalidCheckpointLength {
        /// Supplied checkpoint byte length.
        actual: usize,
        /// Required fixed byte length.
        expected: usize,
    },
    /// The no-RTC MBC3 profile uses exactly four 8-KiB battery SRAM banks.
    #[error("battery SRAM has {actual} bytes; expected exactly {expected}")]
    InvalidBatterySramLength {
        /// Supplied `.sav` length.
        actual: usize,
        /// Required profile length.
        expected: usize,
    },
    /// The address belongs to a different profile owner.
    #[error("address 0x{address:04x} is not owned by mutable memory")]
    AddressNotMutable {
        /// Rejected address.
        address: u16,
    },
    /// The mapper selected a byte outside the stored mutable image.
    #[error("physical memory address 0x{physical_address:05x} is outside the stored image")]
    PhysicalAddressOutOfRange {
        /// Rejected physical byte index.
        physical_address: u32,
    },
    /// A validated fixed-size tree failed its internal shape invariant.
    #[error("mutable-memory commitment tree violated its fixed shape invariant")]
    CommitmentInvariant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TreeKind {
    Rom,
    Memory,
}

impl TreeKind {
    const fn leaf_domain(self) -> HashDomain {
        match self {
            Self::Rom => HashDomain::RomLeaf,
            Self::Memory => HashDomain::MemoryLeaf,
        }
    }

    const fn node_domain(self, level: u8) -> HashDomain {
        match self {
            Self::Rom => HashDomain::RomNode(level),
            Self::Memory => HashDomain::MemoryNode(level),
        }
    }
}

#[derive(Clone, Debug)]
struct MerkleTree {
    kind: TreeKind,
    bytes: Vec<u8>,
    levels: Vec<Vec<CommitmentRoot>>,
    zero_roots: Vec<CommitmentRoot>,
    stored_depth: usize,
    root: CommitmentRoot,
}

impl MerkleTree {
    fn build(kind: TreeKind, bytes: Vec<u8>) -> Result<Self, TreeShapeError> {
        if !bytes.len().is_power_of_two()
            || bytes.len() < CPU_ADDRESS_SPACE_BYTES
            || bytes.len() > ROM_BYTES
        {
            return Err(TreeShapeError);
        }
        let stored_depth = usize::try_from(bytes.len().ilog2()).map_err(|_| TreeShapeError)?;
        if !(MIN_TREE_DEPTH..=TREE_DEPTH).contains(&stored_depth) {
            return Err(TreeShapeError);
        }
        let zero_leaf = leaf(kind, 0);
        let leaves = bytes
            .iter()
            .copied()
            .map(|value| {
                if value == 0 {
                    zero_leaf
                } else {
                    leaf(kind, value)
                }
            })
            .collect::<Vec<_>>();
        let mut levels = vec![leaves];
        let mut zero_child = zero_leaf;
        let mut zero_roots = Vec::with_capacity(TREE_DEPTH + 1);
        zero_roots.push(zero_leaf);
        let stored_depth_u8 = u8::try_from(stored_depth).map_err(|_| TreeShapeError)?;
        for level in 0_u8..stored_depth_u8 {
            let current = levels.last().ok_or(TreeShapeError)?;
            let mut parents = Vec::with_capacity(current.len() / 2);
            let zero_parent = node(kind, level, zero_child, zero_child);
            for pair in current.chunks_exact(2) {
                let left = pair.first().copied().ok_or(TreeShapeError)?;
                let right = pair.last().copied().ok_or(TreeShapeError)?;
                let parent = if left == zero_child && right == zero_child {
                    zero_parent
                } else {
                    node(kind, level, left, right)
                };
                parents.push(parent);
            }
            levels.push(parents);
            zero_child = zero_parent;
            zero_roots.push(zero_child);
        }
        let mut root = levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .ok_or(TreeShapeError)?;
        let protocol_depth_u8 = u8::try_from(TREE_DEPTH).map_err(|_| TreeShapeError)?;
        for level in stored_depth_u8..protocol_depth_u8 {
            root = node(kind, level, root, zero_child);
            zero_child = node(kind, level, zero_child, zero_child);
            zero_roots.push(zero_child);
        }
        Ok(Self {
            kind,
            bytes,
            levels,
            zero_roots,
            stored_depth,
            root,
        })
    }

    fn read(&self, address: u32) -> Result<(u8, MerklePath), TreeShapeError> {
        let mut position = usize::try_from(address).map_err(|_| TreeShapeError)?;
        let value = self.bytes.get(position).copied().ok_or(TreeShapeError)?;
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        for level in self.levels.iter().take(self.stored_depth) {
            let sibling = level.get(position ^ 1).copied().ok_or(TreeShapeError)?;
            siblings.push(sibling);
            position >>= 1;
        }
        for level in self.stored_depth..TREE_DEPTH {
            siblings.push(self.zero_roots.get(level).copied().ok_or(TreeShapeError)?);
        }
        let path = MerklePath::from_slice(&siblings).map_err(|_| TreeShapeError)?;
        Ok((value, path))
    }

    fn write(&mut self, address: u32, value: u8) -> Result<(), TreeShapeError> {
        let mut position = usize::try_from(address).map_err(|_| TreeShapeError)?;
        let byte = self.bytes.get_mut(position).ok_or(TreeShapeError)?;
        *byte = value;
        let first_level = self.levels.first_mut().ok_or(TreeShapeError)?;
        let first_leaf = first_level.get_mut(position).ok_or(TreeShapeError)?;
        *first_leaf = leaf(self.kind, value);
        let stored_depth_u8 = u8::try_from(self.stored_depth).map_err(|_| TreeShapeError)?;
        for (level_number, next_level) in (0_u8..stored_depth_u8).zip(1_usize..=self.stored_depth) {
            let parent = self.parent(level_number, next_level - 1, position)?;
            position >>= 1;
            let level = self.levels.get_mut(next_level).ok_or(TreeShapeError)?;
            let slot = level.get_mut(position).ok_or(TreeShapeError)?;
            *slot = parent;
        }
        let mut root = self
            .levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .ok_or(TreeShapeError)?;
        let protocol_depth_u8 = u8::try_from(TREE_DEPTH).map_err(|_| TreeShapeError)?;
        for level in stored_depth_u8..protocol_depth_u8 {
            let zero = self
                .zero_roots
                .get(usize::from(level))
                .copied()
                .ok_or(TreeShapeError)?;
            root = node(self.kind, level, root, zero);
        }
        self.root = root;
        Ok(())
    }

    fn parent(
        &self,
        level_number: u8,
        level_index: usize,
        position: usize,
    ) -> Result<CommitmentRoot, TreeShapeError> {
        let level = self.levels.get(level_index).ok_or(TreeShapeError)?;
        let even_position = position & !1;
        let left = level.get(even_position).copied().ok_or(TreeShapeError)?;
        let right = level
            .get(even_position.saturating_add(1))
            .copied()
            .ok_or(TreeShapeError)?;
        Ok(node(self.kind, level_number, left, right))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TreeShapeError;

fn leaf(kind: TreeKind, value: u8) -> CommitmentRoot {
    CommitmentRoot::from_field(crate::hash_elements(
        kind.leaf_domain(),
        Fp::from(u64::from(value)),
        Fp::zero(),
    ))
}

fn node(kind: TreeKind, level: u8, left: CommitmentRoot, right: CommitmentRoot) -> CommitmentRoot {
    CommitmentRoot::from_field(crate::hash_elements(
        kind.node_domain(level),
        left.field(),
        right.field(),
    ))
}

fn validate_mutable_address(address: u16) -> Result<(), MemoryImageError> {
    if owner(address) != AddressOwner::Memory && dmg_owner(address) != AddressOwner::Memory {
        return Err(MemoryImageError::AddressNotMutable { address });
    }
    Ok(())
}
