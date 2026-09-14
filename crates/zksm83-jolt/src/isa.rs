//! Canonical 512-row SM83 instruction-alignment table.

use sha2::{Digest, Sha256};
use thiserror::Error;
use zksm83_isa::{AlignedInstruction, AlignmentPackingError};

/// Number of primary plus CB-prefixed lookup addresses.
pub const ISA_TABLE_ROW_COUNT: usize = 512;

/// Number of non-redundant outputs in one native ISA-table row.
pub const ISA_OUTPUT_COUNT: usize = 38;
/// Canonical undefined primary opcode used for inactive ISA lookup lanes.
pub const ISA_PADDING_ADDRESS: u16 = 0x00d3;

/// Index of the validity bit in [`IsaTableRow::outputs`].
pub const ISA_VALID: usize = 0;
/// Index of the low 64 bits of the collision-free packed descriptor.
pub const ISA_PACKED_LOW: usize = 1;
/// Index of the high 42 bits of the collision-free packed descriptor.
pub const ISA_PACKED_HIGH: usize = 2;
/// First index of the 13 register-write selector bits.
pub const ISA_WRITE_BITS_START: usize = 11;
/// Index of the fixed primary/CB opcode-fetch count.
pub const ISA_OPCODE_FETCHES: usize = 5;
/// Index of the fixed immediate-byte read count.
pub const ISA_IMMEDIATE_READS: usize = 6;
/// Index of the fixed base-path data-read count.
pub const ISA_DATA_READS: usize = 7;
/// Index of the fixed base-path data-write count.
pub const ISA_DATA_WRITES: usize = 8;
/// Index of the instruction's unconditional machine-cycle count.
pub const ISA_BASE_M_CYCLES: usize = 3;
/// Index of the additional machine-cycle count for a taken branch.
pub const ISA_TAKEN_M_CYCLES: usize = 4;
/// Index of the conditional taken-path data-read count.
pub const ISA_TAKEN_DATA_READS: usize = 9;
/// Index of the conditional taken-path data-write count.
pub const ISA_TAKEN_DATA_WRITES: usize = 10;
/// Index indicating that the instruction has taken-branch timing.
pub const ISA_TAKEN_TIMING: usize = 24;
/// First index of the six operation-code bits.
pub const ISA_OPERATION_BITS_START: usize = 25;
/// First index of the three first-argument bits.
pub const ISA_ARGUMENT_ZERO_BITS_START: usize = 31;
/// First index of the four second-argument bits.
pub const ISA_ARGUMENT_ONE_BITS_START: usize = 34;

const REGISTER_WRITE_BITS: usize = 13;
const OPERATION_BITS: usize = 6;
const ARGUMENT_ZERO_BITS: usize = 3;
const ARGUMENT_ONE_BITS: usize = 4;
const ISA_TABLE_DIGEST_DOMAIN: &[u8] = b"zksm83/native-isa-table/v2";

const _: () = assert!(ISA_TABLE_ROW_COUNT == 512);
const _: () = assert!(ISA_PADDING_ADDRESS < 512);

/// One fixed output row selected by the nine-bit `(prefix, opcode)` address.
///
/// Undefined primary opcodes are represented by the all-zero output row. A
/// valid instruction always has `outputs[ISA_VALID] == 1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IsaTableRow {
    address: u16,
    outputs: [u64; ISA_OUTPUT_COUNT],
}

impl IsaTableRow {
    /// Returns the canonical nine-bit table address.
    #[must_use]
    pub const fn address(self) -> u16 {
        self.address
    }

    /// Returns the complete scalar output row.
    #[must_use]
    pub const fn outputs(self) -> [u64; ISA_OUTPUT_COUNT] {
        self.outputs
    }

    /// Returns whether this address names a defined instruction.
    #[must_use]
    pub const fn is_defined(self) -> bool {
        self.outputs[ISA_VALID] == 1
    }

    fn undefined(address: u16) -> Self {
        Self {
            address,
            outputs: [0; ISA_OUTPUT_COUNT],
        }
    }

    fn from_aligned(aligned: AlignedInstruction) -> Result<Self, IsaTableError> {
        let address = u16::from(aligned.key.prefix)
            .checked_mul(256)
            .and_then(|prefix| prefix.checked_add(u16::from(aligned.key.opcode)))
            .ok_or(IsaTableError::AddressOverflow)?;
        let packed = aligned.packed()?;
        let packed_low = u64::try_from(packed & u128::from(u64::MAX))
            .map_err(|_| IsaTableError::PackedDescriptor)?;
        let packed_high =
            u64::try_from(packed >> 64).map_err(|_| IsaTableError::PackedDescriptor)?;
        let mut outputs = [0_u64; ISA_OUTPUT_COUNT];
        let fields = [
            1,
            packed_low,
            packed_high,
            u64::from(aligned.base_m_cycles),
            u64::from(aligned.taken_m_cycles),
            u64::from(aligned.opcode_fetches),
            u64::from(aligned.immediate_reads),
            u64::from(aligned.data_reads),
            u64::from(aligned.data_writes),
            u64::from(aligned.taken_data_reads),
            u64::from(aligned.taken_data_writes),
        ];
        outputs
            .get_mut(..fields.len())
            .ok_or(IsaTableError::OutputLayout)?
            .copy_from_slice(&fields);
        for bit in 0..REGISTER_WRITE_BITS {
            let target = ISA_WRITE_BITS_START
                .checked_add(bit)
                .ok_or(IsaTableError::OutputLayout)?;
            *outputs.get_mut(target).ok_or(IsaTableError::OutputLayout)? =
                u64::from((aligned.register_writes >> bit) & 1);
        }
        *outputs
            .get_mut(ISA_TAKEN_TIMING)
            .ok_or(IsaTableError::OutputLayout)? = u64::from(aligned.taken_m_cycles != 0);
        write_bits(
            &mut outputs,
            ISA_OPERATION_BITS_START,
            OPERATION_BITS,
            u64::from(aligned.operation),
        )?;
        write_bits(
            &mut outputs,
            ISA_ARGUMENT_ZERO_BITS_START,
            ARGUMENT_ZERO_BITS,
            u64::from(aligned.argument_zero),
        )?;
        write_bits(
            &mut outputs,
            ISA_ARGUMENT_ONE_BITS_START,
            ARGUMENT_ONE_BITS,
            u64::from(aligned.argument_one),
        )?;
        Ok(Self { address, outputs })
    }
}

/// Invalid construction of the verifier-fixed SM83 ISA table.
#[derive(Debug, Error)]
pub enum IsaTableError {
    /// The packed descriptor did not fit its two declared limbs.
    #[error("SM83 ISA packed descriptor exceeds its declared limbs")]
    PackedDescriptor,
    /// Prefix/opcode addressing exceeded the fixed nine-bit table.
    #[error("SM83 ISA table address overflow")]
    AddressOverflow,
    /// A generated output index exceeded the frozen layout.
    #[error("SM83 ISA output layout is inconsistent")]
    OutputLayout,
    /// Two defined instructions mapped to the same address.
    #[error("duplicate defined SM83 ISA table address {address}")]
    DuplicateAddress {
        /// Repeated nine-bit address.
        address: u16,
    },
    /// A source alignment record exceeded its frozen bit allocation.
    #[error(transparent)]
    AlignmentPacking(#[from] AlignmentPackingError),
}

/// Constructs all 512 verifier-fixed ISA rows in address order.
pub fn fixed_isa_table() -> Result<Vec<IsaTableRow>, IsaTableError> {
    let mut rows = (0..ISA_TABLE_ROW_COUNT)
        .map(|address| {
            u16::try_from(address)
                .map(IsaTableRow::undefined)
                .map_err(|_| IsaTableError::AddressOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    for aligned in AlignedInstruction::all() {
        let row = IsaTableRow::from_aligned(aligned)?;
        let target = rows
            .get_mut(usize::from(row.address))
            .ok_or(IsaTableError::AddressOverflow)?;
        if target.is_defined() {
            return Err(IsaTableError::DuplicateAddress {
                address: row.address,
            });
        }
        *target = row;
    }
    Ok(rows)
}

/// Returns the protocol digest of the complete fixed ISA table.
pub fn fixed_isa_table_digest() -> Result<[u8; 32], IsaTableError> {
    let rows = fixed_isa_table()?;
    let mut hasher = Sha256::new();
    hasher.update(ISA_TABLE_DIGEST_DOMAIN);
    hasher.update(
        u64::try_from(rows.len())
            .map_err(|_| IsaTableError::OutputLayout)?
            .to_le_bytes(),
    );
    hasher.update(
        u64::try_from(ISA_OUTPUT_COUNT)
            .map_err(|_| IsaTableError::OutputLayout)?
            .to_le_bytes(),
    );
    for row in rows {
        hasher.update(row.address.to_le_bytes());
        for output in row.outputs {
            hasher.update(output.to_le_bytes());
        }
    }
    Ok(hasher.finalize().into())
}

fn write_bits(
    outputs: &mut [u64; ISA_OUTPUT_COUNT],
    start: usize,
    count: usize,
    value: u64,
) -> Result<(), IsaTableError> {
    for bit in 0..count {
        let target = start.checked_add(bit).ok_or(IsaTableError::OutputLayout)?;
        *outputs.get_mut(target).ok_or(IsaTableError::OutputLayout)? = (value >> bit) & 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ISA_OUTPUT_COUNT, ISA_TABLE_ROW_COUNT, ISA_VALID, fixed_isa_table, fixed_isa_table_digest,
    };
    use zksm83_isa::ALIGNMENT_ROW_COUNT;

    #[test]
    fn fixed_table_has_all_addresses_and_exact_defined_set()
    -> Result<(), Box<dyn std::error::Error>> {
        let rows = fixed_isa_table()?;
        assert_eq!(rows.len(), ISA_TABLE_ROW_COUNT);
        assert_eq!(
            rows.iter().filter(|row| row.is_defined()).count(),
            ALIGNMENT_ROW_COUNT
        );
        for (address, row) in rows.iter().copied().enumerate() {
            assert_eq!(usize::from(row.address()), address);
            assert_eq!(row.outputs().len(), ISA_OUTPUT_COUNT);
            assert!(row.outputs()[ISA_VALID] <= 1);
            if address >= 256 {
                assert!(row.is_defined());
            }
        }
        Ok(())
    }

    #[test]
    fn fixed_table_digest_is_stable() -> Result<(), Box<dyn std::error::Error>> {
        let digest = fixed_isa_table_digest()?;
        assert_eq!(
            digest,
            [
                0x14, 0xf2, 0x48, 0xa5, 0x3f, 0x5f, 0xcd, 0x04, 0x9c, 0xbd, 0x6c, 0x8f, 0x2e, 0xd3,
                0x0c, 0x53, 0x0f, 0x73, 0xb5, 0x6e, 0x2e, 0x26, 0x93, 0xcd, 0xaf, 0xc3, 0x8a, 0x85,
                0x81, 0x7d, 0x81, 0x70,
            ]
        );
        Ok(())
    }
}
