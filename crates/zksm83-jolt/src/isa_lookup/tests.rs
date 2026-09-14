use akita_pcs::Ring;
use sha2::{Digest, Sha256};

use super::{
    FIXED_ISA_TABLE_COMMITMENT_SHA256, ISA_OUTPUT_COUNT, ISA_SCHEDULE_ARTIFACT, ISA_TABLE_LAYOUT,
    IsaLookupColumns, IsaLookupError, canonical_indices, fixed_table_columns, hex_digest,
    prove_isa_lookup, verify_isa_lookup,
};
use crate::{
    AKITA_ISA_TABLE_SCHEDULE_SHA256, ISA_ADDRESS_BIT_COUNT, UNIFORM_ROW_COUNT, commit_witness,
    fixed_isa_table, pcs::scheme,
};

#[test]
fn pinned_isa_schedule_has_only_the_frozen_shape() -> Result<(), IsaLookupError> {
    let scheme = scheme(ISA_TABLE_LAYOUT)?;
    let rows = scheme.schedules().catalog().rows().collect::<Vec<_>>();
    let row = rows.first().ok_or(IsaLookupError::Shape)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(row.profiles().final_group.group.num_vars(), 9);
    assert_eq!(
        row.profiles().final_group.group.num_polynomials(),
        crate::COMMITMENT_GROUP_COLUMNS
    );
    assert!(row.profiles().precommitteds.is_empty());
    assert_eq!(
        format!("{:x}", Sha256::digest(ISA_SCHEDULE_ARTIFACT)),
        AKITA_ISA_TABLE_SCHEDULE_SHA256
    );
    Ok(())
}

#[test]
fn fixed_table_columns_preserve_all_outputs() -> Result<(), IsaLookupError> {
    let columns = fixed_table_columns()?;
    assert_eq!(columns.len(), ISA_OUTPUT_COUNT);
    assert!(columns.iter().all(|column| column.len() == 512));
    Ok(())
}

#[test]
fn overlapping_or_repeated_layout_is_rejected() {
    let address = std::array::from_fn(|index| index);
    let repeated_outputs = [0; ISA_OUTPUT_COUNT];
    assert!(IsaLookupColumns::new(address, repeated_outputs).is_err());
    assert_eq!(canonical_indices().len(), ISA_OUTPUT_COUNT);
}

#[test]
#[ignore = "expensive shared-trace and fixed-table Akita Shout gate"]
fn committed_isa_lookup_verifies_and_rejects_tampering() -> Result<(), IsaLookupError> {
    let address_bits = std::array::from_fn(|index| index);
    let outputs = std::array::from_fn(|index| ISA_ADDRESS_BIT_COUNT + index);
    let layout = IsaLookupColumns::new(address_bits, outputs)?;
    let table = fixed_isa_table()?;
    let mut columns = (0..(ISA_ADDRESS_BIT_COUNT + ISA_OUTPUT_COUNT))
        .map(|_| vec![0_u64; UNIFORM_ROW_COUNT])
        .collect::<Vec<_>>();
    for row_index in 0..UNIFORM_ROW_COUNT {
        let address = row_index % table.len();
        for (bit, column_index) in address_bits.iter().copied().enumerate() {
            let value = u64::from(((address >> bit) & 1) != 0);
            let column = columns.get_mut(column_index).ok_or(IsaLookupError::Shape)?;
            *column.get_mut(row_index).ok_or(IsaLookupError::Shape)? = value;
        }
        let table_outputs = table
            .get(address)
            .copied()
            .ok_or(IsaLookupError::Shape)?
            .outputs();
        for (column_index, value) in outputs.iter().copied().zip(table_outputs) {
            let column = columns.get_mut(column_index).ok_or(IsaLookupError::Shape)?;
            *column.get_mut(row_index).ok_or(IsaLookupError::Shape)? = value;
        }
    }
    let witness = commit_witness(&columns)?;
    let proof = prove_isa_lookup(layout, &witness)?;
    verify_isa_lookup(layout, witness.commitments(), &proof)?;
    assert_eq!(
        hex_digest(proof.table_commitments().digest()?),
        FIXED_ISA_TABLE_COMMITMENT_SHA256
    );

    let mut tampered = proof.clone();
    let first_round = tampered
        .table_sumcheck
        .rounds
        .first_mut()
        .ok_or(IsaLookupError::Shape)?;
    let first_value = first_round.first_mut().ok_or(IsaLookupError::Shape)?;
    *first_value += crate::NativeField::from_u64(1);
    assert!(verify_isa_lookup(layout, witness.commitments(), &tampered).is_err());

    let mut reordered_outputs = outputs;
    reordered_outputs.swap(0, 1);
    let reordered_layout = IsaLookupColumns::new(address_bits, reordered_outputs)?;
    assert!(verify_isa_lookup(reordered_layout, witness.commitments(), &proof).is_err());
    Ok(())
}
