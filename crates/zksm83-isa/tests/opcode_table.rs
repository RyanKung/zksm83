//! Exhaustive opcode-table proposition tests.

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use zksm83_isa::{
    AluOperation, CbOperation, FlagAction, InstructionEncoding, OPCODE_TABLE, OpcodeClassification,
    Operand8, Operation, StateComponent, TransferDirection, UndefinedOpcode, decode_cb,
    decode_primary,
};

const UNDEFINED_PRIMARY: [u8; 11] = [
    0xd3, 0xdb, 0xdd, 0xe3, 0xe4, 0xeb, 0xec, 0xed, 0xf4, 0xfc, 0xfd,
];

#[test]
fn opcode_table_covers_every_primary_byte() {
    let entries = OPCODE_TABLE.primary_entries().collect::<Vec<_>>();
    assert_eq!(entries.len(), 256);
    assert_eq!(
        entries
            .iter()
            .filter(|entry| matches!(entry, OpcodeClassification::Defined(_)))
            .count(),
        245
    );
    for byte in u8::MIN..=u8::MAX {
        match decode_primary(byte) {
            OpcodeClassification::Defined(decoded) => {
                assert!(matches!(
                    decoded.encoding(),
                    InstructionEncoding::Primary(opcode) if opcode.byte() == byte
                ));
            }
            OpcodeClassification::Undefined(undefined) => {
                assert!(UNDEFINED_PRIMARY.contains(&undefined.byte));
            }
        }
    }
}

#[test]
fn cb_opcode_table_covers_every_secondary_byte() {
    let entries = OPCODE_TABLE.cb_entries().collect::<Vec<_>>();
    assert_eq!(entries.len(), 256);
    for (byte, decoded) in (u8::MIN..=u8::MAX).zip(entries) {
        assert_eq!(
            decoded.encoding(),
            InstructionEncoding::Cb(zksm83_isa::CbOpcode::new(byte))
        );
    }
}

#[test]
fn undefined_opcode_fails_closed() {
    for byte in UNDEFINED_PRIMARY {
        assert_eq!(
            decode_primary(byte),
            OpcodeClassification::Undefined(zksm83_isa::UndefinedOpcode { byte })
        );
    }
}

#[test]
fn decode_encode_opcode_round_trip_preserves_instruction() {
    for byte in u8::MIN..=u8::MAX {
        if let OpcodeClassification::Defined(decoded) = decode_primary(byte) {
            let (encoded, encoded_len) = decoded.encoded_opcode();
            assert_eq!(encoded_len, 1);
            assert_eq!(encoded.first().copied(), Some(byte));
            assert_eq!(decode_primary(byte), OpcodeClassification::Defined(decoded));
        }

        let decoded_cb = decode_cb(byte);
        let (encoded, encoded_len) = decoded_cb.encoded_opcode();
        assert_eq!(encoded_len, 2);
        assert_eq!(encoded.first().copied(), Some(0xcb));
        assert_eq!(encoded.last().copied(), Some(byte));
        assert_eq!(decode_cb(byte), decoded_cb);
    }
}

#[test]
fn instruction_length_matches_table() {
    for entry in OPCODE_TABLE.primary_entries() {
        let OpcodeClassification::Defined(decoded) = entry else {
            continue;
        };
        assert!((1..=3).contains(&decoded.byte_len()));
        assert_eq!(
            decoded.bus().opcode_fetches() + decoded.bus().immediate_reads(),
            decoded.byte_len()
        );
    }
    for decoded in OPCODE_TABLE.cb_entries() {
        assert_eq!(decoded.byte_len(), 2);
        assert_eq!(decoded.bus().opcode_fetches(), 2);
        assert_eq!(decoded.bus().immediate_reads(), 0);
    }
}

#[test]
fn timing_matches_table() {
    let mut primary_manifest = Vec::with_capacity(256 * 4);
    for entry in OPCODE_TABLE.primary_entries() {
        match entry {
            OpcodeClassification::Defined(decoded) => primary_manifest.extend([
                1,
                decoded.byte_len(),
                decoded.timing().base_m_cycles(),
                decoded.timing().taken_m_cycles().map_or(0, |cycles| cycles),
            ]),
            OpcodeClassification::Undefined(_) => primary_manifest.extend([0, 0, 0, 0]),
        }
    }
    let primary_digest = Sha256::digest(primary_manifest);
    assert_eq!(
        format!("{primary_digest:x}"),
        "4c2ecd6f834a8fb3d9305b3893435c79519abfb185bb763c966ccc9c91002a8c"
    );

    let cb_manifest = OPCODE_TABLE
        .cb_entries()
        .map(|decoded| decoded.timing().base_m_cycles())
        .collect::<Vec<_>>();
    let cb_digest = Sha256::digest(cb_manifest);
    assert_eq!(
        format!("{cb_digest:x}"),
        "3d2c060a33cb93a63c14ef27c2fd21b4327f84dd46f8aa3bce0527fe099b95e3"
    );
}

#[test]
fn flag_laws_match_fixtures() -> Result<(), UndefinedOpcode> {
    let inc_b = defined(0x04)?;
    assert_eq!(inc_b.flags().zero, FlagAction::Derived);
    assert_eq!(inc_b.flags().subtract, FlagAction::Clear);
    assert_eq!(inc_b.flags().half_carry, FlagAction::Derived);
    assert_eq!(inc_b.flags().carry, FlagAction::Preserve);

    let and_immediate = defined(0xe6)?;
    assert_eq!(
        and_immediate.operation(),
        Operation::Alu8(AluOperation::And, Operand8::Immediate)
    );
    assert_eq!(and_immediate.flags().half_carry, FlagAction::Set);
    assert_eq!(and_immediate.flags().carry, FlagAction::Clear);

    let bit_hl = decode_cb(0x46);
    assert_eq!(
        bit_hl.operation(),
        Operation::Cb(CbOperation::TestBit(0), Operand8::IndirectHl)
    );
    assert_eq!(bit_hl.flags().half_carry, FlagAction::Set);
    assert_eq!(bit_hl.flags().carry, FlagAction::Preserve);
    Ok(())
}

#[test]
fn bus_and_state_effects_match_fixtures() -> Result<(), UndefinedOpcode> {
    let store_sp = defined(0x08)?;
    assert_eq!(store_sp.bus().immediate_reads(), 2);
    assert_eq!(store_sp.bus().data_writes(), 2);
    assert!(store_sp.state_access().reads(StateComponent::Sp));

    let load_high_a = defined(0xf0)?;
    assert_eq!(
        load_high_a.operation(),
        Operation::HighImmediateLoad(TransferDirection::IntoAccumulator)
    );
    assert_eq!(load_high_a.bus().data_reads(), 1);
    assert!(load_high_a.state_access().writes(StateComponent::A));

    let conditional_return = defined(0xc0)?;
    assert_eq!(conditional_return.bus().data_reads(), 0);
    assert_eq!(conditional_return.bus().taken_data_reads(), 2);
    assert!(conditional_return.state_access().reads(StateComponent::Sp));

    let reset_hl = decode_cb(0x86);
    assert_eq!(reset_hl.bus().data_reads(), 1);
    assert_eq!(reset_hl.bus().data_writes(), 1);
    assert!(reset_hl.state_access().reads(StateComponent::H));
    assert!(reset_hl.state_access().reads(StateComponent::L));
    Ok(())
}

#[test]
fn proof_descriptors_uniquely_identify_defined_encodings() {
    let mut descriptors = HashSet::new();
    for entry in OPCODE_TABLE.primary_entries() {
        if let OpcodeClassification::Defined(decoded) = entry {
            assert!(descriptors.insert(decoded.descriptor()));
        }
    }
    for decoded in OPCODE_TABLE.cb_entries() {
        assert!(descriptors.insert(decoded.descriptor()));
    }
    assert_eq!(descriptors.len(), 501);
}

fn defined(byte: u8) -> Result<zksm83_isa::DecodedInstruction, UndefinedOpcode> {
    match decode_primary(byte) {
        OpcodeClassification::Defined(decoded) => Ok(decoded),
        OpcodeClassification::Undefined(undefined) => Err(undefined),
    }
}
