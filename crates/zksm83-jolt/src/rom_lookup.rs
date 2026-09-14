//! PCS-bound Shout lookup for the statement-scoped MBC3 cartridge ROM.

use akita_pcs::{AkitaTranscript, Ring, Transcript};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    AKITA_ROM_SCHEDULE_SHA256, AkitaWorkerError, FieldFoldError, NativeField,
    NativeProtocolVersion, NativeProverBackend, TRACE_BUS_SLOTS, UNIFORM_NUM_VARIABLES,
    pcs::{
        ColumnCommitments, CommittedColumns, OpeningProof, PcsError, PcsLayout,
        commit_columns_with_backend, prove_opening_with_backend, verify_opening_with_backend,
    },
    sumcheck::{
        ProductSumcheckError, ProductSumcheckProof, SumOfProductsSumcheckProof, SumcheckFactor,
    },
    uniform::{
        CommittedWitness, WitnessCommitments, prove_witness_selected_opening_with_backend,
        verify_witness_selected_opening_for_protocol_with_backend,
    },
};

/// Number of bytes in the padded one-MiB immutable-ROM lookup table.
pub const ROM_IMAGE_BYTES: usize = 1 << ROM_ADDRESS_BIT_COUNT;
/// Number of bytes in the supported 256-KiB MBC3 cartridge profile.
pub const ROM_256KIB_IMAGE_BYTES: usize = 256 * 1024;
/// Number of least-significant-bit-first physical ROM address columns.
pub const ROM_ADDRESS_BIT_COUNT: usize = 20;

const ROM_TABLE_NUM_VARIABLES: usize = ROM_ADDRESS_BIT_COUNT;
const ROM_LOOKUP_FACTOR_COUNT: usize = ROM_ADDRESS_BIT_COUNT + 2;
const ROM_LOOKUP_TRANSCRIPT_DOMAIN_V2: &[u8] = b"zksm83-native-rom-shout/v2";
const ROM_COMMITMENT_DOMAIN: &[u8] = b"zksm83/native-rom-commitment/v1";
const ROM_OPENING_DOMAIN: &[u8] = b"zksm83-native-rom-opening/v1";
const ROM_SCHEDULE_FILE: &[u8] =
    include_bytes!("../protocol/akita/fp128_dense_bounded_nv20_p1.aks");
const ROM_SCHEDULE_ARTIFACT: &[u8] = ROM_SCHEDULE_FILE.split_at(ROM_SCHEDULE_FILE.len() - 1).0;
const ROM_LAYOUT: PcsLayout = PcsLayout::new(
    ROM_TABLE_NUM_VARIABLES,
    1,
    ROM_SCHEDULE_ARTIFACT,
    ROM_COMMITMENT_DOMAIN,
    ROM_OPENING_DOMAIN,
);

/// Shared trace positions used by the five-way immutable-ROM read lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RomLookupColumns {
    selectors: [usize; TRACE_BUS_SLOTS],
    address_bits: [[usize; ROM_ADDRESS_BIT_COUNT]; TRACE_BUS_SLOTS],
    values: [usize; TRACE_BUS_SLOTS],
}

/// Prover-owned ROM polynomial and Akita commitment hint.
pub struct CommittedRom {
    inner: CommittedColumns,
    commitment: RomCommitment,
}

/// Verifier-visible commitment to the logical cartridge image and padded ROM table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RomCommitment {
    pub(crate) logical_byte_length: u64,
    pub(crate) inner: ColumnCommitments,
}

/// One batched Shout proof for all ROM reads in five trace bus slots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RomLookupProof {
    pub(crate) claimed_output: NativeField,
    pub(crate) table_sumcheck: ProductSumcheckProof,
    pub(crate) address_sumcheck: SumOfProductsSumcheckProof,
    pub(crate) table_values: Vec<NativeField>,
    pub(crate) trace_cycle_values: Vec<NativeField>,
    pub(crate) trace_address_values: Vec<NativeField>,
    pub(crate) table_opening: OpeningProof,
    pub(crate) trace_cycle_opening: OpeningProof,
    pub(crate) trace_address_opening: OpeningProof,
}

/// Invalid ROM image, lookup layout, proof, or backend operation.
#[derive(Debug, Error)]
pub enum RomLookupError {
    /// The cartridge image is not one of the supported logical profile sizes.
    #[error("ROM image has {actual} bytes; expected 262144 or 1048576")]
    InvalidRomLength {
        /// Supplied image length.
        actual: usize,
    },
    /// Selector, address-bit, and value columns are invalid or overlap.
    #[error("native ROM lookup column layout is invalid")]
    InvalidColumnLayout,
    /// A committed selector or address limb is not Boolean.
    #[error("native ROM lookup selector or address bit is not Boolean")]
    NonBoolean,
    /// Proof vectors or commitment dimensions are malformed.
    #[error("native ROM lookup proof shape is invalid")]
    Shape,
    /// The table inner product disagrees with the committed selected values.
    #[error("native ROM lookup output claim is inconsistent")]
    OutputClaimMismatch,
    /// The ROM opening disagrees with the table sumcheck terminal.
    #[error("native ROM lookup table opening is inconsistent")]
    TableOpeningMismatch,
    /// The committed selectors and addresses disagree with the lookup reduction.
    #[error("native ROM lookup address binding is inconsistent")]
    AddressBindingMismatch,
    /// A required Fiat-Shamir challenge was zero.
    #[error("native ROM lookup Fiat-Shamir challenge is zero")]
    ZeroChallenge,
    /// A native-field sumcheck failed.
    #[error("native ROM lookup sumcheck failed")]
    Sumcheck,
    /// The selected prover backend could not fold an evaluation table.
    #[error(transparent)]
    FieldFold(#[from] FieldFoldError),
    /// An Akita commitment or opening operation failed.
    #[error("native ROM lookup Akita operation failed: {0}")]
    Pcs(String),
    /// A shared-witness opening operation failed.
    #[error("native ROM lookup shared witness opening failed: {0}")]
    SharedOpening(#[from] crate::UniformError),
    /// The operating system rejected creation of the bounded proof worker.
    #[error("failed to start native ROM lookup worker: {0}")]
    WorkerSpawn(#[source] std::io::Error),
    /// The bounded proof worker panicked and its result was rejected.
    #[error("native ROM lookup worker terminated unexpectedly")]
    WorkerPanicked,
}

impl From<ProductSumcheckError> for RomLookupError {
    fn from(error: ProductSumcheckError) -> Self {
        match error {
            ProductSumcheckError::FieldFold(source) => Self::FieldFold(source),
            _ => Self::Sumcheck,
        }
    }
}

impl From<PcsError> for RomLookupError {
    fn from(error: PcsError) -> Self {
        Self::Pcs(error.to_string())
    }
}

impl RomLookupColumns {
    /// Creates a five-slot layout with physical address bits in LSB-first order.
    pub fn new(
        selectors: [usize; TRACE_BUS_SLOTS],
        address_bits: [[usize; ROM_ADDRESS_BIT_COUNT]; TRACE_BUS_SLOTS],
        values: [usize; TRACE_BUS_SLOTS],
    ) -> Result<Self, RomLookupError> {
        let layout = Self {
            selectors,
            address_bits,
            values,
        };
        layout.validate(usize::MAX)?;
        Ok(layout)
    }

    /// Returns the immutable-ROM event selector columns.
    #[must_use]
    pub const fn selectors(self) -> [usize; TRACE_BUS_SLOTS] {
        self.selectors
    }

    /// Returns each slot's physical ROM address columns.
    #[must_use]
    pub const fn address_bits(self) -> [[usize; ROM_ADDRESS_BIT_COUNT]; TRACE_BUS_SLOTS] {
        self.address_bits
    }

    /// Returns the selector-multiplied ROM byte columns.
    #[must_use]
    pub const fn values(self) -> [usize; TRACE_BUS_SLOTS] {
        self.values
    }

    fn validate(self, column_count: usize) -> Result<(), RomLookupError> {
        let mut indices = Vec::with_capacity(TRACE_BUS_SLOTS * (ROM_ADDRESS_BIT_COUNT + 2));
        indices.extend_from_slice(&self.selectors);
        indices.extend(self.address_bits.into_iter().flatten());
        indices.extend_from_slice(&self.values);
        indices.sort_unstable();
        if indices.iter().any(|index| *index >= column_count)
            || indices
                .windows(2)
                .any(|pair| matches!(pair, [left, right] if left == right))
        {
            return Err(RomLookupError::InvalidColumnLayout);
        }
        Ok(())
    }
}

impl CommittedRom {
    /// Returns the verifier-visible ROM commitment.
    #[must_use]
    pub const fn commitment(&self) -> &RomCommitment {
        &self.commitment
    }

    /// Returns the statement-bound logical ROM byte length.
    #[must_use]
    pub const fn logical_byte_length(&self) -> u64 {
        self.commitment.logical_byte_length
    }
}

impl RomCommitment {
    /// Returns the statement-bound logical ROM byte length.
    #[must_use]
    pub const fn logical_byte_length(&self) -> u64 {
        self.logical_byte_length
    }

    /// Returns the canonical protocol encoding of this ROM commitment.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RomLookupError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.logical_byte_length.to_le_bytes());
        bytes.extend_from_slice(&self.inner.canonical_bytes(ROM_LAYOUT)?);
        Ok(bytes)
    }

    /// Returns SHA-256 of the canonical ROM commitment encoding.
    pub fn digest(&self) -> Result<[u8; 32], RomLookupError> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }

    pub(crate) fn validate(&self) -> Result<(), RomLookupError> {
        let length = usize::try_from(self.logical_byte_length)
            .map_err(|_| RomLookupError::InvalidRomLength { actual: usize::MAX })?;
        validate_rom_length(length)?;
        self.inner.validate(ROM_LAYOUT).map_err(Into::into)
    }
}

/// Commits a supported logical cartridge ROM, padded to the one-MiB lookup table.
pub fn commit_rom(image: &[u8]) -> Result<CommittedRom, RomLookupError> {
    commit_rom_with_backend(image, &NativeProverBackend::cpu())
}

/// Commits a supported logical cartridge ROM through a backend boundary.
pub fn commit_rom_with_backend(
    image: &[u8],
    backend: &NativeProverBackend,
) -> Result<CommittedRom, RomLookupError> {
    validate_rom_length(image.len())?;
    on_worker(|| {
        let logical_byte_length =
            u64::try_from(image.len()).map_err(|_| RomLookupError::InvalidRomLength {
                actual: image.len(),
            })?;
        let mut padded = Vec::with_capacity(ROM_IMAGE_BYTES);
        padded.extend_from_slice(image);
        padded.resize(ROM_IMAGE_BYTES, 0);
        let column = padded.iter().copied().map(u64::from).collect::<Vec<_>>();
        let inner = commit_columns_with_backend(ROM_LAYOUT, &[column], backend)?;
        let commitment = RomCommitment {
            logical_byte_length,
            inner: inner.commitments().clone(),
        };
        Ok(CommittedRom { inner, commitment })
    })
}

/// Returns whether the native proof supports a logical ROM byte length.
#[must_use]
pub const fn is_supported_rom_length(length: usize) -> bool {
    matches!(length, ROM_256KIB_IMAGE_BYTES | ROM_IMAGE_BYTES)
}

fn validate_rom_length(length: usize) -> Result<(), RomLookupError> {
    if is_supported_rom_length(length) {
        Ok(())
    } else {
        Err(RomLookupError::InvalidRomLength { actual: length })
    }
}

/// Proves all selected immutable-ROM reads against one public ROM commitment.
pub fn prove_rom_lookup(
    layout: RomLookupColumns,
    rom: &CommittedRom,
    witness: &CommittedWitness,
) -> Result<RomLookupProof, RomLookupError> {
    prove_rom_lookup_with_backend(layout, rom, witness, &NativeProverBackend::cpu())
}

pub(crate) fn prove_rom_lookup_with_backend(
    layout: RomLookupColumns,
    rom: &CommittedRom,
    witness: &CommittedWitness,
    backend: &NativeProverBackend,
) -> Result<RomLookupProof, RomLookupError> {
    on_worker(|| prove_on_worker(layout, rom, witness, backend))
}

/// Verifies ROM reads without receiving the image, addresses, or read bytes.
pub fn verify_rom_lookup(
    layout: RomLookupColumns,
    rom: &RomCommitment,
    trace_commitments: &WitnessCommitments,
    proof: &RomLookupProof,
) -> Result<(), RomLookupError> {
    verify_rom_lookup_for_protocol(
        NativeProtocolVersion::current(),
        layout,
        rom,
        trace_commitments,
        proof,
    )
}

pub(crate) fn verify_rom_lookup_for_protocol(
    protocol: NativeProtocolVersion,
    layout: RomLookupColumns,
    rom: &RomCommitment,
    trace_commitments: &WitnessCommitments,
    proof: &RomLookupProof,
) -> Result<(), RomLookupError> {
    verify_rom_lookup_for_protocol_with_backend(
        protocol,
        layout,
        rom,
        trace_commitments,
        proof,
        &NativeProverBackend::cpu(),
    )
}

pub(crate) fn verify_rom_lookup_for_protocol_with_backend(
    protocol: NativeProtocolVersion,
    layout: RomLookupColumns,
    rom: &RomCommitment,
    trace_commitments: &WitnessCommitments,
    proof: &RomLookupProof,
    backend: &NativeProverBackend,
) -> Result<(), RomLookupError> {
    on_worker(|| verify_on_worker(protocol, layout, rom, trace_commitments, proof, backend))
}

fn prove_on_worker(
    layout: RomLookupColumns,
    rom: &CommittedRom,
    witness: &CommittedWitness,
    backend: &NativeProverBackend,
) -> Result<RomLookupProof, RomLookupError> {
    layout.validate(witness.commitments().column_count())?;
    rom.commitment.validate()?;
    let protocol = NativeProtocolVersion::current();
    let descriptor = instance_descriptor(protocol, layout, &rom.commitment, witness.commitments())?;
    let mut transcript = lookup_transcript(protocol, &descriptor, TranscriptSide::Prover);
    let coefficients = slot_coefficients(&mut transcript)?;
    let cycle_point = sample_point(&mut transcript, UNIFORM_NUM_VARIABLES, b"rom-cycle-point");
    let trace_columns = witness.field_columns()?;
    let rom_columns = rom.inner.field_columns()?;
    let mixed_trace = mix_columns(trace_columns.as_slice(), &layout.values, &coefficients)?;
    let claimed_output = evaluate_mle(&mixed_trace, &cycle_point)?;
    transcript.append_field(b"rom-claimed-output", &claimed_output);
    let cycle_weights = equality_evaluations(&cycle_point);
    let read_address = read_address_entries(
        trace_columns.as_slice(),
        layout,
        &coefficients,
        &cycle_weights,
    )?;
    let table = rom_columns
        .as_slice()
        .first()
        .ok_or(RomLookupError::Shape)?;
    let (table_sumcheck, actual_claim, table_point) = ProductSumcheckProof::prove_sparse_left(
        read_address,
        ROM_IMAGE_BYTES,
        table,
        backend,
        &mut transcript,
    )?;
    if actual_claim != claimed_output {
        return Err(RomLookupError::OutputClaimMismatch);
    }
    let table_values = evaluate_columns(rom_columns.as_slice(), &table_point)?;
    require_table_value(&table_values, table_sumcheck.final_right())?;
    let terms = address_binding_terms(
        trace_columns.as_slice(),
        layout,
        &coefficients,
        &cycle_weights,
        &table_point,
    )?;
    let (address_sumcheck, address_claim, address_point) =
        SumOfProductsSumcheckProof::prove_shared_first(terms, backend, &mut transcript)?;
    if address_claim != table_sumcheck.final_left() {
        return Err(RomLookupError::AddressBindingMismatch);
    }
    let (trace_cycle_values, trace_cycle_opening) = prove_witness_selected_opening_with_backend(
        witness,
        &cycle_point,
        &layout.values,
        &descriptor,
        backend,
    )?;
    require_mixed_value(
        &trace_cycle_values,
        &layout.values,
        &coefficients,
        claimed_output,
    )?;
    let address_opening_columns = address_opening_columns(layout);
    let (trace_address_values, trace_address_opening) =
        prove_witness_selected_opening_with_backend(
            witness,
            &address_point,
            &address_opening_columns,
            &descriptor,
            backend,
        )?;
    verify_address_terminal(
        &address_sumcheck,
        layout,
        &coefficients,
        &cycle_point,
        &table_point,
        &address_point,
        &trace_address_values,
    )?;
    let table_opening = prove_opening_with_backend(
        ROM_LAYOUT,
        &rom.inner,
        &table_point,
        &table_values,
        &descriptor,
        backend,
    )?;
    Ok(RomLookupProof {
        claimed_output,
        table_sumcheck,
        address_sumcheck,
        table_values,
        trace_cycle_values,
        trace_address_values,
        table_opening,
        trace_cycle_opening,
        trace_address_opening,
    })
}

fn verify_on_worker(
    protocol: NativeProtocolVersion,
    layout: RomLookupColumns,
    rom: &RomCommitment,
    trace_commitments: &WitnessCommitments,
    proof: &RomLookupProof,
    backend: &NativeProverBackend,
) -> Result<(), RomLookupError> {
    layout.validate(trace_commitments.column_count())?;
    rom.validate()?;
    let descriptor = instance_descriptor(protocol, layout, rom, trace_commitments)?;
    let mut transcript = lookup_transcript(protocol, &descriptor, TranscriptSide::Verifier);
    let coefficients = slot_coefficients(&mut transcript)?;
    let cycle_point = sample_point(&mut transcript, UNIFORM_NUM_VARIABLES, b"rom-cycle-point");
    transcript.append_field(b"rom-claimed-output", &proof.claimed_output);
    let table_point = proof.table_sumcheck.verify(
        proof.claimed_output,
        ROM_TABLE_NUM_VARIABLES,
        &mut transcript,
    )?;
    verify_opening_with_backend(
        ROM_LAYOUT,
        &rom.inner,
        &table_point,
        &proof.table_values,
        &descriptor,
        &proof.table_opening,
        backend,
    )?;
    require_table_value(&proof.table_values, proof.table_sumcheck.final_right())?;
    let address_point = proof.address_sumcheck.verify(
        proof.table_sumcheck.final_left(),
        UNIFORM_NUM_VARIABLES,
        TRACE_BUS_SLOTS,
        ROM_LOOKUP_FACTOR_COUNT,
        &mut transcript,
    )?;
    verify_witness_selected_opening_for_protocol_with_backend(
        protocol,
        trace_commitments,
        &cycle_point,
        &proof.trace_cycle_values,
        &layout.values,
        &descriptor,
        &proof.trace_cycle_opening,
        backend,
    )?;
    require_mixed_value(
        &proof.trace_cycle_values,
        &layout.values,
        &coefficients,
        proof.claimed_output,
    )?;
    let address_opening_columns = address_opening_columns(layout);
    verify_witness_selected_opening_for_protocol_with_backend(
        protocol,
        trace_commitments,
        &address_point,
        &proof.trace_address_values,
        &address_opening_columns,
        &descriptor,
        &proof.trace_address_opening,
        backend,
    )?;
    verify_address_terminal(
        &proof.address_sumcheck,
        layout,
        &coefficients,
        &cycle_point,
        &table_point,
        &address_point,
        &proof.trace_address_values,
    )
}

fn address_opening_columns(layout: RomLookupColumns) -> Vec<usize> {
    layout
        .selectors
        .into_iter()
        .chain(layout.address_bits.into_iter().flatten())
        .collect()
}

fn read_address_entries(
    columns: &[impl AsRef<[NativeField]>],
    layout: RomLookupColumns,
    coefficients: &[NativeField; TRACE_BUS_SLOTS],
    cycle_weights: &[NativeField],
) -> Result<Vec<(usize, NativeField)>, RomLookupError> {
    let capacity = cycle_weights
        .len()
        .checked_mul(TRACE_BUS_SLOTS)
        .ok_or(RomLookupError::Shape)?;
    let mut reads = Vec::with_capacity(capacity);
    for ((selector_index, address_bits), coefficient) in layout
        .selectors
        .iter()
        .copied()
        .zip(&layout.address_bits)
        .zip(coefficients)
    {
        let selectors = column(columns, selector_index, cycle_weights.len())?;
        let addresses = trace_addresses(columns, address_bits, cycle_weights.len())?;
        for ((selector, address), weight) in selectors.iter().zip(addresses).zip(cycle_weights) {
            require_boolean(*selector)?;
            if *selector != NativeField::from_u64(0) {
                reads.push((address, *weight * *coefficient * *selector));
            }
        }
    }
    Ok(reads)
}

fn trace_addresses(
    columns: &[impl AsRef<[NativeField]>],
    bits: &[usize; ROM_ADDRESS_BIT_COUNT],
    row_count: usize,
) -> Result<Vec<usize>, RomLookupError> {
    let mut addresses = vec![0_usize; row_count];
    for (bit, index) in bits.iter().copied().enumerate() {
        let values = column(columns, index, row_count)?;
        for (address, value) in addresses.iter_mut().zip(values) {
            require_boolean(*value)?;
            if *value == NativeField::from_u64(1) {
                *address |= 1_usize << bit;
            }
        }
    }
    Ok(addresses)
}

fn address_binding_terms<'a>(
    columns: &'a [impl AsRef<[NativeField]>],
    layout: RomLookupColumns,
    coefficients: &[NativeField; TRACE_BUS_SLOTS],
    cycle_weights: &'a [NativeField],
    table_point: &[NativeField],
) -> Result<Vec<Vec<SumcheckFactor<'a>>>, RomLookupError> {
    if table_point.len() != ROM_ADDRESS_BIT_COUNT {
        return Err(RomLookupError::Shape);
    }
    let one = NativeField::from_u64(1);
    layout
        .selectors
        .iter()
        .copied()
        .zip(&layout.address_bits)
        .zip(coefficients)
        .map(|((selector_index, address_bits), coefficient)| {
            let selector = column(columns, selector_index, cycle_weights.len())?;
            let mut factors = Vec::with_capacity(ROM_LOOKUP_FACTOR_COUNT);
            factors.push(SumcheckFactor::borrowed(cycle_weights));
            factors.push(SumcheckFactor::scaled(selector, *coefficient));
            for (index, point) in address_bits.iter().zip(table_point) {
                let bits = column(columns, *index, cycle_weights.len())?;
                factors.push(SumcheckFactor::affine(
                    bits,
                    NativeField::from_u64(2) * *point - one,
                    one - *point,
                ));
            }
            Ok(factors)
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn verify_address_terminal(
    proof: &SumOfProductsSumcheckProof,
    layout: RomLookupColumns,
    coefficients: &[NativeField; TRACE_BUS_SLOTS],
    cycle_point: &[NativeField],
    table_point: &[NativeField],
    address_point: &[NativeField],
    trace_values: &[NativeField],
) -> Result<(), RomLookupError> {
    if table_point.len() != ROM_ADDRESS_BIT_COUNT || proof.final_terms().len() != TRACE_BUS_SLOTS {
        return Err(RomLookupError::Shape);
    }
    let expected_weight = equality_evaluation(cycle_point, address_point)?;
    let one = NativeField::from_u64(1);
    for (((factors, selector_index), address_bits), coefficient) in proof
        .final_terms()
        .iter()
        .zip(layout.selectors)
        .zip(layout.address_bits)
        .zip(coefficients)
    {
        if factors.first().copied() != Some(expected_weight)
            || factors.get(1).copied()
                != Some(*coefficient * trace_value(trace_values, selector_index)?)
        {
            return Err(RomLookupError::AddressBindingMismatch);
        }
        for (offset, (index, point)) in address_bits.iter().zip(table_point).enumerate() {
            let bit = trace_value(trace_values, *index)?;
            let expected = bit * *point + (one - bit) * (one - *point);
            if factors.get(offset + 2).copied() != Some(expected) {
                return Err(RomLookupError::AddressBindingMismatch);
            }
        }
    }
    Ok(())
}

fn slot_coefficients(
    transcript: &mut AkitaTranscript<NativeField>,
) -> Result<[NativeField; TRACE_BUS_SLOTS], RomLookupError> {
    let challenge = transcript.challenge_scalar(b"rom-slot-mix");
    if challenge == NativeField::from_u64(0) {
        return Err(RomLookupError::ZeroChallenge);
    }
    let mut power = NativeField::from_u64(1);
    Ok(std::array::from_fn(|_| {
        let coefficient = power;
        power *= challenge;
        coefficient
    }))
}

fn instance_descriptor(
    protocol: NativeProtocolVersion,
    layout: RomLookupColumns,
    rom: &RomCommitment,
    trace: &WitnessCommitments,
) -> Result<Vec<u8>, RomLookupError> {
    let mut descriptor = Vec::new();
    push_bytes(&mut descriptor, protocol.protocol_id().as_bytes())?;
    push_bytes(&mut descriptor, AKITA_ROM_SCHEDULE_SHA256.as_bytes())?;
    push_usize(&mut descriptor, ROM_IMAGE_BYTES)?;
    push_indices(&mut descriptor, &layout.selectors)?;
    for bits in layout.address_bits {
        push_indices(&mut descriptor, &bits)?;
    }
    push_indices(&mut descriptor, &layout.values)?;
    push_bytes(&mut descriptor, &rom.canonical_bytes()?)?;
    push_bytes(&mut descriptor, &trace.canonical_bytes_for(protocol)?)?;
    Ok(descriptor)
}

enum TranscriptSide {
    Prover,
    Verifier,
}

fn lookup_transcript(
    protocol: NativeProtocolVersion,
    descriptor: &[u8],
    side: TranscriptSide,
) -> AkitaTranscript<NativeField> {
    let domain = match protocol {
        NativeProtocolVersion::V2 => ROM_LOOKUP_TRANSCRIPT_DOMAIN_V2,
    };
    let mut transcript = match side {
        TranscriptSide::Prover => AkitaTranscript::unbound_prover(domain),
        TranscriptSide::Verifier => AkitaTranscript::unbound_verifier(domain),
    };
    transcript.bind_instance_bytes(descriptor);
    transcript
}

fn sample_point(
    transcript: &mut AkitaTranscript<NativeField>,
    count: usize,
    label: &[u8],
) -> Vec<NativeField> {
    (0..count)
        .map(|_| transcript.challenge_scalar(label))
        .collect()
}

fn mix_columns(
    columns: &[impl AsRef<[NativeField]>],
    indices: &[usize],
    coefficients: &[NativeField],
) -> Result<Vec<NativeField>, RomLookupError> {
    if indices.is_empty() || indices.len() != coefficients.len() {
        return Err(RomLookupError::Shape);
    }
    let row_count = columns
        .first()
        .map(|column| column.as_ref().len())
        .ok_or(RomLookupError::Shape)?;
    let mut mixed = vec![NativeField::from_u64(0); row_count];
    for (index, coefficient) in indices.iter().copied().zip(coefficients) {
        for (target, value) in mixed.iter_mut().zip(column(columns, index, row_count)?) {
            *target += *coefficient * *value;
        }
    }
    Ok(mixed)
}

fn require_mixed_value(
    values: &[NativeField],
    indices: &[usize],
    coefficients: &[NativeField],
    expected: NativeField,
) -> Result<(), RomLookupError> {
    if indices.len() != coefficients.len() {
        return Err(RomLookupError::Shape);
    }
    let actual = indices.iter().copied().zip(coefficients).try_fold(
        NativeField::from_u64(0),
        |sum, (index, coefficient)| {
            Ok::<_, RomLookupError>(sum + *coefficient * trace_value(values, index)?)
        },
    )?;
    if actual != expected {
        return Err(RomLookupError::OutputClaimMismatch);
    }
    Ok(())
}

fn require_table_value(
    values: &[NativeField],
    expected: NativeField,
) -> Result<(), RomLookupError> {
    if values.len() != 1 || values.first().copied() != Some(expected) {
        return Err(RomLookupError::TableOpeningMismatch);
    }
    Ok(())
}

fn evaluate_columns(
    columns: &[impl AsRef<[NativeField]>],
    point: &[NativeField],
) -> Result<Vec<NativeField>, RomLookupError> {
    columns
        .iter()
        .map(|column| evaluate_mle(column.as_ref(), point))
        .collect()
}

fn evaluate_mle(
    evaluations: &[NativeField],
    point: &[NativeField],
) -> Result<NativeField, RomLookupError> {
    crate::field_fold::evaluate_mle(evaluations, point).map_err(|_| RomLookupError::Shape)
}

fn equality_evaluations(point: &[NativeField]) -> Vec<NativeField> {
    let one = NativeField::from_u64(1);
    let mut evaluations = vec![one];
    for coordinate in point {
        let mut next = Vec::with_capacity(evaluations.len() * 2);
        next.extend(evaluations.iter().map(|value| *value * (one - *coordinate)));
        next.extend(evaluations.iter().map(|value| *value * *coordinate));
        evaluations = next;
    }
    evaluations
}

fn equality_evaluation(
    left: &[NativeField],
    right: &[NativeField],
) -> Result<NativeField, RomLookupError> {
    if left.len() != right.len() {
        return Err(RomLookupError::Shape);
    }
    let one = NativeField::from_u64(1);
    Ok(left.iter().zip(right).fold(one, |product, (left, right)| {
        product * (*left * *right + (one - *left) * (one - *right))
    }))
}

fn column(
    columns: &[impl AsRef<[NativeField]>],
    index: usize,
    row_count: usize,
) -> Result<&[NativeField], RomLookupError> {
    let column = columns
        .get(index)
        .map(AsRef::as_ref)
        .ok_or(RomLookupError::Shape)?;
    if column.len() != row_count {
        return Err(RomLookupError::Shape);
    }
    Ok(column)
}

fn trace_value(values: &[NativeField], index: usize) -> Result<NativeField, RomLookupError> {
    values.get(index).copied().ok_or(RomLookupError::Shape)
}

fn require_boolean(value: NativeField) -> Result<(), RomLookupError> {
    if value != NativeField::from_u64(0) && value != NativeField::from_u64(1) {
        return Err(RomLookupError::NonBoolean);
    }
    Ok(())
}

fn push_indices(bytes: &mut Vec<u8>, indices: &[usize]) -> Result<(), RomLookupError> {
    push_usize(bytes, indices.len())?;
    for index in indices {
        push_usize(bytes, *index)?;
    }
    Ok(())
}

fn push_usize(bytes: &mut Vec<u8>, value: usize) -> Result<(), RomLookupError> {
    let value = u64::try_from(value).map_err(|_| RomLookupError::Shape)?;
    bytes.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), RomLookupError> {
    push_usize(bytes, value.len())?;
    bytes.extend_from_slice(value);
    Ok(())
}

fn on_worker<T: Send>(
    operation: impl FnOnce() -> Result<T, RomLookupError> + Send,
) -> Result<T, RomLookupError> {
    match crate::on_akita_worker(operation) {
        Ok(result) => result,
        Err(AkitaWorkerError::Spawn(error)) => Err(RomLookupError::WorkerSpawn(error)),
        Err(AkitaWorkerError::Panicked) => Err(RomLookupError::WorkerPanicked),
    }
}

#[cfg(test)]
mod tests {
    use akita_pcs::Ring;
    use sha2::{Digest, Sha256};

    use super::{
        ROM_ADDRESS_BIT_COUNT, ROM_IMAGE_BYTES, ROM_LAYOUT, ROM_SCHEDULE_ARTIFACT,
        RomLookupColumns, RomLookupError, commit_rom, prove_rom_lookup, verify_rom_lookup,
    };
    use crate::{
        AKITA_ROM_SCHEDULE_SHA256, TRACE_BUS_SLOTS, UNIFORM_ROW_COUNT, commit_witness, pcs::scheme,
    };

    #[test]
    fn pinned_rom_schedule_admits_exact_rom_shape() -> Result<(), RomLookupError> {
        let scheme = scheme(ROM_LAYOUT)?;
        let admitted = scheme.schedules().catalog().rows().any(|row| {
            row.profiles().final_group.group.num_vars() == ROM_ADDRESS_BIT_COUNT
                && row.profiles().final_group.group.num_polynomials() == 1
                && row.profiles().precommitteds.is_empty()
        });
        assert!(admitted);
        assert_eq!(ROM_IMAGE_BYTES, 1 << 20);
        assert_eq!(
            format!("{:x}", Sha256::digest(ROM_SCHEDULE_ARTIFACT)),
            AKITA_ROM_SCHEDULE_SHA256
        );
        Ok(())
    }

    #[test]
    fn overlapping_rom_layout_is_rejected() {
        let selectors = [0; TRACE_BUS_SLOTS];
        let addresses = [[1; ROM_ADDRESS_BIT_COUNT]; TRACE_BUS_SLOTS];
        let values = [2; TRACE_BUS_SLOTS];
        assert!(RomLookupColumns::new(selectors, addresses, values).is_err());
    }

    #[test]
    fn rejects_non_profile_rom_length() {
        assert!(matches!(
            commit_rom(&[0; 32]),
            Err(RomLookupError::InvalidRomLength { .. })
        ));
    }

    #[test]
    fn commits_supported_256kib_logical_rom_length() -> Result<(), RomLookupError> {
        let image = vec![0x5a; super::ROM_256KIB_IMAGE_BYTES];
        let committed = commit_rom(&image)?;
        assert_eq!(
            committed.logical_byte_length(),
            u64::try_from(super::ROM_256KIB_IMAGE_BYTES).map_err(|_| RomLookupError::Shape)?
        );
        assert_eq!(
            committed.commitment().logical_byte_length(),
            u64::try_from(super::ROM_256KIB_IMAGE_BYTES).map_err(|_| RomLookupError::Shape)?
        );
        Ok(())
    }

    #[test]
    #[ignore = "expensive one-MiB ROM commitment plus shared-trace Shout gate"]
    fn committed_rom_lookup_verifies_and_rejects_tampering() -> Result<(), RomLookupError> {
        let selectors = std::array::from_fn(|slot| slot);
        let address_bits = std::array::from_fn(|slot| {
            std::array::from_fn(|bit| TRACE_BUS_SLOTS + slot * ROM_ADDRESS_BIT_COUNT + bit)
        });
        let value_start = TRACE_BUS_SLOTS * (ROM_ADDRESS_BIT_COUNT + 1);
        let values = std::array::from_fn(|slot| value_start + slot);
        let layout = RomLookupColumns::new(selectors, address_bits, values)?;
        let image = (0..ROM_IMAGE_BYTES)
            .map(|address| {
                u8::try_from((address * 17 + 3) & 0xff).map_err(|_| RomLookupError::Shape)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut columns = (0..value_start + TRACE_BUS_SLOTS)
            .map(|_| vec![0_u64; UNIFORM_ROW_COUNT])
            .collect::<Vec<_>>();
        populate_queries(&mut columns, layout, &image)?;
        let rom = commit_rom(&image)?;
        let witness = commit_witness(&columns)?;
        let proof = prove_rom_lookup(layout, &rom, &witness)?;
        verify_rom_lookup(layout, rom.commitment(), witness.commitments(), &proof)?;

        let mut tampered = proof;
        let round = tampered
            .table_sumcheck
            .rounds
            .first_mut()
            .ok_or(RomLookupError::Shape)?;
        *round.first_mut().ok_or(RomLookupError::Shape)? += crate::NativeField::from_u64(1);
        assert!(
            verify_rom_lookup(layout, rom.commitment(), witness.commitments(), &tampered).is_err()
        );
        Ok(())
    }

    fn populate_queries(
        columns: &mut [Vec<u64>],
        layout: RomLookupColumns,
        image: &[u8],
    ) -> Result<(), RomLookupError> {
        for row in 0..UNIFORM_ROW_COUNT {
            for (slot, ((selector_index, address_bits), value_index)) in layout
                .selectors
                .iter()
                .copied()
                .zip(&layout.address_bits)
                .zip(layout.values)
                .enumerate()
            {
                let selected = (row + slot).is_multiple_of(slot + 2);
                let address = (row * 31 + slot * 65_537) % ROM_IMAGE_BYTES;
                set(columns, selector_index, row, u64::from(selected))?;
                for (bit, index) in address_bits.iter().copied().enumerate() {
                    let limb =
                        u64::try_from((address >> bit) & 1).map_err(|_| RomLookupError::Shape)?;
                    set(columns, index, row, limb)?;
                }
                set(
                    columns,
                    value_index,
                    row,
                    u64::from(selected)
                        * u64::from(*image.get(address).ok_or(RomLookupError::Shape)?),
                )?;
            }
        }
        Ok(())
    }

    fn set(
        columns: &mut [Vec<u64>],
        column: usize,
        row: usize,
        value: u64,
    ) -> Result<(), RomLookupError> {
        *columns
            .get_mut(column)
            .and_then(|column| column.get_mut(row))
            .ok_or(RomLookupError::Shape)? = value;
        Ok(())
    }
}
