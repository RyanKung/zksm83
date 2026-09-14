//! Fixed row and commitment geometry for native uniform relations.

use crate::{BLOCK_CPU_COLUMN_COUNT, NATIVE_TRACE_COLUMN_COUNT};

/// Number of rows in every native relation segment, including inactive padding.
pub const UNIFORM_ROW_COUNT: usize = 1 << UNIFORM_NUM_VARIABLES;

/// Number of row-address variables in every native relation segment.
pub const UNIFORM_NUM_VARIABLES: usize = 14;

/// Number of polynomials in each independently opened Akita commitment group.
pub const COMMITMENT_GROUP_COLUMNS: usize = 128;

/// Fixed number of commitment groups in the retained legacy native trace plane.
pub const NATIVE_TRACE_COMMITMENT_GROUP_COUNT: usize = 26;

/// Fixed number of adjacent-pair openings in the retained legacy native trace plane.
pub const NATIVE_TRACE_OPENING_COUNT: usize = NATIVE_TRACE_COMMITMENT_GROUP_COUNT / 2;

/// Physical retained native trace width after canonical group padding.
pub const NATIVE_TRACE_PADDED_COLUMN_COUNT: usize =
    NATIVE_TRACE_COMMITMENT_GROUP_COUNT * COMMITMENT_GROUP_COLUMNS;

/// Canonical zero columns remaining in the final retained native trace group.
pub const NATIVE_TRACE_PADDING_COLUMN_COUNT: usize =
    NATIVE_TRACE_PADDED_COLUMN_COUNT - NATIVE_TRACE_COLUMN_COUNT;

/// Fixed number of paired-opening commitment groups in the packed v2 CPU plane.
pub const BLOCK_CPU_COMMITMENT_GROUP_COUNT: usize = 36;

/// Fixed number of adjacent-pair openings in the packed v2 CPU plane.
pub const BLOCK_CPU_OPENING_COUNT: usize = BLOCK_CPU_COMMITMENT_GROUP_COUNT / 2;

/// Physical packed v2 CPU width after canonical group padding.
pub const BLOCK_CPU_PADDED_COLUMN_COUNT: usize =
    BLOCK_CPU_COMMITMENT_GROUP_COUNT * COMMITMENT_GROUP_COLUMNS;

/// Canonical zero columns remaining in the final packed v2 opening pair.
pub const BLOCK_CPU_PADDING_COLUMN_COUNT: usize =
    BLOCK_CPU_PADDED_COLUMN_COUNT - BLOCK_CPU_COLUMN_COUNT;

const _: () = assert!(NATIVE_TRACE_COMMITMENT_GROUP_COUNT.is_multiple_of(2));
const _: () = assert!(
    NATIVE_TRACE_COLUMN_COUNT
        > (NATIVE_TRACE_COMMITMENT_GROUP_COUNT - 1) * COMMITMENT_GROUP_COLUMNS
);
const _: () = assert!(NATIVE_TRACE_COLUMN_COUNT <= NATIVE_TRACE_PADDED_COLUMN_COUNT);
const _: () = assert!(BLOCK_CPU_COMMITMENT_GROUP_COUNT.is_multiple_of(2));
const _: () = assert!(
    BLOCK_CPU_COLUMN_COUNT > (BLOCK_CPU_COMMITMENT_GROUP_COUNT - 2) * COMMITMENT_GROUP_COLUMNS
);
const _: () = assert!(BLOCK_CPU_COLUMN_COUNT <= BLOCK_CPU_PADDED_COLUMN_COUNT);
