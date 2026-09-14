//! Canonical per-T-cycle timer stage layout shared by quiet and MMIO paths.

use zksm83_trace::BASIC_BLOCK_M_CYCLE_BOUND;

pub(crate) const STAGE_WIDTH: usize = 42;
pub(crate) const STAGE_DIV_BITS_OFFSET: usize = 0;
pub(crate) const STAGE_COUNTER_BITS_OFFSET: usize = 16;
pub(crate) const STAGE_PHASE_BITS_OFFSET: usize = 24;
pub(crate) const STAGE_LATCH_OFFSET: usize = 27;
pub(crate) const STAGE_INTERRUPT_OFFSET: usize = 28;
pub(crate) const STAGE_RELOAD_COUNTER_BITS_OFFSET: usize = 29;
pub(crate) const STAGE_RELOAD_PHASE_BITS_OFFSET: usize = 37;
pub(crate) const STAGE_DIV_WRAP_OFFSET: usize = 40;
pub(crate) const STAGE_COUNTER_OVERFLOW_OFFSET: usize = 41;
pub(crate) const TIMER_TICK_BOUND: usize = BASIC_BLOCK_M_CYCLE_BOUND * 4;
pub(crate) const TIMER_STAGE_COLUMN_COUNT: usize = TIMER_TICK_BOUND * STAGE_WIDTH;

const _: () = assert!(BASIC_BLOCK_M_CYCLE_BOUND == 6);
const _: () = assert!(TIMER_TICK_BOUND == 24);
const _: () = assert!(TIMER_STAGE_COLUMN_COUNT == 1_008);
const _: () = assert!(STAGE_COUNTER_OVERFLOW_OFFSET + 1 == STAGE_WIDTH);
