# Implementation status

This document separates code-complete protocol surfaces from validation that
has actually been performed. Generated receipts, ROMs, traces, saves, inputs,
and measurements are not versioned.

## Current pipeline

The workspace has one proof route: native SM83 execution is packed into generic
bounded blocks and proved by `zksm83-jolt` with the transparent Akita lattice
PCS. There is no RV64 guest, compiler, emulator replay in the verifier,
Halo2/Pasta path, MOVA path, or ROM-specific transition.

The v2 main witness is `BlockCpuWitness`. One active relation row is either:

- an instruction block containing one to four ordered SM83 instructions; or
- one generic machine-event block for HALT/device progress, interrupt dispatch,
  or DMA progress.

The deepest row-local relation is `BlockCpuRelation`:

| Property | v2 value |
| --- | ---: |
| Logical columns | 4,505 |
| Fixed constraint slots | 13,004 |
| Conservative maximum degree | 41 |
| Rows per segment | 16,384 |
| Columns per commitment group | 128 |
| Commitment groups | 36 |
| Adjacent-pair openings | 18 |
| Physical padded columns | 4,608 |
| Canonical zero columns | 103 |

The final 858 columns contain five shared 106-column CPU/mapper boundary bit
ranges plus four 82-column lane-local semantic ranges. Six scalar helpers per
lane are derived linearly from their committed bits. Before/after state, ISA
outputs, branch decisions, ROM values, and bus tuples are projected from the
shared packed prefix instead of copied into four legacy 3,292-column rows.

The relation reuses the native instruction constraints for register and flag
ranges, state write masks, MBC3 mapping, byte arithmetic, control flow and
fetch, data movement, 16-bit operations, stack operations, bit/rotate
operations, and DAA. Device behavior remains in the shared block prefix and is
not duplicated per instruction lane.

## Receipt composition

`PackedBlockProof` is now the segment proof encoded by `NativeSegmentReceipt`.
Every component opens the same 4,505-column commitment plane where applicable:

1. `BlockCpuRelation` for the packed shared device/memory relation and all four
   lane-local CPU semantics;
2. four fixed-ISA table lookups, one for each lane;
3. immutable one-MiB ROM lookup;
4. ordered 128-KiB mutable-memory chronology and boundary commitments;
5. cross-row state continuity and exact public segment endpoints; and
6. canonical-position bus/input/output/ISA log arguments.

The receipt statement binds the ROM identity, exact initial and final machine
boundaries, segment count, packed relation-row count, M-cycle delta, and all
four cumulative log identities. The independent verifier receives a separately
pinned statement and does not receive an emulator, trace, ROM image, memory
image, or private log values.

The canonical receipt layer is a hard v2 cutover. Writers emit `ZKSM83R2` and
`ZKSM83S2`; high-level validation and wire decoders reject v1 rather than
dispatching a legacy nested proof layout. The former one-transition CPU,
continuity, memory, and log proof types, functions, relation modules, and wire
encodings have been deleted. The one-transition witness/relation survives only
as a semantic reference for packed lane construction and audit; it has no
receipt entry point. `ZKSM83R1`/`ZKSM83S1` survive only as explicit rejection
sentinels. Lower-level `/v1` suffixes name independently frozen PCS component
schemas and are not selectable receipt versions.

## Generic execution model

The sole execution semantics remain `zksm83_core::StepRelation`. Block planning
uses only authenticated machine state and generic resource bounds: at most four
instructions, bounded M-cycles, bounded shared bus events, control-flow cuts,
and machine-event boundaries. It does not inspect cartridge identity, ROM root,
fixed PC ranges, bank values, or opcode byte patterns to select a fast path.

The shared relation covers ordinary instruction timing, long HALT advancement,
VBlank/STAT, serial completion, timer reload and edge behavior, interrupt
priority/dispatch, DMA debt and byte copies, implemented DMG MMIO, joypad, APU,
MBC3, mutable memory, and stream cursors. ISA and bus ordering belongs to the
explicit lookup/log planes; lookup-native legacy ISA/bus state cursors remain
zero under v2.

## Crash recovery

The prover writes a complete length-delimited segment frame, synchronizes the
spool, and only then atomically publishes its state/memory progress checkpoint.
Resume truncates only an uncheckpointed crash tail and verifies every retained
frame before continuing.

Segment construction now fills the packed-row capacity rather than limiting a
segment to 16,384 raw transitions. It repeatedly executes at most the number
of still-free rows, packs that bounded chunk, and continues while capacity
remains. Because one raw transition can always consume at most one block row,
the builder cannot overrun the fixed relation. Instruction-heavy segments can
therefore approach four transitions per row, while machine-event-heavy
segments safely fall back toward one per row.

Progress schema v5 separates two quantities that ceased to be interchangeable
after block packing:

- `completed_steps`: raw emulator transitions authenticated by the verified
  spool and used to resume endpoint replay;
- `relation_row_count`: authenticated packed rows recovered from the spool.

The packed continuity auxiliary plane commits the per-row source transition
count and its opened sum, so a checkpoint cannot advance `completed_steps`
without a matching proof frame. The checkpoint also binds the receipt version,
protocol ID, explicit proof-composition revision, compiled backend digest, both
PCS schedule digests, input identities, segment count, exact spool length, VM
state, and full mutable-memory checkpoint. There is no fallback reader for
older progress schemas. Recovery durably synchronizes a truncated crash tail
before replaying, and finalization rechecks that the receipt path is absent
immediately before publishing the receipt completion marker. Progress v5 also
rejects unknown fields and impossible segment, row, transition-density, and
spool-byte counts before proof-frame decoding.

## Current validation evidence

The source contains generic unit and mutation coverage for CPU families,
devices, block routing, memory, continuity, lookup/log ordering, padding,
wire encoding, and recovery invariants. The compact CPU relation includes a
sentinel showing that a post-state mutation accepted by the preceding memory
layer is rejected once lane CPU semantics are added.

During the current no-long-run development phase, only formatting, diff
sanity, strict Clippy, and bounded all-target compilation are permitted. The
proof-free profiler has been migrated to schema v4, binds the backend digest
and proof-composition revision, and now targets
`BlockCpuWitness`/`BlockCpuRelation`; it has not been executed. No current
packed relation test, PCS proof, ignored test, release proof, profiler run, or
cartridge-scale proof is claimed here.

## Remaining gates

The next gates, in order, are:

1. preserve the completed static protocol/document/repository audit and keep
   all source gates green;
2. when short test execution is authorized, run focused packed CPU, receipt
   wire, and recovery tests before the workspace suite;
3. when PCS execution is separately authorized, run one deliberately bounded
   packed component proof and independent verification;
4. only after those pass, collect generic proof-free and proof performance
   measurements; and
5. design and review a witness-hiding layer before using the term zero
   knowledge.

Completion still requires one independently verified v2 receipt binding every
admitted transition, lookup, memory event, device transition, ordered log, and
segment boundary for a declared execution. Static compilation and component
source coverage do not substitute for that result.
