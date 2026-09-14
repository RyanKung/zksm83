# Native relation audit

This is the proof-free producer/consumer inventory for the generic packed v2
SM83 relation. It records source facts and protocol-visible optimization
constraints. It does not claim that the current packed proof has been run.

## Deepest relation

`BlockCpuRelation` is the v2 receipt relation:

| Property | Value |
| --- | ---: |
| Logical columns | 4,505 |
| Constraint slots | 13,004 |
| Maximum declared degree | 41 |
| Fixed rows | 16,384 |
| Commitment groups | 36 |
| Pair openings | 18 |
| Canonical padding columns | 103 |

The first 3,647 columns are the shared packed memory/device prefix. The final
858 columns contain five 106-column CPU/mapper boundary bit ranges and four
82-column lane-local semantic ranges. This is a deliberate hard v2 identity
change from the legacy 3,292-column one-transition-per-row relation.

## Composition lineage

Each row-local layer appends columns to, or adds constraints over, the same
ordered prefix:

| Layer | Columns | Constraints | Max degree | Purpose |
| --- | ---: | ---: | ---: | --- |
| Routing | 50 | 129 | 7 | block/lane activity and bounded cycle/bus ownership |
| Boundary | 145 | 297 | 3 | five non-device boundaries and shared device endpoints |
| Control composition | 195 | 432 | 7 | selector equality across routing and boundaries |
| ISA control | 437 | 729 | 7 | four lane ISA descriptors and branch values |
| Front end | 773 | 1,140 | 7 | shared five-slot bus and per-lane ISA event counts |
| Flow | 773 | 1,168 | 7 | timing, cursor flow, and profile preservation |
| Machine | 840 | 1,397 | 7 | HALT/wake/interrupt/DMA machine rows |
| Device envelope | 841 | 1,406 | 7 | unique device I/O and quiet-state preservation |
| Shared PPU | 1,038 | 1,868 | 7 | bounded PPU position and frame behavior |
| Shared serial | 1,206 | 2,343 | 7 | countdown and completion behavior |
| Shared DIV | 1,243 | 2,420 | 7 | divider advancement |
| Timer core | 2,282 | 4,812 | 7 | bounded T-cycle timer stages |
| PPU/interrupt | 2,362 | 5,066 | 7 | VBlank, STAT, and IF ordering |
| DMA | 2,474 | 5,352 | 7 | debt, addresses, copies, and completion |
| Typed MMIO | 2,565 | 5,600 | 7 | implemented DMG register classification |
| Joypad | 2,610 | 5,717 | 7 | P1 samples, select state, and interrupt edge |
| APU | 3,269 | 7,395 | 7 | modeled APU visibility and writes |
| Serial MMIO | 3,319 | 7,552 | 7 | write-before-clock serial ordering |
| Timer MMIO | 3,368 | 7,963 | 7 | write-before-clock timer ordering over shared timer stages |
| PPU MMIO | 3,443 | 8,177 | 7 | LCD/STAT/LYC write ordering |
| Mutable memory | 3,647 | 8,431 | 7 | event selection and 17-bit chronology |
| Compact CPU | 4,505 | 13,004 | 41 | shared boundary ranges plus four lane-local instruction semantics |

The compact CPU degree bound is higher because lane-local bus selection is a
polynomial projection over shared routing and kind selectors, then feeds the
existing MBC3 predicates. It is a conservative declared bound, not a measured
sumcheck cost.

## Producer/consumer matrix

| Family | Producer | Required consumers |
| --- | --- | --- |
| Active block/lane and ownership selectors | block planner and routing encoder | routing, boundaries, ISA, bus, CPU projection, padding |
| Five non-device boundaries | block boundary encoder | flow, machine, compact CPU, packed continuity |
| Shared device before/after state | block boundary/device encoders | device relations, machine relation, compact CPU projection, continuity |
| Four ISA addresses/outputs/branches | ISA encoder | front end, flow, compact CPU, four fixed-table lookups, packed ISA log |
| Five ordered bus tuples and decompositions | shared bus encoder | device/MMIO, compact CPU, ROM lookup, mutable memory, packed bus/input/output logs |
| Shared timer stage bits | quiet timer core or typed timer-MMIO encoder, under disjoint owners | timer-core Boolean/ownership checks and path-specific timer semantics |
| Other device auxiliaries | typed device encoders | deepest row-local relation only |
| Row tags and memory chronology | packed memory encoder | deepest relation, memory event inverse relation, clock/boundary/multiset proofs |
| Five 106-column CPU/mapper boundary bit ranges | compact CPU encoder | both lanes adjacent to each boundary and their scalar reconstruction identities |
| Four 82-column CPU semantic ranges | compact CPU encoder | lane-local arithmetic, control, stack, bit, and DAA identities |
| Final timestamp table | packed memory encoder | mutable-memory proof boundary and multiset claims |
| Bus/input/output/ISA table entries | packed log extractor | table commitments and trace/table inverse-sum arguments |

No family in the current receipt main plane is intentionally unconsumed.
Canonical inactive lanes, empty bus slots, inactive rows, unused helper values,
and final PCS padding are constrained to zero or a protocol-defined inactive
value.

## Compact CPU projection

The four CPU lanes do not copy four complete legacy rows. `RowView` can read a
native or packed projection. In packed mode it derives:

- lane before/after state from adjacent shared block boundaries;
- ISA address, output, and branch values from the chosen lane;
- bus tuple fields and decomposed bits from the shared slot selected by routing;
- ROM selector/value from the same shared bus plane; and
- CPU and mapper bit decompositions from one of five shared boundary ranges;
  and
- only instruction-local arithmetic and control helpers from the appended
  82-column lane auxiliary range.

Operand, result, both immediate bytes, sequential PC, and the discarded
`POP AF` nibble are not separately committed in packed mode. Each is a linear
projection of its already constrained bit columns, cached once per lane view.

The retained 82 columns per lane have an exact semantic partition:

| Lane-local family | Columns | Why retained |
| --- | ---: | --- |
| Arithmetic bits, carries, zero tree | 25 | low-degree byte arithmetic and zero predicate |
| Immediate/sequential bits and control wraps | 38 | fetch/control range and modular target checks |
| Word/stack wraps and POP nibble bits | 12 | 16-bit, signed-SP, stack, and address wrap checks |
| DAA predicates and wrap | 7 | decimal-adjust comparison and correction witnesses |

No further retained scalar is a linear duplicate of another committed range.
Projecting immediate or operand/result bits would require ISA- and routing-
dependent polynomial selectors, while removing the result-zero tree would
increase degree. Those changes are a separate algebraic redesign, not a
witness-layout cleanup.

CPU constraints are gated by the instruction-block selector. Inactive lanes
repeat the final boundary with canonical inactive helpers. Machine rows and
fixed padding have zero CPU auxiliaries.

The reused semantic families cover range and flag invariants, state write
masks, MBC3 mapping and updates, byte arithmetic, PC/fetch/control flow, data
movement, word operations, stack operations, CB bit/rotate operations, and
DAA. Device semantics are owned once by the shared prefix.

## Cross-component bindings

`PackedBlockProof` consumes the same main commitments in seven places:

1. deepest uniform relation;
2. four fixed-ISA lookups;
3. immutable ROM lookup;
4. mutable-memory proof;
5. packed state continuity; and
6. packed protocol logs.

The auxiliary memory, continuity, and log inverse relations include the
4,505-column base width and explicit revision values in their statements. The
packed continuity auxiliary plane has four inverse limbs plus one constrained
per-row source-transition count; its opened sum binds the receipt's raw
transition count. The main CPU relation statement binds its prefix dimensions,
shared-boundary and lane-local auxiliary widths, lane count, constraint
allocation, final dimensions, degree, and revision. This cut advances the CPU
relation statement to revision 5, packed continuity to revision 6, packed
memory-event inverses to revision 6, and packed log inverses to revision 5.
The backend identity binds a named proof-composition revision. Any such change
alters the proof transcript and compiled backend digest.

The v2 PCS dispatcher treats both the packed 4,505-column main plane and the
retained legacy 3,292-column low-level relation as paired layouts, but the
receipt backend identity names only the packed plane. Other column counts use
the explicit auxiliary layout. The receipt wire and high-level validation are
v2-only.

## Public identity and recovery closure

The progress checkpoint and inspection evidence use schema v5. Both carry the
proof-composition revision explicitly in addition to the compiled backend
digest and the main and auxiliary schedule digests. Progress decoding rejects
unknown fields, older schemas, and counters outside the 4,096-segment,
16,384-row-per-segment, four-transition-per-row, and 2-TiB spool bounds before
proof-frame decoding.

The statement authenticates segment, source-transition, packed-row,
machine-cycle, and ordered-log counts. Segment verification recomputes each
delta, checks `active + padded == 16,384`, and aggregates with checked
arithmetic before comparing the final statement. A checkpoint is accepted only
when verified spool counts, final state, and final mutable-memory commitment
match it exactly.

Crash publication order is frame write, spool synchronization, atomic progress
replacement plus parent-directory synchronization, statement publication or
byte equality, then final receipt publication. Resume may discard only bytes
beyond the checkpointed spool length and durably synchronizes that truncation
before verifying and replaying the retained prefix. Finalization rechecks that
the receipt path remains absent immediately before publishing it.

## Mutation coverage in source

Checked-in fixtures now carry a rejection sentinel for every layer in the
packed composition lineage: routing, boundaries, control, ISA, shared bus,
flow, machine events, every shared-device and typed-MMIO relation, mutable
memory, and compact CPU semantics. Device sentinels mutate only columns owned
by the relation under test. The shared-timer sentinel is stronger: the
serial-MMIO prefix accepts a Boolean mutation in the device-I/O-owned shared
stage, while timer-MMIO must reject it. The compact CPU sentinel mutates an
`INC B` post-state: the preceding memory layer accepts the mutation, while
`BlockCpuRelation` must reject it. Separate shared-boundary-bit and
lane-local-helper mutations must also reject; the memory prefix still accepts
the former.

These fixtures have not been executed during the current no-long-run phase.
Only formatting, strict lint, and bounded compilation are current evidence.

## Protocol-visible candidates

Future width or degree reductions require a new backend identity when they
change a committed layout or relation statement. The leading candidates are:

1. share repeated lane equality/zero products;
2. project more helper bits from already range-checked shared values;
3. remove fixed unused constraint slots only after per-family mutation proof;
4. evaluate sparse device commitments against their total transcript/opening
   overhead; and
5. lower the actual MBC3 projection degree before reducing the declared bound.

Every candidate must be promoted across several structurally distinct generic
workloads. A ROM-specific observation cannot become a production selector.
