# Generic optimization plan

This plan optimizes the native SM83 proof pipeline without recognizing any
particular cartridge. Selection predicates must derive from authenticated
machine state and apply unchanged to every supported ROM.

## Non-negotiable boundary

Production code must not branch on a ROM digest, title, cartridge identity,
fixed program counter, fixed bank, or expected instruction/data bytes. A ROM
may be a workload, but observations from it may not become semantic cases.
Every optimization must preserve the exact public boundaries, ordered logs,
device behavior, memory ordering, and fail-closed transition relation.

The current backend is transparent. Throughput work cannot be described as a
zero-knowledge improvement until a separate hiding layer exists.

## Current baseline

The v2 main plane is `BlockCpuWitness`/`BlockCpuRelation`:

| Quantity | Current value |
| --- | ---: |
| Rows per segment | 16,384 |
| Instructions per ordinary block | 1 to 4 |
| Logical columns | 4,505 |
| Constraint slots | 13,004 |
| Maximum declared degree | 41 |
| Commitment groups | 36 |
| Paired openings | 18 |
| Canonical padding columns | 103 |

One row carries either up to four ordinary instructions or one generic
machine event. The shared prefix contains device, mapper, bus, memory,
boundary, and lookup data once per block. Five shared CPU/mapper boundary bit
ranges add 106 columns each, while four compact lane-local semantic ranges add
82 columns each. Six scalar helpers per lane are linear projections of retained
bit columns rather than separate commitments.

The proof-free profiler schema is `zksm83-proof-free-profile/v4`. It binds the
backend digest and named proof-composition revision. Its optional
`--packed-trace-steps` path builds and evaluates this deepest relation. The
profiler has been migrated but not run under the current no-long-run policy, so
the dimensions above are source facts, not performance measurements.

## Completed engineering phases

### P0: allocation and copy reduction

- removed full-memory cloning from ordinary witness construction;
- made binary multilinear folding allocation-free;
- retained one committed field-column owner and one mutable sumcheck plane;
- reused row and constraint scratch buffers;
- reused one fixed 300-value CPU projection buffer and streamed block rows
  without per-block or per-lane temporary vectors;
- moved the 128-KiB final memory-timestamp table into the deepest witness
  instead of cloning its one-MiB `u64` representation;
- let the PCS commit path borrow a single timestamp column directly, removing
  the second one-MiB temporary copy from mutable-memory proving;
- made the legacy-shaped CPU semantic scratch allocate storage only for helper
  columns that are actually populated;
- replaced per-block timer-MMIO row and shared-stage heap vectors with fixed
  buffers, removing two allocations for every active packed row;
- replaced repeated selector allocation with stack arrays, borrowed slices,
  and per-row caches; and
- skipped the canonical all-zero constraint suffix during mixing.

Runtime and transcript-equivalence measurements remain deferred.

### P1: relation inventory

Every legacy native column received a producer/consumer classification before
the packed cutover. The current packed relation now publishes explicit column,
constraint, degree, group, opening, and padding constants. Statement revisions
change when a downstream relation changes its base witness or formula.

### P2: event-driven devices

Generic guarded events cover long HALT to VBlank, serial completion, and timer
interrupt, plus bounded ordinary HALT, interrupts, and DMA. Guards prove from
hardware state that no observable competing event is skipped. No event is
selected by code location or ROM identity.

### P3: bounded SM83 blocks

The block planner consumes accepted contiguous rows and applies universal
instruction, M-cycle, bus, control-flow, low-power, interrupt, DMA, MMIO,
mapper, mutable-code, and machine-event cuts. It moves rows into blocks without
cloning their state, bus effects, or authentication paths.

The packed relation then composes routing, intermediate state boundaries, four
ISA lanes, one shared bus, flow, machine events, shared devices, MMIO, MBC3,
mutable memory, and compact CPU semantics. Typed device-register and
PPU-mode-sensitive accesses are singleton cuts where moving an MMIO write
across another lane's cycles would change semantics.

### P4: shared proof and receipt

The receipt source path now commits the 4,505-column plane once and composes:

- `BlockCpuRelation`;
- four fixed-ISA lookups;
- immutable ROM lookup;
- packed mutable memory;
- packed state continuity; and
- packed bus/input/output/ISA logs.

`NativeSegmentReceipt` encodes `PackedBlockProof`. The backend identity and v2
PCS dispatcher select 36 groups and 18 adjacent-pair openings. Progress v5
separates raw completed transitions from authenticated packed relation rows and
binds the proof-composition revision as an explicit field. Receipt and
statement wire decoders reject v1.

The CLI fills a segment by executing chunks bounded by the number of remaining
packed rows. Each chunk can produce no more blocks than source transitions, so
capacity cannot be exceeded. If packing creates free rows, another bounded
chunk is admitted. This recovers most of the four-lane density for ordinary
instruction streams while retaining a one-row-per-transition worst case for
machine-event-heavy execution.

This phase is statically integrated, not dynamically proved.

### P4.5: shared timer stages

The quiet timer-core path and typed timer-MMIO path now reuse one 24-by-42
per-T-cycle stage range. Their owners are algebraically disjoint: the quiet
selector is `short_device_clocked * (1 - device_io)`, while the typed path is
owned by `device_io`. Timer-core enforces Booleanity and canonical zero under
`quiet + device_io`; timer-MMIO supplies the device-I/O witness values and
binds their write-before-clock semantics.

Timer-MMIO retains only 49 post-write/selector columns. The hard cut removes
1,008 committed columns and 2,016 duplicate Boolean/canonicality constraints,
moving the packed plane from 5,855 to 4,847 columns and from 15,743 to 13,727
constraint slots. Relation statements, commitment geometry, the backend
digest, and the named proof-composition revision all change. A source mutation
sentinel requires the serial-MMIO prefix to accept a changed shared stage while
the timer-MMIO relation rejects it. Dynamic execution remains deferred.

### P4.6: shared CPU boundary decompositions

Each instruction lane previously committed both its before and after CPU and
mapper bit decompositions. Adjacent lanes refer to the same authenticated
state boundary, so the three internal boundaries were committed twice. The
packed auxiliary layout now owns five 106-column boundary ranges—96 CPU-state
bits plus 10 mapper bits—and four 88-column lane-local semantic ranges.

All four lane views map their legacy before/after columns onto those shared
ranges. Witness construction rejects unequal encodings for an internal
boundary. The range, reconstruction, enum, and mapper identities are evaluated
once for each of the five boundaries instead of once for both sides of all
four lanes. This removes 318 logical columns, 318 padding identities, and 381
duplicate range-constraint slots: 4,847 becomes 4,529 columns and 13,727
becomes 13,028 constraint slots. The paired PCS geometry falls from 38
groups/19 openings to 36/18, with 4,608 physical columns and 79 canonical
padding columns. The CPU relation
keeps 635 shared-boundary slots and reduces each lane-local allocation from
1,024 to 770 slots. Its statement, backend digest, and proof-composition
revision change together. A source mutation sentinel changes a shared boundary
bit while the memory prefix still accepts it and requires the CPU relation to
reject it. Dynamic execution remains deferred.

### P4.7: derived CPU helper scalars

Packed mode no longer commits six scalar values per lane when an existing bit
range is already their canonical representation: operand, result, both
immediate bytes, sequential PC, and the discarded `POP AF` nibble. The packed
row view reconstructs and caches each scalar as the linear combination of its
retained bits. Native legacy rows and their relation ordering are unchanged.

This removes 24 logical columns and 24 canonical machine-row identities,
moving 4,529 to 4,505 columns and 13,028 to 13,004 constraint slots. The layout
remains within 36 commitment groups and 18 pair openings; physical width stays
4,608 and canonical padding grows to 103 columns. The CPU and dependent inverse
relation statements, backend digest, and proof-composition revision change.
The CPU helper mutation now targets a retained result bit, so the derived
scalar changes with it and arithmetic semantics must still reject the row.
Dynamic execution remains deferred.

## Active work

### P5: static protocol closure

Current allowed work:

1. keep formatting, strict lint, bounded all-target compilation, and diff
   sanity clean;
2. audit all public identities, statement revisions, wire bounds, and count
   propagation after the packed hard cut;
3. keep production files below the project size limits and production paths
   free of panics; and
4. maintain negative fixtures for each semantic family without executing
   proof or long-running tests.

Exit gate: no stale v1 receipt path, old 3,292-column backend identity, or
raw-step/packed-row alias remains in the production v2 flow.

### P6: bounded dynamic validation

This phase starts only after short tests are authorized:

1. run focused packed CPU representatives and mutation sentinels;
2. run block device, memory, continuity, and log tests;
3. run v2-only wire and progress-v5 recovery tests; and
4. run the default workspace suite under an explicit short timeout.

After proof work is separately authorized, run one small packed component
proof and independent verification. Do not begin a cartridge-scale proof.

Exit gate: deterministic fixtures satisfy the packed relation; mutations in
each CPU/device/memory/log family reject; the receipt round-trips; recovery
reconstructs identical boundaries; and one bounded proof verifies.

## Next optimization candidates

These candidates are generic and require measurements after P6:

### Reduce committed width

- identify packed auxiliary bits that can be projected from an already range-
  checked shared value;
- share repeated zero/equality products across CPU lanes;
- replace scalar-plus-bit duplication only when every consumer can use the
  canonical representation; and
- remove fixed unused constraint slots only with a new backend identity and
  family-specific mutation coverage.

Width reduction is the highest-leverage target because it reduces commitment,
opening, field-conversion, and sumcheck work together.

### Split independently sparse relations

Evaluate whether device or MMIO auxiliaries should use separate commitments
when their authenticated selector is sparse. Count all additional transcripts,
commitments, openings, inverse planes, and verifier work; a narrower main plane
is not automatically a smaller total proof.

### Stream the sumcheck working set

The committed plane must survive for openings, but the mutable sumcheck plane
may admit chunked or recomputable families. Promotion requires an explicit peak
RSS ceiling and a proof that recomputation costs less than retained memory on
the full workload matrix.

### Pipeline bounded segments

Overlap witness construction, commitment, sumcheck, opening, encoding, and
verification with bounded queues. Preserve deterministic receipt order and the
existing durable spool/checkpoint sequence. Parallelism must have a fixed
memory budget.

### Platform acceleration

Only after algorithms stabilize, compare target-CPU builds, LTO/PGO, Akita NTT
kernels, and optional accelerator backends. The scalar CPU path remains the
reference and must produce identically verified statements.

## Measurement and promotion rules

Use at least three structurally distinct synthetic or redistributable generic
workloads: CPU/control heavy, mutable-memory/stack heavy, and device/input
heavy. Add timer/serial/PPU/DMA stress when measuring affected code. No single
ROM is a promotion gate.

Every accepted result records:

- source revision and dirty-state description;
- Rust target, optimization profile, and machine;
- workload and input identities;
- raw transitions and packed rows;
- all relation dimensions and schedule digests;
- witness, commit, sumcheck, opening, encode, and verify times;
- proof/receipt bytes; and
- peak resident memory.

An optimization lands only when verifier results and transcript identities are
correct for its declared protocol revision, negative fixtures still reject,
wall time improves across the workload set, and peak memory stays within the
fixed ceiling.
