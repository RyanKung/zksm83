# Native SM83 Jolt/Akita plan

This is the implementation contract for the proof path that executes SM83
semantics directly. It never compiles the machine into, or replays it through,
an RV64 guest. The existing `zksm83_core::StepRelation` remains the only native
execution semantics used to construct witness rows.

## Status and non-claims

| Milestone | Status | Exit condition |
| --- | --- | --- |
| M0 supply-chain baseline | complete | pinned toolchain, sources, schedule, and real Akita opening |
| M1 public proposition | complete | exact statement, segment, and verification predicates |
| M2 protocol skeleton | complete | native claims, commitments, prover, and verifier compile end to end |
| M3a shared witness commitments | complete | uniform claims reuse one fixed-width Akita commitment plane and reject substitution/reordering |
| M3 CPU and ISA | complete | every SM83 opcode and current machine-step CPU family is constrained |
| M4 ROM, RAM, and MBC3 | complete | ordered memory and mapper relations share the segment proof |
| M5 DMG devices | complete | timer, interrupt, serial, APU, PPU, DMA, joypad, and save state are constrained |
| M6 receipt protocol | complete | bounded canonical stream, independent verifier, resumable prover, and exact segment chain pass |
| M7 Pokémon Blue and cutover | in progress | native-only dependency cutover is complete; the full declared path and reproducible final measurements must pass |

The M0 opening proves only that the pinned Akita PCS can be consumed and
verified by this workspace. It is not an SM83 execution proof. The target is a
transparent proof: the implementation makes no witness-hiding or zero-knowledge
claim. “ZKSM83” is the project name, not evidence that the current Akita mode is
ZK. The proof may only be called witness-hiding after a separate hiding layer,
negative leakage tests, and review exist.

## Frozen M0 backend

| Component | Identity |
| --- | --- |
| Rust | `1.95.0`, minimal profile |
| Jolt protocol reference | `95c898d3d2bbcc178fd8b18603662fce69cfa37d` |
| Akita | `69438de6cd8ce8ed7c9ebb21bdf60b813e8fcabc` |
| Akita transitive `jolt-field` | `72dc6451628d8b1dd794147a1f1cc40be0d77963` |
| Field/config | `fp128::DenseBounded` |
| Fiat-Shamir transcript | Blake2b |
| M0 single-column schedule SHA-256 | `c2098502e4c976a6a6cf687e4f70acfcb818372e2fbd589bff7b18e8decfa9cf` |
| Native relation schedule SHA-256 | `e601bc0bd9d4501220c367b3012901aac09467f145899c8e907b282d30e96646` |
| Fixed ISA table schedule SHA-256 | `3a8bbab5196d9233434abf33552cd7fc5637c74f0f76cea66cf247eddb8e7287` |
| One-MiB ROM schedule SHA-256 | `141f4ffaf9b1546351a35582352a6337b2855aab3d77cd456bfe30241d4c40af` |
| 128-KiB memory schedule SHA-256 | `8292b771966f1e30f7919796f5ebad3b6327686b7be61a4c778cd4972719ef15` |
| Protocol-log schedule SHA-256 | `2dba5b6d53ca57eaee58c872ceba3cdf6c7dbfe522162144577e71cadf543a80` |
| Fixed ISA table commitment SHA-256 | `fc4afaeb9c3d6a7dc063e2927caee773ae4a29f3c16e7d3f1aa5f266ea3f9c9a` |
| Protocol ID | `zksm83-native-jolt-akita-v1` |
| Privacy | transparent, not witness-hiding |

The current Jolt Git workspace cannot be used as a normal downstream
`jolt-akita` dependency: its root-level Cargo patches do not propagate, which
selects incompatible `jolt-field` and Arkworks sources. M0 therefore consumes
the exact Akita PCS revision directly. Jolt relation, claim, and verifier code
is introduced only at explicit crate boundaries in later milestones; the SDK
and RV64 tracer remain out of the dependency graph.

The six checked-in schedules are verifier-relevant protocol parameters, not
generated proof fixtures. The upstream one-column catalog remains the M0
supply-chain baseline. Native relations use a project-generated catalog that
admits exactly one `14 variables x 128 polynomials` layout. Logical columns are
split into ordered 128-column commitments and the last group is constrained to
canonical zero padding. The fixed ISA table uses a separate generated catalog
admitting only `9 variables x 128 polynomials`. Dynamic cartridge ROM uses a
fourth final-only catalog admitting exactly `20 variables x 1 polynomial`. A
fifth final-only catalog admits `17 variables x 1 polynomial` for each
128-KiB mutable-memory value, timestamp, or inverse-limb column. The sixth
catalog admits exactly `17 variables x 128 polynomials` for the four
fixed-capacity protocol logs and their inverse witnesses. All other `.aks`
files remain ignored.

The fixed SM83 ISA table is now materialized independently of the legacy audit
crate. It contains all 512 primary/CB addresses, marks exactly 501 as defined,
splits the 106-bit collision-free descriptor into two field-safe limbs, and has
protocol digest
`95e3e3c83028bc695b115f5f341e589621241bae76a4b0faaef55514a2f3218f`.
The fixed table is consumed by a committed Shout-style lookup. Its nine query
bits and 49 result columns share the exact Akita commitment plane used by the
CPU relation. The CPU relation also binds primary and CB fetch bytes and
addresses to that lookup key, so changing a fetched opcode without changing
the shared lookup claim is rejected.

Native witness columns are committed once through the public
`CommittedWitness` boundary. Uniform CPU relations return a
`UniformRelationProof` against its verifier-visible `WitnessCommitments` rather
than creating private duplicate commitments. The commitment encoding binds the
14-variable layout, logical column count, ordered 128-column groups, canonical
zero padding, and compressed Akita commitments. Release tests reject a valid
relation proof when supplied with commitments for another satisfying witness,
as well as group reordering. The ISA lookup consumes this same commitment
identity; M3a by itself still does not imply CPU, memory, or device soundness.

The current M5j row schema has 3,292 committed logical columns in twenty-six ordered
Akita groups. A 6,144-slot uniform relation of declared maximum degree 18
constrains CPU ranges and frames, fetch/immediate alignment, conditional and
absolute control flow, all ALU8 and CB families, DAA, byte and word loads,
signed-SP arithmetic, stack operations, interrupt dispatch, HALT-bug repeated
fetch/reset behavior, and canonical padding. Blue sound-wait rows bind their
three authenticated RAM reads, bytewise OR, zero/nonzero branch, and 19-cycle
quotient; delay rows bind DE iterations, both IME paths, flags, PC, and timing;
DMA-wait rows bind the three exact HRAM instruction bytes and CPU result. The
same columns now decompose every bus address, value, and 20-bit
physical address; constrain MBC3 ROM-bank, RAM-enable, and RAM/RTC-select
updates; derive every immutable-ROM physical address from the CPU address and
before-state bank; and bind mutable-memory before/after bytes, 17-bit physical
addresses, fixed row/slot clocks, predecessor timestamps, strict positive
deltas, and four-bank SRAM mapping. A statement-scoped Akita commitment binds the exact
one-MiB ROM, while one batched Shout claim authenticates all five bus slots
without giving the verifier ROM bytes or queries. The isolated ROM gate took
3.14 seconds; the earlier 742-column combined CPU, ISA, ROM, and
ROM-substitution release gate took 43.87 seconds on the local Apple Silicon
host. First release compilation is excluded from both numbers.

Mutable memory now uses separate statement commitments for the exact initial
and final 128-KiB images. A two-phase Fiat-Shamir transcript derives tuple and
log-derivative challenges only after the trace, image, and final-timestamp
commitments exist. Full fp128 inverses are committed as two bounded 64-bit limbs
and reconstructed in the relation. Pointwise inverse identities plus one
multiset-sum opening prove that initial tokens and event outputs equal event
inputs and final tokens. Strictly increasing, globally unique row/slot
timestamps rule out cycles and branches, so each address has one latest-value
chain. The verifier receives no memory image or event vector and does not replay
the emulator. The isolated release gate passed in 17.33 seconds and rejected a
substituted final-memory commitment. The preceding M4 CPU/ISA/ROM/RAM composite
gate passed in 68.30 seconds against one shared 987-column trace commitment;
the process reported 5,017,305,088 bytes maximum resident set size. Its 2m26s
release compilation is excluded. The preceding 1,072-column M5a composite gate
passed in 83.09 seconds with 5,033,656,320 bytes maximum resident set size; its
1m37s release compilation is excluded. Akita proof calls use an explicit 512-MiB
worker stack because its dense multi-group opening exceeds the platform-default
stack; a local Rayon pool applies the same bound to Akita's internal parallel
kernels. This is a virtual stack bound, while peak RSS is measured separately.
The preceding 1,152-column, degree-16 M5b composite gate passed in 90.81 seconds
with 5,170,118,656 bytes maximum resident set size; its 1m32s release compilation
is excluded. The historical 1,331-column, degree-16 M5c composite gate passed in
106.11 seconds with 2,622,210,048 bytes maximum resident set size; its separate
1m32s release compilation is excluded. The preceding 3,181-column, degree-16 M5g
composite gate passed in 226.62 seconds with 4,870,389,760 bytes maximum resident
set size; its separate 1m32s release compilation is excluded.

M3's row-local CPU/ISA exit has passed. M5a additionally binds ordered bus, ISA,
input, and output cursors; IF/IE ranges and pending-interrupt priority; HALT-bug
entry and wake selection; DMA debt serialization and exact source/destination
copy events; fail-closed MMIO address classes; canonical MMIO tuples; and exact
IF/IE visible values and IE writes. M5b binds each ordered P1 sample and FF00
write, including same-row read-modify-write ordering, active-low values, button
and selection state, falling-line IF updates, FF0F interactions, and joypad
interrupt acknowledgement. M5c additionally binds the before-state low/high
device packs, DIV/TIMA/timer phase, LY/dot ranges, derived PPU mode/coincidence,
and exact non-APU MMIO read and write-before values for FF01-FF07, FF0F,
FF40-FF4B, and FFFF. These are not the complete device relation: timer, serial,
and PPU transitions and MMIO write-after state remain open. M5d closes the
remaining APU visibility gap by decomposing all five APU packs and binding stored
read masks, FF10-FF26 control/status values, FF27-FF2F unused values, and
FF30-FF3F wave RAM. M5e binds static non-APU write-after registers and the full
modeled APU write transition, including power-off clearing, off-state length
writes, NR52 power and channel status, DAC disable, trigger activation, and wave
RAM preservation. M5f binds serial post-write state, the exact `4 * m_cycles`
countdown, completion writeback, SC bit-seven clearing, and IF bit three. M5g binds ordinary
timer writes and up to 24 exact T-cycles per row, including divider wrap,
frequency-selected falling edges, TIMA overflow/reload phases, TMA writeback,
and IF bit two. Long Blue rows use a bounded divider quotient and require the
timer-disabled quiet state. M5h binds the post-row LCD line/dot state, LCD-disable
reset, exact frame quotient and wrap, the next VBlank crossing, and IF bit zero
without adding per-T-cycle PPU columns. Its composite gate passed in 279.48 seconds
with 5,051,596,800 bytes maximum resident set size; its separate 2m33s release
compilation is excluded. M5i binds the composite STAT line before MMIO writes,
after FF40/FF41/FF45 writes, and after clock advancement; proves mode-zero,
mode-one, mode-two, and LYC-coincidence rising edges at the next bounded PPU
boundary; prevents repeat requests while the composite line remains high; and
binds IF bit one. STAT-enabled long steps are rejected unless the LCD is off.
Log commitments and canonical Blue ROM admission remain open. The current M5i composite gate passed
in 246.58 seconds with 5,117,280,256 bytes maximum resident set size and zero
swap; its separate 1m53s release compilation is excluded. M5j binds FF46 DMA
startup, exact ordinary-step copy debt, before/after `index + owed + remaining =
160` capacity, and inactive/active cursor invariants. It also enforces the CPU's
HRAM-only bus window while DMA is active and the mode-dependent CPU VRAM/OAM
access gates without blocking DMA's own OAM writes. M5j also closes early
serial-completion claims with a bounded completion gap, rejects serial-active
long steps, and binds the LCD/interrupt guard and exact next-VBlank target of
long HALT. The current M5j composite gate passed in 245.21 seconds with
5,057,085,440 bytes maximum resident set size and zero swap; its separate 1m45s
release compilation is excluded.
M6 adds a row-tagged log-derivative argument over every complete 38-limb state.
It binds the public first pre-state, each active post-state to the next active
pre-state, the public final post-state, and an exact active-row prefix. Four
deterministic fixed-capacity tables commit bus, raw input, output, and fixed-ISA
events and prove ordered multiset equality plus exact cursor-derived counts.
The first complete receipt gate composed these claims with CPU/ISA/ROM/RAM and
passed without verifier replay. A current degree-18 two-segment streamed gate
proved exact semantic, raw memory-commitment, and cumulative-log boundary
chaining and rejected a broken middle boundary and segment reordering. The current canonical
version-1 encoding is a length-delimited bounded stream: the independent
verifier decodes and verifies one proof frame at a time, while the prover
persists each complete frame before atomically replacing its exact SM83
state-and-memory progress checkpoint. Resume cryptographically rechecks every
persisted frame and refuses a shorter, substituted, or noncanonical spool. The
whole per-segment proof-and-encode operation runs in a named 512-MiB-stack Rayon
pool, so dependency parallel iterators cannot escape to the process-global
default-stack pool.

## Native state boundary

The native proof separates semantic state from backend authentication data.
The semantic portion is 38 canonical `u64` limbs, in this exact order:

```text
cpu_a cpu_b cpu_c cpu_d cpu_e cpu_h cpu_l cpu_flags
cpu_pc cpu_sp cpu_ime cpu_run_state cpu_m_cycles
mbc3_ram_enabled mbc3_rom_bank mbc3_ram_rtc_select
input_next_index output_next_index bus_event_next_index isa_row_next_index
machine_profile dmg_interrupt_request dmg_interrupt_enable
dmg_low_register_pack dmg_high_register_pack dmg_ppu_line dmg_ppu_dot
dmg_timer_div dmg_timer_counter dmg_timer_reload_phase dmg_timer_edge_latch
dmg_apu_control_low_pack dmg_apu_control_high_pack dmg_apu_mixer_pack
dmg_apu_wave_low_pack dmg_apu_wave_high_pack dmg_joypad_pack dmg_dma_pack
```

Byte, word, Boolean, enum, and packed-register range constraints are part of
the relation; injection into the Akita field is canonical. The packs are the
ones exposed by `DmgDeviceState`, `DmgTimerState`, and `DmgApuState`, so no
device byte is omitted.

Each boundary additionally carries five typed commitment identities:

```text
mutable_memory input_log output_log bus_transcript isa_transcript
```

A direct ROM or memory commitment identity is SHA-256 over a domain tag,
commitment kind, column-layout digest, logical byte length, and the canonical
serialized Akita commitment. Ordered-log boundaries instead carry cumulative
chain identities: every nonempty append binds the preceding identity, log kind,
segment index, start/end cursors, and a typed digest of the verifier-checked
segment table commitment. Empty appends preserve the unique prior identity.
The corresponding Akita commitments live in the receipt and are consumed by
the verifier; these SHA-256 identities never substitute for checking openings.
Immutable ROM is statement-scoped and does not vary between segments.

Witness-side `VmState` roots now use the versioned
`zksm83/witness-auth-sha256/v1` domain-separated SHA-256 construction. They
authenticate trace construction but are not native proof identities: the
verifier establishes ROM, RAM, and ordered-log consistency from its own Akita
commitments and openings. Halo2/Pasta and the reference/audit crates have been
removed, and the remaining native dependency graph contains no RV64/RISC-V
guest, Jolt SDK, Dory, or BN254 route. Legacy Blue endpoint files remain
readable, but their old Poseidon root fields are ignored in favor of exact ROM,
memory, input-prefix, and typed endpoint checks.

## Canonical public statement

The outer receipt starts with fixed magic and version 1. Its statement contains
exactly:

```text
backend_digest
machine_profile
rom_byte_length
rom_commitment_id
initial_state_boundary
final_state_boundary
segment_count
relation_step_count
m_cycle_count
bus_event_count
input_event_count
output_event_count
isa_row_count
statement_id
```

`backend_digest` is recomputed from the verifier's compiled protocol identifier,
revisions, field/config, transcript, all schedule digests, privacy mode, and
`uses_rv64_guest = false`. A receipt cannot select another backend by changing
JSON. Counts are exact, checked `u64` values. `statement_id` is SHA-256 over a
domain tag and the canonical little-endian encoding of every preceding field;
it identifies the claim but proves none of it by itself.

The initial and final profiles and immutable ROM identities must equal the
top-level fields. The first boundary is either the canonical DMG post-boot
state or an explicitly versioned continuation accepted by policy. A full Blue
claim always starts from the canonical post-boot state; a checkpoint alone is
not a full-path claim.

## Segment receipt

One segment contains:

```text
segment_index
active_row_count
padded_row_count
initial_state_boundary
final_state_boundary
initial_memory_commitment
final_memory_commitment
ordered_protocol_log_commitment
m_cycle_count
bus_input_output_isa_counts
composed_akita_proof
```

`active_row_count + padded_row_count` equals the frozen 16,384-row capacity.
Padding rows are constrained inactive identities and cannot consume cycles, bus
events, ISA rows, input, output, or memory operations. There is no IVC or
recursive segment folding in version 1. A receipt is accepted only after the
independent verifier checks every segment proof and exact equality of all
adjacent boundaries.

## Complete verification predicate

`verify(receipt, expected_statement)` returns success only if all of the
following hold without executing `StepRelation` or another emulator:

1. The encoding is canonical and all version/backend constants match the
   verifier binary.
2. The supplied statement equals `expected_statement`, and its identifier and
   exact aggregate counts recompute.
3. Every segment proof verifies against the bundled canonical commitments and
   the compiled Akita schedule.
4. The first and last segment boundaries equal the public statement, every
   adjacent pair is identical, indices are contiguous, and aggregate counts do
   not overflow.
5. Each active row selects exactly one admitted `StepKind`; its before/after
   semantic limbs satisfy the corresponding pure SM83 transition relation and
   all untouched fields satisfy frame conditions.
6. Opcode fetches select exactly one row from the fixed 256 primary plus 256 CB
   ISA tables. Undefined primary opcodes have no accepting transition.
7. Ordered bus slots match the selected instruction or machine transition,
   including address, physical address, prior value, auxiliary value, result,
   and event index.
8. ROM reads match the immutable committed ROM table. RAM reads see the latest
   admitted value, RAM writes change exactly one mapped byte, and MBC3 control,
   bank selection, disabled-RAM behavior, and no-RTC policy are constrained.
9. Input/output commitments and cursors match exactly the ordered events used
   by the execution; no byte may be skipped, duplicated, or appended off-row.
10. Interrupt priority/acknowledgement, EI delay, HALT bug/wake behavior, timer,
    serial, APU registers, PPU/STAT timing, OAM DMA, joypad, and battery SRAM
    satisfy the typed DMG relation for every relevant row.
11. Specialized long-step modes (`HaltUntilVBlank`, `BlueSoundWait`,
    `BlueDelayLoop`, and `BlueDmaWait`) prove the same state delta as their
    declared batched base transitions under their explicit guards. A ROM/PC
    heuristic alone is insufficient.

Any missing item is a proof gap, even when native trace validation or an
emulator replay succeeds.

## Validation gates

- Default: format, workspace Clippy with warnings denied, and all self-contained
  tests.
- Cryptographic: release Akita opening, canonical serialization round trip,
  wrong statement/commitment/proof/schedule rejection, and dependency-tree
  checks excluding Dory, BN254, Jolt SDK, and RV64.
- Semantic: exhaustive primary/CB classification, per-operation positive and
  negative transitions, all machine-step modes, memory/mapper/device mutation,
  padding, segment reordering/omission/duplication, and count overflow.
- Cartridge: user-supplied ROM and inputs only; ROM, saves, checkpoints,
  traces, receipts, proofs, and benchmark output stay outside Git.
- Performance: commands, source revision, machine/toolchain, dimensions, proof
  size, prove/verify time, and peak RSS are recorded separately. First-build
  compiler time or RSS is never reported as proof performance.

M0 local evidence on Apple Silicon: the 14-variable/16,384-value gate produced
a 61,841-byte proof and passed compressed serialization, deserialization, and
verification. The warm release test body reported 0.12 seconds; this is a
supply-chain smoke measurement, not an SM83 benchmark or a general Akita/Jolt
performance claim.

M6 single-segment local evidence on the same class of host: under the corrected
degree-18 protocol, a complete four-row DMG receipt constructed its proof in
319.26 seconds and encoded to 19,018,996 bytes. Parsed verification completed
at 321.94 seconds, both byte-slice and incremental-reader verification by
327.37 seconds, and the full tamper matrix at 330.11 seconds. Peak RSS was
7,684,227,072 bytes with zero swap; a separate 1m34s release compilation is
excluded. This does not establish multi-segment or Pokémon Blue performance,
and it remains transparent rather than witness-hiding.

The current degree-18 two-segment stream completed its first proof frame in
312.88 seconds and both proofs in 624.06 seconds. Incremental and parsed
positive verification plus broken-link/reordering rejection completed in
636.47 seconds. Peak RSS was 8,154,365,952 bytes with zero swap; its separate
1m34s release compilation is excluded. Before installing the complete segment
operation into the named large-stack Rayon pool, this gate failed closed when
an Akita dependency iterator escaped to an unnamed process-global worker and
overflowed its default stack; the refreshed gate exercises the repaired
production stream boundary.

The current Blue preflight fixes a 9,994,417-row endpoint, split into 611
segments of 16,384 rows. The first real segment exposed the understated APU
selector degree and failed closed; after correcting the declared bound to 18,
the segment proved in 316.263 seconds and produced a 19,016,810-byte frame.
Cross-process append then exposed that Akita's derived Rust equality can differ
for canonically identical commitments. Chaining now compares canonical
commitment identities and checks the full persisted state before continuing.
The adjacent second segment proved in 325.733 seconds, bringing the spool to
37,864,191 bytes and 32,768 rows; a fresh process cryptographically reverified
both frames and the exact checkpoint in 17.74 seconds. A serial extrapolation
from both real segments is about 54.5 hours and 10.77 GiB, not a completed
Blue-path measurement. Those two frames predate the witness-auth cutover and
are not resumed into the final artifact. M7 remains open until a fresh
native-only run proves all 611 frames and the exact endpoint verifies.
