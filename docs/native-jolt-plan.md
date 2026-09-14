# Native SM83 Jolt/Akita plan

This is the implementation contract for the only proof path in the workspace.
It proves native SM83 semantics directly and never compiles or replays the
machine through an RV64 guest.

## Fixed decisions

- `zksm83_core::StepRelation` is the sole execution semantics.
- The proof route is the transparent Akita lattice PCS integrated by
  `zksm83-jolt`.
- Receipt and statement wire formats are v2-only; there is no legacy fallback
  or negotiation.
- Only packed-block receipt composition is callable. The one-transition trace
  and CPU relation are reference models with no receipt or wire entry point.
- The relation is cartridge-independent. ROM identity, PC ranges, bank values,
  and opcode byte patterns cannot select a different transition or compressed
  relation.
- The current backend is transparent, not witness-hiding. “ZKSM83” is the
  project name, not a zero-knowledge claim.
- Proof, ignored, release, profiler, and other long-running gates require
  separate authorization.

## Current status

| Phase | Status | Concrete exit |
| --- | --- | --- |
| P0 dependency and protocol baseline | complete | pinned Jolt reference, Akita, `jolt-field`, schedules, field, and transcript |
| P1 native machine relation | complete in source | CPU, mapper, DMG devices, memory, and logs have generic constraints and mutation fixtures |
| P2 event-driven execution | complete in source | guarded long HALT, DMA, interrupt, timer, serial, PPU, joypad, and APU events use authenticated hardware state |
| P3 bounded block packing | complete in source | one row carries up to four ordinary instructions or one machine event with deterministic generic cuts |
| P4 compact packed CPU relation | complete in source | 4,505 columns, 13,004 constraints, degree bound 41; five shared boundary ranges plus four 82-column lane-local ranges |
| P5 shared proof composition | complete in source | CPU relation, four ISA lookups, ROM, mutable memory, continuity, and ordered logs share the packed commitments |
| P6 receipt/recovery v2 hard cut | complete in source | packed proof wire, v2-only decoder, progress v5, explicit composition identity and raw-step/packed-row cursor separation |
| P6b packed segment filling | complete in source | bounded adaptive chunks fill free relation rows without exceeding fixed capacity |
| P7 static integration gate | complete | documentation/repository/identity/wire/count audits, strict lint, and bounded all-target compilation are green |
| P8 bounded dynamic validation | pending authorization | focused packed relation, wire, recovery, then one bounded component proof and independent verification |
| P9 generic performance work | source optimization active; measurement pending P8 | proof-free and proof measurements across structurally different generic workloads |
| P10 witness hiding | not designed | explicit hiding construction, leakage tests, and review |

No current packed proof or cartridge-scale receipt has been executed. “Complete
in source” means the production path is connected and statically checked; it
does not mean its cryptographic runtime gate has passed.

## Frozen backend identity

| Component | Identity |
| --- | --- |
| Rust | `1.95.0`, minimal profile |
| Jolt protocol reference | `95c898d3d2bbcc178fd8b18603662fce69cfa37d` |
| Akita | `69438de6cd8ce8ed7c9ebb21bdf60b813e8fcabc` |
| Akita transitive `jolt-field` | `72dc6451628d8b1dd794147a1f1cc40be0d77963` |
| Field/config | `fp128::DenseBounded` |
| Fiat-Shamir transcript | Blake2b-512 |
| Native v2 pair schedule SHA-256 | `1cd339f09114c2a941abbfb434ab795868866cb15485f83300d81cee7bf46e71` |
| Native v2 auxiliary schedule SHA-256 | `e601bc0bd9d4501220c367b3012901aac09467f145899c8e907b282d30e96646` |
| Fixed ISA table schedule SHA-256 | `3a8bbab5196d9233434abf33552cd7fc5637c74f0f76cea66cf247eddb8e7287` |
| One-MiB ROM schedule SHA-256 | `141f4ffaf9b1546351a35582352a6337b2855aab3d77cd456bfe30241d4c40af` |
| 128-KiB memory schedule SHA-256 | `8292b771966f1e30f7919796f5ebad3b6327686b7be61a4c778cd4972719ef15` |
| Protocol-log schedule SHA-256 | `2dba5b6d53ca57eaee58c872ceba3cdf6c7dbfe522162144577e71cadf543a80` |
| Fixed ISA commitment SHA-256 | `fc4afaeb9c3d6a7dc063e2927caee773ae4a29f3c16e7d3f1aa5f266ea3f9c9a` |
| Protocol ID | `zksm83-native-jolt-akita-v2` |
| Proof composition revision | `packed-block-transition-count-derived-cpu-scalars-v2` |
| Privacy | transparent |
| RV64 guest | false |

The compiled backend digest additionally binds the exact relation dimensions:
14 row variables, 4,505 logical columns, 13,004 constraint slots, maximum
degree 41, and 128 columns per commitment group.

## Packed relation architecture

The block planner owns accepted trace rows and partitions them using public,
generic bounds:

- at most four ordinary instructions per block;
- bounded total M-cycles and bus events;
- cuts at control-flow and machine-event boundaries; and
- one active machine event per non-instruction block.

`BlockCpuWitness` contains the full shared device, bus, ISA, mapper, memory,
boundary, and routing prefix plus 858 compact CPU auxiliary columns: five
106-column shared CPU/mapper boundary bit ranges and four 82-column lane-local
semantic ranges. Six scalar helpers per lane are recovered linearly from their
committed bit columns. It does not replicate the legacy complete device state or
adjacent CPU boundaries four times. Each instruction lane projects its
before/after state from shared boundaries, its ISA values from the lane plane,
and its memory/ROM tuple from the routed shared bus slots.

The 4,505 logical columns are padded to 4,608 and committed as 36 ordered
128-column groups. The v2 schedule opens them as 18 fixed adjacent pairs. The
final 103 polynomials and their openings are canonical zero.

## Segment composition

One packed segment proves:

1. the deepest row-local block and CPU relation;
2. one fixed-ISA lookup for each of four lanes;
3. every immutable ROM read against the statement-scoped ROM commitment;
4. mutable-memory chronology, fixed clocks, initial/final boundaries, and
   global multiset equality;
5. active-row state continuity and exact public endpoints; and
6. canonical-position bus, input, output, and ISA logs.

All proof components are serialized inside `PackedBlockProof`. The verifier
reconstructs claims from the segment receipt and the separately supplied
statement; it does not execute SM83 code.

## Public statement

The canonical statement binds:

```text
backend_digest
machine_profile
rom_byte_length
rom_commitment_id
initial_boundary
final_boundary
segment_count
transition_count
packed_relation_row_count
m_cycle_count
bus_event_count
input_event_count
output_event_count
isa_row_count
statement_id
```

The initial and final boundaries contain exact machine-state limbs, mutable
memory identity, and cumulative protocol-log identities. Bus and ISA identity
lengths are owned by the explicit packed log plane. The lookup-native legacy
bus/ISA state cursors remain zero; input/output state cursors must equal their
corresponding cumulative log lengths.

## Recovery contract

Progress schema v5 stores both raw `completed_steps` and authenticated packed
`relation_row_count`. The former resumes endpoint execution, but is no longer a
trusted JSON cursor: it must equal the transition count recovered from the
verified frames. A fifth packed-continuity auxiliary column contributes one for
a machine row or the number of active instruction lanes, so its opened sum
authenticates that count. The relation-row count, state, and full memory must
also equal the last verified spool boundary and commitment.

Within one segment, the CLI executes at most the current number of free
relation rows, packs that chunk, and repeats if packing freed capacity. This is
safe for the one-block-per-transition worst case and lets ordinary instruction
streams approach the four-instruction lane bound. Diagnostic source-row indices
are rebased across chunks; they do not affect relation semantics.

The durable ordering is:

1. append the complete segment frame;
2. synchronize the spool;
3. atomically replace and synchronize the progress checkpoint;
4. after the final endpoint matches, publish or byte-check the statement; and
5. publish the receipt last as the completion marker.

Only bytes beyond the last checkpointed spool length may be discarded after a
crash, and the truncated length is durably synchronized before replay. A
shorter spool, mismatched counter, state, memory commitment, explicit
proof-composition revision, backend, schedule, or input identity fails closed.
The final receipt path is checked again immediately before the last rename.

## Next execution sequence

While the no-long-run restriction remains active:

1. keep formatting, strict Clippy, all-target compilation, file-size, and
   ROM-specialization searches clean;
2. preserve the completed statement-revision, identity, wire-bound, count, and
   recovery-publication audit; and
3. prepare focused tests but do not execute them.

After short tests are authorized:

1. run packed CPU family and mutation tests;
2. run v2-only statement/receipt wire tests;
3. run progress-v5 and spool recovery tests; and
4. run the workspace default suite under an explicit short timeout.

After proof work is separately authorized, run exactly one bounded packed
component proof and independent verification before any performance campaign.
Only results that record revision, toolchain, machine, workload identities,
relation geometry, proof size, prove/verify time, and peak RSS count as current
evidence.
