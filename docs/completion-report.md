# Implementation status

This document separates source-backed capabilities from unfinished proof
claims. Generated receipts, ROMs, traces, saves, inputs, and measurements are
not versioned.

## Current native receipt

The workspace has one proof route. `zksm83-jolt` composes the 6,144-slot,
degree-18 CPU/device relation with fixed-table ISA lookup, immutable ROM,
ordered mutable memory, row-tagged continuity, and committed bus/input/output/
ISA logs. The v2 receipt binds one statement-scoped ROM commitment and an exact
chain of segment boundaries, memory commitments, counters, and cumulative log
identities. Its shared trace uses 13 paired openings for 26 ordered commitment
groups. Existing v1 receipts remain readable through an explicit
verification-only branch; new proving and recovery checkpoints are v2-only.

The independent verifier takes a separately supplied exact statement. It does
not receive or reconstruct an emulator, execution trace, ROM image, memory
image, or private input. The canonical binary format bounds statement, ROM,
segment, segment-count, and total-stream sizes, rejects trailing data, and
verifies one segment frame at a time.

The resumable prover writes each complete proof frame to a seekable spool,
syncs it, and atomically replaces an exact SM83 state plus 128-KiB memory
checkpoint. Resume verifies every checkpointed proof and rejects noncanonical
or shorter data. Bytes beyond the checkpoint-declared spool length are an
uncommitted crash tail: resume discards them without parsing or accepting them,
then checks the exact semantic and canonical memory boundary before executing
another row. Final receipts use a different immutable format whose verifier
rejects every trailing byte. Proving and encoding remain inside a named
large-stack Rayon pool.

## Cutover status

Halo2/Pasta, `zksm83-proof`, `zksm83-receipt`, `zksm83-audit`, and the obsolete
CLI have been removed from the workspace. The remaining crate graph has no
RV64, RISC-V guest, Jolt SDK, Halo2, Pasta, Dory, or BN254 dependency.

The pure `zksm83-core::StepRelation` remains the only execution semantics.
Witness-side Merkle and prefix authentication uses a versioned,
domain-separated SHA-256 construction. These witness roots are deliberately
absent from `NativeStateBoundary`: the native verifier establishes ROM, RAM,
and protocol-log consistency from Akita commitments and openings instead.
Legacy endpoint checkpoints remain readable, but their old Poseidon root
fields are compatibility data rather than proof identities. Endpoint policy
still checks exact CPU, MBC3, devices, complete mutable memory, consumed input
prefix, and the empty output accumulator for the current Blue target.

This is a transparent proof system. No witness-hiding or zero-knowledge claim
is made.

## Completed proof evidence

The complete receipt and Blue-prefix measurements below were produced by the
v1 independent-opening pipeline. They remain historical evidence for the
unchanged SM83 relation, but are not v2 performance or full-receipt evidence.
The v2 migration intentionally ran only bounded PCS micro-gates and fast tests.

The corrected transcript declares maximum degree 18. A regression reaches that
exact APU selector degree, preventing the earlier degree-16 understatement.

A complete four-row synthetic receipt passed canonical serialization,
positive parsed/byte/stream verification, and statement, proof, encoding, and
segment tamper rejection. It produced 19,018,996 bytes in 319.26 seconds; the
full tamper gate completed in 330.15 seconds at 7,684,227,072 bytes peak RSS and
zero swap. Compilation is excluded.

A separate degree-18 two-segment stream passed exact semantic, memory, and
cumulative-log chaining plus incremental and parsed verification. It rejected
a broken middle boundary and segment reordering. The first frame completed in
312.88 seconds, both proofs in 624.06 seconds, and the full gate in 636.47
seconds at 8,154,365,952 bytes peak RSS and zero swap. Compilation is excluded.

On the pre-cutover revision, the first two adjacent real Pokémon Blue segments
proved 32,768 rows into a 37,864,191-byte spool. Segment proof times were
316.263 and 325.733 seconds; fresh-process recovery verified both frames and
the exact checkpoint in 17.74 seconds. Peak proving RSS was 7,705,133,056 and
7,233,519,616 bytes respectively, with zero swap. This established bounded
recovery, not a complete game-path receipt. Because the witness-auth scheme
changed during native-only cutover, that old progress checkpoint is not resumed
into the final artifact.

The first post-cutover launch at `c49b110` exposed a startup race in Akita's
lazy NTT cache: parallel root commitments could wait on the same initialization
slot. Revision `2b342e7` prewarms the exact root-commit requirements selected by
each pinned schedule before parallel commitment. From that frozen revision,
four adjacent real Blue segments completed in 335.488, 336.909, 334.381, and
328.288 seconds. The checkpointed prefix contains 65,536 rows in 75,559,650
bytes and a fresh process reverified all four frames plus the exact state and
memory checkpoint in 10.109 seconds. The operator then stopped the long run;
no final receipt or statement was emitted. The available measurement did not
capture a reliable peak-RSS value, so none is claimed for this revision.

```text
four-frame spool SHA-256      ab8fda32c28dbeec22aa0b38e3dee7387cd5a82130da234bc565499fcdd8c7ab
progress checkpoint SHA-256  979279bbcfeb6c2706a3f0de9958861649ef9820cd0a07b16f320665f5264dd1
```

## Pokémon Blue boundary

Current preflight pins:

```text
relation rows                    9,994,417
16,384-row segments                    611
expanded private input bytes          131,072
consumed input bytes                    62,685
ROM SHA-256                    2a951313c2640e8c2cb21f25d1db019ae6245d9c7121f754fa61afd7bee6452d
input SHA-256                  96cb311647ec7e5f750425232f15dcc091e8b069ca013f889ec0131323dbbe10
endpoint checkpoint SHA-256    5bbcce5ef386027aa27897a434e0627d39ec22018fea363e9626df00d9b5da36
ROM witness-auth root          ff453435441a975fb1d1df3a74cf306477a0e0108506892bd8b5a82744386174
endpoint memory witness root   5732c1ae44d4f657093dc5ce9427f0d94ee29878fcbe9f0e5179c729f10a1ccd
```

The observed post-cutover four-segment average projects a serial 611-segment
run at roughly 56.6 hours and 10.75 GiB. That is only a revision-specific linear
estimate. The full native-only chain was explicitly deferred before segment
five and has not completed.

## Completion condition

The target completes only when one independently verified receipt binds:

1. the exact initial and final public VM boundaries;
2. every admitted native SM83 transition;
3. ISA selection from authenticated opcode bytes;
4. ordered ROM and mutable-memory accesses;
5. every modeled no-RTC MBC3 and DMG device transition;
6. all four ordered protocol logs and counters; and
7. every segment boundary across the declared 9,994,417-row Blue execution.

Component proofs, trace construction, endpoint replay, two-segment evidence,
and performance projections do not substitute for that final proposition.
