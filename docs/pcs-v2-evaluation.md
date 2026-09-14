# PCS v2 batching evaluation

This document records the historical bounded decision gate that selected
two-group Akita pair openings. The current receipt is a later hard-cut v2
format; it rejects v1 wire data and applies the selected pair schedule to the
4,505-column packed CPU plane.

## Historical version 1 boundary

Each pinned version 1 schedule catalog admits exactly one final group and no
precommitted groups. The former 3,292-column native trace was committed as 26 groups of
128 polynomials, and `prove_opening` created one independently
transcript-bound Akita proof per group. Passing all 26 groups to one existing
call would fail schedule resolution; it is not a compatible wire optimization.

A 26-group Akita root requires an ordered profile containing 25 precommitted
`(num_vars=14, num_polynomials=128)` groups and one final group of the same
shape. The prover setup capacity becomes 3,328 polynomials. The final group
must be committed with the exact precommitted profile prefix, so the change
affects commitments, transcripts, proof shape, schedule identity, and wire
encoding.

## Isolation rules used by the gate

- Keep the historical v1 identities and schedules byte-separated while
  evaluating a new protocol; the later hard cut no longer exposes a v1 receipt
  decoder.
- Generate candidate schedules only from pinned Akita revision
  `69438de6cd8ce8ed7c9ebb21bdf60b813e8fcabc` into a fresh ignored directory.
- Give an accepted candidate a new schedule digest, protocol identifier,
  transcript domain, receipt version, and decoder branch.
- Never make a proof select an unpinned schedule or infer group order from
  proof-controlled data.
- Preserve transparent, non-witness-hiding wording.

## Short micro-gate

The first candidate contains two 512-row, 128-polynomial groups: one exact
precommitted group followed by one exact final group. Compare it with two
independent version 1 openings over the same columns, point, and opened values.
The harness must reject swapped groups, a changed commitment, a changed opened
value, a changed point, and a changed schedule selection.

Stop the process if setup plus either proof path reaches 30 seconds. Do not run
the 16,384-row native relation, any ignored repository proof gate, or a full
segment for this decision. Record warm and cold setup separately from commit,
opening, encoding, verification, proof bytes, and peak resident memory.

Proceed to a larger candidate only if the two-group batch:

- verifies against the exact independent public claims;
- reduces total proof bytes;
- reduces warm opening time by at least 10 percent; and
- increases peak resident memory by no more than 25 percent.

Failure or timeout keeps independent version 1 openings. A successful micro
gate permits schedule planning for four groups, then 26 groups, but does not by
itself authorize a protocol migration or a full-path proof.

## Reproducible bounded runner

Generate the candidate from the exact pinned Akita revision in a fresh local
directory. The resulting `.aks` remains ignored and is not a version-one
protocol artifact:

```sh
cargo run --release -p akita-planner --features catalog-gen \
  --bin gen_schedule_artifacts -- /absolute/path/to/local-candidate \
  --final-group fp128_dense_bounded:9:128 \
  --precommitted-group fp128_dense_bounded:9:128
```

Run the comparison from this repository:

```sh
cargo run --release -p zksm83-jolt --bin zksm83-pcs-batch-gate -- \
  --candidate-schedule /absolute/path/to/local-candidate/fp128_dense_bounded.aks \
  --timeout-seconds 30
```

The controller runs the independent and batched paths in separate child
processes, samples their resident memory, and kills either child at its hard
deadline. Direct worker invocation is rejected. Each path records cold and
warm setup/prewarm, commitment, opening, canonical encode/decode, verification,
payload bytes, and total worker time. The batched path also rejects swapped
groups, changed commitments, values, points, and schedule selection. The final
JSON sets `accepted_for_larger_candidate` only when every gate above passes.

The command performs a real PCS micro-opening but never executes or proves an
SM83 transition. It is not part of default tests, fast CI, receipt version 1,
or any claim about a complete cartridge execution.

## Accepted two-group micro-gate

Revision `088796c` ran the release gate on Apple M1 Max, macOS arm64, with
Rust 1.95.0. The separately optimized binary build took 1 minute 54 seconds;
compiler time is excluded from every PCS measurement. The pinned planner made
the two-group candidate in 8.53 seconds. Its ignored 11,648-byte schedule had
SHA-256
`b35cc4ab357df85fcd751532358d3b534433fd1922f891508bdd34c2c57f9d97`.

Both child paths stayed far below their independent 30-second deadlines:

| Measurement | Two independent openings | One batched opening |
| --- | ---: | ---: |
| cold setup/prewarm | 0.033398 s | 0.018257 s |
| warm setup/prewarm | 0.055336 s | 0.014303 s |
| commitment | 0.052249 s | 0.033387 s |
| opening | 0.575955 s | 0.503537 s |
| canonical encode/decode | 0.000148 s | 0.000085 s |
| verification | 0.012078 s | 0.010285 s |
| total worker | 0.732209 s | 0.581636 s |
| framed proof payload | 140,737 bytes | 74,309 bytes |
| sampled peak RSS | 233,095,168 bytes | 245,006,336 bytes |

The batched opening was 12.57 percent faster, reduced the framed proof payload
by 47.20 percent, and increased sampled peak RSS by 5.11 percent. Exact claims
verified, and all five group-order, commitment, value, point, and schedule
mutations failed closed. At that decision checkpoint, the two-group gate
permitted the next bounded candidate but did not yet admit a receipt format or
alter version 1.

## Larger bounded candidates and final selection

The four-group `nv9/p128` candidate completed the same real PCS micro-gate. It
reduced opening time by 31.55 percent and framed proof bytes from 281,531 to
82,580, and rejected all five mutations. Sampled peak RSS increased from
294,174,720 to 386,842,624 bytes, or 31.50 percent, so it failed the 25 percent
memory gate.

A three-group candidate was then measured as a bounded fallback. It reduced
opening time by 41.51 percent and framed proof bytes from 211,173 to 77,538,
and rejected all five mutations. Sampled peak RSS increased from 260,177,920
to 334,544,896 bytes, or 28.58 percent, so it also failed the memory gate.

The accepted two-group geometry was regenerated for the real `nv14/p128`
trace layout. The checked-in 13,502-byte schedule has SHA-256
`1cd339f09114c2a941abbfb434ab795868866cb15485f83300d81cee7bf46e71`.
The current packed v2 layout reuses that two-group schedule for 36 groups and
18 adjacent pairs. No 16,384-row packed SM83 proof or cartridge-scale proof has
been run for this 4,505-column geometry; the measurements above remain
historical PCS micro-gates only.
