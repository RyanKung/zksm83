# PCS v2 batching evaluation

This document defines the bounded decision gate for replacing version 1's
independent Akita openings with a genuine multi-group opening. It is an
experiment plan, not a protocol claim. Version 1 remains the only accepted
receipt format until every gate below passes.

## Confirmed version 1 boundary

Each pinned version 1 schedule catalog admits exactly one final group and no
precommitted groups. The 3,292-column native trace is committed as 26 groups of
128 polynomials, and `prove_opening` currently creates one independently
transcript-bound Akita proof per group. Passing all 26 groups to one existing
call would fail schedule resolution; it is not a compatible wire optimization.

A 26-group Akita root requires an ordered profile containing 25 precommitted
`(num_vars=14, num_polynomials=128)` groups and one final group of the same
shape. The prover setup capacity becomes 3,328 polynomials. The final group
must be committed with the exact precommitted profile prefix, so the change
affects commitments, transcripts, proof shape, schedule identity, and wire
encoding.

## Isolation rules

- Keep `zksm83-native-jolt-akita-v1`, receipt version 1, and all current
  schedules byte-for-byte verifiable.
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
the 16,384-row native relation, any ignored repository proof gate, or a Blue
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
or any claim about the complete Blue path.

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
mutations failed closed. The two-group gate therefore permits the next bounded
candidate; it does not admit a receipt format or alter version 1.

The next four-group schedule was planned but not proved. Generation completed
in 16.28 seconds and produced an ignored 15,841-byte artifact containing three
ordered precommitted `nv9/p128` groups plus one final `nv9/p128` group. Its
SHA-256 is
`0ff710c72a46d3681cb367581e2ff13bdace5e9ba4984eccfd94ed110580b17f`.
No four-group or 26-group commitment/opening has been run.
