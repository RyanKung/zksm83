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
