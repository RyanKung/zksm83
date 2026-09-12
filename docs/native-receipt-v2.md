# Native receipt v2

This document freezes the protocol model for the second native SM83 receipt
format. Version 2 changes the shared trace PCS topology. It does not change the
SM83 transition relation, public machine profile, or privacy claim.

## Protocol identity

- Receipt version: `2`.
- Receipt magic: `ZKSM83R2`.
- Statement magic: `ZKSM83S2`.
- Protocol identifier: `zksm83-native-jolt-akita-v2`.
- Trace schedule: `fp128_dense_bounded_nv14_p128_pair.aks`.
- Trace schedule SHA-256:
  `1cd339f09114c2a941abbfb434ab795868866cb15485f83300d81cee7bf46e71`.
- Auxiliary single-group trace schedule SHA-256:
  `e601bc0bd9d4501220c367b3012901aac09467f145899c8e907b282d30e96646`.
- Trace opening domain: `zksm83-native-shared-opening/v2`.
- Trace commitment identity domain:
  `zksm83/native-witness-commitments/v2`.
- PCS batch descriptor domain: `zksm83/native-pcs-pair/v2`.

The backend digest binds the v2 protocol identifier, pair schedule digest, and
auxiliary single-group schedule digest.
The statement digest binds that backend digest. A v1 statement cannot be
relabelled as v2, and a v2 segment proof cannot be decoded through the v1
receipt branch.

## Trace PCS object

The trace is an ordered vector of 3,292 logical multilinear polynomials over
14 Boolean variables. The vector is padded canonically to 3,328 polynomials and
partitioned into 26 ordered groups of 128 polynomials.

Version 2 partitions those groups into 13 adjacent pairs:

```text
pair(i) = (group(2i), group(2i + 1)), 0 <= i < 13
```

For each pair, the first group is committed with the exact precommitted profile
frozen by the pinned schedule. The second group is committed as the final group
against that ordered precommitment. One Akita batched opening proves both groups
at the same sumcheck point. Pair order, group order, commitment identity,
opening values, opening point, schedule-row digest, and pair index are
transcript-bound.

No schedule is selected from proof-controlled geometry. The compiled layout
requires exactly 26 groups, exactly 13 pair openings, and the one pinned
schedule row. The final 36 padding polynomials are zero and their claimed
openings must also be zero.

## Compatibility rule

New provers and the prover CLI emit only v2 receipts and statements. Verifiers
select a decoder and transcript model from the outer receipt or statement
magic before decoding nested proofs:

- v2 is the canonical generation format;
- v1 remains verification-only for existing canonical receipts;
- unknown versions, mixed-version statements, and cross-version proof
  substitution fail closed;
- v1 bytes and v1 transcript construction remain unchanged.

## Bounded selection evidence

The two-group `nv9/p128` micro-gate passed exact verification and all required
tamper cases. It reduced framed proof payload by 47.20 percent, reduced opening
time by 12.57 percent, and increased sampled peak RSS by 5.11 percent.

Three- and four-group candidates reduced time and bytes further but increased
sampled peak RSS by 28.58 and 31.50 percent, exceeding the frozen 25 percent
memory gate. Version 2 therefore uses pair batching rather than an unbounded
26-group opening.

These measurements are PCS micro-gates. They are not an SM83 receipt benchmark
and do not establish complete Pokémon Blue proving performance.

## Privacy and execution boundary

Version 2 remains a transparent Module-SIS proof. It does not claim witness
hiding. Execution is native SM83 and does not use an RV64 guest. Full 611-segment
Pokémon Blue proving is outside the migration validation path.
