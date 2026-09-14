# Native receipt v2

This document freezes the canonical native-SM83 receipt model. Version 2 uses
the generic packed-block relation and a transparent Akita lattice PCS. It does
not change the public DMG/MBC3 machine profile and does not claim witness
hiding.

## Protocol identity

- Receipt version: `2`.
- Receipt magic: `ZKSM83R2`.
- Statement magic: `ZKSM83S2`.
- Protocol identifier: `zksm83-native-jolt-akita-v2`.
- Proof composition revision:
  `packed-block-transition-count-derived-cpu-scalars-v2`.
- Main relation: `BlockCpuRelation`.
- Logical relation width: 4,505 columns.
- Constraint slots: 13,004.
- Conservative maximum degree: 41.
- Trace schedule: `fp128_dense_bounded_nv14_p128_pair.aks`.
- Trace schedule SHA-256:
  `1cd339f09114c2a941abbfb434ab795868866cb15485f83300d81cee7bf46e71`.
- Auxiliary single-group schedule SHA-256:
  `e601bc0bd9d4501220c367b3012901aac09467f145899c8e907b282d30e96646`.
- Trace opening domain: `zksm83-native-shared-opening/v2`.
- Trace commitment domain: `zksm83/native-witness-commitments/v2`.
- PCS pair descriptor domain: `zksm83/native-pcs-pair/v2`.

The backend digest binds these values together with the pinned Jolt, Akita,
and `jolt-field` revisions, fixed ISA identity, ROM/memory/log schedules,
field, transcript, row geometry, privacy mode, and absence of an RV64 guest.
The statement digest binds the backend digest.

## Main PCS object

The packed CPU witness is an ordered vector of 4,505 multilinear polynomials
over 14 Boolean row variables. It is padded with 103 canonical zero polynomials
to 4,608 columns and split into 36 ordered groups of 128 columns.

Version 2 opens adjacent pairs:

```text
pair(i) = (group(2i), group(2i + 1)), 0 <= i < 18
```

For each pair, the first group uses the precommitted profile frozen by the
pinned schedule. The second is committed as the final group against that
ordered precommitment. One Akita batched proof opens both groups at the shared
sumcheck point. Pair index, group order, commitments, opening values, point,
and schedule-row digest are transcript-bound.

The layout is selected from the compiled protocol and logical column count,
not from proof-controlled geometry. The v2 main plane must have exactly 36
groups and 18 pair openings. Auxiliary inverse and table planes continue to
use their explicit single-group or component-specific schedules.

## Segment proof

One `NativeSegmentReceipt` carries a `PackedBlockProof` over the shared main
commitments. The proof contains:

- the 4,505-column `BlockCpuRelation` opening;
- four lane-specific fixed-ISA lookup proofs;
- one immutable-ROM lookup proof;
- packed mutable-memory event, clock, boundary, and multiset proofs;
- packed state-continuity inverse and sum proofs; and
- packed protocol-log trace/table inverse and sum proofs.

The segment also carries its exact initial/final public boundaries, initial and
final memory commitments, protocol-log commitments and counts, active packed
row count, padding count, and M-cycle delta. Verification reconstructs the
claims from those public values and never replays an emulator.

## Compatibility rule

The canonical high-level format is v2-only:

- provers and encoders emit only `ZKSM83R2`/`ZKSM83S2`;
- receipt and statement decoders reject `ZKSM83R1`/`ZKSM83S1` as unsupported;
- mixed numeric versions, magic values, statements, or proof layouts fail
  closed; and
- there is no legacy decoder, negotiation, or dual-format fallback.

The former `NativeCpuStructuralProof`, `NativeRomCpuProof`,
`NativeMemoryCpuProof`, `ContinuityProof`, `MutableMemoryProof`, and
`ProtocolLogProof` types, their prove/verify functions, and their wire layouts
are absent. `NativeTraceWitness` and `CpuStructuralRelation` remain only as a
one-transition semantic reference for constructing and auditing packed CPU
lanes; they cannot be encoded or accepted as a receipt.

`ZKSM83R1` and `ZKSM83S1` remain only as decoder rejection sentinels. Some
lower-level PCS components retain `/v1` domain suffixes because those suffixes
identify independently frozen component schemas, not a selectable receipt
protocol. Renaming them would change the V2 cryptographic statement and is not
part of deleting the V1 receipt route.

## Recovery identity

The resumable prover uses progress schema
`zksm83-native-prover-progress/v5`. It records raw `completed_steps` separately
from authenticated `relation_row_count`, because up to four instructions now
share one relation row. Inspection emits
`zksm83-native-progress-evidence/v5`.

Resume first compares the exact protocol/backend/schedule and input identities,
then verifies the declared spool prefix. It checks the recovered segment count,
source transition count, packed row count, spool length, final state, and final
memory commitment against the checkpoint before rebuilding the trace builder.
The packed continuity proof commits a fifth auxiliary column equal to one for a
machine row or to the number of active instruction lanes; its authenticated sum
therefore binds `completed_steps` without trusting the JSON checkpoint. The
checkpoint and inspection evidence carry the proof-composition revision as an
explicit field in addition to the compiled backend digest. A relation-width,
constraint-count, degree, transcript, proof-composition or wire revision,
privacy, or schedule change invalidates the checkpoint. Older progress schemas
are not accepted. Progress v5 also rejects unknown JSON fields and counters
outside the fixed segment count, segment row capacity, four-transition row
density, or spool byte bounds before it decodes a proof frame.

## Validation boundary

The earlier two-group PCS micro-gate established the chosen pair schedule and
its bounded memory policy. It did not test the current 36-group packed CPU
plane. During the current no-long-run phase, the new receipt composition and
wire layout have only been subjected to formatting, strict linting, and
bounded compilation. No packed proof or cartridge-scale receipt benchmark has
been run.

Version 2 is transparent Module-SIS proof infrastructure. A separate
witness-hiding construction and review are required before the system can
claim zero knowledge.
