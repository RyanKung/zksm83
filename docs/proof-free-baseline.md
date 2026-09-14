# Proof-free performance baseline

`zksm83-proof-free-profile` measures generic execution and witness
construction. It never commits polynomials, runs sumcheck, opens the PCS, or
emits a receipt. Its synthetic programs are workloads, not recognized
production ROMs or alternate transition modes.

The current report schema is `zksm83-proof-free-profile/v4`. Each report binds
the protocol ID, backend digest, and named proof-composition revision.

## Workload matrix

| Workload | Structural purpose |
| --- | --- |
| `cpu_branch_loop` | register arithmetic and taken relative control flow |
| `wram_read_write_loop` | ordered mutable-memory reads and writes |
| `stack_multi_write_loop` | multiple ordered stack writes and matching reads |
| `joypad_input_loop` | committed private input and typed MMIO reads |

Each report includes the protocol ID, exact step count, event metrics,
frequent authenticated PCs, synthetic ROM witness root, and final 38-limb
semantic state. Comparisons are valid only when those semantic fields match.

## Current dimensions

The dimension section reports the current v2 packed relation:

| Quantity | Value |
| --- | ---: |
| Logical columns | 4,505 |
| Rows per column | 16,384 |
| `u64` witness cells | 73,809,920 |
| Raw `u64` payload bytes | 590,479,360 |
| Physical padded columns | 4,608 |
| Canonical zero columns | 103 |
| Commitment groups | 36 |
| Paired openings | 18 |
| Constraint slots | 13,004 |
| Maximum declared degree | 41 |

The raw byte count is only the logical `u64` witness payload. It excludes
vector overhead, field conversion, the mutable sumcheck plane, commitments,
inverse/table planes, PCS setup, and proof encoding.

## Commands

Run the execution-only suite with:

```sh
cargo run -p zksm83-jolt --bin zksm83-proof-free-profile -- \
  --steps 4096 --repeats 5
```

The optional packed path retains one workload, plans generic blocks, builds
the complete fixed-row `BlockCpuWitness`, and evaluates
`BlockCpuRelation` without PCS work:

```sh
cargo run -p zksm83-jolt --bin zksm83-proof-free-profile -- \
  --steps 1 --repeats 1 --packed-trace-steps 4096
```

On macOS, peak resident memory can be collected around the already-built
binary:

```sh
/usr/bin/time -l \
  target/aarch64-apple-darwin/debug/zksm83-proof-free-profile \
  --steps 4096 --repeats 1 --packed-trace-steps 4096 >/dev/null
```

These commands are documentation only while the no-long-run restriction is
active. The profiler has not been executed after its schema-v4 packed and
identity migration.

## Packed report fields

The optional `packed_trace` object records:

- raw transitions retained;
- block planning time;
- packed CPU encoding time;
- packed CPU relation validation time;
- packed relation rows;
- instruction-block and machine-event counts;
- maximum instruction-lane, M-cycle, and bus-slot occupancy;
- final packed active rows and column count; and
- the final exact state boundary.

Raw transitions and packed rows are deliberately different quantities. Up to
four ordinary instructions share one row, while each machine event occupies a
singleton row.

## Historical P0 facts

Earlier proof-free inspection motivated several generic allocation changes:

- ordered same-instruction memory dependencies no longer clone the full
  128-KiB table;
- program-counter summaries use a sparse map rather than a 65,536-entry dense
  array;
- basic-block ownership moves trace rows instead of cloning them;
- binary MLE folding mutates buffers in place;
- committed dense field columns are borrowed by later relation consumers;
- row/constraint evaluator scratch is reused; and
- CPU selector and log tuple temporaries use fixed arrays or caches.

Measurements made before the current packed hard cut are historical and
must not be presented as current proof or memory performance.

## Promotion gate

For every optimization, record:

1. source revision and dirty-state description;
2. Rust target/profile and machine;
3. workload and input identities;
4. raw transitions and packed rows;
5. relation dimensions and schedule digests;
6. per-phase time and peak RSS; and
7. exact semantic endpoints.

Use several structurally distinct generic workloads. No cartridge is the sole
promotion gate, and no observation may create a ROM-specific production fast
path.

Proof-free results say nothing about proof size, PCS opening time, verifier
time, or witness hiding. Those require separately authorized gates.
