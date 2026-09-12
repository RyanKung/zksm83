# Development and data policy

## Versioned inputs

The repository tracks Rust source, manifests, documentation, and the six
verifier-relevant Akita schedules documented under
`crates/zksm83-jolt/protocol/`. Default tests must run from a fresh clone
without downloading or locating cartridge images, saves, input schedules,
checkpoints, traces, receipts, statements, or benchmark output.

## Local-only data

Git ignores the following classes deliberately:

- `roms/`, `*.gb`, `*.gbc`, `*.rom`: user-supplied cartridge images;
- `*.sav`, `*.srm`: save data;
- `examples/blue-*`: long-running private input schedules;
- `artifacts/`: generated receipts, statements, spools, proofs, traces,
  checkpoints, and reports;
- `*.aks`: unreviewed or generated Akita schedules, except the six explicitly
  admitted M0, native-relation, fixed-ISA, ROM, mutable-memory, and protocol-log
  schedules;
- `backup/`: historical implementation material;
- `jolt-zksm83/`: local backend experiments not integrated into the workspace;
- `tmp/`, `target/`, coverage output, editor state, and local environment files.

Do not weaken these rules by force-adding generated or third-party data. If a
small deterministic fixture becomes necessary, generate it in the test or put
it under a crate-local `tests/fixtures/` directory with its origin and license
documented.

## Optional cartridge runs

Supply absolute local paths to the native prover or trace profiler. Do not copy
cartridge data into a tracked fixture directory:

```sh
cargo run --release -p zksm83-jolt --bin zksm83-native-prover -- \
  --rom /absolute/path/pokemon-blue.gb \
  --input /absolute/path/blue-input.json \
  --expected-checkpoint /absolute/path/blue-endpoint.json \
  --spool /absolute/path/blue.spool \
  --progress-checkpoint /absolute/path/blue.progress.json \
  --receipt /absolute/path/blue.receipt.bin \
  --statement /absolute/path/blue.statement.bin \
  --preflight-only
```

The caller is responsible for providing a lawful image matching the cartridge
contract in [blue-path.md](blue-path.md).

## Slow cryptographic gates

The native Akita gates are explicit because they allocate
setup and commit 16,384-row polynomials. The uniform gates additionally verify
that relation proofs are bound to caller-visible shared commitments and reject
commitment substitution, sumcheck tampering, and multi-group reordering:

```sh
cargo test --release -p zksm83-jolt \
  baseline::tests::pinned_transparent_akita_opening_verifies -- \
  --ignored --exact --nocapture

cargo test --release -p zksm83-jolt \
  uniform::tests::committed_boolean_relation_verifies_and_rejects_tampering -- \
  --ignored --exact --nocapture

cargo test --release -p zksm83-jolt \
  uniform::tests::multiple_commitment_groups_verify_and_reject_reordering -- \
  --ignored --exact --nocapture

cargo test --release -p zksm83-jolt \
  isa_lookup::tests::committed_isa_lookup_verifies_and_rejects_tampering -- \
  --ignored --exact --nocapture

cargo test --release -p zksm83-jolt \
  cpu::tests_more::shared_cpu_and_isa_claims_verify_and_reject_commitment_substitution -- \
  --ignored --exact --nocapture

cargo test --release -p zksm83-jolt \
  rom_lookup::tests::committed_rom_lookup_verifies_and_rejects_tampering -- \
  --ignored --exact --nocapture

cargo test --release -p zksm83-jolt \
  cpu::tests_more::shared_cpu_isa_and_rom_claims_reject_rom_substitution -- \
  --ignored --exact --nocapture

cargo test --release -p zksm83-jolt \
  memory::tests::committed_latest_value_proof_rejects_final_memory_substitution -- \
  --ignored --exact --nocapture

cargo test --release -p zksm83-jolt \
  logs::tests::committed_protocol_logs_reject_table_substitution -- \
  --ignored --exact --nocapture

cargo test --release -p zksm83-jolt --lib \
  receipt::tests::native_receipt_round_trip_and_structural_tampering_are_fail_closed -- \
  --ignored --exact --nocapture

cargo test --release -p zksm83-jolt --lib \
  receipt::tests::two_segment_receipt_authenticates_exact_shared_boundary -- \
  --ignored --exact --nocapture
```

The M4 mutable-memory gate committed a 16,384-row, 987-column trace and exact
initial/final 128-KiB images, proved strict timestamp ordering and a
log-derivative multiset equality, and rejects final-memory substitution. Its
test body completed in 17.33 seconds on the local Apple Silicon development
host. The earlier 742-column revision's combined CPU/ISA/ROM gate took 43.87
seconds, and the isolated one-MiB ROM Shout gate took 3.14 seconds; the combined
987-column CPU/ISA/ROM/RAM composite gate completed in 68.30 seconds and
reported 5,017,305,088 bytes maximum resident set size. Its 2m26s release
compilation is excluded. The preceding 1,072-column M5a CPU/ISA/ROM/RAM composite
gate completed in 83.09 seconds and reported 5,033,656,320 bytes maximum resident
set size; its 1m37s release compilation is excluded. Akita calls run inside an
explicit 512-MiB virtual-stack worker after the dense multi-group trace exceeded the
platform-default stack; a local Rayon pool applies the same bound to Akita's
parallel kernels, and the separately measured RSS is the memory evidence. The
preceding 1,152-column, degree-16 M5b composite gate completed in 90.81 seconds
and reported 5,170,118,656 bytes maximum resident set size; its 1m32s release
compilation is excluded. The current M5c relation has 1,331 columns in eleven
groups, 2,816 constraint slots, and then-declared maximum degree 16. Its composite
gate completed in 106.11 seconds and reported 2,622,210,048 bytes maximum
resident set size after a separate 1m32s release compilation. The preceding M5g
relation had 3,181 columns in twenty-five groups and 6,144 constraint slots; its
composite gate completed in 226.62 seconds with 4,870,389,760 bytes maximum
resident set size after a separate 1m32s release compilation. The preceding M5h
relation has 3,226 columns in twenty-six groups and the same 6,144 constraint
slots. It adds compressed LCD position, frame wrap, VBlank crossing, and IF-zero
constraints. Its composite gate completed in 279.48 seconds with 5,051,596,800
bytes maximum resident set size after a separate 2m33s release compilation.
The preceding M5i relation has 3,266 columns in the same twenty-six groups and adds
all modeled composite STAT rising edges plus IF bit one. Its composite gate
completed in 246.58 seconds with 5,117,280,256 bytes maximum resident set size
and zero swap after a separate 1m53s release compilation. The current M5j
relation has 3,292 columns in the same twenty-six groups and a corrected
maximum degree of 18. It adds FF46 startup,
DMA capacity/debt, DMA-time HRAM-only CPU access, and LCD-mode CPU VRAM/OAM
gates. It also proves the serial completion threshold and all current long-step
device guards. Its composite gate completed in 245.21 seconds with 5,057,085,440
bytes maximum resident set size and zero swap after a separate 1m45s release
compilation under the earlier degree-16 declaration. A real Blue segment later
showed that the APU bus-kind, address, and DAC-any selector composition reaches
degree 18; that old proof timing is historical rather than evidence for the
corrected transcript. A fast finite-difference regression reaches the exact
degree-18 bound. Treat all numbers as revision-specific engineering
measurements, not Jolt-wide or production-throughput claims.

The first M6 protocol-log gate uses one `nv17/p128` group for deterministic
bus/input/output/ISA tables, 32 trace-side inverse limbs, and eight table-side
inverse limbs. It proves exact cursor-derived counts and log-derivative equality,
then rejects a commitment built from a different input. Its test body completed
in 61.16 seconds with 7,336,411,136 bytes maximum resident set size and zero swap;
the preceding 2m27s release compilation is excluded. This is an isolated log gate,
not a full receipt measurement.

The current complete native receipt gate uses a four-row synthetic
`DmgPostBootMbc3V1` trace and composes the current CPU, fixed ISA, one-MiB ROM,
128-KiB initial/final memory, row continuity, and all four protocol-log proofs.
It writes the canonical length-delimited stream, round-trips the statement and
receipt, verifies through parsed, byte-slice, and incremental-reader paths
without an emulator or witness, and rejects a different expected statement,
changed proof bytes, trailing bytes, segment omission, duplication, and a
changed segment index. Under the corrected degree-18 protocol, the proof was
constructed in 319.26 seconds and encoded to 19,018,996 bytes; decoding
completed at 319.31 seconds, parsed verification at 321.94 seconds, and both
byte-slice and incremental-reader verification by 327.37 seconds. The complete
test body finished in 330.15 seconds. The process reported 7,684,227,072 bytes
maximum resident set size and zero swap. Its separate 1m34s release compilation
is excluded. This is single-segment synthetic evidence, not a complete Pokémon
Blue receipt result.

The current degree-18 two-segment receipt gate proved one `LD A,d8` row followed by a
separate `LD (a16),A` row. The second segment starts from the first segment's
exact 38-limb semantic state, identical raw middle-memory commitment, and four
cumulative ordered-log identities. Its bounded stream completed the first
frame in 312.88 seconds and both proofs in 624.06 seconds; incremental and
parsed positive verification plus broken-middle-boundary and reordered-segment
rejection completed in 636.47 seconds. Peak RSS was 8,154,365,952 bytes with
zero swap; a separate 1m34s release compilation is excluded. An earlier
in-memory attempt exposed an unnamed process-global Rayon worker's default-stack
overflow. The production segment boundary now installs the whole proof and
encoding operation into the named 512-MiB-stack pool and retains only encoded
frames between segments.

The receipt and expected-statement formats are bounded binary encodings. The
canonical stream length-prefixes the statement, ROM commitment, and each proof
frame. It limits statements to 16 KiB, ROM commitments to 16 MiB, individual
segments to 512 MiB, segment count to 4096, and a receipt file to 2 TiB. The
standalone verifier processes one segment at a time, rejects trailing bytes and
unsupported versions, and requires a separately supplied exact statement:

```sh
cargo run --release -p zksm83-jolt --bin zksm83-native-verifier -- \
  /absolute/path/expected-statement.bin \
  /absolute/path/native-receipt.bin
```

## Pokémon Blue streaming gate

The local endpoint preflight recomputed the supplied one-MiB ROM and 128-KiB
checkpoint roots and fixed 9,994,417 relation rows, 611 segments of 16,384 rows,
131,072 supplied input bytes, and 62,685 consumed bytes. It produced these
content identities without creating proof data:

```text
ROM SHA-256                  2a951313c2640e8c2cb21f25d1db019ae6245d9c7121f754fa61afd7bee6452d
expanded input SHA-256       96cb311647ec7e5f750425232f15dcc091e8b069ca013f889ec0131323dbbe10
endpoint checkpoint SHA-256 5bbcce5ef386027aa27897a434e0627d39ec22018fea363e9626df00d9b5da36
```

The first real 16,384-row segment initially failed closed at the reduced CPU
sumcheck, exposing the understated degree. After correction to 18, it proved in
316.263 seconds, wrote a 19,016,810-byte frame, used 7,705,133,056 bytes maximum
resident memory, and reported zero swap. Explicit resume reverified that frame,
matched the atomic SM83 state/memory checkpoint, and paused without adding a
segment in 18.40 seconds with 334,282,752 bytes maximum resident memory.

The first cross-process append then failed closed because Akita's derived Rust
equality distinguished reconstructed commitment metadata even though both
canonical commitment digests were exactly
`a0ee9cf05b1011df147a1ec7d60cee6ee33f0e3688df241bec4f1b67bc85ba73`.
The segment chain now compares canonical commitment identities and resume
separately checks the full persisted native state and canonical memory
commitment before executing another row. With that fix, the adjacent second
segment completed in 325.733 seconds. The durable spool now contains 32,768
rows in two frames and is 37,864,191 bytes; a new process reverified both frames
and the progress checkpoint in 17.74 seconds using 333,365,248 bytes maximum
resident memory. The second-segment run used 7,233,519,616 bytes maximum
resident memory and zero swap. At the observed two-segment average, a purely
serial 611-segment run projects to about 54.5 hours and 10.77 GiB; that is an
estimate, not a completed path result.

A fresh native-only run initially exposed a separate Akita startup race: the
parallel root-commit workers could contend on one lazily initialized NTT slot.
Revision `2b342e7` derives and prewarms only the root-commit NTT requirements
from each pinned schedule before parallel fan-out. Four adjacent real segments
then completed in 335.488, 336.909, 334.381, and 328.288 seconds, producing a
75,559,650-byte checkpointed spool for 65,536 rows. After the run was stopped,
a fresh process verified the four frames and exact checkpoint in 10.109
seconds. Short negative checks rejected a spool shorter than its checkpoint and
a changed checkpoint CPU state. A byte appended beyond the checkpointed length
was discarded as an uncommitted crash tail; it was not parsed as a receipt
frame. The full 611-segment run was deliberately deferred, so these figures are
prefix and recovery evidence only.

The prover never finalizes a partial path as the declared Blue statement. A
bounded engineering run uses `--segment-limit`; `--resume --segment-limit 0`
only verifies recovery state. Omitting the limit continues toward the exact
endpoint. Spool, progress checkpoint, ROM, input schedule, receipt, and public
statement all remain ignored local artifacts.

For audit-only recovery checks, use the normal prover arguments with
`--inspect-progress-only`. This path opens the spool read-only, rejects both a
short spool and uncheckpointed trailing bytes, verifies every frame plus the
checkpointed final state and memory commitment, and emits stable JSON with the
input, checkpoint, progress, and spool SHA-256 identities. It performs no VM
steps, proof generation, truncation, or receipt finalization.

## Generated output

Prefer a fresh temporary directory for manual proofs and measurements. Record
the source revision, complete command, toolchain, parameters, and public
statement whenever a result is used as evidence. Generated output remains
local unless a later review explicitly approves a bounded, reproducible
artifact for version control.
