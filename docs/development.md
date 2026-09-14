# Development and data policy

## Versioned inputs

The repository tracks Rust source, manifests, documentation, and explicitly
admitted verifier schedules under `crates/zksm83-jolt/protocol/`. Default tests
must run from a fresh clone without cartridge images, saves, input schedules,
checkpoints, traces, receipts, statements, or benchmark output.

## Native receipt v2

New output uses `zksm83-native-jolt-akita-v2`, `ZKSM83R2` receipts,
`ZKSM83S2` statements, and the pinned paired schedule. The current 4,505
logical packed CPU columns form 36 commitments and 18 adjacent-pair openings.
Auxiliary planes use the pinned single-group schedule. Both schedule digests,
the exact trace width, and the relation dimensions are bound by the backend
identity and required progress-v5 proof-composition revision and backend
digest. Progress records raw completed transitions separately from
authenticated packed rows. Resume has no
compatibility fallback for earlier progress schemas, and receipt/statement
decoders reject v1.

The generic-relation cutover removed cartridge-specific execution modes and
changed the trace width. Older proof artifacts are not resumable and must not be
reported as current performance evidence.

## Local-only data

Git ignores these classes deliberately:

- `roms/`, `*.gb`, `*.gbc`, `*.rom`: user-supplied cartridge images;
- `*.sav`, `*.srm`: save data;
- local input schedules and endpoint/checkpoint data;
- `artifacts/`: receipts, statements, spools, proofs, traces, checkpoints, and reports;
- unreviewed/generated `*.aks` schedules except explicit allow-listed protocol parameters;
- `backup/` and local backend experiments;
- fuzz corpora and failure artifacts;
- evidence, metrics, folded profile, and profiler output;
- temporary directories, build output, coverage, editor state, and local environment files.

Do not force-add generated or third-party data. A small deterministic fixture
must be generated in its test or live under a crate-local `tests/fixtures/`
directory with origin and license documented.

## Optional cartridge runs

Supply absolute local paths to the generic prover or trace profiler. A
cartridge is a workload, never a selector for a different proof relation:

```sh
cargo run --release -p zksm83-jolt --bin zksm83-native-prover -- \
  --rom /absolute/path/cartridge.gb \
  --input /absolute/path/input-schedule.json \
  --expected-checkpoint /absolute/path/endpoint.json \
  --spool /absolute/path/native.spool \
  --progress-checkpoint /absolute/path/native.progress.json \
  --receipt /absolute/path/native.receipt.bin \
  --statement /absolute/path/native.statement.bin \
  --preflight-only
```

The `lookup_rom_prefix` example profiles a caller-supplied cartridge. The
deterministic proof-free comparison suite runs without private data:

```sh
cargo run -p zksm83-jolt --bin zksm83-proof-free-profile -- \
  --steps 4096 --repeats 5 --packed-trace-steps 4096
```

Profile at least three structurally different workloads before accepting a
performance change. See [proof-free-baseline.md](proof-free-baseline.md) for
the report contract, optional native-column encoder, and peak-memory command.
The P1 producer/consumer inventory and protocol-visible candidates are recorded
in [relation-audit.md](relation-audit.md).

## Test tiers

The normal development gate is:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

Cryptographic gates are `#[ignore]`, explicit, and potentially memory-heavy.
Run them only when separately authorized. Full cartridge proofs are release
measurements, not development tests. A result is evidence only when it records
source revision, toolchain, machine, workload identities, trace dimensions,
proof size, prove/verify time, and peak resident memory.

## Generated output

Use a fresh temporary directory for manual proofs and measurements. The
standalone verifier requires an independently supplied statement:

```sh
cargo run --release -p zksm83-jolt --bin zksm83-native-verifier -- \
  /absolute/path/expected-statement.bin \
  /absolute/path/native-receipt.bin
```

Generated output remains local unless a later review explicitly approves a
bounded, reproducible artifact for version control.
