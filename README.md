# zksm83

`zksm83` is a native SM83 proof-system research workspace. It executes and
proves the SM83 transition relation directly.

The only proof pipeline is `zksm83-jolt`: a transparent Akita lattice-PCS
receipt over a shared native witness. It binds the complete SM83 CPU/ISA
relation, a one-MiB immutable ROM, ordered 128-KiB mutable memory, no-RTC MBC3,
the modeled DMG devices, segment continuity, and ordered bus/input/output/ISA
logs. The standalone verifier receives a separately pinned public statement
and no emulator, trace, ROM image, memory image, or private log values.

Halo2/Pasta, the MOVA-era audit implementation, and their old CLI/receipt crates
have been removed. Witness-side execution authentication now uses
domain-separated SHA-256; verifier-visible ROM/RAM/log claims remain Akita
commitments and openings. This cutover does not turn the transparent protocol
into witness-hiding zero knowledge.

New statements and receipts use a hard-cut native receipt v2. Its 4,604-column
packed CPU plane forms 36 ordered commitment groups. The full CPU relation
opens all 18 schedule-bound adjacent pairs. Memory-event, continuity, and log
sumchecks use transcript-bound projections containing only the main columns
they consume. The four ISA lanes are reduced by one Fiat-Shamir random linear
combination and share one table proof plus two trace openings; ISA, ROM,
fixed-clock, and projected composite checks open only the adjacent pairs they
consume. CPU execution uses 13 generic byte-level SM83 tables and at most two
queries per instruction. Their aligned 19-bit union is authenticated by one
Shout-style proof across all eight packed lookup slots, plus two selective
trace openings. High-level encoders and decoders reject v1; there is no legacy
receipt fallback.

Source-level accounting for one segment now schedules 37 main-trace
group-pair opening proofs instead of the former 270: 18 for the full CPU
relation, 15 across projected memory, continuity, logs, batched ISA, ROM, and
fixed clock checks, and four for the two execution-lookup trace openings. ISA
table proofs fall from four to one. The packed relation contains 11,458
identities. These are algorithmic operation counts; no proof timing is inferred
from them.

The former one-transition CPU, continuity, mutable-memory, and protocol-log
proof APIs and their wire layouts have been deleted. The one-transition trace
and relation remain only as a semantic reference used to construct and audit
the packed V2 instruction lanes; they cannot produce a receipt.

Execution and proof construction contain no cartridge-identity, ROM-root,
program-counter, bank, or instruction-byte-pattern fast path. Every cartridge
uses the same transition modes, lookup tables, and constraints. The proved
device projection contains CPU-observable Timer, PPU timing and interrupts,
DMA, serial, joypad, APU-register/Wave-RAM, and MMIO state; it does not prove a
framebuffer renderer or generated audio samples. Historical prefix proofs made
before this generic-relation cutover are incompatible with the current backend
identity and are not current performance evidence.
See [implementation status](docs/completion-report.md), the
[validation map](docs/validation.md), and the
[native milestone contract](docs/native-jolt-plan.md). The next optimization
work is specified in the [generic optimization plan](docs/optimization-plan.md),
with a reproducible [proof-free baseline](docs/proof-free-baseline.md).

## Workspace

| Crate | Responsibility |
| --- | --- |
| `zksm83-isa` | typed primary and CB opcode metadata |
| `zksm83-core` | deterministic machine state and the sole transition relation |
| `zksm83-memory` | ROM/RAM images and witness-side authentication |
| `zksm83-trace` | validated bounded witness construction |
| `zksm83-jolt` | native relation, Akita prover, receipt stream, and independent verifier |

## Verify a receipt

Verification requires the expected statement as a separate policy input:

```sh
cargo run --release -p zksm83-jolt --bin zksm83-native-verifier -- \
  /absolute/path/expected-statement.bin \
  /absolute/path/native-receipt.bin
```

The receipt's embedded statement is never sufficient authorization by itself.
The verifier decodes and drops one bounded segment at a time.

## Prove and resume

Long proofs use a length-delimited spool plus an atomic state/memory progress
checkpoint. Preflight validates file shapes, protocol bounds, input consumption,
and content identities without creating proof data:

```sh
cargo run --release -p zksm83-jolt --bin zksm83-native-prover -- \
  --rom /absolute/path/cartridge.gb \
  --input /absolute/path/input-schedule.json \
  --expected-checkpoint /absolute/path/expected-endpoint.json \
  --spool /absolute/path/native.spool \
  --progress-checkpoint /absolute/path/native.progress.json \
  --receipt /absolute/path/native.receipt.bin \
  --statement /absolute/path/native.statement.bin \
  --preflight-only
```

Replace `--preflight-only` with `--segment-limit 1` for a bounded first run.
Use the same arguments plus `--resume` to verify the durable prefix and
continue from its exact SM83 boundary. A partial spool is never published as
the declared final receipt. Finalization durably publishes or byte-checks the
statement first and publishes the receipt last as the completion marker, so a
crash cannot leave a declared receipt without its matching statement.

Use the same arguments plus `--inspect-progress-only` to verify an existing
progress/spool pair without opening either file for writing. This mode requires
the spool length to match the checkpoint exactly, verifies every persisted
proof frame, checks the final state and memory commitment, and prints stable
`zksm83-native-progress-evidence/v5` JSON. The progress-v5 checkpoint records
raw completed transitions separately from packed relation rows. Both counters
must equal the values recovered by verifying every persisted proof frame: a
fifth packed-continuity auxiliary column authenticates the number of source
SM83 transitions represented by each row. The checkpoint also binds the
receipt version, protocol ID, explicit proof-composition revision, complete
compiled backend digest, and both trace schedule digests. A relation, layout,
transcript, wire, or schedule change is therefore rejected before the spool is
decoded. Unknown checkpoint fields and counters outside the fixed segment,
row, transition-density, or spool-size bounds also fail before spool decoding.
There is no fallback reader for earlier progress schemas. Inspection never
truncates crash-tail bytes, continues execution, or creates a receipt or
statement.

Completed segment log lines separate process-local `setup`, `commit`,
`sumcheck`, `opening`, and `encode` wall times. The standalone verifier reports
its aggregate `verify_seconds`. These diagnostics are not receipt fields and do
not affect the protocol identity.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

Default tests are self-contained. Expensive cryptographic gates are ignored
and must be invoked explicitly. ROMs, saves, input schedules, checkpoints,
spools, receipts, statements, traces, benchmarks, and temporary proof data are
local-only; see [development.md](docs/development.md).

## Privacy boundary

The current protocol is transparent and is not witness-hiding. The project may
not claim zero knowledge until a separate hiding construction, leakage tests,
and security review exist.

Version 2 pair batching was selected by the isolated bounded gate documented in
[pcs-v2-evaluation.md](docs/pcs-v2-evaluation.md). The gate runs only through
the explicit `zksm83-pcs-batch-gate` binary and is absent from default tests.
Three- and four-group candidates exceeded the frozen memory-growth limit, so
v2 deliberately stops at two groups per opening.

## License

The workspace is licensed under [GPL-3.0-only](LICENSE).
