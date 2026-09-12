# zksm83

`zksm83` is a native SM83 proof-system research workspace. It executes the
SM83 transition relation directly; no RV64 guest, compiler, or emulator replay
exists in the proving or verification path.

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

The complete 611-segment Pokémon Blue receipt is still unfinished. Synthetic
single- and two-segment receipt gates have passed. A fresh native-only run from
the frozen `2b342e7` revision produced and recovery-verified four adjacent real
Blue segments before the operator deliberately stopped the long proof run.
That prefix is bounded recovery evidence, not a complete-path receipt.
See [implementation status](docs/completion-report.md), the
[validation map](docs/validation.md), and the
[native milestone contract](docs/native-jolt-plan.md).

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
the declared final receipt.

Use the same arguments plus `--inspect-progress-only` to verify an existing
progress/spool pair without opening either file for writing. This mode requires
the spool length to match the checkpoint exactly, verifies every persisted
proof frame, checks the final state and memory commitment, and prints stable
`zksm83-native-progress-evidence/v1` JSON. It never truncates crash-tail bytes,
continues execution, or creates a receipt or statement.

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

## License

The workspace is licensed under [GPL-3.0-only](LICENSE).
