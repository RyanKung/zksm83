# zksm83

`zksm83` is a native SM83 zkVM research workspace. It models an SM83 CPU over
immutable ROM, authenticated mutable memory, and committed input/output logs.

The workspace currently has two proof layers:

- `zksm83-proof` and `zksm83-receipt` provide a small Halo2 IPA reference
  receipt for the `sm83-core-v1` profile.
- `zksm83-audit` contains the native multilinear relation, sumcheck, fixed ISA
  lookup, and ROM/RAM lookup experiments.

The native layer is incomplete. It does not yet provide one independently
verifiable receipt covering the complete DMG/MBC3 device relation or a full
Pokémon Blue execution. See [the implementation status](docs/completion-report.md)
and [validation map](docs/validation.md) for the exact boundary.

## Workspace

| Crate | Responsibility |
| --- | --- |
| `zksm83-isa` | typed primary and CB opcode metadata |
| `zksm83-core` | deterministic machine state and transition relation |
| `zksm83-memory` | ROM/RAM images, commitments, and transcripts |
| `zksm83-trace` | validated witness and lookup-trace construction |
| `zksm83-proof` | Halo2 reference circuit and proof backend |
| `zksm83-receipt` | canonical statement, receipt, and verifier API |
| `zksm83-audit` | native sumcheck and lookup proof experiments |
| `zksm83-cli` | filesystem and command-line boundary |

## Reference demo

The checked-in demo is an 11-byte hand-authored SM83 program. It writes and
reads authenticated RAM, emits one public byte, and halts. Generated outputs go
to a temporary directory and are never required as test fixtures:

```sh
run_dir="$(mktemp -d)"
cargo run --release -p zksm83-cli -- prove \
  --rom examples/demo.rom.hex \
  --max-steps 20 \
  --receipt "$run_dir/demo.receipt.json"
cargo run --release -p zksm83-cli -- verify \
  --receipt "$run_dir/demo.receipt.json" \
  --output "$run_dir/demo.verification.json"
cargo run --release -p zksm83-cli -- bench \
  --rom examples/demo.rom.hex \
  --max-steps 20 \
  --output "$run_dir/demo.benchmark.json"
```

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

The default suite is self-contained. Costly cartridge integration tests are
ignored and require a user-supplied ROM outside the repository. The complete
receipt tamper suite is also an explicit slow gate because it constructs and
verifies a real proof. Repository and local-data policy is documented in
[development.md](docs/development.md).

## License

The workspace is licensed under [GPL-3.0-only](LICENSE).
