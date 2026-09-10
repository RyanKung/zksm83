# Development and data policy

## Versioned inputs

The repository tracks Rust source, manifests, documentation, and the small
hand-authored `examples/demo.rom.hex` program. Default tests must run from a
fresh clone without downloading or locating cartridge images, saves,
checkpoints, traces, receipts, or benchmark output.

## Local-only data

Git ignores the following classes deliberately:

- `roms/`, `*.gb`, `*.gbc`, `*.rom`: user-supplied cartridge images;
- `*.sav`, `*.srm`: save data;
- `examples/blue-*`: long-running private input schedules;
- `artifacts/`: generated receipts, proofs, traces, checkpoints, and reports;
- `backup/`: historical implementation material;
- `jolt-zksm83/`: local backend experiments not integrated into the workspace;
- `tmp/`, `target/`, coverage output, editor state, and local environment files.

Do not weaken these rules by force-adding generated or third-party data. If a
small deterministic fixture becomes necessary, generate it in the test or put
it under a crate-local `tests/fixtures/` directory with its origin and license
documented.

## Optional cartridge tests

The costly Blue tests are ignored by default. Supply an absolute path through
the environment instead of copying a ROM into the repository:

```sh
ZKSM83_BLUE_ROM=/absolute/path/to/pokemon-blue.gb \
  cargo test -p zksm83-audit blue_ -- --ignored --test-threads=1
```

The caller is responsible for providing a lawful image matching the cartridge
contract in [blue-path.md](blue-path.md).

## Slow receipt gate

The receipt integration suite constructs one real Halo2 proof and checks every
tamper case against it. It is self-contained but intentionally excluded from
the default test command because its CPU and memory cost is substantial:

```sh
cargo test --release -p zksm83-receipt --test receipt -- --ignored
```

## Generated output

Prefer a fresh temporary directory for manual proofs and measurements. Record
the source revision, complete command, toolchain, parameters, and public
statement whenever a result is used as evidence. Generated output remains
local unless a later review explicitly approves a bounded, reproducible
artifact for version control.
