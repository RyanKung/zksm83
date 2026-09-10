# Local artifacts

This directory is intentionally empty in version control except for this file.
Receipts, proofs, traces, checkpoints, saves, verification reports, profiles,
and benchmarks are generated data and are ignored by Git.

Use a fresh temporary directory for routine runs:

```sh
run_dir="$(mktemp -d)"
cargo run --release -p zksm83-cli -- prove \
  --rom examples/demo.rom.hex \
  --max-steps 20 \
  --receipt "$run_dir/demo.receipt.json"
```

An artifact is evidence only for the exact source revision, parameters, public
statement, and command that produced it. Do not commit user-supplied ROMs,
private input schedules, save data, or generated proof material here.
