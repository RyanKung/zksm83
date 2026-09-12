# Local artifacts

This directory is intentionally empty in version control except for this file.
Receipts, proofs, traces, checkpoints, saves, verification reports, profiles,
and benchmarks are generated data and are ignored by Git.

Use a fresh temporary directory for routine runs:

```sh
run_dir="$(mktemp -d)"
cargo run --release -p zksm83-jolt --bin zksm83-native-prover -- \
  --rom /absolute/path/cartridge.gb \
  --input /absolute/path/input.json \
  --expected-checkpoint /absolute/path/endpoint.json \
  --spool "$run_dir/native.spool" \
  --progress-checkpoint "$run_dir/native.progress.json" \
  --receipt "$run_dir/native.receipt.bin" \
  --statement "$run_dir/native.statement.bin" \
  --preflight-only
```

An artifact is evidence only for the exact source revision, parameters, public
statement, and command that produced it. Do not commit user-supplied ROMs,
private input schedules, save data, or generated proof material here.
