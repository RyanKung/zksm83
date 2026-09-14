# zksm83-cuda

Experimental CUDA primitives for the native SM83 prover.

This crate currently implements one device operation: binary folding over
Akita's `Prime128OffsetA7F7` base field. `zksm83-jolt` routes the native backend
selection across witness construction, relation evaluation, field folding,
Akita commitment/opening, canonical encoding, and receipt verification. Field
folding dispatches to this CUDA kernel when `--proof-backend cuda` is selected.
The other phases run through the same backend boundary with byte-equivalent CPU
implementations until dedicated CUDA or Akita GPU kernels land. The transcript,
proof format, receipt format, and backend digest remain unchanged.

The cuda-oxide revision is pinned for compiler reproducibility. The GPU target
is not pinned: `cargo oxide run` may detect the selected device, while `--arch`
or `CUDA_OXIDE_TARGET` may select an explicit deployment target. The runtime
also reads and validates the selected device's actual compute capability.

The portable field kernel accepts `sm_70` and newer devices. `sm_70` is an
experimental cuda-oxide path, not the globally fixed compilation target.

cuda-oxide currently requires `nightly-2026-08-28`. Invoke that toolchain
explicitly so the workspace can keep its normal stable `1.95` pin. On a Linux
CUDA host, run the differential smoke test without an architecture argument to
let `cargo oxide run` detect CUDA device 0:

```text
cargo +nightly-2026-08-28 install \
  --git https://github.com/NVlabs/cuda-oxide.git cargo-oxide
```

```text
cd crates/zksm83-cuda
cargo +nightly-2026-08-28 oxide run --features cuda --bin zksm83-cuda-fold-smoke
```

The optional native-prover integration is run from its package directory:

```text
cd crates/zksm83-jolt
cargo +nightly-2026-08-28 oxide run --features cuda \
  --bin zksm83-native-prover -- \
  <normal prover arguments> --proof-backend cuda --cuda-device 0
```

The standalone verifier accepts the same backend selection:

```text
cargo +nightly-2026-08-28 oxide run --features cuda \
  --bin zksm83-native-verifier -- \
  --proof-backend cuda --cuda-device 0 <statement.bin> <receipt.bin>
```

An explicit target remains available for cross-compilation and repeatable CI:

```text
cargo +nightly-2026-08-28 oxide build --features cuda --arch <detected-sm-version>
```

Normal workspace builds do not enable CUDA and remain compatible with the
repository's stable Rust toolchain and macOS development host.
