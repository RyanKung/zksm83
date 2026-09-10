# Validation map

A blank evidence cell means the proposition is incomplete. Checked-in tests are
self-contained; generated artifacts and user-supplied cartridge data are not
part of the repository.

## Reference `sm83-core-v1` receipt

| Proposition | Evidence |
| --- | --- |
| All primary and CB bytes are classified | exhaustive `zksm83-isa` tests |
| Undefined opcodes fail closed | decoder and VM negative tests |
| Step execution is deterministic | `zksm83-core` transition tests |
| ROM and mutable-memory accesses are authenticated | memory and proof tamper tests |
| Input/output order and roots are bound | trace and receipt negative tests |
| Verifier receives no witness | `zksm83-receipt` integration tests |
| A nontrivial program proves and verifies | runtime-generated 11-byte demo fixture |

## Native DMG/MBC3 relation

| Proposition | Evidence |
| --- | --- |
| Fixed ISA alignment is PCS-bound | committed ISA lookup and segment tests |
| Complete state columns and adjacent rows are bound | shifted-trace and segment-chain tests |
| Bus rows use one canonical five-slot shape | structural relation tests |
| User-supplied Blue ROM can enter native component tests | ignored tests gated by `ZKSM83_BLUE_ROM` |
| Complete CPU/control semantics | |
| Bus address/value transcript is proved without explicit replay | |
| ROM lookup and mutable-memory proof share segment commitments | |
| MMIO, timer, PPU, DMA, joypad, and save transitions are complete | |
| A full Blue segment chain produces one accepted receipt | |

Any change to the relation, commitment scheme, transcript, machine model, or
segment granularity requires new measurements and proof artifacts.
