# Validation map

A blank evidence cell means the proposition is incomplete. Checked-in tests are
self-contained; generated artifacts and user-supplied cartridge data are not
part of the repository.

## Native DMG/MBC3 receipt

The public proposition and milestone exits are specified in
[native-jolt-plan.md](native-jolt-plan.md). The Akita baseline is only a PCS
integration gate.

| Proposition | Evidence |
| --- | --- |
| The workspace has one native proof pipeline | workspace manifest and dependency-tree audit contain no Halo2, Pasta, RV64/RISC-V guest, Jolt SDK, Dory, or BN254 route |
| Current privacy mode is explicit | backend identity fixes transparent mode; unit tests reject RV64 and witness-hiding identities |
| Native receipt v2 pair layout is frozen | checked-in pair schedule, compiled 4,505-to-4,608 padding geometry, 36-to-18 layout invariant, and bounded PCS gate |
| Fixed ISA table is canonical and exhaustive | ISA digest, coverage, undefined-opcode, and fetch-binding tests |
| Complete state columns, adjacent rows, and packed source-transition count are bound | initial/final limbs, active-row prefix, row-tagged continuity relation, constrained lane-count auxiliary sum, and negative boundary/count tests |
| Every ROM uses the same transition modes | production search contains no ROM digest, title, fixed PC/bank, expected byte sequence, or cartridge-named `StepKind`; generic mode and trace tests |
| CPU/control semantics are row-local | four compact instruction lanes reuse arithmetic, control, load, word, stack, DAA, CB, and MBC3 constraints; five shared boundary ranges remove duplicated endpoint columns/checks and six scalar helpers per lane derive from committed bits; shared machine rows cover HALT, interrupt, devices, and DMA; packed relation declares 13,004 slots |
| Dynamic one-MiB ROM reads are authenticated | dedicated ROM schedule, Shout lookup gate, physical-address constraints, and commitment-substitution rejection |
| Mutable reads and writes are ordered | fixed clocks, predecessor constraints, log-derivative relation, and final-commitment substitution rejection |
| MBC3 mapping and control are constrained | bank-zero remap, banked fetch, RAM enable/select, no-RTC policy, and four-bank SRAM tests |
| Device semantics are row-local | interrupt, joypad, timer, PPU/STAT, serial, APU, MMIO, DMA, and access-control positive/negative fixtures |
| Generic long HALT is guarded | VBlank, serial-completion, and timer-interrupt selectors derive from hardware state; interrupt masks, LCD, timer, serial, STAT, DMA, exact-boundary, and quotient guards have positive/negative fixtures |
| Segment continuity and ordered logs are commitment-bound | row-tagged continuity, authenticated source-transition and packed-row totals, deterministic bus/input/output/ISA tables, and exact cursor deltas |
| Receipt encoding is bounded and fail-closed | exact external statement, typed identities, v2-only wire decoder, streaming verifier, mutation/truncation/noise/hostile-length tests |
| A current small v2 proof verifies | |
| Diverse cartridge workloads match single-step semantics | |
| A declared cartridge-scale segment chain verifies | |

Any relation, layout, commitment, transcript, machine-model, or segment-size
change invalidates earlier proof and performance evidence until remeasured.
