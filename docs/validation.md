# Validation map

A blank evidence cell means the proposition is incomplete. Checked-in tests are
self-contained; generated artifacts and user-supplied cartridge data are not
part of the repository.

## Native DMG/MBC3 receipt

The frozen public proposition and milestone exits are specified in
[native-jolt-plan.md](native-jolt-plan.md). The Akita baseline below is only a
PCS integration gate.

| Proposition | Evidence |
| --- | --- |
| The workspace has one native proof pipeline | workspace manifest and dependency-tree audit contain no Halo2, Pasta, RV64/RISC-V guest, Jolt SDK, Dory, or BN254 route |
| Current privacy mode is explicit | backend identity fixes transparent mode; unit test rejects RV64 and witness-hiding identities |
| Pinned Akita commits, opens, serializes, and verifies | ignored release gate in `zksm83-jolt` |
| Backend identity excludes RV64 and witness hiding | `zksm83-jolt` unit test |
| Embedded schedule matches its admitted digest | `zksm83-jolt` unit test |
| Fixed 512-row ISA table is canonical and exhaustive | `zksm83-jolt` ISA digest and coverage tests |
| Uniform claims share one fixed-width witness commitment plane | ignored Akita substitution, sumcheck-tamper, and group-reordering release gates |
| Fixed ISA table/output lookup terminals use shared Akita commitments | ignored native-field Shout release gate with tamper and layout-reorder rejection |
| Fixed ISA alignment and fetched opcode bytes are PCS-bound | shared CPU/ISA release gate plus fetch-byte and commitment-substitution negative tests |
| Complete state columns and adjacent rows are bound | public initial/final semantic limbs, active-row count, row-tagged inverse relation, discontinuity/wrong-boundary/wrong-count tests, and the complete native receipt release gate |
| Bus rows use one canonical five-slot shape | structural relation tests |
| Ordinary instruction families have row-local CPU identities | arithmetic, control, load, word, stack, DAA, CB, and interrupt relation tests; memory and devices are composed by their dedicated relations |
| Blue summary CPU deltas and bus patterns are row-local identities | sound zero/nonzero, delay complete/interruptible, DMA HRAM-code, summary-aux tamper, HALT-bug reset, complete device guards, and pinned Blue ROM witness-auth root |
| Dynamic one-MiB ROM reads are authenticated without query replay | dedicated `nv20/p1` schedule test, ROM Shout release gate, and combined ROM-commitment substitution gate |
| MBC3 bank mapping and control updates are row-local identities | bank-zero remap, banked-fetch, RAM-enable, RAM/RTC-select, and physical-address tamper tests |
| Mutable reads observe the latest ordered value and writes update one mapped byte | dedicated `nv17/p1` schedule, fixed row-clock opening, strict predecessor/delta constraints, two-limb inverse relations, log-derivative multiset proof, and final-commitment substitution release gate |
| User-supplied Blue ROM can enter native component tests | ignored tests gated by `ZKSM83_BLUE_ROM` |
| Complete CPU/control semantics | exhaustive positive/negative instruction-family fixtures, machine-step fixtures, 6,144-slot row relation, degree-18 algebraic-bound regression, complete native receipt release gate, and one real 16,384-row Blue segment proof |
| Ordered bus/ISA/input/output cursors are row-local identities | cursor-delta, event-index, canonical-port, index-tamper tests, and four committed segment log tables with exact public-boundary deltas |
| Bus address/value transcript is proved without explicit replay | all canonical tuple fields plus global ordinal are committed and matched to the shared trace by a log-derivative proof; wrong table commitment is rejected |
| ROM lookup, mutable memory, continuity, and protocol logs share segment commitments | `NativeMemoryCpuProof` verifies all claims against one trace commitment plane and expected external boundary/log/memory/ROM commitments |
| Interrupt priority, HALT selection, and serialized DMA copy are row-local identities | IF/IE range, priority-tamper, HALT-bug entry, FF46 startup, capacity/debt scheduling, HRAM-only CPU access during DMA, and copy-tamper tests |
| Joypad samples, FF00 writes, and IF falling edges are row-local identities | active-low sample, pack/value tamper, falling-interrupt, and same-row read-modify-write tests |
| Timer and PPU register visibility is row-local | low/high device-pack decomposition, timer/LY/dot ranges, phase-five and PPU predicate tamper tests, and DIV/TIMA/TAC/STAT/LY read fixture |
| Static MMIO and APU write-after state is row-local | TMA/TAC/LCD/scroll/palette/window updates; APU power-off clearing, off-state length write, NR52 power/status, DAC/trigger, wave-RAM preservation, and tamper tests |
| APU register visibility is row-local | five-pack decomposition, stored-mask rejection, exact FF10-FF26 values, fixed FF27-FF2F unused reads, and FF30-FF3F wave RAM fixture |
| Serial timing and completion are row-local | FF01/FF02 post-write state, 4096-tick start, exact cycle decrement, bounded completion threshold, completion data/control writeback, IF bit-three update, and early-completion/gap tamper tests |
| Timer writes, ticks, reload, and interrupt are row-local | FF04-FF07 post-write state, six-cycle selector, 24 exact T-cycle stages, divider wrap, detector falling edge, TIMA overflow phases, TMA reload, IF bit-two update, and long-step quiet quotient |
| LCD position, frame wrap, VBlank crossing, and interrupts are row-local | compressed post-row LY/dot, FF40 disable reset, bounded frame quotient, exact next-crossing comparison, IF bit-zero update, composite STAT mode/LYC rising edges, IF bit-one update, no-repeat-high behavior, and event/quotient tamper tests |
| CPU VRAM and OAM access follows LCD mode | mode-three VRAM block, mode-two/mode-three OAM block, exact OAM-range witness, positive unblocked CPU OAM fixture, and DMA-device OAM exemption |
| Specialized long steps carry all modeled device guards | LCD/VBlank-IE/Joypad-IE guard and exact next crossing for long HALT; timer, serial, STAT, and DMA quiet conditions for all applicable Blue summaries |
| Current no-RTC DMG device and save-state transitions are complete | M5j 3,292-column composite proof, 60-test M5 fast gate, interrupt/MMIO/APU/timer/serial/PPU/joypad/DMA negative fixtures, four-bank SRAM mapping, and exact initial/final 128-KiB memory commitments |
| Segment continuity and four protocol logs are commitment-bound | M6 row-tagged initial/adjacent/final multiset relation; deterministic bus/input/output/ISA tables; joypad raw-sample fixture; `nv17/p128` schedule digest; wrong-commitment rejection; complete single-segment native receipt release gate |
| A versioned native receipt round-trips and verifies without witness or emulator | bounded canonical wire format, typed ROM/memory/log identities, exact expected-statement equality, standalone verifier binary, and real proof/proof-byte/trailing-byte/segment-shape rejection gate |
| A valid multi-segment synthetic receipt verifies | current degree-18 streamed pair, named large-stack proof pool, exact semantic/memory/log boundary chaining, incremental and parsed verification, and broken-link/reordering rejection release gate |
| Receipt memory is bounded across a long segment chain | length-delimited statement/ROM/segment frames, one-frame-at-a-time verifier, seekable prover spool, atomic state/memory progress checkpoint, canonical commitment-identity recovery, read-only exact-length progress inspection with stable evidence JSON, and verified four-segment native-only Blue resume |
| The declared Blue endpoint and local inputs are pinned before proving | release preflight validates shapes and bounds, computes the current SHA-256 witness-auth roots, and pins 9,994,417 rows, 611 segments, 62,685 consumed input bytes, and content identities for ROM, expanded input, and endpoint checkpoint |
| Adjacent real Blue segments satisfy the complete native proof relation | revision `2b342e7` produced four adjacent 16,384-row segments and fresh-process resume reverified the 75,559,650-byte spool plus exact state/memory checkpoint; the operator deferred the remaining 607 segments |
| A full Blue segment chain produces one accepted receipt | |

Any change to the relation, commitment scheme, transcript, machine model, or
segment granularity requires new measurements and proof artifacts.
