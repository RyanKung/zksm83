# Pokémon Blue path contract

The optional cartridge tests target the exact USA/Europe SGB-enhanced Blue
image supplied outside the repository through `ZKSM83_BLUE_ROM`:

```text
size  1,048,576 bytes
SHA1  d7037c83e1ae5b39bde3c30787637ba1d4c48ce2
```

The image was reproduced byte-for-byte from pret/pokered commit
[`a1a22aaf`](https://github.com/pret/pokered/commit/a1a22aaf84d1675bcdbaeb194592379d586d838e)
with RGBDS 1.0.1. The resulting symbols are navigation aids only. They are not
trusted by the executor, proof relation, receipt, or verifier; those bind the
authenticated ROM bytes and mapper state.

## Path landmarks

| Bank:PC | Source landmark | Required evidence |
| --- | --- | --- |
| `00:0100` | cartridge entry | canonical DMG post-boot state and Blue ROM root |
| `1c:609b` | `CheckSGB` | neutral P1 samples; DMG result `wOnSGB = 0` |
| `1c:614a` | `Wait7000` | startup/SGB delay only; not a title milestone |
| `01:42dd` | `DisplayTitleScreen` | title construction has begun |
| `01:443b` | title input loop | first Start/A pulse may be scheduled here |
| `01:5af2` | `MainMenu` | menu reached |
| `01:5d52` | `StartNewGame` | new-game branch selected |
| `01:60ca` | `PrepareOakSpeech` | character-creation flow entered |
| `01:6596` | `DisplayNamingScreen` | committed naming inputs are being consumed |
| `1c:770a` | `SaveMenu` | in-game save flow entered |
| `1c:7848` | `SaveGameData` | SRAM-writing routine entered |

Relevant committed WRAM/HRAM observations include `wOnSGB = cf1b`,
`wSaveFileStatus = d088`, `wPlayerName = d158`, `wRivalName = d34a`,
`wPlayerID = d359`, `wCurMap = d35e`, `hJoyPressed = ffb3`, and
`hJoyHeld = ffb4`. These addresses can identify an exploration checkpoint, but
the accepted save milestones must additionally be demonstrated by
authenticated writes to physical SRAM `10000..17fff` and by an exported
32-KiB save whose commitment is linked to the final VM boundary.

## Input semantics

One private byte is consumed for every authenticated read of P1 (`ff00`). It is
a raw active-high two-line witness, not pokered's post-poll `hJoyInput` layout:
Right=`01`, Left=`02`, Up=`04`, Down=`08`, A=`10`, B=`20`, Select=`40`,
Start=`80`. `ReadJoypad` turns those physical groups into the game's conventional
Down..Right/Start..A byte. SGB detection also reads P1, so a button cannot be
queued merely "near startup": the consumed prefix and the exact title-loop
sample index must be fixed. Checkpoint resume recomputes that consumed input
prefix before accepting any continuation.

## Acceptance boundary

A complete path run must start from canonical DMG post-boot state, stop at a
declared occurrence of the target bank and PC, bind the exact consumed input
prefix, authenticate every physical battery-SRAM write, and link the exported
32-KiB save to the final committed memory state.

ROMs, input schedules, checkpoints, traces, and saves remain local. A result is
not reviewable unless it also records the source revision, command, cartridge
digest, public boundaries, and proof scope. A symbol hit, WRAM value, native
trace, ignored integration test, or host-emulator replay alone is not a
complete proof. See [completion-report.md](completion-report.md) for the
remaining proof obligations.
