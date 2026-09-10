# zksm83-core v1 model

This file specifies the backend-independent `sm83-core-v1` machine boundary.
The Halo2 implementation is the current reference witness for this profile.

## Status

This document fixes the first complete proof boundary before implementation.
It is normative for the `sm83-core-v1` machine profile. Any implementation
shortcut that widens trust beyond this boundary is a model violation.

## Mathematical objects

Let `B = {0, ..., 255}` and `A = {0, ..., 65535}`. A CPU state is:

```text
C = (A, B, C, D, E, H, L, F, PC, SP, IME, run_state, m_cycles)
```

where the eight registers and `F` are bytes, `PC` and `SP` are 16-bit words,
`IME` is `Disabled | EnablePending | Enabled`, `run_state` is
`Running | Halted | Stopped`, and `m_cycles` is a checked 64-bit counter. The
low nibble of `F` is always zero. The upper bits are `(Z, N, H, C)`.

A VM state is:

```text
V = (C, mutable_memory_root, input_cursor, input_accumulator,
     output_accumulator)
```

The transition is a pure partial function:

```text
step : V × InputEvent -> Result<(V, StepEffects), StepError>
```

The function reads only values and authentication paths supplied in its typed
input. It has no filesystem, clock, random, process, emulator, or ambient-device
access.

## Machine profile

`sm83-core-v1` owns the 16-bit address bus as follows:

| Range | Owner | Rule |
| --- | --- | --- |
| `0x0000..=0x7fff` | ROM | Immutable authenticated reads; writes fail |
| `0x8000..=0xffef` | RAM | Authenticated latest-value reads and root-changing writes |
| `0xfff0` | input port | Reads consume the next committed input byte; writes fail |
| `0xfff1` | output port | Writes append a committed output byte; reads fail |
| `0xfff2..=0xffff` | unowned | Every access fails |

The ROM commitment accepts and binds up to 1 MiB. Authentication paths have
depth 20. The Halo2 reference authenticates only the direct CPU-addressed
window and rejects MBC3 control/open-bus events during shape construction. The
broader native DMG/MBC3 trace has logical-to-physical address resolution and
mapper continuity, but its complete proof relation remains under
implementation. MBC5 remains unsupported.

The initial CPU state is part of validated witness construction and is fixed by
the profile in v1: zeroed 8-bit registers, `PC = 0`, `SP = 0xff00`, disabled
IME, running state, and zero M-cycles. No interrupt source exists in v1.
Consequently, `EI`, `DI`, `RETI`, `HALT`, and `STOP` still have explicit state
semantics, but interrupt dispatch and the DMG HALT bug are outside this profile.
`HALT` and `STOP` are terminal unless a later profile declares an authenticated
wake event.

## ISA relation

Every primary byte maps to exactly one of:

```text
Defined(DecodedInstruction)
Undefined(UndefinedOpcode)
```

The eleven undefined primary bytes are:

```text
d3 db dd e3 e4 eb ec ed f4 fc fd
```

All 256 CB bytes are defined. Every defined instruction records encoded length,
base and taken M-cycles, register reads, register writes, flag effects, bus
access pattern, and semantic operation. Decoding may use the standard SM83
`x/y/z/p/q` decomposition, but execution dispatches only on the typed semantic
operation. Undefined encodings have no transition.

The instruction relation enforces:

```text
R_isa(before, fetched bytes, bus events, after, timing)
```

It constrains every register and state component. A component not named as an
instruction output equals its input value. This frame condition prevents hidden
mutation.

## Bus transcript

Each instruction produces an ordered, bounded sequence of typed events:

```text
OpcodeFetch(address, value, rom_path)
ImmediateRead(address, value, rom_path)
RomRead(address, value, rom_path)
MemoryRead(address, value, path)
MemoryWrite(address, before, after, path)
InputRead(address = 0xfff0, index, value)
OutputWrite(address = 0xfff1, index, value)
```

Opcode and immediate bytes are ROM reads and are authenticated identically.
The event order is part of the proof witness and is constrained by instruction
semantics. No generic MMIO fallback exists.

## Commitments

ROM and mutable memory are depth-20 binary Merkle trees over the Pasta base
field. A leaf commits to `(domain, byte, zero)` and its address is bound by its
unique position in the depth-20 path. Each internal node commits to
`(domain, level, left, right)` using the field-native permutation implemented in
`zksm83-memory`. Domain separation distinguishes ROM, mutable memory, input,
output, leaves, nodes, and transcript elements.

For an authenticated read, the circuit recomputes the root from the supplied
leaf and path and constrains it to the current root. For a mutable write, it
recomputes both the before-root and after-root with the same address/path, then
threads the after-root into the next event. This makes latest-write consistency
the induction invariant:

```text
Base: root_0 = initial_memory_root
Step: read preserves root_i; write proves root_i -> root_(i+1)
Post: root_n = final_memory_root
```

Input and output logs use ordered field-native accumulators that bind the event
index and byte. `input_root` commits the complete declared input log. A proof
fails if execution consumes beyond it or leaves a profile-required input byte
unaccounted for. `public_output_root` commits the ordered produced output log.

The field permutation constants and round schedule are protocol constants. A
change increments `vm_version` and invalidates old receipts.

## Trace

A `TraceRow` contains the before/after CPU states, decoded instruction, ordered
bus events, memory-root endpoints, and input/output accumulator endpoints for
one instruction. A `TraceChunk` is non-empty and contiguous:

```text
row[i].after_cpu = row[i + 1].before_cpu
row[i].after_memory_root = row[i + 1].before_memory_root
row[i].after_input = row[i + 1].before_input
row[i].after_output = row[i + 1].before_output
```

`Witness` construction validates each row with the pure relation before the
proof backend receives it. Native validation is a prover safety check only. The
Halo2 constraints independently enforce the same propositions; the verifier
does not trust native validation.

## Public statement

The canonical public statement is:

```text
vm_version
machine_profile
rom_root
initial_memory_root
final_memory_root
input_root
cycle_count_or_step_bound
public_output_root
receipt_id
```

`vm_version` is `zksm83-core/1`. `machine_profile` is `sm83-core-v1`.
The implementation spells `cycle_count_or_step_bound` as two fields:
`step_count` and `cycle_count`. Both are exact; neither is merely a prover hint.

The circuit exposes thirteen Pasta-field instances in this fixed order:

```text
0 vm_version                 7 cycle_count
1 machine_profile           8 public_output_root
2 rom_root                  9 receipt_id limb 0 (little-endian u64)
3 initial_memory_root      10 receipt_id limb 1
4 final_memory_root        11 receipt_id limb 2
5 input_root               12 receipt_id limb 3
6 step_count
```

`receipt_id` is deterministic SHA-256 over a domain tag and the canonical public
statement fields excluding `receipt_id`. SHA-256 identifies the receipt; it does
not replace any in-circuit commitment or relation.

## Receipt and proof

The proof is a Halo2 IPA proof over Pasta curves. Polynomial commitment
parameters are deterministically derived for the circuit size. The verification
key is derived by the verifier from the compiled circuit shape and VM version,
never accepted from the receipt. Public instances bind every statement field.

The receipt contains the public statement, proof scheme and circuit exponent,
the public circuit specialization, and proof bytes. The specialization reveals
the instruction sequence, branch choices, and bus-event kinds, but not register
values, bus values, Merkle paths, input bytes, or memory contents. It is
validated canonically and determines the verification key. The verifier returns
`VerifiedReceipt` or a typed
`ReceiptVerificationError`. It verifies canonical encoding, deterministic ID,
supported version/profile/circuit, public-instance mapping, and the proof.

## Trust boundary and non-claims

The verifier trusts the implemented Halo2/curve/hash dependencies and the
compiled `zksm83-core` verifier. It does not trust the prover, trace, native
executor, filesystem, ROM loader, benchmark harness, or `backup/`.

This profile does not prove PPU, APU, LCD, audio, GBC hardware, Pokémon state,
save provenance, recursion, chain deployment, or real-time performance.

Benchmark resident-memory fields are point-in-time RSS samples collected after
trace construction, proof construction, and verification. They are not peak
memory measurements.
