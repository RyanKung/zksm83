# Implementation status

This document separates source-backed capabilities from unfinished proof
claims. Generated receipts, traces, saves, and benchmarks are not versioned.

## Reference receipt

The `sm83-core-v1` path produces and independently verifies a Halo2 IPA receipt
for the deterministic program in `examples/demo.rom.hex`. The statement binds:

- VM version and machine profile;
- ROM, initial-memory, final-memory, private-input, and public-output roots;
- exact step and cycle counts; and
- a canonical receipt identifier.

The verifier reconstructs fixed parameters and receives neither an execution
witness nor a receipt-supplied verification key. Integration tests generate the
demo witness and proof at runtime, so no serialized proof fixture is required.
This reference profile intentionally excludes typed DMG/MBC3 device events.

## Native proof work

The source contains native trace construction, committed state continuity,
fixed-table ISA lookup, structural bus rows, and experimental ROM/RAM lookup
proofs. Unit and integration tests cover these components on synthetic programs.

Ignored integration tests can exercise a user-supplied Pokémon Blue cartridge.
They are local research runs, not default test dependencies and not evidence of
a complete device proof.

## Completion condition

The native target is complete only when one verifier path binds:

1. the exact initial and final public VM states;
2. every native state transition in every admitted step mode;
3. fixed-table ISA selection from authenticated opcode bytes;
4. ordered ROM and mutable-memory reads and writes;
5. bus, ISA, input, and output transcript boundaries;
6. every supported DMG/MBC3 device transition; and
7. every segment boundary across the claimed execution.

Trace construction, component proofs, ignored cartridge tests, and linear
performance estimates do not substitute for that proposition.
