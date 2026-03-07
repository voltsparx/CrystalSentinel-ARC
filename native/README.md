# Native Layer

This directory holds the non-Rust execution layers for CrystalSentinel-CRA.

The Rust workspace remains the orchestration and policy plane. The native layer
exists for capabilities that eventually need lower-level execution,
deterministic memory layout, or extremely tight timing.

## Layer Responsibilities

- `c/`: resource guards, packet-adjacent system helpers, OS-facing primitives
- `cpp/`: richer attack-template models and stateful classifiers
- `asm/`: timing primitives and ultra-low-latency helpers
- `include/`: shared header contracts across native components

## Current Status

The external `native/` tree remains scaffolded for future out-of-process or
shared-library integration. The ASM decision path is already linked inside the
Rust bridge crate through inline assembly for cycle stamping and fast-path
pressure scoring.

## Build Direction

When native compilation is enabled, use:

```powershell
cmake -S native -B native/build
cmake --build native/build
```

ASM support is intentionally opt-in in the initial scaffold.
