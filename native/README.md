# Native Layer

This directory holds the non-Rust execution layers for CrystalSentinel-CRA.

The Rust workspace remains the orchestration and policy plane. The native layer
exists for capabilities that eventually need lower-level execution,
deterministic memory layout, or extremely tight timing.

## Layer Responsibilities

- `c/`: resource guards, descriptor-safe compatibility shims, packet-adjacent
  system helpers, observation budgeting, fragility caps, and OS-facing primitives
- `cpp/`: richer attack-template models, stateful classifiers, scan-behavior
  prediction, and behavioral modeling support
- `asm/`: timing primitives, ultra-low-latency helpers, and future bounded
  direct-to-wire defensive interfaces
- `include/`: shared header contracts across native components

## Current Status

The external `native/` tree remains scaffolded for future out-of-process or
shared-library integration. The ASM decision path is already linked inside the
Rust bridge crate through inline assembly for cycle stamping and fast-path
pressure scoring.

That does not make the C and C++ layers optional. They are part of the layered
defense strategy:

- C is the right home for lower-level interface compatibility and packet-adjacent
  execution, resource budgeting, and fragile-asset caps.
- C++ is the right home for richer stateful models when the Rust control plane
  should stay simpler and safer, especially scan-path prediction and
  decoy-first posture recommendations.

Recent assessment work also adds a "zero-copy packet engine" direction for the
ASM layer. In the current repo that is treated as a bounded defensive design
goal for future work, not as live packet injection code.

## Native Contracts

The native header now exposes three defensive contracts:

- `sentinel_c_resource_guard`: low-level guardrail classification
- `sentinel_c_budget_window`: stability-first observation and decoy budgeting
- `sentinel_cpp_classify`: stateful recognition hints
- `sentinel_cpp_predict_scan_path`: scan-behavior prediction and posture advice

The current design split is intentional:

- Rust decides policy and final action.
- C caps what is safe for the host and the network.
- C++ predicts what kind of hostile behavior is unfolding and whether decoy-first
  Phantom capture is worthwhile.
- ASM provides the lowest-latency pressure path.

## Build Direction

When native compilation is enabled, use:

```powershell
cmake -S native -B native/build
cmake --build native/build
```

ASM support is intentionally opt-in in the initial scaffold.
