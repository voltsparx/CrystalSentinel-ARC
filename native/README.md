# Native Layer

This directory holds the non-Rust execution layers for CrystalSentinel-ARC.

The Rust workspace remains the orchestration and policy plane. The native layer
exists for capabilities that eventually need lower-level execution,
deterministic memory layout, or extremely tight timing.

## Layer Responsibilities

- `c/`: resource guards, descriptor-safe compatibility shims, packet-adjacent
  system helpers, observation budgeting, protocol/mesh safety caps, fragility
  caps, exposure reduction, dynamic load balancing, heartbeat auditing, and
  OS-facing primitives
- `cpp/`: richer attack-template models, stateful classifiers, scan-behavior
  prediction, behavior matrices, recovery prediction, ambient-state support,
  and guardian-facing voice translation for operator-safe telemetry summaries
- `asm/`: timing primitives, weighted pressure kernels, ultra-low-latency
  directive helpers, load-balance intensity kernels, heartbeat trust modes, and
  future bounded direct-to-wire defensive interfaces
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

The native header now exposes the current defensive contract surface:

- `sentinel_c_resource_guard`: low-level guardrail classification
- `sentinel_c_budget_window`: stability-first observation and decoy budgeting
- `sentinel_c_exposure_guard`: low-resource exposure reduction and zen fallback guidance
- `sentinel_c_protocol_budget`: protocol-aware observation and decoy caps
- `sentinel_c_mesh_guard`: multi-node and gentle-device action caps
- `sentinel_c_dynamic_load_balancer`: background decoy recoil and micro-pacing guidance
- `sentinel_c_mesh_heartbeat_audit`: trusted, missing, drift, and compromised peer state
- `sentinel_cpp_classify`: stateful recognition hints
- `sentinel_cpp_predict_scan_path`: scan-behavior prediction and posture advice
- `sentinel_cpp_ambient_state`: ambient pressure modeling and zen-recovery recommendations
- `sentinel_cpp_behavior_matrix`: next-move prediction and evidence-goal advice
- `sentinel_cpp_recovery_predictor`: quiet-recovery and exposure-reduction advice
- `sentinel_cpp_guardian_report`: calm operator-facing status and threat phrasing
- `sentinel_asm_weighted_mix`: tiny weighted pressure kernel
- `sentinel_asm_weighted_mix4`: four-lane weighted pressure kernel
- `sentinel_asm_pressure_mode`: low-latency mode selection for standby, decoy capture, containment guard, or zen recovery
- `sentinel_asm_observation_window`: low-latency observation window sizing
- `sentinel_asm_decoy_budget`: low-latency decoy budget capping
- `sentinel_asm_evidence_budget`: low-latency evidence-ladder sizing
- `sentinel_asm_phantom_jitter`: bounded Phantom jitter guidance
- `sentinel_asm_guard_bias`: fast-path authority weighting for runtime lane rebalance
- `sentinel_asm_load_balance_intensity`: low-latency background work recoil guidance
- `sentinel_asm_micro_pacing_gap`: low-latency fragile-device pacing gap sizing
- `sentinel_asm_heartbeat_guard_mode`: low-latency heartbeat trust posture selection

The current design split is intentional:

- Rust decides policy and final action.
- C caps what is safe for the host and the network.
- C can also reduce exposure and pause non-essential decoy work when the
  defended host is too stressed to keep spending resources.
- C++ predicts what kind of hostile behavior is unfolding and whether decoy-first
  Phantom capture is worthwhile.
- C++ also models ambient pressure so the runtime can separate decoy capture,
  containment-guard behavior, and quiet recovery.
- ASM provides the lowest-latency pressure path and can push the runtime toward
  fast decoy capture or zen recovery before slower layers fully react.

## Build Direction

When native compilation is enabled, use:

```powershell
cmake -S native -B native/build
cmake --build native/build
ctest --test-dir native/build --output-on-failure
```

ASM support is intentionally opt-in in the initial scaffold.
