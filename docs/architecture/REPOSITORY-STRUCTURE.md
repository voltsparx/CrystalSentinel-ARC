# CrystalSentinel-CRA Repository Structure

This repository is organized as a product monorepo. The goal is to keep runtime
applications, reusable detection logic, content, operations, and research
artifacts separate so the project scales without collapsing into one large
binary or one unreadable folder.

## Structure Principles

- Keep binaries in `apps/` and shared Rust code in `crates/`.
- Keep detection content in `rules/` so policies and signatures can evolve
  without being buried in application code.
- Keep operational material in `configs/`, `deploy/`, `observability/`, and
  `security/`.
- Keep replay, regression, and benchmark assets outside source code in
  `testdata/` and `tests/`.
- Keep design notes and scenario definitions under `docs/` while preserving the
  current concept material in `self-assessments/`.

## Top-Level Layout

```text
.
|-- .github/
|   `-- workflows/
|-- apps/
|   |-- sentineld/
|   |-- sentinelctl/
|   `-- sentinel-console-api/
|-- crates/
|   |-- sentinel-common/
|   |-- sentinel-config/
|   |-- sentinel-telemetry/
|   |-- sentinel-flow/
|   |-- sentinel-detection/
|   |-- sentinel-decoy/
|   |-- sentinel-education/
|   |-- sentinel-integrity/
|   |-- sentinel-native-bridge/
|   |-- sentinel-correlation/
|   |-- sentinel-reporting/
|   |-- sentinel-runtime/
|   |-- sentinel-shadow-vault/
|   |-- sentinel-policy/
|   |-- sentinel-response/
|   |-- sentinel-forensics/
|   |-- sentinel-storage/
|   |-- sentinel-bio-response/
|   `-- sentinel-scenario/
|-- native/
|   |-- include/
|   |-- c/
|   |   `-- src/
|   |-- cpp/
|   |   `-- src/
|   `-- asm/
|       `-- src/
|-- configs/
|   |-- base/
|   |-- environments/
|   |   |-- dev/
|   |   |-- stage/
|   |   `-- prod/
|   |-- sensors/
|   `-- response/
|-- deploy/
|   |-- docker/
|   |-- kubernetes/
|   |   `-- base/
|   |-- systemd/
|   `-- windows-service/
|-- docs/
|   |-- adr/
|   |-- api/
|   |-- architecture/
|   |-- compliance/
|   |-- implementation/
|   |-- operations/
|   |-- research/
|   |-- scenarios/
|   `-- threat-models/
|-- observability/
|   |-- alerts/
|   |-- dashboards/
|   `-- otel/
|-- rules/
|   |-- allowlists/
|   |-- anomaly/
|   |-- baselines/
|   |-- heuristics/
|   |-- response-policies/
|   `-- signatures/
|-- schemas/
|   |-- alerts/
|   |-- events/
|   `-- scenarios/
|-- scripts/
|   |-- bootstrap/
|   |-- ci/
|   |-- dev/
|   `-- ops/
|-- security/
|   |-- hardening/
|   |-- supply-chain/
|   `-- threat-model/
|-- self-assessments/
|-- testdata/
|   |-- baselines/
|   |-- fixtures/
|   |-- pcaps/
|   `-- scenarios/
|-- tests/
|   |-- detection/
|   |-- integration/
|   |-- performance/
|   |-- regression/
|   |-- replay/
|   `-- safety/
`-- tools/
    |-- generators/
    |-- pcap-replay/
    `-- rule-lint/
```

## Runtime Boundaries

- `apps/sentineld/` owns the long-running defensive runtime.
- `apps/sentinelctl/` owns operator workflows and debugging commands.
- `apps/sentinel-console-api/` exposes controlled APIs for dashboards and
  external integrations.

## Detection Boundaries

- `sentinel-telemetry` ingests packet, host, and service data.
- `sentinel-flow` converts raw observations into sessions and state.
- `sentinel-detection` executes signatures, heuristics, and anomaly logic.
- `sentinel-decoy` plans health-aware ambient mist, IDF windows, spot mimicry,
  cadence randomization, and bounded Phantom observation variance while
  preserving internal truth tagging.
- `sentinel-education` turns scan types and defensive behavior into operator
  teaching material and harmlessness guarantees.
- `sentinel-integrity` evaluates drift, tamper, and baseline violations and
  decides when a restorable compromise exists.
- `sentinel-native-bridge` defines the contracts to C, C++, and ASM support
  layers without forcing those components into the Rust-only control plane.
- `sentinel-correlation` assembles multiple runtime decisions into incidents,
  timelines, and evidence bundles.
- `sentinel-reporting` produces operator, forensic, and plain-language
  explanations of what happened, including calm care-centered guidance for the
  person behind the screen.
- `sentinel-runtime` fuses fast-path signals, situation awareness,
  self-integrity, and bounded autonomous decisions into one runtime loop.
- `sentinel-shadow-vault` stores the trusted artifact inventory and plans
  bounded restoration when integrity-safe recovery is possible.
- `sentinel-policy` selects a response based on confidence, asset criticality,
  and safety policy.
- `sentinel-response` performs bounded defensive actions and rollback.
- `sentinel-forensics` packages evidence and timelines.

## Native Layer Boundaries

- `native/c/` is reserved for resource guards, packet-adjacent system helpers,
  descriptor-safe compatibility shims, exposure reduction helpers, and other
  OS-facing primitives, including protocol and multi-node safety caps.
- `native/cpp/` is reserved for stateful classifiers, attack-template models,
  ambient-state models, and richer behavioral correlation paths where C++
  modeling is useful, including behavior matrices and recovery predictors.
- `native/asm/` is reserved for timing primitives and ultra-low-latency
  fast-path helpers, weighted pressure kernels, health-aware zen fallback
  decisions, and future room for bounded zero-copy defensive packet paths.
- `native/include/` contains shared headers for native components.

The native layers are part of the intended layered defense strategy. In v1.0,
ASM is the only native path already linked into the active runtime. C and C++
remain scaffolded so the repo can acknowledge their role without pretending
they are already wired.

## Safety and Fail-Safe Boundaries

- Stability-first control means the runtime preserves host, service, and
  network stability before escalating into stronger protection.
- Situation-aware control must account for attack stage, asset criticality,
  protocol context, and whether a protected device is fragile or
  safety-sensitive.
- Real-time health monitoring must cap automation when CPU, memory, jitter, or
  thermal pressure threatens the protected host.
- Bio-response logic must downgrade or back off when a defensive action itself
  risks destabilizing fragile infrastructure.
- Self-integrity monitoring must detect tamper, corruption, stalled logic, or
  runtime instability inside the protector itself.
- ASM fast-path logic exists to accelerate defensive sensing and last-line
  fail-safe support under heavy pressure, not to introduce offensive behavior.
- Kernel-bypass or direct-to-wire ideas are constrained to bounded defensive
  sensing and protection paths and must remain gated by health, stability, and
  safety policy.
- Source cut-off or isolation is reserved for bounded containment when
  continued contact risks overwhelming or damaging the defended environment.

## Content Boundaries

- `rules/` contains versioned detection and response content.
- `schemas/` defines stable contracts for alerts, events, and scenario files.
- `docs/scenarios/` holds scenario design material.
- `testdata/` holds replay and benchmarking inputs.

## Why This Layout Fits CrystalSentinel-CRA

CrystalSentinel-CRA is scenario-driven and safety-sensitive. That means the repo
must support three kinds of work at the same time:

- product engineering
- detection content authoring
- validation and research

This layout keeps those concerns separate while still allowing one repository
to ship a coherent system.
