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
|   |-- sentinel-native-bridge/
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
- `sentinel-native-bridge` defines the contracts to C, C++, and ASM support
  layers without forcing those components into the Rust-only control plane.
- `sentinel-policy` selects a response based on confidence, asset criticality,
  and safety policy.
- `sentinel-response` performs bounded defensive actions and rollback.
- `sentinel-forensics` packages evidence and timelines.

## Native Layer Boundaries

- `native/c/` is reserved for resource guards, packet-adjacent system helpers,
  and OS-facing primitives.
- `native/cpp/` is reserved for stateful classifiers and richer attack-template
  logic where C++ modeling is useful.
- `native/asm/` is reserved for timing primitives and ultra-low-latency
  fast-path helpers.
- `native/include/` contains shared headers for native components.

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
