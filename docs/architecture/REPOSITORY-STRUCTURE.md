# CrystalIDPS-CRA Repository Structure

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
|   |-- crystald/
|   |-- crystalctl/
|   `-- crystal-console-api/
|-- crates/
|   |-- crystal-common/
|   |-- crystal-config/
|   |-- crystal-telemetry/
|   |-- crystal-flow/
|   |-- crystal-detection/
|   |-- crystal-policy/
|   |-- crystal-response/
|   |-- crystal-forensics/
|   |-- crystal-storage/
|   |-- crystal-bio-response/
|   `-- crystal-scenario/
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

- `apps/crystald/` owns the long-running defensive runtime.
- `apps/crystalctl/` owns operator workflows and debugging commands.
- `apps/crystal-console-api/` exposes controlled APIs for dashboards and
  external integrations.

## Detection Boundaries

- `crystal-telemetry` ingests packet, host, and service data.
- `crystal-flow` converts raw observations into sessions and state.
- `crystal-detection` executes signatures, heuristics, and anomaly logic.
- `crystal-policy` selects a response based on confidence, asset criticality,
  and safety policy.
- `crystal-response` performs bounded defensive actions and rollback.
- `crystal-forensics` packages evidence and timelines.

## Content Boundaries

- `rules/` contains versioned detection and response content.
- `schemas/` defines stable contracts for alerts, events, and scenario files.
- `docs/scenarios/` holds scenario design material.
- `testdata/` holds replay and benchmarking inputs.

## Why This Layout Fits CrystalIDPS-CRA

CrystalIDPS-CRA is scenario-driven and safety-sensitive. That means the repo
must support three kinds of work at the same time:

- product engineering
- detection content authoring
- validation and research

This layout keeps those concerns separate while still allowing one repository
to ship a coherent system.

