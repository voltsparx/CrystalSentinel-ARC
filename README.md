# CrystalSentinel-CRA

CrystalSentinel-CRA is a defensive platform concept focused on safe detection, prevention,
containment, and investigation of hostile activity across modern networks and
endpoints.

The project starts from attack scenarios: what an attacker is trying to do,
what signals appear during that activity, what defensive action is safe, and
how the system should explain its decision to operators and researchers.

## Project Intent

- Detect hostile behavior as early as possible.
- Prevent attacker progress when confidence is high.
- Contain threatening activity without destabilizing normal systems.
- Produce logs, timelines, and reasoning that are useful to operators,
  learners, and researchers.

## Positioning

CrystalSentinel-CRA is a defensive system. In this project, "neutralize" means
defensive containment, not retaliation.

Allowed containment actions:

- alert and watch
- rate-limit or throttle a flow
- terminate a suspicious session
- block traffic temporarily
- isolate a host, interface, service, or process
- require operator approval for high-impact actions

## Safety Principles

- Passive first: observe before interfering whenever possible.
- Least disruptive action: prefer alerting, throttling, or temporary blocking
  before stronger isolation.
- Rollback by default: responses should expire, reverse, or downgrade if
  confidence drops.
- Explainability: every action must include evidence and reasoning.
- Resource awareness: protection must not crash or degrade the protected
  environment.
- Research value: artifacts should help investigation, replay, and learning.

## Core Problem Statement

Traditional security tools often force a tradeoff between speed, safety, and
clarity. CrystalSentinel-CRA aims to close that gap by combining:

- early observation
- scenario-driven detection
- safe response policies
- resource-aware execution
- human-readable explanations

## High-Level Objectives

1. Build a system that observes traffic, system state, and attack indicators.
2. Convert those signals into confidence-scored detections.
3. Apply bounded, reversible defensive responses.
4. Preserve forensic value for review and research.
5. Provide operator guidance instead of opaque automation.

## Concept Vocabulary

These terms already appear in the design notes. This outline anchors them to
concrete engineering meaning.

- Bio-Response: host and service health telemetry such as CPU, memory, packet
  loss, jitter, retransmits, and service readiness.
- Situation-Aware: attack state, asset criticality, confidence score, and
  current response stage.
- Safe Override: a bounded defensive action path with safety checks and
  rollback rules.

## Repository Layout

The repository now uses an enterprise-style monorepo structure with separate
areas for runtime applications, reusable Rust crates, detection content,
operational material, and validation assets.

See `docs/architecture/REPOSITORY-STRUCTURE.md` for the full layout.

## System Outline

### 1. Telemetry Layer

Collect the raw signals needed for detection and safe decision-making.

- packet and flow metadata
- protocol features
- endpoint and service health
- resource usage on the protected system
- baseline behavior for normal traffic

### 2. Detection Layer

Combine multiple detection methods so the system is not dependent on a single
logic path.

- signature matching for known attacks
- heuristics for suspicious sequences and protocol abuse
- anomaly scoring against learned or recorded baselines
- correlation across packets, flows, and host signals

### 3. Decision Layer

Take raw detections and turn them into action decisions.

- confidence scoring
- attack state tracking
- asset criticality weighting
- false-positive guards
- response selection based on safety policy

### 4. Response Layer

Apply defensive actions in a staged ladder.

- observe only
- alert
- rate-limit
- block temporarily
- isolate or quarantine
- escalate to operator

### 5. Investigation Layer

Preserve evidence and make decisions understandable.

- event timeline
- packet and flow context
- response audit trail
- reason codes
- operator guidance

## Scenario-Driven Design Method

Every idea or "attack situation" should be written in a standard format before
it becomes code.

For each scenario, define:

- scenario name
- attacker goal
- entry point
- observable signals
- benign lookalikes
- confidence rules
- safe response options
- rollback conditions
- evidence to preserve
- success and failure criteria

## Example Scenario Template

Use this template for new scenarios:

```text
Scenario:
Attacker Goal:
Protected Asset:
Initial Signals:
Escalation Signals:
Benign False-Positive Risks:
Detection Logic:
Confidence Thresholds:
Allowed Responses:
Safety Checks:
Rollback Rule:
Artifacts To Store:
Operator Guidance:
Research Value:
```

## Threat Categories To Start With

- port scan and service fingerprinting
- brute-force authentication attempts
- protocol abuse and malformed packets
- lateral movement between hosts
- command-and-control patterns
- data exfiltration behavior
- denial-of-service indicators
- exploit delivery against exposed services

## MVP Scope

The first version should prove the core idea with the smallest credible build.

- one implementation language first, preferably Rust
- passive packet capture and flow tracking
- signature and heuristic detection
- confidence-scored response policy
- safe temporary blocking or rate-limiting
- structured logs and replayable test inputs

## Researcher Value

To make the project useful beyond defense operations, CrystalSentinel-CRA should support:

- reproducible attack scenario definitions
- PCAP replay and offline analysis
- comparison of rule hits versus anomaly scores
- explanation logs for why a response happened
- forensic timelines for post-incident review

## Success Metrics

Measure the project with concrete outcomes, not architecture claims.

- detection rate on known scenarios
- false-positive rate on normal traffic
- time to detect
- time to contain
- rollback correctness
- host and network overhead during protection
- clarity of operator-facing explanations

## Non-Goals

CrystalSentinel-CRA should avoid claims that are not technically defensible.

- no "100% secure" claims
- no autonomous retaliation
- no unexplained high-impact actions
- no architecture complexity without measured benefit

## Roadmap

### Phase 1: Foundations

- define scenarios
- define telemetry model
- define response ladder
- define logging format

### Phase 2: Detection MVP

- packet capture
- flow tracking
- signature engine
- heuristic rules

### Phase 3: Safe Response

- temporary block and rate-limit actions
- rollback logic
- confidence thresholds

### Phase 4: Research and Validation

- PCAP replay
- benchmark runs
- false-positive testing
- operator explanation review

## Current Repository Notes

The existing concept material lives in:

- `self-assessments/blueprint.txt`
- `self-assessments/4-layered-security-system.txt`
- `self-assessments/4-layered-steel-kernel-flow.txt`
- `self-assessments/safe-override-logic.txt`

Those documents contain useful ideas. This outline is the engineering frame for
turning them into an implementable defensive system.
