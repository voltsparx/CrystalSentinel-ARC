# CrystalSentinel-ARC

CrystalSentinel-ARC is a research-driven defensive architecture and prototype
direction focused on real-time detection, prevention, containment,
investigation, and explanation of hostile activity across modern networks and
endpoints.

It is not positioned as only an IDPS and not positioned as only a learning
framework. This repository is best read as a design, reverse-engineering, and
prototype program toward a full-scale protector that can sense the earliest
meaningful echo of hostile behavior, make fast health-aware decisions, apply
bounded defensive action, and then teach operators exactly how and why it
acted.

The project starts from attack scenarios: what an attacker is trying to do,
what signals appear during that activity, what harmless defensive scan or decoy
behavior can expose more information, what defensive action is safe, and how
the system should explain its decision to operators and researchers.

## Project Intent

- Detect hostile behavior on the earliest meaningful echo.
- Use decoy-first Phantom evidence collection to buy decision time.
- Prevent attacker progress when confidence is high.
- Contain threatening activity without destabilizing normal systems.
- Produce logs, timelines, reasoning, and teaching that are useful to
  operators, learners, and researchers.
- Speak with care for the person behind the screen by reducing panic,
  explaining next steps, and separating calm guidance from raw forensic detail.

## Positioning

CrystalSentinel-ARC is a real-time autonomous defensive system. In this
project, "neutralize" means defensive containment, not retaliation.

It is designed to close the gap between:

- protection
- interpretation
- operator understanding
- safe autonomous action

Allowed containment actions:

- alert and watch
- rate-limit or throttle a flow
- terminate a suspicious session
- block traffic temporarily
- isolate a host, interface, service, or process
- require operator approval for high-impact actions

## What Makes It Different

CrystalSentinel-ARC is designed around behavior-driven defense rather than only
rule-triggered blocking. Its intended design points are:

- new defensive scan concepts such as TBNS, Phantom-Scan, KIS, SARS, IDF Scan, and Callback-Ping research
- harmless defensive decoys that buy time for better classification
- harmless reconnaissance-friction decoys that make high-speed scanning less reliable
- multi-layer sensing from Rust, C++, C, and ASM support paths
- runtime architecture patterns that rebalance packet lanes, classifier lanes, fault isolation, and decoy spread under pressure
- multi-lane fusion across signature-style, classification-style, stateful, heuristic, decoy, bio-response, and ASM fast-path signals
- built-in operator teaching instead of opaque automation
- open-source reference material used to strengthen defensive coverage

## Decoy-First Capture Loop

One of the core ideas in the CrystalSentinel-ARC design is the decoy-first information
collection method.

Instead of waiting for a threat to fully arrive before reacting, the platform
can use a bounded defensive decoy such as IDF Scan to create a short flare
window. During that window:

1. inert decoy pressure is released in a harmless and controlled way
2. Phantom-Scan and fast-path telemetry open a bounded evidence ladder and collect reaction behavior
3. KIS and other intelligence layers correlate timing, flow, and protocol clues
4. SARS watches ambient network resonance so hidden throttling or pressure spikes become visible
5. the policy layer makes a faster containment decision
6. the system explains what it saw and why it acted

For high-speed scan pressure, the same loop can add harmless reconnaissance
friction so automated tools spend more retries and lose confidence before they
can trust what they are seeing.

This is meant to push defensive power further without crossing into offensive
behavior. The purpose is to force exposure, accelerate classification, and
improve early containment.

## Defensive Nervous System

CrystalSentinel-ARC treats the defense stack as a layered nervous-system model rather
than a single detector.

- Rust is intended to be the executive layer that applies policy, explanation,
  and bounded autonomous action.
- C++ is intended to predict scan behavior and classification paths while C
  models behavior and recovery paths while C caps budgets, protocol pressure,
  mesh action spread, and fragile assets.
- ASM is intended to be the lowest-latency sensing and fast-path decision
  layer for timing-critical pressure signals such as offensive scans,
  intrusion bursts, and DDoS pressure.
- The ASM layer is intended to choose between fast decoy capture,
  containment-guard behavior, and a low-resource zen recovery mode when the
  defended host is too stressed to keep spending resources on heavier defense.
- The native fast path can grow toward bounded zero-copy or direct-to-wire
  defensive paths, but only under the same stability-first and safety-aware
  controls as the rest of the platform.

When pressure becomes severe, the system is designed to respond in this order:

1. detect the earliest meaningful echo or drift
2. collect additional signal through fast-path telemetry and decoy-first Phantom capture
3. classify the pressure as reconnaissance, intrusion, saturation, or unknown
4. cap action based on real-time host health and policy safety limits
5. isolate or cut off the source only if continued contact risks damaging the
   protected system or overwhelming the defensive runtime

When the defended system itself is under heavy resource or thermal stress, the
same lower layer should be able to reduce exposure, pause non-essential decoy
activity, keep only minimum observation alive, and return to standby once the
system is healthy enough to defend again.

This makes the lower layer a defensive last line, not a retaliation engine.
Its intended job is to preserve system survival, buy classification time, and
keep the protector stable under heavy pressure.

## Runtime Architecture Patterns

CrystalSentinel-ARC now carries a runtime architecture planner so the
protector can stay autonomous without becoming unstable or wasteful.

- `edge-guardian`: balanced single-node protection for normal deployment
- `balanced-mesh`: wider distribution across multiple protected systems
- `fragile-mesh-guard`: extra headroom and gentler decoy limits for fragile environments
- `pressure-shield`: heavier fast-path and classifier emphasis during scan or intrusion pressure

These patterns do not just rename modes. They change:

- packet, classifier, correlation, and reporting lane budgets
- fault-isolation strictness
- how much headroom is reserved for stability
- how far harmless decoys are allowed to spread
- how much work is pushed toward Rust, C, C++, and ASM paths

## Situation Awareness and Bio-Response

CrystalSentinel-ARC is designed to remain aware of both the threat and the
condition of the environment it is defending.

- Situation-Aware intelligence tracks attack state, asset criticality, device
  role, protocol context, and current response stage.
- Bio-Response intelligence tracks the health of the protected environment,
  including CPU load, memory pressure, thermal state, packet loss, jitter,
  retransmits, and service readiness.

These two layers exist so the platform does not accidentally damage fragile
hardware while trying to stop a threat. That matters most in environments such
as:

- legacy infrastructure
- IoT devices
- industrial controllers
- medical or safety-sensitive hardware

The protective rule is simple:

1. identify the threat
2. identify how fragile the target environment is
3. choose the least disruptive action that still preserves safety
4. escalate only when the current level is no longer enough
5. cut off the source only when continued contact is more dangerous than the
   containment action itself

## Safety Principles

- Stability first: the platform must preserve host, service, and network
  stability before it escalates into stronger protection.
- Passive first: observe before interfering whenever possible.
- Harmless decoys only: synthetic fog and dummy scans must stay inert,
  bounded, and non-weaponizable.
- Situation-aware by default: action must be based on attack context, asset
  criticality, and response stage, not raw signal strength alone.
- Health-aware by default: real-time CPU, memory, jitter, and thermal state
  must cap or downgrade automated action before the defense harms the host.
- Fragile-hardware aware: if a protected device shows signs of instability,
  the platform must back off, downgrade, or isolate safely instead of pushing a
  heavier response through it.
- Self-integrity first: if the runtime detects tamper, corruption, or internal
  instability, it must shift to safe containment and protect itself before
  resuming normal operation.
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
clarity. CrystalSentinel-ARC aims to close that gap by combining:

- early observation
- decoy-first information collection
- scenario-driven detection
- safe response policies
- resource-aware execution
- human-readable explanations

## High-Level Objectives

1. Build a system that observes traffic, system state, and attack indicators.
2. Use harmless scan and decoy primitives to expose more attacker behavior.
3. Convert those signals into confidence-scored detections.
4. Apply bounded, reversible defensive responses.
5. Preserve forensic value and teach the operator instead of acting opaquely.

## Concept Vocabulary

These terms already appear in the design notes. This outline anchors them to
concrete engineering meaning.

- Bio-Response: host and service health telemetry such as CPU, memory, packet
  loss, jitter, retransmits, and service readiness.
- Situation-Aware: attack state, asset criticality, confidence score, and
  current response stage, including whether the protected environment is
  fragile, latency-sensitive, or safety-critical.
- IDF Scan: Inert Decoy Fog Scan, a harmless defensive decoy that creates a
  short-lived flare window for additional observation.
- Callback-Ping: a reverse-probe research concept for studying suspicious
  source reactions through a tightly bounded callback window. It is not part of
  the active harmless decoy runtime.
- KIS: Kinetic Impedance System, a timing and pressure signal that helps the
  runtime understand how hard the path, service, or attacker is pushing.
- SARS: Synthetic Ambient Resonance Scan, a harmless ambient monitor that
  watches device and network resonance for spikes that suggest throttling,
  congestion, or hidden pressure.
- Decoy-First Capture Loop: a defensive sequence in which harmless decoy
  pressure buys enough time to observe reaction behavior and decide faster.
- Self-Integrity Monitoring: runtime checks that detect tamper, instability,
  stalled logic, or degradation inside the protector itself.
- Safe Override: a bounded defensive action path with safety checks and
  rollback rules.

## Repository Layout

## Install and Rule Layout

CrystalSentinel-ARC now follows a prefix-based install layout so the runtime,
config, and rules can be staged consistently across Linux, macOS, and Windows.

- Linux and macOS use `${prefix}/etc/crystalsentinel-arc` for config and
  `${prefix}/etc/crystalsentinel-arc/rules` for rule content.
- Windows uses `%ProgramData%\\CrystalSentinel-ARC\\etc` for config and
  `%ProgramData%\\CrystalSentinel-ARC\\etc\\rules` for rule content.
- Platform installers live under `scripts/bootstrap/`.
- Service templates live under `deploy/systemd/`, `deploy/launchd/`, and
  `deploy/windows-service/`.

The initial rule pack is CrystalSentinel-native and defense-only. It is
organized for:

- traffic pressure and tunneling
- scanning and fingerprinting detection
- staged delivery and reverse-channel detection
- exfiltration indicators
- fragile-device baselines
- stability-first response policy

The rule language is intentionally small. CrystalSentinel-ARC uses readable
TOML rule files plus local profile state files instead of a large external
rule scripting language. The goal is to keep authoring, review, deployment,
and incident response simpler without weakening defensive control.

The repository uses an enterprise-style monorepo layout as the target
architecture for runtime applications, reusable Rust crates, detection
content, operational material, and validation assets.

See `docs/architecture/REPOSITORY-STRUCTURE.md` for the full layout.
See `docs/implementation/V1-COVERAGE.md` for the current v1.0
design-and-prototype comparison against the self-assessments.

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

## Replay Validation Workflow

Replayable scenario contracts now live under `testdata/scenarios/` as JSON files.
Each contract can carry:

- scenario metadata and success criteria
- optional runtime overrides for deployment or performance mode
- an ordered telemetry event stream
- expected families, response stage, and report fragments

Run a scenario contract through the current runtime with:

```powershell
cargo run -p sentinelctl -- replay testdata/scenarios/scan-pressure-capture.json
```

This keeps the validation path close to the self-assessment ideas: decoy-first
capture, fast-path pressure scoring, bounded response, and human-readable
explanations are all exercised together.

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

To make the project useful beyond defense operations, CrystalSentinel-ARC should support:

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

CrystalSentinel-ARC should avoid claims that are not technically defensible.

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
