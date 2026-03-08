# Test Data

Non-production validation assets live here.

- `pcaps/`: replay captures
- `fixtures/`: structured input fixtures
- `scenarios/`: JSON scenario contracts with runtime overrides, ordered
  telemetry events, and expected outcomes
- `telemetry/`: JSONL event streams for `sentineld` ingestion tests and
  operator smoke checks
- `baselines/`: reference normal-behavior datasets

Do not store live secrets, production traffic, or harmful payloads here.
