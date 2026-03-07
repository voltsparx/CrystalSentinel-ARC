# Configuration

Configuration is split by shared defaults, deployment environment, sensor
role, and response policy.

- `base/`: common defaults
- `environments/`: dev, stage, and prod overlays
- `sensors/`: collector-specific tuning
- `response/`: response ladders and safety controls

Base configuration now also includes:

- `install-layout.toml`: install-prefix and directory layout guidance for Linux, macOS, and Windows
- `defense-modules.toml`: minimum, balanced, and high-guard defensive module profiles
