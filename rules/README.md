# Detection and Response Content

Versioned security content lives here.

- `manifest.toml`: top-level rule pack include list
- `signatures/`: deterministic rule content for traffic, scanning, staged delivery, reverse channels, and exfiltration
- `heuristics/`: sequence and behavior rules
- `anomaly/`: anomaly model configs and thresholds
- `baselines/`: normal-behavior references, including fragile-device classes
- `response-policies/`: staged response ladders
- `allowlists/`: approved exceptions and suppressions
- `states/`: local profile files that enable, disable, or isolate rules
- `compiled/`: optional output directory for a single locally compiled rule pack

Install layout:

- Linux and macOS: `${prefix}/etc/crystalsentinel-arc/rules`
- Windows: `%ProgramData%\\CrystalSentinel-ARC\\etc\\rules`

The current rule files are a CrystalSentinel-native defensive pack. They are
meant to strengthen detection and containment planning for:

- traffic pressure and tunneling
- offensive scanning and fingerprinting
- staged delivery and reverse channels
- data egress
- fragile-asset protection

Rule language:

- CrystalSentinel uses small TOML files instead of a large rule scripting language.
- Signature files use repeated `[[rules]]` blocks with `id`, `name`, `family`,
  `recommended_stage`, `severity`, `summary`, and `indicators`.
- Profile files use one line per action in `rules/states/*.states`:
  `enable <rule-id>`, `disable <rule-id>`, or `isolate <rule-id>`.
- `sentinelctl rule-profiles` lists built-in profiles.
- `sentinelctl rule-pack <profile>` shows the active pack.
- `sentinelctl rule-build <profile> <output>` writes one compiled local rule pack.
