# Scripts

Project automation lives here.

- `bootstrap/`: workstation, install-layout, and repo setup
- `ci/`: validation and packaging automation
- `dev/`: developer convenience commands
- `ops/`: operational and maintenance scripts

Current bootstrap scripts include platform-specific installers that stage:

- binaries under the install prefix
- configuration under `etc/crystalsentinel-arc`
- defensive rule packs under `etc/crystalsentinel-arc/rules`
- state, log, and run directories for the runtime
