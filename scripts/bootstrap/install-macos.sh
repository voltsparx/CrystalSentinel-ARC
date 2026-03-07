#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PREFIX="${PREFIX:-/usr/local}"
CONFIG_ROOT="${CONFIG_ROOT:-$PREFIX/etc/crystalsentinel}"
RULES_ROOT="${RULES_ROOT:-$CONFIG_ROOT/rules}"
STATE_ROOT="${STATE_ROOT:-$PREFIX/var/lib/crystalsentinel}"
LOG_ROOT="${LOG_ROOT:-$PREFIX/var/log/crystalsentinel}"
RUN_ROOT="${RUN_ROOT:-$PREFIX/var/run/crystalsentinel}"
BIN_ROOT="${BIN_ROOT:-$PREFIX/bin}"
LIB_ROOT="${LIB_ROOT:-$PREFIX/lib}"

echo "Installing CrystalSentinel-CRA layout for macOS"
echo "  prefix:      $PREFIX"
echo "  config root: $CONFIG_ROOT"
echo "  rules root:  $RULES_ROOT"
echo "Override PREFIX=/opt/homebrew if needed on Apple Silicon."

install -d "$BIN_ROOT" "$LIB_ROOT" "$CONFIG_ROOT" "$RULES_ROOT" \
  "$RULES_ROOT/signatures" "$RULES_ROOT/heuristics" "$RULES_ROOT/anomaly" \
  "$RULES_ROOT/baselines" "$RULES_ROOT/response-policies" "$RULES_ROOT/allowlists" \
  "$RULES_ROOT/states" "$RULES_ROOT/compiled" \
  "$STATE_ROOT" "$LOG_ROOT" "$RUN_ROOT"

install -m 0644 "$ROOT_DIR/configs/base/runtime.toml" "$CONFIG_ROOT/runtime.toml"
install -m 0644 "$ROOT_DIR/configs/base/install-layout.toml" "$CONFIG_ROOT/install-layout.toml"
install -m 0644 "$ROOT_DIR/configs/base/defense-modules.toml" "$CONFIG_ROOT/defense-modules.toml"

cp -R "$ROOT_DIR/rules/." "$RULES_ROOT/"

if [[ -f "$ROOT_DIR/target/release/sentineld" ]]; then
  install -m 0755 "$ROOT_DIR/target/release/sentineld" "$BIN_ROOT/sentineld"
fi

if [[ -f "$ROOT_DIR/target/release/sentinelctl" ]]; then
  install -m 0755 "$ROOT_DIR/target/release/sentinelctl" "$BIN_ROOT/sentinelctl"
fi

if [[ -f "$ROOT_DIR/native/build-asm/libsentinel-native-asm.a" ]]; then
  install -m 0644 "$ROOT_DIR/native/build-asm/libsentinel-native-asm.a" "$LIB_ROOT/"
fi

if [[ -f "$ROOT_DIR/native/build-gcc/libsentinel-native-c.a" ]]; then
  install -m 0644 "$ROOT_DIR/native/build-gcc/libsentinel-native-c.a" "$LIB_ROOT/"
fi

if [[ -f "$ROOT_DIR/native/build-gcc/libsentinel-native-cpp.a" ]]; then
  install -m 0644 "$ROOT_DIR/native/build-gcc/libsentinel-native-cpp.a" "$LIB_ROOT/"
fi

echo "Installation layout complete."
echo "Build release binaries first with: cargo build --release --bins"
