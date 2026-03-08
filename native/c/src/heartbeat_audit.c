#include "sentinel_native.h"

sentinel_mesh_heartbeat_audit sentinel_c_mesh_heartbeat_audit(
    const sentinel_resource_profile *profile,
    uint8_t missing_peers,
    uint8_t malformed_peers,
    uint16_t jitter_us) {
  sentinel_mesh_heartbeat_audit audit;

  audit.layer = "c";
  audit.status = "trusted";
  audit.trust_mode = "full-handoff";
  audit.heartbeat_interval_ms = 100;
  audit.observed_jitter_us = jitter_us;
  audit.quarantine_peer = 0;
  audit.shift_guardian_coverage = 0;
  audit.ghost_mode_bias = 0;

  if (profile == 0) {
    audit.status = "invalid-profile";
    audit.trust_mode = "observe-only";
    audit.heartbeat_interval_ms = 0;
    audit.quarantine_peer = 1;
    audit.shift_guardian_coverage = 1;
    audit.ghost_mode_bias = 1;
    return audit;
  }

  if (profile->passive_only || profile->fragility == SENTINEL_FRAGILITY_CRITICAL) {
    audit.heartbeat_interval_ms = 140;
  }

  if (malformed_peers > 0 || jitter_us > 10) {
    audit.status = "compromised-peer";
    audit.trust_mode = "suspend-handoff";
    audit.quarantine_peer = 1;
    audit.shift_guardian_coverage = 1;
    audit.ghost_mode_bias = 1;
    return audit;
  }

  if (missing_peers > 0) {
    audit.status = "missing-peer";
    audit.trust_mode = "shadow-gateway";
    audit.shift_guardian_coverage = 1;
    if (missing_peers > 1) {
      audit.ghost_mode_bias = 1;
    }
    return audit;
  }

  if (jitter_us > 2) {
    audit.status = "timing-drift";
    audit.trust_mode = "tighten-trust";
    if (jitter_us > 6) {
      audit.ghost_mode_bias = 1;
    }
  }

  return audit;
}
