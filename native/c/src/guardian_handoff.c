#include "sentinel_native.h"

static uint8_t stressed_host(const sentinel_resource_profile *profile) {
  return profile != 0 &&
         (profile->passive_only || profile->fragility == SENTINEL_FRAGILITY_CRITICAL ||
          profile->cpu_load_pct >= 88 || profile->memory_load_pct >= 88 ||
          profile->thermal_c >= 84);
}

sentinel_guardian_handoff sentinel_c_guardian_handoff(
    const sentinel_resource_profile *profile,
    uint16_t protected_nodes,
    uint16_t gentle_nodes,
    uint8_t peer_capacity_pct,
    uint8_t peer_distress) {
  sentinel_guardian_handoff handoff;

  handoff.layer = "c";
  handoff.mode = "local-observe";
  handoff.adoption_budget = 0;
  handoff.clean_forward_only = 1;
  handoff.handoff_ready = 0;
  handoff.preserve_fragile_paths = 0;
  handoff.surrogate_load_pct = 0;

  if (profile == 0) {
    handoff.mode = "invalid-profile";
    return handoff;
  }

  if (peer_distress || stressed_host(profile)) {
    handoff.mode = "shadow-gateway";
    handoff.adoption_budget = 0;
    handoff.handoff_ready = peer_capacity_pct >= 20 ? 1 : 0;
    handoff.preserve_fragile_paths = 1;
    handoff.surrogate_load_pct = peer_capacity_pct >= 85 ? 85 : peer_capacity_pct;
    return handoff;
  }

  if (protected_nodes > 0 || gentle_nodes > 0 ||
      profile->fragility == SENTINEL_FRAGILITY_SENSITIVE) {
    handoff.mode = "adopt-fragile-peer";
    handoff.adoption_budget = protected_nodes >= 2 ? 3 : 2;
    handoff.handoff_ready = peer_capacity_pct >= 40 ? 1 : 0;
    handoff.preserve_fragile_paths = 1;
    handoff.surrogate_load_pct = peer_capacity_pct >= 60 ? 60 : peer_capacity_pct;
    return handoff;
  }

  if (peer_capacity_pct >= 55) {
    handoff.mode = "shared-guardian";
    handoff.adoption_budget = 1;
    handoff.handoff_ready = 1;
    handoff.surrogate_load_pct = peer_capacity_pct >= 50 ? 50 : peer_capacity_pct;
  }

  return handoff;
}
