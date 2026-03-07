#include "sentinel_native.h"

sentinel_mesh_guard sentinel_c_mesh_guard(
    const sentinel_resource_profile *profile,
    uint16_t protected_nodes,
    uint16_t gentle_nodes) {
  sentinel_mesh_guard guard;
  guard.layer = "c";
  guard.mode = "distributed";
  guard.protected_nodes = protected_nodes;
  guard.gentle_nodes = gentle_nodes;
  guard.max_parallel_actions = 4;
  guard.pause_nonessential_decoys = 0;

  if (profile == 0) {
    guard.mode = "invalid-profile";
    guard.max_parallel_actions = 0;
    guard.pause_nonessential_decoys = 1;
    return guard;
  }

  if (profile->passive_only || profile->fragility == SENTINEL_FRAGILITY_CRITICAL ||
      profile->cpu_load_pct >= 90 || profile->memory_load_pct >= 90 ||
      profile->thermal_c >= 86) {
    guard.mode = "zen-mesh";
    guard.max_parallel_actions = 1;
    guard.pause_nonessential_decoys = 1;
  } else if (gentle_nodes > 0 || profile->fragility == SENTINEL_FRAGILITY_SENSITIVE) {
    guard.mode = "gentle-mesh";
    guard.max_parallel_actions = 2;
    guard.pause_nonessential_decoys = 1;
  } else if (protected_nodes >= 32) {
    guard.mode = "broad-mesh";
    guard.max_parallel_actions = 3;
  }

  return guard;
}
