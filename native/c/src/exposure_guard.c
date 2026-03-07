#include "sentinel_native.h"

sentinel_exposure_guard sentinel_c_exposure_guard(
    const sentinel_resource_profile *profile) {
  sentinel_exposure_guard guard;
  guard.layer = "c";
  guard.mode = "normal";
  guard.exposure_reduction_pct = 10;
  guard.pause_nonessential_decoys = 0;
  guard.keep_minimum_observation = 1;
  guard.resume_standby_after_ms = 240;

  if (profile == 0) {
    guard.mode = "invalid-profile";
    guard.exposure_reduction_pct = 100;
    guard.pause_nonessential_decoys = 1;
    guard.keep_minimum_observation = 0;
    guard.resume_standby_after_ms = 0;
    return guard;
  }

  if (profile->passive_only ||
      profile->fragility == SENTINEL_FRAGILITY_CRITICAL ||
      profile->cpu_load_pct >= 92 || profile->memory_load_pct >= 92 ||
      profile->thermal_c >= 88) {
    guard.mode = "zen";
    guard.exposure_reduction_pct = 80;
    guard.pause_nonessential_decoys = 1;
    guard.keep_minimum_observation = 1;
    guard.resume_standby_after_ms = 900;
  } else if (profile->fragility == SENTINEL_FRAGILITY_SENSITIVE ||
             profile->cpu_load_pct >= 80 || profile->memory_load_pct >= 80 ||
             profile->thermal_c >= 82) {
    guard.mode = "guarded";
    guard.exposure_reduction_pct = 45;
    guard.pause_nonessential_decoys = 1;
    guard.keep_minimum_observation = 1;
    guard.resume_standby_after_ms = 480;
  }

  return guard;
}
