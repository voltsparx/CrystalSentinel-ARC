#include "sentinel_native.h"

#include <cstring>

namespace {

bool contains(const char *haystack, const char *needle) {
  return haystack != nullptr && needle != nullptr &&
         std::strstr(haystack, needle) != nullptr;
}

bool high_host_pressure(const sentinel_resource_profile *profile) {
  return profile != nullptr &&
         (profile->passive_only || profile->cpu_load_pct >= 88 ||
          profile->memory_load_pct >= 88 || profile->thermal_c >= 85);
}

}  // namespace

extern "C" sentinel_recovery_prediction sentinel_cpp_recovery_predictor(
    const sentinel_native_event *event,
    const sentinel_resource_profile *profile) {
  sentinel_recovery_prediction prediction;
  prediction.layer = "c++";
  prediction.mode = "standby";
  prediction.reason = "nominal";
  prediction.quiet_window_ms = 0;
  prediction.keep_minimum_observation = 0;
  prediction.reduce_exposure_pct = 0;

  if (profile == nullptr) {
    prediction.mode = "observe-only";
    prediction.reason = "invalid-profile";
    prediction.keep_minimum_observation = 1;
    prediction.reduce_exposure_pct = 100;
    return prediction;
  }

  if (high_host_pressure(profile)) {
    prediction.mode = "zen-recovery";
    prediction.reason = "host-pressure";
    prediction.quiet_window_ms = 900;
    prediction.keep_minimum_observation = 1;
    prediction.reduce_exposure_pct = 80;
  } else if (event != nullptr && event->summary != nullptr &&
             (contains(event->summary, "integrity_breach") ||
              contains(event->summary, "rootkit") ||
              contains(event->summary, "tamper"))) {
    prediction.mode = "deep-heal";
    prediction.reason = "integrity-pressure";
    prediction.quiet_window_ms = 700;
    prediction.keep_minimum_observation = 1;
    prediction.reduce_exposure_pct = 65;
  } else if (profile->fragility != SENTINEL_FRAGILITY_STABLE) {
    prediction.mode = "gentle-recovery";
    prediction.reason = "fragile-assets";
    prediction.quiet_window_ms = 420;
    prediction.keep_minimum_observation = 1;
    prediction.reduce_exposure_pct = 40;
  }

  return prediction;
}
