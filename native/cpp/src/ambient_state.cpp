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

extern "C" sentinel_ambient_state sentinel_cpp_ambient_state(
    const sentinel_native_event *event,
    const sentinel_resource_profile *profile) {
  sentinel_ambient_state state;
  state.layer = "c++";
  state.ambient_state = "nominal";
  state.recommended_mode = "standby";
  state.observation_window_ms = 160;
  state.pressure_bias = 20;
  state.decoy_budget = 2;

  if (event == nullptr || event->summary == nullptr) {
    state.ambient_state = "invalid-event";
    state.recommended_mode = "observe-only";
    state.observation_window_ms = 0;
    state.pressure_bias = 0;
    state.decoy_budget = 0;
    return state;
  }

  if (contains(event->summary, "burst_flood") || contains(event->summary, "ddos") ||
      contains(event->summary, "pps_spike")) {
    state.ambient_state = "saturated";
    state.recommended_mode = "containment-guard";
    state.observation_window_ms = 80;
    state.pressure_bias = 90;
    state.decoy_budget = 0;
  } else if (contains(event->summary, "masscan") ||
             contains(event->summary, "async_scan") ||
             contains(event->summary, "wide_port_sweep")) {
    state.ambient_state = "recon-pressure";
    state.recommended_mode = "decoy-capture";
    state.observation_window_ms = 180;
    state.pressure_bias = 78;
    state.decoy_budget = 3;
  } else if (contains(event->summary, "stage_loader") ||
             contains(event->summary, "reverse_https") ||
             contains(event->summary, "reverse_tcp") ||
             contains(event->summary, "interactive_shell")) {
    state.ambient_state = "intrusion-pressure";
    state.recommended_mode = "containment-guard";
    state.observation_window_ms = 120;
    state.pressure_bias = 84;
    state.decoy_budget = 1;
  }

  if (high_host_pressure(profile)) {
    state.ambient_state = "recovery-pressure";
    state.recommended_mode = "zen-recovery";
    state.observation_window_ms = 90;
    state.pressure_bias = 96;
    state.decoy_budget = 0;
  }

  return state;
}
