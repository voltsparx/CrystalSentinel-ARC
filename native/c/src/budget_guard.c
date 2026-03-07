#include "sentinel_native.h"

#include <string.h>

static int contains(const char *haystack, const char *needle) {
  return haystack != 0 && needle != 0 && strstr(haystack, needle) != 0;
}

static uint16_t clamp_window(const sentinel_resource_profile *profile,
                             uint16_t baseline_ms) {
  uint16_t window_ms = baseline_ms;

  if (profile == 0) {
    return window_ms;
  }

  if (profile->cpu_load_pct >= 85 || profile->memory_load_pct >= 85 ||
      profile->thermal_c >= 84) {
    window_ms = 120;
  } else if (profile->cpu_load_pct >= 70 || profile->memory_load_pct >= 70 ||
             profile->thermal_c >= 78) {
    window_ms = 180;
  }

  if (profile->fragility == SENTINEL_FRAGILITY_CRITICAL || profile->passive_only) {
    window_ms = 100;
  } else if (profile->fragility == SENTINEL_FRAGILITY_SENSITIVE &&
             window_ms > 150) {
    window_ms = 150;
  }

  return window_ms;
}

sentinel_native_budget sentinel_c_budget_window(
    const sentinel_native_event *event,
    const sentinel_resource_profile *profile) {
  sentinel_native_budget budget;
  budget.layer = "c";
  budget.profile = "balanced";
  budget.guardrail = "stability-first";
  budget.observation_window_ms = 220;
  budget.decoy_cap = 3;
  budget.phantom_budget = 3;
  budget.automation_limited = 0;

  if (event == 0 || event->summary == 0) {
    budget.profile = "invalid-event";
    budget.guardrail = "observe-only";
    budget.observation_window_ms = 0;
    budget.decoy_cap = 0;
    budget.phantom_budget = 0;
    budget.automation_limited = 1;
    return budget;
  }

  if (contains(event->summary, "masscan") || contains(event->summary, "async_scan") ||
      contains(event->summary, "wide_port_sweep")) {
    budget.profile = "recon-friction";
    budget.observation_window_ms = 180;
    budget.decoy_cap = 4;
    budget.phantom_budget = 5;
  } else if (contains(event->summary, "nmap") ||
             contains(event->summary, "service_probe") ||
             contains(event->summary, "version_scan")) {
    budget.profile = "fingerprint-capture";
    budget.observation_window_ms = 210;
    budget.decoy_cap = 3;
    budget.phantom_budget = 4;
  } else if (contains(event->summary, "stage_loader") ||
             contains(event->summary, "meterpreter")) {
    budget.profile = "stage-triage";
    budget.observation_window_ms = 160;
    budget.decoy_cap = 2;
    budget.phantom_budget = 4;
  }

  budget.observation_window_ms =
      clamp_window(profile, budget.observation_window_ms);

  if (profile != 0) {
    if (profile->fragility == SENTINEL_FRAGILITY_CRITICAL ||
        profile->passive_only) {
      budget.guardrail = "fragility-cap";
      budget.decoy_cap = 1;
      budget.phantom_budget = 2;
      budget.automation_limited = 1;
    } else if (profile->fragility == SENTINEL_FRAGILITY_SENSITIVE) {
      budget.guardrail = "gentle-fragility-cap";
      if (budget.decoy_cap > 2) {
        budget.decoy_cap = 2;
      }
    } else if (profile->cpu_load_pct >= 85 || profile->memory_load_pct >= 85 ||
               profile->thermal_c >= 84) {
      budget.guardrail = "resource-pressure-cap";
      budget.decoy_cap = 1;
      budget.phantom_budget = 2;
    }
  }

  return budget;
}
