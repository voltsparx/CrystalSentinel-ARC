#include "sentinel_native.h"

#include <string.h>

static int contains(const char *haystack, const char *needle) {
  return haystack != 0 && needle != 0 && strstr(haystack, needle) != 0;
}

sentinel_protocol_budget sentinel_c_protocol_budget(
    const sentinel_native_event *event,
    const sentinel_resource_profile *profile) {
  sentinel_protocol_budget budget;
  budget.layer = "c";
  budget.protocol_family = "generic";
  budget.mode = "balanced";
  budget.observation_window_ms = 180;
  budget.decoy_cap = 2;
  budget.preserve_gentle_assets = 0;

  if (event == 0 || event->summary == 0) {
    budget.mode = "observe-only";
    budget.observation_window_ms = 0;
    budget.decoy_cap = 0;
    budget.preserve_gentle_assets = 1;
    return budget;
  }

  if (contains(event->summary, "https") || contains(event->summary, "reverse_https") ||
      contains(event->summary, "tls")) {
    budget.protocol_family = "https";
    budget.mode = "staged-transport-triage";
    budget.observation_window_ms = 150;
    budget.decoy_cap = 1;
  } else if (contains(event->summary, "deauth_flood") ||
             contains(event->summary, "disassociation_storm") ||
             contains(event->summary, "management_frame_spike")) {
    budget.protocol_family = "wireless-management";
    budget.mode = "radio-shield";
    budget.observation_window_ms = 100;
    budget.decoy_cap = 0;
  } else if (contains(event->summary, "mesh_heartbeat_missing") ||
             contains(event->summary, "guardian_pulse_invalid") ||
             contains(event->summary, "peer_trust_drift")) {
    budget.protocol_family = "mesh-heartbeat";
    budget.mode = "trust-tightening";
    budget.observation_window_ms = 120;
    budget.decoy_cap = 0;
  } else if (contains(event->summary, "http") || contains(event->summary, "uri_sqli") ||
             contains(event->summary, "service_probe")) {
    budget.protocol_family = "http";
    budget.mode = "application-recon";
    budget.observation_window_ms = 170;
    budget.decoy_cap = 2;
  } else if (contains(event->summary, "dns_tunnel") ||
             contains(event->summary, "high_entropy")) {
    budget.protocol_family = "dns";
    budget.mode = "entropy-watch";
    budget.observation_window_ms = 120;
    budget.decoy_cap = 0;
  } else if (contains(event->summary, "reverse_tcp") ||
             contains(event->summary, "interactive_shell") ||
             contains(event->summary, "port_sweep")) {
    budget.protocol_family = "tcp";
    budget.mode = "socket-pressure";
    budget.observation_window_ms = 140;
    budget.decoy_cap = 1;
  }

  if (profile != 0 &&
      (profile->passive_only || profile->fragility != SENTINEL_FRAGILITY_STABLE ||
       profile->cpu_load_pct >= 80 || profile->memory_load_pct >= 80 ||
       profile->thermal_c >= 82)) {
    budget.mode = "gentle";
    budget.preserve_gentle_assets = 1;
    if (budget.observation_window_ms > 110) {
      budget.observation_window_ms = 110;
    }
    if (budget.decoy_cap > 1) {
      budget.decoy_cap = 1;
    }
  }

  return budget;
}
