#include "sentinel_native.h"

#include <cstring>

namespace {

bool contains(const char *haystack, const char *needle) {
  return haystack != nullptr && needle != nullptr &&
         std::strstr(haystack, needle) != nullptr;
}

bool fragile_profile(const sentinel_resource_profile *profile) {
  return profile != nullptr &&
         (profile->passive_only ||
          profile->fragility != SENTINEL_FRAGILITY_STABLE);
}

uint16_t decision_window_for(const sentinel_resource_profile *profile,
                             uint16_t baseline_ms) {
  if (profile == nullptr) {
    return baseline_ms;
  }

  if (profile->passive_only ||
      profile->fragility == SENTINEL_FRAGILITY_CRITICAL) {
    return 100;
  }

  if (profile->cpu_load_pct >= 80 || profile->memory_load_pct >= 80 ||
      profile->thermal_c >= 82) {
    return 140;
  }

  if (profile->fragility == SENTINEL_FRAGILITY_SENSITIVE &&
      baseline_ms > 170) {
    return 170;
  }

  return baseline_ms;
}

}  // namespace

extern "C" sentinel_scan_prediction sentinel_cpp_predict_scan_path(
    const sentinel_native_event *event,
    const sentinel_resource_profile *profile) {
  sentinel_scan_prediction prediction;
  prediction.layer = "c++";
  prediction.predicted_identity = "unknown-pressure";
  prediction.predicted_family = "unknown";
  prediction.recommended_posture = "baseline-observe";
  prediction.decision_window_ms = decision_window_for(profile, 220);
  prediction.confidence = event != nullptr ? event->confidence : 0;
  prediction.prefers_recon_friction = 0;
  prediction.prefers_phantom_focus = 1;
  prediction.protect_fragile_assets = fragile_profile(profile) ? 1 : 0;

  if (event == nullptr || event->summary == nullptr) {
    prediction.recommended_posture = "observe-only";
    prediction.decision_window_ms = 0;
    prediction.prefers_phantom_focus = 0;
    prediction.protect_fragile_assets = 1;
    return prediction;
  }

  if (contains(event->summary, "masscan") || contains(event->summary, "async_scan") ||
      contains(event->summary, "wide_port_sweep") ||
      contains(event->summary, "pps_scan")) {
    prediction.predicted_identity = "high-speed-asynchronous-scan";
    prediction.predicted_family = "offensive-scan";
    prediction.recommended_posture = "decoy-first-capture";
    prediction.decision_window_ms = decision_window_for(profile, 180);
    prediction.confidence = 95;
    prediction.prefers_recon_friction = 1;
  } else if (contains(event->summary, "nmap") ||
             contains(event->summary, "service_probe") ||
             contains(event->summary, "version_scan") ||
             contains(event->summary, "banner_grab")) {
    prediction.predicted_identity = "service-fingerprint-scan";
    prediction.predicted_family = "offensive-scan";
    prediction.recommended_posture = "decoy-first-capture";
    prediction.decision_window_ms = decision_window_for(profile, 210);
    prediction.confidence = 88;
    prediction.prefers_recon_friction = 1;
  } else if (contains(event->summary, "stage_loader") ||
             contains(event->summary, "meterpreter") ||
             contains(event->summary, "reverse_https") ||
             contains(event->summary, "reverse_tcp")) {
    prediction.predicted_identity = "stage-fingerprint";
    prediction.predicted_family = "payload-stager";
    prediction.recommended_posture = "decoy-first-capture";
    prediction.decision_window_ms = decision_window_for(profile, 160);
    prediction.confidence = 90;
  } else if (contains(event->summary, "dns_tunnel") ||
             contains(event->summary, "high_entropy")) {
    prediction.predicted_identity = "pressure-mapping";
    prediction.predicted_family = "dns-tunneling";
    prediction.recommended_posture = "bounded-containment";
    prediction.decision_window_ms = decision_window_for(profile, 150);
    prediction.confidence = 89;
  } else if (contains(event->summary, "deauth_flood") ||
             contains(event->summary, "disassociation_storm") ||
             contains(event->summary, "management_frame_spike")) {
    prediction.predicted_identity = "wireless-management-disruption";
    prediction.predicted_family = "volumetric-flood";
    prediction.recommended_posture = "protective-isolation";
    prediction.decision_window_ms = decision_window_for(profile, 110);
    prediction.confidence = 93;
    prediction.prefers_phantom_focus = 0;
    prediction.protect_fragile_assets = 1;
  } else if (contains(event->summary, "mesh_heartbeat_missing") ||
             contains(event->summary, "guardian_pulse_invalid") ||
             contains(event->summary, "peer_trust_drift")) {
    prediction.predicted_identity = "mesh-heartbeat-drift";
    prediction.predicted_family = "integrity-attack";
    prediction.recommended_posture = "bounded-containment";
    prediction.decision_window_ms = decision_window_for(profile, 120);
    prediction.confidence = 96;
    prediction.prefers_recon_friction = 0;
  }

  if (fragile_profile(profile)) {
    prediction.recommended_posture = "baseline-observe";
    prediction.prefers_recon_friction = 0;
    prediction.protect_fragile_assets = 1;
  }

  return prediction;
}
