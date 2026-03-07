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

}  // namespace

extern "C" sentinel_behavior_matrix sentinel_cpp_behavior_matrix(
    const sentinel_native_event *event,
    const sentinel_resource_profile *profile) {
  sentinel_behavior_matrix matrix;
  matrix.layer = "c++";
  matrix.predicted_identity = "unknown-pressure";
  matrix.next_move = "observe";
  matrix.evidence_goal = "triage";
  matrix.confidence = event != nullptr ? event->confidence : 0;
  matrix.prefers_decoy_first = 0;
  matrix.protect_fragile_assets = fragile_profile(profile) ? 1 : 0;

  if (event == nullptr || event->summary == nullptr) {
    matrix.next_move = "observe-only";
    matrix.confidence = 0;
    return matrix;
  }

  if (contains(event->summary, "masscan") || contains(event->summary, "async_scan") ||
      contains(event->summary, "wide_port_sweep") ||
      contains(event->summary, "pps_scan")) {
    matrix.predicted_identity = "high-speed-asynchronous-scan";
    matrix.next_move = "recon-friction-capture";
    matrix.evidence_goal = "scan-fingerprint";
    matrix.confidence = 95;
    matrix.prefers_decoy_first = 1;
  } else if (contains(event->summary, "nmap") ||
             contains(event->summary, "service_probe") ||
             contains(event->summary, "version_scan") ||
             contains(event->summary, "banner_grab")) {
    matrix.predicted_identity = "service-fingerprint-scan";
    matrix.next_move = "phantom-fingerprint-capture";
    matrix.evidence_goal = "service-fingerprint";
    matrix.confidence = 88;
    matrix.prefers_decoy_first = 1;
  } else if (contains(event->summary, "interactive_shell") ||
             contains(event->summary, "reverse_shell") ||
             contains(event->summary, "session_spawn")) {
    matrix.predicted_identity = "interactive-command-channel";
    matrix.next_move = "bounded-containment";
    matrix.evidence_goal = "command-channel-proof";
    matrix.confidence = 94;
  } else if (contains(event->summary, "stage_loader") ||
             contains(event->summary, "reverse_https") ||
             contains(event->summary, "reflective_loader")) {
    matrix.predicted_identity = "staged-intrusion-chain";
    matrix.next_move = "capture-then-contain";
    matrix.evidence_goal = "stager-chain";
    matrix.confidence = 91;
    matrix.prefers_decoy_first = 1;
  }

  if (fragile_profile(profile)) {
    matrix.next_move = "gentle-capture";
    matrix.protect_fragile_assets = 1;
  }

  return matrix;
}
