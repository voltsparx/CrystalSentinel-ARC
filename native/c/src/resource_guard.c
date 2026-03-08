#include "sentinel_native.h"

#include <string.h>

static int contains(const char *haystack, const char *needle) {
  return haystack != 0 && needle != 0 && strstr(haystack, needle) != 0;
}

sentinel_native_result sentinel_c_resource_guard(const sentinel_native_event *event) {
  sentinel_native_result result;
  result.layer = "c";
  result.decision = "observe";
  result.adjusted_confidence = event != 0 ? event->confidence : 0;

  if (event == 0 || event->summary == 0) {
    result.decision = "invalid-event";
    result.adjusted_confidence = 0;
    return result;
  }

  if (contains(event->summary, "burst_flood")) {
    result.decision = "throttle";
    result.adjusted_confidence = 95;
  } else if (contains(event->summary, "deauth_flood") ||
             contains(event->summary, "disassociation_storm") ||
             contains(event->summary, "management_frame_spike")) {
    result.decision = "shield-radio-edge";
    result.adjusted_confidence = 93;
  } else if (contains(event->summary, "stage_loader")) {
    result.decision = "contain";
    result.adjusted_confidence = 88;
  } else if (contains(event->summary, "mesh_heartbeat_missing") ||
             contains(event->summary, "guardian_pulse_invalid") ||
             contains(event->summary, "peer_trust_drift")) {
    result.decision = "shift-guardian-coverage";
    result.adjusted_confidence = 96;
  } else if (contains(event->summary, "legacy") || contains(event->summary, "medical") ||
             contains(event->summary, "plc")) {
    result.decision = "stability-cap";
    result.adjusted_confidence = 82;
  }

  return result;
}
