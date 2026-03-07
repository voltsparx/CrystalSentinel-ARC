#include "sentinel_native.h"

#include <string.h>

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

  if (strstr(event->summary, "burst_flood") != 0) {
    result.decision = "throttle";
    result.adjusted_confidence = 95;
  } else if (strstr(event->summary, "stage_loader") != 0) {
    result.decision = "contain";
    result.adjusted_confidence = 88;
  }

  return result;
}

