#include "sentinel_native.h"

#include <cstring>

namespace {

bool contains(const char *haystack, const char *needle) {
  return haystack != nullptr && needle != nullptr && std::strstr(haystack, needle) != nullptr;
}

}  // namespace

extern "C" sentinel_native_result sentinel_cpp_classify(const sentinel_native_event *event) {
  sentinel_native_result result;
  result.layer = "c++";
  result.decision = "unknown";
  result.adjusted_confidence = event != nullptr ? event->confidence : 0;

  if (event == nullptr || event->summary == nullptr) {
    result.decision = "invalid-event";
    result.adjusted_confidence = 0;
    return result;
  }

  if (contains(event->summary, "oauth_token_abuse")) {
    result.decision = "identity-abuse";
    result.adjusted_confidence = 90;
  } else if (contains(event->summary, "dns_tunnel")) {
    result.decision = "dns-tunnel";
    result.adjusted_confidence = 92;
  } else if (contains(event->summary, "stage_loader")) {
    result.decision = "payload-stager";
    result.adjusted_confidence = 88;
  }

  return result;
}

