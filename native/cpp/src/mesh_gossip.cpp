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

bool share_worthy_event(const sentinel_native_event *event) {
  return event != nullptr && event->summary != nullptr &&
         (contains(event->summary, "masscan") ||
          contains(event->summary, "async_scan") ||
          contains(event->summary, "wide_port_sweep") ||
          contains(event->summary, "stage_loader") ||
          contains(event->summary, "reverse_https") ||
          contains(event->summary, "reflective_loader") ||
          contains(event->summary, "deauth_flood") ||
          contains(event->summary, "disassociation_storm") ||
          contains(event->summary, "mesh_heartbeat_missing") ||
          contains(event->summary, "guardian_pulse_invalid") ||
          contains(event->summary, "peer_trust_drift"));
}

}  // namespace

extern "C" sentinel_mesh_gossip_plan sentinel_cpp_mesh_gossip(
    const sentinel_native_event *event,
    const sentinel_resource_profile *profile,
    const sentinel_mesh_heartbeat_audit *heartbeat,
    const sentinel_guardian_handoff *guardian) {
  sentinel_mesh_gossip_plan plan;
  plan.layer = "c++";
  plan.mode = "quiet";
  plan.share_hostile_observation = 0;
  plan.tighten_trust = 0;
  plan.open_shadow_gateway = 0;
  plan.consensus_quorum = 0;
  plan.evidence_ttl_ms = 0;

  if (profile == nullptr) {
    plan.mode = "observe-only";
    return plan;
  }

  if (high_host_pressure(profile)) {
    plan.mode = "guardian-minimum";
    plan.consensus_quorum = 2;
    plan.evidence_ttl_ms = 100;
    return plan;
  }

  if (heartbeat != nullptr &&
      std::strcmp(heartbeat->status, "compromised-peer") == 0) {
    plan.mode = "shadow-gateway";
    plan.share_hostile_observation = 1;
    plan.tighten_trust = 1;
    plan.open_shadow_gateway = 1;
    plan.consensus_quorum = 2;
    plan.evidence_ttl_ms = 120;
    return plan;
  }

  if (guardian != nullptr && std::strcmp(guardian->mode, "shadow-gateway") == 0) {
    plan.mode = "shadow-gateway";
    plan.share_hostile_observation = 1;
    plan.tighten_trust = 1;
    plan.open_shadow_gateway = 1;
    plan.consensus_quorum = 2;
    plan.evidence_ttl_ms = 120;
    return plan;
  }

  if (heartbeat != nullptr &&
      (std::strcmp(heartbeat->status, "missing-peer") == 0 ||
       std::strcmp(heartbeat->status, "timing-drift") == 0)) {
    plan.mode = "tighten-trust";
    plan.share_hostile_observation = 1;
    plan.tighten_trust = 1;
    plan.consensus_quorum = 2;
    plan.evidence_ttl_ms = 160;
    return plan;
  }

  if (share_worthy_event(event)) {
    plan.mode = "share-observation";
    plan.share_hostile_observation = 1;
    plan.consensus_quorum = event != nullptr && event->confidence >= 90 ? 2 : 3;
    plan.evidence_ttl_ms =
        event != nullptr && event->confidence >= 90 ? 220 : 180;
  }

  return plan;
}
