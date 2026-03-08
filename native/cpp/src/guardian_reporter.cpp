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

extern "C" sentinel_guardian_report sentinel_cpp_guardian_report(
    const sentinel_native_event *event,
    const sentinel_resource_profile *profile,
    const sentinel_load_balance_plan *load_balance,
    const sentinel_mesh_heartbeat_audit *heartbeat) {
  sentinel_guardian_report report;
  report.layer = "c++";
  report.health_voice = "The system is breathing calmly.";
  report.threat_voice = "The outer paths are quiet.";
  report.mesh_voice = "The mesh is steady and watching gently.";
  report.operator_hint = "status=nominal";
  report.severity = event != nullptr ? event->confidence : 0;

  if (profile == nullptr) {
    report.health_voice = "The shield is listening quietly while we verify our footing.";
    report.mesh_voice = "Mesh trust is paused until the local profile is restored.";
    report.operator_hint = "status=invalid-profile";
    report.severity = 100;
    return report;
  }

  if (high_host_pressure(profile)) {
    report.health_voice =
        "The system is breathing carefully while we keep the shield thin and calm.";
    report.operator_hint = "status=host-pressure";
    report.severity = 80;
  } else if (load_balance != nullptr && load_balance->heartbeat_only != 0) {
    report.health_voice =
        "We are keeping only the smallest pulse alive so local work stays smooth.";
    report.operator_hint = "status=heartbeat-only";
    report.severity = 70;
  }

  if (event != nullptr && event->summary != nullptr) {
    if (contains(event->summary, "masscan") || contains(event->summary, "async_scan") ||
        contains(event->summary, "wide_port_sweep")) {
      report.threat_voice = "A curious pulse tapped on the gate, so the fog opened a maze.";
      report.operator_hint = "status=recon-friction";
      report.severity = 40;
    } else if (contains(event->summary, "deauth_flood") ||
               contains(event->summary, "disassociation_storm") ||
               contains(event->summary, "management_frame_spike")) {
      report.threat_voice =
          "A noisy wave shook the radio edge, but the local shield held the path steady.";
      report.operator_hint = "status=wireless-shield";
      report.severity = 78;
    } else if (contains(event->summary, "stage_loader") ||
               contains(event->summary, "reverse_https") ||
               contains(event->summary, "reflective_loader")) {
      report.threat_voice =
          "An uncertain shadow touched the outer fog and was held away from the garden.";
      report.operator_hint = "status=delivery-hold";
      report.severity = 66;
    }
  }

  if (heartbeat != nullptr) {
    if (std::strcmp(heartbeat->status, "compromised-peer") == 0) {
      report.mesh_voice =
          "One guardian pulse failed its truth check, so the mesh closed that handoff.";
      report.operator_hint = "status=mesh-quarantine";
      report.severity = 92;
    } else if (std::strcmp(heartbeat->status, "missing-peer") == 0) {
      report.mesh_voice =
          "A guardian fell quiet, so the mesh is shifting coverage and keeping the path alive.";
      report.operator_hint = "status=shadow-gateway";
      report.severity = 72;
    } else if (std::strcmp(heartbeat->status, "timing-drift") == 0) {
      report.mesh_voice =
          "The mesh heard a pulse that felt slightly off, so trust has been tightened gently.";
      report.operator_hint = "status=timing-drift";
      if (report.severity < 55) {
        report.severity = 55;
      }
    }
  }

  return report;
}
