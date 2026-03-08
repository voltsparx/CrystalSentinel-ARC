#include "sentinel_native.h"

#include <cassert>
#include <cstring>

int main() {
  sentinel_resource_profile calm = {};
  calm.cpu_load_pct = 18;
  calm.memory_load_pct = 24;
  calm.thermal_c = 42;
  calm.passive_only = 0;
  calm.fragility = SENTINEL_FRAGILITY_STABLE;

  sentinel_resource_profile stressed = {};
  stressed.cpu_load_pct = 94;
  stressed.memory_load_pct = 88;
  stressed.thermal_c = 86;
  stressed.passive_only = 0;
  stressed.fragility = SENTINEL_FRAGILITY_CRITICAL;

  sentinel_native_event wireless = {};
  wireless.source = "radio-edge-03";
  wireless.summary = "deauth_flood disassociation_storm management_frame_spike";
  wireless.confidence = 90;

  sentinel_native_event mesh = {};
  mesh.source = "guardian-node-02";
  mesh.summary = "mesh_heartbeat_missing peer_trust_drift";
  mesh.confidence = 96;

  sentinel_load_balance_plan calm_plan =
      sentinel_c_dynamic_load_balancer(&calm, 12, 10, 8);
  assert(std::strcmp(calm_plan.mode, "full-spectrum") == 0);
  assert(calm_plan.chaff_intensity_pct == 100);

  sentinel_load_balance_plan stressed_plan =
      sentinel_c_dynamic_load_balancer(&stressed, 91, 84, 88);
  assert(std::strcmp(stressed_plan.mode, "heartbeat-only") == 0);
  assert(stressed_plan.heartbeat_only == 1);

  sentinel_mesh_heartbeat_audit missing_audit =
      sentinel_c_mesh_heartbeat_audit(&calm, 1, 0, 1);
  assert(std::strcmp(missing_audit.status, "missing-peer") == 0);
  assert(missing_audit.shift_guardian_coverage == 1);

  sentinel_mesh_heartbeat_audit compromised_audit =
      sentinel_c_mesh_heartbeat_audit(&calm, 0, 1, 14);
  assert(std::strcmp(compromised_audit.status, "compromised-peer") == 0);
  assert(compromised_audit.quarantine_peer == 1);

  sentinel_guardian_handoff adoption =
      sentinel_c_guardian_handoff(&calm, 1, 1, 65, 0);
  assert(std::strcmp(adoption.mode, "adopt-fragile-peer") == 0);
  assert(adoption.preserve_fragile_paths == 1);

  sentinel_guardian_handoff shadow_gateway =
      sentinel_c_guardian_handoff(&stressed, 1, 1, 72, 1);
  assert(std::strcmp(shadow_gateway.mode, "shadow-gateway") == 0);
  assert(shadow_gateway.handoff_ready == 1);

  sentinel_mesh_gossip_plan share_plan =
      sentinel_cpp_mesh_gossip(&wireless, &calm, &missing_audit, &adoption);
  assert(std::strcmp(share_plan.mode, "tighten-trust") == 0);
  assert(share_plan.share_hostile_observation == 1);

  sentinel_mesh_gossip_plan shadow_plan =
      sentinel_cpp_mesh_gossip(&mesh, &calm, &compromised_audit, &shadow_gateway);
  assert(std::strcmp(shadow_plan.mode, "shadow-gateway") == 0);
  assert(shadow_plan.open_shadow_gateway == 1);

  sentinel_guardian_report radio_report = sentinel_cpp_guardian_report(
      &wireless, &calm, &calm_plan, &missing_audit);
  assert(std::strcmp(radio_report.operator_hint, "status=shadow-gateway") == 0);
  assert(radio_report.severity >= 72);

  sentinel_guardian_report mesh_report = sentinel_cpp_guardian_report(
      &mesh, &calm, &calm_plan, &compromised_audit);
  assert(std::strcmp(mesh_report.operator_hint, "status=mesh-quarantine") == 0);
  assert(mesh_report.severity >= 92);

  sentinel_native_result classify_wireless = sentinel_cpp_classify(&wireless);
  assert(std::strcmp(classify_wireless.decision, "wireless-management-disruption") == 0);

  sentinel_scan_prediction mesh_prediction =
      sentinel_cpp_predict_scan_path(&mesh, &calm);
  assert(std::strcmp(mesh_prediction.predicted_identity, "mesh-heartbeat-drift") == 0);

  sentinel_behavior_matrix wireless_matrix =
      sentinel_cpp_behavior_matrix(&wireless, &calm);
  assert(std::strcmp(wireless_matrix.next_move, "local-radio-shield") == 0);

  sentinel_ambient_state mesh_state = sentinel_cpp_ambient_state(&mesh, &calm);
  assert(std::strcmp(mesh_state.ambient_state, "mesh-trust-pressure") == 0);

  sentinel_recovery_prediction mesh_recovery =
      sentinel_cpp_recovery_predictor(&mesh, &calm);
  assert(std::strcmp(mesh_recovery.mode, "mesh-heal") == 0);

#ifdef SENTINEL_NATIVE_HAS_ASM
  assert(sentinel_asm_load_balance_intensity(10, 10, 10, 10) == 100);
  assert(sentinel_asm_load_balance_intensity(92, 10, 10, 10) == 5);
  assert(sentinel_asm_micro_pacing_gap(
             SENTINEL_FRAGILITY_SENSITIVE, 86, 30, 0) >= 450);
  assert(sentinel_asm_heartbeat_guard_mode(0, 1, 0, 0) == 3);
  assert(sentinel_asm_guardian_mode(1, 1, 30, 0) == 1);
  assert(sentinel_asm_guardian_mode(0, 0, 92, 1) == 3);
  assert(sentinel_asm_mesh_gossip_ttl(95, 0, 0, 0) == 220);
  assert(sentinel_asm_mesh_gossip_ttl(40, 1, 1, 1) == 120);
#endif

  return 0;
}
