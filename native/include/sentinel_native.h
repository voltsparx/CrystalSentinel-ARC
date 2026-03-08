#ifndef SENTINEL_NATIVE_H
#define SENTINEL_NATIVE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sentinel_native_event {
  const char *source;
  const char *summary;
  uint8_t confidence;
} sentinel_native_event;

typedef enum sentinel_fragility_level {
  SENTINEL_FRAGILITY_STABLE = 0,
  SENTINEL_FRAGILITY_SENSITIVE = 1,
  SENTINEL_FRAGILITY_CRITICAL = 2
} sentinel_fragility_level;

typedef struct sentinel_resource_profile {
  uint8_t cpu_load_pct;
  uint8_t memory_load_pct;
  uint8_t thermal_c;
  uint8_t passive_only;
  sentinel_fragility_level fragility;
} sentinel_resource_profile;

typedef struct sentinel_native_result {
  const char *layer;
  const char *decision;
  uint8_t adjusted_confidence;
} sentinel_native_result;

typedef struct sentinel_native_budget {
  const char *layer;
  const char *profile;
  const char *guardrail;
  uint16_t observation_window_ms;
  uint8_t decoy_cap;
  uint8_t phantom_budget;
  uint8_t automation_limited;
} sentinel_native_budget;

typedef struct sentinel_exposure_guard {
  const char *layer;
  const char *mode;
  uint8_t exposure_reduction_pct;
  uint8_t pause_nonessential_decoys;
  uint8_t keep_minimum_observation;
  uint16_t resume_standby_after_ms;
} sentinel_exposure_guard;

typedef struct sentinel_protocol_budget {
  const char *layer;
  const char *protocol_family;
  const char *mode;
  uint16_t observation_window_ms;
  uint8_t decoy_cap;
  uint8_t preserve_gentle_assets;
} sentinel_protocol_budget;

typedef struct sentinel_mesh_guard {
  const char *layer;
  const char *mode;
  uint16_t protected_nodes;
  uint16_t gentle_nodes;
  uint8_t max_parallel_actions;
  uint8_t pause_nonessential_decoys;
} sentinel_mesh_guard;

typedef struct sentinel_load_balance_plan {
  const char *layer;
  const char *mode;
  uint8_t chaff_intensity_pct;
  uint8_t mirror_intensity_pct;
  uint16_t micro_pacing_gap_us;
  uint16_t background_burst_cap;
  uint8_t heartbeat_only;
  uint8_t protect_local_apps;
} sentinel_load_balance_plan;

typedef struct sentinel_mesh_heartbeat_audit {
  const char *layer;
  const char *status;
  const char *trust_mode;
  uint16_t heartbeat_interval_ms;
  uint16_t observed_jitter_us;
  uint8_t quarantine_peer;
  uint8_t shift_guardian_coverage;
  uint8_t ghost_mode_bias;
} sentinel_mesh_heartbeat_audit;

typedef struct sentinel_guardian_handoff {
  const char *layer;
  const char *mode;
  uint8_t adoption_budget;
  uint8_t clean_forward_only;
  uint8_t handoff_ready;
  uint8_t preserve_fragile_paths;
  uint8_t surrogate_load_pct;
} sentinel_guardian_handoff;

typedef struct sentinel_scan_prediction {
  const char *layer;
  const char *predicted_identity;
  const char *predicted_family;
  const char *recommended_posture;
  uint16_t decision_window_ms;
  uint8_t confidence;
  uint8_t prefers_recon_friction;
  uint8_t prefers_phantom_focus;
  uint8_t protect_fragile_assets;
} sentinel_scan_prediction;

typedef struct sentinel_ambient_state {
  const char *layer;
  const char *ambient_state;
  const char *recommended_mode;
  uint16_t observation_window_ms;
  uint8_t pressure_bias;
  uint8_t decoy_budget;
} sentinel_ambient_state;

typedef struct sentinel_behavior_matrix {
  const char *layer;
  const char *predicted_identity;
  const char *next_move;
  const char *evidence_goal;
  uint8_t confidence;
  uint8_t prefers_decoy_first;
  uint8_t protect_fragile_assets;
} sentinel_behavior_matrix;

typedef struct sentinel_recovery_prediction {
  const char *layer;
  const char *mode;
  const char *reason;
  uint16_t quiet_window_ms;
  uint8_t keep_minimum_observation;
  uint8_t reduce_exposure_pct;
} sentinel_recovery_prediction;

typedef struct sentinel_mesh_gossip_plan {
  const char *layer;
  const char *mode;
  uint8_t share_hostile_observation;
  uint8_t tighten_trust;
  uint8_t open_shadow_gateway;
  uint8_t consensus_quorum;
  uint16_t evidence_ttl_ms;
} sentinel_mesh_gossip_plan;

typedef struct sentinel_guardian_report {
  const char *layer;
  const char *health_voice;
  const char *threat_voice;
  const char *mesh_voice;
  const char *operator_hint;
  uint8_t severity;
} sentinel_guardian_report;

sentinel_native_result sentinel_c_resource_guard(const sentinel_native_event *event);
sentinel_native_budget sentinel_c_budget_window(
    const sentinel_native_event *event,
    const sentinel_resource_profile *profile);
sentinel_exposure_guard sentinel_c_exposure_guard(
    const sentinel_resource_profile *profile);
sentinel_protocol_budget sentinel_c_protocol_budget(
    const sentinel_native_event *event,
    const sentinel_resource_profile *profile);
sentinel_load_balance_plan sentinel_c_dynamic_load_balancer(
    const sentinel_resource_profile *profile,
    uint8_t gpu_load_pct,
    uint8_t link_pressure_pct,
    uint8_t queue_fill_pct);
sentinel_mesh_guard sentinel_c_mesh_guard(
    const sentinel_resource_profile *profile,
    uint16_t protected_nodes,
    uint16_t gentle_nodes);
sentinel_mesh_heartbeat_audit sentinel_c_mesh_heartbeat_audit(
    const sentinel_resource_profile *profile,
    uint8_t missing_peers,
    uint8_t malformed_peers,
    uint16_t jitter_us);
sentinel_guardian_handoff sentinel_c_guardian_handoff(
    const sentinel_resource_profile *profile,
    uint16_t protected_nodes,
    uint16_t gentle_nodes,
    uint8_t peer_capacity_pct,
    uint8_t peer_distress);
sentinel_native_result sentinel_cpp_classify(const sentinel_native_event *event);
sentinel_scan_prediction sentinel_cpp_predict_scan_path(
    const sentinel_native_event *event,
    const sentinel_resource_profile *profile);
sentinel_ambient_state sentinel_cpp_ambient_state(
    const sentinel_native_event *event,
    const sentinel_resource_profile *profile);
sentinel_behavior_matrix sentinel_cpp_behavior_matrix(
    const sentinel_native_event *event,
    const sentinel_resource_profile *profile);
sentinel_recovery_prediction sentinel_cpp_recovery_predictor(
    const sentinel_native_event *event,
    const sentinel_resource_profile *profile);
sentinel_mesh_gossip_plan sentinel_cpp_mesh_gossip(
    const sentinel_native_event *event,
    const sentinel_resource_profile *profile,
    const sentinel_mesh_heartbeat_audit *heartbeat,
    const sentinel_guardian_handoff *guardian);
sentinel_guardian_report sentinel_cpp_guardian_report(
    const sentinel_native_event *event,
    const sentinel_resource_profile *profile,
    const sentinel_load_balance_plan *load_balance,
    const sentinel_mesh_heartbeat_audit *heartbeat);
uint64_t sentinel_asm_cycle_stamp(void);
uint16_t sentinel_asm_weighted_mix(uint16_t a, uint16_t b, uint16_t c);
uint16_t sentinel_asm_weighted_mix4(
    uint16_t a,
    uint16_t b,
    uint16_t c,
    uint16_t d);
uint8_t sentinel_asm_pressure_mode(
    uint16_t scan_score,
    uint16_t intrusion_score,
    uint16_t ddos_score,
    uint8_t cpu_load_pct,
    uint8_t memory_load_pct,
    uint8_t thermal_c);
uint16_t sentinel_asm_observation_window(
    uint8_t mode,
    uint8_t cpu_load_pct,
    uint8_t memory_load_pct,
    uint8_t thermal_c);
uint8_t sentinel_asm_decoy_budget(
    uint8_t mode,
    uint8_t cpu_load_pct,
    uint8_t memory_load_pct,
    uint8_t thermal_c);
uint8_t sentinel_asm_evidence_budget(
    uint8_t mode,
    uint8_t overall_score,
    uint8_t dominance_margin,
    uint8_t kinetic_score);
uint8_t sentinel_asm_phantom_jitter(
    uint8_t mode,
    uint8_t kinetic_score,
    uint8_t dominance_margin,
    uint8_t resource_pressure);
uint8_t sentinel_asm_guard_bias(
    uint8_t mode,
    uint8_t overall_score,
    uint8_t dominance_margin,
    uint8_t criticality);
uint8_t sentinel_asm_load_balance_intensity(
    uint8_t cpu_load_pct,
    uint8_t gpu_load_pct,
    uint8_t link_pressure_pct,
    uint8_t queue_fill_pct);
uint16_t sentinel_asm_micro_pacing_gap(
    uint8_t fragility,
    uint8_t queue_fill_pct,
    uint8_t link_pressure_pct,
    uint8_t passive_only);
uint8_t sentinel_asm_heartbeat_guard_mode(
    uint8_t missing_peers,
    uint8_t malformed_peers,
    uint16_t jitter_us,
    uint8_t passive_only);
uint8_t sentinel_asm_guardian_mode(
    uint16_t protected_nodes,
    uint16_t gentle_nodes,
    uint8_t cpu_load_pct,
    uint8_t passive_only);
uint16_t sentinel_asm_mesh_gossip_ttl(
    uint8_t confidence,
    uint8_t integrity_event,
    uint8_t mesh_pressure,
    uint8_t shadow_gateway);

#ifdef __cplusplus
}
#endif

#endif
