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

sentinel_native_result sentinel_c_resource_guard(const sentinel_native_event *event);
sentinel_native_budget sentinel_c_budget_window(
    const sentinel_native_event *event,
    const sentinel_resource_profile *profile);
sentinel_exposure_guard sentinel_c_exposure_guard(
    const sentinel_resource_profile *profile);
sentinel_protocol_budget sentinel_c_protocol_budget(
    const sentinel_native_event *event,
    const sentinel_resource_profile *profile);
sentinel_mesh_guard sentinel_c_mesh_guard(
    const sentinel_resource_profile *profile,
    uint16_t protected_nodes,
    uint16_t gentle_nodes);
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
uint64_t sentinel_asm_cycle_stamp(void);
uint16_t sentinel_asm_weighted_mix(uint16_t a, uint16_t b, uint16_t c);
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

#ifdef __cplusplus
}
#endif

#endif
