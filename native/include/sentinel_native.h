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

sentinel_native_result sentinel_c_resource_guard(const sentinel_native_event *event);
sentinel_native_budget sentinel_c_budget_window(
    const sentinel_native_event *event,
    const sentinel_resource_profile *profile);
sentinel_native_result sentinel_cpp_classify(const sentinel_native_event *event);
sentinel_scan_prediction sentinel_cpp_predict_scan_path(
    const sentinel_native_event *event,
    const sentinel_resource_profile *profile);
uint64_t sentinel_asm_cycle_stamp(void);

#ifdef __cplusplus
}
#endif

#endif
