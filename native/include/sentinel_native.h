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

typedef struct sentinel_native_result {
  const char *layer;
  const char *decision;
  uint8_t adjusted_confidence;
} sentinel_native_result;

sentinel_native_result sentinel_c_resource_guard(const sentinel_native_event *event);
sentinel_native_result sentinel_cpp_classify(const sentinel_native_event *event);
uint64_t sentinel_asm_cycle_stamp(void);

#ifdef __cplusplus
}
#endif

#endif

