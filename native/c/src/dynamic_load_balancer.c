#include "sentinel_native.h"

static uint8_t hottest_load(const sentinel_resource_profile *profile,
                            uint8_t gpu_load_pct,
                            uint8_t link_pressure_pct,
                            uint8_t queue_fill_pct) {
  uint8_t hottest = 0;

  if (profile != 0) {
    if (profile->cpu_load_pct > hottest) {
      hottest = profile->cpu_load_pct;
    }
    if (profile->memory_load_pct > hottest) {
      hottest = profile->memory_load_pct;
    }
    if (profile->thermal_c > hottest) {
      hottest = profile->thermal_c;
    }
  }

  if (gpu_load_pct > hottest) {
    hottest = gpu_load_pct;
  }
  if (link_pressure_pct > hottest) {
    hottest = link_pressure_pct;
  }
  if (queue_fill_pct > hottest) {
    hottest = queue_fill_pct;
  }

  return hottest;
}

sentinel_load_balance_plan sentinel_c_dynamic_load_balancer(
    const sentinel_resource_profile *profile,
    uint8_t gpu_load_pct,
    uint8_t link_pressure_pct,
    uint8_t queue_fill_pct) {
  sentinel_load_balance_plan plan;
  uint8_t pressure = hottest_load(profile, gpu_load_pct, link_pressure_pct, queue_fill_pct);

  plan.layer = "c";
  plan.mode = "full-spectrum";
  plan.chaff_intensity_pct = 100;
  plan.mirror_intensity_pct = 100;
  plan.micro_pacing_gap_us = 40;
  plan.background_burst_cap = 1024;
  plan.heartbeat_only = 0;
  plan.protect_local_apps = 1;

  if (profile == 0) {
    plan.mode = "invalid-profile";
    plan.chaff_intensity_pct = 0;
    plan.mirror_intensity_pct = 0;
    plan.micro_pacing_gap_us = 1000;
    plan.background_burst_cap = 0;
    plan.heartbeat_only = 1;
    return plan;
  }

  if (profile->passive_only || profile->fragility == SENTINEL_FRAGILITY_CRITICAL ||
      pressure >= 90) {
    plan.mode = "heartbeat-only";
    plan.chaff_intensity_pct = 5;
    plan.mirror_intensity_pct = 0;
    plan.micro_pacing_gap_us = 900;
    plan.background_burst_cap = 16;
    plan.heartbeat_only = 1;
    return plan;
  }

  if (profile->fragility == SENTINEL_FRAGILITY_SENSITIVE || pressure >= 78) {
    plan.mode = "protect-local-apps";
    plan.chaff_intensity_pct = 20;
    plan.mirror_intensity_pct = 10;
    plan.micro_pacing_gap_us = 300;
    plan.background_burst_cap = 96;
  } else if (pressure >= 65) {
    plan.mode = "recoil";
    plan.chaff_intensity_pct = 40;
    plan.mirror_intensity_pct = 25;
    plan.micro_pacing_gap_us = 180;
    plan.background_burst_cap = 256;
  }

  if (link_pressure_pct >= 80 || queue_fill_pct >= 85) {
    plan.mode = "micro-paced";
    if (plan.chaff_intensity_pct > 15) {
      plan.chaff_intensity_pct = 15;
    }
    if (plan.mirror_intensity_pct > 10) {
      plan.mirror_intensity_pct = 10;
    }
    plan.micro_pacing_gap_us = 450;
    plan.background_burst_cap = 48;
  }

  if (profile->fragility == SENTINEL_FRAGILITY_SENSITIVE &&
      plan.micro_pacing_gap_us < 500) {
    plan.micro_pacing_gap_us = 500;
  }

  return plan;
}
