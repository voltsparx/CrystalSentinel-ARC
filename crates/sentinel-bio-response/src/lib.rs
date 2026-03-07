#![forbid(unsafe_code)]

use sentinel_common::{HealthSnapshot, MitigationStage};

#[derive(Default)]
pub struct BioResponseGuard;

impl BioResponseGuard {
    pub fn cap_stage(
        &self,
        health: &HealthSnapshot,
        requested: MitigationStage,
    ) -> MitigationStage {
        if health.passive_only {
            return MitigationStage::Observe;
        }

        if health.thermal_c >= 90 || health.cpu_load_pct >= 95 {
            return requested.least_aggressive(MitigationStage::Throttle);
        }

        if health.memory_load_pct >= 90 {
            return requested.least_aggressive(MitigationStage::Contain);
        }

        requested
    }
}

#[cfg(test)]
mod tests {
    use super::BioResponseGuard;
    use sentinel_common::{HealthSnapshot, MitigationStage};

    #[test]
    fn caps_to_observe_in_passive_mode() {
        let guard = BioResponseGuard;
        let health = HealthSnapshot {
            passive_only: true,
            ..HealthSnapshot::default()
        };

        assert_eq!(
            guard.cap_stage(&health, MitigationStage::Isolate),
            MitigationStage::Observe
        );
    }
}
