#![forbid(unsafe_code)]

use sentinel_bio_response::BioResponseGuard;
use sentinel_common::{AttackFamily, HealthSnapshot, MitigationStage, ThreatAssessment, ThreatSignal};

#[derive(Default)]
pub struct PolicyEngine {
    bio_guard: BioResponseGuard,
}

impl PolicyEngine {
    pub fn assess(&self, signal: ThreatSignal, health: HealthSnapshot) -> ThreatAssessment {
        let requested_stage = self.base_stage_for(&signal);
        let stage = self.bio_guard.cap_stage(&health, requested_stage);
        let rationale = format!(
            "family={} confidence={} requested={} applied={}",
            signal.family.as_str(),
            signal.confidence,
            requested_stage.as_str(),
            stage.as_str()
        );

        ThreatAssessment {
            signal,
            stage,
            rationale,
        }
    }

    fn base_stage_for(&self, signal: &ThreatSignal) -> MitigationStage {
        match signal.family {
            AttackFamily::OffensiveScan => MitigationStage::Throttle,
            AttackFamily::VolumetricFlood | AttackFamily::IntegrityAttack => MitigationStage::Isolate,
            AttackFamily::DnsTunneling | AttackFamily::DataExfiltration | AttackFamily::IdentityAbuse => {
                MitigationStage::Contain
            }
            AttackFamily::PayloadStager
            | AttackFamily::ExploitDelivery
            | AttackFamily::RemoteAccessTrojan
            | AttackFamily::Beaconing => MitigationStage::Throttle,
            AttackFamily::ApiScraping => MitigationStage::Observe,
            AttackFamily::Unknown => {
                if signal.confidence >= 90 {
                    MitigationStage::Throttle
                } else {
                    MitigationStage::Observe
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PolicyEngine;
    use sentinel_common::{AttackFamily, HealthSnapshot, ThreatSignal};

    #[test]
    fn high_heat_caps_isolation() {
        let engine = PolicyEngine::default();
        let signal = ThreatSignal {
            source_name: "198.51.100.10".to_string(),
            family: AttackFamily::VolumetricFlood,
            confidence: 99,
            detail: "burst".to_string(),
        };
        let assessment = engine.assess(
            signal,
            HealthSnapshot {
                cpu_load_pct: 96,
                ..HealthSnapshot::default()
            },
        );

        assert_eq!(assessment.stage.as_str(), "throttle");
    }
}
