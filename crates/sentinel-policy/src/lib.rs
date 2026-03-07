#![forbid(unsafe_code)]

use sentinel_bio_response::BioResponseGuard;
use sentinel_common::{
    AttackFamily, HealthSnapshot, MitigationStage, ThreatAssessment, ThreatSignal,
};

#[derive(Default)]
pub struct PolicyEngine {
    bio_guard: BioResponseGuard,
}

impl PolicyEngine {
    pub fn assess(&self, signal: ThreatSignal, health: HealthSnapshot) -> ThreatAssessment {
        let requested_stage = self.base_stage_for(&signal);
        let stage = self.bio_guard.cap_stage(&health, requested_stage);
        let rationale = format!(
            "family={} confidence={} lanes={} requested={} applied={}",
            signal.family.as_str(),
            signal.confidence,
            if signal.analysis_lanes.is_empty() {
                "none".to_string()
            } else {
                signal.analysis_lanes.join(",")
            },
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
        let lane_count = signal.analysis_lanes.len();
        let has_label = |needle: &str| {
            signal
                .recognition
                .as_ref()
                .map(|recognition| recognition.labels.iter().any(|label| label == needle))
                .unwrap_or(false)
        };

        match signal.family {
            AttackFamily::OffensiveScan => {
                if lane_count >= 3
                    && signal.confidence >= 93
                    && (has_label("high_speed_scan")
                        || has_label("asynchronous_sweep")
                        || has_label("service_fingerprint")
                        || has_label("version_probe"))
                {
                    MitigationStage::Contain
                } else {
                    MitigationStage::Throttle
                }
            }
            AttackFamily::VolumetricFlood | AttackFamily::IntegrityAttack => {
                MitigationStage::Isolate
            }
            AttackFamily::DnsTunneling
            | AttackFamily::DataExfiltration
            | AttackFamily::IdentityAbuse => MitigationStage::Contain,
            AttackFamily::PayloadStager
            | AttackFamily::ExploitDelivery
            | AttackFamily::Beaconing => {
                if signal.confidence >= 92 || lane_count >= 3 {
                    MitigationStage::Contain
                } else {
                    MitigationStage::Throttle
                }
            }
            AttackFamily::RemoteAccessTrojan => {
                if signal
                    .recognition
                    .as_ref()
                    .map(|recognition| {
                        recognition.labels.iter().any(|label| {
                            matches!(
                                label.as_str(),
                                "reverse_shell" | "interactive_shell" | "command_channel"
                            )
                        })
                    })
                    .unwrap_or(false)
                    || lane_count >= 3
                    || signal.confidence >= 90
                {
                    MitigationStage::Contain
                } else {
                    MitigationStage::Throttle
                }
            }
            AttackFamily::ApiScraping => MitigationStage::Observe,
            AttackFamily::Unknown => {
                if signal.confidence >= 90 || (lane_count >= 3 && signal.confidence >= 80) {
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
    use sentinel_common::{AttackFamily, HealthSnapshot, ThreatRecognition, ThreatSignal};

    #[test]
    fn high_heat_caps_isolation() {
        let engine = PolicyEngine::default();
        let signal = ThreatSignal {
            source_name: "198.51.100.10".to_string(),
            family: AttackFamily::VolumetricFlood,
            confidence: 99,
            recognition: None,
            analysis_lanes: vec!["asm-fast-path".to_string()],
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

    #[test]
    fn high_confidence_payload_stager_moves_to_contain() {
        let engine = PolicyEngine::default();
        let signal = ThreatSignal {
            source_name: "198.51.100.11".to_string(),
            family: AttackFamily::PayloadStager,
            confidence: 96,
            recognition: None,
            analysis_lanes: vec![
                "asm-fast-path".to_string(),
                "heuristic".to_string(),
                "transport-intelligence".to_string(),
            ],
            detail: "stage loader".to_string(),
        };

        let assessment = engine.assess(signal, HealthSnapshot::default());

        assert_eq!(assessment.stage.as_str(), "contain");
    }

    #[test]
    fn reverse_shell_label_moves_remote_access_to_contain() {
        let engine = PolicyEngine::default();
        let signal = ThreatSignal {
            source_name: "198.51.100.12".to_string(),
            family: AttackFamily::RemoteAccessTrojan,
            confidence: 82,
            recognition: Some(ThreatRecognition {
                identity: "heuristic-interactive-reverse-shell".to_string(),
                display_name: "Interactive Reverse Shell Pattern".to_string(),
                category: "interactive-reverse-shell".to_string(),
                labels: vec!["reverse_shell".to_string(), "interactive_shell".to_string()],
                protocols: vec!["tcp".to_string()],
                sources: vec!["heuristic".to_string()],
                summary: "interactive shell".to_string(),
            }),
            analysis_lanes: vec![
                "asm-fast-path".to_string(),
                "heuristic".to_string(),
                "intrusion-model".to_string(),
            ],
            detail: "reverse shell".to_string(),
        };

        let assessment = engine.assess(signal, HealthSnapshot::default());

        assert_eq!(assessment.stage.as_str(), "contain");
    }

    #[test]
    fn high_speed_scan_with_multi_lane_concurrence_moves_to_contain() {
        let engine = PolicyEngine::default();
        let signal = ThreatSignal {
            source_name: "198.51.100.13".to_string(),
            family: AttackFamily::OffensiveScan,
            confidence: 95,
            recognition: Some(ThreatRecognition {
                identity: "research-high-speed-asynchronous-scan".to_string(),
                display_name: "High-Speed Asynchronous Scan Pattern".to_string(),
                category: "high-speed-recon".to_string(),
                labels: vec![
                    "scan".to_string(),
                    "high_speed_scan".to_string(),
                    "asynchronous_sweep".to_string(),
                ],
                protocols: vec!["tcp".to_string()],
                sources: vec!["heuristic".to_string(), "research".to_string()],
                summary: "high-speed reconnaissance".to_string(),
            }),
            analysis_lanes: vec![
                "asm-fast-path".to_string(),
                "heuristic".to_string(),
                "behavioral-research".to_string(),
                "recon-model".to_string(),
            ],
            detail: "high-speed scan".to_string(),
        };

        let assessment = engine.assess(signal, HealthSnapshot::default());

        assert_eq!(assessment.stage.as_str(), "contain");
    }
}
