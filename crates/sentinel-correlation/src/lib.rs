#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use sentinel_common::MitigationStage;
use sentinel_response::ResponseAction;
use sentinel_runtime::RuntimeDecision;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl IncidentSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CorrelatedIncident {
    pub incident_id: String,
    pub primary_source: String,
    pub sources: Vec<String>,
    pub families: Vec<String>,
    pub recognitions: Vec<String>,
    pub recognition_labels: Vec<String>,
    pub recognition_protocols: Vec<String>,
    pub highest_stage: MitigationStage,
    pub severity: IncidentSeverity,
    pub prevailing_posture: String,
    pub stability_priority: bool,
    pub phantom_summary: Option<String>,
    pub recovery_summary: Option<String>,
    pub recovery_voice: Option<String>,
    pub timeline: Vec<String>,
    pub operator_summary: String,
    pub human_summary: String,
}

pub struct CorrelationEngine;

impl CorrelationEngine {
    pub fn correlate(decisions: &[RuntimeDecision]) -> Vec<CorrelatedIncident> {
        let mut buckets: BTreeMap<String, Vec<&RuntimeDecision>> = BTreeMap::new();

        for decision in decisions {
            buckets
                .entry(decision.assessment.signal.source_name.clone())
                .or_default()
                .push(decision);
        }

        buckets
            .into_iter()
            .enumerate()
            .map(|(index, (source, bucket))| correlate_bucket(index, source, bucket))
            .collect()
    }
}

fn correlate_bucket(
    index: usize,
    source: String,
    bucket: Vec<&RuntimeDecision>,
) -> CorrelatedIncident {
    let mut families = Vec::new();
    let mut recognitions = Vec::new();
    let mut recognition_labels = Vec::new();
    let mut recognition_protocols = Vec::new();
    let mut highest_stage = MitigationStage::Observe;
    let mut max_confidence = 0u8;
    let mut prevailing_posture = "baseline-observe".to_string();
    let mut stability_priority = false;
    let mut phantom_summary = None;
    let mut recovery_summary = None;
    let mut recovery_voice = None;
    let mut timeline = Vec::new();

    for (event_index, decision) in bucket.iter().enumerate() {
        let family = decision.assessment.signal.family.as_str().to_string();
        if !families.contains(&family) {
            families.push(family);
        }
        if let Some(recognition) = &decision.assessment.signal.recognition {
            if !recognitions.contains(&recognition.display_name) {
                recognitions.push(recognition.display_name.clone());
            }
            for label in &recognition.labels {
                if !recognition_labels.contains(label) {
                    recognition_labels.push(label.clone());
                }
            }
            for protocol in &recognition.protocols {
                if !recognition_protocols.contains(protocol) {
                    recognition_protocols.push(protocol.clone());
                }
            }
        }

        if decision.assessment.stage.rank() >= highest_stage.rank() {
            highest_stage = decision.assessment.stage;
            prevailing_posture = decision.posture.as_str().to_string();
        }

        max_confidence = max_confidence.max(decision.assessment.signal.confidence);
        stability_priority |= decision
            .plan
            .actions
            .contains(&ResponseAction::PreserveServiceContinuity);

        if phantom_summary.is_none() {
            phantom_summary = decision.decoy_plan.as_ref().and_then(|plan| {
                plan.phantom_observation.as_ref().map(|phantom| {
                    format!(
                        "bounded cadence_ms={} jitter_ms={} phase_offset_ms={} burst_slots={} decision_window_ms={} sample_budget={} goal={} sars_snapshot={}",
                        phantom.cadence_ms,
                        phantom.jitter_ms,
                        phantom.phase_offset_ms,
                        phantom.burst_slots,
                        phantom.decision_window_ms,
                        phantom.sample_budget,
                        phantom.evidence_goal.as_str(),
                        phantom.requires_sars_snapshot
                    )
                })
            });
        }
        if recovery_summary.is_none() {
            recovery_summary = decision
                .recovery_triage
                .as_ref()
                .map(|triage| triage.summary.clone());
        }
        if recovery_voice.is_none() {
            recovery_voice = decision
                .recovery_triage
                .as_ref()
                .map(|triage| triage.guardian_voice.clone());
        }

        let actions = decision
            .plan
            .actions
            .iter()
            .map(|action| action.as_str())
            .collect::<Vec<_>>()
            .join(", ");

        timeline.push(format!(
            "{}. family={} recognized={} labels={} posture={} stage={} fast_kind={} actions=[{}] decoy={} detail={} rationale={}",
            event_index + 1,
            decision.assessment.signal.family.as_str(),
            decision
                .assessment
                .signal
                .recognition
                .as_ref()
                .map(|recognition| recognition.display_name.as_str())
                .unwrap_or("none"),
            decision
                .assessment
                .signal
                .recognition
                .as_ref()
                .map(|recognition| recognition.labels.join(","))
                .unwrap_or_else(|| "none".to_string()),
            decision.posture.as_str(),
            decision.assessment.stage.as_str(),
            decision.fast_path.kind.as_str(),
            actions,
            decision
                .decoy_plan
                .as_ref()
                .map(|plan| plan.narrative.as_str())
                .unwrap_or("none"),
            decision.assessment.signal.detail,
            decision.assessment.rationale
        ));
    }

    let severity = severity_for(highest_stage, max_confidence);
    let family_list = families.join(", ");
    let human_summary = human_summary_for(
        &source,
        &family_list,
        recognitions.as_slice(),
        recognition_labels.as_slice(),
        prevailing_posture.as_str(),
        highest_stage,
        stability_priority,
        phantom_summary.as_deref(),
        recovery_voice.as_deref(),
    );
    let operator_summary = format!(
        "source={} severity={} stage={} posture={} stability_first={} families={} recognized={} labels={} protocols={} phantom={} recovery={} timeline_events={}",
        source,
        severity.as_str(),
        highest_stage.as_str(),
        prevailing_posture,
        stability_priority,
        family_list,
        if recognitions.is_empty() {
            "none".to_string()
        } else {
            recognitions.join(", ")
        },
        if recognition_labels.is_empty() {
            "none".to_string()
        } else {
            recognition_labels.join(", ")
        },
        if recognition_protocols.is_empty() {
            "none".to_string()
        } else {
            recognition_protocols.join(", ")
        },
        phantom_summary.as_deref().unwrap_or("none"),
        recovery_summary.as_deref().unwrap_or("none"),
        timeline.len()
    );

    CorrelatedIncident {
        incident_id: format!("incident-{:04}", index + 1),
        primary_source: source.clone(),
        sources: vec![source],
        families,
        recognitions,
        recognition_labels,
        recognition_protocols,
        highest_stage,
        severity,
        prevailing_posture,
        stability_priority,
        phantom_summary,
        recovery_summary,
        recovery_voice,
        timeline,
        operator_summary,
        human_summary,
    }
}

fn severity_for(stage: MitigationStage, max_confidence: u8) -> IncidentSeverity {
    match stage {
        MitigationStage::Isolate => IncidentSeverity::Critical,
        MitigationStage::Contain => IncidentSeverity::High,
        MitigationStage::Throttle => IncidentSeverity::Medium,
        MitigationStage::Observe | MitigationStage::OperatorApproval => {
            if max_confidence >= 85 {
                IncidentSeverity::Medium
            } else {
                IncidentSeverity::Low
            }
        }
    }
}

fn human_summary_for(
    source: &str,
    families: &str,
    recognitions: &[String],
    recognition_labels: &[String],
    posture: &str,
    stage: MitigationStage,
    stability_priority: bool,
    phantom_summary: Option<&str>,
    recovery_voice: Option<&str>,
) -> String {
    let recognition_line = if recognitions.is_empty() {
        String::new()
    } else {
        format!(
            " It was recognized as {} with labels {}.",
            recognitions.join(", "),
            recognition_labels.join(", ")
        )
    };
    let stability_line = if stability_priority {
        " It kept service stability ahead of aggressive action."
    } else {
        ""
    };
    let phantom_line = phantom_summary
        .map(|summary| format!(" Phantom-Scan stayed active with {}.", summary))
        .unwrap_or_default();
    let recovery_line = recovery_voice
        .map(|voice| format!(" {}", voice))
        .unwrap_or_default();

    format!(
        "Source {source} showed behavior consistent with {families}. CrystalSentinel-CRA interpreted it with the {posture} posture and ended at the {stage} response stage, preserving evidence for investigation and later review.{recognition_line}{stability_line}{phantom_line}{recovery_line}",
        stage = stage.as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::{CorrelationEngine, IncidentSeverity};
    use sentinel_common::{HealthSnapshot, TelemetryKind};
    use sentinel_config::RuntimeConfig;
    use sentinel_runtime::SentinelRuntime;
    use sentinel_telemetry::TelemetryEvent;

    #[test]
    fn groups_multiple_decisions_by_source() {
        let runtime = SentinelRuntime::default();
        let config = RuntimeConfig::default();
        let scan = runtime.process_event(
            &config,
            &TelemetryEvent {
                kind: TelemetryKind::Packet,
                source: "203.0.113.88".to_string(),
                summary: "syn probe recon fingerprint".to_string(),
                health: HealthSnapshot::default(),
            },
        );
        let follow_up = runtime.process_event(
            &config,
            &TelemetryEvent {
                kind: TelemetryKind::Packet,
                source: "203.0.113.88".to_string(),
                summary: "payload stage_loader".to_string(),
                health: HealthSnapshot::default(),
            },
        );

        let incidents = CorrelationEngine::correlate(&[scan, follow_up]);

        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].timeline.len(), 2);
        assert!(incidents[0].families.len() >= 2);
        assert!(incidents[0].stability_priority);
    }

    #[test]
    fn isolate_stage_maps_to_critical_incident() {
        let runtime = SentinelRuntime::default();
        let config = RuntimeConfig::default();
        let flood = runtime.process_event(
            &config,
            &TelemetryEvent {
                kind: TelemetryKind::Flow,
                source: "198.51.100.44".to_string(),
                summary: "burst_flood ddos pps_spike".to_string(),
                health: HealthSnapshot::default(),
            },
        );

        let incidents = CorrelationEngine::correlate(&[flood]);

        assert_eq!(incidents[0].severity, IncidentSeverity::Critical);
    }
}
