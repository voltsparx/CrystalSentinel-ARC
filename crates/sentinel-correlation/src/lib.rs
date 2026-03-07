#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use sentinel_common::MitigationStage;
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
    pub highest_stage: MitigationStage,
    pub severity: IncidentSeverity,
    pub prevailing_posture: String,
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

fn correlate_bucket(index: usize, source: String, bucket: Vec<&RuntimeDecision>) -> CorrelatedIncident {
    let mut families = Vec::new();
    let mut highest_stage = MitigationStage::Observe;
    let mut max_confidence = 0u8;
    let mut prevailing_posture = "baseline-observe".to_string();
    let mut timeline = Vec::new();

    for (event_index, decision) in bucket.iter().enumerate() {
        let family = decision.assessment.signal.family.as_str().to_string();
        if !families.contains(&family) {
            families.push(family);
        }

        if decision.assessment.stage.rank() >= highest_stage.rank() {
            highest_stage = decision.assessment.stage;
            prevailing_posture = decision.posture.as_str().to_string();
        }

        max_confidence = max_confidence.max(decision.assessment.signal.confidence);

        let actions = decision
            .plan
            .actions
            .iter()
            .map(|action| action.as_str())
            .collect::<Vec<_>>()
            .join(", ");

        timeline.push(format!(
            "{}. family={} posture={} stage={} fast_kind={} actions=[{}] detail={} rationale={}",
            event_index + 1,
            decision.assessment.signal.family.as_str(),
            decision.posture.as_str(),
            decision.assessment.stage.as_str(),
            decision.fast_path.kind.as_str(),
            actions,
            decision.assessment.signal.detail,
            decision.assessment.rationale
        ));
    }

    let severity = severity_for(highest_stage, max_confidence);
    let family_list = families.join(", ");
    let human_summary = human_summary_for(&source, &family_list, prevailing_posture.as_str(), highest_stage);
    let operator_summary = format!(
        "source={} severity={} stage={} posture={} families={} timeline_events={}",
        source,
        severity.as_str(),
        highest_stage.as_str(),
        prevailing_posture,
        family_list,
        timeline.len()
    );

    CorrelatedIncident {
        incident_id: format!("incident-{:04}", index + 1),
        primary_source: source.clone(),
        sources: vec![source],
        families,
        highest_stage,
        severity,
        prevailing_posture,
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

fn human_summary_for(source: &str, families: &str, posture: &str, stage: MitigationStage) -> String {
    format!(
        "Source {source} showed behavior consistent with {families}. CrystalSentinel-CRA interpreted it with the {posture} posture and ended at the {stage} response stage, preserving evidence for investigation and later review.",
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
