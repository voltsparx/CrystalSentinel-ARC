#![forbid(unsafe_code)]

use sentinel_correlation::CorrelatedIncident;

#[derive(Clone, Debug)]
pub struct ReporterBundle {
    pub operator_report: String,
    pub forensic_report: String,
    pub human_report: String,
}

pub struct OperatorReporter;
pub struct ForensicReporter;
pub struct NarrativeReporter;
pub struct ReporterEngine;

impl OperatorReporter {
    pub fn render(incidents: &[CorrelatedIncident]) -> String {
        if incidents.is_empty() {
            return "CrystalSentinel Operator Report\nNo correlated incidents were found.".to_string();
        }

        let mut lines = vec!["CrystalSentinel Operator Report".to_string()];
        for incident in incidents {
            lines.push(format!(
                "- {} {}",
                incident.incident_id, incident.operator_summary
            ));
        }
        lines.join("\n")
    }
}

impl ForensicReporter {
    pub fn render(incidents: &[CorrelatedIncident]) -> String {
        if incidents.is_empty() {
            return "CrystalSentinel Forensic Report\nNo evidence bundles were produced.".to_string();
        }

        let mut sections = vec!["CrystalSentinel Forensic Report".to_string()];
        for incident in incidents {
            sections.push(format!(
                "[{}] source={} stage={} severity={}",
                incident.incident_id,
                incident.primary_source,
                incident.highest_stage.as_str(),
                incident.severity.as_str()
            ));
            sections.push(format!("families={}", incident.families.join(", ")));
            for item in &incident.timeline {
                sections.push(format!("timeline {}", item));
            }
        }
        sections.join("\n")
    }
}

impl NarrativeReporter {
    pub fn render(incidents: &[CorrelatedIncident]) -> String {
        if incidents.is_empty() {
            return "CrystalSentinel Human Report\nNothing suspicious required a human explanation.".to_string();
        }

        let mut paragraphs = vec!["CrystalSentinel Human Report".to_string()];
        for incident in incidents {
            paragraphs.push(format!(
                "{}: {}",
                incident.incident_id, incident.human_summary
            ));
        }
        paragraphs.join("\n")
    }
}

impl ReporterEngine {
    pub fn render_all(incidents: &[CorrelatedIncident]) -> ReporterBundle {
        ReporterBundle {
            operator_report: OperatorReporter::render(incidents),
            forensic_report: ForensicReporter::render(incidents),
            human_report: NarrativeReporter::render(incidents),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{NarrativeReporter, ReporterEngine};
    use sentinel_correlation::{CorrelatedIncident, IncidentSeverity};
    use sentinel_common::MitigationStage;

    fn sample_incident() -> CorrelatedIncident {
        CorrelatedIncident {
            incident_id: "incident-0001".to_string(),
            primary_source: "203.0.113.88".to_string(),
            sources: vec!["203.0.113.88".to_string()],
            families: vec!["offensive-scan".to_string()],
            highest_stage: MitigationStage::Throttle,
            severity: IncidentSeverity::Medium,
            prevailing_posture: "decoy-first-capture".to_string(),
            timeline: vec!["1. family=offensive-scan".to_string()],
            operator_summary: "source=203.0.113.88 severity=medium".to_string(),
            human_summary: "Source 203.0.113.88 looked like reconnaissance.".to_string(),
        }
    }

    #[test]
    fn narrative_report_uses_human_summary() {
        let report = NarrativeReporter::render(&[sample_incident()]);

        assert!(report.contains("reconnaissance"));
    }

    #[test]
    fn reporter_engine_builds_all_views() {
        let bundle = ReporterEngine::render_all(&[sample_incident()]);

        assert!(bundle.operator_report.contains("Operator Report"));
        assert!(bundle.forensic_report.contains("Forensic Report"));
        assert!(bundle.human_report.contains("Human Report"));
    }
}
