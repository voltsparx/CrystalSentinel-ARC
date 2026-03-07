#![forbid(unsafe_code)]

use sentinel_correlation::CorrelatedIncident;

#[derive(Clone, Debug)]
pub struct ReporterBundle {
    pub operator_report: String,
    pub forensic_report: String,
    pub human_report: String,
    pub teaching_report: String,
}

pub struct OperatorReporter;
pub struct ForensicReporter;
pub struct NarrativeReporter;
pub struct TeachingReporter;
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

impl TeachingReporter {
    pub fn render(incidents: &[CorrelatedIncident]) -> String {
        if incidents.is_empty() {
            return "CrystalSentinel Teaching Report\nEverything is calm right now. If something unusual happens later, I will explain it step by step.".to_string();
        }

        let mut sections = vec!["CrystalSentinel Teaching Report".to_string()];
        for incident in incidents {
            sections.push(format!("{}:", incident.incident_id));
            sections.push(format!("What we noticed: {}", noticed_line(incident)));
            sections.push(format!("What Sentinel did: {}", action_line(incident)));
            sections.push(format!("What this means: {}", meaning_line(incident)));
        }
        sections.join("\n")
    }
}

impl ReporterEngine {
    pub fn render_all(incidents: &[CorrelatedIncident]) -> ReporterBundle {
        ReporterBundle {
            operator_report: OperatorReporter::render(incidents),
            forensic_report: ForensicReporter::render(incidents),
            human_report: NarrativeReporter::render(incidents),
            teaching_report: TeachingReporter::render(incidents),
        }
    }
}

fn noticed_line(incident: &CorrelatedIncident) -> String {
    format!(
        "We saw {} behavior coming from {}. The main themes were {}.",
        incident.severity.as_str(),
        incident.primary_source,
        incident.families.join(", ")
    )
}

fn action_line(incident: &CorrelatedIncident) -> String {
    match incident.highest_stage.as_str() {
        "observe" => {
            "Sentinel watched closely, kept evidence, and avoided unnecessary disruption.".to_string()
        }
        "throttle" => {
            "Sentinel slowed the suspicious activity, preserved service continuity, and kept collecting context.".to_string()
        }
        "contain" => {
            "Sentinel contained the behavior, protected the surrounding system, and prepared the case for investigation.".to_string()
        }
        "isolate" => {
            "Sentinel isolated the risky workload or source to protect the rest of the environment while keeping a forensic trail.".to_string()
        }
        _ => {
            "Sentinel paused and asked for human approval before doing anything more disruptive.".to_string()
        }
    }
}

fn meaning_line(incident: &CorrelatedIncident) -> String {
    if incident.families.iter().any(|family| family == "data-exfiltration") {
        "This usually means sensitive data looked ready to leave the environment, so the system treated it seriously.".to_string()
    } else if incident.families.iter().any(|family| family == "integrity-attack") {
        "This means something tried to change or hook a trusted component, so Sentinel shifted toward self-protection and recovery.".to_string()
    } else if incident.families.iter().any(|family| family == "offensive-scan") {
        "This means someone was likely mapping the environment. Sentinel used that moment to watch carefully and reduce their certainty.".to_string()
    } else {
        "This is part of how Sentinel teaches while it protects: it explains the pattern, the response, and the safety tradeoff in plain language.".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{NarrativeReporter, ReporterEngine, TeachingReporter};
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
        assert!(bundle.teaching_report.contains("Teaching Report"));
    }

    #[test]
    fn teaching_report_explains_event_in_plain_language() {
        let report = TeachingReporter::render(&[sample_incident()]);

        assert!(report.contains("What we noticed:"));
        assert!(report.contains("What Sentinel did:"));
    }
}
