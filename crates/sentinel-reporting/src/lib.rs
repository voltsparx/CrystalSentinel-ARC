#![forbid(unsafe_code)]

use sentinel_correlation::CorrelatedIncident;

#[derive(Clone, Debug)]
pub struct ReporterBundle {
    pub operator_report: String,
    pub forensic_report: String,
    pub human_report: String,
    pub teaching_report: String,
    pub care_report: String,
}

pub struct OperatorReporter;
pub struct ForensicReporter;
pub struct NarrativeReporter;
pub struct TeachingReporter;
pub struct CareReporter;
pub struct ReporterEngine;

impl OperatorReporter {
    pub fn render(incidents: &[CorrelatedIncident]) -> String {
        if incidents.is_empty() {
            return "CrystalSentinel Operator Report\nNo correlated incidents were found."
                .to_string();
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
            return "CrystalSentinel Forensic Report\nNo evidence bundles were produced."
                .to_string();
        }

        let mut sections = vec!["CrystalSentinel Forensic Report".to_string()];
        for incident in incidents {
            sections.push(format!(
                "[{}] source={} stage={} severity={} stability_first={}",
                incident.incident_id,
                incident.primary_source,
                incident.highest_stage.as_str(),
                incident.severity.as_str(),
                incident.stability_priority
            ));
            sections.push(format!("families={}", incident.families.join(", ")));
            sections.push(format!(
                "recognized={}",
                if incident.recognitions.is_empty() {
                    "none".to_string()
                } else {
                    incident.recognitions.join(", ")
                }
            ));
            sections.push(format!(
                "labels={}",
                if incident.recognition_labels.is_empty() {
                    "none".to_string()
                } else {
                    incident.recognition_labels.join(", ")
                }
            ));
            sections.push(format!(
                "protocols={}",
                if incident.recognition_protocols.is_empty() {
                    "none".to_string()
                } else {
                    incident.recognition_protocols.join(", ")
                }
            ));
            sections.push(format!(
                "phantom={}",
                incident.phantom_summary.as_deref().unwrap_or("none")
            ));
            sections.push(format!(
                "recovery={}",
                incident.recovery_summary.as_deref().unwrap_or("none")
            ));
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

impl CareReporter {
    pub fn render(incidents: &[CorrelatedIncident]) -> String {
        if incidents.is_empty() {
            return "CrystalSentinel Care Report\nThe system is calm. If anything changes, Sentinel will explain it clearly and tell you whether any action is needed.".to_string();
        }

        let mut sections = vec!["CrystalSentinel Care Report".to_string()];
        for incident in incidents {
            sections.push(format!("{}:", incident.incident_id));
            sections.push(format!("Right now: {}", status_line(incident)));
            sections.push(format!("Do you need to act? {}", guidance_line(incident)));
            sections.push(format!("Why this felt safe: {}", comfort_line(incident)));
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
            care_report: CareReporter::render(incidents),
        }
    }
}

fn noticed_line(incident: &CorrelatedIncident) -> String {
    let recognition_note = if incident.recognitions.is_empty() {
        String::new()
    } else {
        format!(
            " Sentinel recognized it as {} with labels {}.",
            incident.recognitions.join(", "),
            incident.recognition_labels.join(", ")
        )
    };
    let phantom_note = incident
        .phantom_summary
        .as_deref()
        .map(|summary| format!(" Phantom-Scan stayed internally clear with {}.", summary))
        .unwrap_or_default();

    format!(
        "We saw {} behavior coming from {}. The main themes were {}.{}{}",
        incident.severity.as_str(),
        incident.primary_source,
        incident.families.join(", "),
        recognition_note,
        phantom_note
    )
}

fn action_line(incident: &CorrelatedIncident) -> String {
    let base = match incident.highest_stage.as_str() {
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
    };

    let stability = if incident.stability_priority {
        " It followed a stability-first rule before taking stronger protective action."
    } else {
        ""
    };
    let phantom = incident
        .phantom_summary
        .as_deref()
        .map(|summary| {
            format!(
                " Phantom-Scan opened a bounded evidence window and varied its observation rhythm within {}.",
                summary
            )
        })
        .unwrap_or_default();
    let scan_friction = if incident
        .recognition_labels
        .iter()
        .any(|label| label == "high_speed_scan" || label == "asynchronous_sweep")
    {
        " It also used harmless scan-friction decoys to make rapid reconnaissance less trustworthy while preserving clear internal visibility."
    } else {
        ""
    };

    format!("{base}{stability}{phantom}{scan_friction}")
}

fn meaning_line(incident: &CorrelatedIncident) -> String {
    if incident
        .recognition_labels
        .iter()
        .any(|label| label == "high_speed_scan" || label == "asynchronous_sweep")
    {
        "This looked like a high-speed asynchronous scan. Sentinel treated it as reconnaissance pressure, used harmless scan friction to reduce certainty, and collected more evidence instead of trying to damage the scanner.".to_string()
    } else if incident
        .recognition_labels
        .iter()
        .any(|label| label == "reverse_https")
    {
        "This looked like a staged channel over HTTPS. Sentinel treated it as a stealthier delivery path and kept the response bounded.".to_string()
    } else if incident
        .recognition_labels
        .iter()
        .any(|label| label == "reverse_http")
    {
        "This looked like a staged channel over HTTP. Sentinel treated it as delivery-oriented behavior and kept watching for follow-up movement.".to_string()
    } else if incident
        .recognition_labels
        .iter()
        .any(|label| label == "reverse_tcp")
    {
        "This looked like a staged or shell-oriented channel over raw TCP. Sentinel slowed it down and preserved evidence before stronger action.".to_string()
    } else if incident
        .recognition_labels
        .iter()
        .any(|label| label == "spyware")
    {
        "This looked like surveillance-oriented behavior, so Sentinel treated it as a privacy risk and kept the environment stable while containing it.".to_string()
    } else if incident
        .recognition_labels
        .iter()
        .any(|label| label == "stager")
    {
        "This looked like staged payload delivery, so Sentinel treated it as the start of a larger chain rather than a harmless one-off event.".to_string()
    } else if incident
        .families
        .iter()
        .any(|family| family == "data-exfiltration")
    {
        "This usually means sensitive data looked ready to leave the environment, so the system treated it seriously.".to_string()
    } else if incident
        .families
        .iter()
        .any(|family| family == "integrity-attack")
    {
        "This means something tried to change or hook a trusted component, so Sentinel shifted toward self-protection and recovery.".to_string()
    } else if incident
        .families
        .iter()
        .any(|family| family == "offensive-scan")
    {
        "This means someone was likely mapping the environment. Sentinel used that moment to watch carefully, keep the system stable, and reduce the attacker's certainty.".to_string()
    } else {
        "This is part of how Sentinel teaches while it protects: it explains the pattern, the response, and the safety tradeoff in plain language, with stability kept ahead of unnecessary disruption.".to_string()
    }
}

fn status_line(incident: &CorrelatedIncident) -> String {
    if let Some(voice) = incident.recovery_voice.as_deref() {
        voice.to_string()
    } else if incident.stability_priority {
        "Sentinel kept the environment stable first and is continuing to watch carefully."
            .to_string()
    } else {
        "Sentinel is still monitoring the situation and keeping a clear record of what happened."
            .to_string()
    }
}

fn guidance_line(incident: &CorrelatedIncident) -> String {
    let recognition_guidance = if incident
        .recognition_labels
        .iter()
        .any(|label| label == "spyware")
    {
        "You may want to review the affected device for privacy-sensitive exposure once Sentinel finishes containing it."
    } else if incident.recognition_labels.iter().any(|label| {
        matches!(
            label.as_str(),
            "reverse_http" | "reverse_https" | "reverse_tcp" | "stager"
        )
    }) {
        "You do not need to react immediately, but reviewing the detailed case later is worthwhile because this looked like staged delivery behavior."
    } else {
        ""
    };

    match incident.highest_stage.as_str() {
        "observe" | "throttle" => {
            if recognition_guidance.is_empty() {
                "No immediate action is needed unless you want to review the detailed case file.".to_string()
            } else {
                recognition_guidance.to_string()
            }
        }
        "contain" => {
            if recognition_guidance.is_empty() {
                "Review the affected service when convenient, but Sentinel already applied bounded containment.".to_string()
            } else {
                recognition_guidance.to_string()
            }
        }
        "isolate" => {
            "A stronger containment step was necessary. Check the affected host or workload before returning it to normal service.".to_string()
        }
        _ => {
            "Sentinel is waiting for a human decision before taking anything more disruptive.".to_string()
        }
    }
}

fn comfort_line(incident: &CorrelatedIncident) -> String {
    let mut parts = Vec::new();
    if incident.stability_priority {
        parts.push("stability was kept ahead of aggressive action".to_string());
    }
    if !incident.recognitions.is_empty() {
        parts.push(format!(
            "the threat was identified as {}",
            incident.recognitions.join(", ")
        ));
    }
    if let Some(phantom) = incident.phantom_summary.as_deref() {
        parts.push(format!("Phantom-Scan stayed bounded with {}", phantom));
    }
    if let Some(recovery) = incident.recovery_summary.as_deref() {
        parts.push(format!("recovery plan {}", recovery));
    }

    if parts.is_empty() {
        "Sentinel stayed calm, explainable, and evidence-driven.".to_string()
    } else {
        format!("Sentinel stayed calm because {}.", parts.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::{CareReporter, NarrativeReporter, ReporterEngine, TeachingReporter};
    use sentinel_common::MitigationStage;
    use sentinel_correlation::{CorrelatedIncident, IncidentSeverity};

    fn sample_incident() -> CorrelatedIncident {
        CorrelatedIncident {
            incident_id: "incident-0001".to_string(),
            primary_source: "203.0.113.88".to_string(),
            sources: vec!["203.0.113.88".to_string()],
            families: vec!["offensive-scan".to_string()],
            recognitions: vec!["Meterpreter Reverse HTTPS Transport".to_string()],
            recognition_labels: vec!["stager".to_string(), "reverse_https".to_string()],
            recognition_protocols: vec!["https".to_string()],
            highest_stage: MitigationStage::Throttle,
            severity: IncidentSeverity::Medium,
            prevailing_posture: "decoy-first-capture".to_string(),
            stability_priority: true,
            phantom_summary: Some(
                "bounded cadence_ms=90 jitter_ms=8 phase_offset_ms=13 burst_slots=2".to_string(),
            ),
            recovery_summary: Some(
                "mode=fast-recovery stability_window_ms=500 restore=shadow-vault services=quick-sync decoys=resume-when-stable".to_string(),
            ),
            recovery_voice: Some(
                "Sentinel is doing a quick recovery. Core services are being refreshed and the environment remains stable.".to_string(),
            ),
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
        assert!(bundle.care_report.contains("Care Report"));
    }

    #[test]
    fn teaching_report_explains_event_in_plain_language() {
        let report = TeachingReporter::render(&[sample_incident()]);

        assert!(report.contains("What we noticed:"));
        assert!(report.contains("What Sentinel did:"));
        assert!(report.contains("stability-first"));
        assert!(report.contains("Phantom-Scan opened a bounded evidence window"));
    }

    #[test]
    fn care_report_answers_action_question() {
        let report = CareReporter::render(&[sample_incident()]);

        assert!(report.contains("Do you need to act?"));
        assert!(report.contains("staged delivery behavior"));
        assert!(report.contains("quick recovery"));
    }
}
