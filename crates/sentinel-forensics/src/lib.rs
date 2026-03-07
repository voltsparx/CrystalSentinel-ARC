#![forbid(unsafe_code)]

use sentinel_common::ThreatAssessment;
use sentinel_response::ResponsePlan;

#[derive(Clone, Debug)]
pub struct InvestigationRecord {
    pub title: String,
    pub family: String,
    pub stage: String,
    pub narrative: String,
}

impl InvestigationRecord {
    pub fn from_assessment(assessment: &ThreatAssessment, plan: &ResponsePlan) -> Self {
        Self {
            title: format!("Sentinel investigation for {}", assessment.signal.source_name),
            family: assessment.signal.family.as_str().to_string(),
            stage: plan.stage.as_str().to_string(),
            narrative: format!("{} | {}", assessment.rationale, plan.narrative),
        }
    }
}

