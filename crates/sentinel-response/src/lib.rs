#![forbid(unsafe_code)]

use sentinel_common::{MitigationStage, ThreatAssessment};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseAction {
    EmitAlert,
    TagSource,
    RateLimitSource,
    TemporaryBlockSource,
    IsolateWorkload,
    TriggerIdfWindow,
    FocusPhantomObservation,
    VerifySelfIntegrity,
    LimitAutomation,
    PreserveServiceContinuity,
    OpenInvestigation,
    RequireOperatorApproval,
}

impl ResponseAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmitAlert => "emit-alert",
            Self::TagSource => "tag-source",
            Self::RateLimitSource => "rate-limit-source",
            Self::TemporaryBlockSource => "temporary-block-source",
            Self::IsolateWorkload => "isolate-workload",
            Self::TriggerIdfWindow => "trigger-idf-window",
            Self::FocusPhantomObservation => "focus-phantom-observation",
            Self::VerifySelfIntegrity => "verify-self-integrity",
            Self::LimitAutomation => "limit-automation",
            Self::PreserveServiceContinuity => "preserve-service-continuity",
            Self::OpenInvestigation => "open-investigation",
            Self::RequireOperatorApproval => "require-operator-approval",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResponsePlan {
    pub stage: MitigationStage,
    pub actions: Vec<ResponseAction>,
    pub narrative: String,
}

pub struct ResponsePlanner;

impl ResponsePlanner {
    pub fn plan(assessment: &ThreatAssessment) -> ResponsePlan {
        let (actions, narrative) = match assessment.stage {
            MitigationStage::Observe => (
                vec![ResponseAction::EmitAlert, ResponseAction::OpenInvestigation],
                "Observe-only posture with investigation opened.".to_string(),
            ),
            MitigationStage::Throttle => (
                vec![
                    ResponseAction::EmitAlert,
                    ResponseAction::TagSource,
                    ResponseAction::RateLimitSource,
                    ResponseAction::OpenInvestigation,
                ],
                "Throttling suspicious source while preserving service continuity.".to_string(),
            ),
            MitigationStage::Contain => (
                vec![
                    ResponseAction::EmitAlert,
                    ResponseAction::TagSource,
                    ResponseAction::TemporaryBlockSource,
                    ResponseAction::OpenInvestigation,
                ],
                "Containing suspicious activity with temporary network controls.".to_string(),
            ),
            MitigationStage::Isolate => (
                vec![
                    ResponseAction::EmitAlert,
                    ResponseAction::TemporaryBlockSource,
                    ResponseAction::IsolateWorkload,
                    ResponseAction::OpenInvestigation,
                    ResponseAction::RequireOperatorApproval,
                ],
                "Escalated to isolation with explicit operator review.".to_string(),
            ),
            MitigationStage::OperatorApproval => (
                vec![
                    ResponseAction::EmitAlert,
                    ResponseAction::OpenInvestigation,
                    ResponseAction::RequireOperatorApproval,
                ],
                "Automation paused pending operator approval.".to_string(),
            ),
        };

        ResponsePlan {
            stage: assessment.stage,
            actions,
            narrative,
        }
    }
}
