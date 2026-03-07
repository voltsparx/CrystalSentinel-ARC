#![forbid(unsafe_code)]

use sentinel_common::{MitigationStage, ThreatAssessment};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseAction {
    EmitAlert,
    TagSource,
    RateLimitSource,
    TemporaryBlockSource,
    IsolateWorkload,
    LockArtifact,
    SuspendCompromisedWorkload,
    VerifyArtifactBaseline,
    RestoreFromShadowVault,
    StartFastRecovery,
    EnterDeepHealStabilityMode,
    ResumeServicesGradually,
    EnableAmbientDecoyMist,
    EnableReconFrictionVeil,
    EnableCadenceRandomizer,
    EnablePhantomRhythmRandomizer,
    EnableSpotMimicry,
    TriggerIdfWindow,
    OpenRapidAreaObservationWindow,
    FocusPhantomObservation,
    SampleAmbientResonance,
    VerifySelfIntegrity,
    LimitAutomation,
    EnterZenMode,
    ReduceExposureSurface,
    PauseNonEssentialDecoys,
    ResumeStandbyWhenStable,
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
            Self::LockArtifact => "lock-artifact",
            Self::SuspendCompromisedWorkload => "suspend-compromised-workload",
            Self::VerifyArtifactBaseline => "verify-artifact-baseline",
            Self::RestoreFromShadowVault => "restore-from-shadow-vault",
            Self::StartFastRecovery => "start-fast-recovery",
            Self::EnterDeepHealStabilityMode => "enter-deep-heal-stability-mode",
            Self::ResumeServicesGradually => "resume-services-gradually",
            Self::EnableAmbientDecoyMist => "enable-ambient-decoy-mist",
            Self::EnableReconFrictionVeil => "enable-recon-friction-veil",
            Self::EnableCadenceRandomizer => "enable-cadence-randomizer",
            Self::EnablePhantomRhythmRandomizer => "enable-phantom-rhythm-randomizer",
            Self::EnableSpotMimicry => "enable-spot-mimicry",
            Self::TriggerIdfWindow => "trigger-idf-window",
            Self::OpenRapidAreaObservationWindow => "open-rapid-area-observation-window",
            Self::FocusPhantomObservation => "focus-phantom-observation",
            Self::SampleAmbientResonance => "sample-ambient-resonance",
            Self::VerifySelfIntegrity => "verify-self-integrity",
            Self::LimitAutomation => "limit-automation",
            Self::EnterZenMode => "enter-zen-mode",
            Self::ReduceExposureSurface => "reduce-exposure-surface",
            Self::PauseNonEssentialDecoys => "pause-non-essential-decoys",
            Self::ResumeStandbyWhenStable => "resume-standby-when-stable",
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
