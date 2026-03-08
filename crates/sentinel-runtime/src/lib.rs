#![forbid(unsafe_code)]

use sentinel_autonomy::{plan_autonomy, ArchitecturePattern, AutonomyPlan};
use sentinel_common::{AttackFamily, HealthSnapshot, MitigationStage, ThreatAssessment};
use sentinel_config::RuntimeConfig;
use sentinel_decoy::{DecoyGovernor, DecoyPlan, DecoyPrimitive};
use sentinel_detection::{detect_signal, fast_assess_event};
use sentinel_education::find_lesson;
use sentinel_forensics::InvestigationRecord;
use sentinel_integrity::{IntegrityAssessment, IntegrityEngine, IntegrityVerdict};
use sentinel_native_bridge::{
    asm_defense_directive, AsmDefenseDirective, AsmDefenseMode, FastPathDecision,
    FastPathHealthProfile, FastThreatKind,
};
use sentinel_policy::PolicyEngine;
use sentinel_response::{ResponseAction, ResponsePlan, ResponsePlanner};
use sentinel_telemetry::TelemetryEvent;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FragilityLevel {
    Stable,
    Sensitive,
    Critical,
}

impl FragilityLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Sensitive => "sensitive",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegrityState {
    Healthy,
    Guarded,
    Critical,
}

impl IntegrityState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Guarded => "guarded",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaturationLevel {
    Nominal,
    Elevated,
    Critical,
}

impl SaturationLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nominal => "nominal",
            Self::Elevated => "elevated",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimePosture {
    BaselineObserve,
    DecoyFirstCapture,
    BoundedContainment,
    ProtectiveIsolation,
    ZenRecovery,
    DefensiveHibernation,
}

impl RuntimePosture {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BaselineObserve => "baseline-observe",
            Self::DecoyFirstCapture => "decoy-first-capture",
            Self::BoundedContainment => "bounded-containment",
            Self::ProtectiveIsolation => "protective-isolation",
            Self::ZenRecovery => "zen-recovery",
            Self::DefensiveHibernation => "defensive-hibernation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryMode {
    FastRecovery,
    DeepHeal,
}

impl RecoveryMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FastRecovery => "fast-recovery",
            Self::DeepHeal => "deep-heal",
        }
    }
}

#[derive(Clone, Debug)]
pub struct RecoveryTriage {
    pub mode: RecoveryMode,
    pub stability_window_ms: u16,
    pub summary: String,
    pub guardian_voice: String,
}

#[derive(Clone, Debug)]
pub struct SituationAwareness {
    pub fragility: FragilityLevel,
    pub integrity: IntegrityState,
    pub saturation: SaturationLevel,
    pub automation_limited: bool,
    pub summary: String,
}

impl SituationAwareness {
    fn from_inputs(
        config: &RuntimeConfig,
        event: &TelemetryEvent,
        signal: &sentinel_common::ThreatSignal,
        fast_path: FastPathDecision,
    ) -> Self {
        let summary = event.summary.to_ascii_lowercase();
        let health = effective_health(config, &event.health);
        let fragility = derive_fragility(&summary, &health);
        let integrity = derive_integrity_state(&summary, signal.family.clone(), fast_path, &health);
        let saturation = derive_saturation(fast_path, &health);
        let automation_limited = health.passive_only
            || matches!(fragility, FragilityLevel::Critical)
            || matches!(integrity, IntegrityState::Critical);

        Self {
            fragility,
            integrity,
            saturation,
            automation_limited,
            summary: format!(
                "fragility={} integrity={} saturation={} automation_limited={}",
                fragility.as_str(),
                integrity.as_str(),
                saturation.as_str(),
                automation_limited
            ),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeDecision {
    pub posture: RuntimePosture,
    pub awareness: SituationAwareness,
    pub fast_path: FastPathDecision,
    pub asm_directive: AsmDefenseDirective,
    pub autonomy_plan: AutonomyPlan,
    pub decoy_plan: Option<DecoyPlan>,
    pub integrity_assessment: Option<IntegrityAssessment>,
    pub recovery_triage: Option<RecoveryTriage>,
    pub assessment: ThreatAssessment,
    pub plan: ResponsePlan,
    pub record: InvestigationRecord,
    pub teaching_hint: Option<&'static str>,
}

#[derive(Default)]
pub struct SentinelRuntime {
    policy: PolicyEngine,
    integrity: IntegrityEngine,
}

impl SentinelRuntime {
    pub fn process_event(&self, config: &RuntimeConfig, event: &TelemetryEvent) -> RuntimeDecision {
        let fast_path = fast_assess_event(event);
        let signal = detect_signal(event);
        let health = effective_health(config, &event.health);
        let integrity_assessment = self.integrity.assess(&event.summary);
        let awareness = SituationAwareness::from_inputs(config, event, &signal, fast_path);
        let asm_directive = asm_defense_directive(
            fast_path,
            FastPathHealthProfile {
                cpu_load_pct: health.cpu_load_pct,
                memory_load_pct: health.memory_load_pct,
                thermal_c: health.thermal_c,
                passive_only: health.passive_only,
            },
        );
        let mut assessment = self.policy.assess(signal, health.clone());
        let autonomy_plan = plan_autonomy(config, &assessment.signal, &health, asm_directive);
        append_rationale(
            &mut assessment,
            &format!(
                "asm_kind={} scan={} intrusion={} integrity={} ddos={} kinetic={} margin={} guard_bias_pct={} evidence_budget={}",
                fast_path.kind.as_str(),
                fast_path.scan_score,
                fast_path.intrusion_score,
                fast_path.integrity_score,
                fast_path.ddos_score,
                fast_path.kinetic_score,
                fast_path.dominance_margin,
                asm_directive.guard_bias_pct,
                asm_directive.evidence_budget
            ),
        );

        apply_runtime_bounds(
            &mut assessment,
            config,
            &awareness,
            &autonomy_plan,
            integrity_assessment.as_ref(),
        );

        let posture = select_posture(&assessment, &awareness, fast_path, asm_directive);
        apply_posture_bounds(&mut assessment, posture, &awareness, asm_directive);
        let recovery_triage = derive_recovery_triage(&health, integrity_assessment.as_ref());
        let decoy_plan = if matches!(
            recovery_triage.as_ref().map(|triage| triage.mode),
            Some(RecoveryMode::DeepHeal)
        ) || matches!(asm_directive.mode, AsmDefenseMode::ZenRecovery)
        {
            None
        } else {
            DecoyGovernor::plan(config, &assessment.signal, &health)
                .map(|plan| refine_decoy_plan(plan, &autonomy_plan, asm_directive))
        };

        let plan = adapt_plan(
            ResponsePlanner::plan(&assessment),
            &assessment,
            posture,
            &awareness,
            asm_directive,
            &autonomy_plan,
            decoy_plan.as_ref(),
            integrity_assessment.as_ref(),
            recovery_triage.as_ref(),
        );
        let record = InvestigationRecord::from_assessment(&assessment, &plan);
        let teaching_hint = teaching_hint_for(&assessment, posture, integrity_assessment.as_ref());

        RuntimeDecision {
            posture,
            awareness,
            fast_path,
            asm_directive,
            autonomy_plan,
            decoy_plan,
            integrity_assessment,
            recovery_triage,
            assessment,
            plan,
            record,
            teaching_hint,
        }
    }
}

fn effective_health(config: &RuntimeConfig, health: &HealthSnapshot) -> HealthSnapshot {
    let mut effective = health.clone();
    effective.passive_only |= config.passive_only;
    effective
}

fn derive_fragility(summary: &str, health: &HealthSnapshot) -> FragilityLevel {
    if health.passive_only
        || contains_any(
            summary,
            &["fragile", "medical", "plc", "industrial", "safety-critical"],
        )
        || health.thermal_c >= 90
    {
        FragilityLevel::Critical
    } else if contains_any(summary, &["legacy", "iot", "embedded"])
        || health.cpu_load_pct >= 75
        || health.memory_load_pct >= 75
        || health.thermal_c >= 80
    {
        FragilityLevel::Sensitive
    } else {
        FragilityLevel::Stable
    }
}

fn derive_integrity_state(
    summary: &str,
    family: AttackFamily,
    fast_path: FastPathDecision,
    health: &HealthSnapshot,
) -> IntegrityState {
    if matches!(family, AttackFamily::IntegrityAttack)
        || matches!(fast_path.kind, FastThreatKind::IntegrityPressure)
        || contains_any(
            summary,
            &["integrity_breach", "tamper", "ptrace", "debug", "hook"],
        )
    {
        if health.passive_only || health.cpu_load_pct >= 90 || health.memory_load_pct >= 90 {
            IntegrityState::Critical
        } else {
            IntegrityState::Guarded
        }
    } else {
        IntegrityState::Healthy
    }
}

fn derive_saturation(fast_path: FastPathDecision, health: &HealthSnapshot) -> SaturationLevel {
    if matches!(fast_path.kind, FastThreatKind::DdosPressure)
        || health.cpu_load_pct >= 90
        || health.memory_load_pct >= 90
        || health.thermal_c >= 88
    {
        SaturationLevel::Critical
    } else if fast_path.overall_score >= 75
        || health.cpu_load_pct >= 70
        || health.memory_load_pct >= 70
        || health.thermal_c >= 78
    {
        SaturationLevel::Elevated
    } else {
        SaturationLevel::Nominal
    }
}

fn apply_runtime_bounds(
    assessment: &mut ThreatAssessment,
    config: &RuntimeConfig,
    awareness: &SituationAwareness,
    autonomy_plan: &AutonomyPlan,
    integrity_assessment: Option<&IntegrityAssessment>,
) {
    cap_stage(assessment, config.max_stage, "config-max-stage");

    append_rationale(
        assessment,
        &format!(
            "architecture={} autonomy={} fault_isolation={} headroom_pct={}",
            autonomy_plan.pattern.as_str(),
            autonomy_plan.autonomy_mode.as_str(),
            autonomy_plan.fault_isolation.as_str(),
            autonomy_plan.stability_headroom_pct
        ),
    );

    if matches!(
        autonomy_plan.autonomy_mode,
        sentinel_config::AutonomyMode::Assisted
    ) && assessment.stage.rank() > MitigationStage::Contain.rank()
    {
        assessment.stage = MitigationStage::OperatorApproval;
        append_rationale(assessment, "autonomy=assisted->operator-approval");
    }

    if matches!(awareness.fragility, FragilityLevel::Critical) {
        cap_stage(assessment, MitigationStage::Throttle, "fragile-asset-guard");
    }

    if matches!(awareness.integrity, IntegrityState::Guarded) {
        cap_stage(assessment, MitigationStage::Contain, "integrity-guard");
    }

    if matches!(awareness.integrity, IntegrityState::Critical) {
        assessment.stage = MitigationStage::Observe;
        append_rationale(assessment, "integrity-critical->observe-only");
    }

    if let Some(integrity) = integrity_assessment {
        append_rationale(
            assessment,
            &format!("integrity_verdict={}", integrity.verdict.as_str()),
        );
    }
}

fn select_posture(
    assessment: &ThreatAssessment,
    awareness: &SituationAwareness,
    fast_path: FastPathDecision,
    asm_directive: AsmDefenseDirective,
) -> RuntimePosture {
    if awareness.automation_limited && !matches!(awareness.integrity, IntegrityState::Healthy) {
        RuntimePosture::DefensiveHibernation
    } else if matches!(asm_directive.mode, AsmDefenseMode::ZenRecovery) {
        RuntimePosture::ZenRecovery
    } else if matches!(
        assessment.signal.family,
        AttackFamily::VolumetricFlood | AttackFamily::IntegrityAttack
    ) || matches!(
        fast_path.kind,
        FastThreatKind::DdosPressure | FastThreatKind::IntegrityPressure
    ) {
        RuntimePosture::ProtectiveIsolation
    } else if matches!(
        assessment.signal.family,
        AttackFamily::OffensiveScan
            | AttackFamily::PayloadStager
            | AttackFamily::ExploitDelivery
            | AttackFamily::Beaconing
            | AttackFamily::RemoteAccessTrojan
    ) || (matches!(assessment.signal.family, AttackFamily::Unknown)
        && matches!(
            fast_path.kind,
            FastThreatKind::OffensiveScan | FastThreatKind::Intrusion
        )
        && assessment.signal.confidence >= 60)
    {
        if awareness.automation_limited {
            RuntimePosture::BaselineObserve
        } else {
            RuntimePosture::DecoyFirstCapture
        }
    } else if assessment.stage.rank() >= MitigationStage::Contain.rank() {
        RuntimePosture::BoundedContainment
    } else {
        RuntimePosture::BaselineObserve
    }
}

fn apply_posture_bounds(
    assessment: &mut ThreatAssessment,
    posture: RuntimePosture,
    awareness: &SituationAwareness,
    asm_directive: AsmDefenseDirective,
) {
    match posture {
        RuntimePosture::DefensiveHibernation => {
            assessment.stage = MitigationStage::Observe;
            append_rationale(assessment, "posture=defensive-hibernation");
        }
        RuntimePosture::ZenRecovery => {
            cap_stage(
                assessment,
                MitigationStage::Throttle,
                "posture=zen-recovery",
            );
            append_rationale(
                assessment,
                &format!(
                    "asm_mode={} exposure_reduction_pct={} resume_standby_after_ms={}",
                    asm_directive.mode.as_str(),
                    asm_directive.exposure_reduction_pct,
                    asm_directive.resume_standby_after_ms
                ),
            );
        }
        RuntimePosture::ProtectiveIsolation
            if matches!(awareness.fragility, FragilityLevel::Critical) =>
        {
            cap_stage(
                assessment,
                MitigationStage::Contain,
                "protective-isolation-fragility-cap",
            );
        }
        _ => {}
    }
}

fn adapt_plan(
    mut plan: ResponsePlan,
    assessment: &ThreatAssessment,
    posture: RuntimePosture,
    awareness: &SituationAwareness,
    asm_directive: AsmDefenseDirective,
    autonomy_plan: &AutonomyPlan,
    decoy_plan: Option<&DecoyPlan>,
    integrity_assessment: Option<&IntegrityAssessment>,
    recovery_triage: Option<&RecoveryTriage>,
) -> ResponsePlan {
    push_unique(&mut plan.actions, ResponseAction::EngageFastPathFusion);
    push_unique(
        &mut plan.actions,
        ResponseAction::EnableFaultIsolatedEngines,
    );
    push_unique(&mut plan.actions, ResponseAction::ReserveStabilityHeadroom);
    if autonomy_plan.allow_mesh_distribution {
        push_unique(&mut plan.actions, ResponseAction::DistributeObservationLoad);
    }
    if matches!(autonomy_plan.pattern, ArchitecturePattern::FragileMeshGuard) {
        push_unique(&mut plan.actions, ResponseAction::ProtectFragileAssets);
    }
    if autonomy_plan.allow_mesh_distribution && is_mesh_peer_integrity_event(assessment) {
        push_unique(&mut plan.actions, ResponseAction::BroadcastMeshAlert);
        push_unique(&mut plan.actions, ResponseAction::ShiftGuardianCoverage);
        push_unique(&mut plan.actions, ResponseAction::SuspendPeerTrust);
    }
    if is_wireless_management_event(assessment) {
        push_unique(
            &mut plan.actions,
            ResponseAction::ShieldWirelessManagementPlane,
        );
        push_unique(&mut plan.actions, ResponseAction::PinTrustedBackhaulLinks);
        push_unique(&mut plan.actions, ResponseAction::ProtectFragileAssets);
        push_unique(&mut plan.actions, ResponseAction::PreserveServiceContinuity);
    }
    if is_delivery_chain_event(assessment) {
        push_unique(&mut plan.actions, ResponseAction::HoldArtifactDelivery);
        push_unique(&mut plan.actions, ResponseAction::RouteToShadowAnalysis);
        push_unique(&mut plan.actions, ResponseAction::QuarantineArtifact);
    }

    match posture {
        RuntimePosture::BaselineObserve => {
            push_unique(&mut plan.actions, ResponseAction::PreserveServiceContinuity);
            plan.narrative = format!(
                "{} awareness={} architecture={}",
                plan.narrative, awareness.summary, autonomy_plan.narrative
            );
        }
        RuntimePosture::DecoyFirstCapture => {
            push_unique(&mut plan.actions, ResponseAction::TriggerIdfWindow);
            push_unique(
                &mut plan.actions,
                ResponseAction::OpenRapidAreaObservationWindow,
            );
            push_unique(&mut plan.actions, ResponseAction::FocusPhantomObservation);
            push_unique(&mut plan.actions, ResponseAction::SampleAmbientResonance);
            push_unique(&mut plan.actions, ResponseAction::PreserveServiceContinuity);
            plan.narrative = format!(
                "Decoy-first capture posture opened a bounded IDF/Phantom window. {} awareness={} architecture={}",
                format!(
                    "{} asm_mode={} observation_window_ms={} evidence_budget={} phantom_jitter_ms={} guard_bias_pct={}",
                    plan.narrative,
                    asm_directive.mode.as_str(),
                    asm_directive.observation_window_ms,
                    asm_directive.evidence_budget,
                    asm_directive.phantom_jitter_ms,
                    asm_directive.guard_bias_pct
                ),
                awareness.summary,
                autonomy_plan.narrative
            );
        }
        RuntimePosture::BoundedContainment => {
            push_unique(&mut plan.actions, ResponseAction::PreserveServiceContinuity);
            if !matches!(awareness.integrity, IntegrityState::Healthy) {
                push_unique(&mut plan.actions, ResponseAction::VerifySelfIntegrity);
            }
            plan.narrative = format!(
                "Bounded containment posture applied. {} asm_mode={} observation_window_ms={} guard_bias_pct={} awareness={} architecture={}",
                plan.narrative,
                asm_directive.mode.as_str(),
                asm_directive.observation_window_ms,
                asm_directive.guard_bias_pct,
                awareness.summary,
                autonomy_plan.narrative
            );
        }
        RuntimePosture::ProtectiveIsolation => {
            push_unique(&mut plan.actions, ResponseAction::VerifySelfIntegrity);
            push_unique(&mut plan.actions, ResponseAction::PreserveServiceContinuity);
            plan.narrative = format!(
                "Protective isolation posture applied under heavy pressure. {} asm_mode={} observation_window_ms={} guard_bias_pct={} awareness={} architecture={}",
                plan.narrative,
                asm_directive.mode.as_str(),
                asm_directive.observation_window_ms,
                asm_directive.guard_bias_pct,
                awareness.summary,
                autonomy_plan.narrative
            );
        }
        RuntimePosture::ZenRecovery => {
            push_unique(&mut plan.actions, ResponseAction::EnterZenMode);
            push_unique(&mut plan.actions, ResponseAction::ReduceExposureSurface);
            push_unique(&mut plan.actions, ResponseAction::PauseNonEssentialDecoys);
            push_unique(&mut plan.actions, ResponseAction::ResumeStandbyWhenStable);
            push_unique(&mut plan.actions, ResponseAction::LimitAutomation);
            push_unique(&mut plan.actions, ResponseAction::PreserveServiceContinuity);
            plan.narrative = format!(
                "ASM zen recovery posture reduced exposure and non-essential activity while the defended system regains health. asm_mode={} observation_window_ms={} exposure_reduction_pct={} evidence_budget={} guard_bias_pct={} resume_standby_after_ms={} awareness={} architecture={}",
                asm_directive.mode.as_str(),
                asm_directive.observation_window_ms,
                asm_directive.exposure_reduction_pct,
                asm_directive.evidence_budget,
                asm_directive.guard_bias_pct,
                asm_directive.resume_standby_after_ms,
                awareness.summary,
                autonomy_plan.narrative
            );
        }
        RuntimePosture::DefensiveHibernation => {
            plan.actions = vec![
                ResponseAction::EmitAlert,
                ResponseAction::VerifySelfIntegrity,
                ResponseAction::LimitAutomation,
                ResponseAction::PreserveServiceContinuity,
                ResponseAction::OpenInvestigation,
                ResponseAction::RequireOperatorApproval,
            ];
            plan.narrative = format!(
                "Defensive hibernation limited autonomous action to protect Sentinel integrity and fragile assets. awareness={} architecture={}",
                awareness.summary, autonomy_plan.narrative
            );
        }
    }

    if let Some(decoy) = decoy_plan {
        if decoy
            .primitives
            .iter()
            .any(|primitive| matches!(primitive, DecoyPrimitive::AmbientMist))
        {
            push_unique(&mut plan.actions, ResponseAction::EnableAmbientDecoyMist);
        }
        if decoy
            .primitives
            .iter()
            .any(|primitive| matches!(primitive, DecoyPrimitive::ReconFrictionVeil))
        {
            push_unique(&mut plan.actions, ResponseAction::EnableReconFrictionVeil);
        }
        if decoy
            .primitives
            .iter()
            .any(|primitive| matches!(primitive, DecoyPrimitive::CadenceRandomizer))
        {
            push_unique(&mut plan.actions, ResponseAction::EnableCadenceRandomizer);
        }
        if decoy
            .primitives
            .iter()
            .any(|primitive| matches!(primitive, DecoyPrimitive::PhantomRhythmRandomizer))
        {
            push_unique(
                &mut plan.actions,
                ResponseAction::EnablePhantomRhythmRandomizer,
            );
        }
        if decoy
            .primitives
            .iter()
            .any(|primitive| matches!(primitive, DecoyPrimitive::SpotMimicry))
        {
            push_unique(&mut plan.actions, ResponseAction::EnableSpotMimicry);
        }
        plan.narrative = format!("{} decoy={}", plan.narrative, decoy.narrative);
    }

    if let Some(integrity) = integrity_assessment {
        push_unique(&mut plan.actions, ResponseAction::VerifyArtifactBaseline);

        if integrity.restoration.is_some() {
            push_unique(&mut plan.actions, ResponseAction::LockArtifact);
            push_unique(
                &mut plan.actions,
                ResponseAction::SuspendCompromisedWorkload,
            );
            push_unique(&mut plan.actions, ResponseAction::RestoreFromShadowVault);
        }

        if matches!(integrity.verdict, IntegrityVerdict::CriticalCompromise) {
            push_unique(&mut plan.actions, ResponseAction::RequireOperatorApproval);
        }

        plan.narrative = format!("{} integrity={}", plan.narrative, integrity.detail);
    }

    if let Some(recovery) = recovery_triage {
        match recovery.mode {
            RecoveryMode::FastRecovery => {
                push_unique(&mut plan.actions, ResponseAction::StartFastRecovery);
            }
            RecoveryMode::DeepHeal => {
                push_unique(
                    &mut plan.actions,
                    ResponseAction::EnterDeepHealStabilityMode,
                );
                push_unique(&mut plan.actions, ResponseAction::ResumeServicesGradually);
                push_unique(&mut plan.actions, ResponseAction::LimitAutomation);
                push_unique(&mut plan.actions, ResponseAction::PreserveServiceContinuity);
            }
        }
        plan.narrative = format!("{} recovery={}", plan.narrative, recovery.summary);
    }

    if is_delivery_chain_event(assessment) {
        plan.narrative = format!(
            "{} delivery_guard=hold-and-verify shadow_path=quarantine-and-analyze",
            plan.narrative
        );
    }

    if autonomy_plan.allow_mesh_distribution && is_mesh_peer_integrity_event(assessment) {
        plan.narrative = format!(
            "{} mesh=peer-heartbeat-guard trust=suspended coverage=shifted",
            plan.narrative
        );
    }
    if is_wireless_management_event(assessment) {
        plan.narrative = format!(
            "{} wireless_guard=local-management-shield backhaul=trusted-links-only",
            plan.narrative
        );
    }

    plan
}

fn refine_decoy_plan(
    mut plan: DecoyPlan,
    autonomy_plan: &AutonomyPlan,
    asm_directive: AsmDefenseDirective,
) -> DecoyPlan {
    plan.ghost_slots = plan.ghost_slots.min(autonomy_plan.max_decoy_slots);
    if autonomy_plan.max_decoy_slots == 0 {
        plan.primitives.clear();
    }

    if !autonomy_plan.allow_spot_mimicry {
        plan.primitives
            .retain(|primitive| !matches!(primitive, DecoyPrimitive::SpotMimicry));
    }

    let mut disable_phantom = false;
    if let Some(phantom) = &mut plan.phantom_observation {
        phantom.sample_budget = phantom.sample_budget.min(autonomy_plan.phantom_sample_cap);
        phantom.sample_budget = phantom.sample_budget.min(asm_directive.evidence_budget.max(1));
        if asm_directive.observation_window_ms > 0 {
            phantom.decision_window_ms = phantom
                .decision_window_ms
                .min(asm_directive.observation_window_ms);
        }
        if asm_directive.phantom_jitter_ms > 0 {
            phantom.jitter_ms = phantom
                .jitter_ms
                .min(u32::from(asm_directive.phantom_jitter_ms));
        }
        if autonomy_plan.phantom_sample_cap == 0 || asm_directive.evidence_budget == 0 {
            disable_phantom = true;
        }
    }
    if disable_phantom {
        plan.phantom_observation = None;
        plan.primitives
            .retain(|primitive| !matches!(primitive, DecoyPrimitive::PhantomRhythmRandomizer));
    }

    if autonomy_plan.stability_headroom_pct >= 40 {
        plan.cadence_ms = plan.cadence_ms.max(700);
        plan.jitter_ms = plan.jitter_ms.min(16);
    }

    if asm_directive.phantom_jitter_ms > 0 {
        plan.jitter_ms = plan
            .jitter_ms
            .min(u32::from(asm_directive.phantom_jitter_ms));
    }
    plan.ghost_slots = plan
        .ghost_slots
        .min(u16::from(asm_directive.evidence_budget.max(1)));

    plan.narrative = format!(
        "{} asm_mode={} evidence_budget={} phantom_jitter_ms={} guard_bias_pct={} architecture={}",
        plan.narrative,
        asm_directive.mode.as_str(),
        asm_directive.evidence_budget,
        asm_directive.phantom_jitter_ms,
        asm_directive.guard_bias_pct,
        autonomy_plan.narrative
    );
    plan
}

fn is_mesh_peer_integrity_event(assessment: &ThreatAssessment) -> bool {
    let Some(recognition) = &assessment.signal.recognition else {
        return false;
    };

    recognition
        .labels
        .iter()
        .any(|label| matches!(label.as_str(), "mesh" | "heartbeat" | "peer_trust"))
}

fn is_delivery_chain_event(assessment: &ThreatAssessment) -> bool {
    if matches!(
        assessment.signal.family,
        AttackFamily::PayloadStager | AttackFamily::ExploitDelivery
    ) {
        return true;
    }

    assessment
        .signal
        .recognition
        .as_ref()
        .map(|recognition| {
            recognition.labels.iter().any(|label| {
                matches!(
                    label.as_str(),
                    "stager"
                        | "reverse_http"
                        | "reverse_https"
                        | "reverse_tcp"
                        | "delivery-wrapper"
                        | "backdoor_wrapper"
                        | "document-delivery"
                )
            })
        })
        .unwrap_or(false)
}

fn is_wireless_management_event(assessment: &ThreatAssessment) -> bool {
    assessment
        .signal
        .analysis_lanes
        .iter()
        .any(|lane| lane == "wireless-guard")
        || assessment
            .signal
            .recognition
            .as_ref()
            .map(|recognition| {
                recognition.labels.iter().any(|label| {
                    matches!(
                        label.as_str(),
                        "wireless" | "deauth" | "disassociation" | "management_frame"
                    )
                })
            })
            .unwrap_or(false)
}

fn teaching_hint_for(
    assessment: &ThreatAssessment,
    posture: RuntimePosture,
    integrity_assessment: Option<&IntegrityAssessment>,
) -> Option<&'static str> {
    if integrity_assessment.is_some() {
        return find_lesson("SHKE").map(|lesson| lesson.summary);
    }

    match posture {
        RuntimePosture::DecoyFirstCapture
            if matches!(
                assessment.signal.family,
                AttackFamily::OffensiveScan
                    | AttackFamily::Unknown
                    | AttackFamily::ApiScraping
                    | AttackFamily::VolumetricFlood
            ) =>
        {
            find_lesson("SARS")
                .map(|lesson| lesson.summary)
                .or_else(|| find_lesson("IDF Scan").map(|lesson| lesson.summary))
        }
        RuntimePosture::DecoyFirstCapture => find_lesson("IDF Scan").map(|lesson| lesson.summary),
        RuntimePosture::ProtectiveIsolation | RuntimePosture::BoundedContainment => {
            find_lesson("SHKE").map(|lesson| lesson.summary)
        }
        RuntimePosture::ZenRecovery => find_lesson("SARS")
            .map(|lesson| lesson.summary)
            .or_else(|| find_lesson("SHKE").map(|lesson| lesson.summary)),
        RuntimePosture::DefensiveHibernation => find_lesson("SHKE").map(|lesson| lesson.summary),
        RuntimePosture::BaselineObserve
            if matches!(
                assessment.signal.family,
                AttackFamily::OffensiveScan
                    | AttackFamily::Unknown
                    | AttackFamily::ApiScraping
                    | AttackFamily::VolumetricFlood
            ) =>
        {
            find_lesson("SARS").map(|lesson| lesson.summary)
        }
        _ => None,
    }
}

fn cap_stage(assessment: &mut ThreatAssessment, max_stage: MitigationStage, reason: &str) {
    let capped_stage = assessment.stage.least_aggressive(max_stage);
    if capped_stage != assessment.stage {
        assessment.stage = capped_stage;
        append_rationale(assessment, reason);
    }
}

fn append_rationale(assessment: &mut ThreatAssessment, extra: &str) {
    assessment.rationale.push_str(" | ");
    assessment.rationale.push_str(extra);
}

fn contains_any(summary: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| summary.contains(needle))
}

fn derive_recovery_triage(
    health: &HealthSnapshot,
    integrity_assessment: Option<&IntegrityAssessment>,
) -> Option<RecoveryTriage> {
    let integrity = integrity_assessment?;
    let high_stress = health.cpu_load_pct >= 85
        || health.memory_load_pct >= 85
        || health.thermal_c >= 84
        || health.passive_only;

    match (integrity.verdict, high_stress) {
        (IntegrityVerdict::RestorableCompromise, false) => Some(RecoveryTriage {
            mode: RecoveryMode::FastRecovery,
            stability_window_ms: 500,
            summary: "mode=fast-recovery stability_window_ms=500 restore=shadow-vault services=quick-sync decoys=resume-when-stable".to_string(),
            guardian_voice: "Sentinel is doing a quick recovery. Core services are being refreshed and the environment remains stable.".to_string(),
        }),
        (IntegrityVerdict::CriticalCompromise, _)
        | (IntegrityVerdict::RestorableCompromise, true)
        | (IntegrityVerdict::DriftDetected, true) => Some(RecoveryTriage {
            mode: RecoveryMode::DeepHeal,
            stability_window_ms: 500,
            summary: "mode=deep-heal stability_window_ms=500 exposure=minimal decoys=suspended restore=gradual-awakening".to_string(),
            guardian_voice: "Sentinel entered a quiet recovery mode to protect the system. Core protection stays up while non-essential activity remains paused.".to_string(),
        }),
        _ => None,
    }
}

fn push_unique(actions: &mut Vec<ResponseAction>, action: ResponseAction) {
    if !actions.contains(&action) {
        actions.push(action);
    }
}

#[cfg(test)]
mod tests {
    use super::{RuntimePosture, SentinelRuntime};
    use sentinel_autonomy::ArchitecturePattern;
    use sentinel_common::{HealthSnapshot, MitigationStage, TelemetryKind};
    use sentinel_config::{DeploymentShape, PerformanceProfile, RuntimeConfig};
    use sentinel_response::ResponseAction;
    use sentinel_telemetry::TelemetryEvent;

    #[test]
    fn offensive_scan_uses_decoy_first_capture() {
        let runtime = SentinelRuntime::default();
        let config = RuntimeConfig::default();
        let event = TelemetryEvent {
            kind: TelemetryKind::Packet,
            source: "203.0.113.88".to_string(),
            summary: "syn probe recon fingerprint".to_string(),
            health: HealthSnapshot::default(),
        };

        let decision = runtime.process_event(&config, &event);

        assert_eq!(decision.posture, RuntimePosture::DecoyFirstCapture);
        assert!(decision.decoy_plan.is_some());
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::TriggerIdfWindow));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::EnableAmbientDecoyMist));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::EnableReconFrictionVeil));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::EnableCadenceRandomizer));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::EnablePhantomRhythmRandomizer));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::FocusPhantomObservation));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::OpenRapidAreaObservationWindow));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::SampleAmbientResonance));
        assert!(decision
            .decoy_plan
            .as_ref()
            .expect("decoy plan should exist")
            .phantom_observation
            .is_some());
    }

    #[test]
    fn integrity_pressure_limits_automation() {
        let runtime = SentinelRuntime::default();
        let config = RuntimeConfig::default();
        let event = TelemetryEvent {
            kind: TelemetryKind::Integrity,
            source: "sentinel-self".to_string(),
            summary: "integrity_breach ptrace tamper".to_string(),
            health: HealthSnapshot {
                passive_only: true,
                ..HealthSnapshot::default()
            },
        };

        let decision = runtime.process_event(&config, &event);

        assert_eq!(decision.posture, RuntimePosture::DefensiveHibernation);
        assert_eq!(decision.assessment.stage, MitigationStage::Observe);
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::VerifySelfIntegrity));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::VerifyArtifactBaseline));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::RequireOperatorApproval));
    }

    #[test]
    fn config_caps_max_stage() {
        let runtime = SentinelRuntime::default();
        let config = RuntimeConfig {
            max_stage: MitigationStage::Contain,
            ..RuntimeConfig::default()
        };
        let event = TelemetryEvent {
            kind: TelemetryKind::Flow,
            source: "198.51.100.44".to_string(),
            summary: "high_entropy dns_tunnel burst_flood".to_string(),
            health: HealthSnapshot {
                cpu_load_pct: 40,
                memory_load_pct: 40,
                thermal_c: 55,
                passive_only: false,
            },
        };

        let decision = runtime.process_event(&config, &event);

        assert_eq!(decision.assessment.stage, MitigationStage::Contain);
    }

    #[test]
    fn restorable_integrity_event_gets_shadow_vault_actions() {
        let runtime = SentinelRuntime::default();
        let config = RuntimeConfig::default();
        let event = TelemetryEvent {
            kind: TelemetryKind::Integrity,
            source: "sentinel-self".to_string(),
            summary: "hash_mismatch sentineld runtime tamper".to_string(),
            health: HealthSnapshot::default(),
        };

        let decision = runtime.process_event(&config, &event);

        assert!(decision.integrity_assessment.is_some());
        assert!(decision.recovery_triage.is_some());
        assert_eq!(
            decision
                .recovery_triage
                .as_ref()
                .expect("recovery triage should exist")
                .mode,
            super::RecoveryMode::FastRecovery
        );
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::RestoreFromShadowVault));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::LockArtifact));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::StartFastRecovery));
    }

    #[test]
    fn critical_integrity_event_enters_deep_heal_and_suspends_decoys() {
        let runtime = SentinelRuntime::default();
        let config = RuntimeConfig::default();
        let event = TelemetryEvent {
            kind: TelemetryKind::Integrity,
            source: "sentinel-self".to_string(),
            summary: "integrity_breach syscall_table rootkit hook".to_string(),
            health: HealthSnapshot {
                cpu_load_pct: 92,
                memory_load_pct: 88,
                thermal_c: 86,
                passive_only: false,
            },
        };

        let decision = runtime.process_event(&config, &event);

        assert_eq!(
            decision
                .recovery_triage
                .as_ref()
                .expect("recovery triage should exist")
                .mode,
            super::RecoveryMode::DeepHeal
        );
        assert!(decision.decoy_plan.is_none());
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::EnterDeepHealStabilityMode));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::ResumeServicesGradually));
    }

    #[test]
    fn payload_stager_can_use_decoy_first_capture() {
        let runtime = SentinelRuntime::default();
        let config = RuntimeConfig::default();
        let event = TelemetryEvent {
            kind: TelemetryKind::Packet,
            source: "198.51.100.77".to_string(),
            summary: "meterpreter tlv unknown_probe".to_string(),
            health: HealthSnapshot::default(),
        };

        let decision = runtime.process_event(&config, &event);

        assert_eq!(decision.posture, RuntimePosture::DecoyFirstCapture);
        assert!(decision.decoy_plan.is_some());
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::OpenRapidAreaObservationWindow));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::SampleAmbientResonance));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::HoldArtifactDelivery));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::RouteToShadowAnalysis));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::QuarantineArtifact));
        assert!(decision.plan.narrative.contains("route-to-shadow-analysis")
            || decision.plan.actions.contains(&ResponseAction::RouteToShadowAnalysis));
    }

    #[test]
    fn high_host_pressure_can_shift_to_zen_recovery() {
        let runtime = SentinelRuntime::default();
        let config = RuntimeConfig::default();
        let event = TelemetryEvent {
            kind: TelemetryKind::Packet,
            source: "203.0.113.91".to_string(),
            summary: "nmap service_probe banner_grab".to_string(),
            health: HealthSnapshot {
                cpu_load_pct: 94,
                memory_load_pct: 90,
                thermal_c: 87,
                passive_only: false,
            },
        };

        let decision = runtime.process_event(&config, &event);

        assert_eq!(decision.posture, RuntimePosture::ZenRecovery);
        assert!(decision.decoy_plan.is_none());
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::EnterZenMode));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::ReduceExposureSurface));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::PauseNonEssentialDecoys));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::ResumeStandbyWhenStable));
    }

    #[test]
    fn fragile_mesh_architecture_caps_decoy_spread() {
        let runtime = SentinelRuntime::default();
        let config = RuntimeConfig {
            deployment_shape: DeploymentShape::FragileMesh,
            performance_profile: PerformanceProfile::StabilityFirst,
            ..RuntimeConfig::default()
        };
        let event = TelemetryEvent {
            kind: TelemetryKind::Packet,
            source: "198.51.100.77".to_string(),
            summary: "payload stage_loader reflective_loader".to_string(),
            health: HealthSnapshot::default(),
        };

        let decision = runtime.process_event(&config, &event);

        assert_eq!(
            decision.autonomy_plan.pattern,
            ArchitecturePattern::FragileMeshGuard
        );
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::ProtectFragileAssets));
        assert!(decision.autonomy_plan.stability_headroom_pct >= 45);
        if let Some(decoy) = &decision.decoy_plan {
            assert!(!decoy
                .primitives
                .contains(&sentinel_decoy::DecoyPrimitive::SpotMimicry));
            assert!(decoy.ghost_slots <= decision.autonomy_plan.max_decoy_slots);
        }
    }

    #[test]
    fn multi_node_mesh_suspends_peer_trust_on_guardian_drift() {
        let runtime = SentinelRuntime::default();
        let config = RuntimeConfig {
            deployment_shape: DeploymentShape::MultiNodeMesh,
            performance_profile: PerformanceProfile::Balanced,
            ..RuntimeConfig::default()
        };
        let event = TelemetryEvent {
            kind: TelemetryKind::Integrity,
            source: "guardian-node-02".to_string(),
            summary: "mesh_heartbeat_malformed guardian_pulse_invalid peer_trust_drift"
                .to_string(),
            health: HealthSnapshot::default(),
        };

        let decision = runtime.process_event(&config, &event);

        assert!(decision.autonomy_plan.allow_mesh_distribution);
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::DistributeObservationLoad));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::BroadcastMeshAlert));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::ShiftGuardianCoverage));
        assert!(decision
            .plan
            .actions
            .contains(&ResponseAction::SuspendPeerTrust));
        assert!(decision
            .plan
            .narrative
            .contains("mesh=peer-heartbeat-guard"));
    }
}
