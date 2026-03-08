use sentinel_common::MitigationStage;

#[cfg(target_arch = "x86_64")]
use core::arch::asm;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeLanguage {
    C,
    Cpp,
    Asm,
}

impl NativeLanguage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::C => "c",
            Self::Cpp => "c++",
            Self::Asm => "asm",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeLayerStatus {
    Scaffolded,
    Linked,
}

impl NativeLayerStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scaffolded => "scaffolded",
            Self::Linked => "linked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeLayerSpec {
    pub language: NativeLanguage,
    pub library: &'static str,
    pub responsibility: &'static str,
    pub entrypoint: &'static str,
    pub status: NativeLayerStatus,
}

pub fn native_layer_manifest() -> Vec<NativeLayerSpec> {
    vec![
        NativeLayerSpec {
            language: NativeLanguage::C,
            library: "sentinel-native-c",
            responsibility: "Resource guards, stability-first observation budgeting, protocol and mesh safety caps, exposure reduction planning, dynamic load balancing, guardian handoff, heartbeat audits, descriptor-safe compatibility shims, and OS-facing packet helpers.",
            entrypoint: "sentinel_c_resource_guard / sentinel_c_budget_window / sentinel_c_exposure_guard / sentinel_c_protocol_budget / sentinel_c_mesh_guard / sentinel_c_dynamic_load_balancer / sentinel_c_mesh_heartbeat_audit / sentinel_c_guardian_handoff",
            status: NativeLayerStatus::Scaffolded,
        },
        NativeLayerSpec {
            language: NativeLanguage::Cpp,
            library: "sentinel-native-cpp",
            responsibility: "Stateful classifiers, scan-path prediction, ambient-state modeling, behavior matrices, recovery prediction, guardian reporting, mesh gossip planning, and attack-template modeling.",
            entrypoint: "sentinel_cpp_classify / sentinel_cpp_predict_scan_path / sentinel_cpp_ambient_state / sentinel_cpp_behavior_matrix / sentinel_cpp_recovery_predictor / sentinel_cpp_guardian_report / sentinel_cpp_mesh_gossip",
            status: NativeLayerStatus::Scaffolded,
        },
        NativeLayerSpec {
            language: NativeLanguage::Asm,
            library: "sentinel-native-asm",
            responsibility: "Linked timing primitives, weighted pressure mixing, kinetic-impedance aware fast-path scoring, bounded evidence-ladder sizing, health-aware zen fallback decisions, guardian-mode selection, mesh gossip TTL sizing, and defensive lane rebalance guidance.",
            entrypoint: "fast_path_assess / asm_defense_directive / sentinel_asm_weighted_mix / sentinel_asm_weighted_mix4 / sentinel_asm_pressure_mode / sentinel_asm_observation_window / sentinel_asm_decoy_budget / sentinel_asm_evidence_budget / sentinel_asm_phantom_jitter / sentinel_asm_guard_bias / sentinel_asm_guardian_mode / sentinel_asm_mesh_gossip_ttl",
            status: NativeLayerStatus::Linked,
        },
    ]
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FastPathFeatures {
    pub scan_pressure: u8,
    pub intrusion_pressure: u8,
    pub ddos_pressure: u8,
    pub identity_pressure: u8,
    pub entropy_pressure: u8,
    pub integrity_pressure: u8,
    pub kinetic_pressure: u8,
    pub heartbeat_pressure: u8,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FastPathHealthProfile {
    pub cpu_load_pct: u8,
    pub memory_load_pct: u8,
    pub thermal_c: u8,
    pub passive_only: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FastThreatKind {
    Benign,
    OffensiveScan,
    Intrusion,
    IntegrityPressure,
    DdosPressure,
}

impl FastThreatKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Benign => "benign",
            Self::OffensiveScan => "offensive-scan",
            Self::Intrusion => "intrusion",
            Self::IntegrityPressure => "integrity-pressure",
            Self::DdosPressure => "ddos-pressure",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FastPathDecision {
    pub cycle_stamp: u64,
    pub scan_score: u16,
    pub intrusion_score: u16,
    pub integrity_score: u16,
    pub ddos_score: u16,
    pub kinetic_score: u16,
    pub dominance_margin: u8,
    pub overall_score: u8,
    pub kind: FastThreatKind,
    pub recommended_stage: MitigationStage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsmDefenseMode {
    Standby,
    DecoyCapture,
    ContainmentGuard,
    ZenRecovery,
}

impl AsmDefenseMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standby => "standby",
            Self::DecoyCapture => "decoy-capture",
            Self::ContainmentGuard => "containment-guard",
            Self::ZenRecovery => "zen-recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsmDefenseDirective {
    pub mode: AsmDefenseMode,
    pub observation_window_ms: u16,
    pub exposure_reduction_pct: u8,
    pub decoy_budget: u8,
    pub evidence_budget: u8,
    pub phantom_jitter_ms: u8,
    pub guard_bias_pct: u8,
    pub keep_decoy_capture: bool,
    pub recovery_bias: bool,
    pub resume_standby_after_ms: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardianBridgeMode {
    LocalObserve,
    AdoptFragilePeer,
    SharedGuardian,
    ShadowGateway,
}

impl GuardianBridgeMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalObserve => "local-observe",
            Self::AdoptFragilePeer => "adopt-fragile-peer",
            Self::SharedGuardian => "shared-guardian",
            Self::ShadowGateway => "shadow-gateway",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardianBridgeDirective {
    pub mode: GuardianBridgeMode,
    pub adoption_budget: u8,
    pub clean_forward_only: bool,
    pub handoff_ready: bool,
    pub preserve_fragile_paths: bool,
    pub surrogate_load_pct: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeshGossipMode {
    Quiet,
    ShareObservation,
    TightenTrust,
    ShadowGateway,
}

impl MeshGossipMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Quiet => "quiet",
            Self::ShareObservation => "share-observation",
            Self::TightenTrust => "tighten-trust",
            Self::ShadowGateway => "shadow-gateway",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeshGossipDirective {
    pub mode: MeshGossipMode,
    pub share_hostile_observation: bool,
    pub tighten_trust: bool,
    pub open_shadow_gateway: bool,
    pub consensus_quorum: u8,
    pub evidence_ttl_ms: u16,
}

pub fn fast_path_assess(features: FastPathFeatures) -> FastPathDecision {
    let cycle_stamp = asm_cycle_stamp();
    let scan_score = weighted_score4(
        features.scan_pressure,
        features.entropy_pressure,
        features.kinetic_pressure,
        features.heartbeat_pressure,
        3,
        1,
        2,
        1,
    );
    let intrusion_score = weighted_score4(
        features.intrusion_pressure,
        features.identity_pressure,
        features.integrity_pressure,
        features.kinetic_pressure,
        4,
        3,
        4,
        1,
    );
    let ddos_score = weighted_score4(
        features.ddos_pressure,
        features.scan_pressure,
        features.entropy_pressure,
        features.kinetic_pressure,
        5,
        1,
        2,
        2,
    );
    let integrity_score = weighted_score4(
        features.integrity_pressure,
        features.heartbeat_pressure,
        features.intrusion_pressure,
        features.kinetic_pressure,
        5,
        4,
        2,
        1,
    );
    let kinetic_score = weighted_score4(
        features.kinetic_pressure,
        features.scan_pressure,
        features.entropy_pressure,
        features.heartbeat_pressure,
        4,
        1,
        1,
        2,
    );

    let (kind, peak, runner_up) =
        dominant_kind(scan_score, intrusion_score, integrity_score, ddos_score);
    let dominance_margin = peak.saturating_sub(runner_up).min(u16::from(u8::MAX)) as u8;
    let overall_score = peak
        .saturating_add(u16::from(dominance_margin / 4))
        .min(u16::from(u8::MAX)) as u8;
    let recommended_stage = match kind {
        FastThreatKind::Benign => MitigationStage::Observe,
        FastThreatKind::OffensiveScan => MitigationStage::Throttle,
        FastThreatKind::Intrusion => MitigationStage::Contain,
        FastThreatKind::IntegrityPressure => MitigationStage::Contain,
        FastThreatKind::DdosPressure => MitigationStage::Isolate,
    };

    FastPathDecision {
        cycle_stamp,
        scan_score,
        intrusion_score,
        integrity_score,
        ddos_score,
        kinetic_score,
        dominance_margin,
        overall_score,
        kind,
        recommended_stage,
    }
}

pub fn asm_defense_directive(
    decision: FastPathDecision,
    health: FastPathHealthProfile,
) -> AsmDefenseDirective {
    let resource_pressure =
        health.cpu_load_pct >= 80 || health.memory_load_pct >= 80 || health.thermal_c >= 82;
    let critical_pressure = health.passive_only
        || health.cpu_load_pct >= 92
        || health.memory_load_pct >= 92
        || health.thermal_c >= 88;

    if critical_pressure {
        return AsmDefenseDirective {
            mode: AsmDefenseMode::ZenRecovery,
            observation_window_ms: 90,
            exposure_reduction_pct: 80,
            decoy_budget: 0,
            evidence_budget: 0,
            phantom_jitter_ms: 0,
            guard_bias_pct: 20,
            keep_decoy_capture: false,
            recovery_bias: true,
            resume_standby_after_ms: 900,
        };
    }

    match decision.kind {
        FastThreatKind::Benign => AsmDefenseDirective {
            mode: AsmDefenseMode::Standby,
            observation_window_ms: 0,
            exposure_reduction_pct: 0,
            decoy_budget: 0,
            evidence_budget: 0,
            phantom_jitter_ms: 0,
            guard_bias_pct: 10,
            keep_decoy_capture: false,
            recovery_bias: false,
            resume_standby_after_ms: 0,
        },
        FastThreatKind::OffensiveScan => scan_directive(decision, resource_pressure),
        FastThreatKind::Intrusion => intrusion_directive(decision, resource_pressure),
        FastThreatKind::IntegrityPressure => integrity_directive(decision, resource_pressure),
        FastThreatKind::DdosPressure => ddos_directive(decision, resource_pressure),
    }
}

pub fn guardian_bridge_directive(
    health: FastPathHealthProfile,
    protected_nodes: u16,
    gentle_nodes: u16,
    mesh_enabled: bool,
    peer_distress: bool,
) -> GuardianBridgeDirective {
    if !mesh_enabled {
        return GuardianBridgeDirective {
            mode: GuardianBridgeMode::LocalObserve,
            adoption_budget: 0,
            clean_forward_only: true,
            handoff_ready: false,
            preserve_fragile_paths: false,
            surrogate_load_pct: 0,
        };
    }

    let stressed_host = health.passive_only
        || health.cpu_load_pct >= 88
        || health.memory_load_pct >= 88
        || health.thermal_c >= 84;

    if peer_distress || stressed_host {
        return GuardianBridgeDirective {
            mode: GuardianBridgeMode::ShadowGateway,
            adoption_budget: 0,
            clean_forward_only: true,
            handoff_ready: true,
            preserve_fragile_paths: true,
            surrogate_load_pct: 72,
        };
    }

    if protected_nodes > 0 || gentle_nodes > 0 {
        return GuardianBridgeDirective {
            mode: GuardianBridgeMode::AdoptFragilePeer,
            adoption_budget: if protected_nodes >= 2 { 3 } else { 2 },
            clean_forward_only: true,
            handoff_ready: true,
            preserve_fragile_paths: true,
            surrogate_load_pct: 60,
        };
    }

    GuardianBridgeDirective {
        mode: GuardianBridgeMode::SharedGuardian,
        adoption_budget: 1,
        clean_forward_only: true,
        handoff_ready: true,
        preserve_fragile_paths: false,
        surrogate_load_pct: 50,
    }
}

pub fn mesh_gossip_directive(
    confidence: u8,
    mesh_enabled: bool,
    integrity_event: bool,
    mesh_pressure: bool,
    shadow_gateway: bool,
) -> MeshGossipDirective {
    if !mesh_enabled {
        return MeshGossipDirective {
            mode: MeshGossipMode::Quiet,
            share_hostile_observation: false,
            tighten_trust: false,
            open_shadow_gateway: false,
            consensus_quorum: 0,
            evidence_ttl_ms: 0,
        };
    }

    if shadow_gateway {
        return MeshGossipDirective {
            mode: MeshGossipMode::ShadowGateway,
            share_hostile_observation: true,
            tighten_trust: true,
            open_shadow_gateway: true,
            consensus_quorum: 2,
            evidence_ttl_ms: 120,
        };
    }

    if integrity_event {
        return MeshGossipDirective {
            mode: MeshGossipMode::TightenTrust,
            share_hostile_observation: true,
            tighten_trust: true,
            open_shadow_gateway: false,
            consensus_quorum: 2,
            evidence_ttl_ms: 140,
        };
    }

    if mesh_pressure {
        return MeshGossipDirective {
            mode: MeshGossipMode::TightenTrust,
            share_hostile_observation: true,
            tighten_trust: true,
            open_shadow_gateway: false,
            consensus_quorum: 2,
            evidence_ttl_ms: 160,
        };
    }

    if confidence >= 80 {
        return MeshGossipDirective {
            mode: MeshGossipMode::ShareObservation,
            share_hostile_observation: true,
            tighten_trust: false,
            open_shadow_gateway: false,
            consensus_quorum: if confidence >= 90 { 2 } else { 3 },
            evidence_ttl_ms: if confidence >= 90 { 220 } else { 180 },
        };
    }

    MeshGossipDirective {
        mode: MeshGossipMode::Quiet,
        share_hostile_observation: false,
        tighten_trust: false,
        open_shadow_gateway: false,
        consensus_quorum: 0,
        evidence_ttl_ms: 0,
    }
}

fn dominant_kind(
    scan_score: u16,
    intrusion_score: u16,
    integrity_score: u16,
    ddos_score: u16,
) -> (FastThreatKind, u16, u16) {
    let mut scores = [
        (FastThreatKind::IntegrityPressure, integrity_score),
        (FastThreatKind::DdosPressure, ddos_score),
        (FastThreatKind::Intrusion, intrusion_score),
        (FastThreatKind::OffensiveScan, scan_score),
    ];
    scores.sort_by(|left, right| right.1.cmp(&left.1));
    let (_kind, peak) = scores[0];
    let runner_up = scores[1].1;

    if peak == 0 {
        return (FastThreatKind::Benign, 0, 0);
    }

    if integrity_score >= ddos_score
        && integrity_score >= intrusion_score
        && integrity_score >= scan_score
        && integrity_score > 0
    {
        (FastThreatKind::IntegrityPressure, integrity_score, runner_up)
    } else if ddos_score >= intrusion_score && ddos_score >= scan_score && ddos_score > 0 {
        (FastThreatKind::DdosPressure, ddos_score, runner_up)
    } else if intrusion_score >= scan_score && intrusion_score > 0 {
        (FastThreatKind::Intrusion, intrusion_score, runner_up)
    } else if scan_score > 0 {
        (FastThreatKind::OffensiveScan, scan_score, runner_up)
    } else {
        (FastThreatKind::Benign, 0, 0)
    }
}

fn scan_directive(decision: FastPathDecision, resource_pressure: bool) -> AsmDefenseDirective {
    let dominant_scan = decision.dominance_margin >= 40;
    let kinetic_bias = decision.kinetic_score >= 160;
    let observation_window_ms = if resource_pressure {
        120
    } else if dominant_scan {
        220
    } else {
        180
    };
    let decoy_budget = if resource_pressure {
        1
    } else if dominant_scan {
        4
    } else {
        3
    };
    let evidence_budget = if resource_pressure {
        2
    } else if kinetic_bias || dominant_scan {
        5
    } else {
        4
    };
    let phantom_jitter_ms = if resource_pressure {
        6
    } else if kinetic_bias {
        8
    } else {
        12
    };
    let resume_standby_after_ms = 240 + u16::from(decision.dominance_margin) * 2;

    AsmDefenseDirective {
        mode: AsmDefenseMode::DecoyCapture,
        observation_window_ms,
        exposure_reduction_pct: if dominant_scan { 25 } else { 20 },
        decoy_budget,
        evidence_budget,
        phantom_jitter_ms,
        guard_bias_pct: if dominant_scan { 55 } else { 45 },
        keep_decoy_capture: true,
        recovery_bias: false,
        resume_standby_after_ms,
    }
}

fn intrusion_directive(decision: FastPathDecision, resource_pressure: bool) -> AsmDefenseDirective {
    let heavy_intrusion = decision.dominance_margin >= 35 || decision.overall_score >= 95;

    AsmDefenseDirective {
        mode: AsmDefenseMode::ContainmentGuard,
        observation_window_ms: if resource_pressure { 100 } else { 150 },
        exposure_reduction_pct: if resource_pressure { 50 } else if heavy_intrusion { 40 } else { 30 },
        decoy_budget: if resource_pressure { 0 } else { 1 },
        evidence_budget: if resource_pressure { 1 } else if heavy_intrusion { 3 } else { 2 },
        phantom_jitter_ms: if resource_pressure { 0 } else { 6 },
        guard_bias_pct: if heavy_intrusion { 68 } else { 60 },
        keep_decoy_capture: !resource_pressure && decision.overall_score < 90,
        recovery_bias: resource_pressure,
        resume_standby_after_ms: 360 + u16::from(decision.dominance_margin),
    }
}

fn integrity_directive(decision: FastPathDecision, resource_pressure: bool) -> AsmDefenseDirective {
    AsmDefenseDirective {
        mode: AsmDefenseMode::ContainmentGuard,
        observation_window_ms: if resource_pressure { 72 } else { 90 },
        exposure_reduction_pct: 65,
        decoy_budget: 0,
        evidence_budget: if resource_pressure { 1 } else { 2 },
        phantom_jitter_ms: 0,
        guard_bias_pct: 82,
        keep_decoy_capture: false,
        recovery_bias: true,
        resume_standby_after_ms: 480 + u16::from(decision.dominance_margin),
    }
}

fn ddos_directive(decision: FastPathDecision, resource_pressure: bool) -> AsmDefenseDirective {
    AsmDefenseDirective {
        mode: AsmDefenseMode::ContainmentGuard,
        observation_window_ms: if resource_pressure { 64 } else { 80 },
        exposure_reduction_pct: 70,
        decoy_budget: 0,
        evidence_budget: 1,
        phantom_jitter_ms: 0,
        guard_bias_pct: 88,
        keep_decoy_capture: false,
        recovery_bias: resource_pressure,
        resume_standby_after_ms: 520 + u16::from(decision.dominance_margin),
    }
}

#[cfg(target_arch = "x86_64")]
fn asm_cycle_stamp() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "rdtsc",
            lateout("eax") low,
            lateout("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

#[cfg(not(target_arch = "x86_64"))]
fn asm_cycle_stamp() -> u64 {
    0
}

#[cfg(target_arch = "x86_64")]
fn weighted_score4(a: u8, b: u8, c: u8, d: u8, wa: u8, wb: u8, wc: u8, wd: u8) -> u16 {
    let out: u64;
    unsafe {
        asm!(
            "mov {out}, {a}",
            "imul {out}, {wa}",
            "mov {tmp}, {b}",
            "imul {tmp}, {wb}",
            "add {out}, {tmp}",
            "mov {tmp}, {c}",
            "imul {tmp}, {wc}",
            "add {out}, {tmp}",
            "mov {tmp}, {d}",
            "imul {tmp}, {wd}",
            "add {out}, {tmp}",
            out = lateout(reg) out,
            tmp = lateout(reg) _,
            a = in(reg) u64::from(a),
            b = in(reg) u64::from(b),
            c = in(reg) u64::from(c),
            d = in(reg) u64::from(d),
            wa = in(reg) u64::from(wa),
            wb = in(reg) u64::from(wb),
            wc = in(reg) u64::from(wc),
            wd = in(reg) u64::from(wd),
            options(pure, nomem, nostack)
        );
    }
    out.min(u64::from(u16::MAX)) as u16
}

#[cfg(not(target_arch = "x86_64"))]
fn weighted_score4(a: u8, b: u8, c: u8, d: u8, wa: u8, wb: u8, wc: u8, wd: u8) -> u16 {
    u16::from(a) * u16::from(wa)
        + u16::from(b) * u16::from(wb)
        + u16::from(c) * u16::from(wc)
        + u16::from(d) * u16::from(wd)
}

#[cfg(test)]
mod tests {
    use super::{
        asm_defense_directive, fast_path_assess, guardian_bridge_directive,
        mesh_gossip_directive, native_layer_manifest, AsmDefenseMode, FastPathFeatures,
        FastPathHealthProfile, FastThreatKind, GuardianBridgeMode, MeshGossipMode,
    };

    #[test]
    fn exposes_three_native_layers() {
        let manifest = native_layer_manifest();
        assert_eq!(manifest.len(), 3);
    }

    #[test]
    fn fast_path_prioritizes_ddos_pressure() {
        let decision = fast_path_assess(FastPathFeatures {
            ddos_pressure: 80,
            entropy_pressure: 40,
            ..FastPathFeatures::default()
        });

        assert_eq!(decision.kind, FastThreatKind::DdosPressure);
        assert!(decision.overall_score > 0);
        assert!(decision.dominance_margin > 0);
    }

    #[test]
    fn fast_path_can_surface_integrity_pressure() {
        let decision = fast_path_assess(FastPathFeatures {
            integrity_pressure: 85,
            intrusion_pressure: 20,
            ..FastPathFeatures::default()
        });

        assert_eq!(decision.kind, FastThreatKind::IntegrityPressure);
        assert!(decision.integrity_score > 0);
    }

    #[test]
    fn fast_path_surfaces_kinetic_pressure_for_mass_scan_style_signals() {
        let decision = fast_path_assess(FastPathFeatures {
            scan_pressure: 75,
            entropy_pressure: 35,
            kinetic_pressure: 80,
            ..FastPathFeatures::default()
        });

        assert_eq!(decision.kind, FastThreatKind::OffensiveScan);
        assert!(decision.kinetic_score > 0);
        assert!(decision.dominance_margin > 0);
    }

    #[test]
    fn asm_directive_prefers_decoy_capture_for_scan_pressure() {
        let directive = asm_defense_directive(
            fast_path_assess(FastPathFeatures {
                scan_pressure: 85,
                ..FastPathFeatures::default()
            }),
            FastPathHealthProfile::default(),
        );

        assert_eq!(directive.mode, AsmDefenseMode::DecoyCapture);
        assert!(directive.keep_decoy_capture);
        assert!(directive.decoy_budget > 0);
        assert!(directive.evidence_budget >= 4);
        assert!(directive.guard_bias_pct >= 45);
    }

    #[test]
    fn asm_directive_expands_evidence_ladder_for_dominant_scan() {
        let directive = asm_defense_directive(
            fast_path_assess(FastPathFeatures {
                scan_pressure: 88,
                entropy_pressure: 42,
                kinetic_pressure: 85,
                ..FastPathFeatures::default()
            }),
            FastPathHealthProfile::default(),
        );

        assert_eq!(directive.mode, AsmDefenseMode::DecoyCapture);
        assert_eq!(directive.decoy_budget, 4);
        assert_eq!(directive.evidence_budget, 5);
        assert!(directive.phantom_jitter_ms <= 8);
    }

    #[test]
    fn asm_directive_can_shift_into_zen_recovery() {
        let directive = asm_defense_directive(
            fast_path_assess(FastPathFeatures {
                intrusion_pressure: 80,
                ..FastPathFeatures::default()
            }),
            FastPathHealthProfile {
                cpu_load_pct: 94,
                memory_load_pct: 91,
                thermal_c: 87,
                passive_only: false,
            },
        );

        assert_eq!(directive.mode, AsmDefenseMode::ZenRecovery);
        assert_eq!(directive.decoy_budget, 0);
        assert!(directive.recovery_bias);
        assert_eq!(directive.evidence_budget, 0);
    }

    #[test]
    fn integrity_pressure_hardens_guard_bias() {
        let directive = asm_defense_directive(
            fast_path_assess(FastPathFeatures {
                integrity_pressure: 90,
                heartbeat_pressure: 60,
                kinetic_pressure: 20,
                ..FastPathFeatures::default()
            }),
            FastPathHealthProfile::default(),
        );

        assert_eq!(directive.mode, AsmDefenseMode::ContainmentGuard);
        assert_eq!(directive.decoy_budget, 0);
        assert!(directive.guard_bias_pct >= 80);
    }

    #[test]
    fn guardian_bridge_adopts_fragile_peers_on_calm_mesh() {
        let directive = guardian_bridge_directive(
            FastPathHealthProfile::default(),
            1,
            1,
            true,
            false,
        );

        assert_eq!(directive.mode, GuardianBridgeMode::AdoptFragilePeer);
        assert!(directive.handoff_ready);
        assert!(directive.preserve_fragile_paths);
        assert!(directive.adoption_budget >= 2);
    }

    #[test]
    fn guardian_bridge_shifts_to_shadow_gateway_under_pressure() {
        let directive = guardian_bridge_directive(
            FastPathHealthProfile {
                cpu_load_pct: 92,
                memory_load_pct: 70,
                thermal_c: 80,
                passive_only: false,
            },
            1,
            0,
            true,
            true,
        );

        assert_eq!(directive.mode, GuardianBridgeMode::ShadowGateway);
        assert_eq!(directive.adoption_budget, 0);
        assert!(directive.handoff_ready);
    }

    #[test]
    fn mesh_gossip_opens_shadow_gateway_on_integrity_pressure() {
        let directive = mesh_gossip_directive(96, true, true, true, true);

        assert_eq!(directive.mode, MeshGossipMode::ShadowGateway);
        assert!(directive.share_hostile_observation);
        assert!(directive.tighten_trust);
        assert_eq!(directive.consensus_quorum, 2);
        assert_eq!(directive.evidence_ttl_ms, 120);
    }
}
