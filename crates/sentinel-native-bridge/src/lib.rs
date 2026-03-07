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
            responsibility: "Resource guards, stability-first observation budgeting, protocol and mesh safety caps, exposure reduction planning, descriptor-safe compatibility shims, and OS-facing packet helpers.",
            entrypoint: "sentinel_c_resource_guard / sentinel_c_budget_window / sentinel_c_exposure_guard / sentinel_c_protocol_budget / sentinel_c_mesh_guard",
            status: NativeLayerStatus::Scaffolded,
        },
        NativeLayerSpec {
            language: NativeLanguage::Cpp,
            library: "sentinel-native-cpp",
            responsibility: "Stateful classifiers, scan-path prediction, ambient-state modeling, behavior matrices, recovery prediction, and attack-template modeling.",
            entrypoint: "sentinel_cpp_classify / sentinel_cpp_predict_scan_path / sentinel_cpp_ambient_state / sentinel_cpp_behavior_matrix / sentinel_cpp_recovery_predictor",
            status: NativeLayerStatus::Scaffolded,
        },
        NativeLayerSpec {
            language: NativeLanguage::Asm,
            library: "sentinel-native-asm",
            responsibility: "Linked timing primitives, weighted pressure mixing, fast-path pressure scoring, health-aware zen fallback decisions, and bounded direct-to-wire readiness for defensive paths.",
            entrypoint: "fast_path_assess / asm_defense_directive / sentinel_asm_weighted_mix / sentinel_asm_pressure_mode / sentinel_asm_observation_window / sentinel_asm_decoy_budget",
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
    pub keep_decoy_capture: bool,
    pub recovery_bias: bool,
    pub resume_standby_after_ms: u16,
}

pub fn fast_path_assess(features: FastPathFeatures) -> FastPathDecision {
    let cycle_stamp = asm_cycle_stamp();
    let scan_score = weighted_score(
        features.scan_pressure,
        features.entropy_pressure,
        features.integrity_pressure,
        3,
        1,
        1,
    );
    let intrusion_score = weighted_score(
        features.intrusion_pressure,
        features.identity_pressure,
        features.integrity_pressure,
        4,
        3,
        4,
    );
    let ddos_score = weighted_score(
        features.ddos_pressure,
        features.scan_pressure,
        features.entropy_pressure,
        5,
        1,
        2,
    );
    let integrity_score = weighted_score(
        features.integrity_pressure,
        features.intrusion_pressure,
        features.identity_pressure,
        5,
        2,
        2,
    );

    let (kind, peak) = dominant_kind(scan_score, intrusion_score, integrity_score, ddos_score);
    let overall_score = peak.min(u16::from(u8::MAX)) as u8;
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
            keep_decoy_capture: false,
            recovery_bias: false,
            resume_standby_after_ms: 0,
        },
        FastThreatKind::OffensiveScan => AsmDefenseDirective {
            mode: AsmDefenseMode::DecoyCapture,
            observation_window_ms: if resource_pressure { 120 } else { 180 },
            exposure_reduction_pct: 20,
            decoy_budget: if resource_pressure { 1 } else { 3 },
            keep_decoy_capture: true,
            recovery_bias: false,
            resume_standby_after_ms: 240,
        },
        FastThreatKind::Intrusion => AsmDefenseDirective {
            mode: AsmDefenseMode::ContainmentGuard,
            observation_window_ms: if resource_pressure { 100 } else { 140 },
            exposure_reduction_pct: if resource_pressure { 45 } else { 30 },
            decoy_budget: if resource_pressure { 0 } else { 1 },
            keep_decoy_capture: !resource_pressure && decision.overall_score < 90,
            recovery_bias: resource_pressure,
            resume_standby_after_ms: 360,
        },
        FastThreatKind::IntegrityPressure | FastThreatKind::DdosPressure => AsmDefenseDirective {
            mode: AsmDefenseMode::ContainmentGuard,
            observation_window_ms: 80,
            exposure_reduction_pct: 60,
            decoy_budget: 0,
            keep_decoy_capture: false,
            recovery_bias: resource_pressure,
            resume_standby_after_ms: 480,
        },
    }
}

fn dominant_kind(
    scan_score: u16,
    intrusion_score: u16,
    integrity_score: u16,
    ddos_score: u16,
) -> (FastThreatKind, u16) {
    if integrity_score >= ddos_score
        && integrity_score >= intrusion_score
        && integrity_score >= scan_score
        && integrity_score > 0
    {
        (FastThreatKind::IntegrityPressure, integrity_score)
    } else if ddos_score >= intrusion_score && ddos_score >= scan_score && ddos_score > 0 {
        (FastThreatKind::DdosPressure, ddos_score)
    } else if intrusion_score >= scan_score && intrusion_score > 0 {
        (FastThreatKind::Intrusion, intrusion_score)
    } else if scan_score > 0 {
        (FastThreatKind::OffensiveScan, scan_score)
    } else {
        (FastThreatKind::Benign, 0)
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
fn weighted_score(a: u8, b: u8, c: u8, wa: u8, wb: u8, wc: u8) -> u16 {
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
            out = lateout(reg) out,
            tmp = lateout(reg) _,
            a = in(reg) u64::from(a),
            b = in(reg) u64::from(b),
            c = in(reg) u64::from(c),
            wa = in(reg) u64::from(wa),
            wb = in(reg) u64::from(wb),
            wc = in(reg) u64::from(wc),
            options(pure, nomem, nostack)
        );
    }
    out.min(u64::from(u16::MAX)) as u16
}

#[cfg(not(target_arch = "x86_64"))]
fn weighted_score(a: u8, b: u8, c: u8, wa: u8, wb: u8, wc: u8) -> u16 {
    u16::from(a) * u16::from(wa) + u16::from(b) * u16::from(wb) + u16::from(c) * u16::from(wc)
}

#[cfg(test)]
mod tests {
    use super::{
        asm_defense_directive, fast_path_assess, native_layer_manifest, AsmDefenseMode,
        FastPathFeatures, FastPathHealthProfile, FastThreatKind,
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
    }
}
