#![forbid(unsafe_code)]

use sentinel_common::{AttackFamily, HealthSnapshot, ThreatSignal};
use sentinel_config::{AutonomyMode, DeploymentShape, PerformanceProfile, RuntimeConfig};
use sentinel_native_bridge::{AsmDefenseDirective, AsmDefenseMode};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchitecturePattern {
    EdgeGuardian,
    BalancedMesh,
    FragileMeshGuard,
    PressureShield,
}

impl ArchitecturePattern {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EdgeGuardian => "edge-guardian",
            Self::BalancedMesh => "balanced-mesh",
            Self::FragileMeshGuard => "fragile-mesh-guard",
            Self::PressureShield => "pressure-shield",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultIsolationLevel {
    Standard,
    Strict,
    Maximum,
}

impl FaultIsolationLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Strict => "strict",
            Self::Maximum => "maximum",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeWorkSplit {
    pub rust_control_pct: u8,
    pub c_guard_pct: u8,
    pub cpp_classifier_pct: u8,
    pub asm_fast_path_pct: u8,
}

impl NativeWorkSplit {
    pub const fn total(self) -> u16 {
        self.rust_control_pct as u16
            + self.c_guard_pct as u16
            + self.cpp_classifier_pct as u16
            + self.asm_fast_path_pct as u16
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutonomyPlan {
    pub autonomy_mode: AutonomyMode,
    pub deployment_shape: DeploymentShape,
    pub performance_profile: PerformanceProfile,
    pub pattern: ArchitecturePattern,
    pub fault_isolation: FaultIsolationLevel,
    pub packet_lanes: u8,
    pub classifier_lanes: u8,
    pub correlation_lanes: u8,
    pub reporter_lanes: u8,
    pub stability_headroom_pct: u8,
    pub max_decoy_slots: u16,
    pub phantom_sample_cap: u8,
    pub allow_spot_mimicry: bool,
    pub allow_mesh_distribution: bool,
    pub native_work_split: NativeWorkSplit,
    pub narrative: String,
}

pub fn plan_autonomy(
    config: &RuntimeConfig,
    signal: &ThreatSignal,
    health: &HealthSnapshot,
    asm_directive: AsmDefenseDirective,
) -> AutonomyPlan {
    let base_pattern = match config.deployment_shape {
        DeploymentShape::FragileMesh => ArchitecturePattern::FragileMeshGuard,
        DeploymentShape::MultiNodeMesh => ArchitecturePattern::BalancedMesh,
        DeploymentShape::SingleNode => {
            if is_pressure_heavy(signal.family.clone(), asm_directive) {
                ArchitecturePattern::PressureShield
            } else {
                ArchitecturePattern::EdgeGuardian
            }
        }
    };

    let mut plan = match base_pattern {
        ArchitecturePattern::EdgeGuardian => AutonomyPlan {
            autonomy_mode: config.autonomy_mode,
            deployment_shape: config.deployment_shape,
            performance_profile: config.performance_profile,
            pattern: base_pattern,
            fault_isolation: FaultIsolationLevel::Standard,
            packet_lanes: 2,
            classifier_lanes: 2,
            correlation_lanes: 1,
            reporter_lanes: 1,
            stability_headroom_pct: 30,
            max_decoy_slots: 6,
            phantom_sample_cap: 4,
            allow_spot_mimicry: true,
            allow_mesh_distribution: false,
            native_work_split: NativeWorkSplit {
                rust_control_pct: 40,
                c_guard_pct: 20,
                cpp_classifier_pct: 20,
                asm_fast_path_pct: 20,
            },
            narrative: String::new(),
        },
        ArchitecturePattern::BalancedMesh => AutonomyPlan {
            autonomy_mode: config.autonomy_mode,
            deployment_shape: config.deployment_shape,
            performance_profile: config.performance_profile,
            pattern: base_pattern,
            fault_isolation: FaultIsolationLevel::Strict,
            packet_lanes: 3,
            classifier_lanes: 3,
            correlation_lanes: 2,
            reporter_lanes: 1,
            stability_headroom_pct: 28,
            max_decoy_slots: 8,
            phantom_sample_cap: 5,
            allow_spot_mimicry: true,
            allow_mesh_distribution: true,
            native_work_split: NativeWorkSplit {
                rust_control_pct: 35,
                c_guard_pct: 20,
                cpp_classifier_pct: 25,
                asm_fast_path_pct: 20,
            },
            narrative: String::new(),
        },
        ArchitecturePattern::FragileMeshGuard => AutonomyPlan {
            autonomy_mode: config.autonomy_mode,
            deployment_shape: config.deployment_shape,
            performance_profile: config.performance_profile,
            pattern: base_pattern,
            fault_isolation: FaultIsolationLevel::Maximum,
            packet_lanes: 2,
            classifier_lanes: 1,
            correlation_lanes: 1,
            reporter_lanes: 1,
            stability_headroom_pct: 45,
            max_decoy_slots: 3,
            phantom_sample_cap: 2,
            allow_spot_mimicry: false,
            allow_mesh_distribution: false,
            native_work_split: NativeWorkSplit {
                rust_control_pct: 45,
                c_guard_pct: 25,
                cpp_classifier_pct: 20,
                asm_fast_path_pct: 10,
            },
            narrative: String::new(),
        },
        ArchitecturePattern::PressureShield => AutonomyPlan {
            autonomy_mode: config.autonomy_mode,
            deployment_shape: config.deployment_shape,
            performance_profile: config.performance_profile,
            pattern: base_pattern,
            fault_isolation: FaultIsolationLevel::Strict,
            packet_lanes: 4,
            classifier_lanes: 3,
            correlation_lanes: 2,
            reporter_lanes: 1,
            stability_headroom_pct: 35,
            max_decoy_slots: 5,
            phantom_sample_cap: 4,
            allow_spot_mimicry: false,
            allow_mesh_distribution: matches!(
                config.deployment_shape,
                DeploymentShape::MultiNodeMesh
            ),
            native_work_split: NativeWorkSplit {
                rust_control_pct: 25,
                c_guard_pct: 20,
                cpp_classifier_pct: 15,
                asm_fast_path_pct: 40,
            },
            narrative: String::new(),
        },
    };

    match config.performance_profile {
        PerformanceProfile::StabilityFirst => {
            plan.stability_headroom_pct = plan.stability_headroom_pct.saturating_add(10).min(60);
            plan.max_decoy_slots = plan.max_decoy_slots.min(3);
            plan.phantom_sample_cap = plan.phantom_sample_cap.min(3);
            plan.packet_lanes = plan.packet_lanes.min(2);
            plan.classifier_lanes = plan.classifier_lanes.min(2);
        }
        PerformanceProfile::Balanced => {}
        PerformanceProfile::PressureShield => {
            plan.pattern = ArchitecturePattern::PressureShield;
            plan.fault_isolation = FaultIsolationLevel::Strict;
            plan.packet_lanes = plan.packet_lanes.max(4);
            plan.classifier_lanes = plan.classifier_lanes.max(3);
            plan.correlation_lanes = plan.correlation_lanes.max(2);
            plan.stability_headroom_pct = plan.stability_headroom_pct.saturating_sub(5).max(25);
            plan.native_work_split = NativeWorkSplit {
                rust_control_pct: 25,
                c_guard_pct: 20,
                cpp_classifier_pct: 15,
                asm_fast_path_pct: 40,
            };
        }
    }

    let under_stress = health.cpu_load_pct >= 80
        || health.memory_load_pct >= 80
        || health.thermal_c >= 82
        || health.passive_only;
    if under_stress {
        plan.fault_isolation = escalate_fault_isolation(plan.fault_isolation);
        plan.stability_headroom_pct = plan.stability_headroom_pct.saturating_add(8).min(65);
        plan.max_decoy_slots = plan.max_decoy_slots.min(2);
        plan.phantom_sample_cap = plan.phantom_sample_cap.min(2);
        plan.allow_spot_mimicry = false;
    }

    if matches!(
        asm_directive.mode,
        AsmDefenseMode::DecoyCapture | AsmDefenseMode::ContainmentGuard
    ) {
        plan.packet_lanes = plan.packet_lanes.max(4);
        plan.correlation_lanes = plan.correlation_lanes.max(2);
        if asm_directive.guard_bias_pct >= 75 {
            plan.native_work_split = NativeWorkSplit {
                rust_control_pct: 25,
                c_guard_pct: 25,
                cpp_classifier_pct: 10,
                asm_fast_path_pct: 40,
            };
        } else if asm_directive.guard_bias_pct >= 50 {
            plan.native_work_split = NativeWorkSplit {
                rust_control_pct: 25,
                c_guard_pct: 20,
                cpp_classifier_pct: 15,
                asm_fast_path_pct: 40,
            };
        } else {
            plan.native_work_split = NativeWorkSplit {
                rust_control_pct: 30,
                c_guard_pct: 20,
                cpp_classifier_pct: 15,
                asm_fast_path_pct: 35,
            };
        }
        if matches!(asm_directive.mode, AsmDefenseMode::DecoyCapture) {
            plan.phantom_sample_cap = plan
                .phantom_sample_cap
                .max(asm_directive.evidence_budget.min(5));
            plan.max_decoy_slots = plan
                .max_decoy_slots
                .min(u16::from(asm_directive.evidence_budget.max(1)));
        } else {
            plan.max_decoy_slots = plan.max_decoy_slots.min(1);
            plan.phantom_sample_cap = plan.phantom_sample_cap.min(2);
        }
    }

    if matches!(asm_directive.mode, AsmDefenseMode::ZenRecovery) {
        plan.fault_isolation = FaultIsolationLevel::Maximum;
        plan.packet_lanes = 1;
        plan.classifier_lanes = 1;
        plan.correlation_lanes = 1;
        plan.reporter_lanes = 1;
        plan.stability_headroom_pct = plan.stability_headroom_pct.max(55);
        plan.max_decoy_slots = 0;
        plan.phantom_sample_cap = 0;
        plan.allow_spot_mimicry = false;
        plan.allow_mesh_distribution = false;
        plan.native_work_split = NativeWorkSplit {
            rust_control_pct: 45,
            c_guard_pct: 25,
            cpp_classifier_pct: 15,
            asm_fast_path_pct: 15,
        };
    }

    if matches!(config.autonomy_mode, AutonomyMode::Assisted) {
        plan.fault_isolation = escalate_fault_isolation(plan.fault_isolation);
        plan.stability_headroom_pct = plan.stability_headroom_pct.max(40);
    }

    plan.narrative = format!(
        "pattern={} autonomy={} deployment={} performance={} fault_isolation={} lanes=packet:{} classifier:{} correlation:{} reporter:{} headroom_pct={} decoy_cap={} phantom_sample_cap={} mesh_distribution={} work_split=rust:{} c:{} cpp:{} asm:{}",
        plan.pattern.as_str(),
        plan.autonomy_mode.as_str(),
        plan.deployment_shape.as_str(),
        plan.performance_profile.as_str(),
        plan.fault_isolation.as_str(),
        plan.packet_lanes,
        plan.classifier_lanes,
        plan.correlation_lanes,
        plan.reporter_lanes,
        plan.stability_headroom_pct,
        plan.max_decoy_slots,
        plan.phantom_sample_cap,
        plan.allow_mesh_distribution,
        plan.native_work_split.rust_control_pct,
        plan.native_work_split.c_guard_pct,
        plan.native_work_split.cpp_classifier_pct,
        plan.native_work_split.asm_fast_path_pct
    );

    plan
}

fn is_pressure_heavy(family: AttackFamily, asm_directive: AsmDefenseDirective) -> bool {
    matches!(
        family,
        AttackFamily::OffensiveScan
            | AttackFamily::VolumetricFlood
            | AttackFamily::PayloadStager
            | AttackFamily::ExploitDelivery
            | AttackFamily::RemoteAccessTrojan
    ) || matches!(
        asm_directive.mode,
        AsmDefenseMode::DecoyCapture | AsmDefenseMode::ContainmentGuard
    )
}

fn escalate_fault_isolation(level: FaultIsolationLevel) -> FaultIsolationLevel {
    match level {
        FaultIsolationLevel::Standard => FaultIsolationLevel::Strict,
        FaultIsolationLevel::Strict | FaultIsolationLevel::Maximum => FaultIsolationLevel::Maximum,
    }
}

#[cfg(test)]
mod tests {
    use super::{plan_autonomy, ArchitecturePattern, FaultIsolationLevel};
    use sentinel_common::{AttackFamily, HealthSnapshot, ThreatSignal};
    use sentinel_config::{AutonomyMode, DeploymentShape, PerformanceProfile, RuntimeConfig};
    use sentinel_native_bridge::{
        asm_defense_directive, fast_path_assess, FastPathFeatures, FastPathHealthProfile,
    };

    fn signal(family: AttackFamily) -> ThreatSignal {
        ThreatSignal {
            source_name: "203.0.113.88".to_string(),
            family,
            confidence: 84,
            recognition: None,
            analysis_lanes: vec!["asm-fast-path".to_string()],
            detail: "test".to_string(),
        }
    }

    #[test]
    fn fragile_mesh_guard_prioritizes_headroom() {
        let config = RuntimeConfig {
            deployment_shape: DeploymentShape::FragileMesh,
            performance_profile: PerformanceProfile::StabilityFirst,
            ..RuntimeConfig::default()
        };
        let plan = plan_autonomy(
            &config,
            &signal(AttackFamily::PayloadStager),
            &HealthSnapshot::default(),
            asm_defense_directive(
                fast_path_assess(FastPathFeatures {
                    intrusion_pressure: 75,
                    ..FastPathFeatures::default()
                }),
                FastPathHealthProfile::default(),
            ),
        );

        assert_eq!(plan.pattern, ArchitecturePattern::FragileMeshGuard);
        assert!(!plan.allow_spot_mimicry);
        assert!(plan.stability_headroom_pct >= 45);
        assert_eq!(plan.fault_isolation, FaultIsolationLevel::Maximum);
        assert_eq!(plan.native_work_split.total(), 100);
    }

    #[test]
    fn pressure_shield_biases_asm_and_packet_lanes() {
        let config = RuntimeConfig {
            autonomy_mode: AutonomyMode::GuardianAutonomous,
            deployment_shape: DeploymentShape::SingleNode,
            performance_profile: PerformanceProfile::PressureShield,
            ..RuntimeConfig::default()
        };
        let plan = plan_autonomy(
            &config,
            &signal(AttackFamily::OffensiveScan),
            &HealthSnapshot::default(),
            asm_defense_directive(
                fast_path_assess(FastPathFeatures {
                    scan_pressure: 88,
                    ..FastPathFeatures::default()
                }),
                FastPathHealthProfile::default(),
            ),
        );

        assert_eq!(plan.pattern, ArchitecturePattern::PressureShield);
        assert!(plan.packet_lanes >= 4);
        assert!(plan.native_work_split.asm_fast_path_pct >= 40);
        assert_eq!(plan.native_work_split.total(), 100);
    }
}
