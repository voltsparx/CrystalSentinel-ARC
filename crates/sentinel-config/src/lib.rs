#![forbid(unsafe_code)]

use sentinel_common::{MitigationStage, SourceInventory};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchProfile {
    Protector,
    Architect,
}

impl LaunchProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Protector => "protector",
            Self::Architect => "architect",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutonomyMode {
    Assisted,
    GuardianAutonomous,
}

impl AutonomyMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Assisted => "assisted",
            Self::GuardianAutonomous => "guardian-autonomous",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeploymentShape {
    SingleNode,
    MultiNodeMesh,
    FragileMesh,
}

impl DeploymentShape {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SingleNode => "single-node",
            Self::MultiNodeMesh => "multi-node-mesh",
            Self::FragileMesh => "fragile-mesh",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PerformanceProfile {
    StabilityFirst,
    Balanced,
    PressureShield,
}

impl PerformanceProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StabilityFirst => "stability-first",
            Self::Balanced => "balanced",
            Self::PressureShield => "pressure-shield",
        }
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub node_name: String,
    pub passive_only: bool,
    pub max_stage: MitigationStage,
    pub launch_profile: LaunchProfile,
    pub autonomy_mode: AutonomyMode,
    pub deployment_shape: DeploymentShape,
    pub performance_profile: PerformanceProfile,
    pub allow_decoys: bool,
    pub quiet_reporter: bool,
    pub source_inventory: SourceInventory,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            node_name: "sentinel-node-01".to_string(),
            passive_only: false,
            max_stage: MitigationStage::Isolate,
            launch_profile: LaunchProfile::Protector,
            autonomy_mode: AutonomyMode::GuardianAutonomous,
            deployment_shape: DeploymentShape::SingleNode,
            performance_profile: PerformanceProfile::Balanced,
            allow_decoys: true,
            quiet_reporter: true,
            source_inventory: SourceInventory::current(),
        }
    }
}
