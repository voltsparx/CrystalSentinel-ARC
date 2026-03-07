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

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub node_name: String,
    pub passive_only: bool,
    pub max_stage: MitigationStage,
    pub launch_profile: LaunchProfile,
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
            allow_decoys: true,
            quiet_reporter: true,
            source_inventory: SourceInventory::current(),
        }
    }
}
