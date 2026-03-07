#![forbid(unsafe_code)]

use sentinel_common::{MitigationStage, SourceInventory};

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub node_name: String,
    pub passive_only: bool,
    pub max_stage: MitigationStage,
    pub source_inventory: SourceInventory,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            node_name: "sentinel-node-01".to_string(),
            passive_only: false,
            max_stage: MitigationStage::Isolate,
            source_inventory: SourceInventory::current(),
        }
    }
}

