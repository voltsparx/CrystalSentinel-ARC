#![forbid(unsafe_code)]

use sentinel_config::RuntimeConfig;
use sentinel_detection::{detect_signal, seed_framework_catalog, seed_intel_sources};
use sentinel_flow::{FlowKey, FlowTracker};
use sentinel_forensics::InvestigationRecord;
use sentinel_native_bridge::native_layer_manifest;
use sentinel_policy::PolicyEngine;
use sentinel_response::ResponsePlanner;
use sentinel_storage::MemoryStore;
use sentinel_telemetry::sample_events;

fn main() {
    let config = RuntimeConfig::default();
    let intel_sources = seed_intel_sources();
    let frameworks = seed_framework_catalog();
    let native_layers = native_layer_manifest();
    let policy = PolicyEngine::default();
    let mut flow_tracker = FlowTracker::default();
    let mut store = MemoryStore::default();

    println!("CrystalSentinel-CRA runtime starting");
    println!("node: {}", config.node_name);
    println!("intel sources loaded: {}", intel_sources.len());
    println!("framework fingerprints seeded: {}", frameworks.len());
    println!("native layers scaffolded: {}", native_layers.len());

    for event in sample_events() {
        let flow_key = FlowKey {
            source: event.source.clone(),
            destination: config.node_name.clone(),
            protocol: event.kind.as_str().to_string(),
        };
        flow_tracker.observe(flow_key);

        let signal = detect_signal(&event);
        let assessment = policy.assess(signal, event.health);
        let plan = ResponsePlanner::plan(&assessment);
        let record = InvestigationRecord::from_assessment(&assessment, &plan);

        println!(
            "assessment: source={} family={} stage={}",
            assessment.signal.source_name,
            assessment.signal.family.as_str(),
            assessment.stage.as_str()
        );

        store.store_assessment(assessment);
        store.store_record(record);
    }

    println!("tracked flows: {}", flow_tracker.len());
    println!("stored assessments: {}", store.assessment_count());
    println!("stored investigation records: {}", store.record_count());
}
