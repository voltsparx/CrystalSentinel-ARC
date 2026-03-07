#![forbid(unsafe_code)]

use std::panic::{catch_unwind, AssertUnwindSafe};

use sentinel_config::RuntimeConfig;
use sentinel_correlation::CorrelationEngine;
use sentinel_detection::{seed_framework_catalog, seed_intel_sources};
use sentinel_flow::{FlowKey, FlowTracker};
use sentinel_native_bridge::native_layer_manifest;
use sentinel_reporting::ReporterEngine;
use sentinel_runtime::SentinelRuntime;
use sentinel_storage::MemoryStore;
use sentinel_telemetry::sample_events;

fn main() {
    let config = RuntimeConfig::default();
    let intel_sources = seed_intel_sources();
    let frameworks = seed_framework_catalog();
    let native_layers = native_layer_manifest();
    let runtime = SentinelRuntime::default();
    let mut flow_tracker = FlowTracker::default();
    let mut store = MemoryStore::default();
    let mut decisions = Vec::new();

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

        let decision = runtime.process_event(&config, &event);
        let actions = decision
            .plan
            .actions
            .iter()
            .map(|action| action.as_str())
            .collect::<Vec<_>>()
            .join(", ");

        println!(
            "assessment: source={} family={} stage={} posture={} fast_kind={} fast_score={}",
            decision.assessment.signal.source_name,
            decision.assessment.signal.family.as_str(),
            decision.assessment.stage.as_str(),
            decision.posture.as_str(),
            decision.fast_path.kind.as_str(),
            decision.fast_path.overall_score
        );
        println!(
            "asm: mode={} observation_window_ms={} exposure_reduction_pct={} decoy_budget={} keep_decoy_capture={} resume_standby_after_ms={}",
            decision.asm_directive.mode.as_str(),
            decision.asm_directive.observation_window_ms,
            decision.asm_directive.exposure_reduction_pct,
            decision.asm_directive.decoy_budget,
            decision.asm_directive.keep_decoy_capture,
            decision.asm_directive.resume_standby_after_ms
        );
        println!(
            "autonomy: mode={} pattern={} fault_isolation={} headroom_pct={} lanes=packet:{} classifier:{} correlation:{} reporter:{} mesh_distribution={} work_split=rust:{} c:{} cpp:{} asm:{}",
            decision.autonomy_plan.autonomy_mode.as_str(),
            decision.autonomy_plan.pattern.as_str(),
            decision.autonomy_plan.fault_isolation.as_str(),
            decision.autonomy_plan.stability_headroom_pct,
            decision.autonomy_plan.packet_lanes,
            decision.autonomy_plan.classifier_lanes,
            decision.autonomy_plan.correlation_lanes,
            decision.autonomy_plan.reporter_lanes,
            decision.autonomy_plan.allow_mesh_distribution,
            decision.autonomy_plan.native_work_split.rust_control_pct,
            decision.autonomy_plan.native_work_split.c_guard_pct,
            decision.autonomy_plan.native_work_split.cpp_classifier_pct,
            decision.autonomy_plan.native_work_split.asm_fast_path_pct
        );
        println!("awareness: {}", decision.awareness.summary);
        if let Some(decoy) = &decision.decoy_plan {
            println!(
                "decoy: profile={} intensity={} cadence_ms={} ghost_slots={} primitives={}",
                decoy.profile.as_str(),
                decoy.intensity.as_str(),
                decoy.cadence_ms,
                decoy.ghost_slots,
                decoy
                    .primitives
                    .iter()
                    .map(|primitive| primitive.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            if let Some(phantom) = &decoy.phantom_observation {
                println!(
                    "phantom: cadence_ms={} jitter_ms={} phase_offset_ms={} burst_slots={}",
                    phantom.cadence_ms,
                    phantom.jitter_ms,
                    phantom.phase_offset_ms,
                    phantom.burst_slots
                );
            }
        }
        if let Some(recovery) = &decision.recovery_triage {
            println!(
                "recovery: mode={} stability_window_ms={} summary={}",
                recovery.mode.as_str(),
                recovery.stability_window_ms,
                recovery.summary
            );
        }
        println!("actions: {}", actions);
        println!("plan: {}", decision.plan.narrative);
        if let Some(hint) = decision.teaching_hint {
            println!("teach: {}", hint);
        }
        println!("detail: {}", decision.assessment.signal.detail);

        decisions.push(decision.clone());
        store.store_assessment(decision.assessment);
        store.store_record(decision.record);
    }

    match run_isolated("correlator", || CorrelationEngine::correlate(&decisions)) {
        Ok(incidents) => {
            println!(
                "engine: correlator status=ready incidents={}",
                incidents.len()
            );

            match run_isolated("reporters", || ReporterEngine::render_all(&incidents)) {
                Ok(reports) => {
                    println!("engine: reporters status=ready");
                    println!("{}", reports.operator_report);
                    println!("{}", reports.forensic_report);
                    println!("{}", reports.human_report);
                    println!("{}", reports.teaching_report);
                    println!("{}", reports.care_report);
                }
                Err(reason) => {
                    println!("engine: reporters status=fault-isolated reason={reason}");
                }
            }
        }
        Err(reason) => {
            println!("engine: correlator status=fault-isolated reason={reason}");
        }
    }

    println!("tracked flows: {}", flow_tracker.len());
    println!("stored assessments: {}", store.assessment_count());
    println!("stored investigation records: {}", store.record_count());
}

fn run_isolated<T, F>(engine_name: &'static str, job: F) -> Result<T, String>
where
    F: FnOnce() -> T,
{
    catch_unwind(AssertUnwindSafe(job))
        .map_err(|_| format!("{engine_name} panicked and was isolated from the main runtime"))
}
