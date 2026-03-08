#![forbid(unsafe_code)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use sentinel_common::MitigationStage;
use sentinel_config::{
    AutonomyMode, DeploymentShape, LaunchProfile, PerformanceProfile, RuntimeConfig,
};
use sentinel_correlation::CorrelationEngine;
use sentinel_detection::{seed_framework_catalog, seed_intel_sources};
use sentinel_flow::{FlowKey, FlowTracker};
use sentinel_native_bridge::native_layer_manifest;
use sentinel_reporting::ReporterEngine;
use sentinel_runtime::SentinelRuntime;
use sentinel_storage::MemoryStore;
use sentinel_telemetry::{
    JsonlFileCollector, SampleTelemetryCollector, StdinJsonlCollector, TelemetryCollector,
};

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let command = DaemonCommand::parse(std::env::args().skip(1))?;
    if matches!(command, DaemonCommand::Help) {
        println!("{}", usage());
        return Ok(());
    }

    let DaemonCommand::Run(args) = command else {
        return Ok(());
    };

    let mut config = RuntimeConfig::default();
    args.apply_to_config(&mut config);
    let intel_sources = seed_intel_sources();
    let frameworks = seed_framework_catalog();
    let native_layers = native_layer_manifest();
    let runtime = SentinelRuntime::default();
    let mut flow_tracker = FlowTracker::default();
    let mut store = MemoryStore::default();
    let mut decisions = Vec::new();

    println!("CrystalSentinel-ARC runtime starting");
    println!("node: {}", config.node_name);
    println!(
        "launch: profile={} autonomy={} deployment={} performance={} passive_only={} max_stage={}",
        config.launch_profile.as_str(),
        config.autonomy_mode.as_str(),
        config.deployment_shape.as_str(),
        config.performance_profile.as_str(),
        config.passive_only,
        config.max_stage.as_str()
    );
    println!("intel sources loaded: {}", intel_sources.len());
    println!("framework fingerprints seeded: {}", frameworks.len());
    println!("native layers scaffolded: {}", native_layers.len());
    println!("telemetry source: {}", args.telemetry_label());

    let collector = args.into_collector();
    let events = collector
        .collect()
        .map_err(|err| format!("telemetry collection failed: {err}"))?;
    println!("telemetry events loaded: {}", events.len());

    for event in events {
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

    Ok(())
}

fn run_isolated<T, F>(engine_name: &'static str, job: F) -> Result<T, String>
where
    F: FnOnce() -> T,
{
    catch_unwind(AssertUnwindSafe(job))
        .map_err(|_| format!("{engine_name} panicked and was isolated from the main runtime"))
}

#[derive(Debug, PartialEq, Eq)]
enum DaemonCommand {
    Run(DaemonArgs),
    Help,
}

impl DaemonCommand {
    fn parse<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut telemetry_mode = None;
        let mut node_name = None;
        let mut passive_only = false;
        let mut launch_profile = None;
        let mut autonomy_mode = None;
        let mut deployment_shape = None;
        let mut performance_profile = None;
        let mut max_stage = None;
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--sample" => set_telemetry_mode(&mut telemetry_mode, TelemetryMode::Sample)?,
                "--stdin-jsonl" => {
                    set_telemetry_mode(&mut telemetry_mode, TelemetryMode::StdinJsonl)?
                }
                "--telemetry-file" => {
                    let path = args
                        .next()
                        .ok_or_else(|| "--telemetry-file requires a path".to_string())?;
                    set_telemetry_mode(
                        &mut telemetry_mode,
                        TelemetryMode::JsonlFile(PathBuf::from(path)),
                    )?;
                }
                "--node-name" => {
                    node_name = Some(
                        args.next()
                            .ok_or_else(|| "--node-name requires a value".to_string())?,
                    );
                }
                "--passive-only" => passive_only = true,
                "--launch-profile" => {
                    launch_profile = Some(LaunchProfile::parse(
                        &args.next()
                            .ok_or_else(|| "--launch-profile requires a value".to_string())?,
                    )?);
                }
                "--autonomy-mode" => {
                    autonomy_mode = Some(AutonomyMode::parse(
                        &args.next()
                            .ok_or_else(|| "--autonomy-mode requires a value".to_string())?,
                    )?);
                }
                "--deployment-shape" => {
                    deployment_shape = Some(DeploymentShape::parse(
                        &args.next()
                            .ok_or_else(|| "--deployment-shape requires a value".to_string())?,
                    )?);
                }
                "--performance-profile" => {
                    performance_profile = Some(PerformanceProfile::parse(
                        &args.next().ok_or_else(|| {
                            "--performance-profile requires a value".to_string()
                        })?,
                    )?);
                }
                "--max-stage" => {
                    max_stage = Some(MitigationStage::parse(
                        &args.next()
                            .ok_or_else(|| "--max-stage requires a value".to_string())?,
                    )?);
                }
                "--help" | "-h" => return Ok(Self::Help),
                _ => return Err(format!("unknown argument `{arg}`\n{}", usage())),
            }
        }

        Ok(Self::Run(DaemonArgs {
            telemetry_mode: telemetry_mode.unwrap_or(TelemetryMode::Sample),
            node_name,
            passive_only,
            launch_profile,
            autonomy_mode,
            deployment_shape,
            performance_profile,
            max_stage,
        }))
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DaemonArgs {
    telemetry_mode: TelemetryMode,
    node_name: Option<String>,
    passive_only: bool,
    launch_profile: Option<LaunchProfile>,
    autonomy_mode: Option<AutonomyMode>,
    deployment_shape: Option<DeploymentShape>,
    performance_profile: Option<PerformanceProfile>,
    max_stage: Option<MitigationStage>,
}

impl DaemonArgs {
    fn telemetry_label(&self) -> &'static str {
        match self.telemetry_mode {
            TelemetryMode::Sample => "sample",
            TelemetryMode::JsonlFile(_) => "jsonl-file",
            TelemetryMode::StdinJsonl => "stdin-jsonl",
        }
    }

    fn into_collector(self) -> Box<dyn TelemetryCollector> {
        match self.telemetry_mode {
            TelemetryMode::Sample => Box::new(SampleTelemetryCollector),
            TelemetryMode::JsonlFile(path) => Box::new(JsonlFileCollector::new(path)),
            TelemetryMode::StdinJsonl => Box::new(StdinJsonlCollector),
        }
    }

    fn apply_to_config(&self, config: &mut RuntimeConfig) {
        if let Some(node_name) = &self.node_name {
            config.node_name = node_name.clone();
        }
        config.passive_only |= self.passive_only;
        if let Some(launch_profile) = self.launch_profile {
            config.launch_profile = launch_profile;
        }
        if let Some(autonomy_mode) = self.autonomy_mode {
            config.autonomy_mode = autonomy_mode;
        }
        if let Some(deployment_shape) = self.deployment_shape {
            config.deployment_shape = deployment_shape;
        }
        if let Some(performance_profile) = self.performance_profile {
            config.performance_profile = performance_profile;
        }
        if let Some(max_stage) = self.max_stage {
            config.max_stage = max_stage;
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum TelemetryMode {
    Sample,
    JsonlFile(PathBuf),
    StdinJsonl,
}

fn set_telemetry_mode(
    current: &mut Option<TelemetryMode>,
    next: TelemetryMode,
) -> Result<(), String> {
    if current.is_some() {
        return Err(
            "only one telemetry source may be selected: use one of --sample, --stdin-jsonl, or --telemetry-file <path>"
                .to_string(),
        );
    }

    *current = Some(next);
    Ok(())
}

fn usage() -> &'static str {
    "usage: sentineld [--sample | --stdin-jsonl | --telemetry-file <jsonl-path>] [--node-name <name>] [--passive-only] [--launch-profile <protector|architect>] [--autonomy-mode <assisted|guardian-autonomous>] [--deployment-shape <single-node|multi-node-mesh|fragile-mesh>] [--performance-profile <stability-first|balanced|pressure-shield>] [--max-stage <observe|throttle|contain|isolate|operator-approval>]"
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{DaemonCommand, DaemonArgs, TelemetryMode};
    use sentinel_common::MitigationStage;
    use sentinel_config::{AutonomyMode, DeploymentShape, LaunchProfile, PerformanceProfile};

    #[test]
    fn defaults_to_sample_mode() {
        let command = DaemonCommand::parse(Vec::<String>::new()).expect("parse should succeed");

        assert_eq!(
            command,
            DaemonCommand::Run(DaemonArgs {
                telemetry_mode: TelemetryMode::Sample,
                node_name: None,
                passive_only: false,
                launch_profile: None,
                autonomy_mode: None,
                deployment_shape: None,
                performance_profile: None,
                max_stage: None,
            })
        );
    }

    #[test]
    fn parses_jsonl_file_mode() {
        let command = DaemonCommand::parse(vec![
            "--telemetry-file".to_string(),
            "testdata/telemetry/sample-stream.jsonl".to_string(),
        ])
        .expect("parse should succeed");

        assert_eq!(
            command,
            DaemonCommand::Run(DaemonArgs {
                telemetry_mode: TelemetryMode::JsonlFile(PathBuf::from(
                    "testdata/telemetry/sample-stream.jsonl"
                )),
                node_name: None,
                passive_only: false,
                launch_profile: None,
                autonomy_mode: None,
                deployment_shape: None,
                performance_profile: None,
                max_stage: None,
            })
        );
    }

    #[test]
    fn parses_runtime_overrides() {
        let command = DaemonCommand::parse(vec![
            "--stdin-jsonl".to_string(),
            "--node-name".to_string(),
            "guardian-02".to_string(),
            "--passive-only".to_string(),
            "--launch-profile".to_string(),
            "architect".to_string(),
            "--autonomy-mode".to_string(),
            "assisted".to_string(),
            "--deployment-shape".to_string(),
            "multi-node-mesh".to_string(),
            "--performance-profile".to_string(),
            "pressure-shield".to_string(),
            "--max-stage".to_string(),
            "contain".to_string(),
        ])
        .expect("parse should succeed");

        assert_eq!(
            command,
            DaemonCommand::Run(DaemonArgs {
                telemetry_mode: TelemetryMode::StdinJsonl,
                node_name: Some("guardian-02".to_string()),
                passive_only: true,
                launch_profile: Some(LaunchProfile::Architect),
                autonomy_mode: Some(AutonomyMode::Assisted),
                deployment_shape: Some(DeploymentShape::MultiNodeMesh),
                performance_profile: Some(PerformanceProfile::PressureShield),
                max_stage: Some(MitigationStage::Contain),
            })
        );
    }

    #[test]
    fn rejects_multiple_telemetry_sources() {
        let err = DaemonCommand::parse(vec![
            "--sample".to_string(),
            "--stdin-jsonl".to_string(),
        ])
        .expect_err("multiple sources should fail");

        assert!(err.contains("only one telemetry source"));
    }
}
