#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use sentinel_common::{AttackFamily, HealthSnapshot, MitigationStage, TelemetryKind};
use sentinel_config::{
    AutonomyMode, DeploymentShape, LaunchProfile, PerformanceProfile, RuntimeConfig,
};
use sentinel_correlation::{CorrelatedIncident, CorrelationEngine};
use sentinel_reporting::{ReporterBundle, ReporterEngine};
use sentinel_runtime::{RuntimeDecision, SentinelRuntime};
use sentinel_telemetry::TelemetryEvent;

#[derive(Clone, Debug)]
pub struct ScenarioDefinition {
    pub name: &'static str,
    pub protected_asset: &'static str,
    pub expected_family: AttackFamily,
    pub success_criteria: &'static str,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReplayFixture {
    pub scenario: ReplayScenarioMetadata,
    #[serde(default)]
    pub runtime: ReplayRuntimeOverrides,
    pub events: Vec<ReplayEvent>,
    #[serde(default)]
    pub expectations: ReplayExpectations,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReplayScenarioMetadata {
    pub name: String,
    pub protected_asset: String,
    pub summary: String,
    pub success_criteria: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ReplayRuntimeOverrides {
    pub node_name: Option<String>,
    pub passive_only: Option<bool>,
    pub max_stage: Option<String>,
    pub launch_profile: Option<String>,
    pub autonomy_mode: Option<String>,
    pub deployment_shape: Option<String>,
    pub performance_profile: Option<String>,
    pub allow_decoys: Option<bool>,
    pub quiet_reporter: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReplayEvent {
    pub kind: String,
    pub source: String,
    pub summary: String,
    #[serde(default)]
    pub health: ReplayHealth,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ReplayHealth {
    #[serde(default)]
    pub cpu_load_pct: u8,
    #[serde(default)]
    pub memory_load_pct: u8,
    #[serde(default)]
    pub thermal_c: u8,
    #[serde(default)]
    pub passive_only: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ReplayExpectations {
    pub incident_count: Option<usize>,
    pub highest_stage: Option<String>,
    #[serde(default)]
    pub families: Vec<String>,
    #[serde(default)]
    pub operator_report_contains: Vec<String>,
    #[serde(default)]
    pub human_report_contains: Vec<String>,
    #[serde(default)]
    pub teaching_report_contains: Vec<String>,
    #[serde(default)]
    pub care_report_contains: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ReplayRunResult {
    pub fixture: ReplayFixture,
    pub config: RuntimeConfig,
    pub decisions: Vec<RuntimeDecision>,
    pub incidents: Vec<CorrelatedIncident>,
    pub reports: ReporterBundle,
    pub validation_errors: Vec<String>,
}

impl ReplayRuntimeOverrides {
    fn apply_to_default(&self) -> Result<RuntimeConfig, String> {
        let mut config = RuntimeConfig::default();

        if let Some(node_name) = &self.node_name {
            config.node_name = node_name.clone();
        }
        if let Some(passive_only) = self.passive_only {
            config.passive_only = passive_only;
        }
        if let Some(allow_decoys) = self.allow_decoys {
            config.allow_decoys = allow_decoys;
        }
        if let Some(quiet_reporter) = self.quiet_reporter {
            config.quiet_reporter = quiet_reporter;
        }
        if let Some(max_stage) = &self.max_stage {
            config.max_stage = parse_mitigation_stage(max_stage)?;
        }
        if let Some(launch_profile) = &self.launch_profile {
            config.launch_profile = parse_launch_profile(launch_profile)?;
        }
        if let Some(autonomy_mode) = &self.autonomy_mode {
            config.autonomy_mode = parse_autonomy_mode(autonomy_mode)?;
        }
        if let Some(deployment_shape) = &self.deployment_shape {
            config.deployment_shape = parse_deployment_shape(deployment_shape)?;
        }
        if let Some(performance_profile) = &self.performance_profile {
            config.performance_profile = parse_performance_profile(performance_profile)?;
        }

        Ok(config)
    }
}

impl ReplayEvent {
    fn to_telemetry_event(&self) -> Result<TelemetryEvent, String> {
        Ok(TelemetryEvent {
            kind: parse_telemetry_kind(&self.kind)?,
            source: self.source.clone(),
            summary: self.summary.clone(),
            health: HealthSnapshot {
                cpu_load_pct: self.health.cpu_load_pct,
                memory_load_pct: self.health.memory_load_pct,
                thermal_c: self.health.thermal_c,
                passive_only: self.health.passive_only,
            },
        })
    }
}

impl ReplayRunResult {
    pub fn is_valid(&self) -> bool {
        self.validation_errors.is_empty()
    }

    pub fn highest_stage(&self) -> Option<MitigationStage> {
        self.incidents
            .iter()
            .map(|incident| incident.highest_stage)
            .max_by_key(|stage| stage.rank())
    }

    pub fn families(&self) -> Vec<String> {
        collect_families(&self.incidents)
    }
}

pub fn load_replay_fixture(path: &Path) -> Result<ReplayFixture, String> {
    let raw =
        fs::read_to_string(path).map_err(|err| format!("unable to read {}: {err}", path.display()))?;
    serde_json::from_str::<ReplayFixture>(&raw)
        .map_err(|err| format!("unable to parse {}: {err}", path.display()))
}

pub fn run_replay_fixture(fixture: &ReplayFixture) -> Result<ReplayRunResult, String> {
    let config = fixture.runtime.apply_to_default()?;
    let runtime = SentinelRuntime::default();
    let mut decisions = Vec::with_capacity(fixture.events.len());

    for event in &fixture.events {
        decisions.push(runtime.process_event(&config, &event.to_telemetry_event()?));
    }

    let incidents = CorrelationEngine::correlate(&decisions);
    let reports = ReporterEngine::render_all(&incidents);
    let validation_errors = validate_replay(fixture, &incidents, &reports)?;

    Ok(ReplayRunResult {
        fixture: fixture.clone(),
        config,
        decisions,
        incidents,
        reports,
        validation_errors,
    })
}

pub fn run_replay_fixture_file(path: &Path) -> Result<ReplayRunResult, String> {
    let fixture = load_replay_fixture(path)?;
    run_replay_fixture(&fixture)
}

pub fn seed_scenarios() -> Vec<ScenarioDefinition> {
    vec![
        ScenarioDefinition {
            name: "stage-loader-detection",
            protected_asset: "edge-service",
            expected_family: AttackFamily::PayloadStager,
            success_criteria: "Detect staging behavior before full session establishment.",
        },
        ScenarioDefinition {
            name: "identity-abuse-containment",
            protected_asset: "auth-api",
            expected_family: AttackFamily::IdentityAbuse,
            success_criteria:
                "Contain impossible-travel or token abuse without blocking valid users.",
        },
        ScenarioDefinition {
            name: "dns-tunnel-escalation",
            protected_asset: "recursive-resolver",
            expected_family: AttackFamily::DnsTunneling,
            success_criteria: "Detect high-entropy DNS patterns and move to safe containment.",
        },
    ]
}

fn validate_replay(
    fixture: &ReplayFixture,
    incidents: &[CorrelatedIncident],
    reports: &ReporterBundle,
) -> Result<Vec<String>, String> {
    let mut errors = Vec::new();

    if let Some(expected_incident_count) = fixture.expectations.incident_count {
        if incidents.len() != expected_incident_count {
            errors.push(format!(
                "incident_count expected {} but got {}",
                expected_incident_count,
                incidents.len()
            ));
        }
    }

    if let Some(expected_stage) = &fixture.expectations.highest_stage {
        let expected_stage = parse_mitigation_stage(expected_stage)?;
        let actual_stage = incidents
            .iter()
            .map(|incident| incident.highest_stage)
            .max_by_key(|stage| stage.rank());

        match actual_stage {
            Some(actual_stage) if actual_stage != expected_stage => {
                errors.push(format!(
                    "highest_stage expected {} but got {}",
                    expected_stage.as_str(),
                    actual_stage.as_str()
                ));
            }
            None => errors.push(format!(
                "highest_stage expected {} but no incidents were produced",
                expected_stage.as_str()
            )),
            _ => {}
        }
    }

    let actual_families = collect_families(incidents);
    for family in &fixture.expectations.families {
        let expected_family = parse_attack_family(family)?;
        let expected_family = expected_family.as_str().to_string();
        if !actual_families.contains(&expected_family) {
            errors.push(format!(
                "family {} was expected but actual families were {}",
                expected_family,
                if actual_families.is_empty() {
                    "none".to_string()
                } else {
                    actual_families.join(", ")
                }
            ));
        }
    }

    validate_report_fragments(
        "operator_report",
        &reports.operator_report,
        &fixture.expectations.operator_report_contains,
        &mut errors,
    );
    validate_report_fragments(
        "human_report",
        &reports.human_report,
        &fixture.expectations.human_report_contains,
        &mut errors,
    );
    validate_report_fragments(
        "teaching_report",
        &reports.teaching_report,
        &fixture.expectations.teaching_report_contains,
        &mut errors,
    );
    validate_report_fragments(
        "care_report",
        &reports.care_report,
        &fixture.expectations.care_report_contains,
        &mut errors,
    );

    Ok(errors)
}

fn validate_report_fragments(
    report_name: &str,
    report: &str,
    fragments: &[String],
    errors: &mut Vec<String>,
) {
    for fragment in fragments {
        if !report.contains(fragment) {
            errors.push(format!(
                "{} missing fragment {:?}",
                report_name, fragment
            ));
        }
    }
}

fn collect_families(incidents: &[CorrelatedIncident]) -> Vec<String> {
    let mut families = BTreeSet::new();
    for incident in incidents {
        for family in &incident.families {
            families.insert(family.clone());
        }
    }
    families.into_iter().collect()
}

fn normalize(input: &str) -> String {
    input
        .trim()
        .to_ascii_lowercase()
        .replace('_', "-")
        .replace(' ', "-")
}

fn parse_attack_family(input: &str) -> Result<AttackFamily, String> {
    match normalize(input).as_str() {
        "offensive-scan" => Ok(AttackFamily::OffensiveScan),
        "remote-access-trojan" => Ok(AttackFamily::RemoteAccessTrojan),
        "payload-stager" => Ok(AttackFamily::PayloadStager),
        "beaconing" => Ok(AttackFamily::Beaconing),
        "dns-tunneling" => Ok(AttackFamily::DnsTunneling),
        "data-exfiltration" => Ok(AttackFamily::DataExfiltration),
        "identity-abuse" => Ok(AttackFamily::IdentityAbuse),
        "api-scraping" => Ok(AttackFamily::ApiScraping),
        "exploit-delivery" => Ok(AttackFamily::ExploitDelivery),
        "volumetric-flood" => Ok(AttackFamily::VolumetricFlood),
        "integrity-attack" => Ok(AttackFamily::IntegrityAttack),
        "unknown" => Ok(AttackFamily::Unknown),
        other => Err(format!("unknown attack family '{}'", other)),
    }
}

fn parse_telemetry_kind(input: &str) -> Result<TelemetryKind, String> {
    TelemetryKind::parse(input)
}

fn parse_mitigation_stage(input: &str) -> Result<MitigationStage, String> {
    MitigationStage::parse(input)
}

fn parse_launch_profile(input: &str) -> Result<LaunchProfile, String> {
    LaunchProfile::parse(input)
}

fn parse_autonomy_mode(input: &str) -> Result<AutonomyMode, String> {
    AutonomyMode::parse(input)
}

fn parse_deployment_shape(input: &str) -> Result<DeploymentShape, String> {
    DeploymentShape::parse(input)
}

fn parse_performance_profile(input: &str) -> Result<PerformanceProfile, String> {
    PerformanceProfile::parse(input)
}

#[cfg(test)]
mod tests {
    use super::{load_replay_fixture, run_replay_fixture, run_replay_fixture_file};
    use sentinel_config::DeploymentShape;
    use std::path::{Path, PathBuf};

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("workspace root")
            .to_path_buf()
    }

    #[test]
    fn replay_fixture_runs_and_validates() {
        let result = run_replay_fixture_file(
            &repo_root()
                .join("testdata")
                .join("scenarios")
                .join("identity-abuse-containment.json"),
        )
        .expect("fixture should run");

        assert!(result.is_valid());
        assert_eq!(result.incidents.len(), 1);
        assert_eq!(
            result
                .highest_stage()
                .expect("fixture should produce a stage")
                .as_str(),
            "contain"
        );
        assert!(result.families().contains(&"identity-abuse".to_string()));
    }

    #[test]
    fn replay_fixture_applies_runtime_overrides() {
        let result = run_replay_fixture_file(
            &repo_root()
                .join("testdata")
                .join("scenarios")
                .join("fragile-mesh-payload.json"),
        )
        .expect("fixture should run");

        assert!(result.is_valid());
        assert_eq!(result.config.deployment_shape, DeploymentShape::FragileMesh);
        assert!(result.decisions[0]
            .autonomy_plan
            .pattern
            .as_str()
            .contains("fragile-mesh-guard"));
    }

    #[test]
    fn replay_validator_reports_mismatch() {
        let mut fixture = load_replay_fixture(
            &repo_root()
                .join("testdata")
                .join("scenarios")
                .join("scan-pressure-capture.json"),
        )
        .expect("fixture should load");
        fixture.expectations.incident_count = Some(2);

        let result = run_replay_fixture(&fixture).expect("fixture should run");

        assert!(!result.is_valid());
        assert!(result
            .validation_errors
            .iter()
            .any(|error| error.contains("incident_count expected 2 but got 1")));
    }
}
