#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct RuleManifest {
    pub version: u8,
    pub default_profile: String,
    pub include: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SignatureRule {
    pub id: String,
    pub name: String,
    pub family: String,
    pub recommended_stage: String,
    pub severity: String,
    pub summary: String,
    pub indicators: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct SignatureRuleFile {
    rules: Vec<SignatureRule>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct HeuristicRule {
    pub minimum_confidence: u8,
    pub phantom_required: bool,
    pub idf_window_allowed: bool,
    pub ambient_resonance_required: bool,
    pub summary: String,
}

#[derive(Clone, Debug, Deserialize)]
struct HeuristicsFile {
    heuristics: BTreeMap<String, HeuristicRule>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PressureThresholdSet {
    pub scan_pressure: u8,
    pub intrusion_pressure: u8,
    pub ddos_pressure: u8,
    pub entropy_pressure: u8,
}

#[derive(Clone, Debug, Deserialize)]
struct AnomalyThresholdFile {
    thresholds: BTreeMap<String, PressureThresholdSet>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BaselineClass {
    pub name: String,
    pub passive_only: bool,
    pub max_decoy_intensity: String,
    pub preferred_posture: String,
}

#[derive(Clone, Debug, Deserialize)]
struct BaselineClassFile {
    classes: Vec<BaselineClass>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ResponsePolicyDefinition {
    pub name: String,
    pub default_max_stage: String,
    pub fragile_asset_max_stage: String,
    pub integrity_critical_stage: String,
    pub zen_recovery_stage: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ResponsePolicyFile {
    policy: ResponsePolicyDefinition,
    transitions: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ResponsePolicyPack {
    pub policy: ResponsePolicyDefinition,
    pub transitions: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AllowlistDefinition {
    pub suppressed_sources: Vec<String>,
    pub suppressed_labels: Vec<String>,
    pub suppressed_identities: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct AllowlistFile {
    allowlists: AllowlistDefinition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleStateAction {
    Enable,
    Disable,
    Isolate,
}

impl RuleStateAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::Isolate => "isolate",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleStateEntry {
    pub action: RuleStateAction,
    pub rule_id: String,
}

#[derive(Clone, Debug)]
pub struct ActiveRule {
    pub id: String,
    pub name: String,
    pub family: String,
    pub stage: String,
    pub severity: String,
    pub summary: String,
    pub indicators: Vec<String>,
    pub enabled: bool,
    pub stage_override: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RulePack {
    pub profile: String,
    pub manifest_path: PathBuf,
    pub include_files: Vec<PathBuf>,
    pub state_file: PathBuf,
    pub total_rules: usize,
    pub enabled_rules: usize,
    pub isolated_rules: usize,
    pub rules: Vec<ActiveRule>,
    pub heuristics: BTreeMap<String, HeuristicRule>,
    pub thresholds: BTreeMap<String, PressureThresholdSet>,
    pub asset_classes: Vec<BaselineClass>,
    pub response_policy: Option<ResponsePolicyPack>,
    pub allowlists: Option<AllowlistDefinition>,
}

pub fn load_manifest(repo_root: &Path) -> Result<RuleManifest, String> {
    let manifest_path = repo_root.join("rules").join("manifest.toml");
    let raw = fs::read_to_string(&manifest_path)
        .map_err(|err| format!("unable to read {}: {err}", manifest_path.display()))?;
    toml::from_str::<RuleManifest>(&raw)
        .map_err(|err| format!("unable to parse {}: {err}", manifest_path.display()))
}

pub fn load_rule_pack(repo_root: &Path, profile: Option<&str>) -> Result<RulePack, String> {
    let manifest = load_manifest(repo_root)?;
    let selected_profile = profile.unwrap_or(&manifest.default_profile).to_string();
    let rules_root = repo_root.join("rules");
    let manifest_path = rules_root.join("manifest.toml");
    let mut include_files = Vec::new();
    let mut rules_by_id = BTreeMap::new();
    let mut heuristics = BTreeMap::new();
    let mut thresholds = BTreeMap::new();
    let mut asset_classes = Vec::new();
    let mut response_policy = None;
    let mut allowlists = None;

    for include in &manifest.include {
        let include_path = rules_root.join(include);
        include_files.push(include_path.clone());
        let raw = fs::read_to_string(&include_path)
            .map_err(|err| format!("unable to read {}: {err}", include_path.display()))?;

        if include_path
            .components()
            .any(|component| component.as_os_str() == "signatures")
        {
            let parsed = toml::from_str::<SignatureRuleFile>(&raw)
                .map_err(|err| format!("unable to parse {}: {err}", include_path.display()))?;
            for rule in parsed.rules {
                rules_by_id.insert(
                    rule.id.clone(),
                    ActiveRule {
                        id: rule.id,
                        name: rule.name,
                        family: rule.family,
                        stage: rule.recommended_stage,
                        severity: rule.severity,
                        summary: rule.summary,
                        indicators: rule.indicators,
                        enabled: true,
                        stage_override: None,
                    },
                );
            }
            continue;
        }

        if include_path
            .components()
            .any(|component| component.as_os_str() == "heuristics")
        {
            let parsed = toml::from_str::<HeuristicsFile>(&raw)
                .map_err(|err| format!("unable to parse {}: {err}", include_path.display()))?;
            heuristics.extend(parsed.heuristics);
            continue;
        }

        if include_path
            .components()
            .any(|component| component.as_os_str() == "anomaly")
        {
            let parsed = toml::from_str::<AnomalyThresholdFile>(&raw)
                .map_err(|err| format!("unable to parse {}: {err}", include_path.display()))?;
            thresholds.extend(parsed.thresholds);
            continue;
        }

        if include_path
            .components()
            .any(|component| component.as_os_str() == "baselines")
        {
            let parsed = toml::from_str::<BaselineClassFile>(&raw)
                .map_err(|err| format!("unable to parse {}: {err}", include_path.display()))?;
            asset_classes.extend(parsed.classes);
            continue;
        }

        if include_path
            .components()
            .any(|component| component.as_os_str() == "response-policies")
        {
            let parsed = toml::from_str::<ResponsePolicyFile>(&raw)
                .map_err(|err| format!("unable to parse {}: {err}", include_path.display()))?;
            response_policy = Some(ResponsePolicyPack {
                policy: parsed.policy,
                transitions: parsed.transitions,
            });
            continue;
        }

        if include_path
            .components()
            .any(|component| component.as_os_str() == "allowlists")
        {
            let parsed = toml::from_str::<AllowlistFile>(&raw)
                .map_err(|err| format!("unable to parse {}: {err}", include_path.display()))?;
            allowlists = Some(parsed.allowlists);
        }
    }

    let state_file = rules_root.join("states").join(format!(
        "{}.states",
        normalize_profile_name(&selected_profile)
    ));
    let state_entries = load_state_file(&state_file)?;

    for entry in state_entries {
        if let Some(rule) = rules_by_id.get_mut(&entry.rule_id) {
            match entry.action {
                RuleStateAction::Enable => {
                    rule.enabled = true;
                    rule.stage_override = None;
                }
                RuleStateAction::Disable => {
                    rule.enabled = false;
                    rule.stage_override = None;
                }
                RuleStateAction::Isolate => {
                    rule.enabled = true;
                    rule.stage_override = Some("isolate".to_string());
                }
            }
        }
    }

    let mut rules = rules_by_id.into_values().collect::<Vec<_>>();
    rules.sort_by(|left, right| left.id.cmp(&right.id));

    let enabled_rules = rules.iter().filter(|rule| rule.enabled).count();
    let isolated_rules = rules
        .iter()
        .filter(|rule| rule.stage_override.as_deref() == Some("isolate"))
        .count();

    Ok(RulePack {
        profile: selected_profile,
        manifest_path,
        include_files,
        state_file,
        total_rules: rules.len(),
        enabled_rules,
        isolated_rules,
        rules,
        heuristics,
        thresholds,
        asset_classes,
        response_policy,
        allowlists,
    })
}

pub fn compile_rule_pack(repo_root: &Path, profile: Option<&str>) -> Result<String, String> {
    let pack = load_rule_pack(repo_root, profile)?;
    let mut lines = vec![
        "# CrystalSentinel-CRA compiled rule pack".to_string(),
        format!("profile = {}", pack.profile),
        format!("manifest = {}", pack.manifest_path.display()),
        format!("state_file = {}", pack.state_file.display()),
        format!(
            "summary = total:{} enabled:{} isolated:{}",
            pack.total_rules, pack.enabled_rules, pack.isolated_rules
        ),
        String::new(),
    ];

    for rule in pack.rules.iter().filter(|rule| rule.enabled) {
        lines.push(format!(
            "rule {} stage={} family={} severity={} indicators={} summary={}",
            rule.id,
            rule.stage_override
                .as_deref()
                .unwrap_or(rule.stage.as_str()),
            rule.family,
            rule.severity,
            rule.indicators.join(","),
            rule.summary
        ));
    }

    if !pack.heuristics.is_empty() {
        lines.push(String::new());
        lines.push("# heuristics".to_string());
        for (name, heuristic) in &pack.heuristics {
            lines.push(format!(
                "heuristic {} min_confidence={} phantom={} idf_window={} ambient_resonance={} summary={}",
                name,
                heuristic.minimum_confidence,
                heuristic.phantom_required,
                heuristic.idf_window_allowed,
                heuristic.ambient_resonance_required,
                heuristic.summary
            ));
        }
    }

    if !pack.thresholds.is_empty() {
        lines.push(String::new());
        lines.push("# anomaly thresholds".to_string());
        for (name, threshold) in &pack.thresholds {
            lines.push(format!(
                "threshold {} scan={} intrusion={} ddos={} entropy={}",
                name,
                threshold.scan_pressure,
                threshold.intrusion_pressure,
                threshold.ddos_pressure,
                threshold.entropy_pressure
            ));
        }
    }

    if !pack.asset_classes.is_empty() {
        lines.push(String::new());
        lines.push("# fragile asset classes".to_string());
        for class in &pack.asset_classes {
            lines.push(format!(
                "asset_class {} passive_only={} max_decoy_intensity={} preferred_posture={}",
                class.name, class.passive_only, class.max_decoy_intensity, class.preferred_posture
            ));
        }
    }

    if let Some(policy) = &pack.response_policy {
        lines.push(String::new());
        lines.push("# response policy".to_string());
        lines.push(format!(
            "policy {} default_max_stage={} fragile_asset_max_stage={} integrity_critical_stage={} zen_recovery_stage={}",
            policy.policy.name,
            policy.policy.default_max_stage,
            policy.policy.fragile_asset_max_stage,
            policy.policy.integrity_critical_stage,
            policy.policy.zen_recovery_stage
        ));
        for (signal, stage) in &policy.transitions {
            lines.push(format!("transition {}={}", signal, stage));
        }
    }

    if let Some(allowlists) = &pack.allowlists {
        lines.push(String::new());
        lines.push("# allowlists".to_string());
        lines.push(format!(
            "allowlist suppressed_sources={}",
            allowlists.suppressed_sources.join(",")
        ));
        lines.push(format!(
            "allowlist suppressed_labels={}",
            allowlists.suppressed_labels.join(",")
        ));
        lines.push(format!(
            "allowlist suppressed_identities={}",
            allowlists.suppressed_identities.join(",")
        ));
    }

    Ok(lines.join("\n"))
}

pub fn write_compiled_rule_pack(
    repo_root: &Path,
    profile: Option<&str>,
    output: &Path,
) -> Result<(), String> {
    let compiled = compile_rule_pack(repo_root, profile)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("unable to create {}: {err}", parent.display()))?;
    }
    fs::write(output, compiled)
        .map_err(|err| format!("unable to write {}: {err}", output.display()))
}

pub fn available_profiles(repo_root: &Path) -> Result<Vec<String>, String> {
    let states_dir = repo_root.join("rules").join("states");
    let entries = fs::read_dir(&states_dir)
        .map_err(|err| format!("unable to read {}: {err}", states_dir.display()))?;
    let mut profiles = BTreeSet::new();
    for entry in entries {
        let entry =
            entry.map_err(|err| format!("unable to scan {}: {err}", states_dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("states") {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) {
            profiles.insert(stem.to_string());
        }
    }
    Ok(profiles.into_iter().collect())
}

pub fn rule_language_summary() -> &'static [&'static str] {
    &[
        "CrystalSentinel rules use small TOML files instead of a large scripting language.",
        "Signature files use repeated [[rules]] blocks with id, family, severity, stage, summary, and indicators.",
        "Profile files live under rules/states/*.states and use one action per line: enable, disable, or isolate.",
        "Compile output folds signatures, heuristics, anomaly thresholds, baselines, response policy, and allowlists into one local pack.",
        "The intent is to keep rule authoring readable, reviewable, and predictable without losing defensive control.",
    ]
}

fn normalize_profile_name(profile: &str) -> String {
    profile.trim().to_ascii_lowercase().replace('_', "-")
}

fn load_state_file(path: &Path) -> Result<Vec<RuleStateEntry>, String> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("unable to read state file {}: {err}", path.display()))?;
    let mut entries = Vec::new();

    for (index, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(action) = parts.next() else {
            continue;
        };
        let Some(rule_id) = parts.next() else {
            return Err(format!(
                "invalid state line {} in {}: missing rule id",
                index + 1,
                path.display()
            ));
        };
        let action = match action {
            "enable" => RuleStateAction::Enable,
            "disable" => RuleStateAction::Disable,
            "isolate" => RuleStateAction::Isolate,
            other => {
                return Err(format!(
                    "invalid state action '{}' on line {} in {}",
                    other,
                    index + 1,
                    path.display()
                ))
            }
        };
        entries.push(RuleStateEntry {
            action,
            rule_id: rule_id.to_string(),
        });
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::{available_profiles, compile_rule_pack, load_rule_pack};
    use std::path::Path;

    fn repo_root() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("workspace root")
    }

    #[test]
    fn loads_balanced_rule_pack() {
        let pack = load_rule_pack(repo_root(), Some("balanced")).expect("rule pack should load");

        assert_eq!(pack.profile, "balanced");
        assert!(pack.total_rules >= 10);
        assert!(pack.enabled_rules > 0);
    }

    #[test]
    fn compiles_high_guard_pack() {
        let compiled =
            compile_rule_pack(repo_root(), Some("high-guard")).expect("compiled rules should work");

        assert!(compiled.contains("profile = high-guard"));
        assert!(compiled.contains("rule channel-003"));
        assert!(compiled.contains("heuristic scan_capture"));
        assert!(compiled.contains("threshold critical"));
        assert!(compiled.contains("policy stability-first"));
    }

    #[test]
    fn lists_available_profiles() {
        let profiles = available_profiles(repo_root()).expect("profiles should load");

        assert!(profiles.contains(&"balanced".to_string()));
        assert!(profiles.contains(&"high-guard".to_string()));
        assert!(profiles.contains(&"minimum".to_string()));
    }
}
