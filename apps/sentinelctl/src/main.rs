#![forbid(unsafe_code)]

use sentinel_config::{LaunchProfile, RuntimeConfig};
use sentinel_decoy::DecoyGovernor;
use sentinel_detection::{seed_framework_catalog, seed_intel_sources, seed_pattern_identities};
use sentinel_education::{find_lesson, harmless_scan_types, learning_catalog};
use sentinel_native_bridge::native_layer_manifest;
use sentinel_rules::{
    available_profiles, load_rule_pack, rule_language_summary, write_compiled_rule_pack,
};
use sentinel_scenario::seed_scenarios;

fn main() {
    let command = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "help".to_string());

    match command.as_str() {
        "intel" => {
            for source in seed_intel_sources() {
                println!(
                    "{} [{}] - {}",
                    source.name,
                    source.kind.as_str(),
                    source.summary
                );
            }
        }
        "frameworks" => {
            for fingerprint in seed_framework_catalog() {
                println!(
                    "{} -> family={} preferred_stage={}",
                    fingerprint.name,
                    fingerprint.family.as_str(),
                    fingerprint.preferred_stage.as_str()
                );
            }
        }
        "patterns" => {
            for identity in seed_pattern_identities() {
                println!(
                    "{} -> display_name={} family={} category={} labels={} protocols={} sources={}",
                    identity.name,
                    identity.display_name,
                    identity.family.as_str(),
                    identity.category,
                    identity.labels.join(","),
                    identity.protocols.join(","),
                    identity.sources.join(",")
                );
            }
        }
        "profiles" => {
            for profile in [LaunchProfile::Protector, LaunchProfile::Architect] {
                println!("{}", profile.as_str());
            }
        }
        "decoys" => {
            let source = std::env::args()
                .nth(2)
                .unwrap_or_else(|| "203.0.113.88".to_string());
            let summary = std::env::args()
                .nth(3)
                .unwrap_or_else(|| "syn probe recon fingerprint".to_string());
            let signal = sentinel_common::ThreatSignal {
                source_name: source,
                family: sentinel_common::AttackFamily::OffensiveScan,
                confidence: 84,
                recognition: None,
                analysis_lanes: vec![
                    "asm-fast-path".to_string(),
                    "heuristic".to_string(),
                    "recon-model".to_string(),
                ],
                detail: summary,
            };

            for profile in [LaunchProfile::Protector, LaunchProfile::Architect] {
                let config = RuntimeConfig {
                    launch_profile: profile,
                    ..RuntimeConfig::default()
                };
                if let Some(plan) = DecoyGovernor::plan(
                    &config,
                    &signal,
                    &sentinel_common::HealthSnapshot::default(),
                ) {
                    println!(
                        "{} -> intensity={} cadence_ms={} ghost_slots={} primitives={}",
                        profile.as_str(),
                        plan.intensity.as_str(),
                        plan.cadence_ms,
                        plan.ghost_slots,
                        plan.primitives
                            .iter()
                            .map(|primitive| primitive.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    );
                    if let Some(phantom) = &plan.phantom_observation {
                        println!(
                            "  phantom -> cadence_ms={} jitter_ms={} phase_offset_ms={} burst_slots={}",
                            phantom.cadence_ms,
                            phantom.jitter_ms,
                            phantom.phase_offset_ms,
                            phantom.burst_slots
                        );
                    }
                }
            }
        }
        "scenarios" => {
            for scenario in seed_scenarios() {
                println!(
                    "{} -> asset={} family={}",
                    scenario.name,
                    scenario.protected_asset,
                    scenario.expected_family.as_str()
                );
            }
        }
        "layers" => {
            for layer in native_layer_manifest() {
                println!(
                    "{} -> library={} status={} entrypoint={}",
                    layer.language.as_str(),
                    layer.library,
                    layer.status.as_str(),
                    layer.entrypoint
                );
            }
        }
        "install-layout" => {
            println!("linux -> prefix=/usr/local config=/usr/local/etc/crystalsentinel rules=/usr/local/etc/crystalsentinel/rules logs=/usr/local/var/log/crystalsentinel state=/usr/local/var/lib/crystalsentinel");
            println!("macos -> prefix=/usr/local config=/usr/local/etc/crystalsentinel rules=/usr/local/etc/crystalsentinel/rules logs=/usr/local/var/log/crystalsentinel state=/usr/local/var/lib/crystalsentinel");
            println!("windows -> program_files=%ProgramFiles%\\CrystalSentinel-CRA program_data=%ProgramData%\\CrystalSentinel-CRA config=%ProgramData%\\CrystalSentinel-CRA\\etc rules=%ProgramData%\\CrystalSentinel-CRA\\etc\\rules");
        }
        "rule-profiles" => match available_profiles(&repo_root()) {
            Ok(profiles) => {
                for profile in profiles {
                    println!("{}", profile);
                }
            }
            Err(err) => eprintln!("{}", err),
        },
        "rule-pack" => {
            let profile = std::env::args().nth(2);
            match load_rule_pack(&repo_root(), profile.as_deref()) {
                Ok(pack) => {
                    println!(
                        "profile={} total_rules={} enabled_rules={} isolated_rules={} heuristics={} thresholds={} asset_classes={}",
                        pack.profile,
                        pack.total_rules,
                        pack.enabled_rules,
                        pack.isolated_rules,
                        pack.heuristics.len(),
                        pack.thresholds.len(),
                        pack.asset_classes.len()
                    );
                    if let Some(policy) = &pack.response_policy {
                        println!(
                            "policy={} default_max_stage={} zen_recovery_stage={}",
                            policy.policy.name,
                            policy.policy.default_max_stage,
                            policy.policy.zen_recovery_stage
                        );
                    }
                    for rule in pack.rules.iter().filter(|rule| rule.enabled) {
                        println!(
                            "rule {} stage={} severity={} family={} name={}",
                            rule.id,
                            rule.stage_override
                                .as_deref()
                                .unwrap_or(rule.stage.as_str()),
                            rule.severity,
                            rule.family,
                            rule.name
                        );
                    }
                }
                Err(err) => eprintln!("{}", err),
            }
        }
        "rule-build" => {
            let profile = std::env::args().nth(2);
            let output = std::env::args()
                .nth(3)
                .unwrap_or_else(|| "rules/compiled/crystalsentinel.rules".to_string());
            match write_compiled_rule_pack(
                &repo_root(),
                profile.as_deref(),
                std::path::Path::new(&output),
            ) {
                Ok(()) => println!("wrote {}", output),
                Err(err) => eprintln!("{}", err),
            }
        }
        "rule-language" => {
            for line in rule_language_summary() {
                println!("{}", line);
            }
        }
        "coverage" => {
            for item in coverage_matrix() {
                println!(
                    "{} -> status={} assessments={} implementation={} notes={}",
                    item.capability,
                    item.status,
                    item.assessments.join(","),
                    item.implementation.join(","),
                    item.notes
                );
            }
        }
        "teach" => {
            if let Some(name) = std::env::args().nth(2) {
                if let Some(lesson) = find_lesson(&name) {
                    print_lesson(&lesson);
                } else {
                    println!("unknown lesson: {}", name);
                }
            } else {
                for lesson in learning_catalog() {
                    println!(
                        "{} [{}] harmless={}",
                        lesson.name, lesson.classification, lesson.harmless
                    );
                }
            }
        }
        "safe-scans" => {
            for lesson in harmless_scan_types() {
                println!("{} -> {}", lesson.name, lesson.summary);
            }
        }
        _ => {
            println!("usage: sentinelctl [intel|frameworks|patterns|profiles|decoys|scenarios|layers|install-layout|rule-profiles|rule-pack|rule-build|rule-language|coverage|teach|safe-scans]");
        }
    }
}

fn repo_root() -> std::path::PathBuf {
    let mut current = std::env::current_dir().expect("current dir");
    loop {
        if current.join("rules").join("manifest.toml").exists() {
            return current;
        }
        if !current.pop() {
            return std::env::current_dir().expect("current dir");
        }
    }
}

fn print_lesson(lesson: &sentinel_education::ScanTypeLesson) {
    println!("name: {}", lesson.name);
    println!("classification: {}", lesson.classification);
    println!("harmless: {}", lesson.harmless);
    println!("summary: {}", lesson.summary);
    println!("how it works:");
    for item in lesson.how_it_works {
        println!("  - {}", item);
    }
    println!("safety contract:");
    for item in lesson.safety_contract {
        println!("  - {}", item);
    }
}

struct CoverageItem {
    capability: &'static str,
    status: &'static str,
    assessments: &'static [&'static str],
    implementation: &'static [&'static str],
    notes: &'static str,
}

fn coverage_matrix() -> &'static [CoverageItem] {
    &[
        CoverageItem {
            capability: "built-in-rule-profiles-and-compiler",
            status: "implemented",
            assessments: &[
                "self-assessments/reverse-engineering-frameworks.txt",
                "self-assessments/deployment-script.txt",
            ],
            implementation: &[
                "crates/sentinel-rules",
                "rules",
                "configs/base/install-layout.toml",
                "scripts/bootstrap",
                "apps/sentinelctl",
            ],
            notes: "The framework now uses a small built-in TOML rule language, local state profiles, and one local compile target instead of a large external rule scripting workflow.",
        },
        CoverageItem {
            capability: "autonomous-runtime-loop",
            status: "implemented",
            assessments: &[
                "self-assessments/the-guardian-system-arch.txt",
                "self-assessments/deployment-script.txt",
            ],
            implementation: &[
                "crates/sentinel-runtime",
                "crates/sentinel-policy",
                "crates/sentinel-response",
                "apps/sentineld",
            ],
            notes: "The runtime already correlates threat, health, integrity, recovery, and bounded action into one defensive loop.",
        },
        CoverageItem {
            capability: "harmless-decoy-system",
            status: "implemented",
            assessments: &[
                "self-assessments/decoy-strategy.txt",
                "self-assessments/genesis-sequence.txt",
                "self-assessments/introducing-literal-new-scan-types-for-defensive-sec/idf-scan/idf-scan-doc.txt",
                "self-assessments/chaff-system-entropy.txt",
                "self-assessments/chaos-oscillator-randomizer.txt",
            ],
            implementation: &[
                "crates/sentinel-decoy",
                "crates/sentinel-runtime",
                "crates/sentinel-education",
                "crates/sentinel-reporting",
            ],
            notes: "The decoy layer is bounded, inert, truth-tagged, and designed to cost hostile recon time and confidence without weaponizing traffic.",
        },
        CoverageItem {
            capability: "phantom-kis-sars-tbns-vocabulary",
            status: "implemented",
            assessments: &[
                "self-assessments/introducing-literal-new-scan-types-for-defensive-sec/TriBlue-Network-Scanning(TBNS)/tbns-doc.txt",
                "self-assessments/introducing-literal-new-scan-types-for-defensive-sec/phantom-scan/phantom-scan-doc.txt",
                "self-assessments/introducing-literal-new-scan-types-for-defensive-sec/kinetic-impadence-scan/kis-doc.txt",
                "self-assessments/introducing-literal-new-scan-types-for-defensive-sec/sar-scan/sars-doc.txt",
            ],
            implementation: &[
                "crates/sentinel-education",
                "crates/sentinel-runtime",
                "crates/sentinel-decoy",
            ],
            notes: "The framework uses these scan concepts as defensive identities and decision paths, while keeping the actual implementation harmless and bounded.",
        },
        CoverageItem {
            capability: "threat-recognition-and-identity",
            status: "implemented",
            assessments: &[
                "self-assessments/reverse-engineering-frameworks.txt",
                "self-assessments/common-attack-patterns.txt",
            ],
            implementation: &[
                "crates/sentinel-detection",
                "crates/sentinel-common",
                "crates/sentinel-correlation",
                "crates/sentinel-reporting",
            ],
            notes: "Reports can name recognized behavior such as stager, spyware, reverse_tcp, reverse_http, and reverse_https instead of only broad families.",
        },
        CoverageItem {
            capability: "care-centered-reporting-and-teaching",
            status: "implemented",
            assessments: &[
                "self-assessments/real-time-telementary.txt",
                "self-assessments/sovwreign-detective-and-reporter.txt",
                "self-assessments/genesis-sequence.txt",
            ],
            implementation: &[
                "crates/sentinel-reporting",
                "crates/sentinel-education",
                "crates/sentinel-correlation",
            ],
            notes: "The reporting engine explains what happened in calm, human language while preserving forensic detail for professionals.",
        },
        CoverageItem {
            capability: "dynamic-recovery-and-shadow-vault",
            status: "partial",
            assessments: &[
                "self-assessments/dynamic-recovery.txt",
                "self-assessments/the-shadow-vault.txt",
                "self-assessments/sovereign-immune-system.txt",
            ],
            implementation: &[
                "crates/sentinel-integrity",
                "crates/sentinel-shadow-vault",
                "crates/sentinel-runtime",
                "crates/sentinel-response",
            ],
            notes: "Recovery triage, healing modes, and restore planning exist now; direct OS-level artifact restore and process control are still future work.",
        },
        CoverageItem {
            capability: "asm-fast-path-nervous-system",
            status: "partial",
            assessments: &[
                "self-assessments/kernel-bypass-for-fast-actions.txt",
                "self-assessments/autonomous-mitigation.txt",
            ],
            implementation: &[
                "crates/sentinel-native-bridge",
                "native/asm",
                "crates/sentinel-runtime",
            ],
            notes: "Inline ASM already drives cycle stamping and fast pressure scoring. Zero-copy and direct-to-wire packet paths remain documented future work behind stability-first controls.",
        },
        CoverageItem {
            capability: "c-low-level-defense-layer",
            status: "scaffolded",
            assessments: &[
                "self-assessments/compaitibility.txt",
                "self-assessments/the-guardian-system-arch.txt",
            ],
            implementation: &[
                "native/c",
                "native/include",
                "crates/sentinel-native-bridge",
            ],
            notes: "The C layer is reserved for OS-facing packet helpers, descriptor-safe buffers, and compatibility shims. Contracts exist; live linking is still ahead.",
        },
        CoverageItem {
            capability: "cpp-stateful-classifier-layer",
            status: "scaffolded",
            assessments: &[
                "self-assessments/the-guardian-system-arch.txt",
                "self-assessments/reverse-engineering-frameworks.txt",
            ],
            implementation: &[
                "native/cpp",
                "native/include",
                "crates/sentinel-native-bridge",
            ],
            notes: "The C++ layer is reserved for richer stateful models and attack-template analysis. It is part of the layered design, but not linked into the runtime yet.",
        },
        CoverageItem {
            capability: "nic-hal-and-multi-vendor-compatibility",
            status: "future",
            assessments: &["self-assessments/compaitibility.txt"],
            implementation: &[
                "native/README.md",
                "docs/architecture/REPOSITORY-STRUCTURE.md",
            ],
            notes: "Queue partitioning, descriptor maps, and vendor-specific HAL logic are accepted design goals but are not implemented in v1.0 yet.",
        },
    ]
}
