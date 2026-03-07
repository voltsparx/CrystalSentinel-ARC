#![forbid(unsafe_code)]

use sentinel_detection::{seed_framework_catalog, seed_intel_sources, seed_pattern_identities};
use sentinel_education::{find_lesson, harmless_scan_types, learning_catalog};
use sentinel_native_bridge::native_layer_manifest;
use sentinel_scenario::seed_scenarios;

fn main() {
    let command = std::env::args().nth(1).unwrap_or_else(|| "help".to_string());

    match command.as_str() {
        "intel" => {
            for source in seed_intel_sources() {
                println!("{} [{}] - {}", source.name, source.kind.as_str(), source.summary);
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
                    "{} -> family={} category={} protocols={} sources={}",
                    identity.name,
                    identity.family.as_str(),
                    identity.category,
                    identity.protocols.join(","),
                    identity.sources.join(",")
                );
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
        "teach" => {
            if let Some(name) = std::env::args().nth(2) {
                if let Some(lesson) = find_lesson(&name) {
                    print_lesson(&lesson);
                } else {
                    println!("unknown lesson: {}", name);
                }
            } else {
                for lesson in learning_catalog() {
                    println!("{} [{}] harmless={}", lesson.name, lesson.classification, lesson.harmless);
                }
            }
        }
        "safe-scans" => {
            for lesson in harmless_scan_types() {
                println!("{} -> {}", lesson.name, lesson.summary);
            }
        }
        _ => {
            println!("usage: sentinelctl [intel|frameworks|patterns|scenarios|layers|teach|safe-scans]");
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
