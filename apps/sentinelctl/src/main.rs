#![forbid(unsafe_code)]

use sentinel_detection::{seed_framework_catalog, seed_intel_sources};
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
        _ => {
            println!("usage: sentinelctl [intel|frameworks|scenarios|layers]");
        }
    }
}
