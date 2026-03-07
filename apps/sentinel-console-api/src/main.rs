#![forbid(unsafe_code)]

use sentinel_detection::seed_intel_sources;

fn main() {
    println!("sentinel-console-api scaffold");
    println!("registered intel sources: {}", seed_intel_sources().len());
    println!("planned responsibilities: investigations, policy review, source inventory");
}

