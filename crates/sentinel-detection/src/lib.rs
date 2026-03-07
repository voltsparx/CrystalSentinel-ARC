#![forbid(unsafe_code)]

use sentinel_common::{AttackFamily, IntelSource, IntelSourceKind, MitigationStage, ThreatSignal};
use sentinel_telemetry::TelemetryEvent;

#[derive(Clone, Debug)]
pub struct FrameworkFingerprint {
    pub name: &'static str,
    pub family: AttackFamily,
    pub indicators: &'static [&'static str],
    pub preferred_stage: MitigationStage,
}

pub fn seed_intel_sources() -> Vec<IntelSource> {
    vec![
        IntelSource {
            name: "AndroRAT",
            kind: IntelSourceKind::OffensiveFramework,
            summary: "Mobile remote-access patterns and Android-focused control flows.",
        },
        IntelSource {
            name: "metasploit-payloads",
            kind: IntelSourceKind::OffensiveFramework,
            summary: "Stage loading and post-exploitation transport behaviors.",
        },
        IntelSource {
            name: "TheFatRat",
            kind: IntelSourceKind::OffensiveFramework,
            summary: "Payload packaging and delivery-chain behavior references.",
        },
        IntelSource {
            name: "snort3",
            kind: IntelSourceKind::SecuritySystem,
            summary: "Rule engine and detection-content reference implementation.",
        },
    ]
}

pub fn seed_framework_catalog() -> Vec<FrameworkFingerprint> {
    vec![
        FrameworkFingerprint {
            name: "AndroRAT",
            family: AttackFamily::RemoteAccessTrojan,
            indicators: &["android control channel", "device command fan-out", "mobile beaconing"],
            preferred_stage: MitigationStage::Contain,
        },
        FrameworkFingerprint {
            name: "metasploit-payloads",
            family: AttackFamily::PayloadStager,
            indicators: &["stage_loader", "reflective payload", "post-exploitation transport"],
            preferred_stage: MitigationStage::Contain,
        },
        FrameworkFingerprint {
            name: "TheFatRat",
            family: AttackFamily::ExploitDelivery,
            indicators: &["payload_builder", "delivery wrapper", "backdoor packaging"],
            preferred_stage: MitigationStage::Throttle,
        },
    ]
}

pub fn detect_signal(event: &TelemetryEvent) -> ThreatSignal {
    let summary = event.summary.to_ascii_lowercase();

    let (family, confidence, detail) = if summary.contains("dns_tunnel") || summary.contains("high_entropy") {
        (
            AttackFamily::DnsTunneling,
            92,
            "High-entropy DNS behavior matched tunneling heuristics.".to_string(),
        )
    } else if summary.contains("burst_flood") {
        (
            AttackFamily::VolumetricFlood,
            95,
            "Burst-flood pattern matched volumetric traffic heuristics.".to_string(),
        )
    } else if summary.contains("oauth_token_abuse") {
        (
            AttackFamily::IdentityAbuse,
            90,
            "Identity telemetry matched autonomous token-abuse behavior.".to_string(),
        )
    } else if summary.contains("api_scrape") {
        (
            AttackFamily::ApiScraping,
            80,
            "Traffic resembled automated scraping of protected APIs.".to_string(),
        )
    } else if summary.contains("stage_loader") || summary.contains("payload") {
        (
            AttackFamily::PayloadStager,
            88,
            "Delivery telemetry resembled staged exploit or loader behavior.".to_string(),
        )
    } else if summary.contains("rat") || summary.contains("beacon") {
        (
            AttackFamily::Beaconing,
            84,
            "Behavior resembled recurring command-and-control beaconing.".to_string(),
        )
    } else if summary.contains("integrity_breach") {
        (
            AttackFamily::IntegrityAttack,
            93,
            "Integrity telemetry indicated direct pressure on the Sentinel runtime.".to_string(),
        )
    } else {
        (
            AttackFamily::Unknown,
            40,
            "Signal catalog did not find a strong family match.".to_string(),
        )
    };

    ThreatSignal {
        source_name: event.source.clone(),
        family,
        confidence,
        detail,
    }
}

