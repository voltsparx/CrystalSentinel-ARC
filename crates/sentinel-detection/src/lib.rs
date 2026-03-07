#![forbid(unsafe_code)]

use sentinel_common::{AttackFamily, IntelSource, IntelSourceKind, MitigationStage, ThreatSignal};
use sentinel_native_bridge::{fast_path_assess, FastPathDecision, FastPathFeatures, FastThreatKind};
use sentinel_telemetry::TelemetryEvent;

#[derive(Clone, Debug)]
pub struct FrameworkFingerprint {
    pub name: &'static str,
    pub family: AttackFamily,
    pub indicators: &'static [&'static str],
    pub preferred_stage: MitigationStage,
}

#[derive(Clone, Debug)]
pub struct PatternIdentity {
    pub name: &'static str,
    pub family: AttackFamily,
    pub category: &'static str,
    pub sources: &'static [&'static str],
    pub protocols: &'static [&'static str],
    pub indicators: &'static [&'static str],
    pub minimum_matches: usize,
    pub confidence: u8,
    pub narrative: &'static str,
}

#[derive(Clone, Debug)]
pub struct PatternMatch {
    pub identity_name: &'static str,
    pub family: AttackFamily,
    pub matched_indicators: Vec<&'static str>,
    pub confidence: u8,
    pub detail: String,
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
        IntelSource {
            name: "suricata",
            kind: IntelSourceKind::SecuritySystem,
            summary: "Classification-driven IDS/IPS patterns and protocol anomaly coverage.",
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

pub fn seed_pattern_identities() -> Vec<PatternIdentity> {
    vec![
        PatternIdentity {
            name: "snort3-shellcode-detect",
            family: AttackFamily::ExploitDelivery,
            category: "shellcode-detect",
            sources: &["snort3"],
            protocols: &["tcp", "http", "smtp", "imap", "pop3"],
            indicators: &["shellcode", "decoder", "executable_code", "stager"],
            minimum_matches: 2,
            confidence: 90,
            narrative: "Mirrors Snort3 shellcode-detect classification for executable delivery artifacts.",
        },
        PatternIdentity {
            name: "snort3-trojan-activity",
            family: AttackFamily::RemoteAccessTrojan,
            category: "trojan-activity",
            sources: &["snort3"],
            protocols: &["tcp", "http", "https", "dns"],
            indicators: &["trojan", "rat", "backdoor", "remote_control", "command_channel"],
            minimum_matches: 2,
            confidence: 88,
            narrative: "Mirrors Snort3 trojan-activity classification for remote-control behavior.",
        },
        PatternIdentity {
            name: "snort3-malware-cnc",
            family: AttackFamily::Beaconing,
            category: "malware-cnc",
            sources: &["snort3"],
            protocols: &["dns", "http", "https", "tcp"],
            indicators: &["malware_cnc", "command_and_control", "beacon", "polling", "uuid"],
            minimum_matches: 2,
            confidence: 89,
            narrative: "Mirrors Snort3 malware-cnc classification for command-and-control traffic.",
        },
        PatternIdentity {
            name: "snort3-client-side-exploit",
            family: AttackFamily::ExploitDelivery,
            category: "client-side-exploit",
            sources: &["snort3"],
            protocols: &["http", "https"],
            indicators: &["client_side_exploit", "document_exploit", "browser_exploit", "decompress_pdf", "decompress_zip"],
            minimum_matches: 2,
            confidence: 86,
            narrative: "Mirrors Snort3 client-side-exploit classification for document and browser attack surfaces.",
        },
        PatternIdentity {
            name: "snort3-sensitive-data-egress",
            family: AttackFamily::DataExfiltration,
            category: "sensitive-data-egress",
            sources: &["snort3"],
            protocols: &["http", "smtp", "ftp-data", "imap", "pop3"],
            indicators: &["credit_card", "us_social", "email", "us_phone", "http_client_body", "file_data"],
            minimum_matches: 2,
            confidence: 93,
            narrative: "Inspired by Snort3 sensitive-data rules for outbound leakage over application protocols.",
        },
        PatternIdentity {
            name: "suricata-network-scan",
            family: AttackFamily::OffensiveScan,
            category: "network-scan",
            sources: &["suricata"],
            protocols: &["tcp", "udp", "icmp"],
            indicators: &["network_scan", "attempted_recon", "port_sweep", "syn_scan"],
            minimum_matches: 2,
            confidence: 87,
            narrative: "Derived from Suricata classification coverage for network-scan and attempted-recon activity.",
        },
        PatternIdentity {
            name: "suricata-command-and-control",
            family: AttackFamily::Beaconing,
            category: "command-and-control",
            sources: &["suricata"],
            protocols: &["dns", "http", "https", "tcp"],
            indicators: &["command_and_control", "domain_c2", "beacon", "malware_cnc"],
            minimum_matches: 2,
            confidence: 91,
            narrative: "Derived from Suricata classification coverage for command-and-control and domain-c2 activity.",
        },
        PatternIdentity {
            name: "suricata-web-application-attack",
            family: AttackFamily::ExploitDelivery,
            category: "web-application-attack",
            sources: &["suricata"],
            protocols: &["http", "https"],
            indicators: &["web_application_attack", "exploit_kit", "http_uri_anomaly", "client_side_exploit"],
            minimum_matches: 2,
            confidence: 89,
            narrative: "Derived from Suricata classifications for exploit-kit and web-application-attack behavior.",
        },
        PatternIdentity {
            name: "suricata-heartbeat-anomaly",
            family: AttackFamily::ExploitDelivery,
            category: "protocol-command-decode",
            sources: &["suricata"],
            protocols: &["tls", "https"],
            indicators: &[
                "tls.invalid_heartbeat_message",
                "tls.overflow_heartbeat_message",
                "tls.dataleak_heartbeat_mismatch",
                "heartbleed",
            ],
            minimum_matches: 1,
            confidence: 94,
            narrative: "Derived from Suricata TLS heartbeat anomaly rules that flag possible heartbeat exploit attempts.",
        },
        PatternIdentity {
            name: "suricata-credential-theft",
            family: AttackFamily::IdentityAbuse,
            category: "credential-theft",
            sources: &["suricata"],
            protocols: &["http", "https", "smtp", "imap"],
            indicators: &["credential_theft", "default_login", "suspicious_login", "password_spray"],
            minimum_matches: 2,
            confidence: 90,
            narrative: "Derived from Suricata classifications for credential theft, suspicious login, and default login attempts.",
        },
        PatternIdentity {
            name: "metasploit-http-transport",
            family: AttackFamily::PayloadStager,
            category: "meterpreter-http-transport",
            sources: &["metasploit-payloads"],
            protocols: &["http", "https"],
            indicators: &["meterpreter", "tlv", "http_transport", "uuid", "custom_headers", "user_agent", "cert_hash"],
            minimum_matches: 3,
            confidence: 91,
            narrative: "Reflects Meterpreter HTTP(S) transport traits such as TLV packeting, UUID tagging, and custom header handling.",
        },
        PatternIdentity {
            name: "metasploit-tcp-transport",
            family: AttackFamily::PayloadStager,
            category: "meterpreter-tcp-transport",
            sources: &["metasploit-payloads"],
            protocols: &["tcp"],
            indicators: &["meterpreter", "tlv", "tcp_transport", "socket", "uuid", "stageless", "stage_loader"],
            minimum_matches: 3,
            confidence: 90,
            narrative: "Reflects Meterpreter TCP transport traits such as TLV packeting, UUID tagging, and staged socket handoff.",
        },
        PatternIdentity {
            name: "metasploit-stager-migration",
            family: AttackFamily::PayloadStager,
            category: "meterpreter-stage-control",
            sources: &["metasploit-payloads"],
            protocols: &["tcp", "http", "https"],
            indicators: &["stage_loader", "migrate_payload", "pivot_stage_data", "reflective_payload"],
            minimum_matches: 2,
            confidence: 92,
            narrative: "Reflects staged payload and migration markers found in metasploit-payload transport and pivot code.",
        },
    ]
}

pub fn detect_signal(event: &TelemetryEvent) -> ThreatSignal {
    let summary = event.summary.to_ascii_lowercase();
    let fast = fast_assess_event(event);

    let (family, confidence, detail) = if matches!(fast.kind, FastThreatKind::IntegrityPressure) && fast.overall_score >= 70 {
        (
            AttackFamily::IntegrityAttack,
            fast.overall_score,
            explain_fast_path("Runtime tamper or integrity pressure triggered the ASM fast path.", fast),
        )
    } else if matches!(fast.kind, FastThreatKind::DdosPressure) && fast.overall_score >= 80 {
        (
            AttackFamily::VolumetricFlood,
            fast.overall_score,
            explain_fast_path("Burst or saturation behavior triggered the ASM fast path.", fast),
        )
    } else if matches!(fast.kind, FastThreatKind::OffensiveScan) && fast.overall_score >= 70 {
        (
            AttackFamily::OffensiveScan,
            fast.overall_score,
            explain_fast_path("Reconnaissance or offensive scan pressure triggered the ASM fast path.", fast),
        )
    } else if let Some(pattern) = identify_pattern(&summary) {
        (
            pattern.family,
            pattern.confidence.max(fast.overall_score),
            explain_fast_path(&pattern.detail, fast),
        )
    } else if matches!(fast.kind, FastThreatKind::Intrusion) && fast.overall_score >= 70 {
        (
            AttackFamily::ExploitDelivery,
            fast.overall_score,
            explain_fast_path("Intrusion-oriented behavior triggered the ASM fast path.", fast),
        )
    } else if summary.contains("dns_tunnel") || summary.contains("high_entropy") {
        (
            AttackFamily::DnsTunneling,
            92.max(fast.overall_score),
            explain_fast_path("High-entropy DNS behavior matched tunneling heuristics.", fast),
        )
    } else if contains_any(&summary, &["credit_card", "us_social", "http_client_body", "file_data"]) {
        (
            AttackFamily::DataExfiltration,
            91.max(fast.overall_score),
            explain_fast_path("Sensitive outbound content matched data exfiltration heuristics.", fast),
        )
    } else if summary.contains("burst_flood") {
        (
            AttackFamily::VolumetricFlood,
            95.max(fast.overall_score),
            explain_fast_path("Burst-flood pattern matched volumetric traffic heuristics.", fast),
        )
    } else if summary.contains("oauth_token_abuse") {
        (
            AttackFamily::IdentityAbuse,
            90.max(fast.overall_score),
            explain_fast_path("Identity telemetry matched autonomous token-abuse behavior.", fast),
        )
    } else if summary.contains("api_scrape") {
        (
            AttackFamily::ApiScraping,
            80.max(fast.overall_score),
            explain_fast_path("Traffic resembled automated scraping of protected APIs.", fast),
        )
    } else if summary.contains("stage_loader") || summary.contains("payload") {
        (
            AttackFamily::PayloadStager,
            88.max(fast.overall_score),
            explain_fast_path("Delivery telemetry resembled staged exploit or loader behavior.", fast),
        )
    } else if summary.contains("rat") || summary.contains("beacon") {
        (
            AttackFamily::Beaconing,
            84.max(fast.overall_score),
            explain_fast_path("Behavior resembled recurring command-and-control beaconing.", fast),
        )
    } else if contains_any(
        &summary,
        &["integrity_breach", "hash_mismatch", "unsigned_change", "syscall_table", "modified_binary"],
    ) {
        (
            AttackFamily::IntegrityAttack,
            93.max(fast.overall_score),
            explain_fast_path("Integrity telemetry indicated direct pressure on the Sentinel runtime.", fast),
        )
    } else {
        (
            AttackFamily::Unknown,
            40.max(fast.overall_score),
            explain_fast_path("Signal catalog did not find a strong family match.", fast),
        )
    };

    ThreatSignal {
        source_name: event.source.clone(),
        family,
        confidence,
        detail,
    }
}

pub fn fast_assess_event(event: &TelemetryEvent) -> FastPathDecision {
    fast_path_assess(build_fast_path_features(event))
}

pub fn identify_pattern(summary: &str) -> Option<PatternMatch> {
    let mut best_match = None;

    for identity in seed_pattern_identities() {
        let matched_indicators: Vec<_> = identity
            .indicators
            .iter()
            .copied()
            .filter(|indicator| summary.contains(indicator))
            .collect();

        if matched_indicators.len() < identity.minimum_matches {
            continue;
        }

        let confidence = identity
            .confidence
            .saturating_add(((matched_indicators.len() - identity.minimum_matches) as u8).saturating_mul(3))
            .min(99);

        let detail = format!(
            "pattern_identity={} category={} family={} sources={} protocols={} matched={} narrative={}",
            identity.name,
            identity.category,
            identity.family.as_str(),
            identity.sources.join(","),
            identity.protocols.join(","),
            matched_indicators.join(","),
            identity.narrative
        );

        let pattern_match = PatternMatch {
            identity_name: identity.name,
            family: identity.family,
            matched_indicators,
            confidence,
            detail,
        };

        if best_match
            .as_ref()
            .map_or(true, |current: &PatternMatch| pattern_match.confidence > current.confidence)
        {
            best_match = Some(pattern_match);
        }
    }

    best_match
}

fn build_fast_path_features(event: &TelemetryEvent) -> FastPathFeatures {
    let summary = event.summary.to_ascii_lowercase();
    let mut features = FastPathFeatures::default();

    if contains_any(&summary, &["scan", "recon", "probe", "fingerprint", "syn", "port_sweep"]) {
        features.scan_pressure = features.scan_pressure.saturating_add(65);
    }
    if contains_any(
        &summary,
        &[
            "stage_loader",
            "payload",
            "rat",
            "beacon",
            "oauth_token_abuse",
            "exploit",
            "intrusion",
            "meterpreter",
            "tlv",
            "shellcode",
            "trojan",
            "stager",
            "reverse_shell",
            "uuid",
            "heartbleed",
            "tls.invalid_heartbeat_message",
            "tls.overflow_heartbeat_message",
        ],
    ) {
        features.intrusion_pressure = features.intrusion_pressure.saturating_add(70);
    }
    if contains_any(&summary, &["burst_flood", "ddos", "flood", "pps_spike", "aisuru"]) {
        features.ddos_pressure = features.ddos_pressure.saturating_add(80);
    }
    if contains_any(&summary, &["oauth", "identity", "token", "impossible-travel"]) {
        features.identity_pressure = features.identity_pressure.saturating_add(60);
    }
    if contains_any(
        &summary,
        &["high_entropy", "dns_tunnel", "encoded", "tunnel"],
    ) {
        features.entropy_pressure = features.entropy_pressure.saturating_add(50);
    }
    if contains_any(
        &summary,
        &[
            "integrity_breach",
            "ptrace",
            "debug",
            "tamper",
            "hash_mismatch",
            "unsigned_change",
            "syscall_table",
            "modified_binary",
        ],
    ) {
        features.integrity_pressure = features.integrity_pressure.saturating_add(75);
    }

    features
}

fn contains_any(summary: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| summary.contains(needle))
}

fn explain_fast_path(prefix: &str, fast: FastPathDecision) -> String {
    format!(
        "{} fast_path.kind={} stage={} score={} scan={} intrusion={} integrity={} ddos={} tick={}",
        prefix,
        fast.kind.as_str(),
        fast.recommended_stage.as_str(),
        fast.overall_score,
        fast.scan_score,
        fast.intrusion_score,
        fast.integrity_score,
        fast.ddos_score,
        fast.cycle_stamp
    )
}

#[cfg(test)]
mod tests {
    use super::{detect_signal, identify_pattern, seed_pattern_identities};
    use sentinel_common::{AttackFamily, HealthSnapshot, TelemetryKind};
    use sentinel_telemetry::TelemetryEvent;

    #[test]
    fn exposes_snort_and_metasploit_pattern_identities() {
        let names: Vec<_> = seed_pattern_identities().into_iter().map(|item| item.name).collect();

        assert!(names.contains(&"snort3-malware-cnc"));
        assert!(names.contains(&"metasploit-http-transport"));
        assert!(names.contains(&"suricata-heartbeat-anomaly"));
    }

    #[test]
    fn identifies_metasploit_http_transport_patterns() {
        let matched = identify_pattern("meterpreter tlv http_transport uuid custom_headers")
            .expect("metasploit transport should match");

        assert_eq!(matched.identity_name, "metasploit-http-transport");
        assert_eq!(matched.family, AttackFamily::PayloadStager);
    }

    #[test]
    fn detects_snort3_sensitive_data_egress() {
        let signal = detect_signal(&TelemetryEvent {
            kind: TelemetryKind::Flow,
            source: "workload-17".to_string(),
            summary: "credit_card http_client_body file_data".to_string(),
            health: HealthSnapshot::default(),
        });

        assert_eq!(signal.family, AttackFamily::DataExfiltration);
        assert!(signal.detail.contains("snort3-sensitive-data-egress"));
    }

    #[test]
    fn identifies_suricata_heartbeat_exploit() {
        let signal = detect_signal(&TelemetryEvent {
            kind: TelemetryKind::Packet,
            source: "198.51.100.61".to_string(),
            summary: "tls.invalid_heartbeat_message heartbleed".to_string(),
            health: HealthSnapshot::default(),
        });

        assert_eq!(signal.family, AttackFamily::ExploitDelivery);
        assert!(signal.detail.contains("suricata-heartbeat-anomaly"));
    }
}
