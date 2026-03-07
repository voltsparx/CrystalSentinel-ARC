#![forbid(unsafe_code)]

use sentinel_common::{
    AttackFamily, IntelSource, IntelSourceKind, MitigationStage, ThreatRecognition, ThreatSignal,
};
use sentinel_native_bridge::{
    fast_path_assess, FastPathDecision, FastPathFeatures, FastThreatKind,
};
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
    pub display_name: &'static str,
    pub family: AttackFamily,
    pub category: &'static str,
    pub sources: &'static [&'static str],
    pub protocols: &'static [&'static str],
    pub labels: &'static [&'static str],
    pub indicators: &'static [&'static str],
    pub minimum_matches: usize,
    pub confidence: u8,
    pub narrative: &'static str,
}

#[derive(Clone, Debug)]
pub struct PatternMatch {
    pub identity_name: &'static str,
    pub family: AttackFamily,
    pub recognition: ThreatRecognition,
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
        IntelSource {
            name: "zeek",
            kind: IntelSourceKind::SecuritySystem,
            summary: "Stateful network analysis, protocol-aware scripting, and notice/intel framework coverage.",
        },
    ]
}

pub fn seed_framework_catalog() -> Vec<FrameworkFingerprint> {
    vec![
        FrameworkFingerprint {
            name: "AndroRAT",
            family: AttackFamily::RemoteAccessTrojan,
            indicators: &[
                "android control channel",
                "device command fan-out",
                "mobile beaconing",
            ],
            preferred_stage: MitigationStage::Contain,
        },
        FrameworkFingerprint {
            name: "metasploit-payloads",
            family: AttackFamily::PayloadStager,
            indicators: &[
                "stage_loader",
                "reflective payload",
                "post-exploitation transport",
            ],
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
            display_name: "Snort3 Shellcode Delivery Pattern",
            family: AttackFamily::ExploitDelivery,
            category: "shellcode-detect",
            sources: &["snort3"],
            protocols: &["tcp", "http", "smtp", "imap", "pop3"],
            labels: &["shellcode", "stager"],
            indicators: &["shellcode", "decoder", "executable_code", "stager"],
            minimum_matches: 2,
            confidence: 90,
            narrative: "Mirrors Snort3 shellcode-detect classification for executable delivery artifacts.",
        },
        PatternIdentity {
            name: "snort3-trojan-activity",
            display_name: "Snort3 Trojan Activity Pattern",
            family: AttackFamily::RemoteAccessTrojan,
            category: "trojan-activity",
            sources: &["snort3"],
            protocols: &["tcp", "http", "https", "dns"],
            labels: &["trojan", "rat"],
            indicators: &["trojan", "rat", "backdoor", "remote_control", "command_channel"],
            minimum_matches: 2,
            confidence: 88,
            narrative: "Mirrors Snort3 trojan-activity classification for remote-control behavior.",
        },
        PatternIdentity {
            name: "snort3-malware-cnc",
            display_name: "Snort3 Malware Command Channel",
            family: AttackFamily::Beaconing,
            category: "malware-cnc",
            sources: &["snort3"],
            protocols: &["dns", "http", "https", "tcp"],
            labels: &["beacon", "command-and-control"],
            indicators: &["malware_cnc", "command_and_control", "beacon", "polling", "uuid"],
            minimum_matches: 2,
            confidence: 89,
            narrative: "Mirrors Snort3 malware-cnc classification for command-and-control traffic.",
        },
        PatternIdentity {
            name: "snort3-client-side-exploit",
            display_name: "Snort3 Client-Side Exploit Pattern",
            family: AttackFamily::ExploitDelivery,
            category: "client-side-exploit",
            sources: &["snort3"],
            protocols: &["http", "https"],
            labels: &["exploit", "document-delivery"],
            indicators: &["client_side_exploit", "document_exploit", "browser_exploit", "decompress_pdf", "decompress_zip"],
            minimum_matches: 2,
            confidence: 86,
            narrative: "Mirrors Snort3 client-side-exploit classification for document and browser attack surfaces.",
        },
        PatternIdentity {
            name: "snort3-sensitive-data-egress",
            display_name: "Snort3 Sensitive Data Egress Pattern",
            family: AttackFamily::DataExfiltration,
            category: "sensitive-data-egress",
            sources: &["snort3"],
            protocols: &["http", "smtp", "ftp-data", "imap", "pop3"],
            labels: &["data-exfiltration", "sensitive-data"],
            indicators: &["credit_card", "us_social", "email", "us_phone", "http_client_body", "file_data"],
            minimum_matches: 2,
            confidence: 93,
            narrative: "Inspired by Snort3 sensitive-data rules for outbound leakage over application protocols.",
        },
        PatternIdentity {
            name: "suricata-network-scan",
            display_name: "Suricata Network Scan Pattern",
            family: AttackFamily::OffensiveScan,
            category: "network-scan",
            sources: &["suricata"],
            protocols: &["tcp", "udp", "icmp"],
            labels: &["scan", "reconnaissance"],
            indicators: &["network_scan", "attempted_recon", "port_sweep", "syn_scan"],
            minimum_matches: 2,
            confidence: 87,
            narrative: "Derived from Suricata classification coverage for network-scan and attempted-recon activity.",
        },
        PatternIdentity {
            name: "research-high-speed-asynchronous-scan",
            display_name: "High-Speed Asynchronous Scan Pattern",
            family: AttackFamily::OffensiveScan,
            category: "high-speed-recon",
            sources: &["heuristic", "research"],
            protocols: &["tcp"],
            labels: &["scan", "reconnaissance", "high_speed_scan", "asynchronous_sweep"],
            indicators: &[
                "masscan",
                "async_scan",
                "asynchronous_sweep",
                "stateless_syn",
                "wide_port_sweep",
                "pps_scan",
            ],
            minimum_matches: 2,
            confidence: 94,
            narrative: "Recognizes high-speed asynchronous scan pressure typical of mass-scan style tooling without relying on one single product signature.",
        },
        PatternIdentity {
            name: "research-service-fingerprint-scan",
            display_name: "Service Fingerprint Scan Pattern",
            family: AttackFamily::OffensiveScan,
            category: "service-fingerprint-recon",
            sources: &["heuristic", "research"],
            protocols: &["tcp", "udp"],
            labels: &["scan", "reconnaissance", "service_fingerprint", "version_probe"],
            indicators: &[
                "nmap",
                "service_probe",
                "version_scan",
                "banner_grab",
                "os_fingerprint",
            ],
            minimum_matches: 2,
            confidence: 89,
            narrative: "Recognizes service and version-fingerprinting probes typically associated with interactive reconnaissance tooling.",
        },
        PatternIdentity {
            name: "suricata-command-and-control",
            display_name: "Suricata Command-and-Control Pattern",
            family: AttackFamily::Beaconing,
            category: "command-and-control",
            sources: &["suricata"],
            protocols: &["dns", "http", "https", "tcp"],
            labels: &["beacon", "command-and-control"],
            indicators: &["command_and_control", "domain_c2", "beacon", "malware_cnc"],
            minimum_matches: 2,
            confidence: 91,
            narrative: "Derived from Suricata classification coverage for command-and-control and domain-c2 activity.",
        },
        PatternIdentity {
            name: "suricata-web-application-attack",
            display_name: "Suricata Web Application Attack Pattern",
            family: AttackFamily::ExploitDelivery,
            category: "web-application-attack",
            sources: &["suricata"],
            protocols: &["http", "https"],
            labels: &["exploit", "web-application-attack"],
            indicators: &["web_application_attack", "exploit_kit", "http_uri_anomaly", "client_side_exploit"],
            minimum_matches: 2,
            confidence: 89,
            narrative: "Derived from Suricata classifications for exploit-kit and web-application-attack behavior.",
        },
        PatternIdentity {
            name: "suricata-heartbeat-anomaly",
            display_name: "Suricata TLS Heartbeat Exploit Pattern",
            family: AttackFamily::ExploitDelivery,
            category: "protocol-command-decode",
            sources: &["suricata"],
            protocols: &["tls", "https"],
            labels: &["exploit", "heartbleed"],
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
            display_name: "Suricata Credential Theft Pattern",
            family: AttackFamily::IdentityAbuse,
            category: "credential-theft",
            sources: &["suricata"],
            protocols: &["http", "https", "smtp", "imap"],
            labels: &["credential-theft", "password-spray"],
            indicators: &["credential_theft", "default_login", "suspicious_login", "password_spray"],
            minimum_matches: 2,
            confidence: 90,
            narrative: "Derived from Suricata classifications for credential theft, suspicious login, and default login attempts.",
        },
        PatternIdentity {
            name: "zeek-heartbleed-observer",
            display_name: "Zeek Heartbleed Observer Pattern",
            family: AttackFamily::ExploitDelivery,
            category: "zeek-heartbleed-notice",
            sources: &["zeek"],
            protocols: &["tls", "https"],
            labels: &["exploit", "heartbleed", "zeek_notice"],
            indicators: &[
                "ssl_heartbeat_attack",
                "ssl_heartbeat_attack_success",
                "ssl_heartbeat_odd_length",
                "ssl_heartbeat_many_requests",
                "heartbleed",
            ],
            minimum_matches: 1,
            confidence: 93,
            narrative: "Derived from the local Zeek heartbleed policy script, which raises notices for heartbeat attacks, odd-length heartbeat requests, and likely exploit success.",
        },
        PatternIdentity {
            name: "zeek-ssh-password-guessing",
            display_name: "Zeek SSH Password Guessing Pattern",
            family: AttackFamily::IdentityAbuse,
            category: "zeek-ssh-bruteforce",
            sources: &["zeek"],
            protocols: &["ssh", "tcp"],
            labels: &["credential-theft", "password-spray", "ssh_bruteforce", "zeek_notice"],
            indicators: &[
                "password_guessing",
                "ssh.login.failure",
                "ssh_auth_failed",
                "ssh_auth_successful",
                "successful_login",
            ],
            minimum_matches: 2,
            confidence: 91,
            narrative: "Derived from the local Zeek SSH password-guessing policy, which tracks failed SSH logins with SumStats and surfaces password guessing notices and successful-login intel events.",
        },
        PatternIdentity {
            name: "zeek-http-uri-sqli",
            display_name: "Zeek HTTP URI SQL Injection Pattern",
            family: AttackFamily::ExploitDelivery,
            category: "zeek-http-sqli",
            sources: &["zeek"],
            protocols: &["http", "https"],
            labels: &["exploit", "sql_injection", "uri_sqli", "zeek_notice"],
            indicators: &[
                "sql_injection_attacker",
                "sql_injection_victim",
                "uri_sqli",
                "match_sql_injection_uri",
                "union select",
            ],
            minimum_matches: 2,
            confidence: 92,
            narrative: "Derived from the local Zeek HTTP SQL-injection script, which tags suspicious URIs, counts attacker/victim behavior, and raises SQL injection notices.",
        },
        PatternIdentity {
            name: "zeek-intel-indicator-observation",
            display_name: "Zeek Intel Indicator Observation",
            family: AttackFamily::Beaconing,
            category: "zeek-intel-seen",
            sources: &["zeek"],
            protocols: &["dns", "http", "https"],
            labels: &["intel", "indicator_observation", "zeek_intel"],
            indicators: &[
                "intel::seen",
                "http::in_url",
                "dns::in_request",
                "indicator_type=intel::url",
                "indicator_type=intel::domain",
            ],
            minimum_matches: 2,
            confidence: 88,
            narrative: "Derived from the local Zeek intel-seen scripts that forward observed URLs and DNS queries into the intel framework for later matching and notice handling.",
        },
        PatternIdentity {
            name: "metasploit-reverse-http-transport",
            display_name: "Meterpreter Reverse HTTP Transport",
            family: AttackFamily::PayloadStager,
            category: "meterpreter-reverse-http",
            sources: &["metasploit-payloads"],
            protocols: &["http"],
            labels: &["stager", "reverse_http", "meterpreter"],
            indicators: &["meterpreter", "tlv", "http_transport", "uuid", "custom_headers", "user_agent"],
            minimum_matches: 3,
            confidence: 91,
            narrative: "Reflects Meterpreter reverse HTTP transport traits such as TLV packeting, UUID tagging, and custom header handling.",
        },
        PatternIdentity {
            name: "metasploit-reverse-https-transport",
            display_name: "Meterpreter Reverse HTTPS Transport",
            family: AttackFamily::PayloadStager,
            category: "meterpreter-reverse-https",
            sources: &["metasploit-payloads"],
            protocols: &["https"],
            labels: &["stager", "reverse_https", "meterpreter"],
            indicators: &["meterpreter", "tlv", "http_transport", "cert_hash", "uuid", "custom_headers"],
            minimum_matches: 3,
            confidence: 90,
            narrative: "Reflects Meterpreter reverse HTTPS transport traits such as TLV packeting, UUID tagging, and certificate pinning hints.",
        },
        PatternIdentity {
            name: "metasploit-reverse-tcp-transport",
            display_name: "Meterpreter Reverse TCP Transport",
            family: AttackFamily::PayloadStager,
            category: "meterpreter-reverse-tcp",
            sources: &["metasploit-payloads"],
            protocols: &["tcp"],
            labels: &["stager", "reverse_tcp", "meterpreter"],
            indicators: &["meterpreter", "tlv", "tcp_transport", "socket", "uuid", "stage_loader"],
            minimum_matches: 3,
            confidence: 90,
            narrative: "Reflects Meterpreter reverse TCP transport traits such as TLV packeting, socket handoff, and staged session setup.",
        },
        PatternIdentity {
            name: "metasploit-stager-migration",
            display_name: "Meterpreter Stage Migration Pattern",
            family: AttackFamily::PayloadStager,
            category: "meterpreter-stage-control",
            sources: &["metasploit-payloads"],
            protocols: &["tcp", "http", "https"],
            labels: &["stager", "migration", "meterpreter"],
            indicators: &["stage_loader", "migrate_payload", "pivot_stage_data", "reflective_payload"],
            minimum_matches: 2,
            confidence: 92,
            narrative: "Reflects staged payload and migration markers found in metasploit-payload transport and pivot code.",
        },
        PatternIdentity {
            name: "androrat-mobile-control-channel",
            display_name: "AndroRAT Mobile Control Channel",
            family: AttackFamily::RemoteAccessTrojan,
            category: "mobile-control-channel",
            sources: &["AndroRAT"],
            protocols: &["tcp", "android"],
            labels: &["rat", "android", "control-channel"],
            indicators: &["reverseshell2", "tcpconnection", "mainservice", "jobscheduler", "broadcastreciever"],
            minimum_matches: 2,
            confidence: 92,
            narrative: "Reflects Android control-channel and persistence markers found in the local AndroRAT sources.",
        },
        PatternIdentity {
            name: "androrat-surveillance-suite",
            display_name: "AndroRAT Surveillance Suite",
            family: AttackFamily::RemoteAccessTrojan,
            category: "mobile-surveillance",
            sources: &["AndroRAT"],
            protocols: &["tcp", "android"],
            labels: &["spyware", "rat", "surveillance"],
            indicators: &["camerapreview", "audiomanager", "locationmanager", "videorecorder", "readsms", "readcalllogs", "newshell"],
            minimum_matches: 2,
            confidence: 94,
            narrative: "Reflects Android surveillance and collection capabilities exposed in the local AndroRAT payload classes.",
        },
        PatternIdentity {
            name: "thefatrat-reverse-tcp-wrapper",
            display_name: "TheFatRat Reverse TCP Wrapper",
            family: AttackFamily::PayloadStager,
            category: "delivery-wrapper",
            sources: &["TheFatRat"],
            protocols: &["tcp"],
            labels: &["stager", "reverse_tcp", "delivery-wrapper"],
            indicators: &["reverse_tcp", "backdoor_apk", "power.py", "apkembed.rb"],
            minimum_matches: 2,
            confidence: 89,
            narrative: "Reflects TheFatRat delivery wrapper behavior around reverse TCP payload generation and packaging.",
        },
        PatternIdentity {
            name: "thefatrat-reverse-http-wrapper",
            display_name: "TheFatRat Reverse HTTP Wrapper",
            family: AttackFamily::PayloadStager,
            category: "delivery-wrapper",
            sources: &["TheFatRat"],
            protocols: &["http"],
            labels: &["stager", "reverse_http", "delivery-wrapper"],
            indicators: &["reverse_http", "backdoor_apk", "power.py", "apkembed.rb"],
            minimum_matches: 2,
            confidence: 89,
            narrative: "Reflects TheFatRat delivery wrapper behavior around reverse HTTP payload generation and packaging.",
        },
        PatternIdentity {
            name: "thefatrat-reverse-https-wrapper",
            display_name: "TheFatRat Reverse HTTPS Wrapper",
            family: AttackFamily::PayloadStager,
            category: "delivery-wrapper",
            sources: &["TheFatRat"],
            protocols: &["https"],
            labels: &["stager", "reverse_https", "delivery-wrapper"],
            indicators: &["reverse_https", "backdoor_apk", "power.py", "apkembed.rb"],
            minimum_matches: 2,
            confidence: 90,
            narrative: "Reflects TheFatRat delivery wrapper behavior around reverse HTTPS payload generation and packaging.",
        },
    ]
}

pub fn detect_signal(event: &TelemetryEvent) -> ThreatSignal {
    let summary = event.summary.to_ascii_lowercase();
    let fast = fast_assess_event(event);

    let (family, confidence, recognition, detail) = if matches!(
        fast.kind,
        FastThreatKind::IntegrityPressure
    ) && fast.overall_score >= 70
    {
        (
            AttackFamily::IntegrityAttack,
            fast.overall_score,
            None,
            explain_fast_path(
                "Runtime tamper or integrity pressure triggered the ASM fast path.",
                fast,
            ),
        )
    } else if matches!(fast.kind, FastThreatKind::DdosPressure) && fast.overall_score >= 80 {
        (
            AttackFamily::VolumetricFlood,
            fast.overall_score,
            None,
            explain_fast_path(
                "Burst or saturation behavior triggered the ASM fast path.",
                fast,
            ),
        )
    } else if let Some(pattern) = identify_pattern(&summary) {
        (
            pattern.family,
            pattern.confidence.max(fast.overall_score),
            Some(pattern.recognition.clone()),
            explain_fast_path(&pattern.detail, fast),
        )
    } else if contains_any(
        &summary,
        &[
            "masscan",
            "async_scan",
            "asynchronous_sweep",
            "stateless_syn",
            "wide_port_sweep",
            "pps_scan",
        ],
    ) {
        (
                AttackFamily::OffensiveScan,
                95.max(fast.overall_score),
                Some(heuristic_recognition(
                    "heuristic-high-speed-scan",
                    "High-Speed Asynchronous Scanner",
                    "high-speed-recon",
                    &["scan", "reconnaissance", "high_speed_scan", "asynchronous_sweep"],
                    &["tcp"],
                    &["heuristic"],
                    "Telemetry matched high-speed asynchronous reconnaissance traits often associated with stateless scanner tooling.",
                )),
                explain_fast_path(
                    "Telemetry matched high-speed asynchronous reconnaissance pressure.",
                    fast,
                ),
            )
    } else if contains_any(
        &summary,
        &[
            "nmap",
            "service_probe",
            "version_scan",
            "banner_grab",
            "os_fingerprint",
        ],
    ) {
        (
            AttackFamily::OffensiveScan,
            90.max(fast.overall_score),
            Some(heuristic_recognition(
                "heuristic-service-fingerprint-scan",
                "Service Fingerprint Scan Pattern",
                "service-fingerprint-recon",
                &["scan", "reconnaissance", "service_fingerprint", "version_probe"],
                &["tcp", "udp"],
                &["heuristic"],
                "Telemetry matched service and version-fingerprinting traits commonly seen in interactive scanning tools.",
            )),
            explain_fast_path(
                "Telemetry matched service and version-fingerprinting reconnaissance pressure.",
                fast,
            ),
        )
    } else if matches!(fast.kind, FastThreatKind::OffensiveScan) && fast.overall_score >= 70 {
        (
            AttackFamily::OffensiveScan,
            fast.overall_score,
            None,
            explain_fast_path(
                "Reconnaissance or offensive scan pressure triggered the ASM fast path.",
                fast,
            ),
        )
    } else if summary.contains("reverse_https") {
        (
            AttackFamily::PayloadStager,
            90.max(fast.overall_score),
            Some(heuristic_recognition(
                "heuristic-reverse-https",
                "Reverse HTTPS Stager",
                "reverse-https-stager",
                &["stager", "reverse_https"],
                &["https"],
                &["heuristic"],
                "Recognized reverse HTTPS staging traits in the telemetry summary.",
            )),
            explain_fast_path("Telemetry resembled a reverse HTTPS stager.", fast),
        )
    } else if summary.contains("reverse_http") {
        (
            AttackFamily::PayloadStager,
            89.max(fast.overall_score),
            Some(heuristic_recognition(
                "heuristic-reverse-http",
                "Reverse HTTP Stager",
                "reverse-http-stager",
                &["stager", "reverse_http"],
                &["http"],
                &["heuristic"],
                "Recognized reverse HTTP staging traits in the telemetry summary.",
            )),
            explain_fast_path("Telemetry resembled a reverse HTTP stager.", fast),
        )
    } else if summary.contains("reverse_tcp") || summary.contains("shell_reverse_tcp") {
        (
            AttackFamily::PayloadStager,
            89.max(fast.overall_score),
            Some(heuristic_recognition(
                "heuristic-reverse-tcp",
                "Reverse TCP Stager",
                "reverse-tcp-stager",
                &["stager", "reverse_tcp"],
                &["tcp"],
                &["heuristic"],
                "Recognized reverse TCP staging traits in the telemetry summary.",
            )),
            explain_fast_path("Telemetry resembled a reverse TCP stager.", fast),
        )
    } else if matches!(fast.kind, FastThreatKind::Intrusion) && fast.overall_score >= 70 {
        (
            AttackFamily::ExploitDelivery,
            fast.overall_score,
            None,
            explain_fast_path(
                "Intrusion-oriented behavior triggered the ASM fast path.",
                fast,
            ),
        )
    } else if summary.contains("dns_tunnel") || summary.contains("high_entropy") {
        (
            AttackFamily::DnsTunneling,
            92.max(fast.overall_score),
            None,
            explain_fast_path(
                "High-entropy DNS behavior matched tunneling heuristics.",
                fast,
            ),
        )
    } else if contains_any(
        &summary,
        &["credit_card", "us_social", "http_client_body", "file_data"],
    ) {
        (
            AttackFamily::DataExfiltration,
            91.max(fast.overall_score),
            None,
            explain_fast_path(
                "Sensitive outbound content matched data exfiltration heuristics.",
                fast,
            ),
        )
    } else if summary.contains("burst_flood") {
        (
            AttackFamily::VolumetricFlood,
            95.max(fast.overall_score),
            None,
            explain_fast_path(
                "Burst-flood pattern matched volumetric traffic heuristics.",
                fast,
            ),
        )
    } else if summary.contains("oauth_token_abuse") {
        (
            AttackFamily::IdentityAbuse,
            90.max(fast.overall_score),
            None,
            explain_fast_path(
                "Identity telemetry matched autonomous token-abuse behavior.",
                fast,
            ),
        )
    } else if summary.contains("api_scrape") {
        (
            AttackFamily::ApiScraping,
            80.max(fast.overall_score),
            None,
            explain_fast_path(
                "Traffic resembled automated scraping of protected APIs.",
                fast,
            ),
        )
    } else if summary.contains("stage_loader") || summary.contains("payload") {
        (
            AttackFamily::PayloadStager,
            88.max(fast.overall_score),
            Some(heuristic_recognition(
                "heuristic-payload-stager",
                "Generic Payload Stager",
                "payload-stager",
                &["stager"],
                &["tcp", "http", "https"],
                &["heuristic"],
                "Telemetry resembled staged payload or loader behavior.",
            )),
            explain_fast_path(
                "Delivery telemetry resembled staged exploit or loader behavior.",
                fast,
            ),
        )
    } else if summary.contains("spyware") {
        (
            AttackFamily::RemoteAccessTrojan,
            87.max(fast.overall_score),
            Some(heuristic_recognition(
                "heuristic-spyware",
                "Spyware / Surveillance Pattern",
                "spyware",
                &["spyware", "surveillance"],
                &["tcp", "http", "https"],
                &["heuristic"],
                "Telemetry resembled spyware or surveillance-oriented collection behavior.",
            )),
            explain_fast_path(
                "Behavior resembled spyware or surveillance-oriented collection.",
                fast,
            ),
        )
    } else if summary.contains("rat") || summary.contains("beacon") {
        (
            AttackFamily::Beaconing,
            84.max(fast.overall_score),
            Some(heuristic_recognition(
                "heuristic-rat-beacon",
                "Remote Access Beacon",
                "remote-access-beacon",
                &["rat", "beacon"],
                &["tcp", "http", "https", "dns"],
                &["heuristic"],
                "Behavior resembled recurring command-and-control beaconing.",
            )),
            explain_fast_path(
                "Behavior resembled recurring command-and-control beaconing.",
                fast,
            ),
        )
    } else if contains_any(
        &summary,
        &[
            "integrity_breach",
            "hash_mismatch",
            "unsigned_change",
            "syscall_table",
            "modified_binary",
        ],
    ) {
        (
            AttackFamily::IntegrityAttack,
            93.max(fast.overall_score),
            None,
            explain_fast_path(
                "Integrity telemetry indicated direct pressure on the Sentinel runtime.",
                fast,
            ),
        )
    } else {
        (
            AttackFamily::Unknown,
            40.max(fast.overall_score),
            None,
            explain_fast_path("Signal catalog did not find a strong family match.", fast),
        )
    };

    ThreatSignal {
        source_name: event.source.clone(),
        family,
        confidence,
        recognition,
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
            .saturating_add(
                ((matched_indicators.len() - identity.minimum_matches) as u8).saturating_mul(3),
            )
            .min(99);

        let detail = format!(
            "pattern_identity={} display_name={} category={} family={} sources={} protocols={} labels={} matched={} narrative={}",
            identity.name,
            identity.display_name,
            identity.category,
            identity.family.as_str(),
            identity.sources.join(","),
            identity.protocols.join(","),
            identity.labels.join(","),
            matched_indicators.join(","),
            identity.narrative
        );

        let pattern_match = PatternMatch {
            identity_name: identity.name,
            family: identity.family,
            recognition: ThreatRecognition {
                identity: identity.name.to_string(),
                display_name: identity.display_name.to_string(),
                category: identity.category.to_string(),
                labels: identity
                    .labels
                    .iter()
                    .map(|item| (*item).to_string())
                    .collect(),
                protocols: identity
                    .protocols
                    .iter()
                    .map(|item| (*item).to_string())
                    .collect(),
                sources: identity
                    .sources
                    .iter()
                    .map(|item| (*item).to_string())
                    .collect(),
                summary: identity.narrative.to_string(),
            },
            matched_indicators,
            confidence,
            detail,
        };

        if best_match.as_ref().map_or(true, |current: &PatternMatch| {
            pattern_match.confidence > current.confidence
        }) {
            best_match = Some(pattern_match);
        }
    }

    best_match
}

fn build_fast_path_features(event: &TelemetryEvent) -> FastPathFeatures {
    let summary = event.summary.to_ascii_lowercase();
    let mut features = FastPathFeatures::default();

    if contains_any(
        &summary,
        &[
            "scan",
            "recon",
            "probe",
            "fingerprint",
            "syn",
            "port_sweep",
            "nmap",
            "service_probe",
            "version_scan",
            "banner_grab",
        ],
    ) {
        features.scan_pressure = features.scan_pressure.saturating_add(65);
    }
    if contains_any(
        &summary,
        &[
            "masscan",
            "async_scan",
            "asynchronous_sweep",
            "stateless_syn",
            "wide_port_sweep",
            "pps_scan",
        ],
    ) {
        features.scan_pressure = features.scan_pressure.saturating_add(25);
        features.entropy_pressure = features.entropy_pressure.saturating_add(10);
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
            "sql_injection_attacker",
            "sql_injection_victim",
            "uri_sqli",
            "password_guessing",
            "ssh.login.failure",
            "ssh_auth_failed",
            "ssh_auth_successful",
            "ssl_heartbeat_attack",
            "ssl_heartbeat_attack_success",
            "heartbleed",
            "tls.invalid_heartbeat_message",
            "tls.overflow_heartbeat_message",
        ],
    ) {
        features.intrusion_pressure = features.intrusion_pressure.saturating_add(70);
    }
    if contains_any(
        &summary,
        &["burst_flood", "ddos", "flood", "pps_spike", "aisuru"],
    ) {
        features.ddos_pressure = features.ddos_pressure.saturating_add(80);
    }
    if contains_any(
        &summary,
        &["oauth", "identity", "token", "impossible-travel"],
    ) {
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

fn heuristic_recognition(
    identity: &str,
    display_name: &str,
    category: &str,
    labels: &[&str],
    protocols: &[&str],
    sources: &[&str],
    summary: &str,
) -> ThreatRecognition {
    ThreatRecognition {
        identity: identity.to_string(),
        display_name: display_name.to_string(),
        category: category.to_string(),
        labels: labels.iter().map(|item| (*item).to_string()).collect(),
        protocols: protocols.iter().map(|item| (*item).to_string()).collect(),
        sources: sources.iter().map(|item| (*item).to_string()).collect(),
        summary: summary.to_string(),
    }
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
        let names: Vec<_> = seed_pattern_identities()
            .into_iter()
            .map(|item| item.name)
            .collect();

        assert!(names.contains(&"snort3-malware-cnc"));
        assert!(names.contains(&"metasploit-reverse-http-transport"));
        assert!(names.contains(&"suricata-heartbeat-anomaly"));
        assert!(names.contains(&"research-high-speed-asynchronous-scan"));
        assert!(names.contains(&"research-service-fingerprint-scan"));
        assert!(names.contains(&"zeek-heartbleed-observer"));
        assert!(names.contains(&"zeek-ssh-password-guessing"));
        assert!(names.contains(&"zeek-http-uri-sqli"));
        assert!(names.contains(&"androrat-surveillance-suite"));
        assert!(names.contains(&"thefatrat-reverse-https-wrapper"));
    }

    #[test]
    fn identifies_metasploit_reverse_http_transport_patterns() {
        let matched = identify_pattern("meterpreter tlv http_transport uuid custom_headers")
            .expect("metasploit transport should match");

        assert_eq!(matched.identity_name, "metasploit-reverse-http-transport");
        assert_eq!(matched.family, AttackFamily::PayloadStager);
        assert!(matched
            .recognition
            .labels
            .contains(&"reverse_http".to_string()));
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

    #[test]
    fn identifies_androrat_surveillance_patterns() {
        let matched = identify_pattern("camerapreview readsms videorecorder locationmanager")
            .expect("androrat surveillance should match");

        assert_eq!(matched.identity_name, "androrat-surveillance-suite");
        assert!(matched.recognition.labels.contains(&"spyware".to_string()));
    }

    #[test]
    fn detects_thefatrat_reverse_https_wrapper() {
        let signal = detect_signal(&TelemetryEvent {
            kind: TelemetryKind::Flow,
            source: "payload-host".to_string(),
            summary: "backdoor_apk reverse_https apkembed.rb meterpreter".to_string(),
            health: HealthSnapshot::default(),
        });

        let recognition = signal.recognition.expect("recognition should exist");
        assert_eq!(signal.family, AttackFamily::PayloadStager);
        assert_eq!(recognition.display_name, "TheFatRat Reverse HTTPS Wrapper");
        assert!(recognition.labels.contains(&"reverse_https".to_string()));
    }

    #[test]
    fn recognizes_high_speed_asynchronous_scan_pressure() {
        let signal = detect_signal(&TelemetryEvent {
            kind: TelemetryKind::Packet,
            source: "198.51.100.22".to_string(),
            summary: "masscan async_scan stateless_syn wide_port_sweep pps_scan".to_string(),
            health: HealthSnapshot::default(),
        });

        let recognition = signal.recognition.expect("recognition should exist");
        assert_eq!(signal.family, AttackFamily::OffensiveScan);
        assert_eq!(
            recognition.display_name,
            "High-Speed Asynchronous Scan Pattern"
        );
        assert!(recognition.labels.contains(&"high_speed_scan".to_string()));
    }

    #[test]
    fn recognizes_service_fingerprint_scan_pressure() {
        let signal = detect_signal(&TelemetryEvent {
            kind: TelemetryKind::Packet,
            source: "198.51.100.29".to_string(),
            summary: "nmap service_probe version_scan banner_grab".to_string(),
            health: HealthSnapshot::default(),
        });

        let recognition = signal.recognition.expect("recognition should exist");
        assert_eq!(signal.family, AttackFamily::OffensiveScan);
        assert_eq!(recognition.display_name, "Service Fingerprint Scan Pattern");
        assert!(recognition
            .labels
            .contains(&"service_fingerprint".to_string()));
    }

    #[test]
    fn detects_zeek_ssh_password_guessing() {
        let signal = detect_signal(&TelemetryEvent {
            kind: TelemetryKind::Identity,
            source: "198.51.100.91".to_string(),
            summary: "password_guessing ssh.login.failure ssh_auth_failed".to_string(),
            health: HealthSnapshot::default(),
        });

        let recognition = signal.recognition.expect("recognition should exist");
        assert_eq!(signal.family, AttackFamily::IdentityAbuse);
        assert_eq!(
            recognition.display_name,
            "Zeek SSH Password Guessing Pattern"
        );
        assert!(recognition.labels.contains(&"ssh_bruteforce".to_string()));
    }

    #[test]
    fn detects_zeek_http_uri_sqli() {
        let signal = detect_signal(&TelemetryEvent {
            kind: TelemetryKind::Flow,
            source: "198.51.100.99".to_string(),
            summary: "sql_injection_attacker uri_sqli union select".to_string(),
            health: HealthSnapshot::default(),
        });

        let recognition = signal.recognition.expect("recognition should exist");
        assert_eq!(signal.family, AttackFamily::ExploitDelivery);
        assert_eq!(
            recognition.display_name,
            "Zeek HTTP URI SQL Injection Pattern"
        );
        assert!(recognition.labels.contains(&"uri_sqli".to_string()));
    }
}
