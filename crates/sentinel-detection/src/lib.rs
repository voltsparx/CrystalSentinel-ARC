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
            name: "reference-mobile-rat",
            kind: IntelSourceKind::OffensiveFramework,
            summary: "Mobile remote-access reference patterns and handheld control flows.",
        },
        IntelSource {
            name: "reference-staged-transport",
            kind: IntelSourceKind::OffensiveFramework,
            summary: "Stage loading and staged transport reference behaviors.",
        },
        IntelSource {
            name: "reference-java-meterpreter",
            kind: IntelSourceKind::OffensiveFramework,
            summary: "Java meterpreter loader and stdapi extension reference behaviors.",
        },
        IntelSource {
            name: "reference-android-meterpreter",
            kind: IntelSourceKind::OffensiveFramework,
            summary: "Android meterpreter command registration and handheld collection reference behaviors.",
        },
        IntelSource {
            name: "reference-payload-wrapper",
            kind: IntelSourceKind::OffensiveFramework,
            summary: "Payload packaging and delivery-chain reference behaviors.",
        },
        IntelSource {
            name: "reference-signature-engine",
            kind: IntelSourceKind::SecuritySystem,
            summary: "Signature and rule-based detection reference coverage.",
        },
        IntelSource {
            name: "reference-classification-engine",
            kind: IntelSourceKind::SecuritySystem,
            summary: "Classification-driven protocol anomaly and network monitoring coverage.",
        },
        IntelSource {
            name: "reference-stateful-network-monitor",
            kind: IntelSourceKind::SecuritySystem,
            summary: "Stateful network analysis, protocol-aware scripting, and notice/intel style coverage.",
        },
        IntelSource {
            name: "reference-mesh-heartbeat",
            kind: IntelSourceKind::InternalNote,
            summary: "Defensive mesh heartbeat, guardian pulse, and peer-trust drift reference behaviors.",
        },
    ]
}

pub fn seed_framework_catalog() -> Vec<FrameworkFingerprint> {
    vec![
        FrameworkFingerprint {
            name: "reference-mobile-rat",
            family: AttackFamily::RemoteAccessTrojan,
            indicators: &[
                "android control channel",
                "device command fan-out",
                "mobile beaconing",
            ],
            preferred_stage: MitigationStage::Contain,
        },
        FrameworkFingerprint {
            name: "reference-staged-transport",
            family: AttackFamily::PayloadStager,
            indicators: &[
                "stage_loader",
                "reflective payload",
                "post-exploitation transport",
            ],
            preferred_stage: MitigationStage::Contain,
        },
        FrameworkFingerprint {
            name: "reference-java-meterpreter",
            family: AttackFamily::PayloadStager,
            indicators: &[
                "meterpreter jar",
                "stdapi extension jar",
                "memory buffer loader",
            ],
            preferred_stage: MitigationStage::Contain,
        },
        FrameworkFingerprint {
            name: "reference-android-meterpreter",
            family: AttackFamily::RemoteAccessTrojan,
            indicators: &[
                "android meterpreter",
                "webcam audio record",
                "screenshot command fan-out",
            ],
            preferred_stage: MitigationStage::Contain,
        },
        FrameworkFingerprint {
            name: "reference-payload-wrapper",
            family: AttackFamily::ExploitDelivery,
            indicators: &["payload_builder", "delivery wrapper", "backdoor packaging"],
            preferred_stage: MitigationStage::Throttle,
        },
    ]
}

pub fn seed_pattern_identities() -> Vec<PatternIdentity> {
    vec![
        PatternIdentity {
            name: "reference-shellcode-detect",
            display_name: "Reference Shellcode Delivery Pattern",
            family: AttackFamily::ExploitDelivery,
            category: "shellcode-detect",
            sources: &["reference-signature-engine"],
            protocols: &["tcp", "http", "smtp", "imap", "pop3"],
            labels: &["shellcode", "stager"],
            indicators: &["shellcode", "decoder", "executable_code", "stager"],
            minimum_matches: 2,
            confidence: 90,
            narrative: "Derived from reference shellcode-detect coverage for executable delivery artifacts.",
        },
        PatternIdentity {
            name: "reference-trojan-activity",
            display_name: "Reference Trojan Activity Pattern",
            family: AttackFamily::RemoteAccessTrojan,
            category: "trojan-activity",
            sources: &["reference-signature-engine"],
            protocols: &["tcp", "http", "https", "dns"],
            labels: &["trojan", "rat"],
            indicators: &["trojan", "rat", "backdoor", "remote_control", "command_channel"],
            minimum_matches: 2,
            confidence: 88,
            narrative: "Derived from reference trojan-activity coverage for remote-control behavior.",
        },
        PatternIdentity {
            name: "reference-malware-cnc",
            display_name: "Reference Malware Command Channel Pattern",
            family: AttackFamily::Beaconing,
            category: "malware-cnc",
            sources: &["reference-signature-engine"],
            protocols: &["dns", "http", "https", "tcp"],
            labels: &["beacon", "command-and-control"],
            indicators: &["malware_cnc", "command_and_control", "beacon", "polling", "uuid"],
            minimum_matches: 2,
            confidence: 89,
            narrative: "Derived from reference malware command-channel coverage for beaconing and command traffic.",
        },
        PatternIdentity {
            name: "reference-client-side-exploit",
            display_name: "Reference Client-Side Exploit Pattern",
            family: AttackFamily::ExploitDelivery,
            category: "client-side-exploit",
            sources: &["reference-signature-engine"],
            protocols: &["http", "https"],
            labels: &["exploit", "document-delivery"],
            indicators: &["client_side_exploit", "document_exploit", "browser_exploit", "decompress_pdf", "decompress_zip"],
            minimum_matches: 2,
            confidence: 86,
            narrative: "Derived from reference client-side exploit coverage for document and browser attack surfaces.",
        },
        PatternIdentity {
            name: "reference-sensitive-data-egress",
            display_name: "Reference Sensitive Data Egress Pattern",
            family: AttackFamily::DataExfiltration,
            category: "sensitive-data-egress",
            sources: &["reference-signature-engine"],
            protocols: &["http", "smtp", "ftp-data", "imap", "pop3"],
            labels: &["data-exfiltration", "sensitive-data"],
            indicators: &["credit_card", "us_social", "email", "us_phone", "http_client_body", "file_data"],
            minimum_matches: 2,
            confidence: 93,
            narrative: "Derived from reference sensitive-data coverage for outbound leakage over application protocols.",
        },
        PatternIdentity {
            name: "reference-network-scan",
            display_name: "Reference Network Scan Pattern",
            family: AttackFamily::OffensiveScan,
            category: "network-scan",
            sources: &["reference-classification-engine"],
            protocols: &["tcp", "udp", "icmp"],
            labels: &["scan", "reconnaissance"],
            indicators: &["network_scan", "attempted_recon", "port_sweep", "syn_scan"],
            minimum_matches: 2,
            confidence: 87,
            narrative: "Derived from reference classification coverage for network-scan and attempted-recon activity.",
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
            name: "reference-command-and-control",
            display_name: "Reference Command-and-Control Pattern",
            family: AttackFamily::Beaconing,
            category: "command-and-control",
            sources: &["reference-classification-engine"],
            protocols: &["dns", "http", "https", "tcp"],
            labels: &["beacon", "command-and-control"],
            indicators: &["command_and_control", "domain_c2", "beacon", "malware_cnc"],
            minimum_matches: 2,
            confidence: 91,
            narrative: "Derived from reference classification coverage for command-and-control and domain-c2 activity.",
        },
        PatternIdentity {
            name: "reference-web-application-attack",
            display_name: "Reference Web Application Attack Pattern",
            family: AttackFamily::ExploitDelivery,
            category: "web-application-attack",
            sources: &["reference-classification-engine"],
            protocols: &["http", "https"],
            labels: &["exploit", "web-application-attack"],
            indicators: &["web_application_attack", "exploit_kit", "http_uri_anomaly", "client_side_exploit"],
            minimum_matches: 2,
            confidence: 89,
            narrative: "Derived from reference classification coverage for exploit-kit and web-application attack behavior.",
        },
        PatternIdentity {
            name: "reference-heartbeat-anomaly",
            display_name: "Reference TLS Heartbeat Exploit Pattern",
            family: AttackFamily::ExploitDelivery,
            category: "protocol-command-decode",
            sources: &["reference-classification-engine"],
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
            narrative: "Derived from reference TLS heartbeat anomaly rules that flag possible heartbeat exploit attempts.",
        },
        PatternIdentity {
            name: "reference-credential-theft",
            display_name: "Reference Credential Abuse Pattern",
            family: AttackFamily::IdentityAbuse,
            category: "credential-theft",
            sources: &["reference-classification-engine"],
            protocols: &["http", "https", "smtp", "imap"],
            labels: &["credential-theft", "password-spray"],
            indicators: &["credential_theft", "default_login", "suspicious_login", "password_spray"],
            minimum_matches: 2,
            confidence: 90,
            narrative: "Derived from reference classification coverage for credential theft, suspicious login, and default login attempts.",
        },
        PatternIdentity {
            name: "reference-stateful-heartbeat-observer",
            display_name: "Stateful Heartbeat Observer Pattern",
            family: AttackFamily::ExploitDelivery,
            category: "stateful-heartbeat-notice",
            sources: &["reference-stateful-network-monitor"],
            protocols: &["tls", "https"],
            labels: &["exploit", "heartbleed", "stateful_notice"],
            indicators: &[
                "ssl_heartbeat_attack",
                "ssl_heartbeat_attack_success",
                "ssl_heartbeat_odd_length",
                "ssl_heartbeat_many_requests",
                "heartbleed",
            ],
            minimum_matches: 1,
            confidence: 93,
            narrative: "Derived from a local stateful heartbeat policy that raises notices for heartbeat attacks, odd-length requests, and likely exploit success.",
        },
        PatternIdentity {
            name: "mesh-heartbeat-guardian-drift",
            display_name: "Mesh Heartbeat Guardian Drift Pattern",
            family: AttackFamily::IntegrityAttack,
            category: "mesh-heartbeat-guardian",
            sources: &["reference-mesh-heartbeat"],
            protocols: &["mesh", "heartbeat", "gossip"],
            labels: &["mesh", "heartbeat", "peer_trust", "guardian"],
            indicators: &[
                "mesh_heartbeat_missing",
                "mesh_heartbeat_malformed",
                "guardian_pulse_invalid",
                "peer_trust_drift",
                "mesh_gossip_tamper",
            ],
            minimum_matches: 2,
            confidence: 95,
            narrative: "Recognizes compromised or drifting guardian heartbeats in a defensive mesh so peer trust can be reduced without collapsing the wider environment.",
        },
        PatternIdentity {
            name: "reference-stateful-ssh-password-guessing",
            display_name: "Stateful SSH Password Guessing Pattern",
            family: AttackFamily::IdentityAbuse,
            category: "stateful-ssh-bruteforce",
            sources: &["reference-stateful-network-monitor"],
            protocols: &["ssh", "tcp"],
            labels: &["credential-theft", "password-spray", "ssh_bruteforce", "stateful_notice"],
            indicators: &[
                "password_guessing",
                "ssh.login.failure",
                "ssh_auth_failed",
                "ssh_auth_successful",
                "successful_login",
            ],
            minimum_matches: 2,
            confidence: 91,
            narrative: "Derived from a local stateful SSH password-guessing policy that tracks failed logins and surfaces password-guessing notices and successful-login intel events.",
        },
        PatternIdentity {
            name: "reference-stateful-http-uri-sqli",
            display_name: "Stateful HTTP URI Injection Pattern",
            family: AttackFamily::ExploitDelivery,
            category: "stateful-http-sqli",
            sources: &["reference-stateful-network-monitor"],
            protocols: &["http", "https"],
            labels: &["exploit", "sql_injection", "uri_sqli", "stateful_notice"],
            indicators: &[
                "sql_injection_attacker",
                "sql_injection_victim",
                "uri_sqli",
                "match_sql_injection_uri",
                "union select",
            ],
            minimum_matches: 2,
            confidence: 92,
            narrative: "Derived from a local stateful HTTP injection policy that tags suspicious URIs, counts attacker and victim behavior, and raises injection notices.",
        },
        PatternIdentity {
            name: "reference-stateful-intel-indicator-observation",
            display_name: "Stateful Intel Indicator Observation",
            family: AttackFamily::Beaconing,
            category: "stateful-intel-seen",
            sources: &["reference-stateful-network-monitor"],
            protocols: &["dns", "http", "https"],
            labels: &["intel", "indicator_observation", "stateful_intel"],
            indicators: &[
                "intel::seen",
                "http::in_url",
                "dns::in_request",
                "indicator_type=intel::url",
                "indicator_type=intel::domain",
            ],
            minimum_matches: 2,
            confidence: 88,
            narrative: "Derived from local stateful intel-seen scripts that forward observed URLs and DNS queries into an intelligence framework for later matching and notice handling.",
        },
        PatternIdentity {
            name: "staged-reverse-http-transport",
            display_name: "Reverse HTTP Transport Pattern",
            family: AttackFamily::PayloadStager,
            category: "staged-reverse-http",
            sources: &["reference-staged-transport"],
            protocols: &["http"],
            labels: &["stager", "reverse_http", "staged_transport"],
            indicators: &["meterpreter", "tlv", "http_transport", "uuid", "custom_headers", "user_agent"],
            minimum_matches: 3,
            confidence: 91,
            narrative: "Reflects staged reverse HTTP transport traits such as TLV-style packing, UUID tagging, and custom header handling.",
        },
        PatternIdentity {
            name: "staged-reverse-https-transport",
            display_name: "Reverse HTTPS Transport Pattern",
            family: AttackFamily::PayloadStager,
            category: "staged-reverse-https",
            sources: &["reference-staged-transport"],
            protocols: &["https"],
            labels: &["stager", "reverse_https", "staged_transport"],
            indicators: &["meterpreter", "tlv", "http_transport", "cert_hash", "uuid", "custom_headers"],
            minimum_matches: 3,
            confidence: 90,
            narrative: "Reflects staged reverse HTTPS transport traits such as TLV-style packing, UUID tagging, and certificate pinning hints.",
        },
        PatternIdentity {
            name: "staged-reverse-tcp-transport",
            display_name: "Reverse TCP Transport Pattern",
            family: AttackFamily::PayloadStager,
            category: "staged-reverse-tcp",
            sources: &["reference-staged-transport"],
            protocols: &["tcp"],
            labels: &["stager", "reverse_tcp", "staged_transport"],
            indicators: &["meterpreter", "tlv", "tcp_transport", "socket", "uuid", "stage_loader"],
            minimum_matches: 3,
            confidence: 90,
            narrative: "Reflects staged reverse TCP transport traits such as TLV-style packing, socket handoff, and staged session setup.",
        },
        PatternIdentity {
            name: "staged-migration-pattern",
            display_name: "Stage Migration Pattern",
            family: AttackFamily::PayloadStager,
            category: "staged-migration-control",
            sources: &["reference-staged-transport"],
            protocols: &["tcp", "http", "https"],
            labels: &["stager", "migration", "staged_transport"],
            indicators: &["stage_loader", "migrate_payload", "pivot_stage_data", "reflective_payload"],
            minimum_matches: 2,
            confidence: 92,
            narrative: "Reflects staged payload and migration markers found in reference transport and pivot code.",
        },
        PatternIdentity {
            name: "java-meterpreter-memory-loader",
            display_name: "Java Meterpreter Memory Loader Pattern",
            family: AttackFamily::PayloadStager,
            category: "java-meterpreter-loader",
            sources: &["reference-java-meterpreter"],
            protocols: &["java", "tcp", "http", "https"],
            labels: &["stager", "java_meterpreter", "memory_loader"],
            indicators: &[
                "meterpreter.jar",
                "ext_server_stdapi.jar",
                "memorybufferurlconnection",
                "memorybufferurlstreamhandler",
                "javapayload.stage.meterpreter",
            ],
            minimum_matches: 2,
            confidence: 92,
            narrative: "Reflects Java meterpreter staging and in-memory loader traits such as bundled meterpreter jars, stdapi extension jars, and memory-buffer stream handlers.",
        },
        PatternIdentity {
            name: "android-meterpreter-command-suite",
            display_name: "Android Meterpreter Command Suite Pattern",
            family: AttackFamily::RemoteAccessTrojan,
            category: "android-meterpreter-control",
            sources: &["reference-android-meterpreter"],
            protocols: &["android", "tcp", "http", "https"],
            labels: &["rat", "android", "meterpreter", "surveillance"],
            indicators: &[
                "androidmeterpreter",
                "android_channel_open",
                "stdapi_ui_desktop_screenshot",
                "stdapi_webcam_audio_record_android",
                "stdapi_sys_process_execute",
            ],
            minimum_matches: 2,
            confidence: 94,
            narrative: "Reflects Android meterpreter command registration for screenshot capture, webcam or audio collection, and remote process control.",
        },
        PatternIdentity {
            name: "reflective-loader-pattern",
            display_name: "Reflective Loader Pattern",
            family: AttackFamily::PayloadStager,
            category: "reflective-loader",
            sources: &["reference-staged-transport", "research"],
            protocols: &["tcp", "http", "https"],
            labels: &["stager", "reflective_loader", "memory_loader"],
            indicators: &[
                "reflective_payload",
                "reflective_loader",
                "memory_loader",
                "stage_loader",
                "pivot_stage_data",
            ],
            minimum_matches: 2,
            confidence: 92,
            narrative: "Recognizes reflective or memory-oriented loader traits that often appear during staged intrusion setup.",
        },
        PatternIdentity {
            name: "interactive-reverse-shell-pattern",
            display_name: "Interactive Reverse Shell Pattern",
            family: AttackFamily::RemoteAccessTrojan,
            category: "interactive-reverse-shell",
            sources: &["reference-staged-transport", "research"],
            protocols: &["tcp", "http", "https"],
            labels: &["reverse_shell", "interactive_shell", "command_channel"],
            indicators: &[
                "reverse_shell",
                "shell_reverse_tcp",
                "interactive_shell",
                "session_spawn",
                "cmd_channel",
            ],
            minimum_matches: 2,
            confidence: 93,
            narrative: "Recognizes interactive reverse-shell traits that indicate an active remote command channel instead of a harmless probe.",
        },
        PatternIdentity {
            name: "mobile-control-channel-pattern",
            display_name: "Mobile Control Channel Pattern",
            family: AttackFamily::RemoteAccessTrojan,
            category: "mobile-control-channel",
            sources: &["reference-mobile-rat"],
            protocols: &["tcp", "android"],
            labels: &["rat", "android", "control-channel"],
            indicators: &["reverseshell2", "tcpconnection", "mainservice", "jobscheduler", "broadcastreciever"],
            minimum_matches: 2,
            confidence: 92,
            narrative: "Reflects mobile control-channel and persistence markers found in local handheld remote-access reference material.",
        },
        PatternIdentity {
            name: "mobile-surveillance-suite",
            display_name: "Mobile Surveillance Pattern",
            family: AttackFamily::RemoteAccessTrojan,
            category: "mobile-surveillance",
            sources: &["reference-mobile-rat"],
            protocols: &["tcp", "android"],
            labels: &["spyware", "rat", "surveillance"],
            indicators: &["camerapreview", "audiomanager", "locationmanager", "videorecorder", "readsms", "readcalllogs", "newshell"],
            minimum_matches: 2,
            confidence: 94,
            narrative: "Reflects mobile surveillance and collection capabilities exposed in local handheld remote-access reference material.",
        },
        PatternIdentity {
            name: "payload-wrapper-reverse-tcp",
            display_name: "Payload Wrapper Reverse TCP Pattern",
            family: AttackFamily::PayloadStager,
            category: "delivery-wrapper",
            sources: &["reference-payload-wrapper"],
            protocols: &["tcp"],
            labels: &["stager", "reverse_tcp", "delivery-wrapper"],
            indicators: &["reverse_tcp", "backdoor_apk", "power.py", "apkembed.rb"],
            minimum_matches: 2,
            confidence: 89,
            narrative: "Reflects payload-wrapper behavior around reverse TCP payload generation and packaging.",
        },
        PatternIdentity {
            name: "payload-wrapper-reverse-http",
            display_name: "Payload Wrapper Reverse HTTP Pattern",
            family: AttackFamily::PayloadStager,
            category: "delivery-wrapper",
            sources: &["reference-payload-wrapper"],
            protocols: &["http"],
            labels: &["stager", "reverse_http", "delivery-wrapper"],
            indicators: &["reverse_http", "backdoor_apk", "power.py", "apkembed.rb"],
            minimum_matches: 2,
            confidence: 89,
            narrative: "Reflects payload-wrapper behavior around reverse HTTP payload generation and packaging.",
        },
        PatternIdentity {
            name: "payload-wrapper-reverse-https",
            display_name: "Payload Wrapper Reverse HTTPS Pattern",
            family: AttackFamily::PayloadStager,
            category: "delivery-wrapper",
            sources: &["reference-payload-wrapper"],
            protocols: &["https"],
            labels: &["stager", "reverse_https", "delivery-wrapper"],
            indicators: &["reverse_https", "backdoor_apk", "power.py", "apkembed.rb"],
            minimum_matches: 2,
            confidence: 90,
            narrative: "Reflects payload-wrapper behavior around reverse HTTPS payload generation and packaging.",
        },
        PatternIdentity {
            name: "android-backdoor-wrapper-obfuscation",
            display_name: "Android Backdoor Wrapper Obfuscation Pattern",
            family: AttackFamily::ExploitDelivery,
            category: "android-backdoor-wrapper",
            sources: &["reference-payload-wrapper"],
            protocols: &["android", "tcp", "http", "https"],
            labels: &["android", "backdoor_wrapper", "obfuscation"],
            indicators: &[
                "backdoor_apk",
                "apkembed.rb",
                "stringobfuscator",
                "android/meterpreter/reverse_https",
                "msfvenom",
            ],
            minimum_matches: 2,
            confidence: 91,
            narrative: "Reflects Android payload-wrapper behavior that combines APK backdooring, string obfuscation, and Android meterpreter packaging.",
        },
    ]
}

pub fn detect_signal(event: &TelemetryEvent) -> ThreatSignal {
    let summary = event.summary.to_ascii_lowercase();
    let fast = fast_assess_event(event);
    let pattern_matches = identify_patterns(&summary);

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
    } else if let Some(pattern) = pattern_matches.first() {
        (
            pattern.family.clone(),
            fused_pattern_confidence(&pattern_matches, fast.overall_score),
            Some(pattern.recognition.clone()),
            explain_fast_path(&fused_pattern_detail(&pattern_matches), fast),
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
    } else if contains_any(
        &summary,
        &[
            "reverse_shell",
            "shell_reverse_tcp",
            "interactive_shell",
            "session_spawn",
            "cmd_channel",
        ],
    ) {
        (
            AttackFamily::RemoteAccessTrojan,
            93.max(fast.overall_score),
            Some(heuristic_recognition(
                "heuristic-interactive-reverse-shell",
                "Interactive Reverse Shell Pattern",
                "interactive-reverse-shell",
                &["reverse_shell", "interactive_shell", "command_channel"],
                &["tcp", "http", "https"],
                &["heuristic"],
                "Recognized an active reverse-shell or interactive command-channel pattern in the telemetry summary.",
            )),
            explain_fast_path(
                "Telemetry resembled an active reverse-shell or interactive command channel.",
                fast,
            ),
        )
    } else if contains_any(
        &summary,
        &[
            "reflective_payload",
            "reflective_loader",
            "memory_loader",
            "pivot_stage_data",
        ],
    ) {
        (
            AttackFamily::PayloadStager,
            92.max(fast.overall_score),
            Some(heuristic_recognition(
                "heuristic-reflective-loader",
                "Reflective Loader Pattern",
                "reflective-loader",
                &["stager", "reflective_loader", "memory_loader"],
                &["tcp", "http", "https"],
                &["heuristic"],
                "Recognized reflective or memory-loader traits in the telemetry summary.",
            )),
            explain_fast_path(
                "Telemetry resembled a reflective or memory-resident loader chain.",
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
    let analysis_lanes =
        derive_signal_analysis_lanes(&summary, recognition.as_ref(), &family, fast);

    ThreatSignal {
        source_name: event.source.clone(),
        family,
        confidence,
        recognition,
        analysis_lanes,
        detail,
    }
}

pub fn fast_assess_event(event: &TelemetryEvent) -> FastPathDecision {
    fast_path_assess(build_fast_path_features(event))
}

pub fn identify_pattern(summary: &str) -> Option<PatternMatch> {
    identify_patterns(summary).into_iter().next()
}

pub fn identify_patterns(summary: &str) -> Vec<PatternMatch> {
    let mut matches = Vec::new();

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

        matches.push(pattern_match);
    }

    matches.sort_by(|left, right| right.confidence.cmp(&left.confidence));
    matches
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
            "interactive_shell",
            "session_spawn",
            "cmd_channel",
            "reflective_loader",
            "memory_loader",
            "reflective_payload",
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

fn derive_signal_analysis_lanes(
    summary: &str,
    recognition: Option<&ThreatRecognition>,
    family: &AttackFamily,
    fast: FastPathDecision,
) -> Vec<String> {
    let mut lanes = std::collections::BTreeSet::new();

    if !matches!(fast.kind, FastThreatKind::Benign) {
        lanes.insert("asm-fast-path".to_string());
    }

    if let Some(recognition) = recognition {
        lanes.insert("pattern-identity".to_string());
        for source in &recognition.sources {
            if let Some(lane) = map_source_to_lane(source) {
                lanes.insert(lane.to_string());
            }
        }
    }

    if matches!(
        family,
        AttackFamily::OffensiveScan
            | AttackFamily::ExploitDelivery
            | AttackFamily::PayloadStager
            | AttackFamily::RemoteAccessTrojan
            | AttackFamily::Beaconing
            | AttackFamily::DnsTunneling
            | AttackFamily::DataExfiltration
            | AttackFamily::IdentityAbuse
            | AttackFamily::ApiScraping
    ) {
        lanes.insert("heuristic".to_string());
    }

    if contains_any(
        summary,
        &[
            "scan",
            "recon",
            "probe",
            "fingerprint",
            "banner_grab",
            "service_probe",
            "version_scan",
        ],
    ) {
        lanes.insert("recon-model".to_string());
    }

    if contains_any(
        summary,
        &[
            "stage_loader",
            "payload",
            "reverse_shell",
            "interactive_shell",
            "reflective_loader",
            "memory_loader",
            "cmd_channel",
            "session_spawn",
            "sql_injection_attacker",
            "sql_injection_victim",
        ],
    ) {
        lanes.insert("intrusion-model".to_string());
    }

    if contains_any(
        summary,
        &[
            "meterpreter",
            "tlv",
            "uuid",
            "custom_headers",
            "cert_hash",
            "backdoor_apk",
            "apkembed.rb",
            "reverseshell2",
            "mainservice",
        ],
    ) {
        lanes.insert("transport-intelligence".to_string());
    }

    if matches!(family, AttackFamily::IntegrityAttack) {
        lanes.insert("self-integrity-candidate".to_string());
    }

    lanes.into_iter().collect()
}

fn map_source_to_lane(source: &str) -> Option<&'static str> {
    match source {
        "reference-signature-engine" => Some("signature-style"),
        "reference-classification-engine" => Some("classification-style"),
        "reference-stateful-network-monitor" => Some("stateful-analysis"),
        "reference-staged-transport" => Some("transport-intelligence"),
        "reference-mobile-rat" => Some("behavioral-intelligence"),
        "reference-payload-wrapper" => Some("delivery-intelligence"),
        "heuristic" => Some("heuristic"),
        "research" => Some("behavioral-research"),
        _ => None,
    }
}

fn fused_pattern_confidence(matches: &[PatternMatch], fast_score: u8) -> u8 {
    let Some(top) = matches.first() else {
        return fast_score;
    };

    let supporting_hits = matches.len().saturating_sub(1) as u8;
    let unique_sources = matches
        .iter()
        .flat_map(|pattern| pattern.recognition.sources.iter())
        .collect::<std::collections::BTreeSet<_>>()
        .len() as u8;

    top.confidence
        .max(fast_score)
        .saturating_add(supporting_hits.saturating_mul(2))
        .saturating_add(unique_sources.saturating_sub(1))
        .min(99)
}

fn fused_pattern_detail(matches: &[PatternMatch]) -> String {
    let Some(primary) = matches.first() else {
        return "pattern_fusion=none".to_string();
    };

    let support = matches
        .iter()
        .map(|pattern| pattern.identity_name)
        .collect::<Vec<_>>()
        .join(",");
    let labels = matches
        .iter()
        .flat_map(|pattern| pattern.recognition.labels.iter())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",");
    let sources = matches
        .iter()
        .flat_map(|pattern| pattern.recognition.sources.iter())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",");

    format!(
        "{} support_patterns={} fused_labels={} fused_sources={} support_count={}",
        primary.detail,
        support,
        labels,
        sources,
        matches.len()
    )
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
    use super::{detect_signal, identify_pattern, identify_patterns, seed_pattern_identities};
    use sentinel_common::{AttackFamily, HealthSnapshot, TelemetryKind};
    use sentinel_telemetry::TelemetryEvent;

    #[test]
    fn exposes_reference_pattern_identities() {
        let names: Vec<_> = seed_pattern_identities()
            .into_iter()
            .map(|item| item.name)
            .collect();

        assert!(names.contains(&"reference-malware-cnc"));
        assert!(names.contains(&"staged-reverse-http-transport"));
        assert!(names.contains(&"reference-heartbeat-anomaly"));
        assert!(names.contains(&"research-high-speed-asynchronous-scan"));
        assert!(names.contains(&"research-service-fingerprint-scan"));
        assert!(names.contains(&"reference-stateful-heartbeat-observer"));
        assert!(names.contains(&"mesh-heartbeat-guardian-drift"));
        assert!(names.contains(&"reference-stateful-ssh-password-guessing"));
        assert!(names.contains(&"reference-stateful-http-uri-sqli"));
        assert!(names.contains(&"mobile-surveillance-suite"));
        assert!(names.contains(&"java-meterpreter-memory-loader"));
        assert!(names.contains(&"android-meterpreter-command-suite"));
        assert!(names.contains(&"android-backdoor-wrapper-obfuscation"));
        assert!(names.contains(&"payload-wrapper-reverse-https"));
        assert!(names.contains(&"reflective-loader-pattern"));
        assert!(names.contains(&"interactive-reverse-shell-pattern"));
    }

    #[test]
    fn identifies_reference_reverse_http_transport_patterns() {
        let matched = identify_pattern("meterpreter tlv http_transport uuid custom_headers")
            .expect("reverse http transport should match");

        assert_eq!(matched.identity_name, "staged-reverse-http-transport");
        assert_eq!(matched.family, AttackFamily::PayloadStager);
        assert!(matched
            .recognition
            .labels
            .contains(&"reverse_http".to_string()));
    }

    #[test]
    fn detects_reference_sensitive_data_egress() {
        let signal = detect_signal(&TelemetryEvent {
            kind: TelemetryKind::Flow,
            source: "workload-17".to_string(),
            summary: "credit_card http_client_body file_data".to_string(),
            health: HealthSnapshot::default(),
        });

        assert_eq!(signal.family, AttackFamily::DataExfiltration);
        assert!(signal.detail.contains("reference-sensitive-data-egress"));
    }

    #[test]
    fn identifies_reference_heartbeat_exploit() {
        let signal = detect_signal(&TelemetryEvent {
            kind: TelemetryKind::Packet,
            source: "198.51.100.61".to_string(),
            summary: "tls.invalid_heartbeat_message heartbleed".to_string(),
            health: HealthSnapshot::default(),
        });

        assert_eq!(signal.family, AttackFamily::ExploitDelivery);
        assert!(signal.detail.contains("reference-heartbeat-anomaly"));
    }

    #[test]
    fn detects_mesh_heartbeat_guardian_drift() {
        let signal = detect_signal(&TelemetryEvent {
            kind: TelemetryKind::Integrity,
            source: "guardian-node-02".to_string(),
            summary: "mesh_heartbeat_malformed guardian_pulse_invalid peer_trust_drift"
                .to_string(),
            health: HealthSnapshot::default(),
        });

        let recognition = signal.recognition.expect("recognition should exist");
        assert_eq!(signal.family, AttackFamily::IntegrityAttack);
        assert_eq!(
            recognition.display_name,
            "Mesh Heartbeat Guardian Drift Pattern"
        );
        assert!(recognition.labels.contains(&"mesh".to_string()));
    }

    #[test]
    fn identifies_mobile_surveillance_patterns() {
        let matched = identify_pattern("camerapreview readsms videorecorder locationmanager")
            .expect("mobile surveillance should match");

        assert_eq!(matched.identity_name, "mobile-surveillance-suite");
        assert!(matched.recognition.labels.contains(&"spyware".to_string()));
    }

    #[test]
    fn identifies_java_meterpreter_loader_patterns() {
        let matched = identify_pattern(
            "meterpreter.jar ext_server_stdapi.jar memorybufferurlconnection javapayload.stage.meterpreter",
        )
        .expect("java meterpreter loader should match");

        assert_eq!(matched.identity_name, "java-meterpreter-memory-loader");
        assert_eq!(matched.family, AttackFamily::PayloadStager);
        assert!(matched
            .recognition
            .labels
            .contains(&"java_meterpreter".to_string()));
    }

    #[test]
    fn identifies_android_meterpreter_command_suite() {
        let matched = identify_pattern(
            "androidmeterpreter stdapi_ui_desktop_screenshot stdapi_webcam_audio_record_android android_channel_open",
        )
        .expect("android meterpreter command suite should match");

        assert_eq!(matched.identity_name, "android-meterpreter-command-suite");
        assert_eq!(matched.family, AttackFamily::RemoteAccessTrojan);
        assert!(matched
            .recognition
            .labels
            .contains(&"meterpreter".to_string()));
    }

    #[test]
    fn detects_payload_wrapper_reverse_https() {
        let signal = detect_signal(&TelemetryEvent {
            kind: TelemetryKind::Flow,
            source: "payload-host".to_string(),
            summary: "backdoor_apk reverse_https apkembed.rb meterpreter".to_string(),
            health: HealthSnapshot::default(),
        });

        let recognition = signal.recognition.expect("recognition should exist");
        assert_eq!(signal.family, AttackFamily::PayloadStager);
        assert_eq!(
            recognition.display_name,
            "Payload Wrapper Reverse HTTPS Pattern"
        );
        assert!(recognition.labels.contains(&"reverse_https".to_string()));
    }

    #[test]
    fn detects_android_backdoor_wrapper_obfuscation() {
        let signal = detect_signal(&TelemetryEvent {
            kind: TelemetryKind::Flow,
            source: "android-wrapper".to_string(),
            summary:
                "backdoor_apk apkembed.rb stringobfuscator android/meterpreter/reverse_https"
                    .to_string(),
            health: HealthSnapshot::default(),
        });

        let recognition = signal.recognition.expect("recognition should exist");
        assert_eq!(signal.family, AttackFamily::ExploitDelivery);
        assert_eq!(
            recognition.display_name,
            "Android Backdoor Wrapper Obfuscation Pattern"
        );
        assert!(recognition
            .labels
            .contains(&"backdoor_wrapper".to_string()));
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
    fn detects_stateful_ssh_password_guessing() {
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
            "Stateful SSH Password Guessing Pattern"
        );
        assert!(recognition.labels.contains(&"ssh_bruteforce".to_string()));
    }

    #[test]
    fn detects_stateful_http_uri_sqli() {
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
            "Stateful HTTP URI Injection Pattern"
        );
        assert!(recognition.labels.contains(&"uri_sqli".to_string()));
    }

    #[test]
    fn detects_reflective_loader_chain() {
        let signal = detect_signal(&TelemetryEvent {
            kind: TelemetryKind::Flow,
            source: "198.51.100.53".to_string(),
            summary: "reflective_loader memory_loader pivot_stage_data".to_string(),
            health: HealthSnapshot::default(),
        });

        let recognition = signal.recognition.expect("recognition should exist");
        assert_eq!(signal.family, AttackFamily::PayloadStager);
        assert_eq!(recognition.display_name, "Reflective Loader Pattern");
        assert!(recognition
            .labels
            .contains(&"reflective_loader".to_string()));
    }

    #[test]
    fn detects_interactive_reverse_shell_channel() {
        let signal = detect_signal(&TelemetryEvent {
            kind: TelemetryKind::Flow,
            source: "198.51.100.54".to_string(),
            summary: "reverse_shell interactive_shell session_spawn cmd_channel".to_string(),
            health: HealthSnapshot::default(),
        });

        let recognition = signal.recognition.expect("recognition should exist");
        assert_eq!(signal.family, AttackFamily::RemoteAccessTrojan);
        assert_eq!(
            recognition.display_name,
            "Interactive Reverse Shell Pattern"
        );
        assert!(recognition.labels.contains(&"reverse_shell".to_string()));
    }

    #[test]
    fn fuses_multiple_exploit_signals_into_one_detection_story() {
        let signal = detect_signal(&TelemetryEvent {
            kind: TelemetryKind::Flow,
            source: "198.51.100.55".to_string(),
            summary: "meterpreter tlv http_transport uuid custom_headers reflective_loader pivot_stage_data".to_string(),
            health: HealthSnapshot::default(),
        });

        let matches = identify_patterns(
            "meterpreter tlv http_transport uuid custom_headers reflective_loader pivot_stage_data",
        );

        assert!(matches.len() >= 2);
        assert_eq!(signal.family, AttackFamily::PayloadStager);
        assert!(signal.confidence >= 95);
        assert!(signal.detail.contains("support_patterns="));
        assert!(signal.detail.contains("fused_sources="));
    }
}
