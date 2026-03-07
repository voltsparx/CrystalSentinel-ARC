#![forbid(unsafe_code)]

use sentinel_common::{HealthSnapshot, TelemetryKind};

#[derive(Clone, Debug)]
pub struct TelemetryEvent {
    pub kind: TelemetryKind,
    pub source: String,
    pub summary: String,
    pub health: HealthSnapshot,
}

pub trait TelemetryCollector {
    fn name(&self) -> &'static str;
    fn collect(&self) -> Vec<TelemetryEvent>;
}

pub fn sample_events() -> Vec<TelemetryEvent> {
    vec![
        TelemetryEvent {
            kind: TelemetryKind::Packet,
            source: "10.0.0.12".to_string(),
            summary: "stage_loader tls callback".to_string(),
            health: HealthSnapshot {
                cpu_load_pct: 42,
                memory_load_pct: 36,
                thermal_c: 63,
                passive_only: false,
            },
        },
        TelemetryEvent {
            kind: TelemetryKind::Identity,
            source: "oauth-client-7".to_string(),
            summary: "oauth_token_abuse impossible-travel".to_string(),
            health: HealthSnapshot {
                cpu_load_pct: 51,
                memory_load_pct: 44,
                thermal_c: 60,
                passive_only: false,
            },
        },
        TelemetryEvent {
            kind: TelemetryKind::Flow,
            source: "198.51.100.44".to_string(),
            summary: "high_entropy dns_tunnel burst_flood".to_string(),
            health: HealthSnapshot {
                cpu_load_pct: 88,
                memory_load_pct: 71,
                thermal_c: 74,
                passive_only: false,
            },
        },
        TelemetryEvent {
            kind: TelemetryKind::Packet,
            source: "203.0.113.88".to_string(),
            summary: "syn probe recon fingerprint".to_string(),
            health: HealthSnapshot {
                cpu_load_pct: 32,
                memory_load_pct: 28,
                thermal_c: 58,
                passive_only: false,
            },
        },
        TelemetryEvent {
            kind: TelemetryKind::Integrity,
            source: "sentinel-self".to_string(),
            summary: "integrity_breach ptrace tamper".to_string(),
            health: HealthSnapshot {
                cpu_load_pct: 67,
                memory_load_pct: 54,
                thermal_c: 61,
                passive_only: true,
            },
        },
        TelemetryEvent {
            kind: TelemetryKind::Packet,
            source: "198.51.100.60".to_string(),
            summary: "meterpreter tlv http_transport uuid custom_headers".to_string(),
            health: HealthSnapshot {
                cpu_load_pct: 47,
                memory_load_pct: 39,
                thermal_c: 59,
                passive_only: false,
            },
        },
        TelemetryEvent {
            kind: TelemetryKind::Flow,
            source: "workload-17".to_string(),
            summary: "credit_card http_client_body file_data".to_string(),
            health: HealthSnapshot {
                cpu_load_pct: 41,
                memory_load_pct: 38,
                thermal_c: 55,
                passive_only: false,
            },
        },
        TelemetryEvent {
            kind: TelemetryKind::Packet,
            source: "198.51.100.61".to_string(),
            summary: "tls.invalid_heartbeat_message heartbleed".to_string(),
            health: HealthSnapshot {
                cpu_load_pct: 44,
                memory_load_pct: 37,
                thermal_c: 56,
                passive_only: false,
            },
        },
    ]
}
