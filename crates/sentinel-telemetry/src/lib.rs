#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sentinel_common::{HealthSnapshot, TelemetryKind};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct TelemetryEvent {
    pub kind: TelemetryKind,
    pub source: String,
    pub summary: String,
    #[serde(default)]
    pub health: HealthSnapshot,
}

#[derive(Debug)]
pub enum TelemetryError {
    Io {
        context: String,
        source: io::Error,
    },
    Parse {
        line: usize,
        message: String,
    },
}

impl TelemetryError {
    fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    fn parse(line: usize, message: impl Into<String>) -> Self {
        Self::Parse {
            line,
            message: message.into(),
        }
    }
}

impl Display for TelemetryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { context, source } => write!(f, "{context}: {source}"),
            Self::Parse { line, message } => {
                write!(f, "telemetry parse error on line {line}: {message}")
            }
        }
    }
}

impl Error for TelemetryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse { .. } => None,
        }
    }
}

pub trait TelemetryCollector {
    fn name(&self) -> &'static str;
    fn collect(&self) -> Result<Vec<TelemetryEvent>, TelemetryError>;
}

#[derive(Default)]
pub struct SampleTelemetryCollector;

impl TelemetryCollector for SampleTelemetryCollector {
    fn name(&self) -> &'static str {
        "sample"
    }

    fn collect(&self) -> Result<Vec<TelemetryEvent>, TelemetryError> {
        Ok(sample_events())
    }
}

pub struct JsonlFileCollector {
    path: PathBuf,
}

impl JsonlFileCollector {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl TelemetryCollector for JsonlFileCollector {
    fn name(&self) -> &'static str {
        "jsonl-file"
    }

    fn collect(&self) -> Result<Vec<TelemetryEvent>, TelemetryError> {
        collect_jsonl_file(&self.path)
    }
}

#[derive(Default)]
pub struct StdinJsonlCollector;

impl TelemetryCollector for StdinJsonlCollector {
    fn name(&self) -> &'static str {
        "stdin-jsonl"
    }

    fn collect(&self) -> Result<Vec<TelemetryEvent>, TelemetryError> {
        let stdin = io::stdin();
        collect_jsonl_reader(stdin.lock())
    }
}

pub fn collect_jsonl_file(path: &Path) -> Result<Vec<TelemetryEvent>, TelemetryError> {
    let file = File::open(path)
        .map_err(|source| TelemetryError::io(format!("failed to open {}", path.display()), source))?;
    collect_jsonl_reader(BufReader::new(file))
}

pub fn collect_jsonl_reader<R: BufRead>(reader: R) -> Result<Vec<TelemetryEvent>, TelemetryError> {
    let mut events = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        let line = line.map_err(|source| {
            TelemetryError::io(format!("failed to read telemetry line {line_number}"), source)
        })?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let event = serde_json::from_str::<TelemetryEvent>(trimmed)
            .map_err(|err| TelemetryError::parse(line_number, err.to_string()))?;
        events.push(event);
    }

    Ok(events)
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::PathBuf;

    use super::{collect_jsonl_reader, sample_events, JsonlFileCollector, TelemetryCollector};

    #[test]
    fn sample_collector_returns_seeded_events() {
        let events = sample_events();
        assert!(!events.is_empty());
    }

    #[test]
    fn parses_jsonl_stream_and_skips_comments() {
        let input = Cursor::new(
            "# sentinel stream\n\
            {\"kind\":\"packet\",\"source\":\"203.0.113.9\",\"summary\":\"syn probe recon\",\"health\":{\"cpu_load_pct\":33}}\n\
            \n\
            {\"kind\":\"integrity\",\"source\":\"sentinel-self\",\"summary\":\"hash_mismatch runtime tamper\"}\n",
        );

        let events = collect_jsonl_reader(input).expect("jsonl stream should parse");

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].source, "203.0.113.9");
        assert_eq!(events[0].health.cpu_load_pct, 33);
        assert_eq!(events[1].kind.as_str(), "integrity");
        assert_eq!(events[1].health, Default::default());
    }

    #[test]
    fn reports_line_number_for_invalid_jsonl() {
        let input = Cursor::new(
            "{\"kind\":\"packet\",\"source\":\"203.0.113.9\",\"summary\":\"syn probe recon\"}\n\
            {\"kind\":\"unknown-kind\",\"source\":\"203.0.113.10\",\"summary\":\"bad\"}\n",
        );

        let err = collect_jsonl_reader(input).expect_err("invalid kind should fail");

        let rendered = err.to_string();
        assert!(rendered.contains("telemetry parse error on line 2"));
        assert!(rendered.contains("unknown-kind"));
    }

    #[test]
    fn file_collector_reads_jsonl_fixture() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("testdata")
            .join("telemetry")
            .join("sample-stream.jsonl");
        let collector = JsonlFileCollector::new(fixture);

        let events = collector.collect().expect("fixture should load");

        assert_eq!(events.len(), 3);
        assert_eq!(events[0].kind.as_str(), "packet");
        assert_eq!(events[2].kind.as_str(), "integrity");
    }
}
