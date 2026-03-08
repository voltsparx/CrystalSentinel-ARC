#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntelSourceKind {
    OffensiveFramework,
    SecuritySystem,
    InternalNote,
}

impl IntelSourceKind {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::OffensiveFramework => "offensive-framework",
            Self::SecuritySystem => "security-system",
            Self::InternalNote => "internal-note",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttackFamily {
    OffensiveScan,
    RemoteAccessTrojan,
    PayloadStager,
    Beaconing,
    DnsTunneling,
    DataExfiltration,
    IdentityAbuse,
    ApiScraping,
    ExploitDelivery,
    VolumetricFlood,
    IntegrityAttack,
    Unknown,
}

impl AttackFamily {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::OffensiveScan => "offensive-scan",
            Self::RemoteAccessTrojan => "remote-access-trojan",
            Self::PayloadStager => "payload-stager",
            Self::Beaconing => "beaconing",
            Self::DnsTunneling => "dns-tunneling",
            Self::DataExfiltration => "data-exfiltration",
            Self::IdentityAbuse => "identity-abuse",
            Self::ApiScraping => "api-scraping",
            Self::ExploitDelivery => "exploit-delivery",
            Self::VolumetricFlood => "volumetric-flood",
            Self::IntegrityAttack => "integrity-attack",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TelemetryKind {
    Packet,
    Flow,
    HostHealth,
    Identity,
    Integrity,
}

impl TelemetryKind {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Packet => "packet",
            Self::Flow => "flow",
            Self::HostHealth => "host-health",
            Self::Identity => "identity",
            Self::Integrity => "integrity",
        }
    }

    pub fn parse(input: &str) -> Result<Self, String> {
        match normalize_variant(input).as_str() {
            "packet" => Ok(Self::Packet),
            "flow" => Ok(Self::Flow),
            "host-health" => Ok(Self::HostHealth),
            "identity" => Ok(Self::Identity),
            "integrity" => Ok(Self::Integrity),
            other => Err(format!("unknown telemetry kind '{}'", other)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MitigationStage {
    Observe,
    Throttle,
    Contain,
    Isolate,
    OperatorApproval,
}

impl MitigationStage {
    pub const fn rank(self) -> u8 {
        match self {
            Self::Observe => 0,
            Self::Throttle => 1,
            Self::Contain => 2,
            Self::Isolate => 3,
            Self::OperatorApproval => 4,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Throttle => "throttle",
            Self::Contain => "contain",
            Self::Isolate => "isolate",
            Self::OperatorApproval => "operator-approval",
        }
    }

    pub const fn least_aggressive(self, other: Self) -> Self {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }

    pub fn parse(input: &str) -> Result<Self, String> {
        match normalize_variant(input).as_str() {
            "observe" => Ok(Self::Observe),
            "throttle" => Ok(Self::Throttle),
            "contain" => Ok(Self::Contain),
            "isolate" => Ok(Self::Isolate),
            "operator-approval" => Ok(Self::OperatorApproval),
            other => Err(format!("unknown mitigation stage '{}'", other)),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthSnapshot {
    #[serde(default)]
    pub cpu_load_pct: u8,
    #[serde(default)]
    pub memory_load_pct: u8,
    #[serde(default)]
    pub thermal_c: u8,
    #[serde(default)]
    pub passive_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreatRecognition {
    pub identity: String,
    pub display_name: String,
    pub category: String,
    pub labels: Vec<String>,
    pub protocols: Vec<String>,
    pub sources: Vec<String>,
    pub summary: String,
}

#[derive(Clone, Debug)]
pub struct ThreatSignal {
    pub source_name: String,
    pub family: AttackFamily,
    pub confidence: u8,
    pub recognition: Option<ThreatRecognition>,
    pub analysis_lanes: Vec<String>,
    pub detail: String,
}

#[derive(Clone, Debug)]
pub struct ThreatAssessment {
    pub signal: ThreatSignal,
    pub stage: MitigationStage,
    pub rationale: String,
}

#[derive(Clone, Debug)]
pub struct IntelSource {
    pub name: &'static str,
    pub kind: IntelSourceKind,
    pub summary: &'static str,
}

#[derive(Clone, Debug)]
pub struct SourceInventory {
    pub offensive_frameworks: Vec<&'static str>,
    pub security_systems: Vec<&'static str>,
}

impl SourceInventory {
    pub fn current() -> Self {
        Self {
            offensive_frameworks: vec![
                "reference-mobile-rat",
                "reference-staged-transport",
                "reference-payload-wrapper",
            ],
            security_systems: vec![
                "reference-signature-engine",
                "reference-classification-engine",
                "reference-stateful-network-monitor",
            ],
        }
    }
}

fn normalize_variant(input: &str) -> String {
    input
        .trim()
        .to_ascii_lowercase()
        .replace('_', "-")
        .replace(' ', "-")
}
