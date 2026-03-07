#![forbid(unsafe_code)]

use sentinel_common::{AttackFamily, HealthSnapshot, ThreatSignal};
use sentinel_config::{LaunchProfile, RuntimeConfig};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecoyPrimitive {
    AmbientMist,
    IdfWindow,
    SpotMimicry,
    ReconFrictionVeil,
    CadenceRandomizer,
    PhantomRhythmRandomizer,
}

impl DecoyPrimitive {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AmbientMist => "ambient-mist",
            Self::IdfWindow => "idf-window",
            Self::SpotMimicry => "spot-mimicry",
            Self::ReconFrictionVeil => "recon-friction-veil",
            Self::CadenceRandomizer => "cadence-randomizer",
            Self::PhantomRhythmRandomizer => "phantom-rhythm-randomizer",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecoyIdentity {
    pub key: &'static str,
    pub display_name: &'static str,
    pub classification: &'static str,
    pub harmless: bool,
    pub summary: &'static str,
    pub visible_effect: &'static str,
    pub internal_truth: &'static str,
    pub safety_contract: &'static [&'static str],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecoyIntensity {
    Minimal,
    Gentle,
    Focused,
}

impl DecoyIntensity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Gentle => "gentle",
            Self::Focused => "focused",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhantomEvidenceGoal {
    ScanFingerprint,
    PressureMapping,
    StageFingerprint,
    UnknownTriage,
}

impl PhantomEvidenceGoal {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ScanFingerprint => "scan-fingerprint",
            Self::PressureMapping => "pressure-mapping",
            Self::StageFingerprint => "stage-fingerprint",
            Self::UnknownTriage => "unknown-triage",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhantomObservationPlan {
    pub cadence_ms: u32,
    pub jitter_ms: u32,
    pub phase_offset_ms: u32,
    pub burst_slots: u8,
    pub decision_window_ms: u16,
    pub sample_budget: u8,
    pub evidence_goal: PhantomEvidenceGoal,
    pub requires_sars_snapshot: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecoyPlan {
    pub profile: LaunchProfile,
    pub intensity: DecoyIntensity,
    pub cadence_ms: u32,
    pub jitter_ms: u32,
    pub ghost_slots: u16,
    pub persona_variants: u8,
    pub truth_tagging: bool,
    pub quiet_reporter: bool,
    pub phantom_observation: Option<PhantomObservationPlan>,
    pub primitives: Vec<DecoyPrimitive>,
    pub narrative: String,
}

pub struct DecoyGovernor;

impl DecoyGovernor {
    pub fn plan(
        config: &RuntimeConfig,
        signal: &ThreatSignal,
        health: &HealthSnapshot,
    ) -> Option<DecoyPlan> {
        if !config.allow_decoys || config.passive_only || health.passive_only {
            return None;
        }

        if matches!(
            &signal.family,
            AttackFamily::VolumetricFlood | AttackFamily::IntegrityAttack
        ) {
            return None;
        }

        let mut primitives = primitives_for(signal);
        if primitives.is_empty() {
            return None;
        }

        let intensity = capped_intensity(config.launch_profile, signal, health);
        let seed = stable_seed(&[
            config.node_name.as_str(),
            signal.source_name.as_str(),
            signal.family.as_str(),
            signal.detail.as_str(),
            config.launch_profile.as_str(),
        ]);

        let cadence_ms = cadence_for(config.launch_profile, intensity, seed);
        let jitter_ms = bounded(seed.rotate_left(11), 4, 32);
        let mut ghost_slots = bounded(seed.rotate_left(23), 2, 16) as u16;
        let persona_variants = bounded(seed.rotate_left(31), 2, 7) as u8;
        let phantom_observation = phantom_observation_for(signal, &primitives, intensity, seed);

        if matches!(config.launch_profile, LaunchProfile::Protector) {
            ghost_slots = ghost_slots.min(6);
        }

        if matches!(intensity, DecoyIntensity::Minimal) {
            primitives.retain(|primitive| !matches!(primitive, DecoyPrimitive::SpotMimicry));
            ghost_slots = ghost_slots.min(3);
        }

        let narrative = format!(
            "decoy profile={} intensity={} cadence_ms={} jitter_ms={} ghost_slots={} persona_variants={} truth_tagging=true quiet_reporter={} phantom={} primitives={}",
            config.launch_profile.as_str(),
            intensity.as_str(),
            cadence_ms,
            jitter_ms,
            ghost_slots,
            persona_variants,
            config.quiet_reporter,
            phantom_observation
                .as_ref()
                .map(|plan| {
                    format!(
                        "cadence_ms:{} jitter_ms:{} phase_offset_ms:{} burst_slots:{} decision_window_ms:{} sample_budget:{} goal:{} sars_snapshot:{}",
                        plan.cadence_ms,
                        plan.jitter_ms,
                        plan.phase_offset_ms,
                        plan.burst_slots,
                        plan.decision_window_ms,
                        plan.sample_budget,
                        plan.evidence_goal.as_str(),
                        plan.requires_sars_snapshot
                    )
                })
                .unwrap_or_else(|| "disabled".to_string()),
            primitives
                .iter()
                .map(|primitive| primitive.as_str())
                .collect::<Vec<_>>()
                .join(",")
        );

        Some(DecoyPlan {
            profile: config.launch_profile,
            intensity,
            cadence_ms,
            jitter_ms,
            ghost_slots,
            persona_variants,
            truth_tagging: true,
            quiet_reporter: config.quiet_reporter,
            phantom_observation,
            primitives,
            narrative,
        })
    }
}

pub fn decoy_identity_catalog() -> Vec<DecoyIdentity> {
    vec![
        DecoyIdentity {
            key: "ambient-mist",
            display_name: "Ambient Mist",
            classification: "background-decoy-cloud",
            harmless: true,
            summary: "A low-pressure background veil of inert decoys that makes reconnaissance less reliable.",
            visible_effect: "A scanner sees extra low-confidence presence and timing drift around the defended boundary.",
            internal_truth: "Sentinel truth-tags every mist pulse and excludes it from threat misclassification.",
            safety_contract: &[
                "Ambient Mist must stay inert and non-amplifying.",
                "It must back off when host or network health degrades.",
            ],
        },
        DecoyIdentity {
            key: "idf-window",
            display_name: "IDF Window",
            classification: "attention-decoy-window",
            harmless: true,
            summary: "A short-lived inert flare that buys a classification window for Phantom observation.",
            visible_effect: "A suspicious source sees a brief burst of misleading interest and timing noise.",
            internal_truth: "Sentinel marks the flare as internal fog and uses the reaction window to collect real behavior.",
            safety_contract: &[
                "IDF windows must be bounded in duration and rate.",
                "They must not become a standing flood or blind Sentinel telemetry.",
            ],
        },
        DecoyIdentity {
            key: "spot-mimicry",
            display_name: "Spot Mimicry",
            classification: "topology-deception",
            harmless: true,
            summary: "A controlled false-presence layer that makes hostile observers build the wrong network map.",
            visible_effect: "An attacker sees believable but low-value network spots or service hints.",
            internal_truth: "Sentinel keeps an exact internal map and knows every mimicry artifact it emitted.",
            safety_contract: &[
                "Spot Mimicry must remain inside the defender's control boundary.",
                "It must not expose real vulnerable surfaces or confuse operators about real assets.",
            ],
        },
        DecoyIdentity {
            key: "recon-friction-veil",
            display_name: "Recon Friction Veil",
            classification: "high-speed-recon-friction",
            harmless: true,
            summary: "A harmless decoy modifier that makes high-speed reconnaissance spend more retries, time, and confidence before it can trust what it sees.",
            visible_effect: "Automated scan tooling sees less stable presence, low-confidence targets, and extra ambiguity around the defended edge.",
            internal_truth: "Sentinel keeps exact provenance, truth tags, and timing records so the same veil never confuses the defender.",
            safety_contract: &[
                "Recon Friction Veil must remain inert, bounded, and non-amplifying.",
                "It exists to increase reconnaissance cost and uncertainty, not to damage tools or external systems.",
            ],
        },
        DecoyIdentity {
            key: "cadence-randomizer",
            display_name: "Cadence Randomizer",
            classification: "safe-timing-variance",
            harmless: true,
            summary: "A safe randomization layer that varies decoy timing and personality within bounded limits.",
            visible_effect: "Automated tooling sees a less stable timing model and loses confidence.",
            internal_truth: "Sentinel keeps deterministic internal provenance even while the outside sees variance.",
            safety_contract: &[
                "Randomization must stay within health and service-continuity limits.",
                "It exists to reduce hostile certainty, not to create denial-of-service conditions.",
            ],
        },
        DecoyIdentity {
            key: "phantom-rhythm-randomizer",
            display_name: "Phantom Rhythm Randomizer",
            classification: "phantom-observation-variance",
            harmless: true,
            summary: "A bounded observation scheduler that keeps Phantom-Scan from exposing a rigid cadence.",
            visible_effect: "Suspicious sources cannot rely on one fixed observation rhythm while the defender keeps clear internal timing.",
            internal_truth: "Sentinel records exact observation cadence, jitter, and phase offset for every Phantom window.",
            safety_contract: &[
                "Phantom rhythm variance must stay within the observation window and never become traffic amplification.",
                "It exists to avoid predictable sampling, not to hide evidence from operators.",
            ],
        },
    ]
}

pub fn find_decoy_identity(key: &str) -> Option<DecoyIdentity> {
    decoy_identity_catalog().into_iter().find(|identity| {
        identity.key.eq_ignore_ascii_case(key) || identity.display_name.eq_ignore_ascii_case(key)
    })
}

fn primitives_for(signal: &ThreatSignal) -> Vec<DecoyPrimitive> {
    match &signal.family {
        AttackFamily::OffensiveScan => vec![
            DecoyPrimitive::AmbientMist,
            DecoyPrimitive::IdfWindow,
            DecoyPrimitive::ReconFrictionVeil,
            DecoyPrimitive::CadenceRandomizer,
            DecoyPrimitive::PhantomRhythmRandomizer,
        ],
        AttackFamily::PayloadStager
        | AttackFamily::ExploitDelivery
        | AttackFamily::Beaconing
        | AttackFamily::RemoteAccessTrojan => vec![
            DecoyPrimitive::AmbientMist,
            DecoyPrimitive::IdfWindow,
            DecoyPrimitive::SpotMimicry,
            DecoyPrimitive::CadenceRandomizer,
            DecoyPrimitive::PhantomRhythmRandomizer,
        ],
        AttackFamily::DnsTunneling | AttackFamily::ApiScraping => vec![
            DecoyPrimitive::AmbientMist,
            DecoyPrimitive::CadenceRandomizer,
        ],
        AttackFamily::Unknown => {
            let mut primitives = vec![
                DecoyPrimitive::AmbientMist,
                DecoyPrimitive::CadenceRandomizer,
            ];

            if signal.confidence >= 60 {
                primitives.push(DecoyPrimitive::IdfWindow);
                primitives.push(DecoyPrimitive::PhantomRhythmRandomizer);
            }

            if signal.detail.contains("fast_path.kind=offensive-scan") {
                primitives.push(DecoyPrimitive::ReconFrictionVeil);
            }

            primitives
        }
        _ => Vec::new(),
    }
}

fn capped_intensity(
    profile: LaunchProfile,
    signal: &ThreatSignal,
    health: &HealthSnapshot,
) -> DecoyIntensity {
    if health.cpu_load_pct >= 80 || health.memory_load_pct >= 80 || health.thermal_c >= 82 {
        return DecoyIntensity::Minimal;
    }

    match profile {
        LaunchProfile::Protector => {
            if signal.confidence >= 90 {
                DecoyIntensity::Gentle
            } else {
                DecoyIntensity::Minimal
            }
        }
        LaunchProfile::Architect => {
            if signal.confidence >= 80 {
                DecoyIntensity::Focused
            } else {
                DecoyIntensity::Gentle
            }
        }
    }
}

fn cadence_for(profile: LaunchProfile, intensity: DecoyIntensity, seed: u64) -> u32 {
    match (profile, intensity) {
        (LaunchProfile::Protector, DecoyIntensity::Minimal) => bounded(seed, 900, 1800),
        (LaunchProfile::Protector, DecoyIntensity::Gentle) => bounded(seed, 500, 1200),
        (LaunchProfile::Protector, DecoyIntensity::Focused) => bounded(seed, 350, 900),
        (LaunchProfile::Architect, DecoyIntensity::Minimal) => bounded(seed, 700, 1400),
        (LaunchProfile::Architect, DecoyIntensity::Gentle) => bounded(seed, 250, 800),
        (LaunchProfile::Architect, DecoyIntensity::Focused) => bounded(seed, 120, 450),
    }
}

fn phantom_observation_for(
    signal: &ThreatSignal,
    primitives: &[DecoyPrimitive],
    intensity: DecoyIntensity,
    seed: u64,
) -> Option<PhantomObservationPlan> {
    if !primitives
        .iter()
        .any(|primitive| matches!(primitive, DecoyPrimitive::PhantomRhythmRandomizer))
    {
        return None;
    }

    let (
        cadence_min,
        cadence_max,
        burst_min,
        burst_max,
        window_min,
        window_max,
        sample_min,
        sample_max,
    ) = match intensity {
        DecoyIntensity::Minimal => (120, 260, 1, 2, 180, 320, 2, 3),
        DecoyIntensity::Gentle => (80, 180, 2, 3, 140, 260, 3, 5),
        DecoyIntensity::Focused => (40, 120, 3, 5, 110, 220, 4, 6),
    };

    let evidence_goal = match &signal.family {
        AttackFamily::OffensiveScan => PhantomEvidenceGoal::ScanFingerprint,
        AttackFamily::PayloadStager
        | AttackFamily::ExploitDelivery
        | AttackFamily::Beaconing
        | AttackFamily::RemoteAccessTrojan => PhantomEvidenceGoal::StageFingerprint,
        AttackFamily::Unknown => PhantomEvidenceGoal::UnknownTriage,
        _ => PhantomEvidenceGoal::PressureMapping,
    };

    let decision_window_ms = match evidence_goal {
        PhantomEvidenceGoal::UnknownTriage => {
            bounded(seed.rotate_left(41), window_min + 40, window_max + 90)
        }
        _ => bounded(seed.rotate_left(41), window_min, window_max),
    };

    let sample_budget = match evidence_goal {
        PhantomEvidenceGoal::UnknownTriage => {
            bounded(seed.rotate_left(47), sample_min + 1, sample_max + 1)
        }
        _ => bounded(seed.rotate_left(47), sample_min, sample_max),
    };

    Some(PhantomObservationPlan {
        cadence_ms: bounded(seed.rotate_left(7), cadence_min, cadence_max),
        jitter_ms: bounded(seed.rotate_left(17), 3, 24),
        phase_offset_ms: bounded(seed.rotate_left(27), 1, 48),
        burst_slots: bounded(seed.rotate_left(37), burst_min, burst_max) as u8,
        decision_window_ms: decision_window_ms as u16,
        sample_budget: sample_budget as u8,
        evidence_goal,
        requires_sars_snapshot: matches!(
            &signal.family,
            AttackFamily::OffensiveScan | AttackFamily::Unknown | AttackFamily::ApiScraping
        ),
    })
}

fn bounded(seed: u64, min: u32, max: u32) -> u32 {
    if min >= max {
        return min;
    }
    min + (seed % u64::from(max - min + 1)) as u32
}

fn stable_seed(parts: &[&str]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for part in parts {
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::{
        decoy_identity_catalog, find_decoy_identity, DecoyGovernor, DecoyIntensity, DecoyPrimitive,
        PhantomEvidenceGoal,
    };
    use sentinel_common::{AttackFamily, HealthSnapshot, ThreatSignal};
    use sentinel_config::{LaunchProfile, RuntimeConfig};

    fn base_signal() -> ThreatSignal {
        ThreatSignal {
            source_name: "203.0.113.88".to_string(),
            family: AttackFamily::OffensiveScan,
            confidence: 84,
            recognition: None,
            detail: "syn probe recon fingerprint".to_string(),
        }
    }

    #[test]
    fn protector_profile_stays_gentle() {
        let config = RuntimeConfig::default();
        let plan = DecoyGovernor::plan(&config, &base_signal(), &HealthSnapshot::default())
            .expect("plan should exist");

        assert_eq!(plan.profile, LaunchProfile::Protector);
        assert!(matches!(
            plan.intensity,
            DecoyIntensity::Minimal | DecoyIntensity::Gentle
        ));
        assert!(plan.primitives.contains(&DecoyPrimitive::IdfWindow));
        assert!(plan
            .primitives
            .contains(&DecoyPrimitive::PhantomRhythmRandomizer));
        assert!(plan.phantom_observation.is_some());
        assert_eq!(
            plan.phantom_observation
                .as_ref()
                .expect("phantom observation should exist")
                .evidence_goal,
            PhantomEvidenceGoal::ScanFingerprint
        );
    }

    #[test]
    fn architect_profile_can_enable_spot_mimicry() {
        let config = RuntimeConfig {
            launch_profile: LaunchProfile::Architect,
            ..RuntimeConfig::default()
        };
        let signal = ThreatSignal {
            family: AttackFamily::ExploitDelivery,
            ..base_signal()
        };
        let plan = DecoyGovernor::plan(&config, &signal, &HealthSnapshot::default())
            .expect("plan should exist");

        assert!(plan.primitives.contains(&DecoyPrimitive::SpotMimicry));
    }

    #[test]
    fn high_load_disables_heavier_decoys() {
        let config = RuntimeConfig {
            launch_profile: LaunchProfile::Architect,
            ..RuntimeConfig::default()
        };
        let signal = ThreatSignal {
            family: AttackFamily::ExploitDelivery,
            ..base_signal()
        };
        let plan = DecoyGovernor::plan(
            &config,
            &signal,
            &HealthSnapshot {
                cpu_load_pct: 85,
                ..HealthSnapshot::default()
            },
        )
        .expect("plan should exist");

        assert_eq!(plan.intensity, DecoyIntensity::Minimal);
        assert!(!plan.primitives.contains(&DecoyPrimitive::SpotMimicry));
        assert_eq!(
            plan.phantom_observation
                .as_ref()
                .expect("phantom observation should exist")
                .burst_slots,
            2
        );
    }

    #[test]
    fn unknown_pressure_can_open_phantom_evidence_ladder() {
        let config = RuntimeConfig::default();
        let signal = ThreatSignal {
            family: AttackFamily::Unknown,
            confidence: 72,
            detail: "Signal catalog did not find a strong family match. fast_path.kind=offensive-scan stage=throttle score=72 scan=72 intrusion=0 integrity=0 ddos=0 tick=7".to_string(),
            ..base_signal()
        };

        let plan = DecoyGovernor::plan(&config, &signal, &HealthSnapshot::default())
            .expect("plan should exist");

        assert!(plan.primitives.contains(&DecoyPrimitive::IdfWindow));
        assert!(plan
            .primitives
            .contains(&DecoyPrimitive::PhantomRhythmRandomizer));
        assert!(plan.primitives.contains(&DecoyPrimitive::ReconFrictionVeil));

        let phantom = plan
            .phantom_observation
            .as_ref()
            .expect("phantom observation should exist");
        assert_eq!(phantom.evidence_goal, PhantomEvidenceGoal::UnknownTriage);
        assert!(phantom.requires_sars_snapshot);
        assert!(phantom.decision_window_ms >= 220);
    }

    #[test]
    fn exposes_decoy_identity_catalog() {
        let keys: Vec<_> = decoy_identity_catalog()
            .into_iter()
            .map(|identity| identity.key)
            .collect();

        assert!(keys.contains(&"ambient-mist"));
        assert!(keys.contains(&"recon-friction-veil"));
        assert!(keys.contains(&"spot-mimicry"));
        assert!(keys.contains(&"phantom-rhythm-randomizer"));
    }

    #[test]
    fn finds_idf_identity() {
        let identity = find_decoy_identity("idf-window").expect("idf identity should exist");
        assert!(identity.harmless);
    }
}
