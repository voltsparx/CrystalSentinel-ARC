#![forbid(unsafe_code)]

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanTypeLesson {
    pub name: &'static str,
    pub classification: &'static str,
    pub harmless: bool,
    pub summary: &'static str,
    pub how_it_works: &'static [&'static str],
    pub safety_contract: &'static [&'static str],
}

pub fn learning_catalog() -> Vec<ScanTypeLesson> {
    vec![
        ScanTypeLesson {
            name: "TBNS",
            classification: "orchestration-model",
            harmless: true,
            summary: "Tri-Blue Network Scanning coordinates observation, timing intelligence, and defensive response into one loop.",
            how_it_works: &[
                "It combines Phantom-Scan, KIS, and SARS under one control flow.",
                "It treats threat handling as observe, classify, then contain.",
                "It gives operators one picture of how the system reacted.",
            ],
            safety_contract: &[
                "TBNS is a coordination model, not a payload or exploit engine.",
                "Its value is in classification and bounded containment.",
            ],
        },
        ScanTypeLesson {
            name: "Phantom-Scan",
            classification: "state-zero-observation",
            harmless: true,
            summary: "Phantom-Scan is the early observation layer that studies suspicious traffic before normal stack interaction becomes the whole story.",
            how_it_works: &[
                "It focuses on stealth observation and early signal collection.",
                "It gives the system a pre-response intelligence window.",
                "It can vary its observation rhythm inside bounded limits so the runtime does not expose one rigid cadence.",
                "It feeds classification and timing evidence into later decisions.",
            ],
            safety_contract: &[
                "Its defensive value comes from visibility, not harm.",
                "Any observation cadence variance must remain internally truth-tagged and health-bounded.",
                "It must not become an uncontrolled interference mechanism.",
            ],
        },
        ScanTypeLesson {
            name: "KIS",
            classification: "timing-intelligence",
            harmless: true,
            summary: "KIS measures timing friction and pressure so CrystalSentinel-CRA can understand how hard a connection or attacker is pushing against the environment.",
            how_it_works: &[
                "It studies packet pacing, variance, and behavioral friction.",
                "It helps estimate pressure on the path, device, or service under observation.",
                "It helps distinguish automation from ambient traffic.",
                "It enriches confidence scoring rather than acting alone.",
            ],
            safety_contract: &[
                "KIS is an intelligence amplifier, not a destructive action path.",
                "Timing data must remain advisory and bounded by safety policy.",
            ],
        },
        ScanTypeLesson {
            name: "IDF Scan",
            classification: "defensive-decoy-fog",
            harmless: true,
            summary: "IDF Scan releases inert synthetic fog to create controlled uncertainty and buy time for better classification.",
            how_it_works: &[
                "It emits inert, non-persistent decoy pressure.",
                "It creates a short-lived flare window for Phantom-Scan to observe reactions.",
                "It is internally tagged so the Sentinel does not confuse its own fog with a real threat.",
            ],
            safety_contract: &[
                "IDF Scan is defensive decoy traffic, not offensive deception.",
                "It must be inert, non-amplifying, and bounded by health and rate limits.",
                "It must never become self-noise or impact uninvolved systems.",
            ],
        },
        ScanTypeLesson {
            name: "Callback-Ping",
            classification: "reverse-probe-research",
            harmless: false,
            summary: "Callback-Ping is a reverse-probe research concept that studies how a suspicious origin reacts when the defender opens a tightly bounded callback window.",
            how_it_works: &[
                "It begins from an incoming suspicious probe and asks whether a controlled callback reveals more about the source behavior.",
                "It tries to distinguish ordinary stack behavior, scripted automation, and hardened silent-drop behavior from the reaction pattern.",
                "In the current framework it is treated as a teaching and planning concept, not as a live covert packet-emission engine.",
            ],
            safety_contract: &[
                "Callback-Ping is not a harmless default primitive and is not part of the active decoy runtime today.",
                "Any future implementation would need strict ownership boundaries, bounded rate and scope, and clear operator visibility.",
                "It must not become a stealth emitter, a covert off-stack action path, or an unreviewed packet crafting engine.",
            ],
        },
        ScanTypeLesson {
            name: "Recon Friction Veil",
            classification: "high-speed-recon-friction",
            harmless: true,
            summary: "Recon Friction Veil is a harmless decoy layer that makes high-speed scanners spend more time, retries, and confidence on low-value uncertainty.",
            how_it_works: &[
                "It adds bounded ambiguity around scanner-visible presence and timing.",
                "It is especially useful during mass-scan style pressure where fast tooling expects rigid answers.",
                "It works with Phantom-Scan and IDF windows to increase reconnaissance cost while keeping internal visibility clear.",
            ],
            safety_contract: &[
                "It must stay inert, internally truth-tagged, and health-bounded.",
                "It exists to raise reconnaissance cost and reduce hostile confidence, not to damage or weaponize traffic.",
            ],
        },
        ScanTypeLesson {
            name: "SARS",
            classification: "ambient-resonance-status-scan",
            harmless: true,
            summary: "SARS is the ambient network status monitor. It watches device and network ambience so spikes can reveal throttling, abnormal load, or hidden pressure in the environment.",
            how_it_works: &[
                "It tracks the baseline feel of the network and the devices behind it.",
                "It watches for resonance spikes, drag, or sudden ambient pressure changes.",
                "It helps CrystalSentinel-CRA tell when something is throttling or squeezing the network even before the cause is fully classified.",
            ],
            safety_contract: &[
                "SARS is a monitor, not an intervention engine.",
                "Its value is ambient visibility and early pressure awareness, not destructive action.",
            ],
        },
        ScanTypeLesson {
            name: "SHKE",
            classification: "escalation-model",
            harmless: true,
            summary: "Sovereign Hibernation and Escalation defines how the Sentinel sleeps, wakes, and increases defensive pressure over time.",
            how_it_works: &[
                "It starts passive, wakes on drift, and escalates only when evidence grows.",
                "It keeps the system quiet when the network is healthy.",
                "It turns aggressive behavior into a tiered decision instead of a constant stance.",
            ],
            safety_contract: &[
                "Escalation must be proportional and health-aware.",
                "The model exists to reduce unnecessary interference, not increase it.",
            ],
        },
    ]
}

pub fn harmless_scan_types() -> Vec<ScanTypeLesson> {
    learning_catalog()
        .into_iter()
        .filter(|lesson| lesson.harmless)
        .collect()
}

pub fn find_lesson(name: &str) -> Option<ScanTypeLesson> {
    learning_catalog()
        .into_iter()
        .find(|lesson| lesson.name.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::{find_lesson, harmless_scan_types};

    #[test]
    fn idf_is_marked_harmless() {
        let idf = find_lesson("idf scan").expect("idf lesson should exist");
        assert!(idf.harmless);
    }

    #[test]
    fn harmless_catalog_includes_sars() {
        let names: Vec<_> = harmless_scan_types()
            .into_iter()
            .map(|item| item.name)
            .collect();
        assert!(names.contains(&"SARS"));
    }

    #[test]
    fn phantom_lesson_mentions_bounded_variance() {
        let phantom = find_lesson("Phantom-Scan").expect("phantom lesson should exist");
        assert!(phantom
            .how_it_works
            .iter()
            .any(|item| item.contains("vary its observation rhythm")));
    }

    #[test]
    fn recon_friction_is_marked_harmless() {
        let lesson =
            find_lesson("Recon Friction Veil").expect("recon friction lesson should exist");
        assert!(lesson.harmless);
    }

    #[test]
    fn callback_ping_is_research_only() {
        let lesson = find_lesson("Callback-Ping").expect("callback lesson should exist");
        assert!(!lesson.harmless);
        assert!(lesson
            .safety_contract
            .iter()
            .any(|item| item.contains("not part of the active decoy runtime")));
    }
}
