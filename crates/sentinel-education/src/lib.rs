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
                "It feeds classification and timing evidence into later decisions.",
            ],
            safety_contract: &[
                "Its defensive value comes from visibility, not harm.",
                "It must not become an uncontrolled interference mechanism.",
            ],
        },
        ScanTypeLesson {
            name: "KIS",
            classification: "timing-intelligence",
            harmless: true,
            summary: "KIS uses timing and jitter as additional intelligence signals for classifying suspicious behavior.",
            how_it_works: &[
                "It studies packet pacing, variance, and behavioral friction.",
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
            name: "SARS",
            classification: "adaptive-response-layer",
            harmless: false,
            summary: "SARS is the adaptive response layer that turns classification into bounded containment decisions.",
            how_it_works: &[
                "It consumes confidence, health, and context signals.",
                "It chooses staged containment actions instead of one blunt response.",
                "It gives the runtime a controlled way to escalate when needed.",
            ],
            safety_contract: &[
                "SARS is not a harmless scan type; it is a response system.",
                "Every action must remain bounded, explainable, and reversible where possible.",
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
    fn harmless_catalog_excludes_sars() {
        let names: Vec<_> = harmless_scan_types().into_iter().map(|item| item.name).collect();
        assert!(!names.contains(&"SARS"));
    }
}

