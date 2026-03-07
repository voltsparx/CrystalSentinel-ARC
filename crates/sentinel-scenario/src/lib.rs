#![forbid(unsafe_code)]

use sentinel_common::AttackFamily;

#[derive(Clone, Debug)]
pub struct ScenarioDefinition {
    pub name: &'static str,
    pub protected_asset: &'static str,
    pub expected_family: AttackFamily,
    pub success_criteria: &'static str,
}

pub fn seed_scenarios() -> Vec<ScenarioDefinition> {
    vec![
        ScenarioDefinition {
            name: "stage-loader-detection",
            protected_asset: "edge-service",
            expected_family: AttackFamily::PayloadStager,
            success_criteria: "Detect staging behavior before full session establishment.",
        },
        ScenarioDefinition {
            name: "identity-abuse-containment",
            protected_asset: "auth-api",
            expected_family: AttackFamily::IdentityAbuse,
            success_criteria:
                "Contain impossible-travel or token abuse without blocking valid users.",
        },
        ScenarioDefinition {
            name: "dns-tunnel-escalation",
            protected_asset: "recursive-resolver",
            expected_family: AttackFamily::DnsTunneling,
            success_criteria: "Detect high-entropy DNS patterns and move to safe containment.",
        },
    ]
}
