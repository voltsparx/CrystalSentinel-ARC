#![forbid(unsafe_code)]

use sentinel_shadow_vault::{RestorationPlan, ShadowVault};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegrityVerdict {
    DriftDetected,
    RestorableCompromise,
    CriticalCompromise,
}

impl IntegrityVerdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DriftDetected => "drift-detected",
            Self::RestorableCompromise => "restorable-compromise",
            Self::CriticalCompromise => "critical-compromise",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegrityAssessment {
    pub verdict: IntegrityVerdict,
    pub artifact_id: Option<String>,
    pub artifact_path: Option<String>,
    pub restoration: Option<RestorationPlan>,
    pub detail: String,
}

#[derive(Clone, Debug, Default)]
pub struct IntegrityEngine {
    vault: ShadowVault,
}

impl IntegrityEngine {
    pub fn assess(&self, summary: &str) -> Option<IntegrityAssessment> {
        let normalized = summary.to_ascii_lowercase();
        if !contains_any(
            &normalized,
            &[
                "integrity_breach",
                "hash_mismatch",
                "tamper",
                "ptrace",
                "debug",
                "hook",
                "syscall",
                "rootkit",
                "unsigned_change",
                "modified_binary",
            ],
        ) {
            return None;
        }

        let restoration = self.vault.plan_restoration(&normalized);
        let verdict = if contains_any(&normalized, &["syscall", "rootkit", "boot", "dma"]) {
            IntegrityVerdict::CriticalCompromise
        } else if restoration.is_some() {
            IntegrityVerdict::RestorableCompromise
        } else {
            IntegrityVerdict::DriftDetected
        };

        let (artifact_id, artifact_path) = restoration
            .as_ref()
            .map(|plan| (Some(plan.artifact_id.clone()), Some(plan.path.clone())))
            .unwrap_or((None, None));

        let detail = if let Some(plan) = &restoration {
            format!(
                "integrity verdict={} artifact={} path={} restoration_mode={} baseline_hash={}",
                verdict.as_str(),
                plan.artifact_id,
                plan.path,
                plan.mode.as_str(),
                plan.baseline_hash
            )
        } else {
            format!(
                "integrity verdict={} no shadow-vault artifact matched summary={}",
                verdict.as_str(),
                normalized
            )
        };

        Some(IntegrityAssessment {
            verdict,
            artifact_id,
            artifact_path,
            restoration,
            detail,
        })
    }
}

fn contains_any(summary: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| summary.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::{IntegrityEngine, IntegrityVerdict};

    #[test]
    fn classifies_restorable_runtime_compromise() {
        let engine = IntegrityEngine::default();
        let assessment = engine
            .assess("hash_mismatch sentineld runtime tamper")
            .expect("assessment should exist");

        assert_eq!(assessment.verdict, IntegrityVerdict::RestorableCompromise);
        assert!(assessment.restoration.is_some());
    }

    #[test]
    fn classifies_critical_rootkit_style_pressure() {
        let engine = IntegrityEngine::default();
        let assessment = engine
            .assess("integrity_breach syscall_table rootkit hook")
            .expect("assessment should exist");

        assert_eq!(assessment.verdict, IntegrityVerdict::CriticalCompromise);
    }
}
