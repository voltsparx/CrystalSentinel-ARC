#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactCriticality {
    Runtime,
    SystemBinary,
    Library,
    Configuration,
}

impl ArtifactCriticality {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::SystemBinary => "system-binary",
            Self::Library => "library",
            Self::Configuration => "configuration",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestorationMode {
    ReplaceInPlace,
    RestartAndRestore,
    RehydrateFromBaseline,
}

impl RestorationMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReplaceInPlace => "replace-in-place",
            Self::RestartAndRestore => "restart-and-restore",
            Self::RehydrateFromBaseline => "rehydrate-from-baseline",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultArtifact {
    pub artifact_id: &'static str,
    pub path: &'static str,
    pub baseline_hash: &'static str,
    pub criticality: ArtifactCriticality,
    pub aliases: &'static [&'static str],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestorationPlan {
    pub artifact_id: String,
    pub path: String,
    pub baseline_hash: String,
    pub criticality: ArtifactCriticality,
    pub mode: RestorationMode,
    pub narrative: String,
}

#[derive(Clone, Debug)]
pub struct ShadowVault {
    artifacts: Vec<VaultArtifact>,
}

impl Default for ShadowVault {
    fn default() -> Self {
        Self {
            artifacts: seed_vault_artifacts(),
        }
    }
}

impl ShadowVault {
    pub fn inventory(&self) -> &[VaultArtifact] {
        &self.artifacts
    }

    pub fn plan_restoration(&self, summary: &str) -> Option<RestorationPlan> {
        let normalized = summary.to_ascii_lowercase();
        let artifact = self.artifacts.iter().find(|artifact| {
            artifact
                .aliases
                .iter()
                .any(|alias| normalized.contains(alias))
        })?;

        let mode = match artifact.criticality {
            ArtifactCriticality::Runtime => RestorationMode::RestartAndRestore,
            ArtifactCriticality::SystemBinary => RestorationMode::ReplaceInPlace,
            ArtifactCriticality::Library => RestorationMode::ReplaceInPlace,
            ArtifactCriticality::Configuration => RestorationMode::RehydrateFromBaseline,
        };

        Some(RestorationPlan {
            artifact_id: artifact.artifact_id.to_string(),
            path: artifact.path.to_string(),
            baseline_hash: artifact.baseline_hash.to_string(),
            criticality: artifact.criticality,
            mode,
            narrative: format!(
                "shadow-vault artifact={} path={} criticality={} mode={} baseline_hash={}",
                artifact.artifact_id,
                artifact.path,
                artifact.criticality.as_str(),
                mode.as_str(),
                artifact.baseline_hash
            ),
        })
    }
}

pub fn seed_vault_artifacts() -> Vec<VaultArtifact> {
    vec![
        VaultArtifact {
            artifact_id: "sentineld-runtime",
            path: "apps/sentineld/bin/sentineld",
            baseline_hash: "sha256:sentinel-runtime-baseline",
            criticality: ArtifactCriticality::Runtime,
            aliases: &[
                "sentineld",
                "sentinel-self",
                "runtime_binary",
                "runtime tamper",
            ],
        },
        VaultArtifact {
            artifact_id: "sentinel-config",
            path: "configs/base/runtime.toml",
            baseline_hash: "sha256:sentinel-config-baseline",
            criticality: ArtifactCriticality::Configuration,
            aliases: &[
                "runtime config",
                "system_config",
                "sentinel-config",
                "config drift",
            ],
        },
        VaultArtifact {
            artifact_id: "kernel-runtime-library",
            path: "system/kernel32.dll",
            baseline_hash: "sha256:kernel-runtime-library-baseline",
            criticality: ArtifactCriticality::Library,
            aliases: &["kernel32", "dll", "shared library", "runtime library"],
        },
        VaultArtifact {
            artifact_id: "system-shell",
            path: "system/cmd.exe",
            baseline_hash: "sha256:system-shell-baseline",
            criticality: ArtifactCriticality::SystemBinary,
            aliases: &["cmd.exe", "/usr/bin/ls", "system shell", "shell binary"],
        },
        VaultArtifact {
            artifact_id: "syscall-table",
            path: "kernel/syscall_table",
            baseline_hash: "sha256:syscall-table-baseline",
            criticality: ArtifactCriticality::Runtime,
            aliases: &["syscall_table", "syscall table", "kernel hook", "rootkit"],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::{ArtifactCriticality, ShadowVault};

    #[test]
    fn finds_restore_plan_for_known_runtime() {
        let vault = ShadowVault::default();
        let plan = vault
            .plan_restoration("integrity_breach sentineld runtime tamper")
            .expect("runtime plan should exist");

        assert_eq!(plan.artifact_id, "sentineld-runtime");
        assert_eq!(plan.criticality, ArtifactCriticality::Runtime);
    }

    #[test]
    fn exposes_seeded_inventory() {
        let vault = ShadowVault::default();
        assert!(vault.inventory().len() >= 4);
    }
}
