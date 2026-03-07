#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeLanguage {
    C,
    Cpp,
    Asm,
}

impl NativeLanguage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::C => "c",
            Self::Cpp => "c++",
            Self::Asm => "asm",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeLayerStatus {
    Scaffolded,
    Linked,
}

impl NativeLayerStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scaffolded => "scaffolded",
            Self::Linked => "linked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeLayerSpec {
    pub language: NativeLanguage,
    pub library: &'static str,
    pub responsibility: &'static str,
    pub entrypoint: &'static str,
    pub status: NativeLayerStatus,
}

pub fn native_layer_manifest() -> Vec<NativeLayerSpec> {
    vec![
        NativeLayerSpec {
            language: NativeLanguage::C,
            library: "sentinel-native-c",
            responsibility: "Resource guards and OS-facing packet helpers.",
            entrypoint: "sentinel_c_resource_guard",
            status: NativeLayerStatus::Scaffolded,
        },
        NativeLayerSpec {
            language: NativeLanguage::Cpp,
            library: "sentinel-native-cpp",
            responsibility: "Stateful classifiers and attack-template modeling.",
            entrypoint: "sentinel_cpp_classify",
            status: NativeLayerStatus::Scaffolded,
        },
        NativeLayerSpec {
            language: NativeLanguage::Asm,
            library: "sentinel-native-asm",
            responsibility: "Timing primitives and fast-path helpers.",
            entrypoint: "sentinel_asm_cycle_stamp",
            status: NativeLayerStatus::Scaffolded,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::native_layer_manifest;

    #[test]
    fn exposes_three_native_layers() {
        let manifest = native_layer_manifest();
        assert_eq!(manifest.len(), 3);
    }
}

