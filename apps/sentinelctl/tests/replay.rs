#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn replay_command_runs_fixture_contract() {
    let fixture = workspace_root()
        .join("testdata")
        .join("scenarios")
        .join("identity-abuse-containment.json");

    let output = Command::new(env!("CARGO_BIN_EXE_sentinelctl"))
        .arg("replay")
        .arg(&fixture)
        .output()
        .expect("replay command should run");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("scenario=identity-abuse-containment"));
    assert!(stdout.contains("validation=ok"));
    assert!(stdout.contains("CrystalSentinel Operator Report"));
    assert!(stdout.contains("CrystalSentinel Care Report"));
}
