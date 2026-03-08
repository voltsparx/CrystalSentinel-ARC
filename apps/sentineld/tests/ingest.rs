use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("testdata")
        .join("telemetry")
        .join("sample-stream.jsonl")
}

#[test]
fn daemon_reads_jsonl_file_stream() {
    let output = Command::new(env!("CARGO_BIN_EXE_sentineld"))
        .arg("--telemetry-file")
        .arg(fixture_path())
        .output()
        .expect("sentineld should launch");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("telemetry source: jsonl-file"));
    assert!(stdout.contains("telemetry events loaded: 3"));
    assert!(stdout.contains("assessment: source=203.0.113.88 family=offensive-scan"));
    assert!(stdout.contains("assessment: source=198.51.100.44 family=volumetric-flood"));
}

#[test]
fn daemon_reads_jsonl_from_stdin() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sentineld"))
        .arg("--stdin-jsonl")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("sentineld should launch");

    {
        let stdin = child.stdin.as_mut().expect("stdin should be piped");
        stdin
            .write_all(
                br#"{"kind":"packet","source":"198.51.100.70","summary":"meterpreter tlv http_transport uuid","health":{"cpu_load_pct":47,"memory_load_pct":39,"thermal_c":59,"passive_only":false}}
"#,
            )
            .expect("stdin write should succeed");
    }

    let output = child
        .wait_with_output()
        .expect("sentineld should exit cleanly");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("telemetry source: stdin-jsonl"));
    assert!(stdout.contains("telemetry events loaded: 1"));
    assert!(stdout.contains("assessment: source=198.51.100.70 family=payload-stager"));
}

#[test]
fn daemon_applies_mesh_runtime_overrides() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sentineld"))
        .arg("--stdin-jsonl")
        .arg("--node-name")
        .arg("guardian-01")
        .arg("--deployment-shape")
        .arg("multi-node-mesh")
        .arg("--autonomy-mode")
        .arg("guardian-autonomous")
        .arg("--performance-profile")
        .arg("balanced")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("sentineld should launch");

    {
        let stdin = child.stdin.as_mut().expect("stdin should be piped");
        stdin
            .write_all(
                br#"{"kind":"integrity","source":"guardian-node-02","summary":"mesh_heartbeat_malformed guardian_pulse_invalid peer_trust_drift","health":{"cpu_load_pct":42,"memory_load_pct":35,"thermal_c":57,"passive_only":false}}
"#,
            )
            .expect("stdin write should succeed");
    }

    let output = child
        .wait_with_output()
        .expect("sentineld should exit cleanly");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("node: guardian-01"));
    assert!(stdout.contains("deployment=multi-node-mesh"));
    assert!(stdout.contains("mesh_distribution=true"));
    assert!(stdout.contains("broadcast-mesh-alert"));
    assert!(stdout.contains("shift-guardian-coverage"));
    assert!(stdout.contains("suspend-peer-trust"));
}
