#![forbid(unsafe_code)]

use std::{fs, path::PathBuf, process::Command};

use serde_json::json;
use tempfile::tempdir;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn synthetic_observation() -> serde_json::Value {
    serde_json::from_slice(
        &fs::read(root().join("evaluations/fixtures/estate-observation.synthetic.json")).unwrap(),
    )
    .unwrap()
}

#[test]
fn blocked_preflight_returns_exit_code_two() {
    let temp = tempdir().unwrap();
    let mut observation = synthetic_observation();
    observation["unknown_fact_codes"] = json!(["module-inventory-incomplete"]);
    let input = temp.path().join("blocked.json");
    fs::write(&input, serde_json::to_vec(&observation).unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_proof-migrate"))
        .arg("preflight")
        .arg("--observation")
        .arg(&input)
        .arg("--output")
        .arg(temp.path().join("output"))
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains(r#""status": "blocked""#)
    );
}

#[test]
fn unsafe_preflight_returns_failure() {
    let temp = tempdir().unwrap();
    let mut observation = synthetic_observation();
    observation["data_safety"]["contains"]["credentials"] = json!(true);
    let input = temp.path().join("unsafe.json");
    fs::write(&input, serde_json::to_vec(&observation).unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_proof-migrate"))
        .arg("preflight")
        .arg("--observation")
        .arg(&input)
        .arg("--output")
        .arg(temp.path().join("output"))
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("must not contain credentials")
    );
}

#[test]
fn blocked_folder_inspection_is_a_successful_discovery_run() {
    let temp = tempdir().unwrap();
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("Sitecore.config"), "not opened").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_proof-migrate"))
        .arg("inspect")
        .arg("--source")
        .arg(&source)
        .arg("--output")
        .arg(temp.path().join("output"))
        .arg("--estate-id")
        .arg("SYNTH-CLI-INSPECT-001")
        .arg("--observed-at")
        .arg("2026-08-21T12:00:00Z")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains(r#""preflight_status": "blocked""#)
    );
}
