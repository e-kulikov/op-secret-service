//! The fake `op` must behave like the real one where the daemon depends on it.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

const FAKE_OP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/fake-op.py");

fn fake(db: &Path, args: &[&str], stdin: Option<&str>) -> String {
    let mut child = Command::new("python3")
        .arg(FAKE_OP)
        .args(args)
        .env("FAKE_OP_DB", db)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(text) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn labels(db: &Path) -> Vec<String> {
    let item: serde_json::Value =
        serde_json::from_str(&fake(db, &["item", "get", "t", "--vault", "V"], None)).unwrap();
    item["fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|field| field["label"].as_str().map(str::to_owned))
        .collect()
}

const CREATE: &str = r#"{"title":"t","tags":["x"],"fields":[
    {"id":"password","purpose":"PASSWORD","label":"password","type":"CONCEALED","value":"old"},
    {"label":"label","type":"STRING","value":"keep me"}]}"#;

#[test]
fn a_partial_template_edit_drops_the_custom_fields_like_the_real_op() {
    // Observed against a real vault: `op item edit <item> -` with a template
    // replaces the custom fields instead of merging them.
    let dir = tempfile::tempdir().unwrap();
    fake(
        dir.path(),
        &["item", "create", "--vault", "V", "-"],
        Some(CREATE),
    );
    assert!(labels(dir.path()).contains(&"label".to_owned()));

    fake(
        dir.path(),
        &["item", "edit", "t", "--vault", "V", "-"],
        Some(r#"{"fields":[{"id":"password","value":"new"}]}"#),
    );
    assert!(
        !labels(dir.path()).contains(&"label".to_owned()),
        "a partial edit must lose the custom `label` field"
    );
}

#[test]
fn a_complete_template_edit_keeps_every_field() {
    let dir = tempfile::tempdir().unwrap();
    fake(
        dir.path(),
        &["item", "create", "--vault", "V", "-"],
        Some(CREATE),
    );
    fake(
        dir.path(),
        &["item", "edit", "t", "--vault", "V", "-"],
        Some(
            r#"{"fields":[
            {"id":"password","purpose":"PASSWORD","label":"password","type":"CONCEALED","value":"new"},
            {"label":"label","type":"STRING","value":"kept"}]}"#,
        ),
    );
    assert!(labels(dir.path()).contains(&"label".to_owned()));
    let item: serde_json::Value = serde_json::from_str(&fake(
        dir.path(),
        &["item", "get", "t", "--vault", "V"],
        None,
    ))
    .unwrap();
    let password = item["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "password")
        .unwrap();
    assert_eq!(password["value"], "new");
}
