mod common;

use std::process::Output;

use common::Harness;

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn run(harness: &Harness, overrides: &[(&str, &str)], args: &[&str]) -> Output {
    let config = harness.write_config(overrides);
    harness.daemon_command(&config).args(args).output().unwrap()
}

#[test]
fn config_init_writes_a_parsable_file_and_refuses_to_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested/config.toml");
    let init = |extra: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_op-secretd"))
            .arg("--config")
            .arg(&path)
            .args(["config", "init"])
            .args(extra)
            .output()
            .unwrap()
    };
    let first = init(&[]);
    assert!(first.status.success(), "{}", text(&first.stderr));
    assert!(
        text(&std::fs::read_to_string(&path).unwrap().into_bytes())
            .contains("vault = \"Secret Service\"")
    );

    let second = init(&[]);
    assert!(!second.status.success());
    assert!(text(&second.stderr).contains("already exists"));

    std::fs::write(&path, "vault = \"changed\"\n").unwrap();
    assert!(init(&["--force"]).status.success());
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("Secret Service")
    );
}

#[test]
fn doctor_passes_with_a_working_setup() {
    let harness = Harness::new();
    let output = run(&harness, &[], &["doctor"]);
    let stdout = text(&output.stdout);
    assert!(output.status.success(), "{stdout}{}", text(&output.stderr));
    for check in [
        "configuration",
        "1Password CLI",
        "vault access",
        "session bus",
        "session algorithms",
    ] {
        assert!(
            stdout.contains(&format!("ok    {check}")),
            "missing `{check}` in:\n{stdout}"
        );
    }
}

#[test]
fn doctor_fails_when_the_vault_is_unreachable() {
    let harness = Harness::new();
    let output = run(&harness, &[("vault", "\"missing\"")], &["doctor"]);
    assert!(!output.status.success());
    assert!(
        text(&output.stdout).contains("FAIL  vault access"),
        "{}",
        text(&output.stdout)
    );
}

#[test]
fn doctor_fails_when_the_configuration_is_invalid() {
    let harness = Harness::new();
    let output = run(&harness, &[("vault", "\"\"")], &["doctor"]);
    assert!(!output.status.success());
    assert!(
        text(&output.stdout).contains("FAIL  configuration"),
        "{}",
        text(&output.stdout)
    );
}

#[test]
fn serve_refuses_to_start_without_a_vault() {
    let harness = Harness::new();
    let output = run(&harness, &[("vault", "\"\"")], &["serve"]);
    assert!(!output.status.success());
    assert!(
        text(&output.stderr).contains("vault"),
        "{}",
        text(&output.stderr)
    );
}

#[tokio::test]
async fn doctor_recognizes_a_running_daemon() {
    let mut harness = Harness::new();
    harness.start_daemon(&[]).await;
    let config = harness.write_config(&[]);
    let output = harness
        .daemon_command(&config)
        .arg("doctor")
        .output()
        .unwrap();
    let stdout = text(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("is served by op-secretd"), "{stdout}");
}
