//! Interoperability with real Secret Service clients. A missing client skips its
//! test, unless OP_SECRETD_REQUIRE_CLIENTS is set (CI sets it).

mod common;

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use common::Harness;

const PYTHON_CLIENT: &str = r#"
import keyring
from keyring.backends import SecretService

kr = SecretService.Keyring()
kr.set_password("gh:github.com", "bob", "tok-from-python")
assert kr.get_password("gh:github.com", "bob") == "tok-from-python"
print("roundtrip ok")
kr.set_password("gh:github.com", "bob", "tok-2")
assert kr.get_password("gh:github.com", "bob") == "tok-2"
print("overwrite ok")
kr.delete_password("gh:github.com", "bob")
assert kr.get_password("gh:github.com", "bob") is None
print("delete ok")
"#;

fn available(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .is_ok_and(|output| output.status.success())
}

/// True when the client can run; panics instead of skipping when clients are required.
fn client_available(name: &str, present: bool) -> bool {
    if !present {
        assert!(
            std::env::var_os("OP_SECRETD_REQUIRE_CLIENTS").is_none(),
            "required client `{name}` is missing"
        );
        eprintln!("SKIPPED: `{name}` is not available");
    }
    present
}

fn expect_success(what: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{what} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn go_keyring_roundtrip() {
    // zalando/go-keyring is the library behind the GitHub and GitLab CLIs.
    if !client_available("go", available("go", &["version"])) {
        return;
    }
    let mut harness = Harness::new();
    harness.start_daemon(&[]).await;
    let binary = harness.path("go-keyring-check");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/go-keyring");
    let build = Command::new("go")
        .args(["build", "-o"])
        .arg(&binary)
        .arg(".")
        .current_dir(fixture)
        .output()
        .unwrap();
    expect_success("go build", &build);

    let run = Command::new(&binary)
        .env("DBUS_SESSION_BUS_ADDRESS", &harness.address)
        .output()
        .unwrap();
    expect_success("go-keyring client", &run);
    assert!(String::from_utf8_lossy(&run.stdout).contains("delete ok"));
}

#[tokio::test]
async fn python_keyring_roundtrip() {
    // SecretStorage negotiates the dh-ietf1024-sha256-aes128-cbc-pkcs7 session.
    let python = std::env::var("OP_SECRETD_TEST_PYTHON").unwrap_or_else(|_| "python3".into());
    if !client_available(
        "python keyring",
        available(&python, &["-c", "import keyring, secretstorage"]),
    ) {
        return;
    }
    let mut harness = Harness::new();
    harness.start_daemon(&[]).await;
    let run = Command::new(&python)
        .args(["-c", PYTHON_CLIENT])
        .env("DBUS_SESSION_BUS_ADDRESS", &harness.address)
        .output()
        .unwrap();
    expect_success("python keyring client", &run);
    assert!(String::from_utf8_lossy(&run.stdout).contains("delete ok"));
}

#[tokio::test]
async fn secret_tool_roundtrip() {
    if !client_available("secret-tool", available("secret-tool", &["--version"])) {
        return;
    }
    let mut harness = Harness::new();
    harness.start_daemon(&[]).await;
    let tool = |args: &[&str], stdin: Option<&str>| {
        let mut child = Command::new("secret-tool")
            .args(args)
            .env("DBUS_SESSION_BUS_ADDRESS", &harness.address)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(text) = stdin {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
        }
        child.wait_with_output().unwrap()
    };
    expect_success(
        "store",
        &tool(
            &["store", "--label=test", "service", "gh", "username", "bob"],
            Some("tok-secret-tool"),
        ),
    );
    let lookup = tool(&["lookup", "service", "gh", "username", "bob"], None);
    expect_success("lookup", &lookup);
    assert_eq!(String::from_utf8_lossy(&lookup.stdout), "tok-secret-tool");
    expect_success(
        "clear",
        &tool(&["clear", "service", "gh", "username", "bob"], None),
    );
    let gone = tool(&["lookup", "service", "gh", "username", "bob"], None);
    assert!(gone.stdout.is_empty());
}
