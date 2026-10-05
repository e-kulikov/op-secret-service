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

/// True when `program args` succeeds and prints `expected`. Checking the output
/// rejects version-manager shims that answer every invocation with their own banner.
fn available(program: &str, args: &[&str], expected: &str) -> bool {
    for _ in 0..10 {
        match Command::new(program).args(args).output() {
            // A script that was written a moment ago can still be busy (ETXTBSY).
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(_) => return false,
            Ok(output) => {
                return output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains(expected);
            }
        }
    }
    false
}

/// True when `program` can be started at all, whatever its exit status.
fn installed(program: &str) -> bool {
    for _ in 0..10 {
        match Command::new(program).arg("--version").output() {
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            result => return result.is_ok(),
        }
    }
    false
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

#[test]
fn a_tool_that_exits_non_zero_without_arguments_is_still_installed() {
    // `secret-tool --version` prints its usage and exits with status 2.
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let tool = dir.path().join("usage-only");
    std::fs::write(&tool, "#!/bin/sh\necho 'usage: tool store' >&2\nexit 2\n").unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(installed(tool.to_str().unwrap()));
    assert!(!installed("/nonexistent/definitely-not-a-tool"));
}

#[test]
fn a_shim_that_ignores_its_arguments_is_not_a_client() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let write_tool = |name: &str, output: &str| {
        let path = dir.path().join(name);
        std::fs::write(&path, format!("#!/bin/sh\necho '{output}'\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.display().to_string()
    };
    // A version-manager shim answers every invocation with its own banner.
    let shim = write_tool("go-shim", "mise 2026.9.1 linux-x64");
    let real = write_tool("go-real", "go version go1.26 linux/amd64");
    assert!(!available(&shim, &["version"], "go version"));
    assert!(available(&real, &["version"], "go version"));
}

#[tokio::test]
async fn go_keyring_roundtrip() {
    // zalando/go-keyring is the library behind the GitHub and GitLab CLIs.
    if !client_available("go", available("go", &["version"], "go version")) {
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
        available(
            &python,
            &["-c", "import keyring, secretstorage; print(\"ok\")"],
            "ok",
        ),
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
    if !client_available("secret-tool", installed("secret-tool")) {
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
