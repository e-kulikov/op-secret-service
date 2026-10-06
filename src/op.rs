//! Running the 1Password CLI: native `op`, Windows `op.exe` through WSL
//! interop, or native `op` with a service account token.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use zeroize::Zeroizing;

use crate::config::{Config, Interop, Mode};
use crate::error::{Error, Result};

/// How long one `op` invocation may take, including waiting for the user to approve it.
const OP_TIMEOUT: Duration = Duration::from_secs(120);

/// Extra attempts after a transient failure of the 1Password client.
const TRANSIENT_RETRIES: usize = 2;
const RETRY_DELAY: Duration = Duration::from_millis(250);

/// The app's CLI integration sometimes refuses a call it would accept a moment later.
fn is_transient(message: &str) -> bool {
    message.contains("error initializing client")
        || message.contains("make sure it is installed, running and CLI integration is enabled")
}

/// What the resolver looks at; replaceable in tests.
#[derive(Debug, Clone)]
pub struct Probe {
    pub wsl: bool,
    pub path_dirs: Vec<PathBuf>,
    pub users_root: PathBuf,
    pub program_files: PathBuf,
    pub env: HashMap<String, String>,
}

impl Probe {
    pub fn real() -> Self {
        let env: HashMap<String, String> = std::env::vars().collect();
        let proc_version = std::fs::read_to_string("/proc/version").unwrap_or_default();
        Self {
            wsl: is_wsl(
                &proc_version,
                env.get("WSL_DISTRO_NAME").map(String::as_str),
            ),
            path_dirs: env
                .get("PATH")
                .map(|path| std::env::split_paths(path).collect())
                .unwrap_or_default(),
            users_root: PathBuf::from("/mnt/c/Users"),
            program_files: PathBuf::from("/mnt/c/Program Files"),
            env,
        }
    }
}

pub fn is_wsl(proc_version: &str, distro: Option<&str>) -> bool {
    distro.is_some_and(|name| !name.is_empty()) || proc_version.to_lowercase().contains("microsoft")
}

fn is_executable(path: &Path) -> bool {
    path.metadata()
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

fn find_in_path(name: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    dirs.iter()
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable(candidate))
}

/// Looks for the Windows CLI: WinGet link of any user, then Program Files.
pub fn find_op_exe(probe: &Probe) -> Option<PathBuf> {
    let mut users: Vec<PathBuf> = std::fs::read_dir(&probe.users_root)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .collect();
    users.sort();
    users
        .into_iter()
        .map(|user| user.join("AppData/Local/Microsoft/WinGet/Links/op.exe"))
        .chain(std::iter::once(
            probe.program_files.join("1Password CLI/op.exe"),
        ))
        .find(|candidate| is_executable(candidate))
}

/// How the CLI is started.
#[derive(Clone)]
pub enum Launch {
    Native(PathBuf),
    Interop(PathBuf),
    ServiceAccount {
        program: PathBuf,
        token: Zeroizing<String>,
    },
}

fn read_token(config: &Config, probe: &Probe) -> Result<Zeroizing<String>> {
    let op = &config.op;
    let token = if !op.service_account_token_file.is_empty() {
        let path = Path::new(&op.service_account_token_file);
        let meta = path
            .metadata()
            .map_err(|error| Error::Config(format!("{}: {error}", path.display())))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(Error::Config(format!(
                "{} must not be accessible by group or others (mode 0600)",
                path.display()
            )));
        }
        Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|error| Error::Config(format!("{}: {error}", path.display())))?,
        )
    } else if !op.service_account_token_env.is_empty() {
        Zeroizing::new(
            probe
                .env
                .get(&op.service_account_token_env)
                .cloned()
                .ok_or_else(|| {
                    Error::Config(format!(
                        "environment variable {} is not set",
                        op.service_account_token_env
                    ))
                })?,
        )
    } else {
        return Err(Error::Config(
            "mode `service-account` needs op.service_account_token_file or op.service_account_token_env".into(),
        ));
    };
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Err(Error::Config("the service account token is empty".into()));
    }
    Ok(Zeroizing::new(trimmed.to_owned()))
}

/// Chooses the launch method from the configuration and the environment.
pub fn resolve(config: &Config, probe: &Probe) -> Result<Launch> {
    let explicit = (config.op.binary != "auto").then(|| PathBuf::from(&config.op.binary));
    let native = || {
        explicit
            .clone()
            .or_else(|| find_in_path("op", &probe.path_dirs))
            .ok_or_else(|| Error::OpUnavailable("`op` was not found in PATH; set op.binary".into()))
    };

    if config.mode == Mode::ServiceAccount {
        return Ok(Launch::ServiceAccount {
            program: native()?,
            token: read_token(config, probe)?,
        });
    }

    let want_interop = match config.op.wsl_interop {
        Interop::Enabled => true,
        Interop::Disabled => false,
        Interop::Auto => {
            probe.wsl
                || explicit
                    .as_ref()
                    .is_some_and(|path| path.extension().is_some_and(|ext| ext == "exe"))
        }
    };
    if want_interop {
        if let Some(program) = explicit.clone().or_else(|| find_op_exe(probe)) {
            return Ok(Launch::Interop(program));
        }
        if config.op.wsl_interop == Interop::Enabled {
            return Err(Error::OpUnavailable(
                "wsl_interop is enabled but op.exe was not found; set op.binary".into(),
            ));
        }
    }
    Ok(Launch::Native(native()?))
}

/// Runs `op` with a fixed launch method and optional `--account`.
#[derive(Clone)]
pub struct OpRunner {
    launch: Launch,
    account: Option<String>,
}

fn first_error_line(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("no error output");
    line.trim_start_matches("[ERROR]").trim().to_owned()
}

impl OpRunner {
    pub fn new(launch: Launch, account: Option<String>) -> Self {
        Self {
            launch,
            account: account.filter(|account| !account.is_empty()),
        }
    }

    pub fn from_config(config: &Config, probe: &Probe) -> Result<Self> {
        Ok(Self::new(
            resolve(config, probe)?,
            Some(config.account.clone()),
        ))
    }

    pub fn describe(&self) -> String {
        match &self.launch {
            Launch::Native(program) => format!("native op ({})", program.display()),
            Launch::Interop(program) => {
                format!("Windows op.exe through WSL interop ({})", program.display())
            }
            Launch::ServiceAccount { program, .. } => {
                format!("service account via op ({})", program.display())
            }
        }
    }

    /// Runs the CLI and returns stdout. `stdin` is passed as the child's standard
    /// input. Transient client errors are retried a couple of times.
    pub async fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut attempt = 0;
        loop {
            match self.run_once(args, stdin).await {
                Err(Error::OpFailed(message))
                    if attempt < TRANSIENT_RETRIES && is_transient(&message) =>
                {
                    attempt += 1;
                    tracing::debug!(attempt, %message, "retrying a transient 1Password client error");
                    tokio::time::sleep(RETRY_DELAY).await;
                }
                other => return other,
            }
        }
    }

    async fn run_once(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
        let program = match &self.launch {
            Launch::Native(program) | Launch::Interop(program) => program,
            Launch::ServiceAccount { program, .. } => program,
        };
        let mut command = Command::new(program);
        command.args(args);
        if let Some(account) = &self.account {
            command.args(["--account", account]);
        }
        command.env_remove("OP_SERVICE_ACCOUNT_TOKEN");
        if let Launch::ServiceAccount { token, .. } = &self.launch {
            command.env("OP_SERVICE_ACCOUNT_TOKEN", token.as_str());
        }
        command
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = spawn_with_retry(&mut command)
            .await
            .map_err(|error| Error::OpUnavailable(format!("{}: {error}", program.display())))?;
        if let (Some(data), Some(mut pipe)) = (stdin, child.stdin.take()) {
            let data = Zeroizing::new(data.to_vec());
            tokio::spawn(async move {
                let _ = pipe.write_all(&data).await;
            });
        }
        let output = tokio::time::timeout(OP_TIMEOUT, child.wait_with_output())
            .await
            .map_err(|_| Error::OpFailed(format!("timed out after {}s", OP_TIMEOUT.as_secs())))?
            .map_err(|error| Error::OpUnavailable(error.to_string()))?;

        if !output.status.success() {
            let message = first_error_line(&output.stderr);
            if message.contains("isn't an item") {
                return Err(Error::NotFound);
            }
            return Err(Error::OpFailed(message));
        }
        let mut stdout = output.stdout;
        if matches!(self.launch, Launch::Interop(_)) {
            stdout = normalize_newlines(&stdout);
        }
        Ok(stdout)
    }
}

/// Spawns `command`, retrying briefly while the executable is busy (`ETXTBSY`),
/// which happens when the file was just written or is being replaced.
async fn spawn_with_retry(command: &mut Command) -> std::io::Result<tokio::process::Child> {
    let mut attempts = 0;
    loop {
        match command.spawn() {
            Err(error)
                if error.kind() == std::io::ErrorKind::ExecutableFileBusy && attempts < 10 =>
            {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            other => return other,
        }
    }
}

/// Converts CRLF to LF (`op.exe` output).
pub fn normalize_newlines(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut iter = bytes.iter().peekable();
    while let Some(&byte) = iter.next() {
        if byte == b'\r' && iter.peek() == Some(&&b'\n') {
            continue;
        }
        out.push(byte);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_exe(path: &Path, body: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn probe(root: &Path, wsl: bool) -> Probe {
        Probe {
            wsl,
            path_dirs: vec![root.join("bin")],
            users_root: root.join("Users"),
            program_files: root.join("Program Files"),
            env: HashMap::new(),
        }
    }

    fn config(mutate: impl FnOnce(&mut Config)) -> Config {
        let mut config = Config {
            vault: "V".into(),
            ..Config::default()
        };
        mutate(&mut config);
        config
    }

    #[test]
    fn wsl_detection() {
        assert!(is_wsl(
            "Linux version 6.18 (root@x) microsoft-standard-WSL2",
            None
        ));
        assert!(is_wsl("Linux version 6.8 generic", Some("Ubuntu")));
        assert!(!is_wsl("Linux version 6.8 generic", Some("")));
        assert!(!is_wsl("Linux version 6.8 generic", None));
    }

    #[test]
    fn op_exe_lookup_order() {
        let dir = tempfile::tempdir().unwrap();
        let p = probe(dir.path(), true);
        assert!(find_op_exe(&p).is_none());
        make_exe(&dir.path().join("Program Files/1Password CLI/op.exe"), "");
        assert_eq!(
            find_op_exe(&p).unwrap(),
            dir.path().join("Program Files/1Password CLI/op.exe")
        );
        let winget = dir
            .path()
            .join("Users/alice/AppData/Local/Microsoft/WinGet/Links/op.exe");
        make_exe(&winget, "");
        assert_eq!(find_op_exe(&p).unwrap(), winget);
    }

    #[test]
    fn auto_prefers_op_exe_on_wsl_and_native_elsewhere() {
        let dir = tempfile::tempdir().unwrap();
        make_exe(&dir.path().join("bin/op"), "");
        make_exe(&dir.path().join("Program Files/1Password CLI/op.exe"), "");
        let c = config(|_| {});
        assert!(matches!(
            resolve(&c, &probe(dir.path(), true)).unwrap(),
            Launch::Interop(_)
        ));
        assert!(matches!(
            resolve(&c, &probe(dir.path(), false)).unwrap(),
            Launch::Native(_)
        ));
    }

    #[test]
    fn wsl_falls_back_to_native_when_op_exe_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        make_exe(&dir.path().join("bin/op"), "");
        let launch = resolve(&config(|_| {}), &probe(dir.path(), true)).unwrap();
        assert!(matches!(launch, Launch::Native(_)));
    }

    #[test]
    fn forced_interop_without_op_exe_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        make_exe(&dir.path().join("bin/op"), "");
        let c = config(|c| c.op.wsl_interop = Interop::Enabled);
        assert!(matches!(
            resolve(&c, &probe(dir.path(), true)),
            Err(Error::OpUnavailable(_))
        ));
    }

    #[test]
    fn disabled_interop_uses_native_even_in_wsl() {
        let dir = tempfile::tempdir().unwrap();
        make_exe(&dir.path().join("bin/op"), "");
        make_exe(&dir.path().join("Program Files/1Password CLI/op.exe"), "");
        let c = config(|c| c.op.wsl_interop = Interop::Disabled);
        assert!(matches!(
            resolve(&c, &probe(dir.path(), true)).unwrap(),
            Launch::Native(_)
        ));
    }

    #[test]
    fn explicit_binary_with_exe_suffix_is_interop() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("custom/op.exe");
        make_exe(&exe, "");
        let c = config(|c| c.op.binary = exe.display().to_string());
        assert!(matches!(
            resolve(&c, &probe(dir.path(), false)).unwrap(),
            Launch::Interop(_)
        ));
    }

    #[test]
    fn missing_native_op_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let c = config(|_| {});
        assert!(matches!(
            resolve(&c, &probe(dir.path(), false)),
            Err(Error::OpUnavailable(_))
        ));
    }

    #[test]
    fn service_account_token_file_must_be_private() {
        let dir = tempfile::tempdir().unwrap();
        make_exe(&dir.path().join("bin/op"), "");
        let token = dir.path().join("token");
        fs::write(&token, "ops_secret\n").unwrap();
        let c = config(|c| {
            c.mode = Mode::ServiceAccount;
            c.op.service_account_token_file = token.display().to_string();
        });
        fs::set_permissions(&token, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            resolve(&c, &probe(dir.path(), false)),
            Err(Error::Config(_))
        ));
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        match resolve(&c, &probe(dir.path(), false)).unwrap() {
            Launch::ServiceAccount { token, .. } => assert_eq!(token.as_str(), "ops_secret"),
            _ => panic!("expected a service account launch"),
        }
    }

    #[test]
    fn service_account_token_from_environment() {
        let dir = tempfile::tempdir().unwrap();
        make_exe(&dir.path().join("bin/op"), "");
        let c = config(|c| {
            c.mode = Mode::ServiceAccount;
            c.op.service_account_token_env = "MY_TOKEN".into();
        });
        let mut p = probe(dir.path(), false);
        assert!(resolve(&c, &p).is_err());
        p.env.insert("MY_TOKEN".into(), "ops_env".into());
        assert!(matches!(
            resolve(&c, &p).unwrap(),
            Launch::ServiceAccount { .. }
        ));
        let none = config(|c| c.mode = Mode::ServiceAccount);
        assert!(resolve(&none, &p).is_err());
    }

    #[test]
    fn crlf_is_normalized() {
        assert_eq!(normalize_newlines(b"a\r\nb\rc\n"), b"a\nb\rc\n");
    }

    #[tokio::test]
    async fn run_passes_args_stdin_and_account() {
        let dir = tempfile::tempdir().unwrap();
        let op = dir.path().join("op");
        make_exe(&op, "printf '%s|' \"$@\"; cat");
        let runner = OpRunner::new(Launch::Native(op), Some("acme".into()));
        let out = runner
            .run(&["item", "get", "-"], Some(b"BODY"))
            .await
            .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "item|get|-|--account|acme|BODY"
        );
    }

    #[tokio::test]
    async fn run_classifies_errors() {
        let dir = tempfile::tempdir().unwrap();
        let op = dir.path().join("op");
        make_exe(
            &op,
            r#"case "$1" in
  missing) echo '[ERROR] 2026/10/05 "x" isn'"'"'t an item in the "V" vault.' >&2; exit 1;;
  denied) echo '[ERROR] 2026/10/05 authorization prompt dismissed' >&2; exit 1;;
esac
echo ok"#,
        );
        let runner = OpRunner::new(Launch::Native(op), None);
        assert!(matches!(
            runner.run(&["missing"], None).await,
            Err(Error::NotFound)
        ));
        match runner.run(&["denied"], None).await {
            Err(Error::OpFailed(message)) => assert!(
                message.contains("authorization prompt dismissed"),
                "{message}"
            ),
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(runner.run(&["fine"], None).await.unwrap(), b"ok\n");
    }

    #[tokio::test]
    async fn service_account_token_reaches_the_child_environment() {
        let dir = tempfile::tempdir().unwrap();
        let op = dir.path().join("op");
        make_exe(&op, "printf '%s' \"$OP_SERVICE_ACCOUNT_TOKEN\"");
        let sa = OpRunner::new(
            Launch::ServiceAccount {
                program: op.clone(),
                token: Zeroizing::new("ops_x".into()),
            },
            None,
        );
        assert_eq!(sa.run(&[], None).await.unwrap(), b"ops_x");
    }

    #[tokio::test]
    async fn missing_program_is_unavailable() {
        let runner = OpRunner::new(Launch::Native(PathBuf::from("/nonexistent/op")), None);
        assert!(matches!(
            runner.run(&[], None).await,
            Err(Error::OpUnavailable(_))
        ));
    }

    /// A stand-in `op` that fails with `error` for its first `failures` runs and prints `ok` afterwards.
    fn flaky_op(dir: &Path, failures: u32, error: &str) -> PathBuf {
        let op = dir.join("op");
        make_exe(
            &op,
            &format!(
                r#"n=$(cat "$0.count" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "$0.count"
if [ "$n" -le {failures} ]; then echo '[ERROR] 2026/10/06 {error}' >&2; exit 1; fi
echo ok"#
            ),
        );
        op
    }

    fn runs(op: &Path) -> u32 {
        fs::read_to_string(format!("{}.count", op.display()))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    #[tokio::test]
    async fn transient_client_errors_are_retried() {
        let dir = tempfile::tempdir().unwrap();
        for error in [
            "error initializing client: connection reset",
            "make sure it is installed, running and CLI integration is enabled",
        ] {
            let op = flaky_op(dir.path(), 2, error);
            let _ = fs::remove_file(format!("{}.count", op.display()));
            let runner = OpRunner::new(Launch::Native(op.clone()), None);
            assert_eq!(runner.run(&["x"], None).await.unwrap(), b"ok\n");
            assert_eq!(runs(&op), 3, "two failures and one success for: {error}");
        }
    }

    #[tokio::test]
    async fn permanent_errors_are_not_retried() {
        let dir = tempfile::tempdir().unwrap();
        let op = flaky_op(dir.path(), 99, "authorization prompt dismissed");
        let runner = OpRunner::new(Launch::Native(op.clone()), None);
        assert!(matches!(
            runner.run(&["x"], None).await,
            Err(Error::OpFailed(_))
        ));
        assert_eq!(runs(&op), 1);
    }

    #[tokio::test]
    async fn a_transient_error_that_persists_is_reported_after_the_retries() {
        let dir = tempfile::tempdir().unwrap();
        let op = flaky_op(dir.path(), 99, "error initializing client");
        let runner = OpRunner::new(Launch::Native(op.clone()), None);
        match runner.run(&["x"], None).await {
            Err(Error::OpFailed(message)) => assert!(message.contains("error initializing client")),
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(runs(&op), 3, "one attempt and two retries");
    }
}
