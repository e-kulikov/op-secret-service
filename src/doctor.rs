//! `op-secretd doctor`: checks that the daemon can run with this setup.

use std::collections::HashMap;
use std::path::PathBuf;

use zbus::fdo::DBusProxy;
use zbus::names::BusName;

use crate::config::Config;
use crate::crypto::{ALGORITHM_DH, DhKeypair, negotiate};
use crate::lifecycle::{BUS_NAME, describe_owner};
use crate::op::{OpRunner, Probe};

/// Outcome of one check. A warning is reported but does not fail `doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
}

fn check(name: &'static str, result: std::result::Result<String, String>) -> Check {
    match result {
        Ok(detail) => Check {
            name,
            status: Status::Ok,
            detail,
        },
        Err(detail) => Check {
            name,
            status: Status::Fail,
            detail,
        },
    }
}

/// True when a `key: value` line sets one of `keys` to a non-empty value.
fn sets_secret(line: &str, keys: &[&str]) -> bool {
    let line = line.trim();
    if line.starts_with('#') {
        return false;
    }
    let Some((key, value)) = line.split_once(':') else {
        return false;
    };
    let value = value.trim();
    keys.contains(&key.trim()) && !matches!(value, "" | "''" | "\"\"" | "null" | "~" | "!!null")
}

fn config_dir(
    env: &HashMap<String, String>,
    override_var: &str,
    xdg_name: &str,
) -> Option<PathBuf> {
    if let Some(dir) = env.get(override_var).filter(|dir| !dir.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    if let Some(xdg) = env.get("XDG_CONFIG_HOME").filter(|dir| !dir.is_empty()) {
        return Some(PathBuf::from(xdg).join(xdg_name));
    }
    env.get("HOME")
        .map(|home| PathBuf::from(home).join(".config").join(xdg_name))
}

/// Warns about GitHub and GitLab CLI tokens kept in plaintext configuration files.
///
/// `gh` and `glab` silently fall back to those files when the keyring cannot be
/// written, so a successful login does not prove the token is in 1Password. Only
/// file paths are reported, never values.
pub fn plaintext_token_check(env: &HashMap<String, String>) -> Check {
    let targets = [
        (
            config_dir(env, "GH_CONFIG_DIR", "gh"),
            "hosts.yml",
            &["oauth_token"][..],
        ),
        (
            config_dir(env, "GLAB_CONFIG_DIR", "glab-cli"),
            "config.yml",
            &["token", "oauth2_refresh_token"][..],
        ),
    ];
    let mut found = Vec::new();
    for (dir, file, keys) in targets {
        let Some(path) = dir.map(|dir| dir.join(file)) else {
            continue;
        };
        if let Ok(text) = std::fs::read_to_string(&path)
            && text.lines().any(|line| sets_secret(line, keys))
        {
            found.push(path.display().to_string());
        }
    }
    if found.is_empty() {
        return Check {
            name: "plaintext tokens",
            status: Status::Ok,
            detail: "no GitHub or GitLab CLI tokens in plaintext configuration".into(),
        };
    }
    Check {
        name: "plaintext tokens",
        status: Status::Warn,
        detail: format!(
            "{} hold a token in plaintext; gh and glab fall back to it silently when the keyring fails. \
             With the daemon healthy, log out and log in again to move it into 1Password",
            found.join(", ")
        ),
    }
}

async fn session_bus_check() -> std::result::Result<String, String> {
    let connection = zbus::Connection::session()
        .await
        .map_err(|e| format!("cannot connect to the session bus: {e}"))?;
    let proxy = DBusProxy::new(&connection)
        .await
        .map_err(|e| e.to_string())?;
    let name = BusName::try_from(BUS_NAME).map_err(|e| e.to_string())?;
    if proxy
        .name_has_owner(name)
        .await
        .map_err(|e| e.to_string())?
    {
        let owner = describe_owner(&connection).await;
        if owner.starts_with("op-secretd") {
            return Ok(format!("{BUS_NAME} is served by {owner}"));
        }
        return Err(format!("{BUS_NAME} is owned by {owner}"));
    }
    Ok(format!("{BUS_NAME} is free"))
}

fn algorithms_check() -> std::result::Result<String, String> {
    let client = DhKeypair::generate().map_err(|e| e.to_string())?;
    negotiate(ALGORITHM_DH, &client.public).map_err(|e| e.to_string())?;
    Ok("plain and dh-ietf1024-sha256-aes128-cbc-pkcs7".into())
}

/// Runs every check; later checks that depend on `op` are skipped when it cannot be resolved.
pub async fn run(config: &Config, probe: &Probe) -> Vec<Check> {
    let mut checks = vec![check(
        "configuration",
        config
            .validate()
            .map(|()| format!("vault `{}`, mode {:?}", config.vault, config.mode))
            .map_err(|e| e.to_string()),
    )];
    match OpRunner::from_config(config, probe) {
        Ok(runner) => {
            checks.push(check("1Password CLI", Ok(runner.describe())));
            let vault = runner
                .run(&["vault", "get", &config.vault, "--format", "json"], None)
                .await;
            checks.push(check(
                "vault access",
                vault
                    .map(|_| format!("vault `{}` is reachable", config.vault))
                    .map_err(|e| e.to_string()),
            ));
        }
        Err(error) => checks.push(check("1Password CLI", Err(error.to_string()))),
    }
    checks.push(check("session bus", session_bus_check().await));
    checks.push(check("session algorithms", algorithms_check()));
    checks.push(plaintext_token_check(&probe.env));
    checks
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use std::path::Path;

    const SECRET: &str = "gho_plainsecret123456789";

    fn env(pairs: &[(&str, &Path)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, path)| ((*key).to_owned(), path.display().to_string()))
            .collect()
    }

    fn write(dir: &Path, name: &str, text: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join(name), text).unwrap();
    }

    #[test]
    fn no_config_files_means_no_plaintext_tokens() {
        let home = tempfile::tempdir().unwrap();
        let check = plaintext_token_check(&env(&[("HOME", home.path())]));
        assert_eq!(check.status, Status::Ok);
        assert_eq!(check.name, "plaintext tokens");
    }

    #[test]
    fn a_gh_token_in_hosts_yml_is_reported_without_its_value() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "hosts.yml",
            &format!(
                "github.com:\n    users:\n        bob:\n            oauth_token: {SECRET}\n    oauth_token: {SECRET}\n    user: bob\n"
            ),
        );
        let check = plaintext_token_check(&env(&[("GH_CONFIG_DIR", dir.path())]));
        assert_eq!(check.status, Status::Warn);
        assert!(check.detail.contains("hosts.yml"), "{}", check.detail);
        assert!(
            !check.detail.contains(SECRET),
            "the value must never be printed"
        );
    }

    #[test]
    fn gh_in_keyring_mode_has_no_oauth_token_line() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "hosts.yml",
            "github.com:\n    git_protocol: https\n    users:\n        bob:\n    user: bob\n",
        );
        let check = plaintext_token_check(&env(&[("GH_CONFIG_DIR", dir.path())]));
        assert_eq!(check.status, Status::Ok, "{}", check.detail);
    }

    #[test]
    fn glab_plaintext_tokens_are_reported_without_their_values() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "config.yml",
            &format!(
                "hosts:\n    gitlab.com:\n        token: {SECRET}\n        oauth2_refresh_token: {SECRET}\n        user: bob\n"
            ),
        );
        let check = plaintext_token_check(&env(&[("GLAB_CONFIG_DIR", dir.path())]));
        assert_eq!(check.status, Status::Warn);
        assert!(check.detail.contains("config.yml"), "{}", check.detail);
        assert!(!check.detail.contains(SECRET));
    }

    #[test]
    fn glab_with_empty_or_commented_token_fields_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "config.yml",
            "hosts:\n    gitlab.com:\n        # Your GitLab access token. token: not-a-value\n        token:\n        job_token: ''\n        oauth2_refresh_token: \"\"\n        use_keyring: true\n",
        );
        let check = plaintext_token_check(&env(&[("GLAB_CONFIG_DIR", dir.path())]));
        assert_eq!(check.status, Status::Ok, "{}", check.detail);
    }

    #[test]
    fn xdg_config_home_is_searched_when_no_override_is_set() {
        let xdg = tempfile::tempdir().unwrap();
        write(
            &xdg.path().join("gh"),
            "hosts.yml",
            &format!("github.com:\n    oauth_token: {SECRET}\n"),
        );
        let check = plaintext_token_check(&env(&[("XDG_CONFIG_HOME", xdg.path())]));
        assert_eq!(check.status, Status::Warn);
        write(
            &xdg.path().join("glab-cli"),
            "config.yml",
            &format!("hosts:\n    x:\n        token: {SECRET}\n"),
        );
        let both = plaintext_token_check(&env(&[("XDG_CONFIG_HOME", xdg.path())]));
        assert!(
            both.detail.contains("hosts.yml") && both.detail.contains("config.yml"),
            "{}",
            both.detail
        );
    }
}
