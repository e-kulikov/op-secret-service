//! Configuration loading: TOML file plus `OP_SECRETD_*` overrides.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Deserializer};

use crate::attrs::AllowList;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Auto,
    App,
    ServiceAccount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interop {
    Auto,
    Enabled,
    Disabled,
}

impl<'de> Deserialize<'de> for Interop {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Bool(bool),
            Text(String),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Bool(true) => Ok(Interop::Enabled),
            Raw::Bool(false) => Ok(Interop::Disabled),
            Raw::Text(text) => parse_interop(&text).map_err(serde::de::Error::custom),
        }
    }
}

fn parse_interop(text: &str) -> std::result::Result<Interop, String> {
    match text {
        "auto" => Ok(Interop::Auto),
        "true" => Ok(Interop::Enabled),
        "false" => Ok(Interop::Disabled),
        other => Err(format!(
            "wsl_interop must be auto, true or false, got `{other}`"
        )),
    }
}

fn parse_mode(text: &str) -> std::result::Result<Mode, String> {
    match text {
        "auto" => Ok(Mode::Auto),
        "app" => Ok(Mode::App),
        "service-account" => Ok(Mode::ServiceAccount),
        other => Err(format!(
            "mode must be auto, app or service-account, got `{other}`"
        )),
    }
}

/// Parses `0`, `30s`, `5m` or `2h`.
pub fn parse_duration(text: &str) -> std::result::Result<Duration, String> {
    let text = text.trim();
    if text == "0" {
        return Ok(Duration::ZERO);
    }
    let (number, unit) = text.split_at(text.len().saturating_sub(1));
    let value: u64 = number
        .parse()
        .map_err(|_| format!("invalid duration `{text}`"))?;
    match unit {
        "s" => Ok(Duration::from_secs(value)),
        "m" => Ok(Duration::from_secs(value * 60)),
        "h" => Ok(Duration::from_secs(value * 3600)),
        _ => Err(format!("invalid duration `{text}`; use 0, 30s, 5m or 2h")),
    }
}

fn de_duration<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Duration, D::Error> {
    let text = String::deserialize(deserializer)?;
    parse_duration(&text).map_err(serde::de::Error::custom)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OpConfig {
    pub binary: String,
    pub wsl_interop: Interop,
    pub service_account_token_file: String,
    pub service_account_token_env: String,
}

impl Default for OpConfig {
    fn default() -> Self {
        Self {
            binary: "auto".into(),
            wsl_interop: Interop::Auto,
            service_account_token_file: String::new(),
            service_account_token_env: String::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub vault: String,
    pub account: String,
    pub mode: Mode,
    pub tag: String,
    #[serde(deserialize_with = "de_duration")]
    pub cache_ttl: Duration,
    #[serde(deserialize_with = "de_duration")]
    pub idle_timeout: Duration,
    pub allow: Vec<String>,
    pub log_level: String,
    pub op: OpConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            vault: String::new(),
            account: String::new(),
            mode: Mode::Auto,
            tag: "secret-service".into(),
            cache_ttl: Duration::from_secs(300),
            idle_timeout: Duration::from_secs(900),
            allow: Vec::new(),
            log_level: "info".into(),
            op: OpConfig::default(),
        }
    }
}

/// Commented configuration written by `op-secretd config init`.
pub const EXAMPLE: &str = r#"# op-secretd configuration.

# Vault that holds the secrets. It must already exist. Required.
vault = "Secret Service"

# 1Password account shorthand or ID, passed to `op --account`. Optional.
account = ""

# auto: Windows op.exe on WSL, otherwise the native op, signed in through the app.
# app: always authenticate through the 1Password app.
# service-account: use a service account token (see [op] below).
mode = "auto"

# Tag put on every item created by the daemon.
tag = "secret-service"

# How long decrypted items stay in memory. "0" disables the cache.
cache_ttl = "5m"

# The daemon exits after this long without requests. "0" disables it.
idle_timeout = "15m"

# Attribute patterns (key=glob). Empty means everything is accepted.
# Example: allow = ["service=gh:*", "service=glab*"]
allow = []

# Log filter: error, warn, info, debug or trace.
log_level = "info"

[op]
# "auto" or the path of the op / op.exe executable.
binary = "auto"

# auto: use op.exe when running inside WSL. true / false force the choice.
wsl_interop = "auto"

# Service account token, read from a file (mode 0600) or from this environment variable.
service_account_token_file = ""
service_account_token_env = ""
"#;

impl Config {
    pub fn from_toml(text: &str) -> Result<Self> {
        toml::from_str(text).map_err(|error| Error::Config(error.to_string()))
    }

    /// Applies `OP_SECRETD_<KEY>` overrides read through `get`.
    pub fn apply_env(&mut self, get: &dyn Fn(&str) -> Option<String>) -> Result<()> {
        let var = |name: &str| get(&format!("OP_SECRETD_{name}"));
        if let Some(value) = var("VAULT") {
            self.vault = value;
        }
        if let Some(value) = var("ACCOUNT") {
            self.account = value;
        }
        if let Some(value) = var("MODE") {
            self.mode = parse_mode(&value).map_err(Error::Config)?;
        }
        if let Some(value) = var("TAG") {
            self.tag = value;
        }
        if let Some(value) = var("CACHE_TTL") {
            self.cache_ttl = parse_duration(&value).map_err(Error::Config)?;
        }
        if let Some(value) = var("IDLE_TIMEOUT") {
            self.idle_timeout = parse_duration(&value).map_err(Error::Config)?;
        }
        if let Some(value) = var("ALLOW") {
            self.allow = value
                .split(',')
                .filter(|p| !p.is_empty())
                .map(str::to_owned)
                .collect();
        }
        if let Some(value) = var("LOG_LEVEL") {
            self.log_level = value;
        }
        if let Some(value) = var("OP_BINARY") {
            self.op.binary = value;
        }
        if let Some(value) = var("OP_WSL_INTEROP") {
            self.op.wsl_interop = parse_interop(&value).map_err(Error::Config)?;
        }
        if let Some(value) = var("OP_SERVICE_ACCOUNT_TOKEN_FILE") {
            self.op.service_account_token_file = value;
        }
        if let Some(value) = var("OP_SERVICE_ACCOUNT_TOKEN_ENV") {
            self.op.service_account_token_env = value;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.vault.trim().is_empty() {
            return Err(Error::Config(
                "`vault` is required; run `op-secretd config init` or set OP_SECRETD_VAULT".into(),
            ));
        }
        if self.tag.trim().is_empty() {
            return Err(Error::Config("`tag` must not be empty".into()));
        }
        AllowList::new(&self.allow)?;
        Ok(())
    }

    pub fn allow_list(&self) -> Result<AllowList> {
        AllowList::new(&self.allow)
    }
}

/// `$OP_SECRETD_CONFIG`, else `$XDG_CONFIG_HOME/op-secretd/config.toml`,
/// else `$HOME/.config/op-secretd/config.toml`.
pub fn default_path(get: &dyn Fn(&str) -> Option<String>) -> Result<PathBuf> {
    if let Some(path) = get("OP_SECRETD_CONFIG") {
        return Ok(PathBuf::from(path));
    }
    if let Some(dir) = get("XDG_CONFIG_HOME").filter(|dir| !dir.is_empty()) {
        return Ok(PathBuf::from(dir).join("op-secretd/config.toml"));
    }
    let home = get("HOME")
        .ok_or_else(|| Error::Config("neither XDG_CONFIG_HOME nor HOME is set".into()))?;
    Ok(PathBuf::from(home).join(".config/op-secretd/config.toml"))
}

/// Reads `path` (a missing file means defaults), applies the environment and validates.
pub fn load(path: &Path, get: &dyn Fn(&str) -> Option<String>) -> Result<Config> {
    let mut config = match std::fs::read_to_string(path) {
        Ok(text) => Config::from_toml(&text)
            .map_err(|error| Error::Config(format!("{}: {error}", path.display())))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Config::default(),
        Err(error) => return Err(Error::Config(format!("{}: {error}", path.display()))),
    };
    config.apply_env(get)?;
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |key| map.get(key).cloned()
    }

    #[test]
    fn example_parses_and_validates() {
        let config = Config::from_toml(EXAMPLE).unwrap();
        config.validate().unwrap();
        assert_eq!(config.vault, "Secret Service");
        assert_eq!(config.mode, Mode::Auto);
        assert_eq!(config.cache_ttl, Duration::from_secs(300));
        assert_eq!(config.idle_timeout, Duration::from_secs(900));
        assert_eq!(config.op.wsl_interop, Interop::Auto);
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("0").unwrap(), Duration::ZERO);
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert!(parse_duration("5").is_err());
        assert!(parse_duration("m").is_err());
        assert!(parse_duration("").is_err());
        assert!(parse_duration("5d").is_err());
    }

    #[test]
    fn interop_accepts_bool_and_string() {
        let config = Config::from_toml("[op]\nwsl_interop = true").unwrap();
        assert_eq!(config.op.wsl_interop, Interop::Enabled);
        let config = Config::from_toml("[op]\nwsl_interop = \"false\"").unwrap();
        assert_eq!(config.op.wsl_interop, Interop::Disabled);
        assert!(Config::from_toml("[op]\nwsl_interop = \"maybe\"").is_err());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(Config::from_toml("vualt = \"x\"").is_err());
    }

    #[test]
    fn vault_is_required() {
        assert!(Config::default().validate().is_err());
    }

    #[test]
    fn env_overrides_file() {
        let mut config = Config::from_toml("vault = \"A\"\nmode = \"app\"").unwrap();
        config
            .apply_env(&env(&[
                ("OP_SECRETD_VAULT", "B"),
                ("OP_SECRETD_MODE", "service-account"),
                ("OP_SECRETD_CACHE_TTL", "1m"),
                ("OP_SECRETD_ALLOW", "service=gh:*,service=glab"),
                ("OP_SECRETD_OP_WSL_INTEROP", "false"),
            ]))
            .unwrap();
        assert_eq!(config.vault, "B");
        assert_eq!(config.mode, Mode::ServiceAccount);
        assert_eq!(config.cache_ttl, Duration::from_secs(60));
        assert_eq!(config.allow, vec!["service=gh:*", "service=glab"]);
        assert_eq!(config.op.wsl_interop, Interop::Disabled);
        assert!(
            config
                .apply_env(&env(&[("OP_SECRETD_MODE", "bogus")]))
                .is_err()
        );
    }

    #[test]
    fn validate_rejects_bad_allow_pattern() {
        let config = Config {
            vault: "V".into(),
            allow: vec!["broken".into()],
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn path_resolution_order() {
        let get = env(&[
            ("OP_SECRETD_CONFIG", "/x/c.toml"),
            ("XDG_CONFIG_HOME", "/xdg"),
            ("HOME", "/h"),
        ]);
        assert_eq!(default_path(&get).unwrap(), PathBuf::from("/x/c.toml"));
        let get = env(&[("XDG_CONFIG_HOME", "/xdg"), ("HOME", "/h")]);
        assert_eq!(
            default_path(&get).unwrap(),
            PathBuf::from("/xdg/op-secretd/config.toml")
        );
        let get = env(&[("HOME", "/h")]);
        assert_eq!(
            default_path(&get).unwrap(),
            PathBuf::from("/h/.config/op-secretd/config.toml")
        );
        assert!(default_path(&env(&[])).is_err());
    }

    #[test]
    fn load_uses_defaults_when_file_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.toml");
        let config = load(&path, &env(&[("OP_SECRETD_VAULT", "V")])).unwrap();
        assert_eq!(config.vault, "V");
        assert!(load(&path, &env(&[])).is_err());
    }

    #[test]
    fn load_reports_the_file_in_parse_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, "vault = [").unwrap();
        let error = load(&path, &env(&[])).unwrap_err().to_string();
        assert!(error.contains("c.toml"), "{error}");
    }
}
