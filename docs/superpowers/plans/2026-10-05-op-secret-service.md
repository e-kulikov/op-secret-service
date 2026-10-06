# op-secretd Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `op-secretd`, a Rust daemon that implements the freedesktop Secret Service API on top of 1Password, with CI, release automation, and documentation.

**Architecture:** One crate with a library (`attrs`, `config`, `crypto`, `op`, `cache`, `store`, `dbus`, `lifecycle`, `doctor`) and the `op-secretd` binary. D-Bus objects (`zbus`) call a `Store`, which keeps secrets as 1Password items through an `OpRunner` that starts `op`, `op.exe`, or `op` with a service account. Tests use a private `dbus-daemon`, a fake `op`, and real third-party clients.

**Tech Stack:** Rust 1.97.1 (edition 2024), `zbus` 5 with `tokio`, `clap`, `serde`/`toml`, RustCrypto (`aes`, `cbc`, `hkdf`, `sha2`), `num-bigint`, `zeroize`; Python 3 (fake `op`), Go (`go-keyring` test client), GitHub Actions with release-please.

**Spec:** `docs/superpowers/specs/2026-10-05-op-secret-service-design.md`

## Global Constraints

- The Rust toolchain is pinned to `1.97.1` in `rust-toolchain.toml`; the edition is 2024; build and test with `--locked`.
- The D-Bus library is `zbus` 5 with `default-features = false` and the `tokio` feature.
- Platforms: Linux (WSL2 and native). Release binaries are static musl builds for `x86_64` and `aarch64`.
- Secrets never appear in process arguments, logs, error messages, test output, or the repository. Item bodies go to `op` as JSON on stdin and secret buffers are `zeroize`d.
- Defaults: `mode = "auto"`, `tag = "secret-service"`, `cache_ttl = "5m"`, `idle_timeout = "1h"`; one `op` invocation is abandoned after 120 seconds, a transient client error is retried twice, and at most four `op` reads run in parallel.
- Item titles are `secret-service/<16 hex digits>`; session algorithms are `plain` and `dh-ietf1024-sha256-aes128-cbc-pkcs7`.
- Tests never touch a real 1Password account or real user directories; every XDG variable points into a temporary directory.
- Commit messages are English Conventional Commits. `CHANGELOG.md`, `.release-please-manifest.json`, and the version in `Cargo.toml` belong to release-please. Documentation is English; the `.ru.md` translations stay untracked and no Cyrillic enters a committed file. Do not push, tag, or publish.

## Review Focus

- A client that silently falls back to plaintext storage when the daemon fails (expected from the daemon: a D-Bus error, never an empty answer; the real `gh` and `glab` fall back anyway, which the daemon cannot prevent, so `doctor` must warn about plaintext tokens without ever printing them): `failures_surface_as_errors_not_empty_results`, `doctor_warns_about_plaintext_tokens_but_still_passes`, `a_gh_token_in_hosts_yml_is_reported_without_its_value`, and the manual checklist.
- A request that waits for a 1Password approval while the idle timeout elapses (expected: the daemon stays alive until the request finishes): `idle_exit_waits_for_a_request_in_flight`.
- Several commands at once on a cold cache (expected: one 1Password load, not one prompt each): `concurrent_requests_share_one_index_load`.
- Empty, 64 KiB, and non-UTF-8 secrets, and attributes with empty values, `=`, newlines, or non-ASCII text (expected: exact round trip): `empty_large_and_binary_secrets_roundtrip`, `empty_secrets_roundtrip`, `odd_attribute_values_survive`.
- Another Secret Service provider already running, or a client that sends a malformed request (expected: a clear message that is not labeled an internal error, or `InvalidArgs`, no crash): `a_second_provider_cannot_take_the_name`, `bad_requests_are_rejected`, `closing_a_session_invalidates_it`.

---

### Task 0: Scaffold the crate

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `LICENSE`, `README.md`, `src/error.rs`, `src/lib.rs`, `src/main.rs`
- Modify: `.gitignore`

Create the branch and the crate skeleton: manifest, pinned toolchain, license, a placeholder README, the shared error type, and an empty binary. Every later task builds on these files.

**Interfaces:**
- Consumes: nothing.
- Produces: `op_secretd::error::{Error, Result}` and `impl From<Error> for zbus::fdo::Error`; `Error` variants `Config`, `OpUnavailable`, `OpFailed`, `NotFound`, `NotPermitted`, `NotSupported`, `Invalid`, `Bus`, `NameTaken`, `Internal`.

- [ ] **Step 1: Create a feature branch**

```bash
git switch -c feat/initial-implementation
```

- [ ] **Step 2: Create `Cargo.toml`**

`Cargo.toml`:

```toml
[package]
name = "op-secretd"
version = "0.0.0"
edition = "2024"
rust-version = "1.97"
description = "Freedesktop Secret Service provider backed by 1Password"
license = "MIT"
repository = "https://github.com/e-kulikov/op-secret-service"
publish = false

[lib]
name = "op_secretd"
path = "src/lib.rs"

[[bin]]
name = "op-secretd"
path = "src/main.rs"

[dependencies]
aes = "0.9"
base64 = "0.22"
cbc = { version = "0.2", features = ["alloc"] }
clap = { version = "4", features = ["derive"] }
getrandom = "0.3"
hkdf = "0.13"
num-bigint = "0.5"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.11"
thiserror = "2"
tokio = { version = "1", features = ["rt-multi-thread", "macros", "time", "signal", "process", "sync", "io-util", "fs"] }
toml = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
zbus = { version = "5", default-features = false, features = ["tokio"] }
zeroize = "1"

[dev-dependencies]
tempfile = "3"

[profile.release]
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

- [ ] **Step 3: Create `rust-toolchain.toml`**

`rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.97.1"
components = ["rustfmt", "clippy"]
profile = "minimal"
```

- [ ] **Step 4: Create `LICENSE` (MIT)**

`LICENSE`:

```text
MIT License

Copyright (c) 2026 Evgeny Kulikov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 5: Create a placeholder `README.md` (Task 10 replaces it)**

`README.md`:

```markdown
# op-secretd
```

- [ ] **Step 6: Create `src/error.rs`**

`src/error.rs`:

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("1Password CLI is unavailable: {0}")]
    OpUnavailable(String),
    #[error("1Password CLI failed: {0}")]
    OpFailed(String),
    #[error("item not found")]
    NotFound,
    #[error("not permitted: {0}")]
    NotPermitted(String),
    #[error("not supported: {0}")]
    NotSupported(String),
    #[error("invalid request: {0}")]
    Invalid(String),
    #[error("D-Bus error: {0}")]
    Bus(String),
    #[error("{0}")]
    NameTaken(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for zbus::fdo::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::NotSupported(message) => zbus::fdo::Error::NotSupported(message),
            Error::Invalid(message) => zbus::fdo::Error::InvalidArgs(message),
            other => zbus::fdo::Error::Failed(other.to_string()),
        }
    }
}
```

- [ ] **Step 7: Create `src/lib.rs`**

`src/lib.rs`:

```rust
pub mod error;
```

- [ ] **Step 8: Create a placeholder `src/main.rs`**

`src/main.rs`:

```rust
fn main() {}
```

- [ ] **Step 9: Append the build directory to `.gitignore`**

```bash
printf '/target\n' >>.gitignore
```

- [ ] **Step 10: Build the skeleton**

```bash
cargo build && cargo fmt --check
```
Expected: the crate builds and Cargo creates `Cargo.lock`.

- [ ] **Step 11: Commit**

```bash
git add Cargo.toml Cargo.lock rust-toolchain.toml LICENSE README.md src .gitignore
git commit -m "build: scaffold the op-secretd crate"
```


### Task 1: Attribute identity and the allow list

**Files:**
- Create: `src/attrs.rs`
- Modify: `src/lib.rs`

Secret Service items are identified by their attribute set. This module turns an attribute map into a stable item key and title, matches search queries, and implements the `allow` patterns.

**Interfaces:**
- Consumes: `crate::error::{Error, Result}`.
- Produces: `Attributes = BTreeMap<String, String>`, `TITLE_PREFIX`, `canonical(&Attributes) -> String`, `item_key(&Attributes) -> String` (16 hex digits), `item_title(&Attributes) -> String`, `matches(query, item) -> bool`, `AllowList::{new(&[String]) -> Result<Self>, permits(&Attributes) -> bool}`.

- [ ] **Step 1: Declare the module in `src/lib.rs`**

`src/lib.rs`:

```rust
pub mod attrs;
pub mod error;
```

- [ ] **Step 2: Create `src/attrs.rs` with only the tests**

`src/attrs.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(pairs: &[(&str, &str)]) -> Attributes {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn key_is_stable_and_order_independent() {
        let a = attrs(&[("service", "gh:github.com"), ("username", "")]);
        let b = attrs(&[("username", ""), ("service", "gh:github.com")]);
        assert_eq!(item_key(&a), item_key(&b));
        assert_eq!(item_key(&a).len(), 16);
        assert!(item_key(&a).chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(item_title(&a), format!("secret-service/{}", item_key(&a)));
    }

    #[test]
    fn canonical_form_is_unambiguous() {
        let a = attrs(&[("a", "b=1:c")]);
        let b = attrs(&[("a", "b"), ("1:c", "")]);
        assert_ne!(item_key(&a), item_key(&b));
        assert_ne!(item_key(&attrs(&[])), item_key(&attrs(&[("", "")])));
    }

    #[test]
    fn query_matches_subsets_only() {
        let item = attrs(&[("service", "gh"), ("username", "bob")]);
        assert!(matches(&attrs(&[]), &item));
        assert!(matches(&attrs(&[("service", "gh")]), &item));
        assert!(!matches(&attrs(&[("service", "glab")]), &item));
        assert!(!matches(&attrs(&[("other", "x")]), &item));
    }

    #[test]
    fn allow_list_globs() {
        let list = AllowList::new(&["service=gh:*".into(), "service=glab".into()]).unwrap();
        assert!(list.permits(&attrs(&[("service", "gh:github.com")])));
        assert!(list.permits(&attrs(&[("service", "glab")])));
        assert!(!list.permits(&attrs(&[("service", "glab:x")])));
        assert!(!list.permits(&attrs(&[("username", "gh:x")])));
        assert!(AllowList::default().permits(&attrs(&[])));
        assert!(AllowList::new(&["*=x".into()]).unwrap().patterns.len() == 1);
    }

    #[test]
    fn glob_edge_cases() {
        assert!(glob_match("a*c", "abc"));
        assert!(glob_match("*", ""));
        assert!(glob_match("a*b*c", "aXbYc"));
        assert!(!glob_match("ab*bc", "abc"));
        assert!(!glob_match("a*b*c", "acb"));
    }

    #[test]
    fn allow_list_rejects_bad_patterns() {
        assert!(AllowList::new(&["nokey".into()]).is_err());
        assert!(AllowList::new(&["=x".into()]).is_err());
    }

    #[test]
    fn the_attribute_tag_round_trips_exactly() {
        let odd = attrs(&[
            ("Service", "GitHub.COM:Token"),
            ("empty", ""),
            ("quote", "a\"b\\c,d;e/f"),
            ("a=b", "line\nbreak"),
            ("κλειδί", "τιμή\u{1F512}"),
        ]);
        let tag = attrs_tag(&odd);
        assert!(tag.starts_with("attrs:{"), "{tag}");
        assert!(!tag.contains('\n'), "a tag must stay on one line");
        assert_eq!(parse_attrs_tag(&tag), Some(odd));
        assert_eq!(parse_attrs_tag(&attrs_tag(&attrs(&[]))), Some(attrs(&[])));
    }

    #[test]
    fn the_attribute_tag_is_independent_of_insertion_order() {
        let a = attrs(&[("b", "2"), ("a", "1")]);
        let b = attrs(&[("a", "1"), ("b", "2")]);
        assert_eq!(attrs_tag(&a), attrs_tag(&b));
    }

    #[test]
    fn other_tags_are_not_attribute_tags() {
        assert_eq!(parse_attrs_tag("secret-service"), None);
        assert_eq!(parse_attrs_tag("attrs:not json"), None);
        assert_eq!(parse_attrs_tag("attrs:[1,2]"), None);
        assert_eq!(parse_attrs_tag("xattrs:{}"), None);
    }
}
```

- [ ] **Step 3: Run the tests to see them fail**

```bash
cargo test --lib attrs::
```
Expected: FAIL, a compile error such as `cannot find function ... in this scope` (the implementation does not exist yet).

- [ ] **Step 4: Write the implementation**

Put this above the `#[cfg(test)]` line of `src/attrs.rs` (the file then holds the implementation followed by the tests from Step 2):

```rust
//! Attribute maps, deterministic item identity and the allow list.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Secret Service attributes, sorted by key.
pub type Attributes = BTreeMap<String, String>;

/// Prefix of every item title created by the daemon.
pub const TITLE_PREFIX: &str = "secret-service/";

/// Canonical, unambiguous text form of an attribute set.
pub fn canonical(attributes: &Attributes) -> String {
    let mut out = String::new();
    for (key, value) in attributes {
        out.push_str(&format!(
            "{}:{}={}:{}\n",
            key.len(),
            key,
            value.len(),
            value
        ));
    }
    out
}

/// Stable 16-hex-digit identifier derived from the attributes.
pub fn item_key(attributes: &Attributes) -> String {
    let digest = Sha256::digest(canonical(attributes).as_bytes());
    digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// 1Password item title for an attribute set.
pub fn item_title(attributes: &Attributes) -> String {
    format!("{TITLE_PREFIX}{}", item_key(attributes))
}

/// Prefix of the item tag that carries the attributes.
pub const ATTRS_TAG_PREFIX: &str = "attrs:";

/// The tag that stores the attributes of an item as one line of compact JSON.
///
/// `op item list` returns tags, so a search by a subset of the attributes needs a
/// single listing instead of reading every item.
pub fn attrs_tag(attributes: &Attributes) -> String {
    let json = serde_json::to_string(attributes).expect("a string map serializes");
    format!("{ATTRS_TAG_PREFIX}{json}")
}

/// The attributes stored in `tag`, if it is an attribute tag.
pub fn parse_attrs_tag(tag: &str) -> Option<Attributes> {
    serde_json::from_str(tag.strip_prefix(ATTRS_TAG_PREFIX)?).ok()
}

/// True when every pair of `query` is present in `item`.
pub fn matches(query: &Attributes, item: &Attributes) -> bool {
    query
        .iter()
        .all(|(key, value)| item.get(key) == Some(value))
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let first = parts[0];
    let last = parts[parts.len() - 1];
    if !text.starts_with(first) {
        return false;
    }
    let mut rest = &text[first.len()..];
    for middle in &parts[1..parts.len() - 1] {
        match rest.find(middle) {
            Some(index) => rest = &rest[index + middle.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

/// Patterns of the form `key=glob`; an empty list permits everything.
#[derive(Debug, Clone, Default)]
pub struct AllowList {
    patterns: Vec<(String, String)>,
}

impl AllowList {
    pub fn new(patterns: &[String]) -> Result<Self> {
        let mut parsed = Vec::with_capacity(patterns.len());
        for pattern in patterns {
            let (key, glob) = pattern.split_once('=').ok_or_else(|| {
                Error::Config(format!("allow pattern `{pattern}` must look like key=glob"))
            })?;
            if key.is_empty() {
                return Err(Error::Config(format!(
                    "allow pattern `{pattern}` has an empty key"
                )));
            }
            parsed.push((key.to_owned(), glob.to_owned()));
        }
        Ok(Self { patterns: parsed })
    }

    pub fn permits(&self, attributes: &Attributes) -> bool {
        self.patterns.is_empty()
            || self.patterns.iter().any(|(key, glob)| {
                attributes
                    .get(key)
                    .is_some_and(|value| glob_match(glob, value))
            })
    }
}
```

- [ ] **Step 5: Run the tests to see them pass**

```bash
cargo test --lib attrs::
```
Expected: PASS.

- [ ] **Step 6: Check formatting and lints**

```bash
cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings
```
Expected: no output.

- [ ] **Step 7: Commit**

```bash
git add src/attrs.rs src/lib.rs
git commit -m "feat(attrs): add attribute identity and the allow list"
```


### Task 2: Configuration

**Files:**
- Create: `src/config.rs`
- Modify: `src/lib.rs`

Loads `config.toml`, applies `OP_SECRETD_*` overrides, validates the result, and provides the commented example written by `config init`.

**Interfaces:**
- Consumes: `crate::attrs::AllowList`, `crate::error`.
- Produces: `Config` (fields `vault`, `account`, `mode`, `tag`, `cache_ttl`, `idle_timeout`, `allow`, `log_level`, `op`), `OpConfig`, `Mode::{Auto, App, ServiceAccount}`, `Interop::{Auto, Enabled, Disabled}`, `parse_duration`, `EXAMPLE`, `Config::{from_toml, apply_env, validate, allow_list}`, `default_path(&dyn Fn(&str) -> Option<String>) -> Result<PathBuf>`, `load(&Path, &dyn Fn(&str) -> Option<String>) -> Result<Config>`.

- [ ] **Step 1: Declare the module in `src/lib.rs`**

`src/lib.rs`:

```rust
pub mod attrs;
pub mod config;
pub mod error;
```

- [ ] **Step 2: Create `src/config.rs` with only the tests**

`src/config.rs`:

```rust
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
        assert_eq!(config.idle_timeout, Duration::from_secs(3600));
        assert_eq!(config.op.wsl_interop, Interop::Auto);
    }

    #[test]
    fn the_example_matches_the_defaults() {
        let example = Config::from_toml(EXAMPLE).unwrap();
        let defaults = Config::default();
        assert_eq!(example.cache_ttl, defaults.cache_ttl);
        assert_eq!(example.idle_timeout, defaults.idle_timeout);
        assert_eq!(example.tag, defaults.tag);
        assert_eq!(defaults.idle_timeout, Duration::from_secs(3600));
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
```

- [ ] **Step 3: Run the tests to see them fail**

```bash
cargo test --lib config::
```
Expected: FAIL, a compile error such as `cannot find function ... in this scope` (the implementation does not exist yet).

- [ ] **Step 4: Write the implementation**

Put this above the `#[cfg(test)]` line of `src/config.rs` (the file then holds the implementation followed by the tests from Step 2):

```rust
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
            idle_timeout: Duration::from_secs(3600),
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
idle_timeout = "1h"

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
```

- [ ] **Step 5: Run the tests to see them pass**

```bash
cargo test --lib config::
```
Expected: PASS.

- [ ] **Step 6: Check formatting and lints**

```bash
cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings
```
Expected: no output.

- [ ] **Step 7: Commit**

```bash
git add src/config.rs src/lib.rs
git commit -m "feat(config): load configuration from TOML and the environment"
```


### Task 3: Session encryption

**Files:**
- Create: `src/crypto.rs`
- Modify: `src/lib.rs`

Implements the two session algorithms: `plain`, and `dh-ietf1024-sha256-aes128-cbc-pkcs7` (Diffie-Hellman over the second Oakley group, HKDF-SHA256 with no salt and empty info, AES-128-CBC with PKCS#7 padding). The shared secret is left-padded to 128 bytes before key derivation.

**Interfaces:**
- Consumes: `crate::error`.
- Produces: `ALGORITHM_PLAIN`, `ALGORITHM_DH`, `DhKeypair::{generate() -> Result<Self>, public: Vec<u8>, derive_key(&self, &[u8]) -> Result<Zeroizing<[u8; 16]>>}`, `SessionCipher::{Plain, Aes(Zeroizing<[u8; 16]>)}` with `encrypt(&[u8]) -> Result<(Vec<u8>, Vec<u8>)>` (parameters, value) and `decrypt(&[u8], &[u8]) -> Result<Zeroizing<Vec<u8>>>`, `Negotiated { cipher, output }`, `negotiate(&str, &[u8]) -> Result<Negotiated>`.

- [ ] **Step 1: Declare the module in `src/lib.rs`**

`src/lib.rs`:

```rust
pub mod attrs;
pub mod config;
pub mod crypto;
pub mod error;
```

- [ ] **Step 2: Create `src/crypto.rs` with only the tests**

`src/crypto.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prime_is_a_1024_bit_probable_prime() {
        let p = prime();
        assert_eq!(p.bits(), 1024);
        assert_eq!(
            BigUint::from(2u8).modpow(&(&p - 1u8), &p),
            BigUint::from(1u8)
        );
    }

    #[test]
    fn plain_session_passes_data_through() {
        let negotiated = negotiate(ALGORITHM_PLAIN, b"").unwrap();
        assert!(negotiated.output.is_empty());
        let (parameters, value) = negotiated.cipher.encrypt(b"secret").unwrap();
        assert!(parameters.is_empty());
        assert_eq!(
            &*negotiated.cipher.decrypt(&parameters, &value).unwrap(),
            b"secret"
        );
    }

    #[test]
    fn dh_client_and_server_derive_the_same_key() {
        let client = DhKeypair::generate().unwrap();
        let negotiated = negotiate(ALGORITHM_DH, &client.public).unwrap();
        let client_cipher = SessionCipher::Aes(client.derive_key(&negotiated.output).unwrap());

        let (iv, value) = client_cipher.encrypt(b"top secret").unwrap();
        assert_eq!(iv.len(), 16);
        assert_ne!(value, b"top secret");
        assert_eq!(
            &*negotiated.cipher.decrypt(&iv, &value).unwrap(),
            b"top secret"
        );

        let (iv, value) = negotiated.cipher.encrypt(b"").unwrap();
        assert_eq!(value.len(), 16, "empty plaintext still pads to one block");
        assert!(client_cipher.decrypt(&iv, &value).unwrap().is_empty());
    }

    #[test]
    fn dh_rejects_degenerate_public_keys() {
        assert!(negotiate(ALGORITHM_DH, &[]).is_err());
        assert!(negotiate(ALGORITHM_DH, &[1]).is_err());
        let p_minus_one = to_fixed_be(&(prime() - 1u8));
        assert!(negotiate(ALGORITHM_DH, &p_minus_one).is_err());
        assert!(negotiate(ALGORITHM_DH, &to_fixed_be(&prime())).is_err());
    }

    #[test]
    fn dh_decrypt_rejects_bad_input() {
        let client = DhKeypair::generate().unwrap();
        let negotiated = negotiate(ALGORITHM_DH, &client.public).unwrap();
        assert!(negotiated.cipher.decrypt(&[0u8; 3], &[0u8; 16]).is_err());
        assert!(negotiated.cipher.decrypt(&[0u8; 16], &[0u8; 5]).is_err());
        assert!(negotiated.cipher.decrypt(&[0u8; 16], &[0u8; 16]).is_err());
    }

    #[test]
    fn unknown_algorithm_is_not_supported() {
        let error = negotiate("rot13", b"").err().unwrap();
        assert!(matches!(error, Error::NotSupported(_)));
    }
}
```

- [ ] **Step 3: Run the tests to see them fail**

```bash
cargo test --lib crypto::
```
Expected: FAIL, a compile error such as `cannot find function ... in this scope` (the implementation does not exist yet).

- [ ] **Step 4: Write the implementation**

Put this above the `#[cfg(test)]` line of `src/crypto.rs` (the file then holds the implementation followed by the tests from Step 2):

```rust
//! Secret Service session encryption: `plain` and
//! `dh-ietf1024-sha256-aes128-cbc-pkcs7`.

use aes::Aes128;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use hkdf::Hkdf;
use num_bigint::BigUint;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const ALGORITHM_PLAIN: &str = "plain";
pub const ALGORITHM_DH: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

/// Second Oakley Group (RFC 2409, 1024 bits); the generator is 2.
const PRIME_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";
const PRIME_LEN: usize = 128;

fn prime() -> BigUint {
    BigUint::parse_bytes(PRIME_HEX.as_bytes(), 16).expect("valid prime constant")
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes)
        .map_err(|error| Error::Internal(format!("random source: {error}")))?;
    Ok(bytes)
}

fn to_fixed_be(value: &BigUint) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    let mut out = vec![0u8; PRIME_LEN - bytes.len()];
    out.extend_from_slice(&bytes);
    out
}

/// One side of the Diffie-Hellman exchange.
pub struct DhKeypair {
    private: BigUint,
    pub public: Vec<u8>,
}

impl DhKeypair {
    pub fn generate() -> Result<Self> {
        let p = prime();
        let private = BigUint::from_bytes_be(&random_bytes::<PRIME_LEN>()?) % (&p - 3u8) + 2u8;
        let public = to_fixed_be(&BigUint::from(2u8).modpow(&private, &p));
        Ok(Self { private, public })
    }

    /// Derives the AES key from the peer's public value.
    pub fn derive_key(&self, peer_public: &[u8]) -> Result<Zeroizing<[u8; 16]>> {
        let p = prime();
        let peer = BigUint::from_bytes_be(peer_public);
        if peer <= BigUint::from(1u8) || peer >= &p - 1u8 {
            return Err(Error::Invalid("peer public key is out of range".into()));
        }
        let shared = Zeroizing::new(to_fixed_be(&peer.modpow(&self.private, &p)));
        let mut key = Zeroizing::new([0u8; 16]);
        Hkdf::<Sha256>::new(None, &shared)
            .expand(&[], key.as_mut())
            .map_err(|error| Error::Internal(format!("key derivation: {error}")))?;
        Ok(key)
    }
}

/// The cipher negotiated for one session.
pub enum SessionCipher {
    Plain,
    Aes(Zeroizing<[u8; 16]>),
}

/// Result of `OpenSession`: the cipher and the bytes sent back to the client.
pub struct Negotiated {
    pub cipher: SessionCipher,
    pub output: Vec<u8>,
}

/// Negotiates a session for `algorithm`; `input` is the client's variant payload as bytes.
pub fn negotiate(algorithm: &str, input: &[u8]) -> Result<Negotiated> {
    match algorithm {
        ALGORITHM_PLAIN => Ok(Negotiated {
            cipher: SessionCipher::Plain,
            output: Vec::new(),
        }),
        ALGORITHM_DH => {
            let server = DhKeypair::generate()?;
            let key = server.derive_key(input)?;
            Ok(Negotiated {
                cipher: SessionCipher::Aes(key),
                output: server.public,
            })
        }
        other => Err(Error::NotSupported(format!("session algorithm `{other}`"))),
    }
}

impl SessionCipher {
    /// Returns `(parameters, value)` for a `Secret` structure.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            SessionCipher::Plain => Ok((Vec::new(), plaintext.to_vec())),
            SessionCipher::Aes(key) => {
                let iv = random_bytes::<16>()?;
                let value = cbc::Encryptor::<Aes128>::new(&(**key).into(), &iv.into())
                    .encrypt_padded_vec::<Pkcs7>(plaintext);
                Ok((iv.to_vec(), value))
            }
        }
    }

    pub fn decrypt(&self, parameters: &[u8], value: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            SessionCipher::Plain => Ok(Zeroizing::new(value.to_vec())),
            SessionCipher::Aes(key) => {
                let iv: [u8; 16] = parameters
                    .try_into()
                    .map_err(|_| Error::Invalid("initialization vector must be 16 bytes".into()))?;
                cbc::Decryptor::<Aes128>::new(&(**key).into(), &iv.into())
                    .decrypt_padded_vec::<Pkcs7>(value)
                    .map(Zeroizing::new)
                    .map_err(|_| Error::Invalid("secret could not be decrypted".into()))
            }
        }
    }
}
```

- [ ] **Step 5: Run the tests to see them pass**

```bash
cargo test --lib crypto::
```
Expected: PASS.

- [ ] **Step 6: Check formatting and lints**

```bash
cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings
```
Expected: no output.

- [ ] **Step 7: Commit**

```bash
git add src/crypto.rs src/lib.rs
git commit -m "feat(crypto): add Secret Service session encryption"
```


### Task 4: Running the 1Password CLI

**Files:**
- Create: `src/op.rs`
- Modify: `src/lib.rs`

Chooses how to start `op` (native, Windows `op.exe` through WSL interop, or native `op` with a service account token), runs it with a timeout, classifies its failures, retries transient client errors twice, and keeps the service account token out of arguments and out of unrelated children.

**Interfaces:**
- Consumes: `crate::config::{Config, Interop, Mode}`, `crate::error`.
- Produces: `Probe::real()`, `is_wsl`, `find_op_exe`, `Launch::{Native, Interop, ServiceAccount}`, `resolve(&Config, &Probe) -> Result<Launch>`, `OpRunner::{new(Launch, Option<String>), from_config(&Config, &Probe) -> Result<Self>, describe(&self) -> String, async run(&self, &[&str], Option<&[u8]>) -> Result<Vec<u8>>}`, `normalize_newlines`. `run` returns `Error::NotFound` when `op` reports `isn't an item`, `Error::OpFailed` for other failures, and `Error::OpUnavailable` when the program cannot start.

- [ ] **Step 1: Declare the module in `src/lib.rs`**

`src/lib.rs`:

```rust
pub mod attrs;
pub mod config;
pub mod crypto;
pub mod error;
pub mod op;
```

- [ ] **Step 2: Create `src/op.rs` with only the tests**

`src/op.rs`:

```rust
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
```

- [ ] **Step 3: Run the tests to see them fail**

```bash
cargo test --lib op::
```
Expected: FAIL, a compile error such as `cannot find function ... in this scope` (the implementation does not exist yet).

- [ ] **Step 4: Write the implementation**

Put this above the `#[cfg(test)]` line of `src/op.rs` (the file then holds the implementation followed by the tests from Step 2):

```rust
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
```

- [ ] **Step 5: Run the tests to see them pass**

```bash
cargo test --lib op::
```
Expected: PASS.

- [ ] **Step 6: Check formatting and lints**

```bash
cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings
```
Expected: no output.

- [ ] **Step 7: Commit**

```bash
git add src/op.rs src/lib.rs
git commit -m "feat(op): run the 1Password CLI natively, through WSL, or with a service account"
```


### Task 5: Cache and store

**Files:**
- Create: `tests/fixtures/fake-op.py`, `tests/fake_op.rs`, `src/cache.rs`, `src/store.rs`
- Modify: `src/lib.rs`

Adds the in-memory `TtlCell`, the fake `op` used by every later test, and `Store`, which keeps each secret as a Password item. Because each `op` call costs seconds through Windows, the store counts calls: an exact search reads one item by its title next to one listing, a subset search finds its matches from the `attrs:` tags of that listing and reads only them (four at a time), and everything is cached in memory. The fake `op` is a small Python script that emulates the few `op` commands the daemon uses on a directory of JSON files; creating `$FAKE_OP_DB/FAIL` makes every call fail and `$FAKE_OP_DB/SLOW` (seconds) delays every call.

**Interfaces:**
- Consumes: `crate::op::{OpRunner, Launch}`, `crate::attrs`, `crate::config::Config`, `crate::error`.
- Produces: `TtlCell::{new(Duration), fresh(), current(), set(T), invalidate()}`; `ItemInfo { key, label, attributes }`; `Store::{new(OpRunner, &Config) -> Result<Self>, async search(&Attributes) -> Result<Vec<ItemInfo>>, async info(&str) -> Result<ItemInfo>, async secret(&str) -> Result<(Zeroizing<Vec<u8>>, String)>, async create(Attributes, &str, &[u8], &str, bool) -> Result<ItemInfo>, async set_secret(&str, &[u8], &str) -> Result<()>, async delete(&str) -> Result<()>}`; `tests/fixtures/fake-op.py`.

- [ ] **Step 1: Create the fake `op` and make it executable (`chmod +x tests/fixtures/fake-op.py`)**

`tests/fixtures/fake-op.py`:

```python
#!/usr/bin/env python3
"""A fake 1Password CLI for tests: just enough of `op` for op-secretd.

State lives in $FAKE_OP_DB (items/*.json, calls.log). Creating the file
$FAKE_OP_DB/FAIL makes every call fail like a dismissed approval prompt, and
$FAKE_OP_DB/SLOW (seconds) delays every call like a pending approval.
"""
import atexit
import json
import os
import sys

db = os.environ["FAKE_OP_DB"]
items_dir = os.path.join(db, "items")
os.makedirs(items_dir, exist_ok=True)
args = sys.argv[1:]

with open(os.path.join(db, "calls.log"), "a") as log:
    log.write(" ".join(args) + "\n")


def fail(message):
    sys.stderr.write("[ERROR] 2026/10/05 00:00:00 " + message + "\n")
    sys.exit(1)


if os.path.exists(os.path.join(db, "FAIL")):
    fail("authorization prompt dismissed")

# Record how many fake ops run at the same time (tests read concurrency.log).
running_dir = os.path.join(db, "running")
os.makedirs(running_dir, exist_ok=True)
marker = os.path.join(running_dir, str(os.getpid()))
open(marker, "w").close()
atexit.register(lambda: os.path.exists(marker) and os.remove(marker))
with open(os.path.join(db, "concurrency.log"), "a") as handle:
    handle.write("%d\n" % len(os.listdir(running_dir)))

slow = os.path.join(db, "SLOW")
if os.path.exists(slow):
    import time
    time.sleep(float(open(slow).read() or "1"))

# `FAIL_LIST` makes only `item list` fail, to test paths that must not depend on it.
if args[:2] == ["item", "list"] and os.path.exists(os.path.join(db, "FAIL_LIST")):
    fail("fake: listing is unavailable")

# Drop global flags; remember the interesting ones.
flags = {}
positional = []
i = 0
while i < len(args):
    arg = args[i]
    if arg in ("--vault", "--account", "--tags", "--format"):
        flags[arg] = args[i + 1]
        i += 2
        continue
    if arg == "--archive":
        flags[arg] = True
    else:
        positional.append(arg)
    i += 1

vault = flags.get("--vault", "V")


def path_for(title):
    return os.path.join(items_dir, title.replace("/", "__") + ".json")


def load_all():
    out = []
    for name in sorted(os.listdir(items_dir)):
        with open(os.path.join(items_dir, name)) as handle:
            out.append(json.load(handle))
    return out


def find(reference):
    """An item by title, or by id (the real op accepts both)."""
    path = path_for(reference)
    if os.path.exists(path):
        with open(path) as handle:
            return json.load(handle)
    for item in load_all():
        if item["id"] == reference:
            return item
    fail('"%s" isn\'t an item in the "%s" vault. Specify the item with its UUID, name, or domain.' % (reference, vault))


def counter():
    path = os.path.join(db, "counter")
    value = int(open(path).read()) + 1 if os.path.exists(path) else 1
    with open(path, "w") as handle:
        handle.write(str(value))
    return value


def write(item):
    with open(path_for(item["title"]), "w") as handle:
        json.dump(item, handle)


command = positional[:2]
rest = positional[2:]

if command == ["vault", "get"]:
    name = rest[0]
    if name == "missing":
        fail('"missing" isn\'t a vault in this account.')
    print(json.dumps({"id": "vault-1", "name": name}))
elif command == ["item", "list"]:
    tag = flags.get("--tags")
    listing = [
        {"id": item["id"], "title": item["title"], "tags": item.get("tags", [])}
        for item in load_all()
        if tag is None or tag in item.get("tags", [])
    ]
    print(json.dumps(listing, indent=2))
elif command == ["item", "get"] and rest == ["-"]:
    wanted = json.loads(sys.stdin.read())
    ids = {entry["id"] for entry in wanted}
    for item in load_all():
        if item["id"] in ids:
            print(json.dumps(item, indent=2))
elif command == ["item", "get"]:
    print(json.dumps(find(rest[0]), indent=2))
elif command == ["item", "create"] and rest == ["-"]:
    template = json.loads(sys.stdin.read())
    if os.path.exists(path_for(template["title"])):
        fail("duplicate title " + template["title"])
    for field in template.get("fields", []):
        field.setdefault("id", "f%d" % counter())
    template["id"] = "item%d" % counter()
    template["vault"] = {"name": vault}
    write(template)
    print(json.dumps({"id": template["id"]}))
elif command == ["item", "edit"] and rest[1:] == ["-"]:
    item = find(rest[0])
    template = json.loads(sys.stdin.read())
    # Like the real op: built-in fields (those with a purpose) are updated in
    # place, while the custom fields are replaced by the template's custom fields.
    builtin = [field for field in item["fields"] if field.get("purpose")]
    custom = []
    for incoming in template.get("fields", []):
        if incoming.get("purpose"):
            for field in builtin:
                if field.get("id") == incoming.get("id"):
                    field.update(incoming)
        else:
            incoming.setdefault("id", "f%d" % counter())
            custom.append(incoming)
    item["fields"] = builtin + custom
    write(item)
    print(json.dumps({"id": item["id"]}))
elif command == ["item", "delete"]:
    find(rest[0])
    os.remove(path_for(rest[0]))
else:
    fail("fake op: unsupported command: " + " ".join(args))
```

- [ ] **Step 2: Create `tests/fake_op.rs`, which pins the fake's behavior to what the real `op item edit -` does (it replaces the custom fields instead of merging them; observed against a real vault)**

`tests/fake_op.rs`:

```rust
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

#[test]
fn an_item_can_be_fetched_by_its_id_as_well_as_by_its_title() {
    let dir = tempfile::tempdir().unwrap();
    let created: serde_json::Value = serde_json::from_str(&fake(
        dir.path(),
        &["item", "create", "--vault", "V", "-"],
        Some(CREATE),
    ))
    .unwrap();
    let id = created["id"].as_str().unwrap();
    let by_id: serde_json::Value = serde_json::from_str(&fake(
        dir.path(),
        &["item", "get", id, "--vault", "V", "--format", "json"],
        None,
    ))
    .unwrap();
    assert_eq!(by_id["title"], "t");
}
```

- [ ] **Step 3: Declare the modules in `src/lib.rs`**

`src/lib.rs`:

```rust
pub mod attrs;
pub mod cache;
pub mod config;
pub mod crypto;
pub mod error;
pub mod op;
pub mod store;
```

- [ ] **Step 4: Create `src/cache.rs` with only the tests**

`src/cache.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_is_fresh_until_it_expires() {
        let mut cell = TtlCell::new(Duration::from_millis(40));
        assert!(cell.fresh().is_none());
        cell.set(7);
        assert_eq!(cell.fresh(), Some(&7));
        std::thread::sleep(Duration::from_millis(60));
        assert!(cell.fresh().is_none());
        assert_eq!(cell.current(), Some(&7));
    }

    #[test]
    fn a_fresh_value_can_be_updated_in_place() {
        let mut cell = TtlCell::new(Duration::from_secs(60));
        assert!(cell.fresh_mut().is_none());
        cell.set(vec![1]);
        cell.fresh_mut().unwrap().push(2);
        assert_eq!(cell.fresh(), Some(&vec![1, 2]));
        let mut disabled = TtlCell::new(Duration::ZERO);
        disabled.set(vec![1]);
        assert!(disabled.fresh_mut().is_none());
    }

    #[test]
    fn zero_ttl_disables_caching() {
        let mut cell = TtlCell::new(Duration::ZERO);
        cell.set(1);
        assert!(cell.fresh().is_none());
        assert_eq!(cell.current(), Some(&1));
    }

    #[test]
    fn invalidate_drops_the_value() {
        let mut cell = TtlCell::new(Duration::from_secs(60));
        cell.set(1);
        cell.invalidate();
        assert!(cell.fresh().is_none());
        assert!(cell.current().is_none());
    }
}
```

- [ ] **Step 5: Create `src/store.rs` with only the tests**

`src/store.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::op::Launch;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::Duration;

    const FAKE_OP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/fake-op.py");

    fn attrs(pairs: &[(&str, &str)]) -> Attributes {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn store_in(dir: &Path, mutate: impl FnOnce(&mut Config)) -> Store {
        let wrapper = dir.join("op");
        let db = dir.join("db");
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nFAKE_OP_DB='{}' exec python3 '{}' \"$@\"\n",
                db.display(),
                FAKE_OP
            ),
        )
        .unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut config = Config {
            vault: "V".into(),
            cache_ttl: Duration::from_secs(60),
            ..Config::default()
        };
        mutate(&mut config);
        Store::new(OpRunner::new(Launch::Native(wrapper), None), &config).unwrap()
    }

    fn calls(dir: &Path) -> Vec<String> {
        std::fs::read_to_string(dir.join("db/calls.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[tokio::test]
    async fn create_search_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), |_| {});
        let a = attrs(&[("service", "gh:github.com"), ("username", "bob")]);
        let info = store
            .create(a.clone(), "gh token", b"s3cret", "text/plain", false)
            .await
            .unwrap();
        assert_eq!(info.key, item_key(&a));

        let found = store
            .search(&attrs(&[("service", "gh:github.com")]))
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].label, "gh token");
        assert_eq!(found[0].attributes, a);
        assert!(
            store
                .search(&attrs(&[("service", "other")]))
                .await
                .unwrap()
                .is_empty()
        );

        let (secret, content_type) = store.secret(&info.key).await.unwrap();
        assert_eq!(&*secret, b"s3cret");
        assert_eq!(content_type, "text/plain");
    }

    #[tokio::test]
    async fn empty_attribute_values_survive() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), |_| {});
        let a = attrs(&[("service", "gh"), ("username", "")]);
        store
            .create(a.clone(), "", b"x", "text/plain", false)
            .await
            .unwrap();
        let found = store.search(&attrs(&[("username", "")])).await.unwrap();
        assert_eq!(found[0].attributes, a);
    }

    #[tokio::test]
    async fn odd_attribute_values_survive() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), |_| {});
        let odd = attrs(&[
            ("a=b", "line\nbreak"),
            ("κλειδί", "τιμή\u{1F512}"),
            ("empty", ""),
            ("quote", "\"'\\"),
        ]);
        let key = store
            .create(odd.clone(), "odd", b"x", "text/plain", false)
            .await
            .unwrap()
            .key;
        assert_eq!(store.info(&key).await.unwrap().attributes, odd);
        assert_eq!(
            store
                .search(&attrs(&[("κλειδί", "τιμή\u{1F512}")]))
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn empty_secrets_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), |_| {});
        let key = store
            .create(attrs(&[("k", "v")]), "", b"", "text/plain", false)
            .await
            .unwrap()
            .key;
        assert!(store.secret(&key).await.unwrap().0.is_empty());
    }

    #[tokio::test]
    async fn binary_secrets_roundtrip_through_base64() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), |_| {});
        let key = store
            .create(
                attrs(&[("k", "v")]),
                "bin",
                &[0xff, 0x00, 0xfe],
                "application/octet-stream",
                false,
            )
            .await
            .unwrap()
            .key;
        let (secret, content_type) = store.secret(&key).await.unwrap();
        assert_eq!(&*secret, &[0xff, 0x00, 0xfe]);
        assert_eq!(content_type, "application/octet-stream");
    }

    #[tokio::test]
    async fn replace_updates_in_place_and_without_replace_keeps_the_old_value() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), |_| {});
        let a = attrs(&[("k", "v")]);
        let key = store
            .create(a.clone(), "one", b"1", "text/plain", false)
            .await
            .unwrap()
            .key;
        store
            .create(a.clone(), "two", b"2", "text/plain", false)
            .await
            .unwrap();
        assert_eq!(&*store.secret(&key).await.unwrap().0, b"1");
        store
            .create(a.clone(), "two", b"2", "text/plain", true)
            .await
            .unwrap();
        assert_eq!(&*store.secret(&key).await.unwrap().0, b"2");
        assert_eq!(store.info(&key).await.unwrap().label, "two");
        assert_eq!(store.search(&attrs(&[])).await.unwrap().len(), 1);
        store.set_secret(&key, b"3", "text/plain").await.unwrap();
        assert_eq!(&*store.secret(&key).await.unwrap().0, b"3");
    }

    #[tokio::test]
    async fn delete_removes_the_item() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), |_| {});
        let key = store
            .create(attrs(&[("k", "v")]), "x", b"1", "text/plain", false)
            .await
            .unwrap()
            .key;
        store.delete(&key).await.unwrap();
        assert!(matches!(store.info(&key).await, Err(Error::NotFound)));
        assert!(matches!(store.delete(&key).await, Err(Error::NotFound)));
        assert!(
            calls(dir.path())
                .iter()
                .any(|c| c.starts_with("item delete") && c.contains("--archive"))
        );
    }

    #[tokio::test]
    async fn the_index_is_cached_until_a_write() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), |_| {});
        store.search(&attrs(&[])).await.unwrap();
        store.search(&attrs(&[])).await.unwrap();
        let lists = || {
            calls(dir.path())
                .iter()
                .filter(|c| c.starts_with("item list"))
                .count()
        };
        assert_eq!(lists(), 1);
        store
            .create(attrs(&[("k", "v")]), "x", b"1", "text/plain", false)
            .await
            .unwrap();
        store.search(&attrs(&[])).await.unwrap();
        assert_eq!(
            lists(),
            2,
            "the write reuses the cached index and then invalidates it"
        );
    }

    #[tokio::test]
    async fn zero_ttl_reloads_every_time() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), |c| c.cache_ttl = Duration::ZERO);
        store.search(&attrs(&[])).await.unwrap();
        store.search(&attrs(&[])).await.unwrap();
        assert_eq!(
            calls(dir.path())
                .iter()
                .filter(|c| c.starts_with("item list"))
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn allow_list_blocks_writes_and_hides_other_items() {
        let dir = tempfile::tempdir().unwrap();
        let open = store_in(dir.path(), |_| {});
        open.create(
            attrs(&[("service", "other")]),
            "x",
            b"1",
            "text/plain",
            false,
        )
        .await
        .unwrap();
        let strict = store_in(dir.path(), |c| c.allow = vec!["service=gh:*".into()]);
        let denied = strict
            .create(
                attrs(&[("service", "other")]),
                "y",
                b"2",
                "text/plain",
                false,
            )
            .await;
        assert!(matches!(denied, Err(Error::NotPermitted(_))));
        assert!(strict.search(&attrs(&[])).await.unwrap().is_empty());
        strict
            .create(
                attrs(&[("service", "gh:x")]),
                "z",
                b"3",
                "text/plain",
                false,
            )
            .await
            .unwrap();
        assert_eq!(strict.search(&attrs(&[])).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn failures_are_errors_not_empty_results() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), |c| c.cache_ttl = Duration::ZERO);
        store
            .create(attrs(&[("k", "v")]), "x", b"1", "text/plain", false)
            .await
            .unwrap();
        std::fs::write(dir.path().join("db/FAIL"), "").unwrap();
        assert!(matches!(
            store.search(&attrs(&[])).await,
            Err(Error::OpFailed(_))
        ));
        assert!(store.secret("0000000000000000").await.is_err());
    }

    #[tokio::test]
    async fn foreign_and_tampered_items_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), |_| {});
        let items = dir.path().join("db/items");
        std::fs::create_dir_all(&items).unwrap();
        std::fs::write(
            items.join("foreign.json"),
            r#"{"id":"1","title":"Some login","tags":["secret-service"],"fields":[]}"#,
        )
        .unwrap();
        std::fs::write(
            items.join("tampered.json"),
            r#"{"id":"2","title":"secret-service/0000000000000000","tags":["secret-service"],"fields":[{"id":"x","label":"attributes","value":"{\"a\":\"b\"}"}]}"#,
        )
        .unwrap();
        assert!(store.search(&attrs(&[])).await.unwrap().is_empty());
    }

    #[test]
    fn json_stream_accepts_arrays_and_concatenated_objects() {
        assert_eq!(
            parse_json_stream(b"[{\"a\":1},{\"a\":2}]").unwrap().len(),
            2
        );
        assert_eq!(
            parse_json_stream(b"{\"a\":1}\n{\"a\":2}\n").unwrap().len(),
            2
        );
        assert!(parse_json_stream(b"").unwrap().is_empty());
        assert!(parse_json_stream(b"{oops").is_err());
    }

    fn reset_calls(dir: &Path) {
        let _ = std::fs::remove_file(dir.join("db/calls.log"));
    }

    fn gh_attrs() -> Attributes {
        attrs(&[("service", "gh:github.com"), ("username", "bob")])
    }

    /// A vault with some noise and one `gh` item, read through a store that has never loaded anything.
    async fn vault_with_a_gh_item(dir: &Path) -> (String, Store) {
        let writer = store_in(dir, |_| {});
        for n in 0..3 {
            let noise = attrs(&[("service", "other"), ("n", &n.to_string())]);
            writer
                .create(noise, "noise", b"x", "text/plain", false)
                .await
                .unwrap();
        }
        let key = writer
            .create(gh_attrs(), "gh", b"tok", "text/plain", false)
            .await
            .unwrap()
            .key;
        reset_calls(dir);
        (key, store_in(dir, |_| {}))
    }

    #[tokio::test]
    async fn an_exact_search_on_a_cold_store_reads_one_item() {
        let dir = tempfile::tempdir().unwrap();
        let (key, cold) = vault_with_a_gh_item(dir.path()).await;

        let found = cold.search(&gh_attrs()).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].key, key);
        let log = calls(dir.path());
        assert_eq!(
            count(&log, "item get"),
            1,
            "only the exact item is read: {log:?}"
        );
        assert!(
            log.iter()
                .any(|call| call.starts_with(&format!("item get secret-service/{key}"))),
            "{log:?}"
        );
        assert!(count(&log, "item list") <= 1, "{log:?}");

        assert_eq!(&*cold.secret(&key).await.unwrap().0, b"tok");
        assert_eq!(
            calls(dir.path()).len(),
            log.len(),
            "the secret needs no further call"
        );
    }

    #[tokio::test]
    async fn a_cold_secret_or_info_lookup_by_key_reads_one_item() {
        let dir = tempfile::tempdir().unwrap();
        let (key, cold) = vault_with_a_gh_item(dir.path()).await;
        assert_eq!(cold.info(&key).await.unwrap().attributes, gh_attrs());
        assert_eq!(&*cold.secret(&key).await.unwrap().0, b"tok");
        let log = calls(dir.path());
        assert_eq!(log.len(), 1, "{log:?}");
        assert!(matches!(
            cold.info("0000000000000000").await,
            Err(Error::NotFound)
        ));
        assert_eq!(
            calls(dir.path()).len(),
            2,
            "an unknown key costs one more read, not a scan"
        );
    }

    #[tokio::test]
    async fn a_subset_search_on_a_cold_store_finds_items_with_more_attributes() {
        let dir = tempfile::tempdir().unwrap();
        let writer = store_in(dir.path(), |_| {});
        let superset = attrs(&[
            ("service", "gh:github.com"),
            ("username", "bob"),
            ("extra", "x"),
        ]);
        writer
            .create(superset.clone(), "gh", b"tok", "text/plain", false)
            .await
            .unwrap();
        reset_calls(dir.path());

        let cold = store_in(dir.path(), |_| {});
        let found = cold.search(&gh_attrs()).await.unwrap();
        assert_eq!(
            found.len(),
            1,
            "a partial query still finds items with more attributes"
        );
        assert_eq!(found[0].attributes, superset);
        let log = calls(dir.path());
        assert!(
            log.iter().any(|call| call.starts_with("item list")),
            "{log:?}"
        );

        let before = calls(dir.path()).len();
        cold.search(&gh_attrs()).await.unwrap();
        assert_eq!(
            calls(dir.path()).len(),
            before,
            "the loaded index answers the repeat"
        );
    }

    #[tokio::test]
    async fn the_fast_path_respects_the_allow_list() {
        let dir = tempfile::tempdir().unwrap();
        let writer = store_in(dir.path(), |_| {});
        writer
            .create(gh_attrs(), "gh", b"tok", "text/plain", false)
            .await
            .unwrap();
        let strict = store_in(dir.path(), |c| c.allow = vec!["service=glab".into()]);
        assert!(strict.search(&gh_attrs()).await.unwrap().is_empty());
        let key = item_key(&gh_attrs());
        assert!(matches!(strict.secret(&key).await, Err(Error::NotFound)));
    }

    #[tokio::test]
    async fn writes_on_a_cold_store_do_not_load_the_whole_vault() {
        let dir = tempfile::tempdir().unwrap();
        let (_, cold) = vault_with_a_gh_item(dir.path()).await;

        cold.create(
            attrs(&[("service", "new")]),
            "new",
            b"1",
            "text/plain",
            false,
        )
        .await
        .unwrap();
        let log = calls(dir.path());
        assert_eq!(log.len(), 2, "one existence check and one create: {log:?}");
        assert!(log[0].starts_with("item get"), "{log:?}");
        assert!(log[1].starts_with("item create"), "{log:?}");

        reset_calls(dir.path());
        cold.create(gh_attrs(), "gh", b"tok2", "text/plain", true)
            .await
            .unwrap();
        let log = calls(dir.path());
        assert!(
            log.iter().all(|call| !call.starts_with("item list")),
            "{log:?}"
        );
        assert!(
            log.iter().any(|call| call.starts_with("item edit")),
            "{log:?}"
        );
    }

    #[tokio::test]
    async fn concurrent_exact_searches_share_one_read() {
        let dir = tempfile::tempdir().unwrap();
        let (_, cold) = vault_with_a_gh_item(dir.path()).await;
        let cold = std::sync::Arc::new(cold);
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..6 {
            let store = cold.clone();
            tasks.spawn(async move { store.search(&gh_attrs()).await.unwrap().len() });
        }
        while let Some(found) = tasks.join_next().await {
            assert_eq!(found.unwrap(), 1);
        }
        let log = calls(dir.path());
        assert_eq!(count(&log, "item get"), 1, "one shared read: {log:?}");
        assert_eq!(count(&log, "item list"), 1, "one shared listing: {log:?}");
    }

    #[tokio::test]
    async fn the_index_is_loaded_with_parallel_reads_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let writer = store_in(dir.path(), |_| {});
        for n in 0..6 {
            let a = attrs(&[("service", "bulk"), ("n", &n.to_string())]);
            writer
                .create(a, "bulk", b"x", "text/plain", false)
                .await
                .unwrap();
        }
        reset_calls(dir.path());
        std::fs::write(dir.path().join("db/SLOW"), "0.5").unwrap();

        let cold = store_in(dir.path(), |_| {});
        let started = std::time::Instant::now();
        assert_eq!(cold.search(&attrs(&[])).await.unwrap().len(), 6);
        let elapsed = started.elapsed();

        // Serial reads would need 0.5 s for the list plus 6 x 0.5 s for the items.
        assert!(elapsed < Duration::from_millis(2400), "took {elapsed:?}");
        let log = calls(dir.path());
        assert!(
            log.iter().all(|call| !call.starts_with("item get -")),
            "{log:?}"
        );
        assert_eq!(
            log.iter()
                .filter(|call| call.starts_with("item get"))
                .count(),
            6
        );
    }

    #[tokio::test]
    async fn the_index_never_runs_more_than_four_reads_at_once() {
        // The 1Password app rejects bursts: eight parallel `op.exe` calls made half of them fail.
        let dir = tempfile::tempdir().unwrap();
        let writer = store_in(dir.path(), |_| {});
        for n in 0..10 {
            let a = attrs(&[("service", "bulk"), ("n", &n.to_string())]);
            writer
                .create(a, "bulk", b"x", "text/plain", false)
                .await
                .unwrap();
        }
        let _ = std::fs::remove_file(dir.path().join("db/concurrency.log"));
        std::fs::write(dir.path().join("db/SLOW"), "0.4").unwrap();

        let cold = store_in(dir.path(), |_| {});
        assert_eq!(cold.search(&attrs(&[])).await.unwrap().len(), 10);

        let peak = std::fs::read_to_string(dir.path().join("db/concurrency.log"))
            .unwrap()
            .lines()
            .map(|line| line.parse::<usize>().unwrap())
            .max()
            .unwrap();
        assert!((2..=4).contains(&peak), "peak concurrency was {peak}");
    }

    fn count(log: &[String], prefix: &str) -> usize {
        log.iter().filter(|call| call.starts_with(prefix)).count()
    }

    #[tokio::test]
    async fn items_are_tagged_with_their_attributes() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), |_| {});
        let a = attrs(&[("service", "gh"), ("username", "")]);
        let key = store
            .create(a.clone(), "x", b"1", "text/plain", false)
            .await
            .unwrap()
            .key;
        let raw = std::fs::read_to_string(
            dir.path()
                .join(format!("db/items/secret-service__{key}.json")),
        )
        .unwrap();
        let item: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let tags: Vec<&str> = item["tags"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t.as_str())
            .collect();
        assert!(tags.contains(&"secret-service"), "{tags:?}");
        assert!(tags.contains(&attrs_tag(&a).as_str()), "{tags:?}");
    }

    #[tokio::test]
    async fn a_subset_search_lists_once_and_reads_only_the_matches() {
        let dir = tempfile::tempdir().unwrap();
        let writer = store_in(dir.path(), |_| {});
        for n in 0..5 {
            let noise = attrs(&[("service", "other"), ("n", &n.to_string())]);
            writer
                .create(noise, "noise", b"x", "text/plain", false)
                .await
                .unwrap();
        }
        let superset = attrs(&[
            ("application", "py"),
            ("service", "gh"),
            ("username", "bob"),
        ]);
        writer
            .create(superset.clone(), "gh", b"tok", "text/plain", false)
            .await
            .unwrap();
        reset_calls(dir.path());

        let cold = store_in(dir.path(), |_| {});
        let query = attrs(&[("service", "gh"), ("username", "bob")]);
        let found = cold.search(&query).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].attributes, superset);
        let log = calls(dir.path());
        assert_eq!(count(&log, "item list"), 1, "{log:?}");
        assert_eq!(
            count(&log, "item get"),
            2,
            "the exact try and the one match: {log:?}"
        );
        assert_eq!(&*cold.secret(&found[0].key).await.unwrap().0, b"tok");
        assert_eq!(
            count(&calls(dir.path()), "item get"),
            2,
            "the match is cached"
        );
    }

    #[tokio::test]
    async fn a_search_without_matches_costs_one_exact_read_and_one_listing() {
        let dir = tempfile::tempdir().unwrap();
        let (_, cold) = vault_with_a_gh_item(dir.path()).await;
        let none = attrs(&[("service", "nothing-like-this")]);
        assert!(cold.search(&none).await.unwrap().is_empty());
        let log = calls(dir.path());
        assert_eq!(count(&log, "item list"), 1, "{log:?}");
        assert_eq!(count(&log, "item get"), 1, "{log:?}");
        assert!(cold.search(&none).await.unwrap().is_empty());
        assert_eq!(
            calls(dir.path()).len(),
            log.len(),
            "the repeat is served from memory"
        );
    }

    #[tokio::test]
    async fn an_exact_hit_does_not_depend_on_the_listing() {
        let dir = tempfile::tempdir().unwrap();
        let (_, cold) = vault_with_a_gh_item(dir.path()).await;
        std::fs::write(dir.path().join("db/FAIL_LIST"), "").unwrap();
        assert_eq!(cold.search(&gh_attrs()).await.unwrap().len(), 1);
        let other = attrs(&[("service", "nothing-like-this")]);
        assert!(
            cold.search(&other).await.is_err(),
            "a miss must not be answered as empty when the listing failed"
        );
    }

    #[tokio::test]
    async fn the_attribute_filter_ignores_items_outside_the_allow_list() {
        let dir = tempfile::tempdir().unwrap();
        let writer = store_in(dir.path(), |_| {});
        let hidden = attrs(&[("service", "gh"), ("username", "bob"), ("extra", "x")]);
        writer
            .create(hidden, "gh", b"tok", "text/plain", false)
            .await
            .unwrap();
        let strict = store_in(dir.path(), |c| c.allow = vec!["service=glab".into()]);
        assert!(strict.search(&gh_attrs()).await.unwrap().is_empty());
    }
}
```

- [ ] **Step 6: Run the tests to see them fail**

```bash
cargo test --lib -- cache:: store::
```
Expected: FAIL, compile errors (`TtlCell`, `Store` not found).

- [ ] **Step 7: Write the implementation of `TtlCell`**

Put this above the `#[cfg(test)]` line of `src/cache.rs`:

```rust
//! A single value that expires after a time-to-live. Memory only.

use std::time::{Duration, Instant};

pub struct TtlCell<T> {
    ttl: Duration,
    value: Option<(Instant, T)>,
}

impl<T> TtlCell<T> {
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, value: None }
    }

    /// The value, unless it is missing, expired, or caching is disabled (`ttl == 0`).
    pub fn fresh(&self) -> Option<&T> {
        match &self.value {
            Some((stored, value)) if !self.ttl.is_zero() && stored.elapsed() < self.ttl => {
                Some(value)
            }
            _ => None,
        }
    }

    /// Mutable access to the value while it is still fresh.
    pub fn fresh_mut(&mut self) -> Option<&mut T> {
        match &mut self.value {
            Some((stored, value)) if !self.ttl.is_zero() && stored.elapsed() < self.ttl => {
                Some(value)
            }
            _ => None,
        }
    }

    /// The stored value regardless of its age; used right after `set`.
    pub fn current(&self) -> Option<&T> {
        self.value.as_ref().map(|(_, value)| value)
    }

    pub fn set(&mut self, value: T) {
        self.value = Some((Instant::now(), value));
    }

    pub fn invalidate(&mut self) {
        self.value = None;
    }
}
```

- [ ] **Step 8: Write the implementation of `Store`**

Put this above the `#[cfg(test)]` line of `src/store.rs`. Reads load the whole tagged set with two `op` calls and cache it; writes address an item by its deterministic title and invalidate the cache:

```rust
//! Secrets as 1Password items. One secret is one Password item whose title is
//! derived from its attributes (see `attrs`). Reads load the whole tagged index
//! with two `op` calls and cache it in memory; writes address items by title.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
use zeroize::Zeroizing;

use crate::attrs::{
    AllowList, Attributes, TITLE_PREFIX, attrs_tag, item_key, item_title, matches, parse_attrs_tag,
};
use crate::cache::TtlCell;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::op::OpRunner;

const FIELD_PASSWORD: &str = "password";
const FIELD_LABEL: &str = "label";
const FIELD_CONTENT_TYPE: &str = "content_type";
const FIELD_ENCODING: &str = "encoding";
const FIELD_ATTRIBUTES: &str = "attributes";

/// Public description of a stored secret (no secret value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemInfo {
    pub key: String,
    pub label: String,
    pub attributes: Attributes,
}

#[derive(Clone)]
struct Record {
    info: ItemInfo,
    secret: Zeroizing<Vec<u8>>,
    content_type: String,
    /// 1Password field ids by field label, needed to edit fields in place.
    field_ids: HashMap<String, String>,
}

type Index = BTreeMap<String, Record>;
type Singles = HashMap<String, Option<Record>>;

/// One line of `op item list`: enough to filter by attributes without reading the item.
#[derive(Clone)]
struct Entry {
    id: String,
    key: String,
    attributes: Option<Attributes>,
}

/// How many `op item get` processes run at once while the index loads. The
/// 1Password app rejects bursts: with eight at once about half of the calls failed.
const PARALLEL_READS: usize = 4;

#[derive(Deserialize)]
struct RawField {
    #[serde(default)]
    id: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Deserialize)]
struct RawItem {
    title: String,
    #[serde(default)]
    fields: Vec<RawField>,
}

/// `op` prints either one JSON array or several concatenated JSON values.
fn parse_json_stream(bytes: &[u8]) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for value in serde_json::Deserializer::from_slice(bytes).into_iter::<Value>() {
        match value
            .map_err(|error| Error::OpFailed(format!("unexpected output from op: {error}")))?
        {
            Value::Array(items) => out.extend(items),
            other => out.push(other),
        }
    }
    Ok(out)
}

/// One item as printed by `op item get`.
fn parse_item(bytes: &[u8]) -> Result<Option<Record>> {
    let Some(value) = parse_json_stream(bytes)?.pop() else {
        return Ok(None);
    };
    let raw: RawItem = serde_json::from_value(value)
        .map_err(|error| Error::OpFailed(format!("unexpected item shape: {error}")))?;
    Ok(record_from(raw))
}

fn record_from(raw: RawItem) -> Option<Record> {
    let key = raw.title.strip_prefix(TITLE_PREFIX)?.to_owned();
    let mut values: HashMap<&str, &str> = HashMap::new();
    let mut field_ids = HashMap::new();
    for field in &raw.fields {
        let name = if field.label.is_empty() {
            field.id.as_str()
        } else {
            field.label.as_str()
        };
        values.insert(name, field.value.as_deref().unwrap_or(""));
        field_ids.insert(name.to_owned(), field.id.clone());
    }
    let attributes: Attributes = serde_json::from_str(values.get(FIELD_ATTRIBUTES)?).ok()?;
    if item_key(&attributes) != key {
        tracing::warn!(title = %raw.title, "ignoring item whose title does not match its attributes");
        return None;
    }
    let text = values.get(FIELD_PASSWORD).copied().unwrap_or("");
    let secret = if values.get(FIELD_ENCODING) == Some(&"base64") {
        STANDARD.decode(text).ok()?
    } else {
        text.as_bytes().to_vec()
    };
    let content_type = values
        .get(FIELD_CONTENT_TYPE)
        .copied()
        .unwrap_or("text/plain")
        .to_owned();
    let label = values.get(FIELD_LABEL).copied().unwrap_or("").to_owned();
    Some(Record {
        info: ItemInfo {
            key,
            label,
            attributes,
        },
        secret: Zeroizing::new(secret),
        content_type,
        field_ids,
    })
}

fn secret_fields(secret: &[u8]) -> (String, &'static str) {
    match std::str::from_utf8(secret) {
        Ok(text) => (text.to_owned(), "utf-8"),
        Err(_) => (STANDARD.encode(secret), "base64"),
    }
}

/// Fields of an item template; `ids` supplies existing field ids when editing.
///
/// An edit must always send the complete set: the real `op item edit <item> -`
/// replaces the custom fields with those of the template instead of merging
/// them, so a partial template silently drops the rest (observed against a real
/// vault, and mirrored by the fake `op` used in the tests).
fn fields_json(
    label: &str,
    attributes: &Attributes,
    secret: &[u8],
    content_type: &str,
    ids: &HashMap<String, String>,
) -> Result<Vec<Value>> {
    let (text, encoding) = secret_fields(secret);
    let attributes_json =
        serde_json::to_string(attributes).map_err(|error| Error::Internal(error.to_string()))?;
    let field = |name: &str, kind: &str, value: String| {
        let mut field = json!({ "label": name, "type": kind, "value": value });
        if let Some(id) = ids.get(name) {
            field["id"] = json!(id);
        }
        field
    };
    let mut password = field(FIELD_PASSWORD, "CONCEALED", text);
    password["id"] = json!(FIELD_PASSWORD);
    password["purpose"] = json!("PASSWORD");
    Ok(vec![
        password,
        field(FIELD_LABEL, "STRING", label.to_owned()),
        field(FIELD_CONTENT_TYPE, "STRING", content_type.to_owned()),
        field(FIELD_ENCODING, "STRING", encoding.to_owned()),
        field(FIELD_ATTRIBUTES, "STRING", attributes_json),
    ])
}

pub struct Store {
    op: Arc<OpRunner>,
    vault: String,
    tag: String,
    allow: AllowList,
    /// Every item of the tagged set, loaded on demand.
    index: Mutex<TtlCell<Index>>,
    /// The listing of the tagged set: ids, keys, and attributes taken from the tags.
    listing: Mutex<TtlCell<Vec<Entry>>>,
    /// Single items read by key (`None` remembers that the item does not exist).
    singles: Mutex<TtlCell<Singles>>,
    write_lock: Mutex<()>,
}

impl Store {
    pub fn new(op: OpRunner, config: &Config) -> Result<Self> {
        Ok(Self {
            op: Arc::new(op),
            vault: config.vault.clone(),
            tag: config.tag.clone(),
            allow: config.allow_list()?,
            index: Mutex::new(TtlCell::new(config.cache_ttl)),
            listing: Mutex::new(TtlCell::new(config.cache_ttl)),
            singles: Mutex::new(TtlCell::new(config.cache_ttl)),
            write_lock: Mutex::new(()),
        })
    }

    /// One `op item list` for the tagged set. It is shared by concurrent callers
    /// and cached; the attributes come from the `attrs:` tag, so no item is read.
    async fn entries(&self) -> Result<Vec<Entry>> {
        let mut cell = self.listing.lock().await;
        if cell.fresh().is_none() {
            let output = self
                .op
                .run(
                    &[
                        "item",
                        "list",
                        "--vault",
                        &self.vault,
                        "--tags",
                        &self.tag,
                        "--format",
                        "json",
                    ],
                    None,
                )
                .await?;
            let mut entries = Vec::new();
            for item in parse_json_stream(&output)? {
                let (Some(id), Some(title)) = (item["id"].as_str(), item["title"].as_str()) else {
                    continue;
                };
                let Some(key) = title.strip_prefix(TITLE_PREFIX) else {
                    continue;
                };
                let attributes = item["tags"].as_array().and_then(|tags| {
                    tags.iter()
                        .filter_map(|tag| tag.as_str())
                        .find_map(parse_attrs_tag)
                });
                entries.push(Entry {
                    id: id.to_owned(),
                    key: key.to_owned(),
                    attributes,
                });
            }
            cell.set(entries);
        }
        Ok(cell.current().expect("the listing was just stored").clone())
    }

    /// Reads items by id, at most `PARALLEL_READS` at a time. An item deleted
    /// since the listing is skipped; any other failure aborts the rest.
    async fn read_items(&self, ids: Vec<String>) -> Result<Vec<Record>> {
        let limit = Arc::new(Semaphore::new(PARALLEL_READS));
        let mut tasks = JoinSet::new();
        for id in ids {
            let (op, vault, limit) = (self.op.clone(), self.vault.clone(), limit.clone());
            tasks.spawn(async move {
                let _permit = limit
                    .acquire_owned()
                    .await
                    .expect("the semaphore stays open");
                op.run(
                    &["item", "get", &id, "--vault", &vault, "--format", "json"],
                    None,
                )
                .await
            });
        }
        let mut records = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            let output = match joined.map_err(|error| Error::Internal(error.to_string()))? {
                Ok(output) => output,
                Err(Error::NotFound) => continue,
                Err(error) => return Err(error),
            };
            if let Some(record) = parse_item(&output)?
                && self.allow.permits(&record.info.attributes)
            {
                records.push(record);
            }
        }
        Ok(records)
    }

    /// Loads the whole tagged set: the listing, then every item.
    async fn load_index(&self) -> Result<Index> {
        let ids = self.entries().await?.into_iter().map(|e| e.id).collect();
        Ok(self
            .read_items(ids)
            .await?
            .into_iter()
            .map(|record| (record.info.key.clone(), record))
            .collect())
    }

    /// Keeps records that were read for a search, so a following `secret` needs no call.
    async fn remember(&self, records: &[Record]) {
        let mut singles = self.singles.lock().await;
        if singles.fresh().is_none() {
            singles.set(Singles::new());
        }
        if let Some(map) = singles.fresh_mut() {
            for record in records {
                map.insert(record.info.key.clone(), Some(record.clone()));
            }
        }
    }

    /// A search on a cold store: the item with exactly these attributes, else
    /// every item whose attributes contain them.
    async fn search_cold(&self, query: &Attributes) -> Result<Vec<ItemInfo>> {
        let key = item_key(query);
        // The exact read and the listing run side by side; the listing only
        // matters on a miss, and each call costs seconds through Windows.
        let (exact, entries) = tokio::join!(self.fetch_one(&key), self.entries());
        if let Some(record) = exact? {
            return Ok(vec![record.info]);
        }
        let candidates: Vec<Entry> = entries?
            .into_iter()
            .filter(|entry| {
                entry.key != key
                    && entry
                        .attributes
                        .as_ref()
                        .is_some_and(|a| matches(query, a) && self.allow.permits(a))
            })
            .collect();
        // Items read earlier are reused; only the others cost a call.
        let mut records = Vec::new();
        let mut missing = Vec::new();
        {
            let singles = self.singles.lock().await;
            for entry in candidates {
                match singles.fresh().and_then(|map| map.get(&entry.key)) {
                    Some(Some(record)) => records.push(record.clone()),
                    _ => missing.push(entry.id),
                }
            }
        }
        let fetched = self.read_items(missing).await?;
        self.remember(&fetched).await;
        records.extend(fetched);
        records.retain(|record| matches(query, &record.info.attributes));
        let mut found: Vec<ItemInfo> = records.into_iter().map(|record| record.info).collect();
        found.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(found)
    }

    async fn with_index<T>(&self, f: impl FnOnce(&Index) -> T) -> Result<T> {
        let mut cell = self.index.lock().await;
        if cell.fresh().is_none() {
            let index = self.load_index().await?;
            cell.set(index);
        }
        Ok(f(cell.current().expect("index was just stored")))
    }

    fn index_is_fresh(&self) -> bool {
        self.index
            .try_lock()
            .is_ok_and(|cell| cell.fresh().is_some())
    }

    /// One item by key. The title is derived from the key, so this is a single
    /// `op item get` instead of a scan of the vault.
    async fn fetch_one(&self, key: &str) -> Result<Option<Record>> {
        // A fresh index is authoritative; a busy one must not delay this read.
        if let Ok(cell) = self.index.try_lock()
            && let Some(index) = cell.fresh()
        {
            return Ok(index.get(key).cloned());
        }
        let mut singles = self.singles.lock().await;
        if let Some(entry) = singles.fresh().and_then(|map| map.get(key)) {
            return Ok(entry.clone());
        }
        let title = format!("{TITLE_PREFIX}{key}");
        let record = match self
            .op
            .run(
                &[
                    "item",
                    "get",
                    &title,
                    "--vault",
                    &self.vault,
                    "--format",
                    "json",
                ],
                None,
            )
            .await
        {
            Ok(output) => parse_item(&output)?
                .filter(|r| r.info.key == key && self.allow.permits(&r.info.attributes)),
            Err(Error::NotFound) => None,
            Err(error) => return Err(error),
        };
        if singles.fresh().is_none() {
            singles.set(Singles::new());
        }
        if let Some(map) = singles.fresh_mut() {
            map.insert(key.to_owned(), record.clone());
        }
        Ok(record)
    }

    async fn invalidate(&self) {
        self.index.lock().await.invalidate();
        self.listing.lock().await.invalidate();
        self.singles.lock().await.invalidate();
    }

    /// Items whose attributes contain every pair of `query`.
    ///
    /// On a cold store a non-empty query costs one exact read and one listing run
    /// side by side, plus a read of each other match; an empty query loads the
    /// whole set; a loaded index answers any query from memory.
    pub async fn search(&self, query: &Attributes) -> Result<Vec<ItemInfo>> {
        if !query.is_empty() && !self.index_is_fresh() {
            return self.search_cold(query).await;
        }
        self.with_index(|index| {
            index
                .values()
                .filter(|r| matches(query, &r.info.attributes))
                .map(|r| r.info.clone())
                .collect()
        })
        .await
    }

    pub async fn info(&self, key: &str) -> Result<ItemInfo> {
        self.fetch_one(key)
            .await?
            .map(|record| record.info)
            .ok_or(Error::NotFound)
    }

    /// The secret value and its content type.
    pub async fn secret(&self, key: &str) -> Result<(Zeroizing<Vec<u8>>, String)> {
        self.fetch_one(key)
            .await?
            .map(|record| (record.secret, record.content_type))
            .ok_or(Error::NotFound)
    }

    /// Creates an item. An existing item with the same attributes is replaced
    /// when `replace` is set and returned untouched otherwise.
    pub async fn create(
        &self,
        attributes: Attributes,
        label: &str,
        secret: &[u8],
        content_type: &str,
        replace: bool,
    ) -> Result<ItemInfo> {
        if !self.allow.permits(&attributes) {
            return Err(Error::NotPermitted(
                "the attributes are not covered by the allow list".into(),
            ));
        }
        let _guard = self.write_lock.lock().await;
        let key = item_key(&attributes);
        let title = item_title(&attributes);
        let existing = self
            .fetch_one(&key)
            .await?
            .map(|record| (record.info, record.field_ids));
        let info = ItemInfo {
            key,
            label: label.to_owned(),
            attributes: attributes.clone(),
        };
        match existing {
            Some((current, _)) if !replace => return Ok(current),
            Some((_, ids)) => {
                let fields = fields_json(label, &attributes, secret, content_type, &ids)?;
                let body = Zeroizing::new(
                    serde_json::to_vec(&json!({ "fields": fields }))
                        .map_err(|e| Error::Internal(e.to_string()))?,
                );
                self.op
                    .run(
                        &["item", "edit", &title, "--vault", &self.vault, "-"],
                        Some(&body),
                    )
                    .await?;
            }
            None => {
                let fields =
                    fields_json(label, &attributes, secret, content_type, &HashMap::new())?;
                let body = Zeroizing::new(
                    serde_json::to_vec(&json!({
                        "title": title,
                        "category": "PASSWORD",
                        "tags": [self.tag, attrs_tag(&attributes)],
                        "fields": fields,
                    }))
                    .map_err(|e| Error::Internal(e.to_string()))?,
                );
                self.op
                    .run(
                        &["item", "create", "--vault", &self.vault, "-"],
                        Some(&body),
                    )
                    .await?;
            }
        }
        self.invalidate().await;
        Ok(info)
    }

    /// Replaces the secret of an existing item, keeping its label and attributes.
    pub async fn set_secret(&self, key: &str, secret: &[u8], content_type: &str) -> Result<()> {
        let info = self.info(key).await?;
        self.create(info.attributes, &info.label, secret, content_type, true)
            .await?;
        Ok(())
    }

    /// Moves the item to the 1Password archive.
    pub async fn delete(&self, key: &str) -> Result<()> {
        let _guard = self.write_lock.lock().await;
        let info = self.info(key).await?;
        self.op
            .run(
                &[
                    "item",
                    "delete",
                    &item_title(&info.attributes),
                    "--vault",
                    &self.vault,
                    "--archive",
                ],
                None,
            )
            .await?;
        self.invalidate().await;
        Ok(())
    }
}
```

- [ ] **Step 9: Run the tests to see them pass**

```bash
cargo test --lib
```
Expected: PASS, 74 tests in total at this point.

- [ ] **Step 10: Run the fixture tests**

```bash
cargo test --test fake_op
```
Expected: PASS, 3 tests (they check the fixture itself, so they pass on the first run).

- [ ] **Step 11: Check formatting and lints**

```bash
cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings
```
Expected: no output.

- [ ] **Step 12: Commit**

```bash
git add tests/fixtures/fake-op.py tests/fake_op.rs src/cache.rs src/store.rs src/lib.rs
git commit -m "feat(store): keep secrets as 1Password items with an in-memory index"
```


### Task 6: D-Bus service and the daemon

**Files:**
- Create: `tests/common/mod.rs`, `tests/protocol.rs`, `src/dbus/mod.rs`, `src/dbus/session.rs`, `src/dbus/item.rs`, `src/dbus/collection.rs`, `src/dbus/service.rs`, `src/lifecycle.rs`
- Modify: `src/lib.rs`, `src/main.rs`

Exports the Secret Service objects with `zbus`, claims the bus name, exits when idle, and wires `op-secretd serve`. The integration harness starts a private `dbus-daemon` and the real binary against the fake `op`; the protocol tests talk to it with a Rust client that implements both session algorithms. Four details were established empirically and are pinned by tests: `GetSecret` must reply with one `(oayays)` structure (go-keyring rejects the flattened form); a property getter must not export objects (`zbus` holds the object tree and `ObjectServer::at` would deadlock), so items are exported by methods (nothing scans the vault at startup); a taken bus name arrives as `zbus::Error::NameTaken`; and a request in flight keeps the daemon from idling out.

**Interfaces:**
- Consumes: `Store`, `OpRunner`, `Probe`, `crypto::{negotiate, SessionCipher}`, `config::{load, default_path}`, `tests/fixtures/fake-op.py`.
- Produces: `dbus::{State, Secret, Service, Collection, Item, serve_objects, export_items, preload, item_path, key_from_path, no_prompt}`, `lifecycle::{serve, describe_owner, BUS_NAME}`, `Harness` in `tests/common/mod.rs` (`new`, `write_config(&[(&str, &str)])`, `daemon_command`, `start_daemon(&[(&str, &str)])`, `connect`, `wait_for_daemon_exit`, `path`, `db`), and `op-secretd serve`.

- [ ] **Step 1: Create the integration harness `tests/common/mod.rs`**

`tests/common/mod.rs`:

```rust
//! Shared harness: a private session bus, a fake `op`, and the real daemon binary.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;
use zbus::Connection;
use zbus::fdo::DBusProxy;
use zbus::names::BusName;

pub const BUS_NAME: &str = "org.freedesktop.secrets";
const FAKE_OP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/fake-op.py");

pub struct Harness {
    pub dir: TempDir,
    pub address: String,
    bus: Child,
    daemons: Vec<Child>,
}

impl Harness {
    /// Starts a private session bus and writes the fake-op wrapper; no daemon yet.
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("bus");
        let address = format!("unix:path={}", socket.display());
        let bus = Command::new("dbus-daemon")
            .args([
                "--session",
                "--nofork",
                "--nopidfile",
                &format!("--address={address}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("dbus-daemon must be installed to run the integration tests");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !socket.exists() {
            assert!(
                Instant::now() < deadline,
                "dbus-daemon did not create its socket"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let wrapper = dir.path().join("op");
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nFAKE_OP_DB='{}' exec python3 '{}' \"$@\"\n",
                dir.path().join("db").display(),
                FAKE_OP
            ),
        )
        .unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            dir,
            address,
            bus,
            daemons: Vec::new(),
        }
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    pub fn db(&self) -> PathBuf {
        self.path("db")
    }

    /// Writes the daemon configuration. `overrides` are `(key, toml_value)` pairs
    /// that replace the top-level defaults, e.g. `("cache_ttl", "\"0\"")`.
    pub fn write_config(&self, overrides: &[(&str, &str)]) -> PathBuf {
        let mut values: BTreeMap<&str, String> = BTreeMap::from([
            ("vault", "\"V\"".to_owned()),
            ("mode", "\"app\"".to_owned()),
            ("cache_ttl", "\"30s\"".to_owned()),
            ("idle_timeout", "\"0\"".to_owned()),
        ]);
        for (key, value) in overrides {
            values.insert(key, (*value).to_owned());
        }
        let mut text: String = values
            .iter()
            .map(|(key, value)| format!("{key} = {value}\n"))
            .collect();
        text.push_str(&format!(
            "\n[op]\nbinary = \"{}\"\nwsl_interop = false\n",
            self.path("op").display()
        ));
        let path = self.path("config.toml");
        std::fs::write(&path, text).unwrap();
        path
    }

    /// A command for the daemon binary with a clean, isolated environment.
    pub fn daemon_command(&self, config: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_op-secretd"));
        command
            .arg("--config")
            .arg(config)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.dir.path())
            .env("XDG_CONFIG_HOME", self.path("xdg-config"))
            .env("XDG_DATA_HOME", self.path("xdg-data"))
            .env("XDG_STATE_HOME", self.path("xdg-state"))
            .env("XDG_CACHE_HOME", self.path("xdg-cache"))
            .env("DBUS_SESSION_BUS_ADDRESS", &self.address);
        command
    }

    /// Starts `op-secretd serve` and waits until it owns the bus name.
    pub async fn start_daemon(&mut self, overrides: &[(&str, &str)]) {
        let config = self.write_config(overrides);
        let child = self
            .daemon_command(&config)
            .arg("serve")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        self.daemons.push(child);
        let connection = self.connect().await;
        let proxy = DBusProxy::new(&connection).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        while !proxy
            .name_has_owner(BusName::try_from(BUS_NAME).unwrap())
            .await
            .unwrap()
        {
            assert!(
                Instant::now() < deadline,
                "the daemon did not claim {BUS_NAME}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    pub async fn connect(&self) -> Connection {
        zbus::connection::Builder::address(self.address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap()
    }

    /// Waits for the first daemon to exit and returns whether it succeeded.
    pub fn wait_for_daemon_exit(&mut self, timeout: Duration) -> Option<bool> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(status) = self.daemons[0].try_wait().unwrap() {
                return Some(status.success());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        for daemon in &mut self.daemons {
            let _ = daemon.kill();
            let _ = daemon.wait();
        }
        let _ = self.bus.kill();
        let _ = self.bus.wait();
    }
}
```

- [ ] **Step 2: Create the protocol tests `tests/protocol.rs`**

`tests/protocol.rs`:

```rust
mod common;

use std::collections::HashMap;

use common::{BUS_NAME, Harness};
use op_secretd::crypto::{ALGORITHM_DH, ALGORITHM_PLAIN, DhKeypair, SessionCipher};
use op_secretd::dbus::Secret;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, Proxy};

const SERVICE: &str = "/org/freedesktop/secrets";
const COLLECTION: &str = "/org/freedesktop/secrets/collection/login";
const SERVICE_IFACE: &str = "org.freedesktop.Secret.Service";
const COLLECTION_IFACE: &str = "org.freedesktop.Secret.Collection";
const ITEM_IFACE: &str = "org.freedesktop.Secret.Item";

type Attrs = HashMap<String, String>;

fn attrs(pairs: &[(&str, &str)]) -> Attrs {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

struct Client {
    connection: Connection,
    session: OwnedObjectPath,
    cipher: SessionCipher,
}

impl Client {
    async fn open(harness: &Harness, algorithm: &str) -> Self {
        let connection = harness.connect().await;
        let (cipher, input) = if algorithm == ALGORITHM_DH {
            let keypair = DhKeypair::generate().unwrap();
            let input = Value::from(keypair.public.clone());
            let reply = open_session(&connection, algorithm, input).await.unwrap();
            let server_public = Vec::<u8>::try_from(reply.0.try_clone().unwrap()).unwrap();
            let cipher = SessionCipher::Aes(keypair.derive_key(&server_public).unwrap());
            return Self {
                connection,
                session: reply.1,
                cipher,
            };
        } else {
            (SessionCipher::Plain, Value::from(""))
        };
        let reply = open_session(&connection, algorithm, input).await.unwrap();
        Self {
            connection,
            session: reply.1,
            cipher,
        }
    }

    async fn call<B, T>(&self, path: &str, iface: &str, member: &str, body: &B) -> zbus::Result<T>
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
        T: for<'d> serde::Deserialize<'d> + zbus::zvariant::Type,
    {
        let message = self
            .connection
            .call_method(Some(BUS_NAME), path, Some(iface), member, body)
            .await?;
        message.body().deserialize::<T>()
    }

    fn secret(&self, value: &[u8]) -> Secret {
        let (parameters, value) = self.cipher.encrypt(value).unwrap();
        Secret {
            session: self.session.clone(),
            parameters,
            value,
            content_type: "text/plain".into(),
        }
    }

    fn reveal(&self, secret: &Secret) -> Vec<u8> {
        self.cipher
            .decrypt(&secret.parameters, &secret.value)
            .unwrap()
            .to_vec()
    }

    async fn create(
        &self,
        label: &str,
        attributes: &Attrs,
        value: &[u8],
        replace: bool,
    ) -> zbus::Result<OwnedObjectPath> {
        let mut properties: HashMap<&str, Value<'_>> = HashMap::new();
        properties.insert("org.freedesktop.Secret.Item.Label", Value::from(label));
        properties.insert(
            "org.freedesktop.Secret.Item.Attributes",
            Value::new(attributes.clone()),
        );
        let (item, _prompt): (OwnedObjectPath, OwnedObjectPath) = self
            .call(
                COLLECTION,
                COLLECTION_IFACE,
                "CreateItem",
                &(properties, self.secret(value), replace),
            )
            .await?;
        Ok(item)
    }

    async fn search(&self, attributes: &Attrs) -> zbus::Result<Vec<OwnedObjectPath>> {
        let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = self
            .call(SERVICE, SERVICE_IFACE, "SearchItems", &(attributes,))
            .await?;
        assert!(locked.is_empty());
        Ok(unlocked)
    }

    async fn get_secret(&self, item: &OwnedObjectPath) -> zbus::Result<Vec<u8>> {
        let secret: Secret = self
            .call(
                item.as_str(),
                ITEM_IFACE,
                "GetSecret",
                &(ObjectPath::try_from(self.session.as_str()).unwrap(),),
            )
            .await?;
        Ok(self.reveal(&secret))
    }

    async fn property<T>(&self, path: &str, iface: &str, name: &str) -> zbus::Result<T>
    where
        T: TryFrom<OwnedValue>,
        T::Error: Into<zbus::Error>,
    {
        Proxy::new(&self.connection, BUS_NAME, path, iface)
            .await?
            .get_property(name)
            .await
    }
}

async fn open_session(
    connection: &Connection,
    algorithm: &str,
    input: Value<'_>,
) -> zbus::Result<(OwnedValue, OwnedObjectPath)> {
    let message = connection
        .call_method(
            Some(BUS_NAME),
            SERVICE,
            Some(SERVICE_IFACE),
            "OpenSession",
            &(algorithm, input),
        )
        .await?;
    message.body().deserialize()
}

async fn search_via(
    connection: &Connection,
    attributes: &Attrs,
) -> zbus::Result<Vec<OwnedObjectPath>> {
    let message = connection
        .call_method(
            Some(BUS_NAME),
            SERVICE,
            Some(SERVICE_IFACE),
            "SearchItems",
            &(attributes,),
        )
        .await?;
    let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) =
        message.body().deserialize()?;
    assert!(locked.is_empty());
    Ok(unlocked)
}

fn error_name(error: &zbus::Error) -> String {
    match error {
        zbus::Error::MethodError(name, ..) => name.to_string(),
        other => other.to_string(),
    }
}

async fn harness() -> Harness {
    let mut harness = Harness::new();
    harness.start_daemon(&[]).await;
    harness
}

#[tokio::test]
async fn plain_session_roundtrip() {
    let harness = harness().await;
    let client = Client::open(&harness, ALGORITHM_PLAIN).await;
    let attributes = attrs(&[("service", "gh:github.com"), ("username", "bob")]);

    let item = client
        .create("gh token", &attributes, b"tok-1", false)
        .await
        .unwrap();
    assert!(item.as_str().starts_with(&format!("{COLLECTION}/")));

    assert_eq!(
        client
            .search(&attrs(&[("service", "gh:github.com")]))
            .await
            .unwrap(),
        vec![item.clone()]
    );
    assert!(
        client
            .search(&attrs(&[("service", "nope")]))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(client.get_secret(&item).await.unwrap(), b"tok-1");

    let stored: Attrs = client
        .property(item.as_str(), ITEM_IFACE, "Attributes")
        .await
        .unwrap();
    assert_eq!(stored, attributes);
    let label: String = client
        .property(item.as_str(), ITEM_IFACE, "Label")
        .await
        .unwrap();
    assert_eq!(label, "gh token");
    let locked: bool = client
        .property(item.as_str(), ITEM_IFACE, "Locked")
        .await
        .unwrap();
    assert!(!locked);

    let items: Vec<OwnedObjectPath> = client
        .property(COLLECTION, COLLECTION_IFACE, "Items")
        .await
        .unwrap();
    assert_eq!(items, vec![item.clone()]);

    let _: OwnedObjectPath = client
        .call(item.as_str(), ITEM_IFACE, "Delete", &())
        .await
        .unwrap();
    assert!(client.search(&attributes).await.unwrap().is_empty());
}

#[tokio::test]
async fn dh_session_roundtrip() {
    let harness = harness().await;
    let client = Client::open(&harness, ALGORITHM_DH).await;
    let attributes = attrs(&[("service", "glab"), ("username", "")]);

    let item = client
        .create(
            "glab token",
            &attributes,
            "秘密-\u{1F512}".as_bytes(),
            false,
        )
        .await
        .unwrap();
    assert_eq!(
        client.get_secret(&item).await.unwrap(),
        "秘密-\u{1F512}".as_bytes()
    );

    let secrets: HashMap<OwnedObjectPath, Secret> = client
        .call(
            SERVICE,
            SERVICE_IFACE,
            "GetSecrets",
            &(
                vec![ObjectPath::try_from(item.as_str()).unwrap()],
                ObjectPath::try_from(client.session.as_str()).unwrap(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(client.reveal(&secrets[&item]), "秘密-\u{1F512}".as_bytes());
}

#[tokio::test]
async fn replace_and_set_secret() {
    let harness = harness().await;
    let client = Client::open(&harness, ALGORITHM_PLAIN).await;
    let attributes = attrs(&[("k", "v")]);

    let first = client
        .create("one", &attributes, b"1", false)
        .await
        .unwrap();
    let again = client
        .create("two", &attributes, b"2", false)
        .await
        .unwrap();
    assert_eq!(first, again);
    assert_eq!(
        client.get_secret(&first).await.unwrap(),
        b"1",
        "without replace the old value stays"
    );

    client.create("two", &attributes, b"2", true).await.unwrap();
    assert_eq!(client.get_secret(&first).await.unwrap(), b"2");

    let _: () = client
        .call(
            first.as_str(),
            ITEM_IFACE,
            "SetSecret",
            &(client.secret(b"3"),),
        )
        .await
        .unwrap();
    assert_eq!(client.get_secret(&first).await.unwrap(), b"3");
    assert_eq!(client.search(&attrs(&[])).await.unwrap().len(), 1);
}

#[tokio::test]
async fn default_alias_and_collections() {
    let harness = harness().await;
    let client = Client::open(&harness, ALGORITHM_PLAIN).await;
    let alias: OwnedObjectPath = client
        .call(SERVICE, SERVICE_IFACE, "ReadAlias", &("default",))
        .await
        .unwrap();
    assert_eq!(alias.as_str(), COLLECTION);
    let other: OwnedObjectPath = client
        .call(SERVICE, SERVICE_IFACE, "ReadAlias", &("nope",))
        .await
        .unwrap();
    assert_eq!(other.as_str(), "/");
    let collections: Vec<OwnedObjectPath> = client
        .property(SERVICE, SERVICE_IFACE, "Collections")
        .await
        .unwrap();
    assert_eq!(collections.len(), 1);

    let via_alias = client
        .create("a", &attrs(&[("k", "v")]), b"x", false)
        .await
        .unwrap();
    let items: Vec<OwnedObjectPath> = client
        .call(
            "/org/freedesktop/secrets/aliases/default",
            COLLECTION_IFACE,
            "SearchItems",
            &(attrs(&[("k", "v")]),),
        )
        .await
        .unwrap();
    assert_eq!(items, vec![via_alias]);
}

#[tokio::test]
async fn bad_requests_are_rejected() {
    let harness = harness().await;
    let client = Client::open(&harness, ALGORITHM_PLAIN).await;

    let error = open_session(&client.connection, "rot13", Value::from(""))
        .await
        .unwrap_err();
    assert!(error_name(&error).ends_with("NotSupported"), "{error}");

    let foreign = Secret {
        session: OwnedObjectPath::try_from("/org/freedesktop/secrets/session/999").unwrap(),
        parameters: vec![],
        value: b"x".to_vec(),
        content_type: "text/plain".into(),
    };
    let mut properties: HashMap<&str, Value<'_>> = HashMap::new();
    properties.insert("org.freedesktop.Secret.Item.Label", Value::from("x"));
    properties.insert(
        "org.freedesktop.Secret.Item.Attributes",
        Value::new(attrs(&[("k", "v")])),
    );
    let result: zbus::Result<(OwnedObjectPath, OwnedObjectPath)> = client
        .call(
            COLLECTION,
            COLLECTION_IFACE,
            "CreateItem",
            &(properties, foreign, false),
        )
        .await;
    assert!(error_name(&result.unwrap_err()).ends_with("InvalidArgs"));

    let mut missing: HashMap<&str, Value<'_>> = HashMap::new();
    missing.insert("org.freedesktop.Secret.Item.Label", Value::from("x"));
    let result: zbus::Result<(OwnedObjectPath, OwnedObjectPath)> = client
        .call(
            COLLECTION,
            COLLECTION_IFACE,
            "CreateItem",
            &(missing, client.secret(b"x"), false),
        )
        .await;
    assert!(error_name(&result.unwrap_err()).ends_with("InvalidArgs"));

    let result: zbus::Result<(OwnedObjectPath, OwnedObjectPath)> = client
        .call(
            SERVICE,
            SERVICE_IFACE,
            "CreateCollection",
            &(HashMap::<&str, Value<'_>>::new(), ""),
        )
        .await;
    assert!(error_name(&result.unwrap_err()).ends_with("NotSupported"));
}

#[tokio::test]
async fn closing_a_session_invalidates_it() {
    let harness = harness().await;
    let client = Client::open(&harness, ALGORITHM_PLAIN).await;
    let item = client
        .create("a", &attrs(&[("k", "v")]), b"x", false)
        .await
        .unwrap();
    let _: () = client
        .call(
            client.session.as_str(),
            "org.freedesktop.Secret.Session",
            "Close",
            &(),
        )
        .await
        .unwrap();
    let error = client.get_secret(&item).await.unwrap_err();
    assert!(error_name(&error).ends_with("InvalidArgs"), "{error}");
}

#[tokio::test]
async fn failures_surface_as_errors_not_empty_results() {
    let mut harness = Harness::new();
    harness.start_daemon(&[("cache_ttl", "\"0\"")]).await;
    let client = Client::open(&harness, ALGORITHM_PLAIN).await;
    client
        .create("a", &attrs(&[("k", "v")]), b"x", false)
        .await
        .unwrap();

    std::fs::write(harness.db().join("FAIL"), "").unwrap();
    let error = client.search(&attrs(&[("k", "v")])).await.unwrap_err();
    assert!(error_name(&error).ends_with("Failed"), "{error}");
    assert!(
        error.to_string().contains("authorization prompt dismissed"),
        "{error}"
    );

    std::fs::remove_file(harness.db().join("FAIL")).unwrap();
    assert_eq!(client.search(&attrs(&[("k", "v")])).await.unwrap().len(), 1);
}

#[tokio::test]
async fn allow_list_rejects_other_attributes() {
    let mut harness = Harness::new();
    harness
        .start_daemon(&[("allow", "[\"service=gh:*\"]")])
        .await;
    let client = Client::open(&harness, ALGORITHM_PLAIN).await;
    client
        .create("ok", &attrs(&[("service", "gh:x")]), b"x", false)
        .await
        .unwrap();
    let error = client
        .create("no", &attrs(&[("service", "other")]), b"x", false)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("allow list"), "{error}");
}

#[tokio::test]
async fn the_cache_is_shared_between_requests() {
    let harness = harness().await;
    let client = Client::open(&harness, ALGORITHM_PLAIN).await;
    let item = client
        .create("a", &attrs(&[("k", "v")]), b"x", false)
        .await
        .unwrap();
    for _ in 0..3 {
        client.get_secret(&item).await.unwrap();
        client.search(&attrs(&[("k", "v")])).await.unwrap();
    }
    let log = std::fs::read_to_string(harness.db().join("calls.log")).unwrap();
    let lists = log
        .lines()
        .filter(|line| line.starts_with("item list"))
        .count();
    let reads = log
        .lines()
        .filter(|line| line.starts_with("item get secret-service/"))
        .count();
    assert!(
        lists <= 1,
        "the listing is shared and cached, never repeated:\n{log}"
    );
    assert!(
        reads <= 2,
        "repeated reads of one item hit the cache after at most the existence check and one read:\n{log}"
    );
}

#[tokio::test]
async fn a_second_provider_cannot_take_the_name() {
    let harness = harness().await;
    let config = harness.write_config(&[]);
    let output = harness
        .daemon_command(&config)
        .arg("serve")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("already owned"), "{stderr}");
    assert!(
        !stderr.contains("internal error"),
        "a taken name is not an internal error: {stderr}"
    );
    assert!(stderr.contains("stop that provider first"), "{stderr}");
}

#[tokio::test]
async fn the_daemon_exits_when_idle() {
    let mut harness = Harness::new();
    harness.start_daemon(&[("idle_timeout", "\"1s\"")]).await;
    assert_eq!(
        harness.wait_for_daemon_exit(std::time::Duration::from_secs(15)),
        Some(true)
    );
}

#[tokio::test]
async fn concurrent_requests_share_one_index_load() {
    let harness = harness().await;
    let client = Client::open(&harness, ALGORITHM_PLAIN).await;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let connection = client.connection.clone();
        tasks.spawn(async move {
            search_via(&connection, &attrs(&[("k", "v")]))
                .await
                .unwrap()
                .len()
        });
    }
    while let Some(found) = tasks.join_next().await {
        assert_eq!(found.unwrap(), 0);
    }
    let log = std::fs::read_to_string(harness.db().join("calls.log")).unwrap();
    let lists = log
        .lines()
        .filter(|line| line.starts_with("item list"))
        .count();
    assert_eq!(
        lists, 1,
        "the startup load serves every concurrent search:\n{log}"
    );
    let reads = log
        .lines()
        .filter(|line| line.starts_with("item get secret-service/"))
        .count();
    assert!(
        reads <= 1,
        "concurrent identical searches share one read:\n{log}"
    );
}

#[tokio::test]
async fn empty_large_and_binary_secrets_roundtrip() {
    let harness = harness().await;
    for algorithm in [ALGORITHM_PLAIN, ALGORITHM_DH] {
        let client = Client::open(&harness, algorithm).await;
        let large: Vec<u8> = (0..64 * 1024).map(|i| b'a' + (i % 26) as u8).collect();
        let cases: [(&str, Vec<u8>); 3] = [
            ("empty", Vec::new()),
            ("large", large),
            ("binary", vec![0xff, 0xfe, 0x00, 0x80]),
        ];
        for (name, value) in cases {
            let attributes = attrs(&[("case", name), ("algorithm", algorithm)]);
            let item = client
                .create(name, &attributes, &value, false)
                .await
                .unwrap();
            assert_eq!(
                client.get_secret(&item).await.unwrap(),
                value,
                "{name} over {algorithm}"
            );
        }
    }
}

#[tokio::test]
async fn idle_exit_waits_for_a_request_in_flight() {
    let mut harness = Harness::new();
    harness
        .start_daemon(&[("idle_timeout", "\"1s\""), ("cache_ttl", "\"0\"")])
        .await;
    let client = Client::open(&harness, ALGORITHM_PLAIN).await;
    client
        .create("a", &attrs(&[("k", "v")]), b"x", false)
        .await
        .unwrap();

    // A pending approval: every `op` call now takes 2 seconds, far longer than the idle timeout.
    std::fs::write(harness.db().join("SLOW"), "2").unwrap();
    let found = client.search(&attrs(&[("k", "v")])).await.unwrap();
    assert_eq!(
        found.len(),
        1,
        "the request must finish although the idle timeout elapsed"
    );

    std::fs::remove_file(harness.db().join("SLOW")).unwrap();
    assert_eq!(
        harness.wait_for_daemon_exit(std::time::Duration::from_secs(15)),
        Some(true)
    );
}

#[tokio::test]
async fn starting_the_daemon_does_not_scan_the_vault() {
    let harness = harness().await;
    // Give a would-be background scan time to start before looking at the log.
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    let log = std::fs::read_to_string(harness.db().join("calls.log")).unwrap_or_default();
    assert!(
        log.lines().all(|line| !line.starts_with("item ")),
        "a started daemon must not touch 1Password until a client asks:\n{log}"
    );
}
```

- [ ] **Step 3: Run the tests to see them fail**

```bash
cargo test --test protocol
```
Expected: FAIL, compile errors (`op_secretd::dbus` does not exist).

- [ ] **Step 4: Create `src/dbus/mod.rs`: the shared state, paths, and helpers**

`src/dbus/mod.rs`:

```rust
//! The D-Bus face of the daemon: shared state, object paths and helpers.

mod collection;
mod item;
mod service;
mod session;

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use zbus::Connection;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, Type};
use zeroize::Zeroizing;

use crate::crypto::SessionCipher;
use crate::error::{Error, Result};
use crate::store::{ItemInfo, Store};

pub use collection::Collection;
pub use item::Item;
pub use service::Service;

pub const SERVICE_PATH: &str = "/org/freedesktop/secrets";
pub const COLLECTION_PATH: &str = "/org/freedesktop/secrets/collection/login";
pub const ALIAS_PATH: &str = "/org/freedesktop/secrets/aliases/default";
const SESSION_PREFIX: &str = "/org/freedesktop/secrets/session/";

/// The `Secret` structure of the Secret Service API: `(oayays)`.
#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct Secret {
    pub session: OwnedObjectPath,
    pub parameters: Vec<u8>,
    pub value: Vec<u8>,
    pub content_type: String,
}

/// State shared by every exported object.
pub struct State {
    pub store: Store,
    sessions: Mutex<HashMap<String, Arc<SessionCipher>>>,
    next_session: AtomicU64,
    last_activity: StdMutex<Instant>,
    in_flight: AtomicUsize,
    exported: StdMutex<BTreeSet<String>>,
}

impl State {
    pub fn new(store: Store) -> Arc<Self> {
        Arc::new(Self {
            store,
            sessions: Mutex::new(HashMap::new()),
            next_session: AtomicU64::new(1),
            last_activity: StdMutex::new(Instant::now()),
            in_flight: AtomicUsize::new(0),
            exported: StdMutex::new(BTreeSet::new()),
        })
    }

    /// Marks a request as started; the returned guard marks it finished.
    /// A daemon with a request in flight is never idle.
    pub fn begin(&self) -> Busy<'_> {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        Busy(self)
    }

    /// True while at least one request is being handled.
    pub fn is_busy(&self) -> bool {
        self.in_flight.load(Ordering::SeqCst) > 0
    }

    /// Time since the last request finished.
    pub fn idle_for(&self) -> Duration {
        self.last_activity.lock().expect("activity lock").elapsed()
    }

    fn set_exported(&self, key: &str, exported: bool) {
        let mut keys = self.exported.lock().expect("exported lock");
        if exported {
            keys.insert(key.to_owned());
        } else {
            keys.remove(key);
        }
    }

    /// Keys of the items that currently have a D-Bus object.
    fn exported_keys(&self) -> Vec<String> {
        self.exported
            .lock()
            .expect("exported lock")
            .iter()
            .cloned()
            .collect()
    }

    async fn add_session(&self, cipher: SessionCipher) -> String {
        let path = format!(
            "{SESSION_PREFIX}{}",
            self.next_session.fetch_add(1, Ordering::Relaxed)
        );
        self.sessions
            .lock()
            .await
            .insert(path.clone(), Arc::new(cipher));
        path
    }

    async fn remove_session(&self, path: &str) {
        self.sessions.lock().await.remove(path);
    }

    async fn cipher(&self, session: &str) -> Result<Arc<SessionCipher>> {
        self.sessions
            .lock()
            .await
            .get(session)
            .cloned()
            .ok_or_else(|| Error::Invalid(format!("unknown session {session}")))
    }

    /// Wraps a secret value for `session`.
    async fn seal(
        &self,
        session: &ObjectPath<'_>,
        value: &[u8],
        content_type: &str,
    ) -> Result<Secret> {
        let cipher = self.cipher(session.as_str()).await?;
        let (parameters, value) = cipher.encrypt(value)?;
        Ok(Secret {
            session: OwnedObjectPath::from(session.clone()),
            parameters,
            value,
            content_type: content_type.to_owned(),
        })
    }

    /// Unwraps a secret received from a client.
    async fn open(&self, secret: &Secret) -> Result<Zeroizing<Vec<u8>>> {
        self.cipher(secret.session.as_str())
            .await?
            .decrypt(&secret.parameters, &secret.value)
    }
}

/// Guard returned by `State::begin`.
pub struct Busy<'a>(&'a State);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        *self.0.last_activity.lock().expect("activity lock") = Instant::now();
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn item_path(key: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!("{COLLECTION_PATH}/{key}")).expect("item keys are hex digits")
}

pub fn no_prompt() -> OwnedObjectPath {
    OwnedObjectPath::try_from("/").expect("root path is valid")
}

/// The item key at the end of an item object path.
pub fn key_from_path(path: &ObjectPath<'_>) -> Result<String> {
    path.as_str()
        .strip_prefix(COLLECTION_PATH)
        .and_then(|rest| rest.strip_prefix('/'))
        .filter(|key| key.len() == 16 && key.chars().all(|c| c.is_ascii_hexdigit()))
        .map(str::to_owned)
        .ok_or_else(|| Error::Invalid(format!("{path} is not an item of this collection")))
}

/// Exports an object for each item that is not exported yet and returns the paths.
pub async fn export_items(
    connection: &Connection,
    state: &Arc<State>,
    items: &[ItemInfo],
) -> Result<Vec<OwnedObjectPath>> {
    let mut paths = Vec::with_capacity(items.len());
    for info in items {
        let path = item_path(&info.key);
        connection
            .object_server()
            .at(path.clone(), Item::new(state.clone(), info.key.clone()))
            .await
            .map_err(|error| Error::Internal(error.to_string()))?;
        state.set_exported(&info.key, true);
        paths.push(path);
    }
    Ok(paths)
}

/// Exports the service and collection objects on `builder`.
pub fn serve_objects(
    builder: zbus::connection::Builder<'static>,
    state: &Arc<State>,
) -> zbus::Result<zbus::connection::Builder<'static>> {
    builder
        .serve_at(SERVICE_PATH, Service::new(state.clone()))?
        .serve_at(COLLECTION_PATH, Collection::new(state.clone()))?
        .serve_at(ALIAS_PATH, Collection::new(state.clone()))
}
```

- [ ] **Step 5: Create `src/dbus/session.rs`: the `Session` interface**

`src/dbus/session.rs`:

```rust
use std::sync::Arc;

use zbus::{ObjectServer, fdo, interface};

use super::State;

/// `org.freedesktop.Secret.Session`, one per client session.
pub struct Session {
    state: Arc<State>,
    path: String,
}

impl Session {
    pub fn new(state: Arc<State>, path: String) -> Self {
        Self { state, path }
    }
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    async fn close(&self, #[zbus(object_server)] server: &ObjectServer) -> fdo::Result<()> {
        let _busy = self.state.begin();
        self.state.remove_session(&self.path).await;
        server.remove::<Session, _>(self.path.as_str()).await?;
        Ok(())
    }
}
```

- [ ] **Step 6: Create `src/dbus/item.rs`: the `Item` interface**

`src/dbus/item.rs`:

```rust
use std::collections::HashMap;
use std::sync::Arc;

use zbus::zvariant::{ObjectPath, OwnedObjectPath};
use zbus::{ObjectServer, fdo, interface};

use super::{Secret, State, item_path, no_prompt};

/// `org.freedesktop.Secret.Item`, one per stored secret.
pub struct Item {
    state: Arc<State>,
    key: String,
}

impl Item {
    pub fn new(state: Arc<State>, key: String) -> Self {
        Self { state, key }
    }
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    #[zbus(property)]
    async fn locked(&self) -> bool {
        false
    }

    #[zbus(property)]
    async fn attributes(&self) -> fdo::Result<HashMap<String, String>> {
        let _busy = self.state.begin();
        Ok(self
            .state
            .store
            .info(&self.key)
            .await?
            .attributes
            .into_iter()
            .collect())
    }

    #[zbus(property)]
    async fn label(&self) -> fdo::Result<String> {
        let _busy = self.state.begin();
        Ok(self.state.store.info(&self.key).await?.label)
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        0
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        0
    }

    #[zbus(property, name = "Type")]
    async fn item_type(&self) -> String {
        "org.freedesktop.Secret.Generic".into()
    }

    async fn delete(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<OwnedObjectPath> {
        let _busy = self.state.begin();
        self.state.store.delete(&self.key).await?;
        server.remove::<Item, _>(item_path(&self.key)).await?;
        self.state.set_exported(&self.key, false);
        Ok(no_prompt())
    }

    async fn get_secret(&self, session: ObjectPath<'_>) -> fdo::Result<(Secret,)> {
        let _busy = self.state.begin();
        let (value, content_type) = self.state.store.secret(&self.key).await?;
        Ok((self.state.seal(&session, &value, &content_type).await?,))
    }

    async fn set_secret(&self, secret: Secret) -> fdo::Result<()> {
        let _busy = self.state.begin();
        let value = self.state.open(&secret).await?;
        self.state
            .store
            .set_secret(&self.key, &value, &secret.content_type)
            .await?;
        Ok(())
    }
}
```

- [ ] **Step 7: Create `src/dbus/collection.rs`: the `Collection` interface**

`src/dbus/collection.rs`:

```rust
use std::collections::HashMap;
use std::sync::Arc;

use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::{Connection, fdo, interface};

use super::{Secret, State, export_items, item_path, no_prompt};
use crate::attrs::Attributes;
use crate::error::Error;

const PROPERTY_LABEL: &str = "org.freedesktop.Secret.Item.Label";
const PROPERTY_ATTRIBUTES: &str = "org.freedesktop.Secret.Item.Attributes";

/// `org.freedesktop.Secret.Collection`; the single `login` collection.
pub struct Collection {
    state: Arc<State>,
}

impl Collection {
    pub fn new(state: Arc<State>) -> Self {
        Self { state }
    }
}

fn string_property(properties: &HashMap<String, OwnedValue>, name: &str) -> Option<String> {
    String::try_from(properties.get(name)?.try_clone().ok()?).ok()
}

fn attributes_property(
    properties: &HashMap<String, OwnedValue>,
) -> Option<HashMap<String, String>> {
    HashMap::<String, String>::try_from(properties.get(PROPERTY_ATTRIBUTES)?.try_clone().ok()?).ok()
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
        #[zbus(connection)] connection: &Connection,
    ) -> fdo::Result<Vec<OwnedObjectPath>> {
        let _busy = self.state.begin();
        let found = self
            .state
            .store
            .search(&attributes.into_iter().collect())
            .await?;
        Ok(export_items(connection, &self.state, &found).await?)
    }

    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: Secret,
        replace: bool,
        #[zbus(connection)] connection: &Connection,
    ) -> fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        let _busy = self.state.begin();
        let attributes: Attributes = attributes_property(&properties)
            .ok_or_else(|| Error::Invalid("the Attributes property is required".into()))?
            .into_iter()
            .collect();
        let label = string_property(&properties, PROPERTY_LABEL).unwrap_or_default();
        let value = self.state.open(&secret).await?;
        let info = self
            .state
            .store
            .create(attributes, &label, &value, &secret.content_type, replace)
            .await?;
        export_items(connection, &self.state, std::slice::from_ref(&info)).await?;
        Ok((item_path(&info.key), no_prompt()))
    }

    async fn delete(&self) -> fdo::Result<OwnedObjectPath> {
        Err(Error::NotSupported("the login collection cannot be deleted".into()).into())
    }

    /// Items that already have an object. A getter must not export objects (the
    /// D-Bus library holds its object tree while a getter runs), so items appear
    /// here after `SearchItems`, `CreateItem`, or another method has exported them.
    #[zbus(property)]
    async fn items(&self) -> Vec<OwnedObjectPath> {
        let _busy = self.state.begin();
        self.state
            .exported_keys()
            .iter()
            .map(|key| item_path(key))
            .collect()
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        "login".into()
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        false
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        0
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        0
    }
}
```

- [ ] **Step 8: Create `src/dbus/service.rs`: the `Service` interface**

`src/dbus/service.rs`:

```rust
use std::collections::HashMap;
use std::sync::Arc;

use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, fdo, interface};

use super::session::Session;
use super::{COLLECTION_PATH, Secret, State, export_items, item_path, key_from_path, no_prompt};
use crate::attrs::Attributes;
use crate::crypto::{ALGORITHM_DH, negotiate};
use crate::error::Error;

/// `org.freedesktop.Secret.Service` at `/org/freedesktop/secrets`.
pub struct Service {
    state: Arc<State>,
}

impl Service {
    pub fn new(state: Arc<State>) -> Self {
        Self { state }
    }
}

fn collection_path() -> OwnedObjectPath {
    OwnedObjectPath::try_from(COLLECTION_PATH).expect("collection path is valid")
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    async fn open_session(
        &self,
        algorithm: &str,
        input: Value<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> fdo::Result<(OwnedValue, OwnedObjectPath)> {
        let _busy = self.state.begin();
        let input_bytes = if algorithm == ALGORITHM_DH {
            Vec::<u8>::try_from(input)
                .map_err(|_| Error::Invalid("the DH public key must be a byte array".into()))?
        } else {
            Vec::new()
        };
        let negotiated = negotiate(algorithm, &input_bytes)?;
        let output = if algorithm == ALGORITHM_DH {
            Value::from(negotiated.output)
        } else {
            Value::from("")
        };
        let output = output
            .try_to_owned()
            .map_err(|error| Error::Internal(error.to_string()))?;
        let path = self.state.add_session(negotiated.cipher).await;
        connection
            .object_server()
            .at(
                path.as_str(),
                Session::new(self.state.clone(), path.clone()),
            )
            .await?;
        let path =
            OwnedObjectPath::try_from(path).map_err(|error| Error::Internal(error.to_string()))?;
        Ok((output, path))
    }

    async fn create_collection(
        &self,
        _properties: HashMap<String, OwnedValue>,
        _alias: &str,
    ) -> fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        Err(Error::NotSupported("only the login collection exists".into()).into())
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
        #[zbus(connection)] connection: &Connection,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        let _busy = self.state.begin();
        let query: Attributes = attributes.into_iter().collect();
        let found = self.state.store.search(&query).await?;
        Ok((
            export_items(connection, &self.state, &found).await?,
            Vec::new(),
        ))
    }

    async fn unlock(
        &self,
        objects: Vec<ObjectPath<'_>>,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let _busy = self.state.begin();
        Ok((
            objects.into_iter().map(OwnedObjectPath::from).collect(),
            no_prompt(),
        ))
    }

    async fn lock(
        &self,
        _objects: Vec<ObjectPath<'_>>,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let _busy = self.state.begin();
        Ok((Vec::new(), no_prompt()))
    }

    async fn get_secrets(
        &self,
        items: Vec<ObjectPath<'_>>,
        session: ObjectPath<'_>,
    ) -> fdo::Result<HashMap<OwnedObjectPath, Secret>> {
        let _busy = self.state.begin();
        let mut secrets = HashMap::new();
        for path in items {
            let Ok(key) = key_from_path(&path) else {
                continue;
            };
            match self.state.store.secret(&key).await {
                Ok((value, content_type)) => {
                    secrets.insert(
                        item_path(&key),
                        self.state.seal(&session, &value, &content_type).await?,
                    );
                }
                Err(Error::NotFound) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(secrets)
    }

    async fn read_alias(&self, name: &str) -> OwnedObjectPath {
        if name == "default" {
            collection_path()
        } else {
            no_prompt()
        }
    }

    async fn set_alias(&self, _name: &str, _collection: ObjectPath<'_>) -> fdo::Result<()> {
        Ok(())
    }

    #[zbus(property)]
    async fn collections(&self) -> Vec<OwnedObjectPath> {
        vec![collection_path()]
    }
}
```

- [ ] **Step 9: Create `src/lifecycle.rs`: claiming the name and exiting when idle**

`src/lifecycle.rs`:

```rust
//! Starting the daemon: claiming the bus name and exiting when idle.

use std::sync::Arc;
use std::time::Duration;

use tokio::signal::unix::{SignalKind, signal};
use zbus::Connection;
use zbus::fdo::{DBusProxy, RequestNameFlags, RequestNameReply};
use zbus::names::BusName;

use crate::config::Config;
use crate::dbus::{State, serve_objects};
use crate::error::{Error, Result};
use crate::op::{OpRunner, Probe};
use crate::store::Store;

pub const BUS_NAME: &str = "org.freedesktop.secrets";

fn bus_error(error: impl std::fmt::Display) -> Error {
    Error::Bus(error.to_string())
}

/// Best-effort description of the process that owns `BUS_NAME`.
pub async fn describe_owner(connection: &Connection) -> String {
    async fn lookup(connection: &Connection) -> zbus::Result<String> {
        let proxy = DBusProxy::new(connection).await?;
        let name = BusName::try_from(BUS_NAME)?;
        let owner = proxy.get_name_owner(name).await?;
        let pid = proxy
            .get_connection_unix_process_id(BusName::from(owner.clone()))
            .await?;
        let command = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        Ok(format!("{} (pid {pid}, {})", command.trim(), owner))
    }
    lookup(connection)
        .await
        .unwrap_or_else(|_| "an unknown process".into())
}

async fn claim_name(connection: &Connection) -> Result<()> {
    let owned_elsewhere = |owner: String| {
        Error::NameTaken(format!(
            "{BUS_NAME} is already owned by {owner}; stop that provider first"
        ))
    };
    match connection
        .request_name_with_flags(BUS_NAME, RequestNameFlags::DoNotQueue.into())
        .await
    {
        Ok(RequestNameReply::PrimaryOwner | RequestNameReply::AlreadyOwner) => Ok(()),
        Ok(RequestNameReply::Exists | RequestNameReply::InQueue) | Err(zbus::Error::NameTaken) => {
            Err(owned_elsewhere(describe_owner(connection).await))
        }
        Err(error) => Err(bus_error(error)),
    }
}

/// Resolves when the process should stop: a signal, or `idle_timeout` without requests.
async fn wait_for_exit(state: &Arc<State>, idle_timeout: Duration) -> Result<()> {
    let mut terminate =
        signal(SignalKind::terminate()).map_err(|e| Error::Internal(e.to_string()))?;
    let mut interrupt =
        signal(SignalKind::interrupt()).map_err(|e| Error::Internal(e.to_string()))?;
    let idle = async {
        if idle_timeout.is_zero() {
            return std::future::pending::<()>().await;
        }
        loop {
            if state.is_busy() {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            let idle_for = state.idle_for();
            if idle_for >= idle_timeout {
                return;
            }
            tokio::time::sleep((idle_timeout - idle_for).min(Duration::from_secs(30))).await;
        }
    };
    tokio::select! {
        _ = terminate.recv() => tracing::info!("received SIGTERM"),
        _ = interrupt.recv() => tracing::info!("received SIGINT"),
        () = idle => tracing::info!("idle timeout reached"),
    }
    Ok(())
}

/// Runs the daemon until it is told to stop or goes idle.
pub async fn serve(config: Config, probe: Probe) -> Result<()> {
    let runner = OpRunner::from_config(&config, &probe)?;
    tracing::info!(op = %runner.describe(), vault = %config.vault, "starting");
    let state = State::new(Store::new(runner, &config)?);
    let builder = zbus::connection::Builder::session().map_err(bus_error)?;
    let connection = serve_objects(builder, &state)
        .map_err(bus_error)?
        .build()
        .await
        .map_err(bus_error)?;
    claim_name(&connection).await?;
    tracing::info!("serving {BUS_NAME}");
    wait_for_exit(&state, config.idle_timeout).await
}
```

- [ ] **Step 10: Declare the new modules in `src/lib.rs`**

`src/lib.rs`:

```rust
pub mod attrs;
pub mod cache;
pub mod config;
pub mod crypto;
pub mod dbus;
pub mod error;
pub mod lifecycle;
pub mod op;
pub mod store;
```

- [ ] **Step 11: Replace `src/main.rs` with a binary that only has `serve` for now**

`src/main.rs`:

```rust
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use op_secretd::config;
use op_secretd::error::Result;
use op_secretd::lifecycle;
use op_secretd::op::Probe;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about = "Secret Service provider backed by 1Password")]
struct Cli {
    /// Path of the configuration file.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon on the session bus.
    Serve,
}

fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn init_logging(level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let path = match &cli.config {
        Some(path) => path.clone(),
        None => config::default_path(&env_var)?,
    };
    match cli.command {
        Command::Serve => {
            let config = config::load(&path, &env_var)?;
            init_logging(&config.log_level);
            lifecycle::serve(config, Probe::real()).await?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("op-secretd: {error}");
            ExitCode::FAILURE
        }
    }
}
```

- [ ] **Step 12: Run all tests**

```bash
cargo test
```
Expected: PASS: 74 library tests, 3 fixture tests, and 15 protocol tests.

- [ ] **Step 13: Check formatting and lints**

```bash
cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings
```
Expected: no output.

- [ ] **Step 14: Commit**

```bash
git add src tests
git commit -m "feat(dbus): serve the Secret Service API on the session bus"
```


### Task 7: doctor and config init

**Files:**
- Create: `tests/cli.rs`, `src/doctor.rs`
- Modify: `src/lib.rs`, `src/main.rs`

Adds `op-secretd doctor` (configuration, `op` resolution, vault access, bus name, session algorithms, and a warning about plaintext `gh` and `glab` tokens; exit code 0 unless a check fails, a warning does not fail it) and `op-secretd config init [--force]`. The plaintext check exists because the real `gh` and `glab` silently store the token in their configuration file when the keyring write fails, so a successful login does not prove the token is in 1Password; it reports file paths only and never a value.

**Interfaces:**
- Consumes: `OpRunner`, `Config`, `Probe` (its `env` map), `lifecycle::{BUS_NAME, describe_owner}`, `crypto::{DhKeypair, negotiate}`, `Harness`.
- Produces: `doctor::{Status::{Ok, Warn, Fail}, Check { name, status, detail }, plaintext_token_check(&HashMap<String, String>) -> Check, run(&Config, &Probe) -> Vec<Check>}`; the `doctor` and `config init` commands.

- [ ] **Step 1: Create `tests/cli.rs`**

`tests/cli.rs`:

```rust
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
        "plaintext tokens",
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

#[test]
fn doctor_warns_about_plaintext_tokens_but_still_passes() {
    let harness = Harness::new();
    let gh = harness.path("gh-config");
    std::fs::create_dir_all(&gh).unwrap();
    std::fs::write(
        gh.join("hosts.yml"),
        "github.com:\n    oauth_token: gho_plainsecret123456789\n    user: bob\n",
    )
    .unwrap();
    let config = harness.write_config(&[]);
    let output = harness
        .daemon_command(&config)
        .arg("doctor")
        .env("GH_CONFIG_DIR", &gh)
        .output()
        .unwrap();
    let stdout = text(&output.stdout);
    assert!(
        output.status.success(),
        "a warning must not fail doctor:\n{stdout}"
    );
    assert!(stdout.contains("warn  plaintext tokens"), "{stdout}");
    assert!(stdout.contains("hosts.yml"), "{stdout}");
    assert!(
        !stdout.contains("gho_plainsecret123456789"),
        "the token leaked:\n{stdout}"
    );
}
```

- [ ] **Step 2: Run the tests to see them fail**

```bash
cargo test --test cli
```
Expected: FAIL: the binary has no `doctor` or `config` command yet.

- [ ] **Step 3: Declare the module in `src/lib.rs`**

`src/lib.rs`:

```rust
pub mod attrs;
pub mod cache;
pub mod config;
pub mod crypto;
pub mod dbus;
pub mod doctor;
pub mod error;
pub mod lifecycle;
pub mod op;
pub mod store;
```

- [ ] **Step 4: Create `src/doctor.rs` with only the unit tests of the plaintext token check**

`src/doctor.rs`:

```rust
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
```

- [ ] **Step 5: Run the tests to see them fail**

```bash
cargo test --lib doctor::
```
Expected: FAIL, compile errors (`plaintext_token_check` and `Status` do not exist yet).

- [ ] **Step 6: Write the implementation of `doctor`**

Put this above the `#[cfg(test)]` line of `src/doctor.rs`:

```rust
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
```

- [ ] **Step 7: Replace `src/main.rs` with the full command line**

`src/main.rs`:

```rust
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use op_secretd::config;
use op_secretd::doctor::Status;
use op_secretd::error::{Error, Result};
use op_secretd::op::Probe;
use op_secretd::{doctor, lifecycle};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about = "Secret Service provider backed by 1Password")]
struct Cli {
    /// Path of the configuration file.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon on the session bus.
    Serve,
    /// Check the configuration, 1Password access and the bus.
    Doctor,
    /// Manage the configuration file.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Write a commented configuration file.
    Init {
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
}

fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn config_path(cli: &Cli) -> Result<PathBuf> {
    match &cli.config {
        Some(path) => Ok(path.clone()),
        None => config::default_path(&env_var),
    }
}

fn init_logging(level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

fn config_init(path: &std::path::Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(Error::Config(format!(
            "{} already exists; use --force to overwrite",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Config(format!("{}: {e}", parent.display())))?;
    }
    std::fs::write(path, config::EXAMPLE)
        .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
    println!("wrote {}", path.display());
    Ok(())
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let path = config_path(&cli)?;
    match &cli.command {
        Command::Config {
            action: ConfigAction::Init { force },
        } => {
            config_init(&path, *force)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Serve => {
            let config = config::load(&path, &env_var)?;
            init_logging(&config.log_level);
            lifecycle::serve(config, Probe::real()).await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Doctor => {
            let config = match config::load(&path, &env_var) {
                Ok(config) => config,
                Err(error) => {
                    println!("FAIL  configuration: {error}");
                    return Ok(ExitCode::FAILURE);
                }
            };
            let checks = doctor::run(&config, &Probe::real()).await;
            for check in &checks {
                let label = match check.status {
                    Status::Ok => "ok  ",
                    Status::Warn => "warn",
                    Status::Fail => "FAIL",
                };
                println!("{label}  {}: {}", check.name, check.detail);
            }
            Ok(if checks.iter().all(|check| check.status != Status::Fail) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("op-secretd: {error}");
            ExitCode::FAILURE
        }
    }
}
```

- [ ] **Step 8: Run all tests**

```bash
cargo test
```
Expected: PASS: 80 library tests (74 plus 6 for `doctor`), 3 fixture tests, 7 CLI tests, and 15 protocol tests.

- [ ] **Step 9: Check formatting and lints**

```bash
cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings
```
Expected: no output.

- [ ] **Step 10: Commit**

```bash
git add src tests/cli.rs
git commit -m "feat(cli): add doctor and config init"
```


### Task 8: Third-party client compatibility

**Files:**
- Create: `tests/clients.rs`, `tests/fixtures/go-keyring/main.go`, `tests/fixtures/go-keyring/go.mod`, `tests/fixtures/go-keyring/go.sum`

Runs real clients against the daemon: the Go `go-keyring` library (the keyring layer of the GitHub and GitLab CLIs), Python's `keyring` with SecretStorage (which negotiates the DH session), and `secret-tool`. A missing client, or a tool that is only a version-manager shim, skips its test unless `OP_SECRETD_REQUIRE_CLIENTS` is set. These tests are compatibility checks for code that already exists, so they are expected to pass on the first run; a failure points at a protocol deviation.

**Interfaces:**
- Consumes: `Harness`, the daemon binary.
- Produces: nothing for later tasks.

- [ ] **Step 1: Create the Go client**

`tests/fixtures/go-keyring/main.go`:

```go
// Command go-keyring exercises the Secret Service through zalando/go-keyring,
// the library the GitHub and GitLab CLIs use. It prints one result per line.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/zalando/go-keyring"
)

func fail(step string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", step, err)
	os.Exit(1)
}

func main() {
	const service, user, secret = "gh:github.com", "bob", "tok-from-go"

	if err := keyring.Set(service, user, secret); err != nil {
		fail("set", err)
	}
	got, err := keyring.Get(service, user)
	if err != nil {
		fail("get", err)
	}
	if got != secret {
		fail("get", fmt.Errorf("got %q, want %q", got, secret))
	}
	fmt.Println("roundtrip ok")

	if err := keyring.Set(service, user, "tok-2"); err != nil {
		fail("overwrite", err)
	}
	if got, _ = keyring.Get(service, user); got != "tok-2" {
		fail("overwrite", fmt.Errorf("got %q, want tok-2", got))
	}
	fmt.Println("overwrite ok")

	if err := keyring.Delete(service, user); err != nil {
		fail("delete", err)
	}
	if _, err := keyring.Get(service, user); !errors.Is(err, keyring.ErrNotFound) {
		fail("get after delete", fmt.Errorf("expected ErrNotFound, got %v", err))
	}
	fmt.Println("delete ok")
}
```

- [ ] **Step 2: Create the Go module file**

`tests/fixtures/go-keyring/go.mod`:

```text
module example.invalid/go-keyring-check

go 1.24
```

- [ ] **Step 3: Resolve the Go dependencies (needs network access)**

```bash
cd tests/fixtures/go-keyring && go get github.com/zalando/go-keyring@v0.2.8 && go mod tidy && cd -
```
Expected: `go.mod` gains the `require` lines and `go.sum` is created.

- [ ] **Step 4: Create `tests/clients.rs`**

`tests/clients.rs`:

```rust
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
```

- [ ] **Step 5: Run the client tests**

```bash
cargo test --test clients
```
Expected: PASS (five tests: two check that tools are detected correctly, since a version-manager shim is not a client and a tool that exits non-zero is still installed; three run real clients, and a client that is not installed prints `SKIPPED` and its test passes).

- [ ] **Step 6: Check formatting and lints**

```bash
cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings
```
Expected: no output.

- [ ] **Step 7: Commit**

```bash
git add tests/clients.rs tests/fixtures/go-keyring
git commit -m "test: check compatibility with go-keyring, python keyring and secret-tool"
```


### Task 9: Packaging and release scripts

**Files:**
- Create: `scripts/test-release-scripts.sh`, `scripts/validate-release-version.sh`, `scripts/package-release.sh`, `scripts/check-conventional-commits.sh`, `packaging/op-secretd.service`, `packaging/org.freedesktop.secrets.service`

The systemd user unit and the D-Bus activation file that start the daemon on demand, plus three scripts: one validates that a release tag equals the crate version, one builds a reproducible archive, and one rejects commit subjects that are not Conventional Commits. The test script runs them against a stand-in binary and a scratch repository.

**Interfaces:**
- Consumes: `op-secretd config init` (the archive embeds its output), `LICENSE`, `README.md`.
- Produces: `scripts/validate-release-version.sh <tag> <Cargo.toml>` (prints the version), `scripts/package-release.sh <version> <target> <binary> <outdir>` (prints the archive path), `scripts/check-conventional-commits.sh <range>`.

- [ ] **Step 1: Create the test script and make it executable**

`scripts/test-release-scripts.sh`:

```bash
#!/usr/bin/env bash
# Tests for the release helper scripts; needs only bash, git, tar and gzip.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temp=$(mktemp -d)
trap 'rm -rf -- "$temp"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# --- validate-release-version.sh
printf '[package]\nname = "x"\nversion = "1.2.3"\n' >"$temp/Cargo.toml"
[[ $("$repo/scripts/validate-release-version.sh" v1.2.3 "$temp/Cargo.toml") == 1.2.3 ]] || fail "version output"
"$repo/scripts/validate-release-version.sh" v1.2.4 "$temp/Cargo.toml" 2>/dev/null && fail "mismatched tag accepted"
"$repo/scripts/validate-release-version.sh" 1.2.3 "$temp/Cargo.toml" 2>/dev/null && fail "tag without v accepted"
"$repo/scripts/validate-release-version.sh" v1.2.3-rc1 "$temp/Cargo.toml" 2>/dev/null && fail "pre-release tag accepted"

# --- package-release.sh with a stand-in binary
cat >"$temp/op-secretd" <<'SCRIPT'
#!/bin/sh
# Stand-in for `op-secretd --config <path> config init`.
[ "$3" = config ] && [ "$4" = init ] && printf 'vault = "x"\n' >"$2"
SCRIPT
chmod 0755 "$temp/op-secretd"
export SOURCE_DATE_EPOCH=1700000000
first=$("$repo/scripts/package-release.sh" 1.2.3 x86_64-unknown-linux-musl "$temp/op-secretd" "$temp/out1")
second=$("$repo/scripts/package-release.sh" 1.2.3 x86_64-unknown-linux-musl "$temp/op-secretd" "$temp/out2")
[[ $(basename "$first") == op-secretd_1.2.3_linux_x86_64.tar.gz ]] || fail "archive name: $first"
cmp "$first" "$second" || fail "archives are not reproducible"

listing=$(tar -tzf "$first")
for expected in \
  op-secretd_1.2.3_linux_x86_64/op-secretd \
  op-secretd_1.2.3_linux_x86_64/LICENSE \
  op-secretd_1.2.3_linux_x86_64/README.md \
  op-secretd_1.2.3_linux_x86_64/share/op-secretd/op-secretd.service \
  op-secretd_1.2.3_linux_x86_64/share/op-secretd/org.freedesktop.secrets.service \
  op-secretd_1.2.3_linux_x86_64/share/op-secretd/config.example.toml; do
  grep -Fxq "$expected" <<<"$listing" || fail "missing $expected"
done
verbose=$(tar -tvzf "$first")
grep -q 'rwxr-xr-x 0/0 .* op-secretd_1.2.3_linux_x86_64/op-secretd$' <<<"$verbose" || fail "binary mode or owner"
grep -q '2023-11-14' <<<"$verbose" || fail "timestamps are not pinned"

"$repo/scripts/package-release.sh" 1.2.3 riscv64-unknown-linux-musl "$temp/op-secretd" "$temp/out3" 2>/dev/null &&
  fail "unsupported target accepted"
aarch=$("$repo/scripts/package-release.sh" 1.2.3 aarch64-unknown-linux-musl "$temp/op-secretd" "$temp/out4")
[[ $(basename "$aarch") == op-secretd_1.2.3_linux_aarch64.tar.gz ]] || fail "aarch64 name"

# --- check-conventional-commits.sh in a scratch repository
git init -q "$temp/repo"
git -C "$temp/repo" config user.email t@example.invalid
git -C "$temp/repo" config user.name T
git -C "$temp/repo" commit -q --allow-empty -m "chore: start"
git -C "$temp/repo" commit -q --allow-empty -m "feat(dbus)!: breaking change"
(cd "$temp/repo" && "$repo/scripts/check-conventional-commits.sh" HEAD) || fail "valid subjects rejected"
git -C "$temp/repo" commit -q --allow-empty -m "Fix the thing"
(cd "$temp/repo" && "$repo/scripts/check-conventional-commits.sh" HEAD 2>/dev/null) && fail "invalid subject accepted"

echo "release script tests passed"
```

- [ ] **Step 2: Run it to see it fail**

```bash
bash scripts/test-release-scripts.sh
```
Expected: FAIL: the scripts it calls do not exist yet.

- [ ] **Step 3: Create `scripts/validate-release-version.sh`**

`scripts/validate-release-version.sh`:

```bash
#!/usr/bin/env bash
# Usage: validate-release-version.sh <tag> <Cargo.toml>
# Checks that a vX.Y.Z tag matches the crate version and prints the version.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <tag> <Cargo.toml>" >&2
  exit 2
fi
tag=$1
manifest=$2

if [[ ! $tag =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
  echo "tag '$tag' is not of the form vX.Y.Z" >&2
  exit 1
fi
version=${BASH_REMATCH[1]}

crate_version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$manifest" | head -n1)
if [[ "$crate_version" != "$version" ]]; then
  echo "tag $tag does not match the crate version '$crate_version' in $manifest" >&2
  exit 1
fi
printf '%s\n' "$version"
```

- [ ] **Step 4: Create `scripts/package-release.sh`**

`scripts/package-release.sh`:

```bash
#!/usr/bin/env bash
# Usage: package-release.sh <version> <target-triple> <binary> <output-dir>
# Builds op-secretd_<version>_linux_<arch>.tar.gz deterministically and prints its path.
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <version> <target-triple> <binary> <output-dir>" >&2
  exit 2
fi
version=$1
target=$2
binary=$3
output=$4

case "$target" in
  x86_64-unknown-linux-musl) arch=x86_64 ;;
  aarch64-unknown-linux-musl) arch=aarch64 ;;
  *)
    echo "unsupported target: $target" >&2
    exit 1
    ;;
esac

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
name="op-secretd_${version}_linux_${arch}"
temp=$(mktemp -d)
trap 'rm -rf -- "$temp"' EXIT
stage="$temp/$name"

install -d "$stage/share/op-secretd"
install -m 0755 "$binary" "$stage/op-secretd"
install -m 0644 "$repo/packaging/op-secretd.service" "$stage/share/op-secretd/op-secretd.service"
install -m 0644 "$repo/packaging/org.freedesktop.secrets.service" \
  "$stage/share/op-secretd/org.freedesktop.secrets.service"
# The binary is the single source of truth for the example configuration.
"$stage/op-secretd" --config "$stage/share/op-secretd/config.example.toml" config init >/dev/null
chmod 0644 "$stage/share/op-secretd/config.example.toml"
install -m 0644 "$repo/LICENSE" "$stage/LICENSE"
install -m 0644 "$repo/README.md" "$stage/README.md"

# A stable timestamp keeps the archive reproducible for a given commit.
: "${SOURCE_DATE_EPOCH:=$(git -C "$repo" log -1 --format=%ct)}"
mkdir -p "$output"
archive="$output/$name.tar.gz"
tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner \
  --format=posix --pax-option='exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime' \
  -C "$temp" -cf - "$name" | gzip -n -9 >"$archive"
printf '%s\n' "$archive"
```

- [ ] **Step 5: Create `scripts/check-conventional-commits.sh`**

`scripts/check-conventional-commits.sh`:

```bash
#!/usr/bin/env bash
# Usage: check-conventional-commits.sh <revision-range>
# Fails when a non-merge commit subject is not a Conventional Commit.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <revision-range>" >&2
  exit 2
fi

pattern='^(feat|fix|docs|refactor|test|build|ci|chore|perf|style|revert)(\([a-z0-9._/-]+\))?!?: .+'
status=0
while IFS= read -r subject; do
  if [[ ! $subject =~ $pattern ]]; then
    echo "not a Conventional Commit subject: $subject" >&2
    status=1
  fi
done < <(git log --no-merges --format=%s "$1")
exit "$status"
```

- [ ] **Step 6: Create the systemd user unit**

`packaging/op-secretd.service`:

```ini
[Unit]
Description=Secret Service provider backed by 1Password
Documentation=https://github.com/e-kulikov/op-secret-service

[Service]
Type=dbus
BusName=org.freedesktop.secrets
ExecStart=%h/.local/bin/op-secretd serve
NoNewPrivileges=yes
PrivateTmp=yes
```

- [ ] **Step 7: Create the D-Bus activation file**

`packaging/org.freedesktop.secrets.service`:

```ini
[D-BUS Service]
Name=org.freedesktop.secrets
Exec=/bin/false
SystemdService=op-secretd.service
```

- [ ] **Step 8: Run the script tests**

```bash
bash scripts/test-release-scripts.sh
```
Expected: `release script tests passed`.

- [ ] **Step 9: Lint the scripts**

```bash
shellcheck scripts/*.sh
```
Expected: no output (install `shellcheck` if it is missing).

- [ ] **Step 10: Commit**

```bash
git add scripts packaging
git commit -m "build: add release packaging scripts"
```


### Task 10: CI, release automation, and the README

**Files:**
- Create: `.github/workflows/verify.yml`, `.github/workflows/release.yml`, `release-please-config.json`, `.release-please-manifest.json`
- Modify: `README.md`

`verify.yml` runs formatting, lints, the whole test suite with every real client required, the script tests, and (on pull requests) the commit-subject check. `release.yml` follows the release process of the spec: release-please maintains the release pull request and creates a draft release with its tag; the verification workflow runs against it; static musl binaries are built for both architectures and checked; the assets, checksums, and attestations are uploaded and re-verified; only then is the draft published and `stable` fast-forwarded. The `tag` input of the manual run recovers a draft whose publication failed.

**Interfaces:**
- Consumes: `scripts/*`, `packaging/*`, the repository secret `RELEASE_PLEASE_TOKEN`.
- Produces: the `verify` workflow (also callable), the `release` workflow, the release-please configuration.

- [ ] **Step 1: Create `.github/workflows/verify.yml`**

`.github/workflows/verify.yml`:

```yaml
name: verify

on:
  pull_request:
  push:
    branches: [main]
  workflow_call:

permissions:
  contents: read

jobs:
  verify:
    name: Verify
    runs-on: ubuntu-latest
    env:
      CARGO_TERM_COLOR: always
      OP_SECRETD_REQUIRE_CLIENTS: "1"
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0

      - name: Install system packages
        run: |
          sudo apt-get update
          sudo apt-get install --yes --no-install-recommends dbus libsecret-tools python3-venv shellcheck

      - uses: actions/setup-go@v7
        with:
          go-version-file: tests/fixtures/go-keyring/go.mod

      - name: Install the Python keyring client
        run: |
          python3 -m venv "$RUNNER_TEMP/venv"
          "$RUNNER_TEMP/venv/bin/pip" install keyring secretstorage
          echo "OP_SECRETD_TEST_PYTHON=$RUNNER_TEMP/venv/bin/python" >>"$GITHUB_ENV"

      - name: Install the pinned Rust toolchain
        run: |
          channel=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)
          rustup toolchain install "$channel" --profile minimal --component rustfmt,clippy
          rustup default "$channel"

      - name: Check formatting
        run: cargo fmt --check

      - name: Lint
        run: cargo clippy --all-targets --locked -- -D warnings

      - name: Test
        run: cargo test --locked

      - name: Check shell scripts
        run: |
          bash -n scripts/*.sh
          shellcheck scripts/*.sh
          scripts/test-release-scripts.sh

      - name: Check commit messages
        if: github.event_name == 'pull_request'
        run: scripts/check-conventional-commits.sh "origin/${{ github.base_ref }}..HEAD"
```

- [ ] **Step 2: Create `.github/workflows/release.yml`**

`.github/workflows/release.yml`:

```yaml
name: release

on:
  push:
    branches: [main]
  workflow_dispatch:
    inputs:
      tag:
        description: Existing draft release tag to build and publish again (recovery)
        required: false
        type: string

permissions: {}

concurrency:
  group: release
  cancel-in-progress: false

jobs:
  release-please:
    name: Release PR and draft release
    runs-on: ubuntu-latest
    permissions:
      contents: read
    outputs:
      tag: ${{ inputs.tag || steps.rp.outputs.tag_name }}
      publish: ${{ inputs.tag != '' || steps.rp.outputs.release_created == 'true' }}
    steps:
      - id: rp
        uses: googleapis/release-please-action@v5
        with:
          token: ${{ secrets.RELEASE_PLEASE_TOKEN }}
          config-file: release-please-config.json
          manifest-file: .release-please-manifest.json

  verify:
    name: Verify the release
    needs: release-please
    if: needs.release-please.outputs.publish == 'true'
    uses: ./.github/workflows/verify.yml
    permissions:
      contents: read

  build:
    name: Build ${{ matrix.target }}
    needs: [release-please, verify]
    runs-on: ${{ matrix.runner }}
    permissions:
      contents: read
    strategy:
      fail-fast: true
      matrix:
        include:
          - target: x86_64-unknown-linux-musl
            runner: ubuntu-latest
          - target: aarch64-unknown-linux-musl
            runner: ubuntu-24.04-arm
    env:
      CARGO_TERM_COLOR: always
      TAG: ${{ needs.release-please.outputs.tag }}
    steps:
      - uses: actions/checkout@v7
        with:
          ref: ${{ needs.release-please.outputs.tag }}
          persist-credentials: false

      - name: Validate the tag against the crate version
        id: version
        run: echo "version=$(scripts/validate-release-version.sh "$TAG" Cargo.toml)" >>"$GITHUB_OUTPUT"

      - name: Install build prerequisites
        run: sudo apt-get install --yes --no-install-recommends musl-tools

      - name: Install the pinned Rust toolchain
        run: |
          channel=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)
          rustup toolchain install "$channel" --profile minimal --target "${{ matrix.target }}"
          rustup default "$channel"

      - name: Build a static binary
        run: |
          cargo build --release --locked --target "${{ matrix.target }}"
          binary="target/${{ matrix.target }}/release/op-secretd"
          file "$binary"
          if readelf -l "$binary" | grep -Fq INTERP; then
            echo "the binary has a dynamic interpreter" >&2
            exit 1
          fi
          if readelf -d "$binary" | grep -Fq NEEDED; then
            echo "the binary has a dynamic dependency" >&2
            exit 1
          fi
          "$binary" --version | grep -Fx "op-secretd ${{ steps.version.outputs.version }}"

      - name: Package
        run: |
          scripts/package-release.sh \
            "${{ steps.version.outputs.version }}" "${{ matrix.target }}" \
            "target/${{ matrix.target }}/release/op-secretd" dist

      - uses: actions/upload-artifact@v7
        with:
          name: dist-${{ matrix.target }}
          path: dist/*.tar.gz
          if-no-files-found: error

  publish:
    name: Publish the release
    needs: [release-please, build]
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
      attestations: write
    env:
      GH_TOKEN: ${{ secrets.RELEASE_PLEASE_TOKEN }}
      TAG: ${{ needs.release-please.outputs.tag }}
    steps:
      - uses: actions/checkout@v7
        with:
          ref: ${{ needs.release-please.outputs.tag }}
          fetch-depth: 0
          token: ${{ secrets.RELEASE_PLEASE_TOKEN }}

      - uses: actions/download-artifact@v8
        with:
          pattern: dist-*
          path: dist
          merge-multiple: true

      - name: Checksums
        working-directory: dist
        run: |
          sha256sum ./*.tar.gz | sed 's# \./# #' >SHA256SUMS
          sha256sum --check SHA256SUMS

      - uses: actions/attest-build-provenance@v4
        with:
          subject-path: |
            dist/*.tar.gz
            dist/SHA256SUMS

      - name: Upload the assets to the draft release
        run: gh release upload "$TAG" dist/*.tar.gz dist/SHA256SUMS --clobber

      - name: Verify the uploaded assets
        run: |
          mkdir verify
          gh release download "$TAG" --dir verify
          (cd verify && sha256sum --check SHA256SUMS)
          archives=(verify/*.tar.gz)
          test "${#archives[@]}" -eq 2

      - name: Publish the release
        run: gh release edit "$TAG" --draft=false --latest

      - name: Fast-forward stable
        run: |
          sha=$(git rev-list -n1 "$TAG")
          git fetch origin stable || true
          if git rev-parse --verify --quiet origin/stable >/dev/null &&
            ! git merge-base --is-ancestor origin/stable "$sha"; then
            echo "stable is not an ancestor of $TAG; refusing to move it" >&2
            exit 1
          fi
          git push origin "$sha:refs/heads/stable"
```

- [ ] **Step 3: Create `release-please-config.json`**

`release-please-config.json`:

```json
{
  "$schema": "https://raw.githubusercontent.com/googleapis/release-please/main/schemas/config.json",
  "release-type": "rust",
  "bump-minor-pre-major": true,
  "bump-patch-for-minor-pre-major": false,
  "draft": true,
  "force-tag-creation": true,
  "include-component-in-tag": false,
  "packages": {
    ".": {}
  }
}
```

- [ ] **Step 4: Create `.release-please-manifest.json`**

`.release-please-manifest.json`:

```json
{
  ".": "0.0.0"
}
```

- [ ] **Step 5: Lint the workflows and the JSON files**

```bash
actionlint .github/workflows/*.yml && python3 -c "import json; json.load(open('release-please-config.json')); json.load(open('.release-please-manifest.json'))"
```
Expected: no output (install `actionlint` with `go install github.com/rhysd/actionlint/cmd/actionlint@latest` if it is missing).

- [ ] **Step 6: Commit**

```bash
git add .github release-please-config.json .release-please-manifest.json
git commit -m "ci: add verification and release workflows"
```


- [ ] **Step 7: Replace the placeholder `README.md`**

`README.md`:

````markdown
# op-secretd

`op-secretd` is a daemon that implements the freedesktop Secret Service API
(`org.freedesktop.secrets`) on top of 1Password. Programs that keep secrets in
the system keyring over D-Bus (the GitHub and GitLab CLIs, `az devops`, Git
Credential Manager, `secret-tool`, Python's `keyring`, and others) store them in
a 1Password vault instead of gnome-keyring or `pass`. There is no separate
keyring password, nothing is stored in plaintext, and the 1Password app shows the
approval prompt.

Platforms: Linux, including WSL2. macOS and Windows clients use their native
keychains and do not need this daemon.

## How it works

The daemon runs on the session bus and talks to 1Password through the `op`
command line tool:

- **WSL:** the Windows `op.exe` is used through WSL interop, so the approval
  prompt appears on the Windows host.
- **Linux:** the native `op` is used, signed in through the 1Password app.
- **Service account:** a service account token can be used instead of the app.

Every secret is one Password item in a dedicated vault, titled
`secret-service/<hash of its attributes>` and tagged `secret-service` plus a tag that
records its attributes, so a search needs one listing instead of reading every item. Items are
cached in memory for `cache_ttl`; nothing is written to disk. The daemon starts
on demand and exits after `idle_timeout` without requests.

## Requirements

- A 1Password account and a vault for the secrets (the daemon never creates one).
- The 1Password CLI: on WSL the Windows `op.exe` (enable *Settings, Developer,
  Integrate with 1Password CLI* in the Windows app), elsewhere the native `op`.
- A D-Bus session bus. No other Secret Service provider may run at the same time
  (gnome-keyring and KeePassXC own the same bus name).

## Install

Download `op-secretd_<version>_linux_<arch>.tar.gz` and `SHA256SUMS` from the
[releases](https://github.com/e-kulikov/op-secret-service/releases), verify the
checksum, and unpack the archive:

```sh
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf op-secretd_<version>_linux_<arch>.tar.gz
cd op-secretd_<version>_linux_<arch>

install -Dm755 op-secretd ~/.local/bin/op-secretd
install -Dm644 share/op-secretd/op-secretd.service ~/.config/systemd/user/op-secretd.service
install -Dm644 share/op-secretd/org.freedesktop.secrets.service \
  ~/.local/share/dbus-1/services/org.freedesktop.secrets.service
systemctl --user daemon-reload

op-secretd config init        # writes ~/.config/op-secretd/config.toml
$EDITOR ~/.config/op-secretd/config.toml    # set `vault`
op-secretd doctor
```

The systemd unit and the D-Bus activation file start the daemon the first time a
client asks for the keyring.

## Configuration

`$XDG_CONFIG_HOME/op-secretd/config.toml`; every key can also be set with an
`OP_SECRETD_<KEY>` environment variable (`OP_SECRETD_OP_BINARY` for `[op] binary`).
`op-secretd config init` writes a commented file.

| Key | Default | Meaning |
| --- | --- | --- |
| `vault` | none | Vault that holds the secrets. Required. |
| `account` | empty | Passed to `op --account`. |
| `mode` | `auto` | `auto`, `app` or `service-account`. |
| `tag` | `secret-service` | Tag put on every item. |
| `cache_ttl` | `5m` | In-memory cache lifetime; `0` disables it. |
| `idle_timeout` | `1h` | Exit after this long without requests; `0` disables it. |
| `allow` | empty | Attribute patterns (`key=glob`); empty accepts everything. |
| `log_level` | `info` | `error`, `warn`, `info`, `debug` or `trace`. |
| `[op] binary` | `auto` | Path of `op` or `op.exe`. |
| `[op] wsl_interop` | `auto` | `auto`, `true` or `false`. |
| `[op] service_account_token_file` | empty | Token file; its mode must be `0600`. |
| `[op] service_account_token_env` | empty | Environment variable holding the token. |

With `mode = auto` the daemon uses `op.exe` inside WSL (falling back to the native
`op` when it is missing) and the native `op` elsewhere.

## Using it

Once the daemon is installed, clients need no configuration:

```sh
gh auth login                          # the token goes to 1Password
glab auth login --use-keyring          # prefer a personal access token over OAuth
secret-tool store --label=demo service demo username me
```

`op-secretd doctor` checks the configuration, access to the vault, the session
bus, the supported session algorithms, and whether `gh` or `glab` keep a token in
a plaintext configuration file.

**Log in only while `op-secretd doctor` is green.** When the keyring cannot be
written (the daemon is not running, 1Password is unreachable, or an approval was
declined), `gh` and `glab` silently store the token in their plaintext
configuration file instead. `gh` offers `--insecure-storage` but no switch that
forbids the fallback, so the daemon cannot prevent it. After logging in, make sure
`doctor` reports no plaintext tokens; if it does, run `gh auth logout` and
`gh auth login` again while the daemon is healthy.

## Troubleshooting

- **The first request after the daemon starts takes several seconds:** every call to
  the 1Password CLI goes through the app (and through Windows in WSL) and can take
  seconds. Results are then cached for `cache_ttl`, and the daemon stays up for
  `idle_timeout`, so later requests are instant.
- **A client fails with `authorization prompt dismissed`:** the approval prompt in
  the 1Password app was closed or the app was locked and not unlocked. Retry the
  command and approve the prompt.
- **A client hangs for about two minutes right after the daemon failed to start:**
  D-Bus waits for its activation timeout after a failed start. Fix the cause
  (`op-secretd doctor` names it), then start the unit once with
  `systemctl --user start op-secretd.service`.
- **The daemon reports that the configuration is missing:** the packaged systemd
  unit uses a private `/tmp`, so keep the configuration in
  `$XDG_CONFIG_HOME/op-secretd/` rather than under `/tmp`.
- **`org.freedesktop.secrets is already owned by ...`:** another Secret Service
  provider (gnome-keyring, KeePassXC) is running; stop it first.

## Security notes

- Any process in your session that can reach the session bus can read the
  secrets, as with any keyring. Use a dedicated vault and the `allow` list to
  limit what is accepted.
- Secrets are held in zeroized memory, never logged, and never passed in process
  arguments.
- When 1Password cannot be reached or an approval is declined, clients receive a
  D-Bus error instead of an empty answer, so they cannot silently fall back to
  plaintext storage.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

The integration tests start a private `dbus-daemon` and a fake `op`; they never
touch a real 1Password account. They also exercise real clients: the Go
`go-keyring` library, Python's `keyring` (set `OP_SECRETD_TEST_PYTHON` to an
interpreter that has `keyring` and `secretstorage`), and `secret-tool`. A missing
client skips its test unless `OP_SECRETD_REQUIRE_CLIENTS` is set.

Commits follow [Conventional Commits](https://www.conventionalcommits.org/).
Releases are prepared by release-please: merging its release pull request
publishes static `x86_64` and `aarch64` binaries and advances the `stable` branch.

## License

MIT.
````

- [ ] **Step 8: Re-run the script tests**

```bash
bash scripts/test-release-scripts.sh
```
Expected: `release script tests passed` (the archive embeds the new README).

- [ ] **Step 9: Commit**

```bash
git add README.md
git commit -m "docs: add the README"
```


### Task 11: Manual verification checklist

**Files:**
- Create: `docs/manual-checklist.md`

Writes down the checks that need a real 1Password account or real clients. They cover the spec's open verification points and stay out of CI. (The Russian translation `docs/manual-checklist.ru.md` is created locally and is never committed.)

**Interfaces:**
- Consumes: nothing.
- Produces: `docs/manual-checklist.md`.

- [ ] **Step 1: Create `docs/manual-checklist.md`**

```markdown
# Manual verification checklist

These checks need a real 1Password account or real clients and therefore stay out
of CI. Run them before the first release and after changes to the `op` runner,
the store, or the release workflow. Use a throwaway vault.

## Setup

1. Install the daemon as described in the README, set `vault` to a throwaway
   vault, and run `op-secretd doctor`. Every line must start with `ok`.
2. Start the daemon in the foreground with `RUST_LOG=debug op-secretd serve`.

## 1Password access

- [ ] **WSL, `op.exe`:** a request makes the 1Password approval prompt appear on
  the Windows host; approving it completes the request.
- [ ] **Declined approval:** dismissing the prompt makes the client fail with an
  error; nothing is written to a plaintext file.
- [ ] **Native Linux `op`:** with `[op] wsl_interop = "false"` on WSL, or on a
  clean Linux machine, the same flow works.
- [ ] **Service account:** with `mode = "service-account"` and a token file of
  mode `0600`, requests succeed without a prompt; a token file with a wider mode
  makes `doctor` fail.

## Items in a real vault

- [ ] Create, replace, and delete a secret with `secret-tool`; the item
  `secret-service/<hash>` appears with the tag `secret-service`, its fields
  `password`, `label`, `content_type`, `encoding`, and `attributes` are as
  described in the spec, and a deleted item lands in the archive.
- [ ] A 64 KiB secret and a secret with non-UTF-8 content round-trip.
- [ ] Editing the item in the 1Password app (changing the secret) is visible to
  the client after `cache_ttl`.

## Real clients

- [ ] `gh auth login` stores its token in the vault; `gh auth status` and
  `gh api user` work afterwards; the plaintext `hosts.yml` has no token.
- [ ] `gh auth logout` removes the item (it moves to the archive).
- [ ] With the daemon unable to reach 1Password (for example the vault renamed),
  `gh auth login` falls back to a plaintext token file without any warning (known
  `gh` behavior); `op-secretd doctor` then reports `warn  plaintext tokens`, and
  after `gh auth logout` and a login with a healthy daemon the warning is gone.
  Use an isolated `GH_CONFIG_DIR` and a token you can revoke.
- [ ] `glab auth login --use-keyring` with a personal access token works and
  survives a day without re-authentication.
- [ ] `git` with `gh auth git-credential` and `glab auth git-credential`
  clones a private repository using the stored token.

## Lifecycle

- [ ] With D-Bus activation installed and the daemon stopped, the first client
  request starts it; after `idle_timeout` it exits.
- [ ] With gnome-keyring or another provider running, `op-secretd serve` fails
  with a message that names the other owner.

## Release (first run)

- [ ] Merging a `feat` commit to `main` makes release-please open a release
  pull request that bumps the version to `0.1.0`.
- [ ] Merging that pull request creates a draft release with the tag `v0.1.0`,
  runs verification, builds both archives, and uploads them with `SHA256SUMS`.
- [ ] The draft is then published, `stable` points at the tagged commit, and the
  next push to `main` does not open a duplicate release pull request.
- [ ] Downloading the archive, verifying the checksum and the attestation
  (`gh attestation verify`), and following the README install steps yields a
  working daemon.
```

- [ ] **Step 2: Check that no Cyrillic reached tracked files**

```bash
git grep -lP '[\x{0400}-\x{04FF}]' -- . ':!*.ru.md' || echo none
```
Expected: `none` (no Cyrillic in tracked files).

- [ ] **Step 3: Commit**

```bash
git add docs/manual-checklist.md
git commit -m "docs: add the manual verification checklist"
```


---

## Self-review notes

- Every section of the spec maps to a task: configuration (2), attribute identity and allow list (1), session encryption (3), 1Password access and the three launch modes (4), storage model and caching (5), the D-Bus API, lifecycle, idle handling, and error behavior (6), `doctor` and `config init` (7), real-client compatibility (8), packaging (9), CI, release process, and README (10), manual checks and open verification points (11).
- Type and method names were checked by building each task in a clean directory in order, so later tasks only use names defined earlier.
- The `.ru.md` translations of the spec, this plan, and the checklist are regenerated in full from the English files and are never committed.
