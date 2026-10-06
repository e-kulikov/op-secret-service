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
