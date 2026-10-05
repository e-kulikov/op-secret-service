//! `op-secretd doctor`: checks that the daemon can run with this setup.

use zbus::fdo::DBusProxy;
use zbus::names::BusName;

use crate::config::Config;
use crate::crypto::{ALGORITHM_DH, DhKeypair, negotiate};
use crate::lifecycle::{BUS_NAME, describe_owner};
use crate::op::{OpRunner, Probe};

pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

fn check(name: &'static str, result: std::result::Result<String, String>) -> Check {
    match result {
        Ok(detail) => Check {
            name,
            ok: true,
            detail,
        },
        Err(detail) => Check {
            name,
            ok: false,
            detail,
        },
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
    checks
}
