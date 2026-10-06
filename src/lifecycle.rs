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
