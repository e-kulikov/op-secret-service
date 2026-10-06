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
