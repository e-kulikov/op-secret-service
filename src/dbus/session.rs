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
