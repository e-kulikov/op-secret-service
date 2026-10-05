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
