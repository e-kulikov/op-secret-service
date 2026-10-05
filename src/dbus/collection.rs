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

    /// Items that already have an object; see `preload` for why this never exports.
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
