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
