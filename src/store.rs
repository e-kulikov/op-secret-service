//! Secrets as 1Password items. One secret is one Password item whose title is
//! derived from its attributes (see `attrs`). Reads load the whole tagged index
//! with two `op` calls and cache it in memory; writes address items by title.

use std::collections::{BTreeMap, HashMap};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::attrs::{AllowList, Attributes, TITLE_PREFIX, item_key, item_title, matches};
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

struct Record {
    info: ItemInfo,
    secret: Zeroizing<Vec<u8>>,
    content_type: String,
    /// 1Password field ids by field label, needed to edit fields in place.
    field_ids: HashMap<String, String>,
}

type Index = BTreeMap<String, Record>;

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
    op: OpRunner,
    vault: String,
    tag: String,
    allow: AllowList,
    index: Mutex<TtlCell<Index>>,
    write_lock: Mutex<()>,
}

impl Store {
    pub fn new(op: OpRunner, config: &Config) -> Result<Self> {
        Ok(Self {
            op,
            vault: config.vault.clone(),
            tag: config.tag.clone(),
            allow: config.allow_list()?,
            index: Mutex::new(TtlCell::new(config.cache_ttl)),
            write_lock: Mutex::new(()),
        })
    }

    async fn load_index(&self) -> Result<Index> {
        let listing = self
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
        if parse_json_stream(&listing)?.is_empty() {
            return Ok(Index::new());
        }
        let items = self
            .op
            .run(&["item", "get", "-", "--format", "json"], Some(&listing))
            .await?;
        let mut index = Index::new();
        for value in parse_json_stream(&items)? {
            let raw: RawItem = serde_json::from_value(value)
                .map_err(|error| Error::OpFailed(format!("unexpected item shape: {error}")))?;
            if let Some(record) = record_from(raw)
                && self.allow.permits(&record.info.attributes)
            {
                index.insert(record.info.key.clone(), record);
            }
        }
        Ok(index)
    }

    async fn with_index<T>(&self, f: impl FnOnce(&Index) -> T) -> Result<T> {
        let mut cell = self.index.lock().await;
        if cell.fresh().is_none() {
            let index = self.load_index().await?;
            cell.set(index);
        }
        Ok(f(cell.current().expect("index was just stored")))
    }

    async fn invalidate(&self) {
        self.index.lock().await.invalidate();
    }

    /// Items whose attributes contain every pair of `query`.
    pub async fn search(&self, query: &Attributes) -> Result<Vec<ItemInfo>> {
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
        self.with_index(|index| index.get(key).map(|r| r.info.clone()))
            .await?
            .ok_or(Error::NotFound)
    }

    /// The secret value and its content type.
    pub async fn secret(&self, key: &str) -> Result<(Zeroizing<Vec<u8>>, String)> {
        self.with_index(|index| {
            index
                .get(key)
                .map(|r| (r.secret.clone(), r.content_type.clone()))
        })
        .await?
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
            .with_index(|index| {
                index
                    .get(&key)
                    .map(|r| (r.info.clone(), r.field_ids.clone()))
            })
            .await?;
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
                        "tags": [self.tag],
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
}
