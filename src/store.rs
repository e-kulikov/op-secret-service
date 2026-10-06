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
            singles: Mutex::new(TtlCell::new(config.cache_ttl)),
            write_lock: Mutex::new(()),
        })
    }

    /// Loads the whole tagged set: one `op item list`, then the items by id in
    /// parallel. Each `op` call costs seconds when it goes through Windows.
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
        let ids: Vec<String> = parse_json_stream(&listing)?
            .iter()
            .filter_map(|item| item["id"].as_str().map(str::to_owned))
            .collect();
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
        let mut index = Index::new();
        while let Some(joined) = tasks.join_next().await {
            let output = match joined.map_err(|error| Error::Internal(error.to_string()))? {
                Ok(output) => output,
                // Deleted between the listing and the read.
                Err(Error::NotFound) => continue,
                Err(error) => return Err(error),
            };
            if let Some(record) = parse_item(&output)?
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
        self.singles.lock().await.invalidate();
    }

    /// Items whose attributes contain every pair of `query`. When the query is
    /// the exact attribute set of one item, that item is read directly and the
    /// vault is scanned only if it does not exist.
    pub async fn search(&self, query: &Attributes) -> Result<Vec<ItemInfo>> {
        if !query.is_empty()
            && !self.index_is_fresh()
            && let Some(record) = self.fetch_one(&item_key(query)).await?
        {
            return Ok(vec![record.info]);
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
        assert_eq!(log.len(), 1, "{log:?}");
        assert!(
            log[0].starts_with(&format!("item get secret-service/{key}")),
            "{log:?}"
        );

        assert_eq!(&*cold.secret(&key).await.unwrap().0, b"tok");
        assert_eq!(
            calls(dir.path()).len(),
            1,
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
    async fn a_miss_on_a_cold_store_falls_back_to_the_full_index() {
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
        assert_eq!(calls(dir.path()).len(), 1, "{:?}", calls(dir.path()));
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
}
