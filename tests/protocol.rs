mod common;

use std::collections::HashMap;

use common::{BUS_NAME, Harness};
use op_secretd::crypto::{ALGORITHM_DH, ALGORITHM_PLAIN, DhKeypair, SessionCipher};
use op_secretd::dbus::Secret;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, Proxy};

const SERVICE: &str = "/org/freedesktop/secrets";
const COLLECTION: &str = "/org/freedesktop/secrets/collection/login";
const SERVICE_IFACE: &str = "org.freedesktop.Secret.Service";
const COLLECTION_IFACE: &str = "org.freedesktop.Secret.Collection";
const ITEM_IFACE: &str = "org.freedesktop.Secret.Item";

type Attrs = HashMap<String, String>;

fn attrs(pairs: &[(&str, &str)]) -> Attrs {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

struct Client {
    connection: Connection,
    session: OwnedObjectPath,
    cipher: SessionCipher,
}

impl Client {
    async fn open(harness: &Harness, algorithm: &str) -> Self {
        let connection = harness.connect().await;
        let (cipher, input) = if algorithm == ALGORITHM_DH {
            let keypair = DhKeypair::generate().unwrap();
            let input = Value::from(keypair.public.clone());
            let reply = open_session(&connection, algorithm, input).await.unwrap();
            let server_public = Vec::<u8>::try_from(reply.0.try_clone().unwrap()).unwrap();
            let cipher = SessionCipher::Aes(keypair.derive_key(&server_public).unwrap());
            return Self {
                connection,
                session: reply.1,
                cipher,
            };
        } else {
            (SessionCipher::Plain, Value::from(""))
        };
        let reply = open_session(&connection, algorithm, input).await.unwrap();
        Self {
            connection,
            session: reply.1,
            cipher,
        }
    }

    async fn call<B, T>(&self, path: &str, iface: &str, member: &str, body: &B) -> zbus::Result<T>
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
        T: for<'d> serde::Deserialize<'d> + zbus::zvariant::Type,
    {
        let message = self
            .connection
            .call_method(Some(BUS_NAME), path, Some(iface), member, body)
            .await?;
        message.body().deserialize::<T>()
    }

    fn secret(&self, value: &[u8]) -> Secret {
        let (parameters, value) = self.cipher.encrypt(value).unwrap();
        Secret {
            session: self.session.clone(),
            parameters,
            value,
            content_type: "text/plain".into(),
        }
    }

    fn reveal(&self, secret: &Secret) -> Vec<u8> {
        self.cipher
            .decrypt(&secret.parameters, &secret.value)
            .unwrap()
            .to_vec()
    }

    async fn create(
        &self,
        label: &str,
        attributes: &Attrs,
        value: &[u8],
        replace: bool,
    ) -> zbus::Result<OwnedObjectPath> {
        let mut properties: HashMap<&str, Value<'_>> = HashMap::new();
        properties.insert("org.freedesktop.Secret.Item.Label", Value::from(label));
        properties.insert(
            "org.freedesktop.Secret.Item.Attributes",
            Value::new(attributes.clone()),
        );
        let (item, _prompt): (OwnedObjectPath, OwnedObjectPath) = self
            .call(
                COLLECTION,
                COLLECTION_IFACE,
                "CreateItem",
                &(properties, self.secret(value), replace),
            )
            .await?;
        Ok(item)
    }

    async fn search(&self, attributes: &Attrs) -> zbus::Result<Vec<OwnedObjectPath>> {
        let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = self
            .call(SERVICE, SERVICE_IFACE, "SearchItems", &(attributes,))
            .await?;
        assert!(locked.is_empty());
        Ok(unlocked)
    }

    async fn get_secret(&self, item: &OwnedObjectPath) -> zbus::Result<Vec<u8>> {
        let secret: Secret = self
            .call(
                item.as_str(),
                ITEM_IFACE,
                "GetSecret",
                &(ObjectPath::try_from(self.session.as_str()).unwrap(),),
            )
            .await?;
        Ok(self.reveal(&secret))
    }

    async fn property<T>(&self, path: &str, iface: &str, name: &str) -> zbus::Result<T>
    where
        T: TryFrom<OwnedValue>,
        T::Error: Into<zbus::Error>,
    {
        Proxy::new(&self.connection, BUS_NAME, path, iface)
            .await?
            .get_property(name)
            .await
    }
}

async fn open_session(
    connection: &Connection,
    algorithm: &str,
    input: Value<'_>,
) -> zbus::Result<(OwnedValue, OwnedObjectPath)> {
    let message = connection
        .call_method(
            Some(BUS_NAME),
            SERVICE,
            Some(SERVICE_IFACE),
            "OpenSession",
            &(algorithm, input),
        )
        .await?;
    message.body().deserialize()
}

async fn search_via(
    connection: &Connection,
    attributes: &Attrs,
) -> zbus::Result<Vec<OwnedObjectPath>> {
    let message = connection
        .call_method(
            Some(BUS_NAME),
            SERVICE,
            Some(SERVICE_IFACE),
            "SearchItems",
            &(attributes,),
        )
        .await?;
    let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) =
        message.body().deserialize()?;
    assert!(locked.is_empty());
    Ok(unlocked)
}

fn error_name(error: &zbus::Error) -> String {
    match error {
        zbus::Error::MethodError(name, ..) => name.to_string(),
        other => other.to_string(),
    }
}

async fn harness() -> Harness {
    let mut harness = Harness::new();
    harness.start_daemon(&[]).await;
    harness
}

#[tokio::test]
async fn plain_session_roundtrip() {
    let harness = harness().await;
    let client = Client::open(&harness, ALGORITHM_PLAIN).await;
    let attributes = attrs(&[("service", "gh:github.com"), ("username", "bob")]);

    let item = client
        .create("gh token", &attributes, b"tok-1", false)
        .await
        .unwrap();
    assert!(item.as_str().starts_with(&format!("{COLLECTION}/")));

    assert_eq!(
        client
            .search(&attrs(&[("service", "gh:github.com")]))
            .await
            .unwrap(),
        vec![item.clone()]
    );
    assert!(
        client
            .search(&attrs(&[("service", "nope")]))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(client.get_secret(&item).await.unwrap(), b"tok-1");

    let stored: Attrs = client
        .property(item.as_str(), ITEM_IFACE, "Attributes")
        .await
        .unwrap();
    assert_eq!(stored, attributes);
    let label: String = client
        .property(item.as_str(), ITEM_IFACE, "Label")
        .await
        .unwrap();
    assert_eq!(label, "gh token");
    let locked: bool = client
        .property(item.as_str(), ITEM_IFACE, "Locked")
        .await
        .unwrap();
    assert!(!locked);

    let items: Vec<OwnedObjectPath> = client
        .property(COLLECTION, COLLECTION_IFACE, "Items")
        .await
        .unwrap();
    assert_eq!(items, vec![item.clone()]);

    let _: OwnedObjectPath = client
        .call(item.as_str(), ITEM_IFACE, "Delete", &())
        .await
        .unwrap();
    assert!(client.search(&attributes).await.unwrap().is_empty());
}

#[tokio::test]
async fn dh_session_roundtrip() {
    let harness = harness().await;
    let client = Client::open(&harness, ALGORITHM_DH).await;
    let attributes = attrs(&[("service", "glab"), ("username", "")]);

    let item = client
        .create(
            "glab token",
            &attributes,
            "秘密-\u{1F512}".as_bytes(),
            false,
        )
        .await
        .unwrap();
    assert_eq!(
        client.get_secret(&item).await.unwrap(),
        "秘密-\u{1F512}".as_bytes()
    );

    let secrets: HashMap<OwnedObjectPath, Secret> = client
        .call(
            SERVICE,
            SERVICE_IFACE,
            "GetSecrets",
            &(
                vec![ObjectPath::try_from(item.as_str()).unwrap()],
                ObjectPath::try_from(client.session.as_str()).unwrap(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(client.reveal(&secrets[&item]), "秘密-\u{1F512}".as_bytes());
}

#[tokio::test]
async fn replace_and_set_secret() {
    let harness = harness().await;
    let client = Client::open(&harness, ALGORITHM_PLAIN).await;
    let attributes = attrs(&[("k", "v")]);

    let first = client
        .create("one", &attributes, b"1", false)
        .await
        .unwrap();
    let again = client
        .create("two", &attributes, b"2", false)
        .await
        .unwrap();
    assert_eq!(first, again);
    assert_eq!(
        client.get_secret(&first).await.unwrap(),
        b"1",
        "without replace the old value stays"
    );

    client.create("two", &attributes, b"2", true).await.unwrap();
    assert_eq!(client.get_secret(&first).await.unwrap(), b"2");

    let _: () = client
        .call(
            first.as_str(),
            ITEM_IFACE,
            "SetSecret",
            &(client.secret(b"3"),),
        )
        .await
        .unwrap();
    assert_eq!(client.get_secret(&first).await.unwrap(), b"3");
    assert_eq!(client.search(&attrs(&[])).await.unwrap().len(), 1);
}

#[tokio::test]
async fn default_alias_and_collections() {
    let harness = harness().await;
    let client = Client::open(&harness, ALGORITHM_PLAIN).await;
    let alias: OwnedObjectPath = client
        .call(SERVICE, SERVICE_IFACE, "ReadAlias", &("default",))
        .await
        .unwrap();
    assert_eq!(alias.as_str(), COLLECTION);
    let other: OwnedObjectPath = client
        .call(SERVICE, SERVICE_IFACE, "ReadAlias", &("nope",))
        .await
        .unwrap();
    assert_eq!(other.as_str(), "/");
    let collections: Vec<OwnedObjectPath> = client
        .property(SERVICE, SERVICE_IFACE, "Collections")
        .await
        .unwrap();
    assert_eq!(collections.len(), 1);

    let via_alias = client
        .create("a", &attrs(&[("k", "v")]), b"x", false)
        .await
        .unwrap();
    let items: Vec<OwnedObjectPath> = client
        .call(
            "/org/freedesktop/secrets/aliases/default",
            COLLECTION_IFACE,
            "SearchItems",
            &(attrs(&[("k", "v")]),),
        )
        .await
        .unwrap();
    assert_eq!(items, vec![via_alias]);
}

#[tokio::test]
async fn bad_requests_are_rejected() {
    let harness = harness().await;
    let client = Client::open(&harness, ALGORITHM_PLAIN).await;

    let error = open_session(&client.connection, "rot13", Value::from(""))
        .await
        .unwrap_err();
    assert!(error_name(&error).ends_with("NotSupported"), "{error}");

    let foreign = Secret {
        session: OwnedObjectPath::try_from("/org/freedesktop/secrets/session/999").unwrap(),
        parameters: vec![],
        value: b"x".to_vec(),
        content_type: "text/plain".into(),
    };
    let mut properties: HashMap<&str, Value<'_>> = HashMap::new();
    properties.insert("org.freedesktop.Secret.Item.Label", Value::from("x"));
    properties.insert(
        "org.freedesktop.Secret.Item.Attributes",
        Value::new(attrs(&[("k", "v")])),
    );
    let result: zbus::Result<(OwnedObjectPath, OwnedObjectPath)> = client
        .call(
            COLLECTION,
            COLLECTION_IFACE,
            "CreateItem",
            &(properties, foreign, false),
        )
        .await;
    assert!(error_name(&result.unwrap_err()).ends_with("InvalidArgs"));

    let mut missing: HashMap<&str, Value<'_>> = HashMap::new();
    missing.insert("org.freedesktop.Secret.Item.Label", Value::from("x"));
    let result: zbus::Result<(OwnedObjectPath, OwnedObjectPath)> = client
        .call(
            COLLECTION,
            COLLECTION_IFACE,
            "CreateItem",
            &(missing, client.secret(b"x"), false),
        )
        .await;
    assert!(error_name(&result.unwrap_err()).ends_with("InvalidArgs"));

    let result: zbus::Result<(OwnedObjectPath, OwnedObjectPath)> = client
        .call(
            SERVICE,
            SERVICE_IFACE,
            "CreateCollection",
            &(HashMap::<&str, Value<'_>>::new(), ""),
        )
        .await;
    assert!(error_name(&result.unwrap_err()).ends_with("NotSupported"));
}

#[tokio::test]
async fn closing_a_session_invalidates_it() {
    let harness = harness().await;
    let client = Client::open(&harness, ALGORITHM_PLAIN).await;
    let item = client
        .create("a", &attrs(&[("k", "v")]), b"x", false)
        .await
        .unwrap();
    let _: () = client
        .call(
            client.session.as_str(),
            "org.freedesktop.Secret.Session",
            "Close",
            &(),
        )
        .await
        .unwrap();
    let error = client.get_secret(&item).await.unwrap_err();
    assert!(error_name(&error).ends_with("InvalidArgs"), "{error}");
}

#[tokio::test]
async fn failures_surface_as_errors_not_empty_results() {
    let mut harness = Harness::new();
    harness.start_daemon(&[("cache_ttl", "\"0\"")]).await;
    let client = Client::open(&harness, ALGORITHM_PLAIN).await;
    client
        .create("a", &attrs(&[("k", "v")]), b"x", false)
        .await
        .unwrap();

    std::fs::write(harness.db().join("FAIL"), "").unwrap();
    let error = client.search(&attrs(&[("k", "v")])).await.unwrap_err();
    assert!(error_name(&error).ends_with("Failed"), "{error}");
    assert!(
        error.to_string().contains("authorization prompt dismissed"),
        "{error}"
    );

    std::fs::remove_file(harness.db().join("FAIL")).unwrap();
    assert_eq!(client.search(&attrs(&[("k", "v")])).await.unwrap().len(), 1);
}

#[tokio::test]
async fn allow_list_rejects_other_attributes() {
    let mut harness = Harness::new();
    harness
        .start_daemon(&[("allow", "[\"service=gh:*\"]")])
        .await;
    let client = Client::open(&harness, ALGORITHM_PLAIN).await;
    client
        .create("ok", &attrs(&[("service", "gh:x")]), b"x", false)
        .await
        .unwrap();
    let error = client
        .create("no", &attrs(&[("service", "other")]), b"x", false)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("allow list"), "{error}");
}

#[tokio::test]
async fn the_cache_is_shared_between_requests() {
    let harness = harness().await;
    let client = Client::open(&harness, ALGORITHM_PLAIN).await;
    let item = client
        .create("a", &attrs(&[("k", "v")]), b"x", false)
        .await
        .unwrap();
    for _ in 0..3 {
        client.get_secret(&item).await.unwrap();
        client.search(&attrs(&[("k", "v")])).await.unwrap();
    }
    let log = std::fs::read_to_string(harness.db().join("calls.log")).unwrap();
    let lists = log
        .lines()
        .filter(|line| line.starts_with("item list"))
        .count();
    let reads = log
        .lines()
        .filter(|line| line.starts_with("item get secret-service/"))
        .count();
    assert_eq!(lists, 1, "only the startup load scans the vault:\n{log}");
    assert!(
        reads <= 2,
        "repeated reads of one item hit the cache after at most the existence check and one read:\n{log}"
    );
}

#[tokio::test]
async fn a_second_provider_cannot_take_the_name() {
    let harness = harness().await;
    let config = harness.write_config(&[]);
    let output = harness
        .daemon_command(&config)
        .arg("serve")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("already owned"), "{stderr}");
    assert!(
        !stderr.contains("internal error"),
        "a taken name is not an internal error: {stderr}"
    );
    assert!(stderr.contains("stop that provider first"), "{stderr}");
}

#[tokio::test]
async fn the_daemon_exits_when_idle() {
    let mut harness = Harness::new();
    harness.start_daemon(&[("idle_timeout", "\"1s\"")]).await;
    assert_eq!(
        harness.wait_for_daemon_exit(std::time::Duration::from_secs(15)),
        Some(true)
    );
}

#[tokio::test]
async fn concurrent_requests_share_one_index_load() {
    let harness = harness().await;
    let client = Client::open(&harness, ALGORITHM_PLAIN).await;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let connection = client.connection.clone();
        tasks.spawn(async move {
            search_via(&connection, &attrs(&[("k", "v")]))
                .await
                .unwrap()
                .len()
        });
    }
    while let Some(found) = tasks.join_next().await {
        assert_eq!(found.unwrap(), 0);
    }
    let log = std::fs::read_to_string(harness.db().join("calls.log")).unwrap();
    let lists = log
        .lines()
        .filter(|line| line.starts_with("item list"))
        .count();
    assert_eq!(
        lists, 1,
        "the startup load serves every concurrent search:\n{log}"
    );
    let reads = log
        .lines()
        .filter(|line| line.starts_with("item get secret-service/"))
        .count();
    assert!(
        reads <= 1,
        "concurrent identical searches share one read:\n{log}"
    );
}

#[tokio::test]
async fn empty_large_and_binary_secrets_roundtrip() {
    let harness = harness().await;
    for algorithm in [ALGORITHM_PLAIN, ALGORITHM_DH] {
        let client = Client::open(&harness, algorithm).await;
        let large: Vec<u8> = (0..64 * 1024).map(|i| b'a' + (i % 26) as u8).collect();
        let cases: [(&str, Vec<u8>); 3] = [
            ("empty", Vec::new()),
            ("large", large),
            ("binary", vec![0xff, 0xfe, 0x00, 0x80]),
        ];
        for (name, value) in cases {
            let attributes = attrs(&[("case", name), ("algorithm", algorithm)]);
            let item = client
                .create(name, &attributes, &value, false)
                .await
                .unwrap();
            assert_eq!(
                client.get_secret(&item).await.unwrap(),
                value,
                "{name} over {algorithm}"
            );
        }
    }
}

#[tokio::test]
async fn idle_exit_waits_for_a_request_in_flight() {
    let mut harness = Harness::new();
    harness
        .start_daemon(&[("idle_timeout", "\"1s\""), ("cache_ttl", "\"0\"")])
        .await;
    let client = Client::open(&harness, ALGORITHM_PLAIN).await;
    client
        .create("a", &attrs(&[("k", "v")]), b"x", false)
        .await
        .unwrap();

    // A pending approval: every `op` call now takes 2 seconds, far longer than the idle timeout.
    std::fs::write(harness.db().join("SLOW"), "2").unwrap();
    let found = client.search(&attrs(&[("k", "v")])).await.unwrap();
    assert_eq!(
        found.len(),
        1,
        "the request must finish although the idle timeout elapsed"
    );

    std::fs::remove_file(harness.db().join("SLOW")).unwrap();
    assert_eq!(
        harness.wait_for_daemon_exit(std::time::Duration::from_secs(15)),
        Some(true)
    );
}
