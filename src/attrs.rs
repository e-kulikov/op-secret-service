//! Attribute maps, deterministic item identity and the allow list.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Secret Service attributes, sorted by key.
pub type Attributes = BTreeMap<String, String>;

/// Prefix of every item title created by the daemon.
pub const TITLE_PREFIX: &str = "secret-service/";

/// Canonical, unambiguous text form of an attribute set.
pub fn canonical(attributes: &Attributes) -> String {
    let mut out = String::new();
    for (key, value) in attributes {
        out.push_str(&format!(
            "{}:{}={}:{}\n",
            key.len(),
            key,
            value.len(),
            value
        ));
    }
    out
}

/// Stable 16-hex-digit identifier derived from the attributes.
pub fn item_key(attributes: &Attributes) -> String {
    let digest = Sha256::digest(canonical(attributes).as_bytes());
    digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// 1Password item title for an attribute set.
pub fn item_title(attributes: &Attributes) -> String {
    format!("{TITLE_PREFIX}{}", item_key(attributes))
}

/// Prefix of the item tag that carries the attributes.
pub const ATTRS_TAG_PREFIX: &str = "attrs:";

/// The tag that stores the attributes of an item as one line of compact JSON.
///
/// `op item list` returns tags, so a search by a subset of the attributes needs a
/// single listing instead of reading every item.
pub fn attrs_tag(attributes: &Attributes) -> String {
    let json = serde_json::to_string(attributes).expect("a string map serializes");
    format!("{ATTRS_TAG_PREFIX}{json}")
}

/// The attributes stored in `tag`, if it is an attribute tag.
pub fn parse_attrs_tag(tag: &str) -> Option<Attributes> {
    serde_json::from_str(tag.strip_prefix(ATTRS_TAG_PREFIX)?).ok()
}

/// True when every pair of `query` is present in `item`.
pub fn matches(query: &Attributes, item: &Attributes) -> bool {
    query
        .iter()
        .all(|(key, value)| item.get(key) == Some(value))
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let first = parts[0];
    let last = parts[parts.len() - 1];
    if !text.starts_with(first) {
        return false;
    }
    let mut rest = &text[first.len()..];
    for middle in &parts[1..parts.len() - 1] {
        match rest.find(middle) {
            Some(index) => rest = &rest[index + middle.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

/// Patterns of the form `key=glob`; an empty list permits everything.
#[derive(Debug, Clone, Default)]
pub struct AllowList {
    patterns: Vec<(String, String)>,
}

impl AllowList {
    pub fn new(patterns: &[String]) -> Result<Self> {
        let mut parsed = Vec::with_capacity(patterns.len());
        for pattern in patterns {
            let (key, glob) = pattern.split_once('=').ok_or_else(|| {
                Error::Config(format!("allow pattern `{pattern}` must look like key=glob"))
            })?;
            if key.is_empty() {
                return Err(Error::Config(format!(
                    "allow pattern `{pattern}` has an empty key"
                )));
            }
            parsed.push((key.to_owned(), glob.to_owned()));
        }
        Ok(Self { patterns: parsed })
    }

    pub fn permits(&self, attributes: &Attributes) -> bool {
        self.patterns.is_empty()
            || self.patterns.iter().any(|(key, glob)| {
                attributes
                    .get(key)
                    .is_some_and(|value| glob_match(glob, value))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(pairs: &[(&str, &str)]) -> Attributes {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn key_is_stable_and_order_independent() {
        let a = attrs(&[("service", "gh:github.com"), ("username", "")]);
        let b = attrs(&[("username", ""), ("service", "gh:github.com")]);
        assert_eq!(item_key(&a), item_key(&b));
        assert_eq!(item_key(&a).len(), 16);
        assert!(item_key(&a).chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(item_title(&a), format!("secret-service/{}", item_key(&a)));
    }

    #[test]
    fn canonical_form_is_unambiguous() {
        let a = attrs(&[("a", "b=1:c")]);
        let b = attrs(&[("a", "b"), ("1:c", "")]);
        assert_ne!(item_key(&a), item_key(&b));
        assert_ne!(item_key(&attrs(&[])), item_key(&attrs(&[("", "")])));
    }

    #[test]
    fn query_matches_subsets_only() {
        let item = attrs(&[("service", "gh"), ("username", "bob")]);
        assert!(matches(&attrs(&[]), &item));
        assert!(matches(&attrs(&[("service", "gh")]), &item));
        assert!(!matches(&attrs(&[("service", "glab")]), &item));
        assert!(!matches(&attrs(&[("other", "x")]), &item));
    }

    #[test]
    fn allow_list_globs() {
        let list = AllowList::new(&["service=gh:*".into(), "service=glab".into()]).unwrap();
        assert!(list.permits(&attrs(&[("service", "gh:github.com")])));
        assert!(list.permits(&attrs(&[("service", "glab")])));
        assert!(!list.permits(&attrs(&[("service", "glab:x")])));
        assert!(!list.permits(&attrs(&[("username", "gh:x")])));
        assert!(AllowList::default().permits(&attrs(&[])));
        assert!(AllowList::new(&["*=x".into()]).unwrap().patterns.len() == 1);
    }

    #[test]
    fn glob_edge_cases() {
        assert!(glob_match("a*c", "abc"));
        assert!(glob_match("*", ""));
        assert!(glob_match("a*b*c", "aXbYc"));
        assert!(!glob_match("ab*bc", "abc"));
        assert!(!glob_match("a*b*c", "acb"));
    }

    #[test]
    fn allow_list_rejects_bad_patterns() {
        assert!(AllowList::new(&["nokey".into()]).is_err());
        assert!(AllowList::new(&["=x".into()]).is_err());
    }

    #[test]
    fn the_attribute_tag_round_trips_exactly() {
        let odd = attrs(&[
            ("Service", "GitHub.COM:Token"),
            ("empty", ""),
            ("quote", "a\"b\\c,d;e/f"),
            ("a=b", "line\nbreak"),
            ("κλειδί", "τιμή\u{1F512}"),
        ]);
        let tag = attrs_tag(&odd);
        assert!(tag.starts_with("attrs:{"), "{tag}");
        assert!(!tag.contains('\n'), "a tag must stay on one line");
        assert_eq!(parse_attrs_tag(&tag), Some(odd));
        assert_eq!(parse_attrs_tag(&attrs_tag(&attrs(&[]))), Some(attrs(&[])));
    }

    #[test]
    fn the_attribute_tag_is_independent_of_insertion_order() {
        let a = attrs(&[("b", "2"), ("a", "1")]);
        let b = attrs(&[("a", "1"), ("b", "2")]);
        assert_eq!(attrs_tag(&a), attrs_tag(&b));
    }

    #[test]
    fn other_tags_are_not_attribute_tags() {
        assert_eq!(parse_attrs_tag("secret-service"), None);
        assert_eq!(parse_attrs_tag("attrs:not json"), None);
        assert_eq!(parse_attrs_tag("attrs:[1,2]"), None);
        assert_eq!(parse_attrs_tag("xattrs:{}"), None);
    }
}
