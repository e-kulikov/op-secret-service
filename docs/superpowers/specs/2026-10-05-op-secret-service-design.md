# op-secret-service: design

Date: 2026-10-05. Status: draft for review.

## Goal

`op-secretd` is a daemon that implements the freedesktop Secret Service API
(`org.freedesktop.secrets`) on top of 1Password. Clients that store secrets in
the system keyring over D-Bus (`gh`, `glab`, `az devops`, Git Credential
Manager, `secret-tool`, python-keyring) get 1Password instead of gnome-keyring
or `pass`. There is no separate keyring master password, secrets are never
stored in plaintext, and the 1Password app shows the access approval prompt.

Motivating problem: `gh` keeps its token in a plaintext `hosts.yml` (WSL has no
Secret Service provider, so `gh` falls back to a file), and `glab`'s OAuth token
expires and forces repeated re-authentication. Git then uses the stock
`gh auth git-credential` and `glab auth git-credential` helpers with no custom
wrappers.

## Non-goals (phase 1)

- macOS and Windows. Their clients use Keychain and Credential Manager rather
  than D-Bus, so the daemon does not apply. Phase 2 is considered separately.
- Per-process client filtering, a graphical prompt, cross-machine sync
  (1Password itself provides sync).
- Multiple collections and multiple vaults. One collection `login` (alias
  `default`) maps to one vault.

## Decisions

| Question | Decision |
| --- | --- |
| Language | Rust, `zbus` + `tokio`, static musl binary |
| Platforms | Linux: WSL2 and native |
| 1Password access | external `op` process (native, `op.exe` through WSL interop, service account) |
| What is accepted | everything, into a dedicated vault, with an optional allowlist |
| Default mode | `auto`: `op.exe` on WSL, otherwise native `op`; authentication through the app |
| Distribution | GitHub Releases with static binaries; any installer that consumes release assets works (for example the `github:` backend of mise) |
| Release | release-please (see below) |

## Architecture

```
client (gh/glab/az) -D-Bus-> dbus -> Store -> OpRunner -> op / op.exe
                               |          |
                        sessions+crypto   cache (memory, TTL, zeroize)
```

Modules of a single crate:

- `dbus`: the `Service`, `Collection`, `Item`, and `Session` interfaces.
- `crypto`: session encryption.
- `attrs`: attribute maps, deterministic item identity, and the allow list.
- `store`: the `Store` type, which keeps secrets as 1Password items.
- `op`: the `OpRunner` type and three ways to launch `op`.
- `cache`: an in-memory value with a time-to-live.
- `config`: TOML loading and validation, environment overrides.
- `lifecycle`: claiming the bus name, exiting when idle.
- `doctor` and the `op-secretd` binary: the `serve`, `doctor`, and `config init`
  commands.

Boundaries: `dbus` knows only `Store`; `store` knows only `OpRunner`; `OpRunner`
knows nothing about Secret Service. Each layer is testable on its own; tests
replace the `op` executable with a fake script instead of mocking a trait.

## D-Bus API

Objects: `/org/freedesktop/secrets` (Service),
`/org/freedesktop/secrets/collection/login` with the alias `.../aliases/default`,
items at `.../collection/login/<key>`, sessions at `.../session/<n>`.

The implementation covers the minimum needed by the target clients:

- Service: `OpenSession`, `SearchItems`, `Unlock`, `Lock`, `GetSecrets`,
  `ReadAlias`, `SetAlias`; the `Collections` property.
- Collection: `SearchItems`, `CreateItem` (with `replace`), `Delete`; the
  properties `Items`, `Label`, `Locked`, `Created`, `Modified`.
- Item: `GetSecret`, `SetSecret`, `Delete`; the properties `Attributes`,
  `Label`, `Type`, `Locked`, `Created`, `Modified`.
- Session: `Close`.
- No `Prompt` objects exist: the collection is always unlocked and the real
  approval prompt comes from 1Password, so every method that may return a
  prompt returns `/`.
- `GetSecret` replies with a single `(oayays)` structure; clients such as
  go-keyring reject a reply whose structure is flattened into four arguments.
- `Created` and `Modified` are always `0`. `Collection.Items` lists the items
  that currently have an object. Objects are exported by `SearchItems`,
  `CreateItem`, and once in the background right after the daemon claims the bus
  name; a property getter never exports objects because the D-Bus library holds
  its object tree while a getter runs. An item created elsewhere therefore shows
  up in `Items` after the next search.

Session encryption: `plain` and `dh-ietf1024-sha256-aes128-cbc-pkcs7`.
Unsupported algorithms return `org.freedesktop.DBus.Error.NotSupported`.

## Storage model

One secret is one Password item in the configured vault:

- Title: `secret-service/<sha256 of the canonical attribute string, 16 hex>`.
  The canonical string is the sorted attributes, each written as
  `<key length>:<key>=<value length>:<value>`, so it is unambiguous. Writes can
  therefore address an item directly by title.
- Field `password`: the secret value. Non-UTF-8 data is base64-encoded and the
  field `encoding` records `base64` (otherwise `utf-8`).
- Field `attributes`: the attributes as one JSON object. A single field
  round-trips empty values and any characters exactly.
- Fields `label` (the readable label) and `content_type`.
- Tag `secret-service` (configurable).

Reads load an index of the whole tagged set with two `op` calls
(`op item list --tags ... --format json`, then `op item get - --format json`
fed with that list) and keep it in memory for `cache_ttl`. Searches, secret
reads, and replace checks use the index; any write invalidates it. Items whose
title does not match their attributes, or whose attributes fall outside the
allow list, are ignored. Concurrent requests share one load.

Deleting an item moves it to the 1Password archive.

Replacing an item always sends the complete field set. The real
`op item edit <item> -` replaces the custom fields with those of the template
instead of merging them, so a partial template would silently drop the rest.
The fake `op` used in the tests reproduces this behavior.

`CreateItem` with `replace = true` replaces the item with the same attributes;
without `replace`, a collision returns the existing item, as most
implementations do.

## 1Password access

`OpRunner` launches one of three variants and parses the output itself:

1. `native`: `op` from PATH or from `op.binary`; authentication through the app.
2. `windows-interop`: `op.exe` from WSL. Lookup order: `op.binary`, then
   `/mnt/c/Users/*/AppData/Local/Microsoft/WinGet/Links/op.exe`, then
   `/mnt/c/Program Files/1Password CLI/op.exe`. Output is normalized
   (CRLF to LF).
3. `service-account`: native `op` with `OP_SERVICE_ACCOUNT_TOKEN`, read from a
   file (mode `0600` is enforced) or from an environment variable and passed
   only in the child process environment, never in arguments.

An explicit `op.binary` that ends in `.exe` selects `windows-interop`.

`mode = auto`: on WSL (detected through `/proc/version` and `WSL_DISTRO_NAME`)
`windows-interop` first, falling back to native `op` when `op.exe` is missing;
outside WSL, native `op`. An explicit `mode = app | service-account` and
`op.wsl_interop = auto | true | false` disable auto-detection. Secrets never
appear in process arguments: item bodies are passed as JSON on stdin.

## Configuration

File `$XDG_CONFIG_HOME/op-secretd/config.toml`; any key can be overridden with
an `OP_SECRETD_<KEY>` environment variable.

```toml
vault = "Secret Service"      # required; the vault must exist
account = ""                  # optional, passed as --account
mode = "auto"                 # auto | app | service-account
tag = "secret-service"
cache_ttl = "5m"
idle_timeout = "1h"
allow = []                    # empty: everything; otherwise attribute patterns, e.g. "service=gh:*"
log_level = "info"

[op]
binary = "auto"               # auto | path
wsl_interop = "auto"          # auto | true | false
service_account_token_file = ""   # path, mode 0600
service_account_token_env = ""    # environment variable name
```

`op-secretd config init` writes a commented file. `op-secretd doctor` checks
that `op` is found, the vault is reachable, the token file permissions are
correct, the bus name is free, and the session algorithms are supported. It also
warns when `gh` or `glab` keep a token in a plaintext configuration file (only
the file paths are reported, never values). It prints a clear result per check
(`ok`, `warn`, or `FAIL`) and exits 0 unless a check failed; a warning does not
fail it.

## Lifecycle

- Started on demand through D-Bus activation (`org.freedesktop.secrets.service`
  in the user's services directory) and a systemd user unit.
- If the name `org.freedesktop.secrets` is already taken (gnome-keyring,
  KeePassXC), the daemon does not start and reports who owns it.
- After `idle_timeout` without requests the daemon exits; the cache disappears
  with it. A request that is still in flight, for example while 1Password waits
  for an approval, keeps the daemon alive; the timeout starts when the last
  request finishes. A single `op` call is abandoned after 120 seconds.

## Errors and security

- When `op` is unavailable, the user declines, or authorization has expired, the
  client receives a D-Bus error. An empty "secret not found" answer is allowed
  only when the item truly does not exist. This keeps a client from silently
  falling back to a plaintext file. An integration test pins this behavior at
  the protocol level.
- The real `gh` and `glab` nevertheless fall back silently: when writing to the
  keyring fails (the daemon is down, 1Password is unreachable, an approval was
  declined), `gh auth login` stores the token in `hosts.yml` and exits 0 with no
  warning. `gh` has `--insecure-storage` but no switch that forbids the fallback,
  so the daemon cannot prevent it. The mitigation is procedural: log in only while
  `doctor` is green, and `doctor` warns about plaintext tokens afterwards.
- Secrets are held in `zeroize` buffers, never written to disk, and never logged;
  logs contain only identifiers and attribute hashes, not values.
- Any process in the session that can talk to the bus can read the secrets, as
  with any keyring. Phase 1 has no per-process filtering; `allow` and a
  dedicated vault limit the exposure.
- A service account token file is rejected when its permissions are wider than
  `0600`.

## Testing

- Unit: attribute canonicalization, crypto (known vectors), cache and TTL,
  config parsing, WSL detection, `op.exe` lookup, and the detection of plaintext
  `gh` and `glab` tokens on mock configuration files (values are never printed).
- Integration: a private `dbus-daemon`, a fake `op` (a Python script emulating
  `vault get` and `item list|get|create|edit|delete` on a file store, with
  switches that make it fail or stall, and with the field-replacing edit
  semantics of the real `op`, which its own tests pin), the real daemon binary,
  and clients: a Rust client that speaks the protocol directly (plain and DH
  sessions, error paths, concurrency, empty, large, and binary secrets), the Go
  `go-keyring` library that the GitHub and GitLab CLIs use, Python's `keyring`
  (SecretStorage), and `secret-tool`. Tests never touch the real 1Password or
  user directories: every XDG variable points into a temporary directory.
- Manual checklist (not in CI): the real `op.exe` on WSL, a service account,
  native `op` on a clean Linux machine, creating, replacing, and deleting items
  in a real vault (the item template with custom fields), and the real `gh` and
  `glab` login and logout.

## Release

Releases are automated with the stock `googleapis/release-please-action`
(`release-type: rust`).

1. Development happens on branches with Conventional Commits, merged to `main`.
2. release-please maintains the release PR: `Cargo.toml`, `Cargo.lock`,
   `CHANGELOG.md`, `.release-please-manifest.json`. Before 1.0, `feat` bumps
   the minor version. The initial version is `0.1.0`.
3. The author merges the release PR by hand. Auto-merge after checks can be
   added later as a separate workflow that merges only the exact release PR head
   after a successful `validate` check.
4. Publication happens in the same workflow, with no separate tag-triggered
   workflow (a tag created by `GITHUB_TOKEN` does not trigger other workflows).
   The release is created as a draft whose tag is created immediately
   (`draft` and `force-tag-creation`). The verification suite runs against the
   release, then static musl binaries (x86_64, aarch64) are built, checked (no
   `INTERP` or `NEEDED`, `--version` matches the release version), and packaged
   into deterministic archives; `SHA256SUMS` and build attestations are added.
5. Once all assets are uploaded and verified against `SHA256SUMS`, the draft is
   published and the `stable` branch is fast-forwarded. Tags are never moved.
   Re-running the workflow is safe; if publication failed after the draft was
   created, the workflow can be started manually with the draft's tag to build
   and publish it again.
6. Token: a fine-grained PAT in the `RELEASE_PLEASE_TOKEN` secret (Contents,
   Pull requests, Issues: read/write on this repository only), so that release
   PRs trigger CI. The token is never printed or committed.

The build and packaging steps live in repository scripts
(`scripts/validate-release-version.sh`, `scripts/package-release.sh`) so that
they can be run and tested locally. A pull request check
(`scripts/check-conventional-commits.sh`) rejects commit subjects that are not
Conventional Commits.

## Packaging and installation

Each release archive (`op-secretd_<version>_linux_<arch>.tar.gz`) contains:

- the static `op-secretd` binary;
- `share/op-secretd/op-secretd.service` (systemd user unit) and
  `share/op-secretd/org.freedesktop.secrets.service` (D-Bus activation file);
- `share/op-secretd/config.example.toml`, produced by `op-secretd config init`;
- `README.md` and `LICENSE`.

The archive is installed by unpacking it: the binary goes on `PATH`, the unit
and the activation file go into the user's systemd and D-Bus service
directories, and `op-secretd config init` followed by `op-secretd doctor`
completes the setup. Installers that fetch GitHub Release assets, such as the
`github:` backend of mise, work without extra metadata because asset names follow
the pattern above and `SHA256SUMS` is published next to them.

Client setup after installation: `gh auth login` and
`glab auth login --use-keyring` write their tokens to the keyring, which now means
1Password. For `glab`, a personal access token is used instead of OAuth because
OAuth access tokens expire quickly.

## Verified manually against real services

Checked on 2026-10-05 against a real 1Password account (WSL, Windows `op.exe`)
with a throwaway vault, which was deleted afterwards:

- `doctor`, the Python `keyring` (DH session) and Go `go-keyring` clients, secrets
  of 64 KiB and non-UTF-8 secrets, deletion into the archive, and cache refresh
  after an edit made outside the daemon all work.
- A failing vault and a declined approval prompt reach the client as a D-Bus
  error with a clear message; nothing is written in plaintext by the daemon.
- A systemd user unit with `Type=dbus`, D-Bus activation, idle exit, and the
  refusal to start next to another provider work. The packaged unit uses a
  private `/tmp`, so the configuration must not live there. After a failed start
  the next activation can wait for the bus's 120 s timeout until the unit is
  started once by hand.
- `gh` (web login): the token is stored in the vault, `hosts.yml` holds none,
  `gh api user` and a `git clone` of a private repository through
  `gh auth git-credential` work, and `gh auth logout` removes the item.
- `glab` (device login): both the access token and the OAuth refresh token are
  stored in the vault, the configuration file holds neither, and `glab api user`
  works. Whether a refreshed token round-trips after its two-hour expiry was not
  waited for.
- `gh` falls back to plaintext when the keyring write fails (see "Errors and
  security").
- A real vault accepts the item template the daemon sends: custom fields without
  ids on create, the complete field set on edit.

## Open verification points

These points are not settled and are resolved by tests or documentation:

1. Whether `az devops` and Git Credential Manager work with the API subset above
   (the Go `go-keyring` library and Python's SecretStorage are covered by tests).
2. Whether the two-call index load (`op item list ... | op item get -`) is fast
   enough with several hundred items, and how the 1Password app handles a burst
   of quick requests through `op.exe`.
3. The limits of a real vault for field values larger than 64 KiB.
4. How release-please behaves on its first run with `draft` and
   `force-tag-creation` (tag creation, the release pull request, and the next
   run seeing the draft).
5. Service account mode and the native Linux `op` signed in with an account.

## Phase 2

macOS and Windows: clients there need a different mechanism (Keychain and
Credential Manager are already secure without a master password), so whether it
is needed is decided separately.
