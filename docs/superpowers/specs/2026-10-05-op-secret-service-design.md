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
client (gh/glab/az) -D-Bus-> dbus -> SecretStore -> OpRunner -> op / op.exe
                               |          |
                        sessions+crypto   cache (memory, TTL, zeroize)
```

Modules of a single crate:

- `dbus`: the `Service`, `Collection`, `Item`, `Session`, and `Prompt` interfaces.
- `crypto`: session encryption.
- `store`: the `SecretStore` trait and the `OpStore` implementation.
- `op`: the `OpRunner` trait and three ways to launch `op`.
- `cache`: in-memory cache of secrets and the item index.
- `config`: TOML loading and validation, environment overrides.
- `lifecycle`: claiming the bus name, exiting when idle.
- `cli`: the `serve`, `doctor`, and `config init` commands.

Boundaries: `dbus` knows only `SecretStore`; `store` knows only `OpRunner`;
`OpRunner` knows nothing about Secret Service. Each layer is testable on its own.

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
- Session: `Close`. Prompt: a stub that always completes without asking, since
  the collection is always unlocked and the real prompt comes from 1Password.

Session encryption: `plain` and `dh-ietf1024-sha256-aes128-cbc-pkcs7`.
Unsupported algorithms return `org.freedesktop.DBus.Error.NotSupported`.

## Storage model

One secret is one Password item in the configured vault:

- Title: `secret-service/<sha256 of the canonical attribute string, 16 hex>`.
  The canonical string is the sorted `key=value` pairs. An exact lookup (which
  is how go-keyring searches, by `service` and `username`) is therefore a
  single `op item get` by title.
- Field `password`: the secret value. Non-UTF-8 data is base64-encoded and
  marked in the `content_type` field.
- Custom fields `attr.<name>`: the attributes; field `label`: the readable label.
- Tag `secret-service` (configurable).

A fuzzy search (a partial set of attributes) runs one
`op item list --tags ... --format json | op item get - --format json` call; the
resulting index is cached and invalidated on writes.

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
idle_timeout = "15m"
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
correct, the bus name is free, and the session algorithms are supported. It
prints a clear result and exits 0 only when everything is fine.

## Lifecycle

- Started on demand through D-Bus activation (`org.freedesktop.secrets.service`
  in the user's services directory) and a systemd user unit.
- If the name `org.freedesktop.secrets` is already taken (gnome-keyring,
  KeePassXC), the daemon does not start and reports who owns it.
- After `idle_timeout` without requests the daemon exits; the cache disappears
  with it.

## Errors and security

- When `op` is unavailable, the user declines, or authorization has expired, the
  client receives a D-Bus error. An empty "secret not found" answer is allowed
  only when the item truly does not exist. This keeps a client from silently
  falling back to a plaintext file. How `gh` reacts is covered by an
  integration test (see "Verify during implementation").
- Secrets are held in `zeroize` buffers, never written to disk, and never logged;
  logs contain only identifiers and attribute hashes, not values.
- Any process in the session that can talk to the bus can read the secrets, as
  with any keyring. Phase 1 has no per-process filtering; `allow` and a
  dedicated vault limit the exposure.
- A service account token file is rejected when its permissions are wider than
  `0600`.

## Testing

- Unit: attribute canonicalization, crypto (known vectors), cache and TTL,
  config parsing, WSL detection, `op.exe` lookup.
- Integration: a private `dbus-daemon`, a fake `op` (a script emulating
  `item get|create|edit|delete|list` and `read` on a file store), and the
  clients `secret-tool`, python-keyring, and the real `gh`. Tests never touch
  the real 1Password or user directories: every XDG variable points into a
  temporary directory.
- Manual checklist (not in CI): the real `op.exe` on WSL, a service account,
  and native `op` on a clean Linux machine.

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
   The release is created as a draft, then static musl binaries (x86_64,
   aarch64), deterministic archives, `SHA256SUMS`, and attestations are built;
   the package is verified (no `INTERP` or `NEEDED`, `--version` matches the
   release version).
5. Once all assets are uploaded and verified, the draft is published and the
   `stable` branch is fast-forwarded. Tags are never moved. Re-running the
   workflow is safe and reuses matching releases.
6. Token: a fine-grained PAT in the `RELEASE_PLEASE_TOKEN` secret (Contents,
   Pull requests, Issues: read/write on this repository only), so that release
   PRs trigger CI. The token is never printed or committed.

The build and packaging steps live in repository scripts
(`scripts/validate-release-version.sh`, `scripts/package-release.sh`) so that
they can be run and tested locally.

## Packaging and installation

Each release archive (`op-secretd_<version>_linux_<arch>.tar.gz`) contains:

- the static `op-secretd` binary;
- a systemd user unit and a D-Bus activation file (`org.freedesktop.secrets.service`);
- a commented example `config.toml`;
- the license.

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

## Verify during implementation

These points are not settled up front and are resolved by tests or documentation:

1. How `gh` reacts to a Secret Service error (silent fallback to a file or an
   explicit failure). A fallback needs a workaround.
2. Which session scheme and attributes `gh`, `glab`, `az devops`, and Git
   Credential Manager use, and whether the API subset above is sufficient.
3. Whether `glab` stores an OAuth refresh token in the keyring; in any case we
   move to a PAT.
4. Whether `op item list ... | op item get -` is fast enough for fuzzy search
   with several hundred items.
5. How the 1Password app handles approval prompts for a burst of quick requests
   through `op.exe` (request debouncing).

## Phase 2

macOS and Windows: clients there need a different mechanism (Keychain and
Credential Manager are already secure without a master password), so whether it
is needed is decided separately.
