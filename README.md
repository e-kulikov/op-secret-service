# op-secretd

`op-secretd` is a daemon that implements the freedesktop Secret Service API
(`org.freedesktop.secrets`) on top of 1Password. Programs that keep secrets in
the system keyring over D-Bus (the GitHub and GitLab CLIs, `az devops`, Git
Credential Manager, `secret-tool`, Python's `keyring`, and others) store them in
a 1Password vault instead of gnome-keyring or `pass`. There is no separate
keyring password, nothing is stored in plaintext, and the 1Password app shows the
approval prompt.

Platforms: Linux, including WSL2. macOS and Windows clients use their native
keychains and do not need this daemon.

## How it works

The daemon runs on the session bus and talks to 1Password through the `op`
command line tool:

- **WSL:** the Windows `op.exe` is used through WSL interop, so the approval
  prompt appears on the Windows host.
- **Linux:** the native `op` is used, signed in through the 1Password app.
- **Service account:** a service account token can be used instead of the app.

Every secret is one Password item in a dedicated vault, titled
`secret-service/<hash of its attributes>` and tagged `secret-service` plus a tag that
records its attributes, so a search needs one listing instead of reading every item. Items are
cached in memory for `cache_ttl`; nothing is written to disk. The daemon starts
on demand and exits after `idle_timeout` without requests.

## Requirements

- A 1Password account and a vault for the secrets (the daemon never creates one).
- The 1Password CLI: on WSL the Windows `op.exe` (enable *Settings, Developer,
  Integrate with 1Password CLI* in the Windows app), elsewhere the native `op`.
- A D-Bus session bus. No other Secret Service provider may run at the same time
  (gnome-keyring and KeePassXC own the same bus name).

## Install

Download `op-secretd_<version>_linux_<arch>.tar.gz` and `SHA256SUMS` from the
[releases](https://github.com/e-kulikov/op-secret-service/releases), verify the
checksum, and unpack the archive:

```sh
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf op-secretd_<version>_linux_<arch>.tar.gz
cd op-secretd_<version>_linux_<arch>

install -Dm755 op-secretd ~/.local/bin/op-secretd
install -Dm644 share/op-secretd/op-secretd.service ~/.config/systemd/user/op-secretd.service
install -Dm644 share/op-secretd/org.freedesktop.secrets.service \
  ~/.local/share/dbus-1/services/org.freedesktop.secrets.service
systemctl --user daemon-reload

op-secretd config init        # writes ~/.config/op-secretd/config.toml
$EDITOR ~/.config/op-secretd/config.toml    # set `vault`
op-secretd doctor
```

The systemd unit and the D-Bus activation file start the daemon the first time a
client asks for the keyring.

## Configuration

`$XDG_CONFIG_HOME/op-secretd/config.toml`; every key can also be set with an
`OP_SECRETD_<KEY>` environment variable (`OP_SECRETD_OP_BINARY` for `[op] binary`).
`op-secretd config init` writes a commented file.

| Key | Default | Meaning |
| --- | --- | --- |
| `vault` | none | Vault that holds the secrets. Required. |
| `account` | empty | Passed to `op --account`. |
| `mode` | `auto` | `auto`, `app` or `service-account`. |
| `tag` | `secret-service` | Tag put on every item. |
| `cache_ttl` | `5m` | In-memory cache lifetime; `0` disables it. |
| `idle_timeout` | `1h` | Exit after this long without requests; `0` disables it. |
| `allow` | empty | Attribute patterns (`key=glob`); empty accepts everything. |
| `log_level` | `info` | `error`, `warn`, `info`, `debug` or `trace`. |
| `[op] binary` | `auto` | Path of `op` or `op.exe`. |
| `[op] wsl_interop` | `auto` | `auto`, `true` or `false`. |
| `[op] service_account_token_file` | empty | Token file; its mode must be `0600`. |
| `[op] service_account_token_env` | empty | Environment variable holding the token. |

With `mode = auto` the daemon uses `op.exe` inside WSL (falling back to the native
`op` when it is missing) and the native `op` elsewhere.

## Using it

Once the daemon is installed, clients need no configuration:

```sh
gh auth login                          # the token goes to 1Password
glab auth login --use-keyring          # prefer a personal access token over OAuth
secret-tool store --label=demo service demo username me
```

`op-secretd doctor` checks the configuration, access to the vault, the session
bus, the supported session algorithms, and whether `gh` or `glab` keep a token in
a plaintext configuration file.

**Log in only while `op-secretd doctor` is green.** When the keyring cannot be
written (the daemon is not running, 1Password is unreachable, or an approval was
declined), `gh` and `glab` silently store the token in their plaintext
configuration file instead. `gh` offers `--insecure-storage` but no switch that
forbids the fallback, so the daemon cannot prevent it. After logging in, make sure
`doctor` reports no plaintext tokens; if it does, run `gh auth logout` and
`gh auth login` again while the daemon is healthy.

## Troubleshooting

- **The first request after the daemon starts takes several seconds:** every call to
  the 1Password CLI goes through the app (and through Windows in WSL) and can take
  seconds. Results are then cached for `cache_ttl`, and the daemon stays up for
  `idle_timeout`, so later requests are instant.
- **A client fails with `authorization prompt dismissed`:** the approval prompt in
  the 1Password app was closed or the app was locked and not unlocked. Retry the
  command and approve the prompt.
- **A client hangs for about two minutes right after the daemon failed to start:**
  D-Bus waits for its activation timeout after a failed start. Fix the cause
  (`op-secretd doctor` names it), then start the unit once with
  `systemctl --user start op-secretd.service`.
- **The daemon reports that the configuration is missing:** the packaged systemd
  unit uses a private `/tmp`, so keep the configuration in
  `$XDG_CONFIG_HOME/op-secretd/` rather than under `/tmp`.
- **`org.freedesktop.secrets is already owned by ...`:** another Secret Service
  provider (gnome-keyring, KeePassXC) is running; stop it first.

## Security notes

- Any process in your session that can reach the session bus can read the
  secrets, as with any keyring. Use a dedicated vault and the `allow` list to
  limit what is accepted.
- Secrets are held in zeroized memory, never logged, and never passed in process
  arguments.
- When 1Password cannot be reached or an approval is declined, clients receive a
  D-Bus error instead of an empty answer, so they cannot silently fall back to
  plaintext storage.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

The integration tests start a private `dbus-daemon` and a fake `op`; they never
touch a real 1Password account. They also exercise real clients: the Go
`go-keyring` library, Python's `keyring` (set `OP_SECRETD_TEST_PYTHON` to an
interpreter that has `keyring` and `secretstorage`), and `secret-tool`. A missing
client skips its test unless `OP_SECRETD_REQUIRE_CLIENTS` is set.

Commits follow [Conventional Commits](https://www.conventionalcommits.org/).
Releases are prepared by release-please: merging its release pull request
publishes static `x86_64` and `aarch64` binaries and advances the `stable` branch.

## License

MIT.
