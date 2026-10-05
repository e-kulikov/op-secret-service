# Manual verification checklist

These checks need a real 1Password account or real clients and therefore stay out
of CI. Run them before the first release and after changes to the `op` runner,
the store, or the release workflow. Use a throwaway vault.

## Setup

1. Install the daemon as described in the README, set `vault` to a throwaway
   vault, and run `op-secretd doctor`. Every line must start with `ok`.
2. Start the daemon in the foreground with `RUST_LOG=debug op-secretd serve`.

## 1Password access

- [ ] **WSL, `op.exe`:** a request makes the 1Password approval prompt appear on
  the Windows host; approving it completes the request.
- [ ] **Declined approval:** dismissing the prompt makes the client fail with an
  error; nothing is written to a plaintext file.
- [ ] **Native Linux `op`:** with `[op] wsl_interop = "false"` on WSL, or on a
  clean Linux machine, the same flow works.
- [ ] **Service account:** with `mode = "service-account"` and a token file of
  mode `0600`, requests succeed without a prompt; a token file with a wider mode
  makes `doctor` fail.

## Items in a real vault

- [ ] Create, replace, and delete a secret with `secret-tool`; the item
  `secret-service/<hash>` appears with the tag `secret-service`, its fields
  `password`, `label`, `content_type`, `encoding`, and `attributes` are as
  described in the spec, and a deleted item lands in the archive.
- [ ] A 64 KiB secret and a secret with non-UTF-8 content round-trip.
- [ ] Editing the item in the 1Password app (changing the secret) is visible to
  the client after `cache_ttl`.

## Real clients

- [ ] `gh auth login` stores its token in the vault; `gh auth status` and
  `gh api user` work afterwards; the plaintext `hosts.yml` has no token.
- [ ] `gh auth logout` removes the item (it moves to the archive).
- [ ] With the daemon unable to reach 1Password (for example the vault renamed),
  `gh` reports an error and does **not** fall back to a plaintext token file.
- [ ] `glab auth login --use-keyring` with a personal access token works and
  survives a day without re-authentication.
- [ ] `git` with `gh auth git-credential` and `glab auth git-credential`
  clones a private repository using the stored token.

## Lifecycle

- [ ] With D-Bus activation installed and the daemon stopped, the first client
  request starts it; after `idle_timeout` it exits.
- [ ] With gnome-keyring or another provider running, `op-secretd serve` fails
  with a message that names the other owner.

## Release (first run)

- [ ] Merging a `feat` commit to `main` makes release-please open a release
  pull request that bumps the version to `0.1.0`.
- [ ] Merging that pull request creates a draft release with the tag `v0.1.0`,
  runs verification, builds both archives, and uploads them with `SHA256SUMS`.
- [ ] The draft is then published, `stable` points at the tagged commit, and the
  next push to `main` does not open a duplicate release pull request.
- [ ] Downloading the archive, verifying the checksum and the attestation
  (`gh attestation verify`), and following the README install steps yields a
  working daemon.
