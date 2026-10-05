# Repository instructions

`op-secretd` is a Rust daemon that implements the freedesktop Secret Service
D-Bus API on top of 1Password. The design lives in
`docs/superpowers/specs/2026-10-05-op-secret-service-design.md`; read it before
changing behavior, and update it in the same change when behavior or interfaces
move.

## Documentation

- Everything under `docs/` is written in English. The English file is the only
  source of truth and the only file that is committed.
- Every file under `docs/` has a Russian companion next to it, named
  `<name>.ru.md`. It is a complete translation of the current English file,
  regenerated in full after every English change. Never edit it by hand and never
  patch it partially.
- `*.ru.md` files are not tracked: they are listed in `.gitignore` and must never
  be committed, staged, or pushed. No Cyrillic may appear in any committed file
  or in git history; check with
  `git grep -lP '[\x{0400}-\x{04FF}]' $(git rev-list --all)` before reporting a
  documentation change as done.
- Documentation is self-contained. Do not mention other repositories, the
  author's workstation, dotfiles, or any other environment-specific setup.
  Describe only this project and its external dependencies.
- Specs go to `docs/superpowers/specs/YYYY-MM-DD-<topic>-design.md`.

## Commits and branches

- Use Conventional Commits for every commit message, in English:
  `type(scope): summary` with types such as `feat`, `fix`, `docs`, `refactor`,
  `test`, `build`, `ci`, `chore`, and `perf`. Mark breaking changes with `!` and
  a `BREAKING CHANGE:` footer. release-please derives versions and the changelog
  from these messages.
- Work on branches and merge to `main`; merge commits keep the original
  messages, so each commit message must be correct on its own. If a PR is
  squashed, the resulting message must preserve the intended type and breaking
  change footer.
- Do not edit `CHANGELOG.md`, `.release-please-manifest.json`, or the version in
  `Cargo.toml` by hand; release-please owns them.
- Do not push, tag, create releases, or change repository settings unless the
  user asks for it explicitly.

## Development rules

- Pin the Rust toolchain in `rust-toolchain.toml`. Build and test with
  `--locked`. Before reporting work as done run `cargo fmt --check`,
  `cargo clippy --all-targets --locked -- -D warnings`, and `cargo test --locked`
  once the crate exists, and state any check that could not be run.
- Keep the module boundaries from the spec: `dbus` knows only `SecretStore`,
  `store` knows only `OpRunner`, and `OpRunner` knows nothing about Secret
  Service.
- Secrets must never appear in process arguments, logs, error messages, test
  output, or the repository. Pass secret bodies to `op` as JSON on stdin and hold
  them in `zeroize` buffers.
- Tests must not touch the real 1Password account or any real user directory.
  Use a temporary directory for every XDG variable, a private `dbus-daemon`, and
  a fake `op`. Anything that needs the real `op` or `op.exe` is a manual check
  and stays out of CI.
- The daemon must fail loudly: when `op` is unavailable or access is denied,
  return a D-Bus error instead of an empty result, so clients cannot silently
  fall back to plaintext storage.
- Release binaries are static musl builds. Releases are published only after all
  assets are uploaded and verified, as described in the spec.
- Commit messages and pull request descriptions end with the attribution lines
  required by the tool that creates them.
