# Development Guide

This guide covers local prerequisites, worktree setup, shared build caches, the repository layout, configuration, and the checks expected from the workspace. AuthKit is still in planning and early scaffolding, so some commands describe the intended toolchain rather than a complete product. See the [project README](../README.md) for status and scope.

For the contribution and review flow, read [CONTRIBUTING.md](../CONTRIBUTING.md) and [Workflow](workflow.md).

## Prerequisites

The intended baseline for development is:

- **Git** with worktree support.
- **Rust 1.98.0** installed with [rustup](https://rustup.rs/) as pinned by `rust-toolchain.toml`, including the `rustfmt` and `clippy` components.
- **Node.js** (a current LTS release) and npm for Tailwind and other frontend tooling. The committed lockfile is authoritative once it exists.
- **SQLx CLI** with SQLite and PostgreSQL support, installed with Cargo.
- **SQLite** for the default local database.
- **PostgreSQL** for storage work and for testing behavior that differs from SQLite. A local service or container is fine.
- **A C compiler and common build tools** for Rust dependencies that contain native code.
- **Cloudflare Workers tooling** only when working on the worker adapter: `wrangler` and, when needed, `worker-build`.

Install the Rust components with:

```sh
rustup component add rustfmt clippy
cargo install sqlx-cli --no-default-features --features rustls,sqlite,postgres
```

If a command or feature set differs on your platform, document the working command in this guide rather than relying on local knowledge.

## Worktrees and shared caches

Use one Git worktree per branch. This allows parallel tasks to keep independent working trees while sharing the repository object database. Do not create a worktree inside another worktree.

From the primary checkout:

```sh
git fetch origin
git worktree add ../authkit-worktrees/feat-my-change -b feat/my-change origin/develop
cd ../authkit-worktrees/feat-my-change
./scripts/setup-worktree.sh
```

The script:

1. resolves the current worktree root with Git;
2. resolves the common Git directory, which is shared by all worktrees;
3. derives the shared cache directory as `<parent-of-primary-checkout>/.cache/<repository-name>`;
4. creates `target` and `node_modules` directories in that shared cache;
5. symlinks them into the current worktree as `target` and `node_modules`.

The cache location is intentionally outside every worktree so removing a worktree does not delete shared dependencies. You can override the location for a specific setup:

```sh
AUTHKIT_CACHE_ROOT=/path/to/cache ./scripts/setup-worktree.sh
```

The script is safe to rerun. It refuses to overwrite an existing real directory or a symlink that points somewhere else, so review the message and move the conflicting path manually if replacing it is intended. It never deletes data. If you already have a local `target` or `node_modules` directory, move it aside after confirming it contains nothing you need, then rerun the script.

`target` and `node_modules` are ignored by Git and must never be committed. The root `.gitignore` intentionally matches those names without a trailing slash so Git also ignores the symlinks themselves.

Operational notes:

- Cargo serializes access to a shared target directory. Parallel builds are safe but may wait on each other.
- `cargo clean` affects every worktree using the shared target. Avoid it unless you intend to invalidate the shared build cache.
- Dependency installs mutate the shared `node_modules`. Do not run `npm ci` or conflicting installs concurrently across worktrees, and coordinate if lockfiles differ.
- Shared caches improve speed, not isolation. If you need a fully isolated build, use a separate cache location via `AUTHKIT_CACHE_ROOT` or skip the setup script and manage dependencies locally, accepting the rebuild cost.

Useful worktree commands:

```sh
git worktree list
git worktree remove ../authkit-worktrees/feat-my-change
git worktree prune
```

Remove a worktree only after its branch is merged and it has no uncommitted or untracked work. A removed worktree leaves the branch in the repository; delete the branch separately when appropriate.

## Branch examples

All normal work branches from `develop` and targets `develop` in its pull request.

```sh
git switch develop
git pull --ff-only
git switch -c feat/session-rotation
```

```sh
git switch develop
git pull --ff-only
git switch -c fix/expired-refresh-cookie
```

Keep the slug short and descriptive. Use `feat/<slug>` for features, documentation improvements, tests, and tooling, and `fix/<slug>` for defects and corrective changes. Do not use `main` as the base for normal work.

If `develop` advances while you work, rebase your branch:

```sh
git fetch origin
git rebase origin/develop
```

Only force-push your own branch, and use `--force-with-lease`. Never force-push `develop` or `main`. An emergency hotfix may branch from `main` under the process in [Workflow](workflow.md#hotfix-path).

## Build and test expectations

The workspace is scaffolded with four crates and a pinned toolchain. The native server
provides an Axum HTTP skeleton with typed configuration, health and readiness endpoints,
request IDs, structured tracing, and RFC 6749 error mapping. The SQLx persistence adapters
and migrations are implemented. The local and CI checks are:

```sh
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps --all-features
python3 scripts/check-docs.py
```

Notes:

- Run formatting and lint checks before opening a pull request. Fix warnings rather than suppressing them unless the suppression is narrow and explained.
- Run `cargo run -p authkit-server -- --help` to verify the binary boundary after changing
  manifests or CLI arguments. Start the server with
  `cargo run -p authkit-server -- serve`. Discovery currently publishes only implemented
  capabilities (`issuer`, `jwks_uri`, and ES256 signing); endpoint metadata is added as
  those endpoints land.
- Documentation changes also run through `python3 scripts/check-docs.py`.
- Unit tests should live beside the code they exercise. Cross-crate integration tests belong in the workspace test area.
- Storage tests should cover both SQLite and PostgreSQL where behavior can differ. Set
  `TEST_POSTGRES_URL` to a disposable PostgreSQL database to run the Postgres contract;
  without it, the Postgres contract skips. Never point tests at a database containing data
  you care about. CI starts a disposable Postgres service and sets this variable.
- `SqlStore` owns a Tokio runtime. Create and drop it on a blocking thread, and call its
  repository methods from a blocking thread (for example `spawn_blocking`) when the caller
  is inside an async task.
- The SQLx adapter uses runtime `Any` queries so one implementation serves SQLite and
  Postgres. A single `.sqlx` offline cache cannot represent both dialects, so offline
  metadata is intentionally not used. Migration application and the shared repository
  contract suite are the guard against schema drift.
- Add a new migration instead of editing one that may already have been applied. Test migrations against both supported databases and document any irreversible step.
- Security-sensitive behavior needs negative tests: expired sessions, revoked tokens, invalid callbacks, cross-account access, CSRF rejection, and redaction of secrets in errors and logs.

Once frontend tooling is scaffolded, the expected checks will include installing from the committed lockfile, linting, and building production assets. Add the exact commands here when the package scripts exist. UI changes should be checked with JavaScript disabled for core flows and with keyboard-only navigation.

For the worker adapter, CI should eventually check the worker build separately from the native server build. Do not assume a native test result proves the worker target compiles or behaves correctly.

## Repository layout

The workspace uses a modular monolith layout:

```text
.
├── Cargo.toml                 # Workspace manifest
├── crates/
│   ├── authkit-core/          # Domain model, policy, application services, ports
│   ├── authkit-store/         # SQLx repositories and database-specific code
│   ├── authkit-server/        # Axum application and self-hosted configuration
│   └── authkit-worker/        # Cloudflare Workers entry point (workers-rs)
├── migrations/                # SQLx migrations shared by supported databases
├── templates/                 # Askama pages and HTMX partials
├── assets/                    # Tailwind source, static assets, UI primitives
├── docs/
│   ├── development.md
│   ├── workflow.md
│   └── adr/                   # Accepted architecture decision records
├── scripts/
│   └── setup-worktree.sh
├── tests/                     # Cross-crate integration tests
├── .github/
└── README.md
```

This layout is the current workspace structure. Changes to it should be recorded through the RFC/ADR process in [GOVERNANCE.md](../GOVERNANCE.md#rfc-and-adr-process).

Keep dependency direction one-way: adapters may depend on the core, but the core must not depend on Axum, Askama, workers-rs, or SQLx. Storage and runtime concerns stay at the edges so both deployment targets can share domain behavior.

## Environment and configuration

Configuration is loaded and validated by `authkit-server` before the listener binds. The
committed `.env.example` contains safe local defaults; copy it to `.env` for local work. Real
environment files are untracked.

| Variable | Purpose |
| --- | --- |
| `AUTHKIT_ENV` | `development`, `test`, or `production`. Defaults to `production`. |
| `AUTHKIT_BIND_ADDR` | Listen address. Defaults to `127.0.0.1:3000`. |
| `AUTHKIT_ISSUER` | Required canonical public origin. Must be an absolute origin with no path, query, fragment, or user information. HTTPS is required outside `development` and `test`. |
| `AUTHKIT_DATABASE_URL` | Required SQLx URL using `sqlite:`, `postgres://`, or `postgresql://`. `DATABASE_URL` is accepted as a fallback. |
| `AUTHKIT_DATABASE_MAX_CONNECTIONS` | Connection pool limit. Defaults to `5`; must be positive. In-memory SQLite always uses one connection. |
| `AUTHKIT_SIGNING_KEY_FILE` | Encrypted ES256 keyring file. Defaults to `authkit-signing-keys.json` in development; production requires an absolute path. Created with one active key on first start. Must not be group- or world-readable. |
| `AUTHKIT_SIGNING_KEY_KEK` | Required 32-byte base64url key-encryption key for private key material. Inject it from a secret manager outside local development. |
| `AUTHKIT_SIGNING_KEY_RETIRED_PUBLISH_SECS` | How long retired public keys remain in JWKS. Defaults to `900`; must be between `1` and `86400`. |
| `AUTHKIT_LOG_FORMAT` | `json` or `pretty`. Defaults to `json` in production and `pretty` otherwise. |
| `RUST_LOG` | Tracing filter. Defaults to `info`; never include credentials in log output. |

Rules:

- Copy `.env.example` to `.env` and generate a local `AUTHKIT_SIGNING_KEY_KEK`; the keyring is created on the first `serve`. Never commit `.env`, `.env.*` local variants, or the keyring file.
- Do not use production secrets for local development.
- Do not put secrets in `AUTHKIT_*` example files, test fixtures, logs, or screenshots.
- Treat issuer validation, cookie security, callback validation, and signing-key
  configuration as security-sensitive. Unsafe defaults must not silently apply in
  production.
- The server fails closed on missing or invalid configuration. It decrypts the signing
  keyring before binding, connects to the database, and `/readyz` pings the database, but
  migrations remain a separate one-shot job.
- Back up the encrypted keyring with the key-encryption key; neither is usable alone.
  Configuration `Debug` output redacts the database URL and key-encryption key. Do not log
  raw configuration, key material, or request bodies.
- Document any new variable here and in `.env.example` in the same change.

Cloudflare Workers configuration will use the worker's bindings and secret storage rather than `.env` files. The worker must not require native-only configuration paths that cannot be represented at the edge.

Local databases such as SQLite files are ignored by Git. Use a disposable file or database per experiment and remove it when finished.

## Documentation checks

Documentation changes are reviewed like code. Before opening a pull request:

- verify every relative link and anchor resolves in the repository;
- update the README, this guide, and the workflow guide when a change affects setup, commands, or process;
- keep terminology consistent with the planned architecture;
- check code fences, tables, and command examples for copy-paste errors;
- run `git diff --check` to catch trailing whitespace and conflict markers;
- run `python3 scripts/check-docs.py` to verify local links and heading anchors;
- add external link checks when the project adopts a link checker with a reviewed allowlist.

The documentation set is intentionally cross-linked. If a heading changes, search for links to its old anchor. Do not add dated announcements or milestone schedules to these guides; keep them current and evergreen.

## Troubleshooting shared caches

**The setup script refuses to replace `target` or `node_modules`.** A real directory or a conflicting symlink exists. Inspect it before moving anything. If it is a local build you no longer need, move it outside the worktree, then rerun the script. Do not use `rm -rf` without verifying the path.

**The symlink is dangling.** The shared cache may have been removed. Rerun the script after checking the computed cache location in its output. It will recreate the shared directories and link only if the existing symlink is valid and expected.

**Builds are unexpectedly slow or serialized.** Every worktree may be sharing one target directory. That is expected under contention; Cargo's lock keeps builds correct. For isolated throughput, use a different `AUTHKIT_CACHE_ROOT`.

**Node dependencies changed unexpectedly.** Another worktree may have run an install against the shared `node_modules`. Reinstall from the lockfile in a coordinated way, or use an isolated cache location for work that must not affect others.

**A worktree was deleted manually.** Run `git worktree prune` from the primary checkout to clean up stale metadata. The branch still exists unless it was deleted separately.
