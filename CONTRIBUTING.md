# Contributing to AuthKit

Thanks for your interest in AuthKit. The project is in documentation and planning, so early contributions should focus on design, RFCs, tests, documentation, and small well-scoped groundwork changes rather than large unreviewed implementations.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Please report security vulnerabilities privately according to [SECURITY.md](SECURITY.md), never in a public issue.

## Before you start

1. Read the [development guide](docs/development.md) and [workflow guide](docs/workflow.md).
2. Search existing issues and RFCs before opening a new one. Explain the problem before proposing an implementation.
3. For a bug, use the bug report template. For a bounded feature, use the feature request template. For cross-cutting, security-sensitive, or hard-to-reverse changes, open an RFC using the template described in [GOVERNANCE.md](GOVERNANCE.md#rfc-and-adr-process).
4. Wait for a maintainer to agree on scope before investing in a large change. A maintainer may ask for an RFC or defer work that is outside the near-term plan.

Security issues, conduct reports, and embargoed release work must not be discussed in public issues or pull requests.

## Local setup

Prerequisites and platform-specific notes are in [docs/development.md](docs/development.md). The intended baseline is a recent Git, a stable Rust toolchain with `rustfmt` and `clippy`, Node.js with npm for frontend assets, and SQLx CLI for migrations. SQLite is required; PostgreSQL is optional for local work unless you are changing storage behavior.

A typical first checkout looks like this:

```sh
git clone https://github.com/devstroop/authkit.git
cd authkit
git switch develop
git fetch origin
```

No production build system exists yet. When workspace scaffolding lands, the documented build and test commands will become the expected local checks. Do not commit generated output, local databases, secrets, or dependency directories.

## Worktrees and shared caches

Use a separate worktree per branch when working on more than one change at a time. This keeps uncommitted work isolated without repeatedly copying the repository. Create worktrees next to the primary checkout, not inside it.

```sh
git fetch origin
git worktree add ../authkit-worktrees/feat-my-change -b feat/my-change origin/develop
cd ../authkit-worktrees/feat-my-change
./scripts/setup-worktree.sh
```

The setup script derives a shared cache location from Git's common directory and links `target` and `node_modules` into the current worktree. This avoids rebuilding the same dependencies in every worktree. The script is idempotent, refuses to overwrite a real `target` or `node_modules` directory, and never deletes existing files.

Important consequences of shared caches:

- `cargo clean` in one worktree can remove build artifacts used by every worktree.
- `npm ci` or dependency installs mutate the shared `node_modules`; coordinate with others when lockfiles differ and do not run conflicting installs at the same time.
- `target` and `node_modules` are ignored by Git. Never commit the symlinks.

Full details, including manual fallback and troubleshooting, are in [docs/development.md](docs/development.md#worktrees-and-shared-caches). Remove a worktree with `git worktree remove ../authkit-worktrees/<name>` after its branch is merged and no uncommitted work remains.

## Branch naming

All normal work starts from an up-to-date `develop`:

```sh
git switch develop
git pull --ff-only
git switch -c feat/<short-slug>
```

Use lowercase kebab-case slugs and keep branches focused:

- `feat/add-session-rotation` for a feature, including documentation or tooling features.
- `fix/expired-cookie-handling` for a defect or a small corrective change.

Do not push directly to `develop` or `main`. Do not use a shared branch for unrelated work. `main` is updated only by maintainers through a promotion or hotfix pull request; see [docs/workflow.md](docs/workflow.md).

If `develop` moves while you work, rebase your own branch:

```sh
git fetch origin
git rebase origin/develop
```

You may force-push your own branch with `--force-with-lease`, but never force-push `develop` or `main`.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) with a meaningful scope. The pull request title must also follow this convention because feature and fix pull requests are squash-merged.

```text
<type>(<scope>)!: <imperative summary>
```

Common types: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, and `chore`. Useful scopes include `core`, `store`, `server`, `worker`, `ui`, `migrations`, `docs`, `ci`, and `security`. Omit the scope when it adds no clarity.

Examples:

```text
feat(server): add password reset request flow
fix(store): scope session lookup by account
docs(workflow): explain release promotion and back-merge
refactor(core)!: replace session identifiers with opaque handles
```

Guidelines:

- Write the summary in the imperative mood and describe the effect, not the mechanics.
- Use the body to explain why the change is needed, notable tradeoffs, and anything a reviewer should know.
- Mark a breaking change with `!` before the colon and add a `BREAKING CHANGE:` footer explaining the migration.
- Keep commits focused. Squash fixups before requesting final review when practical.
- Never include credentials, tokens, personal data, or production configuration in a commit.

## Pull requests

Open pull requests against `develop`, except for a maintainer-led promotion into `main` or an approved hotfix that must target `main`. Fill in the pull request template and link the relevant issue or RFC.

A pull request is ready for review when:

- the title follows Conventional Commits and the scope is clear;
- the branch is based on the current `develop` and unrelated changes have been removed;
- tests cover the new behavior, failure paths, and any regression;
- migrations and compatibility implications are documented for storage changes;
- documentation, configuration examples, and cross-links are updated in the same pull request;
- CI is green, including formatting, linting, tests, and documentation checks;
- security-sensitive changes have the additional review required by [GOVERNANCE.md](GOVERNANCE.md#security-sensitive-changes);
- no generated caches, local database files, secrets, or `target`/`node_modules` symlinks are included.

Keep pull requests small and reviewable. A maintainer may ask you to split a change or move a design discussion into an RFC. Do not merge your own pull request without maintainer approval. Feature, fix, and documentation pull requests are normally squash-merged; release promotion uses a merge commit so the release boundary remains visible.

## Tests and quality checks

The intended checks for a Rust change are:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo sqlx prepare --check --workspace
```

Use `SQLX_OFFLINE=true` when validating against committed query metadata, and provide a disposable database for checks that require a live connection. Storage changes should be exercised against both SQLite and PostgreSQL where the behavior can differ. Do not edit migrations that have already been applied; add a new migration instead.

Frontend and template changes should include an accessible keyboard path and should not depend on JavaScript for core flows. Once frontend tooling is scaffolded, the expected checks will include dependency installation from the lockfile, linting, and a production asset build. Document any new command in [docs/development.md](docs/development.md).

Test behavior, not implementation details. Security-relevant cases such as expired or revoked sessions, CSRF rejection, invalid redirect targets, authorization failures, and sensitive-data redaction deserve explicit tests.

## Documentation

Documentation is part of the change, not an afterthought. Update the relevant guide when behavior, configuration, API shape, deployment, or contributor process changes. Use relative links within the repository and verify that headings and anchors still resolve. Keep documentation evergreen: describe current behavior and decisions rather than dated announcements or schedules.

Architecture decisions belong in ADRs rather than scattered across pull request comments. The RFC and ADR process is defined in [GOVERNANCE.md](GOVERNANCE.md#rfc-and-adr-process).

## Issues and RFCs

Use the GitHub issue templates:

- Bug report for reproducible defects.
- Feature request for a bounded capability or improvement.
- RFC for architecture, public interfaces, data model, security model, dependency or infrastructure changes, governance changes, and other decisions that are expensive to reverse.

An accepted RFC becomes an ADR in `docs/adr/` when that directory is introduced. Implementation pull requests should link the accepted RFC or ADR. Maintainers decide whether an RFC is accepted, deferred, or rejected and record the rationale publicly unless the discussion must remain private for security or conduct reasons.

## Licensing and contributions

The project license is still an open governance item. Before public launch, maintainers will publish the chosen license and any contribution terms in the repository. Do not assume a license for redistribution before that happens.
