# AuthKit

AuthKit is a planned open-source identity and authentication service for teams that want a
small, auditable, self-hostable system for sign-in, sessions, and account lifecycle. It is
designed to run as a conventional Rust server or on Cloudflare Workers without duplicating
the domain model.

It can be used standalone by one project, shared by an organization across many
applications, or embedded in another product. AI Gateway is one planned consumer, not a
dependency of the core.

> **Status: documentation and planning.** There is no production-ready code, release, or
> stable API yet. Do not deploy AuthKit or use it to protect real identities. The
> architecture, interfaces, and configuration described here are proposals and may change
> substantially.
>
> **Working name.** AuthKit is provisional. WorkOS AuthKit is an existing product, so naming
> and trademark review is an open item. Do not publish packages, register domains, or launch
> publicly under this name until that review is complete. See
> [Governance](GOVERNANCE.md#access-continuity-and-open-items).

## Principles

- **Secure by default.** Authentication code is treated as security-critical. Defaults are
  conservative, privileged operations are explicit, and security-sensitive changes receive
  additional review.
- **Boring and auditable.** Prefer a small dependency surface, clear data flows, and
  standard protocols over clever abstractions. If a decision is not obvious, write it down.
- **Portable by design.** SQLite is enough for local development and small single-node
  deployments; PostgreSQL supports larger and multi-instance deployments. Storage-specific
  behavior belongs in adapters, not the domain model.
- **Accessible, progressive UI.** Server-rendered pages work without JavaScript. HTMX is an
  enhancement, not a requirement, and the interface is keyboard usable and screen-reader
  friendly.
- **Open process.** Issues, RFCs, architecture decisions, and review rationale are public by
  default. Security reports and conduct reports are handled privately.
- **No accidental commitments.** The project does not promise a release schedule, support
  window, or production readiness before those policies exist.

## What it does

AuthKit provides:

- OIDC/OAuth 2.0 authorization code flow with PKCE, refresh rotation, userinfo, revocation,
  RP-initiated logout, and client credentials.
- Organizations as tenants, applications as product surfaces, and composable roles and
  permissions.
- Email/password authentication with verification, password reset, session management, and
  audit.
- A server-rendered account and administration UI, including first-run setup.
- SQLite for a single node; PostgreSQL for multi-replica deployments.
- An optional Workers-lite profile after the compatibility spike.

It deliberately does **not** provide SAML, SCIM, LDAP, an auth proxy, outposts, a visual
flow builder, or a React SPA in v1. See the [product definition](docs/product.md) for the
full scope and non-goals.

## Planned architecture

AuthKit is a modular monolith: a framework-independent core, pluggable storage, and thin
HTTP/UI adapters.

```text
Browser or API client
          |
  Axum server / workers-rs
          |
     authkit-core
  (domain, ports, use cases)
          |
     authkit-store
        (SQLx / D1)
          |
  SQLite / PostgreSQL
```

- `authkit-core` owns the domain model, identity and session lifecycle, policy, ports, and
  application use cases. It does not depend on HTTP, a database, templates, or a runtime.
- `authkit-store` implements persistence with SQLx for SQLite and PostgreSQL, plus a
  feature-gated D1 adapter for Workers.
- `authkit-server` provides the self-hosted Axum application, configuration, routes,
  Askama/HTMX UI, adapters, and administrative CLI subcommands.
- `authkit-worker` provides the Cloudflare Workers entry point and Workers-lite feature
  gates.

The layout and dependency rules are documented in
[architecture](docs/architecture.md#4-modular-monolith-and-crate-layout) and recorded in
[ADR-0001](docs/adr/0001-modular-monolith-four-crates.md).

## Stack

| Area | Planned choice |
| --- | --- |
| Language | Rust (stable toolchain) |
| HTTP server | Axum |
| Edge runtime | Cloudflare Workers via workers-rs (preview) |
| Persistence | SQLx with SQLite and PostgreSQL; D1 for Workers |
| Templates | Askama |
| Interactivity | HTMX |
| Styling | Tailwind CSS with shadcn-inspired, accessible primitives |
| Tooling | Cargo, npm for frontend assets, SQLx CLI |

## Documentation

Start here:

- [Product definition](docs/product.md) - problem, personas, use cases, scope, and
  success criteria.
- [Roadmap](docs/roadmap.md) - milestones, exit criteria, and how work is sequenced.
- [Open decisions](docs/open-decisions.md) - unresolved choices and their proposed v1
  defaults.

Architecture and protocol:

- [Architecture](docs/architecture.md) - system context, boundaries, flows, and deployment
  topologies.
- [Domain model](docs/domain-model.md) - entities, invariants, schema constraints, and
  representative DDL.
- [Standards and conformance](docs/standards.md) - OIDC/OAuth profile, endpoint behavior,
  and test requirements.
- [Runtime targets](docs/runtime-targets.md) - native versus Workers support matrix and
  platform constraints.
- [UI stack](docs/ui-stack.md) - Askama, HTMX, design tokens, and accessibility rules.
- [Architecture decision records](docs/adr/) - accepted foundational decisions.

Security and operations:

- [Security model](docs/security-model.md) - required controls and secure defaults.
- [Threat model](docs/threat-model.md) - adversaries, attack paths, and residual risks.
- [Operations](docs/operations.md) - deployment, configuration, backups, rotation, and
  incident response.
- [AI Gateway migration](docs/migration-ai-gateway.md) - one optional pilot cutover; not a
  core dependency.

Contributing:

- [Development guide](docs/development.md) - prerequisites, worktrees, shared caches,
  configuration, and build/test expectations.
- [Workflow guide](docs/workflow.md) - issue-to-release flow, review checklist, merge
  strategy, hotfixes, and parallel work.
- [Contributing](CONTRIBUTING.md) - how to propose changes, name branches, write commits,
  and open pull requests.
- [Governance](GOVERNANCE.md) - maintainers, decision-making, RFCs and ADRs, releases, and
  security-sensitive changes.
- [Security policy](SECURITY.md) - supported versions, private reporting, scope, and
  response process.
- [Code of Conduct](CODE_OF_CONDUCT.md) - community expectations and enforcement.

## Branch model

```text
main        promoted from develop; tagged releases only
  ^
develop     integration branch for all completed work
  ^
feat/*      feature branches
fix/*       fix branches
```

All work lands on `develop` first through reviewed pull requests. `main` is promoted from
`develop` by maintainers and always represents the last accepted release state. Emergency
fixes may go to `main` first, then be merged back into `develop`. Worktrees are encouraged
for parallel work; see
[docs/workflow.md](docs/workflow.md#parallel-worktrees-and-shared-caches).

## Security

Please do not open a public issue for a suspected vulnerability. Report it privately through
[GitHub security advisories](https://github.com/devstroop/authkit/security/advisories/new),
which is enabled for this repository, or email `security@devstroop.com`. See
[SECURITY.md](SECURITY.md) for scope, triage ownership, and response expectations.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Contributions are accepted under the same dual license. See
[CONTRIBUTING.md](CONTRIBUTING.md#licensing-and-contributions) for contribution
terms and [ADR-0010](docs/adr/0010-dual-mit-apache-2-0-license.md) for the decision.
