# Roadmap

AuthKit is built in milestones, not dates. A milestone closes when its exit criteria are
met and the work is on `develop`; a release is promoted to `main` only after the release
checks pass. The order is deliberate: protocol correctness and tenant isolation come
before UI breadth, and production operations come before edge-runtime support.

Milestones are tracked as GitHub milestones. Individual work items are issues linked to the
milestone; epics use the `type/epic` label. See [Open decisions](open-decisions.md) for
choices that must be resolved before the dependent milestone can close.

## M0 - Foundation

**Objective:** make the repository buildable, reviewable, and honest about what it is.

Scope:

- Architecture, domain model, standards profile, runtime targets, UI stack.
- Security model, threat model, operations guide, and optional migration guide.
- Product definition, roadmap, decision register, and ADRs.
- Contribution, governance, security, and code-of-conduct policies.
- Issue and pull-request templates; branch and worktree workflow; shared caches.
- Minimal CI for formatting, linting, documentation links, and secret scanning.

Exit criteria:

- The documentation set is internally consistent and cross-linked.
- Every foundational decision has an accepted ADR.
- A new contributor can clone, install prerequisites, and run the documented checks.
- The branch model works end to end: feature branch to `develop`, promotion to `main`.
- No production code is claimed to exist.

## M1 - Core domain and storage

**Objective:** implement the portable domain and the SQLite/Postgres persistence contract
before exposing HTTP.

Scope:

- Workspace scaffolding for `authkit-core`, `authkit-store`, and `authkit-server`.
- IDs, timestamps, tenant context, stable domain errors, and guarded write batches.
- Users, credentials, sessions, organizations, memberships, invitations, applications,
  OAuth clients, roles, permissions, role bindings, grants, refresh families, and audit.
- SQLx migrations for SQLite and Postgres with dialect-specific SQL where required.
- Repository contract tests that run against both databases.
- Deterministic clock/ID fakes and fixtures for use-case tests.

Exit criteria:

- The domain core compiles without HTTP, SQL, template, or runtime dependencies.
- Authorization-code consumption, refresh rotation, session rotation, last-owner
  protection, and invitation acceptance are atomic under concurrent tests.
- Cross-tenant reads and writes are rejected by construction and covered by tests.
- SQLite and Postgres pass the same repository contract suite.
- Migrations are forward-only, tested from an empty database, and documented.

## M2 - OIDC/OAuth 2.0 provider

**Objective:** make AuthKit a conformant authorization server for the documented profile.

Scope:

- Axum server skeleton, typed configuration, health/readiness, and OAuth error mapping.
- Discovery metadata, JWKS, signing-key lifecycle, and key rotation.
- Authorization endpoint, login/session integration, consent, and exact redirect matching.
- Token endpoint for authorization code + PKCE, refresh rotation, and client credentials.
- Userinfo, revocation, and RP-initiated logout.
- Cookie, CSRF, and session middleware with host-only `__Host-` cookies in production.
- Conformance tests and the required negative tests in [Standards](standards.md).

Exit criteria:

- An OIDC basic-profile conformance run passes for the implemented profile.
- Code replay, refresh reuse, PKCE downgrade, redirect manipulation, algorithm confusion,
  and ID-token-as-access-token are covered by failing tests.
- A reference BFF completes login, refresh, logout, and revocation end to end.
- No endpoint advertises a capability the runtime does not implement.
- The security invariants in the [security model](security-model.md) are enforced in code.

## M3 - Account and administration UI

**Objective:** make the service usable by operators and end users without hand-editing the
database.

Scope:

- Askama/HTMX shell, design tokens, accessible primitives, and progressive enhancement.
- First-run setup: system administrator, issuer, optional email, optional signing key.
- Login, logout, consent, email verification, password reset, and error pages.
- Account pages: profile, email change, password change, sessions, and connected
  applications.
- Organization administration: members, invitations, roles, applications, OAuth clients,
  redirect URIs, and scopes.
- System administration: organizations, deployment settings, signing keys, audit review,
  and break-glass actions.
- Native `<dialog>` forms for create/edit operations instead of buried page forms.

Exit criteria:

- The core flows work with JavaScript disabled.
- Keyboard navigation, focus management, labels, and error announcements pass the
  accessibility checklist.
- Destructive and privileged actions require confirmation and produce audit events.
- CSRF, same-origin, and content-security-policy rules are applied to every form and
  fragment.
- An operator can complete setup and onboard an application without reading the source.

## M4 - Security hardening

**Objective:** close the gap between "works" and "safe to expose".

Scope:

- Argon2id parameter policy, lazy rehash, and credential-change session revocation.
- Login, reset, verification, token, and authorization rate limits with lockout semantics.
- Session-theft detection, refresh-family revocation, and administrator session policy.
- MFA decision and implementation if in v1: passkeys/WebAuthn, TOTP, recovery codes.
- Email delivery adapters, bounce handling, and security notifications.
- Audit integrity, export, retention, and redaction checks.
- Fuzzing/property tests for parsers, tokens, redirects, and form handling.
- Load tests for login, token exchange, refresh, and JWKS.

Exit criteria:

- The threat-model priority threats have mitigations and tests.
- The pre-release security review has no open critical or high findings.
- Rate limits and lockouts behave correctly across restarts and multiple replicas.
- Logs, errors, and audit exports contain no tokens, passwords, or full email bodies.
- Key rotation and credential rotation are rehearsed and documented.

## M5 - Production native deployment

**Objective:** support a real self-hosted deployment with confidence.

Scope:

- Postgres production path, connection pooling, migration safety, and replica guidance.
- Docker image, compose example, reverse-proxy/TLS example, and health checks.
- Administrative CLI: migrate, bootstrap, key rotate, audit export, doctor.
- Backups, restore, upgrade, and rollback runbooks tested against SQLite and Postgres.
- Metrics, structured logs, traces, alerts, and an operations dashboard.
- Release automation, reproducible builds, checksums, and signed artifacts where possible.

Exit criteria:

- A clean host can deploy, upgrade, back up, restore, and roll back using only the docs.
- The reference deployment passes the operational acceptance checklist.
- Migrations are tested from the previous release, not only from empty.
- Metrics and alerts cover availability, error rate, latency, key age, and audit failures.
- Release artifacts are built from the tagged commit and independently verifiable.

## M6 - Workers preview

**Objective:** validate the Workers-lite profile without compromising the native contract.

Scope:

- `authkit-worker` entry point, workers-rs bindings, and D1 storage adapter.
- D1-compatible migrations and guarded write batches.
- Workers-lite feature gates for password authentication, admin UI, audit export, and
  background jobs.
- Platform limits: CPU, memory, batch size, read replication, and key custody.
- Compatibility spike checklist from [Runtime targets](runtime-targets.md).

Exit criteria:

- The compatibility spike is complete and its results are published.
- Unsupported features are hidden in the UI and rejected by the API.
- Auth-critical reads use the consistency mechanism the deployment requires.
- A documented Workers deployment completes login, token exchange, refresh, and logout.
- The profile is clearly labeled preview, with its limits in the deployment docs.

## M7 - Integrations and migration

**Objective:** make adoption cheap without coupling the core to one consumer.

Scope:

- A reference BFF integration and framework-specific samples.
- An OIDC integration guide for resource servers, including JWKS caching and claim checks.
- A generic import path for users, password hashes, and audit metadata.
- The optional AI Gateway pilot migration, if that consumer still needs it.
- A compatibility and rollback guide for dual-run cutovers.

Exit criteria:

- A new application can integrate by following the guide, without reading AuthKit source.
- Imported credentials either verify correctly or force a documented reset.
- No account is linked solely because two rows share an email address.
- Dual-run and rollback are rehearsed on a staging deployment.
- The core contains no consumer-specific branches or schema.

## 1.0 release gate

A 1.0 tag requires all of the following:

- M0 through M5 complete; M6 and M7 may remain preview/optional.
- OIDC conformance evidence and the security review published.
- A supported upgrade path from the previous minor release.
- A chosen license, completed naming review, and published support policy.
- No open critical or high security findings.
- A second maintainer or independent security/conduct reviewer named.
- The operational acceptance checklist completed on both SQLite and Postgres.

## Parallel tracks

Work that can run alongside the numbered milestones:

- **Documentation:** keep the guides, ADRs, and decision register current as code lands.
- **Security:** threat modeling and negative tests are part of each milestone, not a final
  phase.
- **Accessibility:** check each UI slice as it lands; do not defer it to M4.
- **Operations:** add metrics, backups, and runbooks with the feature that needs them.
- **Community:** issue templates, contribution guidance, and good-first-issue curation.

## Explicitly unscheduled

These are not commitments and must not be presented as roadmap items without an accepted
RFC: SAML, SCIM, LDAP, outposts, an auth proxy, a visual flow builder, a hosted SaaS
control plane, billing, and mobile SDKs.
