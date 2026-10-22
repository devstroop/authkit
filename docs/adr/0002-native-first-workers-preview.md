# ADR-0002: Native runtime first, Workers preview

- Status: Accepted
- Deciders: maintainers
- Related: [Runtime targets](../runtime-targets.md), [Roadmap](../roadmap.md)

## Context

Cloudflare Workers is an attractive deployment target: no server to patch, global
placement, and a generous free tier. It is also a restricted runtime. There is no general
SQLx driver for D1, no interactive transactions, no filesystem, and tight CPU/memory
budgets for password hashing and background work. Pretending that a Workers deployment is
feature-identical to a native one would produce either insecure password handling or
silent data loss.

## Decision

The native Axum + SQLx runtime with SQLite or Postgres is the reference implementation and
the only runtime that can claim full feature support in v1. The Workers target is a
**preview** profile that may omit password authentication, the admin UI, SMTP, background
jobs, and other capabilities the platform cannot support safely. Unsupported features are
gated in the UI and rejected by the API. Workers support becomes generally available only
after the compatibility checklist is complete and published.

## Alternatives considered

- **Workers-only.** Rejected: it would force the product into D1's limits and make
  self-hosting on a normal server a second-class path.
- **Feature parity from day one.** Rejected: it would require weakening Argon2 parameters,
  inventing transaction semantics, or moving auth-critical operations to another service.
- **No Workers target.** Rejected: edge deployment is a real use case for Cloudflare-native
  teams, and the portable core makes a limited profile feasible.

## Consequences

- The native binary and SQLite file remain the simplest supported deployment.
- The support matrix must be visible in the UI and documentation; "Workers" must never be
  advertised as a drop-in replacement.
- The core must use guarded write batches rather than interactive transactions so the same
  use cases can run on D1.
- CI needs a separate Workers build job; a native test pass does not prove the worker
  compiles or behaves correctly.

## Security considerations

The Workers profile must not lower password-hashing parameters, skip audit durability, or
accept stale reads for authorization decisions without an explicit, documented risk
decision. If a safe implementation is not possible on the platform, the feature is disabled
rather than weakened.
