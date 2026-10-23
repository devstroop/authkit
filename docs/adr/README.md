# Architecture decision records

ADRs record decisions that are expensive to reverse or that shape multiple parts of
AuthKit. They are historical: a changed decision is superseded by a new ADR, not rewritten
in place.

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-modular-monolith-four-crates.md) | Start with a four-crate modular monolith | Accepted |
| [0002](0002-native-first-workers-preview.md) | Native runtime first, Workers preview | Accepted |
| [0003](0003-organizations-are-tenants.md) | Organizations are tenants; applications are surfaces | Accepted |
| [0004](0004-oidc-oauth-only-v1.md) | OIDC/OAuth 2.0 only in v1 | Accepted |
| [0005](0005-server-rendered-htmx-ui.md) | Server-rendered Askama/HTMX UI | Accepted |
| [0006](0006-bff-host-only-cookies.md) | BFF default and host-only cookies | Accepted |
| [0007](0007-no-auth-proxy-or-outposts.md) | No auth proxy or outposts | Accepted |
| [0008](0008-sqlite-first-postgres-scale.md) | SQLite first, Postgres for scale | Accepted |
| [0009](0009-generic-consumer-agnostic-product.md) | A generic, consumer-agnostic product | Accepted |
| [0010](0010-dual-mit-apache-2-0-license.md) | Dual MIT and Apache-2.0 license | Accepted |

## When an ADR is required

An ADR is required for changes to:

- public APIs, configuration formats, or compatibility promises;
- the tenant, identity, session, token, or authorization model;
- cryptography, key management, or secret handling;
- storage guarantees, migrations, or transaction semantics;
- the runtime support matrix or deployment topology;
- governance, licensing, or the project name;
- any choice that would be costly to reverse.

Routine implementation choices belong in code review, not in an ADR. The RFC and ADR
process is defined in [GOVERNANCE.md](../../GOVERNANCE.md#rfc-and-adr-process).

## Template

```markdown
# ADR-NNNN: Title

- Status: Proposed | Accepted | Superseded by ADR-NNNN | Rejected
- Deciders: maintainers
- Related: links

## Context

What problem are we solving, and what constraints apply?

## Decision

What did we choose? State it precisely enough to implement and test.

## Alternatives considered

What else was plausible, and why was it not chosen?

## Consequences

What becomes easier, harder, or impossible? Include operational and migration impact.

## Security considerations

What trust boundaries, abuse cases, or failure modes does this decision affect?
```
