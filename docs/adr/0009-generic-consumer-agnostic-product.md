# ADR-0009: A generic, consumer-agnostic product

- Status: Accepted
- Deciders: maintainers
- Related: [Product](../product.md)

## Context

AuthKit started inside an AI Gateway project, and the first migration plan was written
around that consumer. A product shaped by one consumer tends to grow consumer-specific
tables, routes, roles, and migration code. That makes it harder to use standalone, harder
to document honestly, and harder to keep secure because every special case becomes an
authorization path.

The product direction is a general-purpose open-source identity service that can run
standalone, serve an organization with many applications, or be embedded in another
product.

## Decision

The core is consumer-agnostic:

- No AI Gateway tables, roles, routes, or configuration in `authkit-core`,
  `authkit-store`, or `authkit-server`.
- AI Gateway is one planned consumer and an integration test. Its migration guide is
  documentation, not a core feature.
- Organization-specific behavior is expressed through standard concepts: organizations,
  applications, OAuth clients, roles, permissions, and scopes.
- Consumer-specific integrations belong in the consumer's repository or in an optional
  adapter, not in the domain.
- A feature that only one consumer needs must justify itself against the generic product
  scope before it lands.

## Alternatives considered

- **Build AuthKit as an internal AI Gateway component first.** Faster for the pilot, but it
  would bake in assumptions and make the standalone product a fork.
- **Fork the core for each consumer.** Rejected: security fixes and protocol work would
  diverge.
- **A plugin system for consumer logic.** Rejected for v1: it adds an extension API and a
  new trust boundary before there is evidence it is needed.

## Consequences

- The AI Gateway migration becomes optional and can proceed on its own schedule.
- Generic integration docs are a first-class deliverable, not an afterthought.
- The schema stays smaller and the threat model stays comprehensible.
- If a consumer needs a unique authorization rule, it should be expressible as a role,
  scope, claim, or application setting; otherwise it is a product decision, not a hidden
  branch.

## Security considerations

Consumer-specific code paths are a common source of authorization bugs because they are
reviewed by fewer people and tested less. Keeping the core generic reduces the number of
special cases that can bypass tenant isolation or role checks.
