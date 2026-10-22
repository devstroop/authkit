# ADR-0008: SQLite first, Postgres for scale

- Status: Accepted
- Deciders: maintainers
- Related: [Architecture](../architecture.md#9-deployment-topologies), [Domain model](../domain-model.md#5-cross-cutting-schema-constraints)

## Context

A self-hosted identity service should be easy to run. Requiring an external database for a
small team adds operational work and a failure mode before the product has delivered value.
Postgres becomes necessary for multiple replicas, larger audit volume, and managed
backups, but it should not be the price of entry.

The domain must also work on D1, which has no interactive transactions. That constraint
pushes the persistence design toward guarded write batches rather than open transactions
held across application logic.

## Decision

- SQLite is a supported production database for a single-node deployment.
- Postgres is the supported database for multi-replica and larger deployments.
- The domain describes reads, decisions, and a **guarded write batch**; each storage
  adapter executes that batch in its native transaction mechanism.
- SQLite and Postgres share one logical migration series with dialect-specific SQL where
  necessary. The D1 adapter follows the same logical series with its own execution path.
- Authorization-critical reads go to the primary. Read replicas may serve reporting and
  audit browsing with an explicit staleness budget.
- Both databases are tested by the same repository contract suite.

## Alternatives considered

- **Postgres only.** Simpler storage matrix, but a worse first-run and small-team story.
- **SQLite only.** Simplest deployment, but no supported horizontal scale and risky for
  larger write volumes.
- **SurrealDB or another multi-model database.** Interesting, but a smaller operational
  track record for security-critical data and no D1 path.
- **Interactive transactions everywhere.** Easier in SQLx, but incompatible with D1 and
  prone to holding locks across I/O.

## Consequences

- The core cannot rely on reading inside a transaction. It must compute writes and use
  compare-and-set guards.
- Migrations need dialect coverage; CI runs them on SQLite and Postgres, and a separate
  job covers D1.
- SQLite deployments are single-writer and must be documented as such.
- Backups differ by database and need separate runbooks.

## Security considerations

Guarded writes are mandatory for one-time grants, refresh rotation, session rotation,
last-owner protection, and invitation acceptance. A guard failure means conflict, replay,
or a lost race; it must fail closed, not retry blindly. Stale reads must never authorize a
revocation-sensitive action.
