# ADR-0001: Start with a four-crate modular monolith

- Status: Accepted
- Deciders: maintainers
- Related: [Architecture](../architecture.md#4-modular-monolith-and-crate-layout)

## Context

AuthKit must run as a native Axum server and, eventually, as a Workers application. The
domain behavior must not depend on either. A common failure mode is to create a crate per
layer before there is evidence that the split is needed. That increases build
configuration, dependency churn, and the number of places a contributor must edit for one
change.

At the same time, letting adapters leak into the domain would make the runtime contract
unverifiable.

## Decision

Start with four crates:

- `authkit-core`: domain, ports, and application use cases, with no HTTP, SQL, template,
  or runtime types.
- `authkit-store`: SQLx repositories and migrations, plus the D1 adapter behind a feature.
- `authkit-server`: Axum, configuration, UI, email/job adapters, and administrative CLI
  subcommands.
- `authkit-worker`: workers-rs entry point and Workers bindings.

Inside `authkit-core`, the dependency direction is `application -> ports -> domain`. The
module boundary is enforced by review and by a compile-time check in CI where practical.
A module is extracted into a new crate only for a measured reason: build time, dependency
isolation, or reuse by another product.

## Alternatives considered

- **One crate.** Simplest, but it makes it too easy for SQLx, Axum, or Askama types to
  reach the domain, and would make the Workers target harder to isolate.
- **One crate per layer (the original 13-crate proposal).** Cleaner on paper, but
  speculative. It multiplies manifests, feature flags, and cross-crate test setup before
  there is a second consumer.
- **Separate domain and ports crates only.** A reasonable middle ground, but ports are
  small and change with the domain; a module boundary is enough for v1.

## Consequences

- Contributors work in fewer manifests and a faster build.
- The runtime contract is still testable because `authkit-core` cannot import adapters.
- If the UI or crypto layer grows independently, it can be extracted later without
  changing callers, because application code already depends on traits.
- The Workers crate can be feature-gated in the workspace so a native `cargo test` does
  not require the Workers toolchain.

## Security considerations

The important boundary is not the number of crates; it is that authorization policy,
credential verification, and token issuance live in code that cannot accidentally depend on
a transport or a database driver. The four-crate layout preserves that boundary while
reducing the surface a reviewer must inspect.
